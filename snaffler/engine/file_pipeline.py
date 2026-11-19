import fnmatch
import logging
import queue
import threading
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Dict, List, Set

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.accessors.smb_file_accessor import SMBFileAccessor
from snaffler.analysis.file_scanner import FileScanner
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.classifiers.rules import Triage
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.shares import share_matches_filter
from snaffler.discovery.smb_tree_walker import SMBTreeWalker
from snaffler.discovery.tree import TreeWalker
from snaffler.engine.batch_writer import (
    _BATCH_INTERVAL,  # noqa: F401 — patched by tests
    _BATCH_SIZE,  # noqa: F401 — patched by tests
    _MAX_ENQUEUED,
    _BatchWriter,
    _extract_share_unc,
)
from snaffler.resume.scan_state import ScanState
from snaffler.utils.fatal import check_fatal_os_error
from snaffler.utils.logger import log_file_result
from snaffler.utils.progress import ProgressState

logger = logging.getLogger("snaffler")

_SENTINEL = None


@dataclass
class PipelineContext:
    file_queue: queue.Queue
    walked_shares: list = field(default_factory=list)
    producer_error: list = field(default_factory=list)
    batch_writer: _BatchWriter | None = None
    consumer_results: list = field(default_factory=lambda: [0])
    consumer_lock: threading.Lock = field(default_factory=threading.Lock)


class FilePipeline:
    def __init__(
        self,
        cfg: SnafflerConfiguration,
        state: ScanState | None = None,
        progress: ProgressState | None = None,
        tree_walker: TreeWalker | None = None,
        file_accessor: FileAccessor | None = None,
    ):
        self.cfg = cfg
        self.state = state
        self.progress = progress

        self.tree_threads = cfg.advanced.tree_threads
        self.file_threads = cfg.advanced.file_threads
        self.max_per_share = cfg.advanced.max_tree_threads_per_share  # 0 = unlimited

        self.tree_walker = tree_walker or SMBTreeWalker(cfg)

        file_accessor = file_accessor or SMBFileAccessor(cfg)
        rule_evaluator = RuleEvaluator(
            file_rules=cfg.rules.file,
            content_rules=cfg.rules.content,
            postmatch_rules=cfg.rules.postmatch,
        )
        self.file_scanner = FileScanner(
            cfg=cfg,
            file_accessor=file_accessor,
            rule_evaluator=rule_evaluator,
        )

    def run(self, paths: List[str]) -> int:
        logger.info(f"Starting file discovery on {len(paths)} paths")

        paths, skipped_shares = self._resume_skip_shares(paths)

        if self.progress:
            self.progress.shares_total = len(paths) + skipped_shares
            self.progress.shares_walked = skipped_shares

        if not paths:
            logger.info("No shares to walk")
            return 0

        ctx = PipelineContext(
            file_queue=queue.Queue(maxsize=100_000),
            batch_writer=_BatchWriter(self.state) if self.state else None,
        )
        if ctx.batch_writer:
            ctx.batch_writer.start()

        producer_thread = threading.Thread(
            target=self._run_producer, args=(paths, ctx), name="walk-producer", daemon=True
        )
        consumer_threads = [
            threading.Thread(target=self._run_consumer, args=(ctx,), name=f"scan-consumer-{i}", daemon=True)
            for i in range(self.file_threads)
        ]

        producer_thread.start()
        for t in consumer_threads:
            t.start()

        interrupted = False
        try:
            producer_thread.join()
            for t in consumer_threads:
                t.join()
        except KeyboardInterrupt:
            interrupted = True
            while True:
                try:
                    ctx.file_queue.get_nowait()
                except queue.Empty:
                    break
            for _ in range(self.file_threads):
                try:
                    ctx.file_queue.put_nowait(_SENTINEL)
                except queue.Full:
                    pass
            for t in consumer_threads:
                t.join(timeout=5)
        finally:
            if ctx.batch_writer:
                timeout = 5 if (interrupted or ctx.producer_error) else 30
                ctx.batch_writer.stop(timeout=timeout)

        if interrupted:
            raise KeyboardInterrupt()

        if ctx.producer_error:
            raise ctx.producer_error[0]

        results_count = ctx.consumer_results[0]
        self._mark_shares_done(ctx.walked_shares)

        if results_count:
            logger.info(f"Scan completed: {results_count} files matched")
        elif self.progress and self.progress.files_total == 0:
            logger.warning("No files found")
        else:
            logger.info("Scan completed: no matches")

        return results_count

    # ------------------------------------------------------------------
    # run() helpers
    # ------------------------------------------------------------------

    def _resume_skip_shares(self, paths: List[str]) -> tuple:
        skipped = 0
        if self.state:
            before = len(paths)
            paths = [p for p in paths if not self.state.should_skip_share(p)]
            skipped = before - len(paths)
            if skipped:
                logger.info(f"Resume: skipped {skipped} fully-processed shares")
        return paths, skipped

    # ------------------------------------------------------------------
    # Producer
    # ------------------------------------------------------------------

    def _run_producer(self, paths: List[str], ctx: PipelineContext):
        shutdown = threading.Event()
        enqueued = set()
        enqueued_lock = threading.Lock()

        def on_file(unc_path, size, mtime, ctime=0.0, atime=0.0):
            normalized = unc_path.lower()
            with enqueued_lock:
                if normalized in enqueued:
                    return
                enqueued.add(normalized)
                if len(enqueued) > _MAX_ENQUEUED:
                    enqueued.clear()
            if self.state and self.state.should_skip_file(unc_path):
                if self.progress:
                    self.progress.files_total += 1
                    self.progress.files_scanned += 1
                return
            if self.progress:
                self.progress.files_total += 1
            if ctx.batch_writer:
                share_unc = _extract_share_unc(unc_path)
                ctx.batch_writer.put_file(unc_path, share_unc, size, mtime, ctime, atime)
            while not shutdown.is_set():
                try:
                    ctx.file_queue.put((unc_path, size, mtime, ctime, atime), timeout=1.0)
                    return
                except queue.Full:
                    continue

        def on_dir(unc_path):
            if ctx.batch_writer:
                share_unc = _extract_share_unc(unc_path)
                ctx.batch_writer.put_dir(unc_path, share_unc)

        try:
            with ThreadPoolExecutor(max_workers=self.tree_threads) as executor:
                dir_for_future = {}
                share_for_future = {}
                share_pending: Dict[str, int] = {}
                shares_with_errors: Set[str] = set()
                cancel_events: Dict[str, threading.Event] = {}
                pending = set()
                submitted_dirs = set()

                max_per_share = self.max_per_share
                share_buffer = {}
                share_root_map: Dict[str, str] = {}

                def _submit_dir(subdir, share_root, cancel_ev):
                    key = share_root.lower()
                    if max_per_share and share_pending.get(key, 0) >= max_per_share:
                        if key not in share_buffer:
                            share_buffer[key] = deque()
                        share_buffer[key].append(subdir)
                        return
                    fut = executor.submit(
                        self.tree_walker.walk_directory,
                        subdir,
                        on_file,
                        on_dir,
                        cancel_ev,
                    )
                    dir_for_future[fut] = subdir
                    share_for_future[fut] = share_root
                    share_pending[key] = share_pending.get(key, 0) + 1
                    pending.add(fut)

                def _drain_buffer(key):
                    if key not in share_buffer:
                        return
                    buf = share_buffer[key]
                    cancel_ev = cancel_events.get(key, threading.Event())
                    root = share_root_map.get(key)
                    while buf and (not max_per_share or share_pending.get(key, 0) < max_per_share):
                        subdir = buf.popleft()
                        fut = executor.submit(
                            self.tree_walker.walk_directory,
                            subdir,
                            on_file,
                            on_dir,
                            cancel_ev,
                        )
                        dir_for_future[fut] = subdir
                        share_for_future[fut] = root
                        share_pending[key] = share_pending.get(key, 0) + 1
                        pending.add(fut)
                    if not buf:
                        del share_buffer[key]

                if self.state:
                    for d in self.state.load_walked_dirs():
                        submitted_dirs.add(d.lower())

                self._seed_share_roots(
                    paths,
                    executor,
                    on_file,
                    on_dir,
                    dir_for_future,
                    share_for_future,
                    share_pending,
                    cancel_events,
                    pending,
                    submitted_dirs,
                    share_root_map,
                    ctx,
                )

                self._seed_unwalked_dirs(
                    _submit_dir,
                    cancel_events,
                    share_root_map,
                    submitted_dirs,
                )

                self._finalize_no_work_shares(
                    share_root_map,
                    share_pending,
                    share_buffer,
                    shares_with_errors,
                    ctx,
                )

                self._seed_unchecked_files(
                    ctx,
                    enqueued,
                    enqueued_lock,
                    shutdown,
                )

                # --- Fan-out loop ---
                try:
                    while pending:
                        done, pending = wait(
                            pending,
                            return_when=FIRST_COMPLETED,
                        )
                        for future in done:
                            dir_unc = dir_for_future.pop(future, None)
                            share_root = share_for_future.pop(future, None)

                            walk_ok = False
                            try:
                                subdirs = future.result()
                                walk_ok = True
                            except Exception as e:
                                check_fatal_os_error(e)
                                logger.debug(f"Error walking {dir_unc}: {e}")
                                subdirs = []
                                if share_root:
                                    shares_with_errors.add(share_root.lower())

                            if self.state and dir_unc and walk_ok:
                                self.state.mark_dir_walked(dir_unc)

                            max_depth = self.cfg.scanning.max_depth
                            for subdir in subdirs:
                                if subdir.lower() in submitted_dirs:
                                    continue
                                if max_depth is not None and share_root:
                                    rel = subdir.lower()[len(share_root.lower()) :].strip("/")
                                    depth = len(rel.split("/")) if rel else 0
                                    if depth > max_depth:
                                        if self.state:
                                            self.state.store_dir(subdir, share_root)
                                        continue
                                submitted_dirs.add(subdir.lower())
                                cancel_ev = cancel_events.get(share_root.lower(), threading.Event())
                                _submit_dir(subdir, share_root, cancel_ev)

                            if share_root:
                                key = share_root.lower()
                                share_pending[key] -= 1
                                _drain_buffer(key)
                                if share_pending.get(key, 0) == 0 and key not in share_buffer:
                                    if self.progress:
                                        self.progress.shares_walked += 1
                                    if key not in shares_with_errors:
                                        ctx.walked_shares.append(share_root)
                                    else:
                                        logger.warning(
                                            f"Share {share_root} completed with walk errors "
                                            f"(will retry failed dirs on resume)"
                                        )

                except KeyboardInterrupt:
                    shutdown.set()
                    for ev in cancel_events.values():
                        ev.set()
                    executor.shutdown(wait=False, cancel_futures=True)
                    ctx.producer_error.append(KeyboardInterrupt())
        finally:
            for _ in range(self.file_threads):
                while True:
                    try:
                        ctx.file_queue.put(_SENTINEL, timeout=5)
                        break
                    except queue.Full:
                        try:
                            ctx.file_queue.get_nowait()
                        except queue.Empty:
                            pass

    def _seed_share_roots(
        self,
        paths,
        executor,
        on_file,
        on_dir,
        dir_for_future,
        share_for_future,
        share_pending,
        cancel_events,
        pending,
        submitted_dirs,
        share_root_map,
        ctx,
    ):
        for path in paths:
            exclude_patterns = getattr(self.tree_walker, "_exclude_unc", None) or self.cfg.targets.exclude_unc
            if exclude_patterns:
                path_lower = path.lower()
                if any(fnmatch.fnmatch(path_lower, p.lower()) for p in exclude_patterns):
                    logger.debug(f"Skipped share root {path} due to --exclude-unc filter")
                    if self.progress:
                        self.progress.shares_walked += 1
                    continue
            key = path.lower()
            if self.state and self.state.should_skip_share(path):
                logger.debug(f"Resume: skipping done share {path}")
                if self.progress:
                    self.progress.shares_walked += 1
                submitted_dirs.add(key)
                continue
            cancel = threading.Event()
            cancel_events[key] = cancel
            share_root_map[key] = path
            if key in submitted_dirs:
                logger.debug(f"Resume: share root already walked {path}")
                share_pending[key] = 0
                continue
            submitted_dirs.add(key)
            future = executor.submit(
                self.tree_walker.walk_directory,
                path,
                on_file,
                on_dir,
                cancel,
            )
            dir_for_future[future] = path
            share_for_future[future] = path
            share_pending[key] = 1
            pending.add(future)

    def _seed_unwalked_dirs(
        self,
        submit_dir,
        cancel_events,
        share_root_map,
        submitted_dirs,
    ):
        if not self.state:
            return
        max_depth = self.cfg.scanning.max_depth
        for unwalked_dir in self.state.load_unwalked_dirs():
            dir_lower = unwalked_dir.lower()
            share_root_unc = _extract_share_unc(unwalked_dir)
            key = share_root_unc.lower()
            if key not in cancel_events:
                key = None
                for ck in cancel_events:
                    if dir_lower == ck or dir_lower.startswith(ck.rstrip("/") + "/"):
                        key = ck
                        break
                if key is None:
                    continue
            share_root = share_root_map.get(key, share_root_unc)
            if dir_lower in submitted_dirs:
                continue
            if max_depth is not None and share_root:
                rel = dir_lower[len(key) :].strip("/")
                depth = len(rel.split("/")) if rel else 0
                if depth > max_depth:
                    continue
            submitted_dirs.add(dir_lower)
            submit_dir(unwalked_dir, share_root, cancel_events[key])

    def _finalize_no_work_shares(
        self,
        share_root_map,
        share_pending,
        share_buffer,
        shares_with_errors,
        ctx,
    ):
        for key in list(share_root_map):
            if share_pending.get(key, 0) == 0 and key not in share_buffer:
                root = share_root_map[key]
                if self.progress:
                    self.progress.shares_walked += 1
                if key not in shares_with_errors:
                    ctx.walked_shares.append(root)

    def _seed_unchecked_files(self, ctx, enqueued, enqueued_lock, shutdown):
        if not self.state:
            return
        include_filter = self.cfg.targets.share_filter
        exclude_filter = self.cfg.targets.exclude_share
        exclude_dir_patterns = self.cfg.targets.exclude_unc
        for unc_path, size, mtime in self.state.iter_unchecked_files():
            file_share = _extract_share_unc(unc_path).lower()
            share_name = file_share.rstrip("/").rsplit("/", 1)[-1]
            if not share_matches_filter(share_name, include_filter, exclude_filter):
                continue
            if exclude_dir_patterns:
                path_lower = unc_path.lower()
                if any(fnmatch.fnmatch(path_lower, p.lower()) for p in exclude_dir_patterns):
                    continue
            normalized = unc_path.lower()
            with enqueued_lock:
                if normalized in enqueued:
                    continue
                enqueued.add(normalized)
            if self.state.should_skip_file(unc_path):
                continue
            if self.progress:
                self.progress.files_total += 1
            while not shutdown.is_set():
                try:
                    ctx.file_queue.put((unc_path, size or 0, mtime or 0.0, 0.0, 0.0), timeout=1.0)
                    break
                except queue.Full:
                    continue

    # ------------------------------------------------------------------
    # Consumer
    # ------------------------------------------------------------------

    def _run_consumer(self, ctx: PipelineContext):
        while True:
            try:
                item = ctx.file_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            if item is _SENTINEL:
                return

            unc_path, size, mtime, ctime, atime = item

            if self.state and self.state.should_skip_file(unc_path):
                if self.progress:
                    self.progress.files_scanned += 1
                continue

            if self.progress:
                self.progress.files_in_progress += 1
            try:
                result = self.file_scanner.scan_file(unc_path, size, mtime, ctime, atime)

                if self.state:
                    self.state.mark_file_done(unc_path)
                    if ctx.batch_writer:
                        ctx.batch_writer.enqueue_checked(unc_path)

                if result:
                    log_file_result(
                        logger,
                        result.file_path,
                        result.triage.label,
                        result.rule_name,
                        result.match,
                        result.context,
                        result.size,
                        result.modified.strftime("%Y-%m-%d %H:%M:%S") if result.modified else None,
                        created=result.created.strftime("%Y-%m-%d %H:%M:%S") if result.created else None,
                        accessed=result.accessed.strftime("%Y-%m-%d %H:%M:%S") if result.accessed else None,
                    )
                    if (
                        self.cfg.scanning.snaffle
                        and result.size <= self.cfg.scanning.max_file_bytes
                        and self.file_scanner.file_accessor is not None
                    ):
                        self.file_scanner.file_accessor.copy_to_local(
                            unc_path,
                            self.cfg.scanning.snaffle_path,
                        )

                    with ctx.consumer_lock:
                        ctx.consumer_results[0] += 1
                    if self.progress:
                        self.progress.files_matched += 1
                        self._count_severity(result)

            except Exception as e:
                check_fatal_os_error(e)
                logger.warning(f"Error scanning {unc_path}: {e}")
            finally:
                if self.progress:
                    self.progress.files_scanned += 1
                    self.progress.files_in_progress -= 1

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _mark_shares_done(self, walked_shares: list):
        if self.state:
            for share_path in walked_shares:
                self.state.mark_share_done(share_path)

    def close(self):
        try:
            self.tree_walker.close()
        except Exception:
            pass
        try:
            self.file_scanner.file_accessor.close()
        except Exception:
            pass

    def _count_severity(self, result):
        triage = result.triage
        if triage == Triage.BLACK:
            self.progress.severity_black += 1
        elif triage == Triage.RED:
            self.progress.severity_red += 1
        elif triage == Triage.YELLOW:
            self.progress.severity_yellow += 1
        elif triage == Triage.GREEN:
            self.progress.severity_green += 1
