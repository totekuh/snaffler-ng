"""
Main Snaffler controller - orchestrates all components
"""
import logging
import signal
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.shares import share_matches_filter
from snaffler.engine.domain_pipeline import DomainPipeline
from snaffler.engine.file_pipeline import FilePipeline
from snaffler.engine.share_pipeline import SharePipeline
from snaffler.engine.runner_filters import FilterMixin
from snaffler.engine.runner_discovery import DiscoveryMixin
from snaffler.engine.runner_auth import AuthMixin
from snaffler.resume.scan_state import SQLiteStateStore, ScanState
from snaffler.utils.hotkeys import start_hotkey_listener, stop_hotkey_listener
from snaffler.utils.logger import print_completion_stats, set_finding_store
from snaffler.utils.fatal import check_fatal_os_error
from snaffler.utils.path_utils import extract_unc_host, extract_unc_share_name
from snaffler.utils.progress import ProgressState

logger = logging.getLogger('snaffler')


def _deduplicate_paths(share_paths: List[str], dfs_paths: List[str]) -> List[str]:
    """Merge share and DFS paths, deduplicating case-insensitively."""
    seen = {p.lower() for p in share_paths}
    merged = list(share_paths)
    for p in dfs_paths:
        if p.lower() not in seen:
            seen.add(p.lower())
            merged.append(p)
    return merged


_STATUS_INTERVAL = 30  # seconds
_PORT_CHECK_TIMEOUT = 3  # seconds — TCP probe during DNS pre-resolution

_PHASE_COMPUTERS = "computer_discovery_done"
_PHASE_DNS = "dns_resolution_done"
_PHASE_SHARES = "share_discovery_done"
_SYNC_SCAN_MODE = "scan_mode"


class SnafflerRunner(FilterMixin, DiscoveryMixin, AuthMixin):
    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.start_time = None

        # ---------- pre-computed exclusion set ----------
        self._exclusion_set = frozenset(e.upper() for e in (cfg.targets.exclusions or []))

        # ---------- progress ----------
        self.progress = ProgressState()
        self._stop_event = threading.Event()
        self._status_thread = None

        # ---------- state ----------
        self.state = ScanState(store=SQLiteStateStore(cfg.state.state_db))
        set_finding_store(self.state.store_finding)
        logger.info(f"State DB: {cfg.state.state_db}")

        # SharePipeline is only needed for SMB-based modes
        if not cfg.targets.ftp_targets and not cfg.targets.local_targets:
            self.share_pipeline = SharePipeline(
                cfg=cfg, state=self.state, progress=self.progress,
            )
        else:
            self.share_pipeline = None

        # Inject FTP transport when --ftp is used
        if cfg.targets.ftp_targets:
            from snaffler.accessors.ftp_file_accessor import FTPFileAccessor
            from snaffler.discovery.ftp_tree_walker import FTPTreeWalker

            _FTP_MAX_PER_BUCKET = 4
            if cfg.advanced.tree_threads > _FTP_MAX_PER_BUCKET:
                cfg.advanced.share_threads = 0
                cfg.advanced.tree_threads = _FTP_MAX_PER_BUCKET
                cfg.advanced.file_threads = _FTP_MAX_PER_BUCKET
                logger.info(
                    f"FTP mode: capped threads to {_FTP_MAX_PER_BUCKET} tree + "
                    f"{_FTP_MAX_PER_BUCKET} file to avoid connection floods"
                )

            tree_walker = FTPTreeWalker(cfg)
            file_accessor = FTPFileAccessor(cfg)
            self.file_pipeline = FilePipeline(
                cfg=cfg, state=self.state, progress=self.progress,
                tree_walker=tree_walker, file_accessor=file_accessor,
            )
        # Inject local transport when --local-fs is used
        elif cfg.targets.local_targets:
            from snaffler.accessors.local_file_accessor import LocalFileAccessor
            from snaffler.discovery.local_tree_walker import LocalTreeWalker

            tree_walker = LocalTreeWalker(
                dir_rules=cfg.rules.directory,
                exclude_unc=cfg.targets.exclude_unc,
            )
            file_accessor = LocalFileAccessor()
            self.file_pipeline = FilePipeline(
                cfg=cfg, state=self.state, progress=self.progress,
                tree_walker=tree_walker, file_accessor=file_accessor,
            )
        else:
            self.file_pipeline = FilePipeline(cfg=cfg, state=self.state, progress=self.progress)

    def _start_status_thread(self):
        self._stop_event.clear()
        self._status_thread = threading.Thread(
            target=self._status_loop, daemon=True
        )
        self._status_thread.start()

    def _stop_status_thread(self):
        self._stop_event.set()
        if self._status_thread is not None:
            self._status_thread.join(timeout=2)

    def _status_loop(self):
        while not self._stop_event.wait(timeout=_STATUS_INTERVAL):
            try:
                self._sync_progress_from_state()
                logger.info(f"Progress: {self.progress.format_status()}")
            except Exception:
                pass

    def _run_file_pipeline(self, paths: list):
        """Rebalance threads and run the file scanning pipeline."""
        if paths:
            self._rebalance_file_threads()
            self.file_pipeline.run(paths)

    def _detect_scan_mode(self) -> str:
        """Determine the current scan mode from config."""
        if self.cfg.targets.rescan_unreadable:
            return "rescan"
        if self.cfg.targets.ftp_targets:
            return "ftp"
        if self.cfg.targets.local_targets:
            return "local"
        if self.cfg.targets.unc_targets:
            return "unc"
        if self.cfg.targets.computer_targets:
            return "computer"
        if self.cfg.auth.domain:
            return "domain"
        return "unknown"

    def _check_scan_mode_changed(self):
        """Reset phase flags if scan mode changed since last run."""
        if not self.state:
            return
        mode = self._detect_scan_mode()
        prev = self.state.get_sync_value(_SYNC_SCAN_MODE)
        if prev and prev != mode:
            logger.warning(
                f"Scan mode changed ({prev} -> {mode}) — "
                f"resetting discovery phase flags (findings preserved)"
            )
            self.state.clear_phase_flags()
        self.state.set_sync_value(_SYNC_SCAN_MODE, mode)

    def execute(self):
        self.start_time = datetime.now()
        logger.info(f"Starting Snaffler at {self.start_time:%Y-%m-%d %H:%M:%S}")

        self._start_status_thread()
        start_hotkey_listener(self._stop_event)
        self._check_scan_mode_changed()
        interrupted = False
        try:
            self._validate_credentials()

            if self.cfg.web.enabled:
                try:
                    from snaffler.web.server import start_web_server
                    start_web_server(self.progress, self.cfg.state.state_db, self.start_time, self.cfg.web.port)
                except ImportError as exc:
                    raise SystemExit(
                        f"FATAL: --web requires Flask: {exc}\n"
                        f"Install with: pip install snaffler-ng[web]"
                    ) from exc

            # ---------- rescan unreadable shares ----------
            if self.cfg.targets.rescan_unreadable:
                other = []
                if self.cfg.targets.unc_targets:
                    other.append("--unc")
                if self.cfg.targets.computer_targets:
                    other.append("--computer")
                if self.cfg.auth.domain:
                    other.append("--domain")
                if other:
                    logger.warning(
                        f"--rescan-unreadable takes priority — ignoring {', '.join(other)}"
                    )
                self._rescan_unreadable()

            # ---------- FTP targets ----------
            elif self.cfg.targets.ftp_targets:
                if self.cfg.targets.shares_only:
                    logger.warning("--shares-only has no effect in --ftp mode")
                if self.cfg.targets.exclusions:
                    logger.warning("--exclusions has no effect in --ftp mode")
                paths = self.cfg.targets.ftp_targets
                self.progress.shares_found = len(paths)
                self._run_file_pipeline(paths)

            # ---------- Local filesystem paths ----------
            elif self.cfg.targets.local_targets:
                if self.cfg.targets.shares_only:
                    logger.warning("--shares-only has no effect in --local-fs mode")
                if self.cfg.targets.exclusions:
                    logger.warning("--exclusions has no effect in --local-fs mode")
                paths = self.cfg.targets.local_targets
                self.progress.shares_found = len(paths)
                self._run_file_pipeline(paths)

            # ---------- Direct UNC paths ----------
            elif self.cfg.targets.unc_targets:
                paths = self._filter_paths_by_share(self.cfg.targets.unc_targets)
                paths = self._filter_paths_by_exclusions(paths)
                # --max-hosts: keep only paths belonging to the first N hosts
                limit = self.cfg.targets.max_hosts
                if isinstance(limit, int):
                    seen_hosts = {}
                    capped = []
                    for p in paths:
                        host = extract_unc_host(p)
                        if host is None:
                            host = p
                        else:
                            host = host.lower()
                        if host not in seen_hosts:
                            if len(seen_hosts) >= limit:
                                continue
                            seen_hosts[host] = True
                        capped.append(p)
                    if len(paths) != len(capped):
                        logger.info(f"--max-hosts {limit}: kept {len(seen_hosts)} hosts, {len(capped)}/{len(paths)} paths")
                    paths = capped
                hosts = {
                    extract_unc_host(p)
                    for p in paths
                    if extract_unc_host(p) is not None
                }
                self.progress.computers_total = len(hosts)
                self.progress.computers_done = len(hosts)
                self.progress.shares_found = len(paths)
                self._run_file_pipeline(paths)

            # ---------- Explicit computer list ----------
            elif self.cfg.targets.computer_targets:
                computers = self._apply_exclusions(
                    self.cfg.targets.computer_targets
                )
                computers = self._cap_hosts(computers)
                resolved = self._resolve_computers(computers) if computers else []
                share_paths = self._resume_share_discovery(resolved) if resolved else []
                self._run_file_pipeline(share_paths)

            # ---------- Domain discovery ----------
            elif self.cfg.auth.domain:
                logger.info("Starting full domain discovery")
                domain_pipeline = DomainPipeline(self.cfg, exclusion_set=self._exclusion_set)
                computers = self._resume_computer_discovery(domain_pipeline)
                computers = self._cap_hosts(computers)
                resolved = self._resolve_computers(computers) if computers else []
                share_paths = self._resume_share_discovery(resolved) if resolved else []

                # DFS discovery via LDAP (always re-runs — fast, deduplicated)
                dfs_paths = domain_pipeline.get_dfs_shares()
                if dfs_paths:
                    logger.info(f"Discovered {len(dfs_paths)} DFS target paths via LDAP")
                    dfs_paths = self._filter_paths_by_share(dfs_paths)

                # Merge + dedup
                all_paths = _deduplicate_paths(share_paths, dfs_paths)
                dfs_only = len(all_paths) - len(share_paths)
                if dfs_only > 0:
                    logger.info(f"Added {dfs_only} new paths from DFS discovery")

                # Reflect DFS-merged total in the status display
                self.progress.shares_found = len(all_paths)

                if not self.cfg.targets.shares_only:
                    self._run_file_pipeline(all_paths)

            else:
                logger.error("No targets specified")
                return

            self.progress.scan_complete = True

        except KeyboardInterrupt:
            interrupted = True
            logger.warning("Interrupted by user — shutting down")
        finally:
            # Mask SIGINT during cleanup so mashing Ctrl+C can't skip DB close.
            # signal.signal() raises ValueError from non-main threads.
            is_main = threading.current_thread() is threading.main_thread()
            prev_handler = None
            if is_main:
                prev_handler = signal.getsignal(signal.SIGINT)
                signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                if self.cfg.web.enabled:
                    try:
                        from snaffler.web.server import stop_web_server
                        stop_web_server()
                    except Exception:
                        pass
                stop_hotkey_listener()
                self._stop_status_thread()
                self._sync_progress_from_state()
                try:
                    print_completion_stats(start_time=self.start_time, progress=self.progress)
                except Exception:
                    pass
                try:
                    self.file_pipeline.close()
                except Exception:
                    pass
                if self.share_pipeline:
                    try:
                        self.share_pipeline.close()
                    except Exception:
                        pass
                if self.state:
                    try:
                        set_finding_store(None)
                        self.state.close()
                        logger.info("State saved")
                    except Exception:
                        pass
            finally:
                if is_main and prev_handler is not None:
                    signal.signal(signal.SIGINT, prev_handler)
            if interrupted:
                raise KeyboardInterrupt
