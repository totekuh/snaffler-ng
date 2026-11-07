"""Daemon thread that batches dir/file inserts and file-checked marks into SQLite."""

import logging
import queue
import threading
import time

logger = logging.getLogger("snaffler")

_BATCH_SIZE = 500
_BATCH_INTERVAL = 1.0
_MAX_ENQUEUED = 500_000


def _extract_share_unc(unc_path: str) -> str:
    """Extract //server/share from a full UNC path."""
    from snaffler.utils.path_utils import extract_share_root
    return extract_share_root(unc_path)


class _BatchWriter:
    """Daemon thread that batches dir/file inserts and file-checked marks into SQLite."""

    def __init__(self, state):
        self._state = state
        self._queue = queue.Queue()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(
            target=self._run, name="batch-writer", daemon=True,
        )
        self._thread.start()

    def stop(self, timeout=30):
        self._queue.put(None)
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning(f"Batch writer did not finish within {timeout}s")

    def put_dir(self, unc_path: str, share: str):
        self._queue.put(("dir", unc_path, share))

    def put_file(self, unc_path: str, share: str, size: int, mtime: float,
                 ctime: float = 0.0, atime: float = 0.0):
        self._queue.put(("file", unc_path, share, size, mtime, ctime, atime))

    def enqueue_checked(self, unc_path: str):
        self._queue.put(("checked", unc_path))

    def _run(self):
        dir_buf = []
        file_buf = []
        checked_buf = []
        deadline = time.monotonic() + _BATCH_INTERVAL

        while True:
            try:
                timeout = max(0, deadline - time.monotonic())
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                item = "flush"

            if item is None:
                while True:
                    try:
                        remaining = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if remaining is None:
                        continue
                    kind = remaining[0]
                    if kind == "dir":
                        dir_buf.append((remaining[1], remaining[2]))
                    elif kind == "file":
                        file_buf.append((remaining[1], remaining[2], remaining[3], remaining[4]))
                    elif kind == "checked":
                        checked_buf.append(remaining[1])
                self._flush(dir_buf, file_buf, checked_buf)
                return

            if item == "flush":
                self._flush(dir_buf, file_buf, checked_buf)
                dir_buf.clear()
                file_buf.clear()
                checked_buf.clear()
                deadline = time.monotonic() + _BATCH_INTERVAL
                continue

            kind = item[0]
            if kind == "dir":
                dir_buf.append((item[1], item[2]))
            elif kind == "file":
                file_buf.append((item[1], item[2], item[3], item[4]))
            elif kind == "checked":
                checked_buf.append(item[1])

            if len(dir_buf) + len(file_buf) + len(checked_buf) >= _BATCH_SIZE:
                self._flush(dir_buf, file_buf, checked_buf)
                dir_buf.clear()
                file_buf.clear()
                checked_buf.clear()
                deadline = time.monotonic() + _BATCH_INTERVAL

    def _flush(self, dir_buf, file_buf, checked_buf=None):
        try:
            if dir_buf:
                self._state.store_dirs(dir_buf)
            if file_buf:
                self._state.store_files(file_buf)
            if checked_buf:
                self._state.store.mark_files_checked_batch(checked_buf)
        except Exception as e:
            logger.warning(
                f"Batch writer flush error ({len(dir_buf)} dirs, "
                f"{len(file_buf)} files, "
                f"{len(checked_buf) if checked_buf else 0} checked): {e}"
            )
