"""Scan state persistence — facade + SQLite backend."""

from snaffler.resume.scan_state.sqlite_store import SQLiteStateStore
from snaffler.resume.scan_state.state_facade import ScanState
from snaffler.utils.path_utils import extract_share_root as _extract_share

__all__ = ["SQLiteStateStore", "ScanState", "_extract_share"]
