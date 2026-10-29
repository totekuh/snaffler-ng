"""SQLiteStateStore — assembled from base + entity mixins."""

import sqlite3
import threading

from snaffler.resume.scan_state.sqlite_computers import ComputersMixin
from snaffler.resume.scan_state.sqlite_shares import SharesMixin
from snaffler.resume.scan_state.sqlite_files import FilesMixin
from snaffler.resume.scan_state.sqlite_dirs_findings import DirsFindingsMixin


class StoreBase:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init()

    def _init(self):
        self.conn.execute("PRAGMA page_size=8192;")
        try:
            mode = self.conn.execute("PRAGMA journal_mode=WAL;").fetchone()[0]
            if mode.lower() not in ("wal", "memory"):
                raise RuntimeError(f"Failed to enable WAL mode (got {mode})")
        except Exception as e:
            raise SystemExit(
                f"FATAL: Cannot enable WAL journal mode on {self.path} — {e}\n"
                f"The SQLite state DB requires WAL mode for concurrent access."
            ) from e
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute("PRAGMA cache_size=-65536;")
        self.conn.execute("PRAGMA mmap_size=268435456;")

        with self.conn:
            self.conn.execute("DROP TABLE IF EXISTS checked_computer")
            self.conn.execute("DROP TABLE IF EXISTS checked_share")
            self.conn.execute("DROP TABLE IF EXISTS checked_file")

            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS sync "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS target_computer "
                "(name TEXT PRIMARY KEY COLLATE NOCASE, ip TEXT, "
                "done INTEGER DEFAULT 0)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS target_share "
                "(unc_path TEXT PRIMARY KEY COLLATE NOCASE, "
                "readable INTEGER DEFAULT NULL, "
                "done INTEGER DEFAULT 0)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS target_dir "
                "(unc_path TEXT PRIMARY KEY COLLATE NOCASE, "
                "share TEXT NOT NULL COLLATE NOCASE, "
                "walked INTEGER DEFAULT 0)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS target_file "
                "(unc_path TEXT PRIMARY KEY COLLATE NOCASE, "
                "share TEXT NOT NULL COLLATE NOCASE, "
                "size INTEGER, mtime REAL, "
                "checked INTEGER DEFAULT 0)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS finding ("
                "finding_id TEXT PRIMARY KEY, "
                "file_path  TEXT NOT NULL, "
                "triage     TEXT NOT NULL, "
                "rule_name  TEXT NOT NULL, "
                "match_text TEXT, "
                "context    TEXT, "
                "size       INTEGER, "
                "mtime      TEXT, "
                "found_at   TEXT NOT NULL"
                ")"
            )

            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_finding_triage "
                "ON finding(triage)"
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_target_dir_share "
                "ON target_dir(share)"
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_target_file_share "
                "ON target_file(share)"
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_target_file_checked "
                "ON target_file(checked) WHERE checked = 0"
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_target_dir_walked "
                "ON target_dir(walked) WHERE walked = 0"
            )
            try:
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_target_computer_done "
                    "ON target_computer(done) WHERE done = 0"
                )
            except Exception:
                pass

    # ---------- sync flags ----------

    def get_sync_flag(self, key: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM sync WHERE key = ?", (key,)
            )
            return cur.fetchone() is not None

    def set_sync_flag(self, key: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO sync VALUES (?, '1')", (key,)
            )
            self.conn.commit()

    def get_sync_value(self, key: str) -> str | None:
        with self.lock:
            cur = self.conn.execute(
                "SELECT value FROM sync WHERE key = ?", (key,)
            )
            row = cur.fetchone()
            return row[0] if row else None

    def set_sync_value(self, key: str, value: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO sync VALUES (?, ?)", (key, value)
            )
            self.conn.commit()

    def clear_phase_flags(self):
        with self.lock:
            self.conn.execute(
                "DELETE FROM sync WHERE key IN "
                "('computer_discovery_done', 'dns_resolution_done', "
                "'share_discovery_done')"
            )
            self.conn.commit()

    # ---------- close ----------

    def close(self):
        with self.lock:
            try:
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass
            try:
                self.conn.close()
            except Exception:
                pass


class SQLiteStateStore(StoreBase, ComputersMixin, SharesMixin, FilesMixin, DirsFindingsMixin):
    pass
