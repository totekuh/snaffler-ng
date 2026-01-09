import sqlite3
import threading


class ScanState:
    def __init__(self, store):
        self.store = store
        self.aborted = False  # reserved for cooperative shutdown

    def should_skip(self, unc_path: str) -> bool:
        return self.store.has_seen(unc_path)

    def mark_done(self, unc_path: str):
        self.store.mark_seen(unc_path)

    def close(self):
        if hasattr(self.store, "close"):
            self.store.close()


class SQLiteStateStore:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.conn:
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS seen_files (
                    unc_path TEXT PRIMARY KEY
                )
            """)

    def has_seen(self, unc_path: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM seen_files WHERE unc_path = ?",
                (unc_path,),
            )
            return cur.fetchone() is not None

    def mark_seen(self, unc_path: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO seen_files VALUES (?)",
                (unc_path,),
            )
            self.conn.commit()

    def close(self):
        with self.lock:
            self.conn.close()
