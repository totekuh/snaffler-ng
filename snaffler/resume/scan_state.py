import sqlite3
import threading


class ScanState:
    def __init__(self, store):
        self.store = store
        self.aborted = False  # reserved for cooperative shutdown

    # ---------- files ----------

    def should_skip_file(self, unc_path: str) -> bool:
        return self.store.has_checked_file(unc_path)

    def mark_file_done(self, unc_path: str):
        self.store.mark_file_checked(unc_path)

    # ---------- dirs ----------

    def should_skip_dir(self, unc_path: str) -> bool:
        return self.store.has_checked_dir(unc_path)

    def mark_dir_done(self, unc_path: str):
        self.store.mark_dir_checked(unc_path)

    def close(self):
        self.store.close()


class SQLiteStateStore:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init()

    def _init(self):
        with self.conn:
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")

            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS checked_files (
                    unc_path TEXT PRIMARY KEY
                )
            """)

            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS checked_dirs (
                    unc_path TEXT PRIMARY KEY
                )
            """)

    # ---------- files ----------

    def has_checked_file(self, unc_path: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM checked_files WHERE unc_path = ?",
                (unc_path,),
            )
            return cur.fetchone() is not None

    def mark_file_checked(self, unc_path: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO checked_files VALUES (?)",
                (unc_path,),
            )
            self.conn.commit()

    # ---------- dirs ----------

    def has_checked_dir(self, unc_path: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM checked_dirs WHERE unc_path = ?",
                (unc_path,),
            )
            return cur.fetchone() is not None

    def mark_dir_checked(self, unc_path: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO checked_dirs VALUES (?)",
                (unc_path,),
            )
            self.conn.commit()

    def close(self):
        with self.lock:
            self.conn.close()
