"""SQLiteStateStore mixin — share operations."""


class SharesMixin:

    def store_shares(self, shares: list):
        """Store shares. Accepts plain strings or (unc_path, readable) tuples."""
        with self.lock:
            for item in shares:
                if isinstance(item, tuple):
                    unc_path, readable = item
                    self.conn.execute(
                        "INSERT INTO target_share (unc_path, readable) VALUES (?, ?) "
                        "ON CONFLICT(unc_path) DO UPDATE SET readable = ?",
                        (unc_path, int(readable), int(readable)),
                    )
                else:
                    self.conn.execute(
                        "INSERT OR IGNORE INTO target_share (unc_path) VALUES (?)",
                        (item,),
                    )
            self.conn.commit()

    def load_shares(self) -> list:
        """Load readable shares (readable=1 or readable=NULL for backwards compat)."""
        with self.lock:
            rows = self.conn.execute(
                "SELECT unc_path FROM target_share WHERE readable IS NULL OR readable = 1"
            ).fetchall()
            return [r[0] for r in rows]

    def load_unreadable_shares(self) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT unc_path FROM target_share WHERE readable = 0"
            ).fetchall()
            return [r[0] for r in rows]

    def update_share_readable(self, unc_path: str):
        with self.lock:
            self.conn.execute(
                "UPDATE target_share SET readable = 1 WHERE unc_path = ?",
                (unc_path,),
            )
            self.conn.commit()

    def has_checked_share(self, unc_path: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "SELECT done FROM target_share WHERE unc_path = ?",
                (unc_path,),
            )
            row = cur.fetchone()
            return row is not None and row[0] == 1

    def mark_share_checked(self, unc_path: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO target_share (unc_path) VALUES (?)",
                (unc_path,),
            )
            self.conn.execute(
                "UPDATE target_share SET done = 1 WHERE unc_path = ?",
                (unc_path,),
            )
            self.conn.commit()

    def count_checked_shares(self) -> int:
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM target_share WHERE done = 1"
            ).fetchone()[0]
