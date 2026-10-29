"""SQLiteStateStore mixin — computer operations."""


class ComputersMixin:

    def store_computers(self, computers: list):
        with self.lock:
            self.conn.executemany(
                "INSERT OR IGNORE INTO target_computer (name) VALUES (?)",
                [(c,) for c in computers],
            )
            self.conn.commit()

    def load_computers(self) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT name FROM target_computer"
            ).fetchall()
            return [r[0] for r in rows]

    def update_computer_ip(self, name: str, ip: str):
        with self.lock:
            self.conn.execute(
                "UPDATE target_computer SET ip = ? WHERE name = ?",
                (ip, name),
            )
            self.conn.commit()

    def load_resolved_computers(self) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT name FROM target_computer WHERE ip IS NOT NULL"
            ).fetchall()
            return [r[0] for r in rows]

    def load_unresolved_computers(self) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT name FROM target_computer WHERE ip IS NULL"
            ).fetchall()
            return [r[0] for r in rows]

    def has_checked_computer(self, name: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "SELECT done FROM target_computer WHERE name = ?", (name,)
            )
            row = cur.fetchone()
            return row is not None and row[0] == 1

    def mark_computer_checked(self, name: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO target_computer (name) VALUES (?)",
                (name,),
            )
            self.conn.execute(
                "UPDATE target_computer SET done = 1 WHERE name = ?",
                (name,),
            )
            self.conn.commit()

    def count_checked_computers(self) -> int:
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM target_computer WHERE done = 1"
            ).fetchone()[0]
