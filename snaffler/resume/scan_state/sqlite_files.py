"""SQLiteStateStore mixin — file operations."""

from snaffler.utils.path_utils import extract_share_root as _extract_share


class FilesMixin:

    def load_checked_files(self) -> set:
        with self.lock:
            rows = self.conn.execute(
                "SELECT unc_path FROM target_file WHERE checked = 1"
            ).fetchall()
            return {r[0].lower() for r in rows}

    def iter_checked_file_keys(self):
        """Yield lowercased paths of checked files for bloom filter seeding."""
        with self.lock:
            cursor = self.conn.execute(
                "SELECT unc_path FROM target_file WHERE checked = 1"
            )
            while True:
                batch = cursor.fetchmany(10000)
                if not batch:
                    break
                for row in batch:
                    yield row[0].lower()

    def is_file_checked(self, path_lower: str) -> bool:
        """Check if a specific file is marked as checked in the DB."""
        with self.lock:
            row = self.conn.execute(
                "SELECT 1 FROM target_file WHERE unc_path = ? AND checked = 1",
                (path_lower,),
            ).fetchone()
            return row is not None

    def mark_file_checked(self, unc_path: str):
        with self.lock:
            share = _extract_share(unc_path)
            self.conn.execute(
                "INSERT OR IGNORE INTO target_file (unc_path, share) VALUES (?, ?)",
                (unc_path, share),
            )
            self.conn.execute(
                "UPDATE target_file SET checked = 1 WHERE unc_path = ?",
                (unc_path,),
            )
            self.conn.commit()

    def mark_files_checked_batch(self, paths: list):
        """Mark multiple files as checked in one transaction.

        Uses an upsert (ON CONFLICT ... DO UPDATE) so it handles the race
        with BatchWriter file inserts that may not have flushed yet.
        """
        with self.lock:
            for unc_path in paths:
                share = _extract_share(unc_path)
                self.conn.execute(
                    "INSERT INTO target_file (unc_path, share, checked) "
                    "VALUES (?, ?, 1) "
                    "ON CONFLICT(unc_path) DO UPDATE SET checked = 1",
                    (unc_path, share),
                )
            self.conn.commit()

    def store_file(self, unc_path: str, share: str, size: int = 0, mtime: float = 0.0):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO target_file "
                "(unc_path, share, size, mtime) VALUES (?, ?, ?, ?)",
                (unc_path, share, size, mtime),
            )
            self.conn.commit()

    def store_files(self, files: list):
        with self.lock:
            self.conn.executemany(
                "INSERT OR IGNORE INTO target_file "
                "(unc_path, share, size, mtime) VALUES (?, ?, ?, ?)",
                files,
            )
            self.conn.commit()

    def load_unchecked_files(self) -> list:
        with self.lock:
            result = []
            cursor = self.conn.execute(
                "SELECT unc_path, size, mtime FROM target_file WHERE checked = 0"
            )
            while True:
                batch = cursor.fetchmany(5000)
                if not batch:
                    break
                result.extend((r[0], r[1], r[2]) for r in batch)
            return result

    def iter_unchecked_files(self):
        """Yield unchecked files in batches (generator).

        Uses LIMIT/OFFSET pagination so the lock is only held briefly per
        batch, and memory usage stays bounded even with millions of rows.
        """
        offset = 0
        batch_size = 10000
        while True:
            with self.lock:
                rows = self.conn.execute(
                    "SELECT unc_path, size, mtime FROM target_file "
                    "WHERE checked = 0 LIMIT ? OFFSET ?",
                    (batch_size, offset),
                ).fetchall()
            if not rows:
                break
            for r in rows:
                yield (r[0], r[1], r[2])
            offset += len(rows)

    def count_target_files(self) -> int:
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM target_file"
            ).fetchone()[0]

    def count_checked_files(self) -> int:
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM target_file WHERE checked = 1"
            ).fetchone()[0]
