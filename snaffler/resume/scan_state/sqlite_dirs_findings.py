"""SQLiteStateStore mixin — directory and finding operations."""

from snaffler.utils.path_utils import extract_share_root as _extract_share


class DirsFindingsMixin:

    # ---------- directories ----------

    def store_dir(self, unc_path: str, share: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO target_dir (unc_path, share) VALUES (?, ?)",
                (unc_path, share),
            )
            self.conn.commit()

    def store_dirs(self, dirs: list):
        with self.lock:
            self.conn.executemany(
                "INSERT OR IGNORE INTO target_dir (unc_path, share) VALUES (?, ?)",
                dirs,
            )
            self.conn.commit()

    def mark_dir_walked(self, unc_path: str):
        with self.lock:
            share = _extract_share(unc_path)
            self.conn.execute(
                "INSERT INTO target_dir (unc_path, share, walked) VALUES (?, ?, 1) "
                "ON CONFLICT(unc_path) DO UPDATE SET walked = 1",
                (unc_path, share),
            )
            self.conn.commit()

    def load_unwalked_dirs(self, share: str | None = None) -> list:
        with self.lock:
            if share is not None:
                rows = self.conn.execute(
                    "SELECT unc_path FROM target_dir WHERE walked = 0 AND share = ?",
                    (share,),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT unc_path FROM target_dir WHERE walked = 0"
                ).fetchall()
            return [r[0] for r in rows]

    def load_walked_dirs(self) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT unc_path FROM target_dir WHERE walked = 1"
            ).fetchall()
            return [r[0] for r in rows]

    # ---------- findings ----------

    def store_finding(
        self,
        finding_id: str,
        file_path: str,
        triage: str,
        rule_name: str,
        match_text: str = None,
        context: str = None,
        size: int = None,
        mtime: str = None,
        found_at: str = None,
    ):
        from datetime import datetime

        if found_at is None:
            found_at = datetime.now().isoformat()
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO finding "
                "(finding_id, file_path, triage, rule_name, match_text, "
                "context, size, mtime, found_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding_id,
                    file_path,
                    triage,
                    rule_name,
                    match_text,
                    context,
                    size,
                    mtime,
                    found_at,
                ),
            )
            self.conn.commit()

    def load_findings(self) -> list:
        with self.lock:
            cur = self.conn.execute(
                "SELECT finding_id, file_path, triage, rule_name, "
                "match_text, context, size, mtime, found_at "
                "FROM finding ORDER BY found_at"
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def count_findings(self) -> int:
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM finding"
            ).fetchone()[0]

    def count_findings_by_triage(self) -> dict:
        """Return {triage_label: count} for all findings."""
        with self.lock:
            rows = self.conn.execute(
                "SELECT triage, COUNT(*) FROM finding GROUP BY triage"
            ).fetchall()
            return {row[0]: row[1] for row in rows}
