"""Database queries for scan results."""

import sqlite3
from pathlib import Path

import typer

from snaffler.utils.logger import Colors

TRIAGE_ORDER = {"Black": 0, "Red": 1, "Yellow": 2, "Green": 3}
TRIAGE_COLORS = {
    "Black": Colors.BLACK + Colors.BOLD,
    "Red": Colors.RED + Colors.BOLD,
    "Yellow": Colors.YELLOW + Colors.BOLD,
    "Green": Colors.GREEN,
}


def _open_db(path: Path) -> sqlite3.Connection:
    if not path.exists():
        typer.echo(f"Error: database not found: {path}", err=True)
        raise typer.Exit(code=1)
    try:
        # Open read-write (default) so SQLite can recover/read WAL data.
        # The scanner uses WAL journal mode; after Ctrl+C the committed
        # findings may still be in the -wal file.  A ?mode=ro connection
        # cannot create the -shm file needed to read the WAL, so it would
        # silently miss those findings.
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.OperationalError as exc:
        typer.echo(f"Error: cannot open database: {exc}", err=True)
        raise typer.Exit(code=1)


def _query_stats(conn: sqlite3.Connection) -> dict:
    def _count(table, col=None, val=None):
        if col:
            total = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
            done = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {col} = ?", (val,)  # noqa: S608
            ).fetchone()[0]
            return {"total": total, "done": done}
        return {"total": conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]}  # noqa: S608

    stats = {}

    # Computers
    comp = _count("target_computer", "done", 1)
    resolved = conn.execute(
        "SELECT COUNT(*) FROM target_computer WHERE ip IS NOT NULL"
    ).fetchone()[0]
    comp["resolved"] = resolved
    stats["computers"] = comp

    # Shares
    share_stats = _count("target_share", "done", 1)
    try:
        unreadable = conn.execute(
            "SELECT COUNT(*) FROM target_share WHERE readable = 0"
        ).fetchone()[0]
    except Exception:
        unreadable = 0
    share_stats["unreadable"] = unreadable
    stats["shares"] = share_stats

    # Directories
    dir_stats = _count("target_dir", "walked", 1)
    stats["directories"] = {"total": dir_stats["total"], "walked": dir_stats["done"]}

    # Files
    file_stats = _count("target_file", "checked", 1)
    stats["files"] = {"total": file_stats["total"], "checked": file_stats["done"]}

    # Findings by triage
    rows = conn.execute(
        "SELECT triage, COUNT(*) as cnt FROM finding GROUP BY triage"
    ).fetchall()
    triage_counts = {row["triage"]: row["cnt"] for row in rows}
    finding_total = sum(triage_counts.values())
    stats["findings"] = {
        "total": finding_total,
        "black": triage_counts.get("Black", 0),
        "red": triage_counts.get("Red", 0),
        "yellow": triage_counts.get("Yellow", 0),
        "green": triage_counts.get("Green", 0),
    }

    return stats


def _query_unreadable_shares(conn: sqlite3.Connection) -> list:
    try:
        rows = conn.execute(
            "SELECT unc_path FROM target_share WHERE readable = 0 ORDER BY unc_path"
        ).fetchall()
        return [row[0] for row in rows]
    except Exception:
        return []


def _query_findings(conn: sqlite3.Connection, min_interest: int) -> list:
    # Map min_interest (0=Green+, 1=Yellow+, 2=Red+, 3=Black only) to triage names
    threshold = 3 - min_interest  # Green=0→3, Yellow=1→2, Red=2→1, Black=3→0
    allowed = [name for name, order in TRIAGE_ORDER.items() if order <= threshold]

    if not allowed:
        return []

    placeholders = ",".join("?" for _ in allowed)
    rows = conn.execute(
        f"SELECT finding_id, file_path, triage, rule_name, "  # noqa: S608
        f"match_text, context, size, mtime, found_at "
        f"FROM finding WHERE triage IN ({placeholders}) "
        f"ORDER BY found_at",
        allowed,
    ).fetchall()

    findings = [dict(row) for row in rows]
    findings.sort(key=lambda f: TRIAGE_ORDER.get(f["triage"], 99))
    return findings


def _query_rule_counts(conn: sqlite3.Connection, min_interest: int = 0) -> list:
    """Return [(rule_name, triage, count)] sorted by count descending."""
    threshold = 3 - min_interest  # Green=0→3, Yellow=1→2, Red=2→1, Black=3→0
    allowed = [name for name, order in TRIAGE_ORDER.items() if order <= threshold]
    if not allowed:
        return []

    placeholders = ",".join("?" for _ in allowed)
    rows = conn.execute(
        f"SELECT rule_name, triage, COUNT(*) as cnt "  # noqa: S608
        f"FROM finding WHERE triage IN ({placeholders}) "
        f"GROUP BY rule_name, triage "
        f"ORDER BY cnt DESC",
        allowed,
    ).fetchall()
    return [(row[0], row[1], row[2]) for row in rows]
