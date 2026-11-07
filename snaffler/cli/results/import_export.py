"""Import/export helpers for scan result databases."""

import json
import sqlite3
from pathlib import Path

import typer


def _detect_format(output_path: str, explicit_format: str | None) -> str:
    """Auto-detect format from file extension, or use explicit format."""
    if explicit_format:
        fmt = explicit_format.lower()
        if fmt not in ("db", "json"):
            typer.echo(f"Error: unsupported format '{explicit_format}'. Use 'db' or 'json'.", err=True)
            raise typer.Exit(code=1)
        return fmt
    ext = Path(output_path).suffix.lower()
    if ext == ".db":
        return "db"
    if ext == ".json":
        return "json"
    typer.echo(
        f"Error: cannot detect format from extension '{ext}'. "
        "Use --format db or --format json, or use a .db/.json extension.",
        err=True,
    )
    raise typer.Exit(code=1)


def _export_db(state_file: str, output: str):
    """Export state DB as a gzip-compressed, clean SQLite file (no WAL sidecar)."""
    import gzip
    import shutil
    import tempfile

    output_path = Path(output)
    if output_path.exists():
        output_path.unlink()

    conn = sqlite3.connect(state_file)
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        # VACUUM INTO a temp file first, then gzip to output
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            try:
                conn.execute("VACUUM INTO ?", (tmp_path,))
            except sqlite3.OperationalError:
                conn.close()
                shutil.copy2(state_file, tmp_path)
                copy_conn = sqlite3.connect(tmp_path)
                try:
                    copy_conn.execute("PRAGMA journal_mode=DELETE")
                finally:
                    copy_conn.close()

            # Gzip compress
            with open(tmp_path, "rb") as f_in, gzip.open(output, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _export_json(state_file: str, output: str) -> int:
    """Export findings as gzip-compressed JSON. Returns finding count."""
    import gzip

    conn = sqlite3.connect(state_file)
    try:
        stats = {
            "computers": conn.execute("SELECT COUNT(*) FROM target_computer").fetchone()[0],
            "shares": conn.execute("SELECT COUNT(*) FROM target_share").fetchone()[0],
            "files_scanned": conn.execute(
                "SELECT COUNT(*) FROM target_file WHERE checked = 1"
            ).fetchone()[0],
            "findings": conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0],
        }

        cursor = conn.execute(
            "SELECT finding_id, file_path, triage, rule_name, match_text, "
            "context, size, mtime, found_at FROM finding ORDER BY triage, file_path"
        )

        with gzip.open(output, "wt", encoding="utf-8") as f:
            f.write("{\n")
            f.write(f'  "stats": {json.dumps(stats)},\n')
            f.write('  "findings": [\n')
            first = True
            while True:
                batch = cursor.fetchmany(1000)
                if not batch:
                    break
                for row in batch:
                    finding = {
                        "id": row[0],
                        "file_path": row[1],
                        "triage": row[2],
                        "rule_name": row[3],
                        "match": row[4],
                        "context": row[5],
                        "size": row[6],
                        "mtime": row[7],
                        "found_at": row[8],
                    }
                    if not first:
                        f.write(",\n")
                    f.write(f"    {json.dumps(finding)}")
                    first = False
            f.write("\n  ]\n")
            f.write("}\n")
    finally:
        conn.close()

    return stats["findings"]


def _is_gzip(path: str) -> bool:
    """Check if a file starts with the gzip magic bytes."""
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"\x1f\x8b"
    except OSError:
        return False


def _decompress_to_temp(path: str) -> str:
    """Decompress a gzip file to a temp file. Caller must delete it."""
    import gzip
    import shutil
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        with gzip.open(path, "rb") as f_in, open(tmp_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    except Exception:
        Path(tmp_path).unlink(missing_ok=True)
        raise
    return tmp_path


def _import_db(input_path: str, state_file: str) -> int:
    """Merge findings from another scan DB (plain or gzip-compressed)."""
    if _is_gzip(input_path):
        actual_path = _decompress_to_temp(input_path)
        cleanup = True
    else:
        actual_path = input_path
        cleanup = False

    try:
        conn = sqlite3.connect(state_file)
        try:
            conn.execute("ATTACH DATABASE ? AS import_db", (actual_path,))

            imported = conn.execute(
                "INSERT OR IGNORE INTO finding "
                "SELECT * FROM import_db.finding"
            ).rowcount

            conn.execute(
                "INSERT OR IGNORE INTO target_computer (name, ip, done) "
                "SELECT name, ip, done FROM import_db.target_computer"
            )

            conn.execute(
                "INSERT OR IGNORE INTO target_share (unc_path, readable, done) "
                "SELECT unc_path, readable, done FROM import_db.target_share"
            )

            conn.commit()
            conn.execute("DETACH DATABASE import_db")
        finally:
            conn.close()
    finally:
        if cleanup:
            Path(actual_path).unlink(missing_ok=True)

    return imported


def _import_json(input_path: str, state_file: str) -> int:
    """Import findings from a JSON export file (plain or gzip-compressed)."""
    import gzip

    if _is_gzip(input_path):
        with gzip.open(input_path, "rt", encoding="utf-8") as f:
            data = json.load(f)
    else:
        with open(input_path) as f:
            data = json.load(f)

    conn = sqlite3.connect(state_file)
    try:
        imported = 0
        for finding in data.get("findings", []):
            cursor = conn.execute(
                "INSERT OR IGNORE INTO finding "
                "(finding_id, file_path, triage, rule_name, match_text, "
                "context, size, mtime, found_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding["id"],
                    finding["file_path"],
                    finding["triage"],
                    finding["rule_name"],
                    finding.get("match"),
                    finding.get("context"),
                    finding.get("size"),
                    finding.get("mtime"),
                    finding.get("found_at"),
                ),
            )
            imported += cursor.rowcount
        conn.commit()
    finally:
        conn.close()

    return imported


def _ensure_state_db(state_file: str):
    """Create the state DB with schema if it doesn't exist (for imports)."""
    from snaffler.resume.scan_state import SQLiteStateStore

    store = SQLiteStateStore(state_file)
    store.close()
