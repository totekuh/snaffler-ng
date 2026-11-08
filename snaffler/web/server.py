"""Flask-based live web dashboard server."""

import logging
import sqlite3
import threading
import time
from datetime import datetime
from types import SimpleNamespace

logger = logging.getLogger("snaffler")

_server_thread = None


def _check_flask():
    """Import guard — raises ImportError with install hint if Flask is missing."""
    try:
        import flask  # noqa: F401
        return flask
    except ImportError:
        raise ImportError(
            "Flask is required for --web support. "
            "Install it with: pip install snaffler-ng[web]"
        )


def _detect_phase(progress) -> str:
    """Determine the current scan phase from ProgressState counters."""
    p = progress

    # Authoritative flag set by SnafflerRunner after file_pipeline.run()
    # returns.  Counter-based inference is unreliable because the scanner
    # can temporarily catch up to files_total while the walker is still
    # discovering new files.
    if p.scan_complete:
        return "complete"

    walking = p.shares_total > 0 and p.shares_walked < p.shares_total
    scanning = p.files_total > 0

    if scanning and not walking:
        return "scanning"
    if walking:
        return "walking"

    # Share discovery active
    if p.computers_total > 0 and p.computers_done < p.computers_total:
        return "shares"

    # DNS active
    if p.dns_total > 0 and (p.dns_resolved + p.dns_filtered) < p.dns_total:
        return "dns"

    return "idle"


def _format_size(size):
    """Format file size for display."""
    if size is None:
        return ""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"


def create_app(progress, db_path, start_time, mode="live"):
    """Create and configure the Flask app.

    Args:
        progress: ProgressState instance (read-only, no DB I/O)
        db_path: Path to the SQLite state database
        start_time: datetime when the scan started
        mode: "live" for active scan, "results" for completed DB
    """
    flask = _check_flask()
    from pathlib import Path
    from snaffler.web.dashboard import render_dashboard

    static_dir = Path(__file__).parent / "static"
    app = flask.Flask(__name__, static_folder=str(static_dir), static_url_path="/static")

    # Suppress werkzeug request logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    @app.route("/")
    def index():
        resp = flask.make_response(render_dashboard(mode=mode))
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.route("/api/progress")
    def api_progress():
        snap = progress.snapshot()
        elapsed = (datetime.now() - start_time).total_seconds()
        phase = _detect_phase(SimpleNamespace(**snap))

        snap["phase"] = phase
        snap["elapsed_seconds"] = int(elapsed)
        return flask.jsonify(snap)

    @app.route("/api/stats")
    def api_stats():
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            try:
                from snaffler.cli.results import _query_stats
                stats = _query_stats(conn)
            finally:
                conn.close()
            return flask.jsonify(stats)
        except Exception as exc:
            logger.debug(f"/api/stats error: {exc}")
            return flask.jsonify({"error": "Internal server error"}), 500

    @app.route("/api/findings")
    def api_findings():
        min_interest = flask.request.args.get("min_interest", 0, type=int)
        since_rowid = flask.request.args.get("since_rowid", 0, type=int)
        limit = flask.request.args.get("limit", 0, type=int)

        # Map min_interest to allowed triage levels
        triage_order = {"Black": 0, "Red": 1, "Yellow": 2, "Green": 3}
        threshold = 3 - min_interest
        allowed = [name for name, order in triage_order.items() if order <= threshold]

        if not allowed:
            return flask.jsonify({"findings": [], "max_rowid": since_rowid, "has_more": False})

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            try:
                placeholders = ",".join("?" for _ in allowed)
                query = (
                    f"SELECT rowid, finding_id, file_path, triage, rule_name, "  # noqa: S608
                    f"match_text, context, size, mtime, found_at "
                    f"FROM finding "
                    f"WHERE triage IN ({placeholders}) AND rowid > ? "
                    f"ORDER BY rowid"
                )
                params = [*allowed, since_rowid]
                if limit > 0:
                    query += " LIMIT ?"
                    params.append(limit)

                rows = conn.execute(query, params).fetchall()

                max_rowid = since_rowid
                findings = []
                for row in rows:
                    d = dict(row)
                    rid = d.pop("rowid")
                    if rid > max_rowid:
                        max_rowid = rid
                    d["size_str"] = _format_size(d.get("size"))
                    findings.append(d)
            finally:
                conn.close()

            has_more = limit > 0 and len(findings) == limit
            return flask.jsonify({"findings": findings, "max_rowid": max_rowid, "has_more": has_more})
        except Exception as exc:
            logger.debug(f"/api/findings error: {exc}")
            return flask.jsonify({"error": "Internal server error", "findings": [], "max_rowid": since_rowid, "has_more": False}), 500

    @app.route("/api/export/csv")
    def api_export_csv():
        min_interest = flask.request.args.get("min_interest", 0, type=int)
        triage_order = {"Black": 0, "Red": 1, "Yellow": 2, "Green": 3}
        threshold = 3 - min_interest
        allowed = [name for name, order in triage_order.items() if order <= threshold]

        import csv
        import io

        def generate():
            yield "triage,rule_name,file_path,size,mtime,match_text,context\n"
            if not allowed:
                return
            try:
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                try:
                    placeholders = ",".join("?" for _ in allowed)
                    rows = conn.execute(
                        f"SELECT triage, rule_name, file_path, size, mtime, "  # noqa: S608
                        f"match_text, context FROM finding "
                        f"WHERE triage IN ({placeholders}) ORDER BY rowid",
                        allowed,
                    )
                    for row in rows:
                        buf = io.StringIO()
                        w = csv.writer(buf)
                        w.writerow([row[k] if row[k] is not None else "" for k in
                                    ("triage", "rule_name", "file_path", "size", "mtime", "match_text", "context")])
                        yield buf.getvalue()
                finally:
                    conn.close()
            except Exception as exc:
                logger.debug(f"/api/export/csv error: {exc}")

        return flask.Response(
            generate(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=snaffler_findings.csv"},
        )

    @app.route("/api/export/json")
    def api_export_json():
        min_interest = flask.request.args.get("min_interest", 0, type=int)
        triage_order = {"Black": 0, "Red": 1, "Yellow": 2, "Green": 3}
        threshold = 3 - min_interest
        allowed = [name for name, order in triage_order.items() if order <= threshold]

        findings = []
        if allowed:
            try:
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                try:
                    placeholders = ",".join("?" for _ in allowed)
                    rows = conn.execute(
                        f"SELECT finding_id, file_path, triage, rule_name, "  # noqa: S608
                        f"match_text, context, size, mtime, found_at "
                        f"FROM finding WHERE triage IN ({placeholders}) ORDER BY rowid",
                        allowed,
                    ).fetchall()
                    findings = [dict(r) for r in rows]
                finally:
                    conn.close()
            except Exception as exc:
                logger.debug(f"/api/export/json error: {exc}")

        resp = flask.jsonify({"findings": findings})
        resp.headers["Content-Disposition"] = "attachment; filename=snaffler_findings.json"
        return resp

    return app


def start_web_server(progress, db_path, start_time, port=8080):
    """Start the Flask web dashboard in a daemon thread.

    Args:
        progress: ProgressState instance
        db_path: Path to the SQLite state database
        start_time: datetime when the scan started
        port: Port to bind to (default 8080)
    """
    global _server_thread

    app = create_app(progress, db_path, start_time)

    def run():
        try:
            app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
        except OSError as exc:
            logger.error(f"Web dashboard failed to start on port {port}: {exc}")

    _server_thread = threading.Thread(target=run, daemon=True, name="web-dashboard")
    _server_thread.start()

    # Give Flask a moment to bind, then verify it's still running
    time.sleep(0.2)
    if _server_thread.is_alive():
        logger.info(f"Web dashboard: http://127.0.0.1:{port}")
    else:
        logger.warning(f"Web dashboard failed to start on port {port}")


def stop_web_server():
    """Clear the server thread reference. The daemon thread dies with the process."""
    global _server_thread
    _server_thread = None


def _make_results_progress(db_path):
    """Build a frozen ProgressState from a completed scan DB."""
    from snaffler.utils.progress import ProgressState
    from snaffler.cli.results import _query_stats

    p = ProgressState()
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            stats = _query_stats(conn)
        finally:
            conn.close()
        p.computers_total = stats["computers"]["total"]
        p.computers_done = stats["computers"]["done"]
        p.dns_total = stats["computers"]["total"]
        p.dns_resolved = stats["computers"]["resolved"]
        p.shares_found = stats["shares"]["total"]
        p.shares_total = stats["shares"]["total"]
        p.shares_walked = stats["shares"]["total"]
        p.files_total = stats["files"]["total"]
        p.files_scanned = stats["files"]["checked"]
        p.files_matched = stats["findings"]["total"]
        p.severity_black = stats["findings"]["black"]
        p.severity_red = stats["findings"]["red"]
        p.severity_yellow = stats["findings"]["yellow"]
        p.severity_green = stats["findings"]["green"]
    except Exception:
        pass
    p.scan_complete = True
    return p


def serve_results(db_path, port=8080):
    """Serve a completed scan DB through the web dashboard (blocks until Ctrl+C)."""
    import os
    _check_flask()
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database not found: {db_path}")

    progress = _make_results_progress(db_path)
    app = create_app(progress, db_path, datetime.now(), mode="results")

    print(f"Serving results: http://127.0.0.1:{port} (Ctrl+C to stop)")
    try:
        import logging as _logging
        _logging.getLogger("werkzeug").setLevel(_logging.CRITICAL)
        app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
    except OSError as exc:
        logger.error(f"Web dashboard failed to start on port {port}: {exc}")
