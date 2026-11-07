"""CLI commands for the results subapp."""

import json
import sys
from pathlib import Path
from typing import Optional

import click
import typer

from snaffler.utils.logger import Colors
from snaffler.cli.results.queries import (
    TRIAGE_COLORS,
    _open_db,
    _query_findings,
    _query_rule_counts,
    _query_stats,
    _query_unreadable_shares,
)
from snaffler.cli.results.render_plain import _render_plain, _render_json
from snaffler.cli.results.render_html import _render_html
from snaffler.cli.results.import_export import (
    _detect_format,
    _ensure_state_db,
    _export_db,
    _export_json,
    _import_db,
    _import_json,
)

results_app = typer.Typer(
    help="Display stats and findings from a scan database",
    add_completion=False,
)


@results_app.callback(invoke_without_command=True)
def results(
    ctx: typer.Context,
    state: Path = typer.Option(
        Path("snaffler.db"),
        "-s", "--state",
        help="Path to the scan state database",
    ),
    fmt: Optional[str] = typer.Option(
        "plain",
        "-f", "--format",
        help="Output format",
        click_type=click.Choice(["plain", "json", "html"], case_sensitive=False),
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable colored output",
    ),
    min_interest: int = typer.Option(
        0,
        "-b", "--min-interest",
        help="Minimum severity to show (0=all, 1=Yellow+, 2=Red+, 3=Black only)",
        min=0,
        max=3,
    ),
    rule: Optional[list[str]] = typer.Option(
        None,
        "--rule", "-r",
        help="Filter findings by rule name (repeatable)",
    ),
    hide_unreadable: bool = typer.Option(
        False,
        "--hide-unreadable", "-hu",
        help="Hide unreadable shares section",
    ),
    files: bool = typer.Option(
        False,
        "--files",
        help="Print one file path per line (pipe into --grab)",
    ),
):
    # Store shared options for subcommands
    ctx.ensure_object(dict)
    ctx.obj["state"] = state
    ctx.obj["no_color"] = no_color
    ctx.obj["min_interest"] = min_interest

    # If a subcommand is being invoked, skip the default results display
    if ctx.invoked_subcommand is not None:
        return

    conn = _open_db(state)
    try:
        findings = _query_findings(conn, min_interest)
        if not files:
            stats = _query_stats(conn)
            unreadable = [] if hide_unreadable else _query_unreadable_shares(conn)
    finally:
        conn.close()

    # Apply --rule filter
    if rule:
        rule_set = {r.lower() for r in rule}
        findings = [f for f in findings if f["rule_name"].lower() in rule_set]

    if files:
        for f in findings:
            typer.echo(f["file_path"])
        return

    if fmt == "json":
        _render_json(stats, findings, unreadable)
    elif fmt == "html":
        typer.echo(_render_html(stats, findings, unreadable))
    else:
        use_color = not no_color and sys.stdout.isatty()
        _render_plain(stats, findings, unreadable, use_color)


@results_app.command()
def rules(
    ctx: typer.Context,
    fmt: Optional[str] = typer.Option(
        "plain",
        "-f", "--format",
        help="Output format",
        click_type=click.Choice(["plain", "json"], case_sensitive=False),
    ),
):
    """List all matching rules and their finding counts."""
    obj = ctx.ensure_object(dict)
    state = obj.get("state", Path("snaffler.db"))
    no_color = obj.get("no_color", False)
    min_interest = obj.get("min_interest", 0)

    conn = _open_db(state)
    try:
        rule_counts = _query_rule_counts(conn, min_interest)
    finally:
        conn.close()

    if fmt == "json":
        output = [
            {"rule_name": name, "triage": triage, "count": cnt}
            for name, triage, cnt in rule_counts
        ]
        typer.echo(json.dumps(output, indent=2))
        return

    if not rule_counts:
        typer.echo("No findings in database.")
        return

    use_color = not no_color and sys.stdout.isatty()
    total = sum(cnt for _, _, cnt in rule_counts)
    lines = [f"{'── Rules (' + str(len(rule_counts)) + ' rules, ' + str(total) + ' findings) ':─<60}"]

    for rule_name, triage, count in rule_counts:
        if use_color:
            color = TRIAGE_COLORS.get(triage, "")
            lines.append(f"  {color}[{triage}]{Colors.RESET} {rule_name}: {count:,}")
        else:
            lines.append(f"  [{triage}] {rule_name}: {count:,}")

    typer.echo("\n".join(lines))


@results_app.command("export")
def export_results(
    output: str = typer.Argument(..., help="Output file path (.db or .json)"),
    state_file: str = typer.Option(
        "snaffler.db", "--state-file", "-s", help="State DB to export from"
    ),
    format: str = typer.Option(
        None, "--format", "-f", help="Output format (db/json). Auto-detected from extension."
    ),
):
    """Export scan results as a gzip-compressed DB or JSON file."""
    if not Path(state_file).exists():
        typer.echo(f"Error: state database not found: {state_file}", err=True)
        raise typer.Exit(code=1)

    fmt = _detect_format(output, format)

    if fmt == "db":
        _export_db(state_file, output)
        typer.echo(f"Exported state DB to {output} (gzip compressed)")
    else:
        count = _export_json(state_file, output)
        typer.echo(f"Exported {count} findings to {output} (gzip compressed)")


@results_app.command("import")
def import_results(
    input_path: str = typer.Argument(..., help="State DB or JSON file to import from"),
    state_file: str = typer.Option(
        "snaffler.db", "--state-file", "-s", help="Target state DB to merge into"
    ),
):
    """Import and merge findings from another scan DB or JSON export."""
    if not Path(input_path).exists():
        typer.echo(f"Error: input file not found: {input_path}", err=True)
        raise typer.Exit(code=1)

    _ensure_state_db(state_file)

    ext = Path(input_path).suffix.lower()
    if ext == ".json":
        imported = _import_json(input_path, state_file)
    else:
        imported = _import_db(input_path, state_file)

    typer.echo(f"Imported {imported} new findings from {input_path}")
