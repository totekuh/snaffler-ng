"""Plain-text and JSON renderers for scan results."""

import json

import typer

from snaffler.utils.logger import Colors, format_size
from snaffler.cli.results.queries import TRIAGE_COLORS


def _render_plain(stats: dict, findings: list, unreadable_shares: list, use_color: bool):
    lines = []

    lines.append(f"{'── Stats ':─<50}")
    c = stats["computers"]
    lines.append(
        f"Computers:   {c['total']:,} discovered, {c['resolved']:,} resolved, {c['done']:,} done"
    )
    s = stats["shares"]
    share_line = f"Shares:      {s['total']:,} discovered, {s['done']:,} done"
    if s.get("unreadable"):
        share_line += f", {s['unreadable']:,} unreadable"
    lines.append(share_line)
    d = stats["directories"]
    lines.append(f"Directories: {d['total']:,} discovered, {d['walked']:,} walked")
    f = stats["files"]
    lines.append(f"Files:       {f['total']:,} discovered, {f['checked']:,} checked")

    lines.append("")
    fc = stats["findings"]
    lines.append(f"{'── Findings (' + str(fc['total']) + ') ':─<50}")

    if use_color:
        severity_parts = [
            f"{TRIAGE_COLORS['Black']}Black: {fc['black']}{Colors.RESET}",
            f"{TRIAGE_COLORS['Red']}Red: {fc['red']}{Colors.RESET}",
            f"{TRIAGE_COLORS['Yellow']}Yellow: {fc['yellow']}{Colors.RESET}",
            f"{TRIAGE_COLORS['Green']}Green: {fc['green']}{Colors.RESET}",
        ]
    else:
        severity_parts = [
            f"Black: {fc['black']}",
            f"Red: {fc['red']}",
            f"Yellow: {fc['yellow']}",
            f"Green: {fc['green']}",
        ]
    lines.append(" " + " | ".join(severity_parts))
    lines.append("")

    for finding in findings:
        triage = finding["triage"]
        rule = finding["rule_name"]
        path = finding["file_path"]
        size = finding["size"]

        size_str = f"[{format_size(size)}]" if size is not None else ""

        if use_color:
            color = TRIAGE_COLORS.get(triage, "")
            line = f"{color}[{triage}]{Colors.RESET} [{rule}] {size_str} {Colors.BOLD}{path}{Colors.RESET}"
        else:
            line = f"[{triage}] [{rule}] {size_str} {path}"

        lines.append(line)

        ctx = finding.get("context")
        if ctx:
            preview = ctx[:200] + ("..." if len(ctx) > 200 else "")
            lines.append(f"  Context: {preview}")

    if unreadable_shares:
        lines.append("")
        lines.append(f"{'── Unreadable Shares (' + str(len(unreadable_shares)) + ') ':─<50}")
        lines.append(" Use --rescan-unreadable with new creds to retry these:")
        for share in unreadable_shares:
            lines.append(f"  {share}")

    typer.echo("\n".join(lines))


def _render_json(stats: dict, findings: list, unreadable_shares: list):
    output = {"stats": stats, "findings": findings, "unreadable_shares": unreadable_shares}
    typer.echo(json.dumps(output, indent=2, default=str))
