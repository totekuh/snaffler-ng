"""HTML report renderer for scan results."""

import html
import json
from datetime import datetime, timezone

from snaffler.utils.logger import format_size
from snaffler.utils.path_utils import extract_unc_host
from snaffler.cli.results.render_html_assets import CSS_STYLES, JS_SCRIPT


TRIAGE_HTML_COLORS = {
    "Black": "#888",
    "Red": "#e74c3c",
    "Yellow": "#f1c40f",
    "Green": "#27ae60",
}


def _render_unreadable_html(shares: list) -> str:
    if not shares:
        return ""
    esc = html.escape
    items = "\n".join(f"<li>{esc(s)}</li>" for s in shares)
    return (
        f'<h2>Unreadable Shares ({len(shares):,})</h2>'
        f'<p style="color:#888;font-size:0.85em;">Use <code>--rescan-unreadable</code> with new creds to retry these.</p>'
        f'<ul style="color:#e74c3c;font-size:0.9em;">{items}</ul>'
    )


def _render_html(stats: dict, findings: list, unreadable_shares: list | None = None) -> str:
    esc = html.escape
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    c = stats["computers"]
    s = stats["shares"]
    d = stats["directories"]
    f = stats["files"]
    fc = stats["findings"]

    def _stat_card(label, done, total):
        return (
            f'<div class="card">'
            f'<div class="card-value">{done:,} / {total:,}</div>'
            f'<div class="card-label">{esc(label)}</div>'
            f'</div>'
        )

    def _badge(triage, clickable=False):
        color = TRIAGE_HTML_COLORS.get(triage, "#888")
        data = f' data-triage="{esc(triage)}"' if clickable else ''
        return f'<span class="badge"{data} style="background:{color}">{esc(triage)}</span>'

    def _stat_card_sub(label, done, total, sub_label=None, sub_value=None):
        sub = ""
        if sub_value:
            sub = f'<div class="card-sub">{sub_value:,} {esc(sub_label)}</div>'
        return (
            f'<div class="card">'
            f'<div class="card-value">{done:,} / {total:,}</div>'
            f'<div class="card-label">{esc(label)}</div>'
            f'{sub}'
            f'</div>'
        )

    cards = (
        _stat_card("Computers", c["done"], c["total"])
        + _stat_card_sub("Shares", s["done"], s["total"], "unreadable", s.get("unreadable", 0))
        + _stat_card("Directories", d["walked"], d["total"])
        + _stat_card("Files", f["checked"], f["total"])
    )

    severity_badges = ""
    for name in ("Black", "Red", "Yellow", "Green"):
        count = fc.get(name.lower(), 0)
        severity_badges += (
            f'<div class="severity">{_badge(name, clickable=True)} <span>{count:,}</span></div>\n'
        )

    # Full match/context stored in a JS array for the modal (keyed by row index).
    # Prevents large text from bloating data-* attributes and keeps them out of
    # the visible DOM where truncation tests can check them independently.
    modal_data_json = json.dumps([
        {
            "match": finding.get("match_text") or "",
            "context": finding.get("context") or "",
        }
        for finding in findings
    ]).replace("</", "<\\/")  # prevent </script> injection

    rows = ""
    for idx, finding in enumerate(findings):
        triage = finding["triage"]
        ctx = finding.get("context") or ""
        match_text = finding.get("match_text") or ""
        size = finding["size"]
        size_str = format_size(size) if size is not None else ""
        mtime_str = str(finding.get('mtime') or '')

        ctx_display = ctx[:200] + ("…" if len(ctx) > 200 else "")
        match_display = match_text[:120] + ("…" if len(match_text) > 120 else "")
        match_html = f'<span class="match">{esc(match_display)}</span>' if match_text else ""

        finding_id = finding.get("finding_id") or f"f{idx}"
        # Extract host from UNC path (//HOST/SHARE/...) or FTP URL (ftp://HOST:PORT/...)
        file_path = finding["file_path"]
        host = extract_unc_host(file_path) or ""
        if not host and file_path.startswith("ftp://"):
            rest = file_path[6:]
            slash_idx = rest.find("/")
            host = rest[:slash_idx] if slash_idx != -1 else rest

        rows += (
            f'<tr data-idx="{idx}" data-id="{esc(finding_id)}" data-triage="{esc(triage)}" '
            f'data-rule="{esc(finding["rule_name"])}" '
            f'data-host="{esc(host)}" '
            f'data-path="{esc(file_path)}" '
            f'data-size="{esc(size_str)}" '
            f'data-mtime="{esc(mtime_str)}" data-status="">'
            f'<td class="status-cell"></td>'
            f"<td>{_badge(triage)}</td>"
            f"<td>{esc(finding['rule_name'])}</td>"
            f"<td>{esc(host)}</td>"
            f'<td class="path">{esc(finding["file_path"])}</td>'
            f"<td>{esc(size_str)}</td>"
            f"<td>{esc(mtime_str)}</td>"
            f'<td class="context">{esc(ctx_display)}{match_html}</td>'
            f"</tr>\n"
        )

    css_styles = CSS_STYLES
    js_script = JS_SCRIPT

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Snaffler Scan Report</title>
<style>
{css_styles}</style>
</head>
<body>
<h1>Snaffler Scan Report</h1>
<div class="timestamp">Generated {esc(timestamp)}</div>

<div class="cards">
{cards}
</div>

<div class="toolbar">
  <div class="severities">
{severity_badges}  </div>
  <div class="status-btns">
    <button class="status-btn" data-status-filter="review">Review Later</button>
    <button class="status-btn" data-status-filter="done">Done</button>
    <button class="status-btn" data-status-filter="hide-done">Hide Done</button>
  </div>
  <button id="clear-filter">Show All</button>
  <input id="search" type="text" placeholder="Filter findings (searches match &amp; context)..." />
</div>

<h2>Findings (<span id="findings-visible">{fc['total']:,}</span> / {fc['total']:,})</h2>
<table id="tbl">
<colgroup>
  <col class="col-status">
  <col class="col-triage">
  <col class="col-rule">
  <col class="col-host">
  <col class="col-path">
  <col class="col-size">
  <col class="col-mtime">
  <col class="col-context">
</colgroup>
<thead>
<tr>
  <th data-col="0"></th>
  <th data-col="1">Triage<div class="resize-handle"></div></th>
  <th data-col="2">Rule<div class="resize-handle"></div></th>
  <th data-col="3">Host<div class="resize-handle"></div></th>
  <th data-col="4">Path<div class="resize-handle"></div></th>
  <th data-col="5">Size<div class="resize-handle"></div></th>
  <th data-col="6">Modified<div class="resize-handle"></div></th>
  <th data-col="7">Context</th>
</tr>
<tr class="filter-row">
  <th></th>
  <th></th>
  <th><div class="filter-cell"><input class="col-filter" id="f-rule" placeholder="rule..." /><select class="col-select" id="s-rule" title="Pick rule">&#9662;</select></div></th>
  <th><div class="filter-cell"><input class="col-filter" id="f-host" placeholder="host..." /><select class="col-select" id="s-host" title="Pick host">&#9662;</select></div></th>
  <th><input class="col-filter" id="f-path" placeholder="path..." /></th>
  <th></th>
  <th></th>
  <th><input class="col-filter" id="f-context" placeholder="context..." /></th>
</tr>
</thead>
<tbody>
{rows}</tbody>
</table>

{_render_unreadable_html(unreadable_shares or [])}
<div class="footer">Generated by snaffler-ng</div>

<!-- Modal -->
<div class="overlay hidden" id="overlay">
  <div class="modal">
    <div class="modal-header">
      <span id="m-badge"></span>
      <span class="modal-rule" id="m-rule"></span>
      <button class="modal-close" id="modal-close">&#x2715;</button>
    </div>
    <div class="modal-field">
      <label>Path</label>
      <div class="modal-path">
        <span id="m-path"></span>
        <button class="copy-btn" id="copy-path">Copy</button>
      </div>
    </div>
    <div class="modal-field" id="m-cmd-wrap">
      <label>Connect</label>
      <div class="modal-path">
        <code id="m-cmd" style="flex:1; color:#7ec8e3; font-size:0.9em;"></code>
        <button class="copy-btn" id="copy-cmd">Copy</button>
      </div>
    </div>
    <div class="modal-meta">
      <div class="modal-field"><label>Size</label><span id="m-size"></span></div>
      <div class="modal-field"><label>Modified</label><span id="m-mtime"></span></div>
    </div>
    <div class="modal-field" id="m-match-wrap">
      <label>Match</label>
      <div class="modal-match" id="m-match"></div>
    </div>
    <div class="modal-field">
      <label>Context</label>
      <div class="modal-context" id="m-context"></div>
    </div>
    <div class="modal-actions">
      <button class="modal-action" id="m-review">Review Later</button>
      <button class="modal-action" id="m-done">Mark Done</button>
      <button class="modal-action" id="m-clear-status">Clear Status</button>
    </div>
  </div>
</div>

<script>
var MODAL_DATA = {modal_data_json};
{js_script}</script>
</body>
</html>"""

