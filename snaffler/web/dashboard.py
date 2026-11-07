"""Self-contained live dashboard HTML page (no CDN, no external deps)."""

from snaffler.web.dashboard_assets import CSS_STYLES, JS_SCRIPT

_HEAD = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Snaffler Live</title>
<style>
"""

_MIDDLE = r"""
</style>
</head>
<body>
<div class="header">
  <h1>Snaffler Live</h1>
  <span class="elapsed" id="elapsed">00:00:00</span>
  <div class="phase-badge">
    <span class="phase-dot active" id="phase-dot"></span>
    <span id="phase-text">Initializing</span>
  </div>
  <div class="rate-indicators" id="rate-box">
    <span class="rate"><span id="rate-files">--</span> files/s</span>
    <span class="rate"><span id="rate-findings">--</span> findings/min</span>
  </div>
</div>

<div class="cards">
  <div class="card"><div class="card-value" id="card-dns">0</div><div class="card-label">DNS Resolved</div></div>
  <div class="card"><div class="card-value" id="card-computers">0 / 0</div><div class="card-label">Computers</div></div>
  <div class="card"><div class="card-value" id="card-shares">0 / 0</div><div class="card-label">Shares</div></div>
  <div class="card"><div class="card-value" id="card-files">0 / 0</div><div class="card-label">Files</div></div>
</div>

<div class="toolbar">
  <div class="severities">
    <div class="severity"><span class="badge" data-triage="Black" style="background:#888">Black</span> <span id="sev-black">0</span></div>
    <div class="severity"><span class="badge" data-triage="Red" style="background:#e74c3c">Red</span> <span id="sev-red">0</span></div>
    <div class="severity"><span class="badge" data-triage="Yellow" style="background:#f1c40f">Yellow</span> <span id="sev-yellow">0</span></div>
    <div class="severity"><span class="badge" data-triage="Green" style="background:#27ae60">Green</span> <span id="sev-green">0</span></div>
  </div>
  <select id="rule-filter"><option value="">All Rules</option></select>
  <button id="clear-filter">Show All</button>
  <input id="search" type="text" placeholder="Filter findings (searches match &amp; context)..." />
  <button id="export-csv" title="Export filtered findings as CSV">&#x2B07; CSV</button>
  <button id="export-json" title="Export filtered findings as JSON">&#x2B07; JSON</button>
</div>

<h2>Findings (<span id="findings-visible">0</span> / <span id="findings-count">0</span>)</h2>
<table id="tbl">
<thead><tr>
  <th data-col="0">Triage</th>
  <th data-col="1">Rule</th>
  <th data-col="2">Path</th>
  <th data-col="3">Size</th>
  <th data-col="4">Modified</th>
  <th data-col="5">Context</th>
</tr></thead>
<tbody></tbody>
</table>

<div class="footer">snaffler-ng live dashboard</div>

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
  </div>
</div>

<script>
"""

_TAIL = r"""
</script>
</body>
</html>"""


def render_dashboard(mode: str = "live") -> str:
    """Return a complete HTML page for the web dashboard."""
    title = "Snaffler Results" if mode == "results" else "Snaffler Live"
    head = _HEAD.replace("Snaffler Live</title>", f"{title}</title>")
    middle = _MIDDLE
    if mode == "results":
        middle = middle.replace("<body>", '<body data-mode="results">')
        middle = middle.replace(">Snaffler Live<", f">{title}<")
        middle = middle.replace("snaffler-ng live dashboard", "snaffler-ng results dashboard")
    return head + CSS_STYLES + middle + JS_SCRIPT + _TAIL
