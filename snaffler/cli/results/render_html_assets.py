"""Inline CSS and JS assets for the HTML scan report."""

CSS_STYLES = """\
  * { box-sizing: border-box; }
  body { background: #1e1e1e; color: #d4d4d4; font-family: 'Cascadia Code', 'Fira Code', monospace; margin: 0; padding: 20px; }
  h1 { color: #e0e0e0; margin-bottom: 4px; }
  h2 { color: #e0e0e0; margin: 20px 0 8px; }
  .timestamp { color: #888; font-size: 0.85em; margin-bottom: 20px; }
  .cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }
  .card { background: #2d2d2d; border-radius: 8px; padding: 16px 24px; min-width: 140px; text-align: center; }
  .card-value { font-size: 1.4em; font-weight: bold; color: #fff; }
  .card-label { color: #888; font-size: 0.85em; margin-top: 4px; }
  .card-sub { color: #e74c3c; font-size: 0.8em; margin-top: 2px; }
  .toolbar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 16px; }
  .severities { display: flex; gap: 16px; flex-wrap: wrap; align-items: center; }
  .severity { display: flex; align-items: center; gap: 6px; font-size: 1em; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 4px; color: #fff; font-weight: bold; font-size: 0.85em; }
  .badge[data-triage] { cursor: pointer; user-select: none; transition: opacity 0.15s; }
  .badge[data-triage].active { outline: 2px solid #fff; outline-offset: 1px; }
  .badge[data-triage].dimmed { opacity: 0.35; }
  #clear-filter { background: #333; color: #aaa; border: 1px solid #444; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-family: inherit; font-size: 0.85em; }
  #clear-filter:hover { background: #444; color: #fff; }
  .filter-row th { padding: 4px 4px; border-bottom: 2px solid #444; cursor: default; }
  .filter-row th:hover { color: #aaa; }
  .filter-cell { display: flex; gap: 2px; }
  .col-filter { flex: 1; min-width: 0; padding: 4px 6px; background: #252525; color: #d4d4d4; border: 1px solid #3a3a3a; border-radius: 4px; font-family: inherit; font-size: 0.8em; outline: none; box-sizing: border-box; }
  .col-filter:focus { border-color: #888; background: #2d2d2d; }
  .col-filter::placeholder { color: #555; }
  .col-select { width: 24px; flex-shrink: 0; padding: 0; background: #252525; color: #888; border: 1px solid #3a3a3a; border-radius: 4px; font-family: inherit; font-size: 0.8em; outline: none; cursor: pointer; appearance: none; -webkit-appearance: none; text-align: center; }
  .col-select:focus { border-color: #888; }
  .col-select:hover { color: #d4d4d4; background: #2d2d2d; }
  #search { flex: 1; min-width: 200px; padding: 10px 14px; background: #2d2d2d; color: #d4d4d4; border: 1px solid #444; border-radius: 6px; font-family: inherit; font-size: 1em; outline: none; }
  #search:focus { border-color: #888; }
  table { width: 100%; border-collapse: collapse; table-layout: fixed; }
  colgroup .col-status { width: 28px; }
  colgroup .col-triage { width: 70px; }
  colgroup .col-rule { width: 130px; }
  colgroup .col-host { width: 130px; }
  colgroup .col-path { width: 28%; }
  colgroup .col-size { width: 70px; }
  colgroup .col-mtime { width: 110px; }
  colgroup .col-context { width: auto; }
  thead { position: sticky; top: 0; z-index: 20; }
  thead tr { background: #1e1e1e; }
  th { text-align: left; padding: 8px 12px; border-bottom: 2px solid #444; color: #aaa; font-size: 0.8em; text-transform: uppercase; cursor: pointer; user-select: none; white-space: nowrap; position: relative; overflow: hidden; text-overflow: ellipsis; }
  th:hover { color: #fff; }
  th.sort-asc::after { content: ' ↑'; color: #fff; }
  th.sort-desc::after { content: ' ↓'; color: #fff; }
  .resize-handle { position: absolute; right: 0; top: 0; width: 5px; height: 100%; cursor: col-resize; z-index: 10; }
  .resize-handle:hover, .resize-handle.active { background: #888; }
  td { padding: 8px 12px; border-bottom: 1px solid #2a2a2a; vertical-align: top; overflow: hidden; text-overflow: ellipsis; }
  tbody tr { cursor: pointer; transition: filter 0.1s; }
  tbody tr:hover { filter: brightness(1.3); }
  tr[data-triage="Black"] { background: #271515; }
  tr[data-triage="Red"] { background: #221212; }
  tr[data-triage="Yellow"] { background: #201e0d; }
  tr[data-triage="Green"] { background: #131d13; }
  .path { word-break: break-all; }
  .match { display: block; margin-top: 4px; font-size: 0.8em; color: #ffd700; background: #1e1900; border-left: 2px solid #ffd700; padding: 2px 6px; word-break: break-all; }
  .context { font-size: 0.82em; color: #999; word-break: break-all; }
  .status-cell { width: 28px; text-align: center; padding: 8px 4px; }
  .status-icon { cursor: pointer; font-size: 0.9em; opacity: 0.4; transition: opacity 0.15s; }
  .status-icon:hover { opacity: 1; }
  tr[data-status="done"] { opacity: 0.35; }
  tr[data-status="done"] .status-icon { opacity: 1; }
  tr[data-status="review"] .status-icon { opacity: 1; }
  .status-btns { display: flex; gap: 8px; align-items: center; }
  .status-btn { background: #333; color: #aaa; border: 1px solid #444; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-family: inherit; font-size: 0.85em; transition: all 0.15s; }
  .status-btn:hover { background: #444; color: #fff; }
  .status-btn.active { outline: 2px solid #fff; outline-offset: 1px; color: #fff; }
  .modal-actions { display: flex; gap: 10px; margin-top: 18px; padding-top: 14px; border-top: 1px solid #333; }
  .modal-action { background: #333; color: #ccc; border: 1px solid #555; border-radius: 6px; padding: 8px 16px; cursor: pointer; font-family: inherit; font-size: 0.85em; }
  .modal-action:hover { background: #444; color: #fff; }
  .modal-action.active { background: #444; color: #fff; border-color: #888; }
  .footer { margin-top: 30px; color: #555; font-size: 0.8em; border-top: 1px solid #333; padding-top: 10px; }
  /* Modal */
  .overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.75); display: flex; align-items: center; justify-content: center; z-index: 1000; padding: 20px; }
  .overlay.hidden { display: none; }
  .modal { background: #252525; border-radius: 10px; padding: 28px 32px; width: 100%; max-width: 820px; max-height: 88vh; overflow-y: auto; position: relative; border: 1px solid #3a3a3a; }
  .modal-header { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }
  .modal-rule { flex: 1; font-size: 1em; font-weight: bold; color: #e0e0e0; word-break: break-all; }
  .modal-close { background: none; border: none; color: #666; font-size: 1.5em; cursor: pointer; line-height: 1; padding: 0; flex-shrink: 0; }
  .modal-close:hover { color: #fff; }
  .modal-field { margin-bottom: 14px; }
  .modal-field label { color: #666; font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 4px; }
  .modal-path { word-break: break-all; display: flex; gap: 10px; align-items: flex-start; }
  .modal-path span { flex: 1; }
  .copy-btn { background: #333; border: 1px solid #555; color: #aaa; border-radius: 4px; padding: 2px 8px; font-size: 0.75em; cursor: pointer; flex-shrink: 0; font-family: inherit; }
  .copy-btn:hover { background: #444; color: #fff; }
  .modal-meta { display: flex; gap: 24px; flex-wrap: wrap; margin-bottom: 14px; }
  .modal-match { background: #1a1500; border-left: 3px solid #ffd700; padding: 10px 14px; color: #ffd700; white-space: pre-wrap; word-break: break-all; font-size: 0.88em; border-radius: 0 4px 4px 0; }
  .modal-context { background: #1a1a1a; border-left: 3px solid #444; padding: 10px 14px; color: #aaa; white-space: pre-wrap; word-break: break-all; font-size: 0.85em; border-radius: 0 4px 4px 0; }
"""

JS_SCRIPT = """\
var activeTriage = null;
var activeStatus = "";  // "", "review", "done", "hide-done"
var TRIAGE_ORDER = {'Black':0,'Red':1,'Yellow':2,'Green':3};
var TRIAGE_COLOR = {'Black':'#888','Red':'#e74c3c','Yellow':'#f1c40f','Green':'#27ae60'};
var STATUS_ICONS = {'': '\u2022', 'review': '\u2691', 'done': '\u2713'};
var currentModalRow = null;

// ── localStorage persistence ─────────────────────────────────────
var LS_KEY = 'snaffler_finding_status';
function loadStatuses() {
  try { return JSON.parse(localStorage.getItem(LS_KEY)) || {}; }
  catch(e) { return {}; }
}
function saveStatuses(obj) {
  localStorage.setItem(LS_KEY, JSON.stringify(obj));
}

function setStatus(findingId, status) {
  var statuses = loadStatuses();
  if (status) { statuses[findingId] = status; }
  else { delete statuses[findingId]; }
  saveStatuses(statuses);
}

function getStatus(findingId) {
  return loadStatuses()[findingId] || "";
}

// ── Status cell rendering ────────────────────────────────────────
function renderStatusCell(td, status) {
  var icon = STATUS_ICONS[status] || STATUS_ICONS[''];
  var color = status === 'done' ? '#27ae60' : status === 'review' ? '#e67e22' : '#555';
  var title = status === 'done' ? 'Done' : status === 'review' ? 'Review later' : 'No status';
  td.innerHTML = '<span class="status-icon" style="color:' + color + '" title="' + title + '">' + icon + '</span>';
}

// ── Init: restore statuses from localStorage ─────────────────────
document.querySelectorAll('#tbl tbody tr').forEach(function(row) {
  var fid = row.getAttribute('data-id');
  var status = getStatus(fid);
  row.setAttribute('data-status', status);
  renderStatusCell(row.querySelector('.status-cell'), status);

  // Click status icon to cycle: none → review → done → none
  row.querySelector('.status-icon').addEventListener('click', function(e) {
    e.stopPropagation();
    var cur = row.getAttribute('data-status');
    var next = cur === '' ? 'review' : cur === 'review' ? 'done' : '';
    row.setAttribute('data-status', next);
    setStatus(fid, next);
    renderStatusCell(row.querySelector('.status-cell'), next);
    applyFilter();
  });
});


// ── Severity filter ──────────────────────────────────────────────
document.querySelectorAll('.badge[data-triage]').forEach(function(badge) {
  badge.addEventListener('click', function() {
    var t = this.getAttribute('data-triage');
    activeTriage = (activeTriage === t) ? null : t;
    syncBadges();
    applyFilter();
  });
});

document.getElementById('clear-filter').addEventListener('click', function() {
  activeTriage = null;
  activeStatus = "";
  document.getElementById('search').value = "";
  document.querySelectorAll('.col-filter').forEach(function(f) { f.value = ""; });
  document.querySelectorAll('.col-select').forEach(function(s) { s.value = ""; });
  document.querySelectorAll('.status-btn').forEach(function(b) { b.classList.remove('active'); });
  syncBadges();
  applyFilter();
});

// ── Inline column filters + select dropdowns ──────────────────────
(function() {
  var seenHost = {}, seenRule = {};
  document.querySelectorAll('#tbl tbody tr').forEach(function(row) {
    var h = row.getAttribute('data-host') || '';
    var r = row.getAttribute('data-rule') || '';
    if (h) seenHost[h] = true;
    if (r) seenRule[r] = true;
  });
  function fillSelect(selId, inputId, obj) {
    var sel = document.getElementById(selId);
    var inp = document.getElementById(inputId);
    // first option is the arrow label (already in HTML), replace with "All"
    sel.innerHTML = '<option value="">All</option>';
    Object.keys(obj).sort().forEach(function(v) {
      var opt = document.createElement('option');
      opt.value = v;
      opt.textContent = v;
      sel.appendChild(opt);
    });
    sel.addEventListener('change', function() {
      inp.value = this.value;
      applyFilter();
    });
  }
  fillSelect('s-host', 'f-host', seenHost);
  fillSelect('s-rule', 'f-rule', seenRule);
})();

document.querySelectorAll('.col-filter').forEach(function(input) {
  input.addEventListener('input', function() {
    // clear the paired select when typing manually
    var sel = this.parentElement && this.parentElement.querySelector('.col-select');
    if (sel) sel.value = '';
    applyFilter();
  });
  // prevent clicking a filter input from triggering column sort
  input.addEventListener('click', function(e) { e.stopPropagation(); });
});
document.querySelectorAll('.col-select').forEach(function(sel) {
  sel.addEventListener('click', function(e) { e.stopPropagation(); });
});

// ── Status filter buttons ────────────────────────────────────────
document.querySelectorAll('.status-btn[data-status-filter]').forEach(function(btn) {
  btn.addEventListener('click', function() {
    var f = this.getAttribute('data-status-filter');
    activeStatus = (activeStatus === f) ? "" : f;
    document.querySelectorAll('.status-btn').forEach(function(b) {
      b.classList.toggle('active', b.getAttribute('data-status-filter') === activeStatus);
    });
    applyFilter();
  });
});

function syncBadges() {
  document.querySelectorAll('.badge[data-triage]').forEach(function(b) {
    var t = b.getAttribute('data-triage');
    b.classList.toggle('active', activeTriage === t);
    b.classList.toggle('dimmed', activeTriage !== null && activeTriage !== t);
  });
}

// ── Search + filter ──────────────────────────────────────────────
document.getElementById('search').addEventListener('input', applyFilter);

function applyFilter() {
  var term = document.getElementById('search').value.toLowerCase();
  var fRule = (document.getElementById('f-rule').value || '').toLowerCase();
  var fHost = (document.getElementById('f-host').value || '').toLowerCase();
  var fPath = (document.getElementById('f-path').value || '').toLowerCase();
  var fCtx  = (document.getElementById('f-context').value || '').toLowerCase();
  var visible = 0;
  document.querySelectorAll('#tbl tbody tr').forEach(function(row) {
    var triageOk = !activeTriage || row.getAttribute('data-triage') === activeTriage;
    var ruleOk = !fRule || (row.getAttribute('data-rule') || '').toLowerCase().indexOf(fRule) !== -1;
    var hostOk = !fHost || (row.getAttribute('data-host') || '').toLowerCase().indexOf(fHost) !== -1;
    var pathOk = !fPath || (row.getAttribute('data-path') || '').toLowerCase().indexOf(fPath) !== -1;
    var rowStatus = row.getAttribute('data-status') || '';
    var statusOk = true;
    if (activeStatus === 'review') { statusOk = rowStatus === 'review'; }
    else if (activeStatus === 'done') { statusOk = rowStatus === 'done'; }
    else if (activeStatus === 'hide-done') { statusOk = rowStatus !== 'done'; }
    var ctxOk = true;
    if (fCtx) {
      var idx = parseInt(row.getAttribute('data-idx'));
      var data = MODAL_DATA[idx] || {};
      var ctxHay = ((data.context || '') + '\\n' + (data.match || '')).toLowerCase();
      ctxOk = ctxHay.indexOf(fCtx) !== -1;
    }
    var textOk = true;
    if (term) {
      var idx2 = parseInt(row.getAttribute('data-idx'));
      var data2 = MODAL_DATA[idx2] || {};
      var haystack = row.textContent.toLowerCase()
        + "\\n" + (data2.match || "").toLowerCase()
        + "\\n" + (data2.context || "").toLowerCase();
      textOk = haystack.indexOf(term) !== -1;
    }
    var show = triageOk && ruleOk && hostOk && pathOk && ctxOk && statusOk && textOk;
    row.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  document.getElementById('findings-visible').textContent = visible.toLocaleString();
}

// ── Sortable columns ─────────────────────────────────────────────
var sortCol = -1, sortAsc = true;
document.querySelectorAll('th[data-col]').forEach(function(th) {
  th.addEventListener('click', function() {
    var col = parseInt(this.getAttribute('data-col'));
    if (col === 0) return;  // status column not sortable
    sortAsc = (sortCol === col) ? !sortAsc : true;
    sortCol = col;
    document.querySelectorAll('th').forEach(function(h) { h.classList.remove('sort-asc', 'sort-desc'); });
    th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
    var tbody = document.querySelector('#tbl tbody');
    var rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort(function(a, b) {
      if (col === 1) {
        var ao = TRIAGE_ORDER[a.getAttribute('data-triage')];
        var bo = TRIAGE_ORDER[b.getAttribute('data-triage')];
        return sortAsc ? (ao - bo) : (bo - ao);
      }
      var av = a.cells[col] ? a.cells[col].textContent.trim() : '';
      var bv = b.cells[col] ? b.cells[col].textContent.trim() : '';
      return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    rows.forEach(function(r) { tbody.appendChild(r); });
  });
});

// ── Modal ────────────────────────────────────────────────────────
var overlay = document.getElementById('overlay');

function syncModalActions() {
  if (!currentModalRow) return;
  var s = currentModalRow.getAttribute('data-status') || '';
  document.getElementById('m-review').classList.toggle('active', s === 'review');
  document.getElementById('m-done').classList.toggle('active', s === 'done');
}

document.querySelectorAll('#tbl tbody tr').forEach(function(row) {
  row.addEventListener('click', function() {
    currentModalRow = this;
    var idx = parseInt(this.getAttribute('data-idx'));
    var data = MODAL_DATA[idx];
    var triage = this.getAttribute('data-triage');
    var color = TRIAGE_COLOR[triage] || '#888';
    document.getElementById('m-badge').innerHTML =
      '<span class="badge" style="background:' + color + '">' + triage + '</span>';
    document.getElementById('m-rule').textContent = this.getAttribute('data-rule');
    document.getElementById('m-path').textContent = this.getAttribute('data-path');
    document.getElementById('m-size').textContent = this.getAttribute('data-size');
    document.getElementById('m-mtime').textContent = this.getAttribute('data-mtime');
    var cmd = buildConnectCmd(this.getAttribute('data-path'));
    var cmdWrap = document.getElementById('m-cmd-wrap');
    if (cmd) {
      document.getElementById('m-cmd').textContent = cmd;
      cmdWrap.style.display = '';
    } else {
      cmdWrap.style.display = 'none';
    }
    var matchWrap = document.getElementById('m-match-wrap');
    if (data.match) {
      document.getElementById('m-match').textContent = data.match;
      matchWrap.style.display = '';
    } else {
      matchWrap.style.display = 'none';
    }
    document.getElementById('m-context').textContent = data.context;
    syncModalActions();
    overlay.classList.remove('hidden');
  });
});

function setModalStatus(status) {
  if (!currentModalRow) return;
  var fid = currentModalRow.getAttribute('data-id');
  var cur = currentModalRow.getAttribute('data-status');
  var next = (cur === status) ? '' : status;
  currentModalRow.setAttribute('data-status', next);
  setStatus(fid, next);
  renderStatusCell(currentModalRow.querySelector('.status-cell'), next);
  syncModalActions();
  applyFilter();
}

document.getElementById('m-review').addEventListener('click', function() { setModalStatus('review'); });
document.getElementById('m-done').addEventListener('click', function() { setModalStatus('done'); });
document.getElementById('m-clear-status').addEventListener('click', function() { setModalStatus(''); });

document.getElementById('modal-close').addEventListener('click', function() {
  overlay.classList.add('hidden');
});
overlay.addEventListener('click', function(e) {
  if (e.target === overlay) overlay.classList.add('hidden');
});
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') overlay.classList.add('hidden');
});
document.getElementById('copy-path').addEventListener('click', function(e) {
  e.stopPropagation();
  navigator.clipboard.writeText(document.getElementById('m-path').textContent);
  var btn = this;
  btn.textContent = 'Copied!';
  setTimeout(function() { btn.textContent = 'Copy'; }, 1500);
});

function buildConnectCmd(path) {
  // UNC: //HOST/SHARE/... → impacket-smbclient HOST -k -no-pass
  // FTP: ftp://HOST:PORT/... → ftp HOST PORT
  // Local: /path/... → no command
  if (path.startsWith('ftp://')) {
    var rest = path.slice(6);
    var slashIdx = rest.indexOf('/');
    var hostPort = slashIdx === -1 ? rest : rest.slice(0, slashIdx);
    var parts = hostPort.split(':');
    var host = parts[0];
    var port = parts[1] || '21';
    return port === '21' ? 'ftp ' + host : 'ftp ' + host + ' ' + port;
  }
  if (path.startsWith('//')) {
    var parts = path.split('/');
    // parts: ["", "", HOST, SHARE, ...]
    if (parts.length >= 3) {
      return 'impacket-smbclient ' + parts[2] + ' -k -no-pass';
    }
  }
  return '';
}

document.getElementById('copy-cmd').addEventListener('click', function(e) {
  e.stopPropagation();
  navigator.clipboard.writeText(document.getElementById('m-cmd').textContent);
  var btn = this;
  btn.textContent = 'Copied!';
  setTimeout(function() { btn.textContent = 'Copy'; }, 1500);
});

// ── Column resize ─────────────────────────────────────────────────
(function() {
  var tbl = document.getElementById('tbl');
  var cols = tbl.querySelectorAll('colgroup col');
  var handles = tbl.querySelectorAll('.resize-handle');
  var activeHandle = null, startX = 0, startW = 0, colIdx = 0;

  handles.forEach(function(handle) {
    handle.addEventListener('mousedown', function(e) {
      e.preventDefault();
      e.stopPropagation();
      activeHandle = handle;
      handle.classList.add('active');
      var th = handle.parentElement;
      colIdx = parseInt(th.getAttribute('data-col'));
      startX = e.pageX;
      startW = th.offsetWidth;
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    });
  });

  document.addEventListener('mousemove', function(e) {
    if (!activeHandle) return;
    var diff = e.pageX - startX;
    var newW = Math.max(40, startW + diff);
    cols[colIdx].style.width = newW + 'px';
  });

  document.addEventListener('mouseup', function() {
    if (!activeHandle) return;
    activeHandle.classList.remove('active');
    activeHandle = null;
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  });
})();
"""
