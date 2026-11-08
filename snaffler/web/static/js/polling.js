function setText(id, value) {
  document.getElementById(id).textContent = (value || 0).toLocaleString();
}

function setCounter(id, done, total) {
  document.getElementById(id).textContent =
    (done || 0).toLocaleString() + " / " + (total || 0).toLocaleString();
}

function updatePhase(d) {
  var phaseEl = document.getElementById("phase-text");
  var dotEl = document.getElementById("phase-dot");
  phaseEl.textContent = PHASE_LABELS[d.phase] || d.phase;

  if (d.phase === "complete") {
    dotEl.classList.remove("active");
    dotEl.style.background = "#888";
    if (!stopScheduled) {
      stopScheduled = true;
      setTimeout(function() {
        if (!isResultsMode) fetchFindings();
        pollActive = false;
        if (timerIval) clearInterval(timerIval);
        clearInterval(progressIval);
        if (findingsIval) clearInterval(findingsIval);
      }, 2000);
    }
  } else {
    dotEl.classList.add("active");
    dotEl.style.background = "#27ae60";
  }
}

function updateCards(d) {
  setText("card-dns", d.dns_resolved);
  setCounter("card-computers", d.computers_done, d.computers_total);
  setCounter("card-shares", d.shares_walked, d.shares_total || d.shares_found);
  setCounter("card-files", d.files_scanned, d.files_total);
}

function updateSeverities(d) {
  setText("sev-black", d.severity_black);
  setText("sev-red", d.severity_red);
  setText("sev-yellow", d.severity_yellow);
  setText("sev-green", d.severity_green);

  var total = (d.severity_black || 0) + (d.severity_red || 0)
    + (d.severity_yellow || 0) + (d.severity_green || 0);
  setText("findings-count", total);
  updateTabTitle();
  return total;
}

function updateRates(d, total) {
  var now = Date.now();
  var dt = (now - prevRateTime) / 1000;
  if (dt < 2) return;

  var filesPerSec = ((d.files_scanned || 0) - prevFilesScanned) / dt;
  var findingsPerMin = ((total - prevFindingsTotal) / dt) * 60;

  setText("rate-files", filesPerSec > 0 ? Math.round(filesPerSec) : "--");
  setText("rate-findings", findingsPerMin > 0 ? Math.round(findingsPerMin) : "--");

  prevFilesScanned = d.files_scanned || 0;
  prevFindingsTotal = total;
  prevRateTime = now;
}

function pollProgress() {
  if (!pollActive) return;
  fetch("/api/progress").then(function(r) { return r.json(); }).then(function(d) {
    serverElapsed = d.elapsed_seconds || 0;
    localSyncTime = Date.now();

    updatePhase(d);
    updateCards(d);
    var total = updateSeverities(d);
    if (!isResultsMode) updateRates(d, total);
  }).catch(function() {});
}

// ── Findings fetch ──────────────────────────────────────────────

function fetchFindings() {
  var url = "/api/findings?since_rowid=" + lastRowid;
  fetch(url).then(function(r) { return r.json(); }).then(function(data) {
    if (data.findings && data.findings.length > 0) {
      for (var i = data.findings.length - 1; i >= 0; i--) {
        var f = data.findings[i];
        if (seenIds[f.finding_id]) continue;
        seenIds[f.finding_id] = true;
        addFindingRow(f);
      }
      lastRowid = data.max_rowid || lastRowid;
      sortTable();
      applyFilter();
    }
  }).catch(function() {});
}

function pollFindings() {
  if (!pollActive) return;
  fetchFindings();
}

// ── Paginated fetch (results mode) ──────────────────────────────

var PAGE_SIZE = 500;
var loadingMore = false;

function fetchFindingsPage() {
  if (loadingMore) return;
  loadingMore = true;
  fetch("/api/findings?since_rowid=" + lastRowid + "&limit=" + PAGE_SIZE)
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.findings && data.findings.length > 0) {
        for (var i = data.findings.length - 1; i >= 0; i--) {
          var f = data.findings[i];
          if (seenIds[f.finding_id]) continue;
          seenIds[f.finding_id] = true;
          addFindingRow(f);
        }
        lastRowid = data.max_rowid || lastRowid;
        sortTable();
        applyFilter();
      }
      loadingMore = false;
      if (data.has_more) {
        setTimeout(fetchFindingsPage, 50);
      }
    }).catch(function() { loadingMore = false; });
}

// ── Export ───────────────────────────────────────────────────────

document.getElementById("export-csv").addEventListener("click", function() {
  window.location.href = "/api/export/csv";
});

document.getElementById("export-json").addEventListener("click", function() {
  window.location.href = "/api/export/json";
});

// ── Init ────────────────────────────────────────────────────────

pollProgress();

if (isResultsMode) {
  fetchFindingsPage();
} else {
  fetchFindings();
}

var progressIval = setInterval(pollProgress, 2500);
var findingsIval = isResultsMode ? null : setInterval(pollFindings, 2500);
