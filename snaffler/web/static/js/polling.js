function pollProgress() {
  if (!pollActive) return;
  fetch("/api/progress").then(function(r) { return r.json(); }).then(function(d) {
    serverElapsed = d.elapsed_seconds || 0;
    localSyncTime = Date.now();

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

    document.getElementById("card-dns").textContent = (d.dns_resolved || 0).toLocaleString();
    document.getElementById("card-computers").textContent =
      (d.computers_done || 0).toLocaleString() + " / " + (d.computers_total || 0).toLocaleString();
    document.getElementById("card-shares").textContent =
      (d.shares_walked || 0).toLocaleString() + " / " + (d.shares_total || d.shares_found || 0).toLocaleString();
    document.getElementById("card-files").textContent =
      (d.files_scanned || 0).toLocaleString() + " / " + (d.files_total || 0).toLocaleString();

    document.getElementById("sev-black").textContent = (d.severity_black || 0).toLocaleString();
    document.getElementById("sev-red").textContent = (d.severity_red || 0).toLocaleString();
    document.getElementById("sev-yellow").textContent = (d.severity_yellow || 0).toLocaleString();
    document.getElementById("sev-green").textContent = (d.severity_green || 0).toLocaleString();

    var total = (d.severity_black || 0) + (d.severity_red || 0) + (d.severity_yellow || 0) + (d.severity_green || 0);
    document.getElementById("findings-count").textContent = total.toLocaleString();

    if (!isResultsMode) {
      var now = Date.now();
      var dt = (now - prevRateTime) / 1000;
      if (dt >= 2) {
        var filesDelta = (d.files_scanned || 0) - prevFilesScanned;
        var filesPerSec = dt > 0 ? (filesDelta / dt) : 0;
        var findingsDelta = total - prevFindingsTotal;
        var findingsPerMin = dt > 0 ? (findingsDelta / dt * 60) : 0;
        document.getElementById("rate-files").textContent =
          filesPerSec > 0 ? Math.round(filesPerSec).toLocaleString() : "--";
        document.getElementById("rate-findings").textContent =
          findingsPerMin > 0 ? Math.round(findingsPerMin).toLocaleString() : "--";
        prevFilesScanned = d.files_scanned || 0;
        prevFindingsTotal = total;
        prevRateTime = now;
      }
    }
  }).catch(function() {});
}

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
