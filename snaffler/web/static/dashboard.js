(function() {
  "use strict";

  var TRIAGE_ORDER = {"Black":0,"Red":1,"Yellow":2,"Green":3};
  var TRIAGE_COLOR = {"Black":"#888","Red":"#e74c3c","Yellow":"#f1c40f","Green":"#27ae60"};

  var activeTriage = null;
  var activeRule = "";
  var lastRowid = 0;
  var findingsData = [];
  var seenIds = {};
  var knownRules = {};
  var pollActive = true;
  var stopScheduled = false;
  var serverElapsed = 0;
  var localSyncTime = Date.now();
  var isResultsMode = (typeof __SNAFFLER_MODE !== "undefined" && __SNAFFLER_MODE === "results")
    || (document.body && document.body.dataset.mode === "results");
  var prevFilesScanned = 0;
  var prevFindingsTotal = 0;
  var prevRateTime = Date.now();

  // ── Elapsed timer ──────────────────────────────────────────────
  var elapsedEl = document.getElementById("elapsed");
  var timerIval = null;
  if (isResultsMode) {
    elapsedEl.textContent = "";
    var rateBox = document.getElementById("rate-box");
    if (rateBox) rateBox.style.display = "none";
  } else {
    timerIval = setInterval(function() {
      var now = Date.now();
      var totalSec = serverElapsed + Math.floor((now - localSyncTime) / 1000);
      if (totalSec < 0) totalSec = 0;
      var h = Math.floor(totalSec / 3600);
      var m = Math.floor((totalSec % 3600) / 60);
      var s = totalSec % 60;
      elapsedEl.textContent =
        (h < 10 ? "0" : "") + h + ":" +
        (m < 10 ? "0" : "") + m + ":" +
        (s < 10 ? "0" : "") + s;
    }, 1000);
  }

  // ── Phase mapping ─────────────────────────────────────────────
  var PHASE_LABELS = {
    "idle": "Initializing",
    "dns": "DNS Resolution",
    "shares": "Share Discovery",
    "walking": "Tree Walking",
    "scanning": "File Scanning",
    "complete": "Complete"
  };

  // ── Helpers ───────────────────────────────────────────────────
  function esc(s) {
    var d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }

  function makeBadge(triage) {
    var color = TRIAGE_COLOR[triage] || "#888";
    return '<span class="badge" style="background:' + color + '">' + esc(triage) + '</span>';
  }

  // ── Severity filter ───────────────────────────────────────────
  document.querySelectorAll(".badge[data-triage]").forEach(function(badge) {
    badge.addEventListener("click", function() {
      var t = this.getAttribute("data-triage");
      activeTriage = (activeTriage === t) ? null : t;
      syncBadges();
      applyFilter();
    });
  });

  document.getElementById("clear-filter").addEventListener("click", function() {
    activeTriage = null;
    activeRule = "";
    document.getElementById("rule-filter").value = "";
    document.getElementById("search").value = "";
    syncBadges();
    applyFilter();
  });

  document.getElementById("rule-filter").addEventListener("change", function() {
    activeRule = this.value;
    applyFilter();
  });

  function syncBadges() {
    document.querySelectorAll(".badge[data-triage]").forEach(function(b) {
      var t = b.getAttribute("data-triage");
      b.classList.toggle("active", activeTriage === t);
      b.classList.toggle("dimmed", activeTriage !== null && activeTriage !== t);
    });
  }

  // ── Search + filter ───────────────────────────────────────────
  document.getElementById("search").addEventListener("input", applyFilter);

  function applyFilter() {
    var term = document.getElementById("search").value.toLowerCase();
    var visible = 0;
    document.querySelectorAll("#tbl tbody tr").forEach(function(row) {
      var triageOk = !activeTriage || row.getAttribute("data-triage") === activeTriage;
      var ruleOk = !activeRule || row.getAttribute("data-rule") === activeRule;
      var textOk = true;
      if (term) {
        var idx = parseInt(row.getAttribute("data-idx"));
        var data = findingsData[idx] || {};
        var haystack = row.textContent.toLowerCase()
          + "\n" + (data.match || "").toLowerCase()
          + "\n" + (data.context || "").toLowerCase();
        textOk = haystack.indexOf(term) !== -1;
      }
      var show = triageOk && ruleOk && textOk;
      row.style.display = show ? "" : "none";
      if (show) visible++;
    });
    document.getElementById("findings-visible").textContent = visible.toLocaleString();
  }

  // ── Sortable columns ─────────────────────────────────────────
  var sortCol = -1, sortAsc = true;

  function sortTable() {
    if (sortCol === -1) return;
    var tbody = document.querySelector("#tbl tbody");
    var rows = Array.from(tbody.querySelectorAll("tr"));
    rows.sort(function(a, b) {
      if (sortCol === 0) {
        var at = a.getAttribute("data-triage");
        var bt = b.getAttribute("data-triage");
        var ao = at in TRIAGE_ORDER ? TRIAGE_ORDER[at] : 99;
        var bo = bt in TRIAGE_ORDER ? TRIAGE_ORDER[bt] : 99;
        return sortAsc ? (ao - bo) : (bo - ao);
      }
      var av = a.cells[sortCol] ? a.cells[sortCol].textContent.trim() : "";
      var bv = b.cells[sortCol] ? b.cells[sortCol].textContent.trim() : "";
      return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    rows.forEach(function(r) { tbody.appendChild(r); });
  }

  document.querySelectorAll("th[data-col]").forEach(function(th) {
    th.addEventListener("click", function() {
      var col = parseInt(this.getAttribute("data-col"));
      sortAsc = (sortCol === col) ? !sortAsc : true;
      sortCol = col;
      document.querySelectorAll("th").forEach(function(h) { h.classList.remove("sort-asc", "sort-desc"); });
      th.classList.add(sortAsc ? "sort-asc" : "sort-desc");
      sortTable();
    });
  });

  // ── Modal ─────────────────────────────────────────────────────
  var overlay = document.getElementById("overlay");

  function openModal(row) {
    var idx = parseInt(row.getAttribute("data-idx"));
    var data = findingsData[idx] || {};
    var triage = row.getAttribute("data-triage");
    var color = TRIAGE_COLOR[triage] || "#888";
    document.getElementById("m-badge").innerHTML =
      '<span class="badge" style="background:' + color + '">' + esc(triage) + '</span>';
    document.getElementById("m-rule").textContent = row.getAttribute("data-rule");
    document.getElementById("m-path").textContent = row.getAttribute("data-path");
    document.getElementById("m-size").textContent = row.getAttribute("data-size");
    document.getElementById("m-mtime").textContent = row.getAttribute("data-mtime");
    var matchWrap = document.getElementById("m-match-wrap");
    if (data.match) {
      document.getElementById("m-match").textContent = data.match;
      matchWrap.style.display = "";
    } else {
      matchWrap.style.display = "none";
    }
    document.getElementById("m-context").textContent = data.context || "";
    overlay.classList.remove("hidden");
  }

  document.getElementById("modal-close").addEventListener("click", function() {
    overlay.classList.add("hidden");
  });
  overlay.addEventListener("click", function(e) {
    if (e.target === overlay) overlay.classList.add("hidden");
  });
  document.addEventListener("keydown", function(e) {
    if (e.key === "Escape") overlay.classList.add("hidden");
  });
  document.getElementById("copy-path").addEventListener("click", function(e) {
    e.stopPropagation();
    navigator.clipboard.writeText(document.getElementById("m-path").textContent);
    var btn = this;
    btn.textContent = "Copied!";
    setTimeout(function() { btn.textContent = "Copy"; }, 1500);
  });

  // ── Add finding row ───────────────────────────────────────────
  function addFindingRow(f) {
    var idx = findingsData.length;
    findingsData.push({match: f.match_text || "", context: f.context || "", rule: f.rule_name || ""});

    if (f.rule_name && !knownRules[f.rule_name]) {
      knownRules[f.rule_name] = true;
      var opt = document.createElement("option");
      opt.value = f.rule_name;
      opt.textContent = f.rule_name;
      document.getElementById("rule-filter").appendChild(opt);
    }

    var tbody = document.querySelector("#tbl tbody");
    var tr = document.createElement("tr");
    tr.setAttribute("data-idx", idx);
    tr.setAttribute("data-triage", f.triage);
    tr.setAttribute("data-rule", f.rule_name);
    tr.setAttribute("data-path", f.file_path);
    tr.setAttribute("data-size", f.size_str || "");
    tr.setAttribute("data-mtime", f.mtime || "");
    tr.className = "new-row";

    var ctxDisplay = (f.context || "").substring(0, 200);
    if ((f.context || "").length > 200) ctxDisplay += "…";
    var matchDisplay = (f.match_text || "").substring(0, 120);
    if ((f.match_text || "").length > 120) matchDisplay += "…";

    tr.innerHTML =
      "<td>" + makeBadge(f.triage) + "</td>" +
      "<td></td>" +
      '<td class="path"></td>' +
      "<td></td>" +
      "<td></td>" +
      '<td class="context"></td>';

    tr.cells[1].textContent = f.rule_name;
    tr.cells[2].textContent = f.file_path;
    tr.cells[3].textContent = f.size_str || "";
    tr.cells[4].textContent = f.mtime || "";

    var ctxCell = tr.cells[5];
    ctxCell.textContent = ctxDisplay;
    if (matchDisplay) {
      var matchSpan = document.createElement("span");
      matchSpan.className = "match";
      matchSpan.textContent = matchDisplay;
      ctxCell.appendChild(matchSpan);
    }

    tr.addEventListener("click", function() { openModal(this); });

    if (tbody.firstChild) {
      tbody.insertBefore(tr, tbody.firstChild);
    } else {
      tbody.appendChild(tr);
    }

    var triageOk = !activeTriage || f.triage === activeTriage;
    var ruleOk = !activeRule || f.rule_name === activeRule;
    var term = document.getElementById("search").value.toLowerCase();
    var textOk = true;
    if (term) {
      var haystack = tr.textContent.toLowerCase()
        + "\n" + (f.match_text || "").toLowerCase()
        + "\n" + (f.context || "").toLowerCase();
      textOk = haystack.indexOf(term) !== -1;
    }
    if (!(triageOk && ruleOk && textOk)) {
      tr.style.display = "none";
    }
  }

  // ── Polling: progress ─────────────────────────────────────────
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

  // ── Polling: findings ─────────────────────────────────────────
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

  // ── Export buttons ─────────────────────────────────────────────
  document.getElementById("export-csv").addEventListener("click", function() {
    window.location.href = "/api/export/csv";
  });
  document.getElementById("export-json").addEventListener("click", function() {
    window.location.href = "/api/export/json";
  });

  // ── Paginated fetch (results mode) ────────────────────────────
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

  // ── Start polling ─────────────────────────────────────────────
  pollProgress();
  if (isResultsMode) {
    fetchFindingsPage();
  } else {
    fetchFindings();
  }

  var progressIval = setInterval(pollProgress, 2500);
  var findingsIval = isResultsMode ? null : setInterval(pollFindings, 2500);
})();
