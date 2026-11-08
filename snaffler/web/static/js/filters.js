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

document.getElementById("search").addEventListener("input", applyFilter);

function matchesTriage(row) {
  return !activeTriage || row.getAttribute("data-triage") === activeTriage;
}

function matchesRule(row) {
  return !activeRule || row.getAttribute("data-rule") === activeRule;
}

function matchesSearch(row, term) {
  if (!term) return true;
  var idx = parseInt(row.getAttribute("data-idx"));
  var data = findingsData[idx] || {};
  var haystack = [
    row.textContent,
    data.match || "",
    data.context || ""
  ].join("\n").toLowerCase();
  return haystack.indexOf(term) !== -1;
}

function applyFilter() {
  var term = document.getElementById("search").value.toLowerCase();
  var visible = 0;

  document.querySelectorAll("#tbl tbody tr").forEach(function(row) {
    var show = matchesTriage(row) && matchesRule(row) && matchesSearch(row, term);
    row.style.display = show ? "" : "none";
    if (show) visible++;
  });

  document.getElementById("findings-visible").textContent = visible.toLocaleString();
  updateTabTitle();
  pushFilterState();
}

// ── Tab title ──────────────────────────────────────────────────

var baseTitle = document.title;

function updateTabTitle() {
  var total = document.getElementById("findings-count").textContent;
  var n = parseInt(total.replace(/,/g, ""), 10) || 0;
  document.title = n > 0 ? "(" + n + ") " + baseTitle : baseTitle;
}

// ── URL permalink filters ──────────────────────────────────────

function pushFilterState() {
  var params = new URLSearchParams();
  if (activeTriage) params.set("triage", activeTriage);
  if (activeRule) params.set("rule", activeRule);
  var search = document.getElementById("search").value;
  if (search) params.set("q", search);
  var qs = params.toString();
  var url = window.location.pathname + (qs ? "?" + qs : "");
  history.replaceState(null, "", url);
}

function restoreFilterState() {
  var params = new URLSearchParams(window.location.search);
  var triage = params.get("triage");
  if (triage && triage in TRIAGE_ORDER) {
    activeTriage = triage;
    syncBadges();
  }
  var rule = params.get("rule");
  if (rule) {
    activeRule = rule;
    document.getElementById("rule-filter").value = rule;
  }
  var q = params.get("q");
  if (q) {
    document.getElementById("search").value = q;
  }
  if (triage || rule || q) applyFilter();
}

restoreFilterState();
