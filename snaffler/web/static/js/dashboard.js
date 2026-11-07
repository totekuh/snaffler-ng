var TRIAGE_ORDER = {"Black": 0, "Red": 1, "Yellow": 2, "Green": 3};
var TRIAGE_COLOR = {"Black": "#888", "Red": "#e74c3c", "Yellow": "#f1c40f", "Green": "#27ae60"};

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

var PHASE_LABELS = {
  "idle": "Initializing",
  "dns": "DNS Resolution",
  "shares": "Share Discovery",
  "walking": "Tree Walking",
  "scanning": "File Scanning",
  "complete": "Complete"
};

function makeBadge(triage) {
  var span = document.createElement("span");
  span.className = "badge";
  span.style.background = TRIAGE_COLOR[triage] || "#888";
  span.textContent = triage;
  return span;
}

// ── Timer ──────────────────────────────────────────────────────

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
