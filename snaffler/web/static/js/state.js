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
