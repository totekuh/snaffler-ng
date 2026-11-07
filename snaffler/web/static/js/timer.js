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
