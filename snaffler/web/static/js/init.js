pollProgress();

if (isResultsMode) {
  fetchFindingsPage();
} else {
  fetchFindings();
}

var progressIval = setInterval(pollProgress, 2500);
var findingsIval = isResultsMode ? null : setInterval(pollFindings, 2500);
