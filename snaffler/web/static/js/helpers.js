function esc(s) {
  var d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function makeBadge(triage) {
  var color = TRIAGE_COLOR[triage] || "#888";
  return '<span class="badge" style="background:' + color + '">' + esc(triage) + '</span>';
}
