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
