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

// ── Add finding row ─────────────────────────────────────────────

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

  var cells = [
    { content: makeBadge(f.triage) },
    { text: f.rule_name },
    { text: f.file_path, cls: "path" },
    { text: f.size_str || "" },
    { text: f.mtime || "" },
    { cls: "context" }
  ];
  cells.forEach(function(spec) {
    var td = document.createElement("td");
    if (spec.cls) td.className = spec.cls;
    if (spec.content) td.appendChild(spec.content);
    if (spec.text) td.textContent = spec.text;
    tr.appendChild(td);
  });

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
    var haystack = [
      tr.textContent,
      f.match_text || "",
      f.context || ""
    ].join("\n").toLowerCase();
    textOk = haystack.indexOf(term) !== -1;
  }
  if (!(triageOk && ruleOk && textOk)) {
    tr.style.display = "none";
  }
}

// ── Modal ───────────────────────────────────────────────────────

var overlay = document.getElementById("overlay");

function openModal(row) {
  var idx = parseInt(row.getAttribute("data-idx"));
  var data = findingsData[idx] || {};
  var triage = row.getAttribute("data-triage");
  var badgeContainer = document.getElementById("m-badge");
  badgeContainer.textContent = "";
  badgeContainer.appendChild(makeBadge(triage));
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
