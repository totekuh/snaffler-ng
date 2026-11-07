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
