// 지출결의서 상신 화면: 내역 줄 추가, 줄별 금액(수량×단가)과 합계를 보여 주고, 계좌 칸을 지급 방법에 맞춰 보이거나 숨긴다.
// 여기 계산은 참고용이다. 저장되는 금액과 합계는 서버가 수량×단가로 다시 계산한다(화면에서 보낸 금액 칸은 읽지 않는다).
// CSP(script-src 'self')에 맞춰 인라인 코드를 쓰지 않는다.
(function () {
  "use strict";
  var body = document.getElementById("exd-rows");
  var total = document.getElementById("exd-total");
  var add = document.getElementById("exd-add");
  var acct = document.getElementById("exd-account-label");
  if (!body || !total) { return; }
  var max = parseInt(body.getAttribute("data-max"), 10) || 30;

  function num(v) { return /^\d+$/.test((v || "").trim()) ? parseInt(v.trim(), 10) : NaN; }
  function fmt(n) { return n.toLocaleString("ko-KR"); }

  function recalc() {
    var sum = 0;
    Array.prototype.forEach.call(body.rows, function (tr) {
      var q = num(tr.querySelector("input[name^=qty_]").value);
      var p = num(tr.querySelector("input[name^=price_]").value);
      var cell = tr.querySelector(".exd-amount");
      if (isNaN(q) || isNaN(p)) { cell.textContent = "-"; return; }
      cell.textContent = fmt(q * p);
      sum += q * p;
    });
    total.textContent = sum ? fmt(sum) : "-";
  }

  function addRow() {
    var n = body.rows.length + 1;
    if (n > max) { window.alert("지출 내역은 최대 " + max + "줄까지 입력할 수 있습니다."); return; }
    var tr = document.createElement("tr");
    tr.className = "exd-row";
    var cells = [["", "num"], ["item", ""], ["memo", ""], ["qty", "num"], ["price", "num"]];
    var first = document.createElement("td");
    first.className = "num";
    first.textContent = String(n);
    tr.appendChild(first);
    cells.slice(1).forEach(function (c) {
      var td = document.createElement("td");
      var input = document.createElement("input");
      input.name = c[0] + "_" + n;
      input.maxLength = c[0] === "item" || c[0] === "memo" ? 100 : 12;
      input.setAttribute("aria-label", { item: "항목", memo: "적요", qty: "수량", price: "단가" }[c[0]] + " " + n);
      if (c[1]) { input.className = c[1]; input.setAttribute("inputmode", "numeric"); }
      td.appendChild(input);
      tr.appendChild(td);
    });
    var amount = document.createElement("td");
    amount.className = "num exd-amount";
    amount.textContent = "-";
    tr.appendChild(amount);
    body.appendChild(tr);
    tr.querySelector("input").focus();
  }

  function syncAccount() {
    var checked = document.querySelector("input[name=pay_method]:checked");
    if (acct) { acct.hidden = !checked || checked.value !== "transfer"; }
  }

  body.addEventListener("input", recalc);
  if (add) { add.addEventListener("click", addRow); }
  Array.prototype.forEach.call(document.querySelectorAll("input[name=pay_method]"), function (r) { r.addEventListener("change", syncAccount); });
  recalc();
  syncAccount();
})();
