// 결재 상신의 서식 편집기: 글자 서식(굵게·기울임·밑줄·취소선·크기·색·배경·정렬·제목·목록)과 표(삽입·행/열 추가·삭제·칸 합치기)를 지원한다.
// CSP(script-src 'self', style-src 'self')를 지키기 위해 인라인 스타일을 쓰지 않는다: 서식은 모두 서버(app/richtext.py)가 허용하는 클래스
// (fs-1~7, c-*, bg-*, al-*, doc-table)로만 만든다. 서버는 상신할 때 이 내용을 허용 목록으로 다시 살균하므로 여기는 편의 기능이다.
// 자바스크립트가 꺼져 있으면 이 편집기는 만들어지지 않고 "내용" 칸이 일반 글 칸으로 쓰인다.
(function () {
  "use strict";
  var src = document.getElementById("body-source");
  var fmt = document.getElementById("body-format");
  if (!src || !fmt || !src.form || !document.execCommand) { return; }

  var COLORS = [["", "글자 색"], ["c-black", "검정", "#000000"], ["c-red", "빨강", "#c8102e"], ["c-blue", "파랑", "#0b50e6"],
    ["c-green", "초록", "#15803d"], ["c-orange", "주황", "#b45309"], ["c-purple", "보라", "#6d28d9"], ["c-gray", "회색", "#566174"]];
  // 배경색은 execCommand(foreColor)에 "표식 색"을 넘긴 뒤 클래스로 바꾼다(배경은 CSS 인라인 스타일 없이 클래스로만 표현하기 위한 우회).
  var BGS = [["", "배경색"], ["none", "배경 없음", "#0a0b00"], ["bg-yellow", "노랑", "#0a0b01"], ["bg-gray", "회색", "#0a0b02"],
    ["bg-blue", "하늘", "#0a0b03"], ["bg-green", "연두", "#0a0b04"], ["bg-red", "분홍", "#0a0b05"]];
  var SIZES = [["", "글자 크기"], ["1", "아주 작게"], ["2", "작게"], ["3", "보통"], ["4", "크게"], ["5", "더 크게"], ["6", "아주 크게"], ["7", "제목급"]];
  var BLOCK_FORMATS = [["", "문단 모양"], ["p", "본문"], ["h2", "제목 1"], ["h3", "제목 2"]];
  var ALLOWED = { p: 1, div: 1, br: 1, hr: 1, span: 1, b: 1, strong: 1, i: 1, em: 1, u: 1, s: 1, strike: 1, sub: 1, sup: 1, h2: 1, h3: 1, ul: 1, ol: 1,
    li: 1, blockquote: 1, table: 1, caption: 1, thead: 1, tbody: 1, tfoot: 1, tr: 1, th: 1, td: 1 };
  var DROP = { script: 1, style: 1, iframe: 1, object: 1, embed: 1, noscript: 1, template: 1, svg: 1, math: 1, textarea: 1, title: 1, head: 1, select: 1,
    option: 1, button: 1, form: 1, input: 1, link: 1, meta: 1, base: 1, audio: 1, video: 1, canvas: 1, map: 1 };
  var CLASS_OK = /^(fs-[1-7]|c-(black|red|blue|green|orange|purple|gray)|bg-(yellow|gray|blue|green|red)|al-(left|center|right|justify)|doc-table|b-none)$/;
  var BLOCKS = "p,div,li,h2,h3,blockquote,td,th";
  var colorByHex = {};
  var bgByHex = {};
  COLORS.forEach(function (c) { if (c[2]) { colorByHex[c[2]] = c[0]; } });
  BGS.forEach(function (c) { if (c[2]) { bgByHex[c[2]] = c[0] === "none" ? "" : c[0]; } });

  // ---------- 화면 만들기 ----------
  var form = src.form;
  var wrap = document.createElement("div");
  wrap.className = "rt";
  var bar = document.createElement("div");
  bar.className = "rt-bar";
  bar.setAttribute("role", "toolbar");
  bar.setAttribute("aria-label", "글자 서식과 표");
  var ed = document.createElement("div");
  ed.className = "rt-editor doc-body";
  ed.contentEditable = "true";
  ed.setAttribute("role", "textbox");
  ed.setAttribute("aria-multiline", "true");
  ed.setAttribute("aria-label", "내용(서식 편집)");
  var hint = document.createElement("p");
  hint.className = "hint";
  hint.textContent = "글자를 선택한 뒤 위의 도구로 서식을 바꿉니다. 표 안에서는 Tab 키로 다음 칸으로 이동합니다. 붙여넣은 글은 서식이 정리됩니다.";

  function button(label, title, handler) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "btn rt-btn";
    b.textContent = label;
    b.title = title;
    b.setAttribute("aria-label", title);
    b.addEventListener("mousedown", function (e) { e.preventDefault(); });      // 눌러도 선택 영역을 잃지 않게
    b.addEventListener("click", handler);
    return b;
  }

  function select(options, handler) {
    var s = document.createElement("select");
    s.className = "rt-select";
    s.setAttribute("aria-label", options[0][1]);
    options.forEach(function (o) {
      var opt = document.createElement("option");
      opt.value = o[0];
      opt.textContent = o[1];
      s.appendChild(opt);
    });
    s.addEventListener("change", function () {
      if (s.value) { handler(s.value); }
      s.selectedIndex = 0;
    });
    return s;
  }

  function group(label) {
    var g = document.createElement("span");
    g.className = "rt-group";
    g.setAttribute("role", "group");
    g.setAttribute("aria-label", label);
    bar.appendChild(g);
    return g;
  }

  // ---------- 선택 영역 ----------
  var saved = null;
  document.addEventListener("selectionchange", function () {
    var s = window.getSelection();
    if (s && s.rangeCount && ed.contains(s.anchorNode)) { saved = s.getRangeAt(0).cloneRange(); }
  });

  function restore() {
    ed.focus();
    if (saved) {
      var s = window.getSelection();
      s.removeAllRanges();
      s.addRange(saved);
    }
  }

  // ---------- 정리: execCommand 결과를 허용 클래스만 쓰도록 바꾼다 ----------
  function hexOf(v) {
    v = (v || "").trim().toLowerCase();
    var m = v.match(/^rgb\((\d+),\s*(\d+),\s*(\d+)\)$/);
    if (m) { return "#" + [1, 2, 3].map(function (i) { return ("0" + (+m[i]).toString(16)).slice(-2); }).join(""); }
    if (/^#[0-9a-f]{3}$/.test(v)) { return "#" + v[1] + v[1] + v[2] + v[2] + v[3] + v[3]; }
    return v;
  }

  function unwrap(el) {
    var parent = el.parentNode;
    while (el.firstChild) { parent.insertBefore(el.firstChild, el); }
    parent.removeChild(el);
  }

  function normalize() {
    var f;
    while ((f = ed.querySelector("font"))) {                      // <font size color> → <span class="fs-N c-… bg-…">
      var span = document.createElement("span");
      var classes = [];
      var size = f.getAttribute("size");
      var color = hexOf(f.getAttribute("color"));
      if (size && /^[1-7]$/.test(size)) { classes.push("fs-" + size); }
      if (colorByHex[color]) { classes.push(colorByHex[color]); }
      else if (bgByHex[color]) { classes.push(bgByHex[color]); }
      while (f.firstChild) { span.appendChild(f.firstChild); }
      if (classes.length) { span.className = classes.join(" "); }
      f.parentNode.replaceChild(span, f);
    }
    ed.querySelectorAll("[style]").forEach(function (el) {         // 브라우저가 붙인 인라인 스타일은 정렬만 클래스로 옮기고 지운다
      var a = el.style.textAlign;
      if (a && /^(left|center|right|justify)$/.test(a)) { setAlign(el, "al-" + a); }
      el.removeAttribute("style");
    });
    ed.querySelectorAll("[face],[color],[size]").forEach(function (el) {
      el.removeAttribute("face"); el.removeAttribute("color"); el.removeAttribute("size");
    });
    ed.querySelectorAll("span:not([class])").forEach(unwrap);      // 서식이 없는 빈 span 은 벗긴다
    ed.querySelectorAll("*").forEach(function (el) {               // 허용하지 않는 클래스는 지운다
      Array.prototype.slice.call(el.classList).forEach(function (c) { if (!CLASS_OK.test(c)) { el.classList.remove(c); } });
      if (el.getAttribute("class") === "") { el.removeAttribute("class"); }
    });
  }

  function ensureBlocks() {                                         // 맨 위에 문단 없이 글자만 있으면 <p> 로 감싼다
    var run = null;
    Array.prototype.slice.call(ed.childNodes).forEach(function (n) {
      var block = n.nodeType === 1 && /^(P|DIV|H2|H3|UL|OL|TABLE|BLOCKQUOTE|HR)$/.test(n.tagName);
      if (block) { run = null; return; }
      if (n.nodeType === 3 && !n.nodeValue.trim() && !run) { return; }
      if (!run) { run = document.createElement("p"); ed.insertBefore(run, n); }
      run.appendChild(n);
    });
    if (!ed.firstChild) { ed.innerHTML = "<p><br></p>"; }
  }

  function run(cmd, value) {
    restore();
    document.execCommand("styleWithCSS", false, false);
    document.execCommand(cmd, false, value === undefined ? null : value);
    normalize();
    ensureBlocks();
    ed.focus();
  }

  // ---------- 정렬(문단에 클래스를 단다) ----------
  function setAlign(block, cls) {
    ["al-left", "al-center", "al-right", "al-justify"].forEach(function (c) { block.classList.remove(c); });
    if (cls && cls !== "al-left") { block.classList.add(cls); }
    if (block.getAttribute("class") === "") { block.removeAttribute("class"); }
  }

  function align(cls) {
    restore();
    ensureBlocks();
    var s = window.getSelection();
    if (!s.rangeCount) { return; }
    var range = s.getRangeAt(0);
    var leafs = [];
    ed.querySelectorAll(BLOCKS).forEach(function (b) {
      if (range.intersectsNode(b) && !b.querySelector(BLOCKS)) { leafs.push(b); }
    });
    if (!leafs.length) {
      var n = s.anchorNode && (s.anchorNode.nodeType === 3 ? s.anchorNode.parentNode : s.anchorNode);
      var b = n && n.closest ? n.closest(BLOCKS) : null;
      if (b && ed.contains(b)) { leafs.push(b); }
    }
    leafs.forEach(function (b) { setAlign(b, cls); });
    ed.focus();
  }

  // ---------- 표 ----------
  function currentCell() {
    restore();
    var s = window.getSelection();
    var n = s.anchorNode;
    if (!n) { return null; }
    if (n.nodeType === 3) { n = n.parentNode; }
    var c = n.closest ? n.closest("td,th") : null;
    return c && ed.contains(c) ? c : null;
  }

  function emptyCell(tag) {
    var c = document.createElement(tag || "td");
    c.innerHTML = "<br>";
    return c;
  }

  var rowsInput, colsInput, headInput;
  function insertTable() {
    var r = Math.max(1, Math.min(30, parseInt(rowsInput.value, 10) || 3));
    var c = Math.max(1, Math.min(10, parseInt(colsInput.value, 10) || 3));
    var html = '<table class="doc-table"><tbody>';
    for (var i = 0; i < r; i++) {
      html += "<tr>";
      for (var j = 0; j < c; j++) {
        var tag = headInput.checked && i === 0 ? "th" : "td";
        html += "<" + tag + "><br></" + tag + ">";
      }
      html += "</tr>";
    }
    run("insertHTML", html + "</tbody></table><p><br></p>");
  }

  function tableOp(op) {
    var c = currentCell();
    if (!c) { window.alert("표 안의 칸을 먼저 선택하세요."); return; }
    var tr = c.parentNode;
    var table = c.closest("table");
    var idx = c.cellIndex;
    if (op === "row+") {
      var nr = document.createElement("tr");
      for (var i = 0; i < tr.cells.length; i++) { nr.appendChild(emptyCell(tr.cells[i].tagName === "TH" && tr.rowIndex !== 0 ? "td" : "td")); }
      tr.parentNode.insertBefore(nr, tr.nextSibling);
    } else if (op === "col+") {
      Array.prototype.forEach.call(table.rows, function (row) {
        var ref = row.cells[idx];
        var nc = emptyCell(ref && ref.tagName === "TH" ? "th" : "td");
        if (ref) { ref.parentNode.insertBefore(nc, ref.nextSibling); } else { row.appendChild(nc); }
      });
    } else if (op === "row-") {
      tr.parentNode.removeChild(tr);
      if (!table.rows.length) { table.parentNode.removeChild(table); }
    } else if (op === "col-") {
      Array.prototype.forEach.call(table.rows, function (row) { if (row.cells[idx]) { row.removeChild(row.cells[idx]); } });
      if (!table.rows[0] || !table.rows[0].cells.length) { table.parentNode.removeChild(table); }
    } else if (op === "table-") {
      table.parentNode.removeChild(table);
    } else if (op === "merge") {
      var next = c.nextElementSibling;
      if (!next) { window.alert("오른쪽에 합칠 칸이 없습니다."); return; }
      var span = (c.colSpan || 1) + (next.colSpan || 1);
      if (span > 20) { return; }
      if (next.textContent.trim()) { c.appendChild(document.createTextNode(" ")); while (next.firstChild) { c.appendChild(next.firstChild); } }
      c.setAttribute("colspan", String(span));
      next.parentNode.removeChild(next);
    } else if (op === "split") {
      var n = c.colSpan || 1;
      if (n < 2) { return; }
      c.removeAttribute("colspan");
      for (var k = 1; k < n; k++) { c.parentNode.insertBefore(emptyCell(c.tagName.toLowerCase()), c.nextSibling); }
    }
    ensureBlocks();
    ed.focus();
  }

  // ---------- 도구 모음 ----------
  var g1 = group("글자 모양");
  g1.appendChild(button("가", "굵게 (Ctrl+B)", function () { run("bold"); }));
  g1.appendChild(button("가", "기울임 (Ctrl+I)", function () { run("italic"); }));
  g1.appendChild(button("가", "밑줄 (Ctrl+U)", function () { run("underline"); }));
  g1.appendChild(button("가", "취소선", function () { run("strikeThrough"); }));
  g1.children[0].className += " rt-b"; g1.children[1].className += " rt-i"; g1.children[2].className += " rt-u"; g1.children[3].className += " rt-s";
  var g2 = group("크기와 색");
  g2.appendChild(select(SIZES, function (v) { run("fontSize", v); }));
  g2.appendChild(select(COLORS, function (v) { var c = COLORS.filter(function (x) { return x[0] === v; })[0]; run("foreColor", c[2]); }));
  g2.appendChild(select(BGS, function (v) { var c = BGS.filter(function (x) { return x[0] === v; })[0]; run("foreColor", c[2]); }));
  var g3 = group("문단");
  g3.appendChild(select(BLOCK_FORMATS, function (v) { run("formatBlock", "<" + v + ">"); }));
  g3.appendChild(button("왼쪽", "왼쪽 정렬", function () { align("al-left"); }));
  g3.appendChild(button("가운데", "가운데 정렬", function () { align("al-center"); }));
  g3.appendChild(button("오른쪽", "오른쪽 정렬", function () { align("al-right"); }));
  g3.appendChild(button("양쪽", "양쪽 정렬", function () { align("al-justify"); }));
  var g4 = group("목록과 줄");
  g4.appendChild(button("• 목록", "글머리 목록", function () { run("insertUnorderedList"); }));
  g4.appendChild(button("1. 목록", "번호 목록", function () { run("insertOrderedList"); }));
  g4.appendChild(button("가로줄", "가로줄 넣기", function () { run("insertHorizontalRule"); }));
  g4.appendChild(button("서식 지우기", "선택한 글의 서식 지우기", function () {
    restore();
    document.execCommand("removeFormat", false, null);
    var s = window.getSelection();
    if (s.rangeCount) {
      var range = s.getRangeAt(0);
      ed.querySelectorAll("span").forEach(function (sp) { if (range.intersectsNode(sp)) { unwrap(sp); } });
    }
    normalize(); ensureBlocks();
  }));

  var g5 = group("표 넣기");
  function number(label, value, max) {
    var l = document.createElement("label");
    l.className = "rt-num";
    l.appendChild(document.createTextNode(label + " "));
    var i = document.createElement("input");
    i.type = "number"; i.min = "1"; i.max = String(max); i.value = String(value);
    l.appendChild(i);
    g5.appendChild(l);
    return i;
  }
  rowsInput = number("행", 3, 30);
  colsInput = number("열", 3, 10);
  var hl = document.createElement("label");
  hl.className = "rt-num";
  headInput = document.createElement("input");
  headInput.type = "checkbox"; headInput.checked = true;
  hl.appendChild(headInput);
  hl.appendChild(document.createTextNode(" 첫 줄은 제목 줄"));
  g5.appendChild(hl);
  g5.appendChild(button("표 삽입", "표 삽입", insertTable));
  var g6 = group("표 고치기");
  [["행 추가", "현재 줄 아래에 행 추가", "row+"], ["열 추가", "현재 칸 오른쪽에 열 추가", "col+"], ["행 삭제", "현재 행 삭제", "row-"],
    ["열 삭제", "현재 열 삭제", "col-"], ["칸 합치기", "오른쪽 칸과 합치기", "merge"], ["칸 나누기", "합친 칸 나누기", "split"],
    ["표 삭제", "표 전체 삭제", "table-"]].forEach(function (o) { g6.appendChild(button(o[0], o[1], function () { tableOp(o[2]); })); });

  // ---------- 붙여넣기: 같은 허용 목록으로 정리 ----------
  function walk(from, to) {
    Array.prototype.forEach.call(from.childNodes, function (n) {
      if (n.nodeType === 3) { to.appendChild(document.createTextNode(n.nodeValue)); return; }
      if (n.nodeType !== 1) { return; }
      var tag = n.tagName.toLowerCase();
      if (DROP[tag]) { return; }
      if (tag === "b" && n.style && n.style.fontWeight === "normal") { walk(n, to); return; }   // 구글 문서가 붙이는 껍데기 <b>
      if (!ALLOWED[tag]) { walk(n, to); return; }
      var el = document.createElement(tag === "strike" ? "s" : tag);
      (n.getAttribute("class") || "").split(/\s+/).forEach(function (c) { if (CLASS_OK.test(c)) { el.classList.add(c); } });
      ["colspan", "rowspan"].forEach(function (a) { var v = n.getAttribute(a); if (v && /^\d+$/.test(v) && +v > 1 && +v <= 20) { el.setAttribute(a, v); } });
      walk(n, el);
      to.appendChild(el);
    });
  }

  ed.addEventListener("paste", function (e) {
    var cd = e.clipboardData;
    if (!cd) { return; }
    e.preventDefault();
    var html = cd.getData("text/html");
    if (html) {
      var doc = new DOMParser().parseFromString(html, "text/html");
      var out = document.createElement("div");
      walk(doc.body, out);
      run("insertHTML", out.innerHTML);
    } else {
      run("insertText", cd.getData("text/plain"));
    }
  });
  ed.addEventListener("drop", function (e) {                          // 끌어다 놓은 파일로 화면이 이동하지 않게(첨부는 아래 첨부 칸을 쓴다)
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) { e.preventDefault(); }
  });
  ed.addEventListener("keydown", function (e) {                       // 표 안에서 Tab → 다음 칸(마지막 칸이면 새 행)
    if (e.key !== "Tab" || e.ctrlKey || e.altKey || e.metaKey) { return; }
    var s = window.getSelection();
    var n = s.anchorNode && (s.anchorNode.nodeType === 3 ? s.anchorNode.parentNode : s.anchorNode);
    var c = n && n.closest ? n.closest("td,th") : null;
    if (!c || !ed.contains(c)) { return; }
    e.preventDefault();
    var dest = e.shiftKey ? c.previousElementSibling || (c.parentNode.previousElementSibling && c.parentNode.previousElementSibling.lastElementChild)
                          : c.nextElementSibling || (c.parentNode.nextElementSibling && c.parentNode.nextElementSibling.firstElementChild);
    if (!dest && !e.shiftKey) {
      var nr = document.createElement("tr");
      for (var i = 0; i < c.parentNode.cells.length; i++) { nr.appendChild(emptyCell("td")); }
      c.parentNode.parentNode.appendChild(nr);
      dest = nr.firstElementChild;
    }
    if (dest) {
      var r = document.createRange();
      r.selectNodeContents(dest);
      r.collapse(true);
      s.removeAllRanges();
      s.addRange(r);
    }
  });

  // ---------- 불러오기와 보내기 ----------
  function plainToHtml(text) {
    var box = document.createElement("div");
    (text || "").replace(/\r\n/g, "\n").split("\n").forEach(function (line) {
      var p = document.createElement("p");
      if (line) { p.textContent = line; } else { p.appendChild(document.createElement("br")); }
      box.appendChild(p);
    });
    return box.innerHTML;
  }

  ed.innerHTML = src.getAttribute("data-format") === "html" ? src.value : plainToHtml(src.value);      // html 값은 서버가 살균한 것이다
  normalize();
  ensureBlocks();
  document.execCommand("defaultParagraphSeparator", false, "p");
  src.hidden = true;
  wrap.appendChild(bar);
  wrap.appendChild(ed);
  wrap.appendChild(hint);
  src.parentNode.insertBefore(wrap, src);

  form.addEventListener("submit", function () {
    normalize();
    ensureBlocks();
    src.value = ed.innerHTML;
    fmt.value = "html";
  });
})();
