// 글쓰기 화면: 내용 칸에 그림이나 파일을 붙여넣거나 끌어다 놓으면 첨부 칸에 넣고 목록(그림은 미리보기)을 보여 준다.
// 형식·개수·용량 제한은 없다. 서버가 파일을 무해하게(무작위 이름·항상 다운로드로만) 다루므로 여기서는 걸러 내지 않는다.
// CSP(script-src 'self', img-src 'self' data:)에 맞춰 인라인 코드와 blob: 주소를 쓰지 않는다.
(function () {
  "use strict";
  var body = document.querySelector("textarea[name=body]");
  var input = document.getElementById("attachment");
  var box = document.getElementById("attach-preview");
  if (!body || !input || !box || !window.DataTransfer) { return; }

  function clear() {
    input.value = "";
    box.hidden = true;
    box.textContent = "";
  }

  function show(files) {
    box.textContent = "";
    var label = document.createElement("p");
    label.className = "hint";
    var total = 0;
    var names = [];
    for (var i = 0; i < files.length; i++) { total += files[i].size; names.push(files[i].name); }
    label.textContent = "첨부됨 " + files.length + "개 (" + total + " bytes): " + names.join(", ") + " ";
    var remove = document.createElement("button");
    remove.type = "button";
    remove.className = "btn";
    remove.textContent = "모두 빼기";
    remove.addEventListener("click", clear);
    label.appendChild(remove);
    box.appendChild(label);
    for (var j = 0; j < files.length && j < 4; j++) {          // 그림은 처음 몇 장만 미리 보여 준다
      if (files[j].type.indexOf("image/") !== 0 || files[j].size > 5 * 1024 * 1024) { continue; }
      (function (file) {
        var reader = new FileReader();                           // data: URL 은 img-src 에 허용되어 있다(blob: 은 아님)
        reader.onload = function () {
          var img = document.createElement("img");
          img.className = "attach-img";
          img.alt = file.name;
          img.src = reader.result;
          box.appendChild(img);
        };
        reader.readAsDataURL(file);
      })(files[j]);
    }
    box.hidden = false;
  }

  function take(files) {
    if (!files || !files.length) { return false; }
    var dt = new DataTransfer();
    var i;
    for (i = 0; i < input.files.length; i++) { dt.items.add(input.files[i]); }     // 이미 고른 파일에 더한다
    for (i = 0; i < files.length; i++) {
      var f = files[i];
      var name = f.name && f.name.indexOf(".") > 0 ? f.name : "붙여넣기" + (dt.files.length + 1) + (f.type === "image/png" ? ".png" : f.type === "image/jpeg" ? ".jpg" : "");
      dt.items.add(new File([f], name, { type: f.type }));                          // 캡처 그림은 이름이 없다
    }
    input.files = dt.files;
    show(dt.files);
    return true;
  }

  body.addEventListener("paste", function (e) {
    if (e.clipboardData && take(e.clipboardData.files)) { e.preventDefault(); }
  });
  body.addEventListener("dragover", function (e) { e.preventDefault(); });
  body.addEventListener("drop", function (e) {
    if (e.dataTransfer && take(e.dataTransfer.files)) { e.preventDefault(); }
  });
  input.addEventListener("change", function () {
    if (input.files.length) { show(input.files); } else { clear(); }
  });
})();
