// 프로필 사진 화면: 고른 그림을 저장하기 전에 미리 보여 준다. 서버가 형식·내용·크기를 다시 검사하므로 여기는 안내용이다.
// CSP(script-src 'self', img-src 'self' data:)에 맞춰 인라인 코드와 blob: 주소를 쓰지 않고 data: 주소로 보여 준다.
(function () {
  "use strict";
  var input = document.getElementById("photo");
  var box = document.getElementById("photo-preview");
  if (!input || !box || !window.FileReader) { return; }
  input.addEventListener("change", function () {
    box.textContent = "";
    box.hidden = true;
    var f = input.files && input.files[0];
    if (!f) { return; }
    if (f.size > 2 * 1024 * 1024) { window.alert("2MB 이하만 올릴 수 있습니다."); input.value = ""; return; }
    if (f.type !== "image/png" && f.type !== "image/jpeg") { return; }
    var reader = new FileReader();
    reader.onload = function () {
      var img = document.createElement("img");
      img.className = "avatar-preview";
      img.alt = "고른 사진 미리보기";
      img.src = reader.result;
      box.appendChild(img);
      box.hidden = false;
    };
    reader.readAsDataURL(f);
  });
})();
