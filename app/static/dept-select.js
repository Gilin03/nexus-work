// 부서 목록(사용자 등록·사용자 관리): "새 부서" 를 골랐을 때만 새 부서 이름 칸을 보여 준다. 스크립트가 없어도 칸이 모두 보여 그대로 쓸 수 있다.
// <select data-new-dept="입력칸 id" [data-new-field="감쌀 요소 id"]> — 감쌀 요소가 없으면 입력칸 자체를 숨긴다.
(function () {
  "use strict";
  var selects = document.querySelectorAll("select[data-new-dept]");
  Array.prototype.forEach.call(selects, function (select) {
    var input = document.getElementById(select.getAttribute("data-new-dept"));
    var field = document.getElementById(select.getAttribute("data-new-field") || "") || input;
    if (!input || !field) { return; }
    function sync(focus) {
      var isNew = select.value === "__new__";
      field.hidden = !isNew;
      input.required = isNew;
      if (isNew && focus) { input.focus(); }
    }
    select.addEventListener("change", function () { sync(true); });
    sync(false);
  });
}());
