// 결재 문서 화면의 "인쇄" 버튼. 인라인 이벤트 핸들러는 CSP 때문에 쓸 수 없어서 별도 파일로 둔다.
// 인쇄할 때는 style.css 의 @media print 가 메뉴·결재 처리 영역을 숨기고 공문(.gongmun)만 남긴다.
(function () {
  "use strict";
  var button = document.getElementById("print-doc");
  if (button) { button.addEventListener("click", function () { window.print(); }); }
})();
