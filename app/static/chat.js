// 채팅: 보내기를 누르면 답이 올 때까지 단추를 막고 "생성 중" 안내를 보여 준다(중복 전송 방지). 인라인 스크립트 없이 CSP 를 지킨다.
(function () {
  var form = document.querySelector("form.composer");
  if (!form) return;
  form.addEventListener("submit", function () {
    var btn = form.querySelector("button[type=submit]");
    var note = document.getElementById("chat-busy");
    if (btn) {
      btn.disabled = true;
      btn.textContent = btn.getAttribute("data-busy") || "답변 생성 중…";
    }
    if (note) note.hidden = false;
  });
  var thread = document.querySelector("ol.thread");
  if (thread && thread.lastElementChild) thread.lastElementChild.scrollIntoView({ block: "end" });
})();
