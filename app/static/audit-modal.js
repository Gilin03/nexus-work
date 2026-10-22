(function () {
  var panel = null;
  var titleEl, badgeEl, codeEl, closeBtn, copyBtn;
  var reasonEl, timeEl, requestEl, actorEl, extraEl;
  var activeRow = null;

  function closePanel() {
    if (!panel) return;
    panel.setAttribute("hidden", "");
    if (activeRow) {
      activeRow.classList.remove("row-selected");
      activeRow = null;
    }
  }

  function openPanel(btn) {
    if (!panel) panel = document.getElementById("audit-detail-panel");
    if (!panel) return;

    var row = btn.closest("tr");
    if (activeRow) {
      activeRow.classList.remove("row-selected");
    }
    if (row) {
      activeRow = row;
      activeRow.classList.add("row-selected");
    }

    var rawEl = row ? row.querySelector("pre.raw") : null;
    var rawText = rawEl ? rawEl.textContent : "{}";

    var time = btn.getAttribute("data-time") || "-";
    var eventType = btn.getAttribute("data-event") || "이벤트 상세";
    var decision = btn.getAttribute("data-decision") || "-";
    var user = btn.getAttribute("data-user") || "-";
    var role = btn.getAttribute("data-role") || "-";
    var ip = btn.getAttribute("data-ip") || "-";
    var reason = btn.getAttribute("data-reason") || "-";
    var method = btn.getAttribute("data-method") || "";
    var path = btn.getAttribute("data-path") || "-";
    var extra = btn.getAttribute("data-extra") || "(추가 파라미터 없음)";

    if (titleEl) titleEl.textContent = eventType;
    if (codeEl) codeEl.textContent = rawText;
    if (reasonEl) reasonEl.textContent = reason;
    if (timeEl) timeEl.textContent = time;
    if (requestEl) requestEl.textContent = method ? (method + " " + path) : path;
    if (actorEl) actorEl.textContent = user !== "-" ? (user + " (" + role + ") · " + ip) : ip;
    if (extraEl) extraEl.textContent = extra;

    if (badgeEl) {
      badgeEl.textContent = decision;
      badgeEl.className = "pill";
      if (decision === "BLOCK") {
        badgeEl.classList.add("pill-block");
      } else if (decision === "DENY") {
        badgeEl.classList.add("pill-deny");
      } else if (decision === "WARN" || decision === "ERROR") {
        badgeEl.classList.add("pill-warn");
      } else {
        badgeEl.classList.add("pill-allow");
      }
    }

    if (copyBtn) {
      copyBtn.textContent = "JSON 복사";
      copyBtn.removeAttribute("disabled");
    }

    panel.removeAttribute("hidden");
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function init() {
    panel = document.getElementById("audit-detail-panel");
    if (!panel) return;

    titleEl = document.getElementById("detail-panel-title");
    badgeEl = document.getElementById("detail-panel-badge");
    codeEl = document.getElementById("detail-panel-code");
    closeBtn = document.getElementById("detail-panel-close-btn");
    copyBtn = document.getElementById("detail-panel-copy-btn");

    reasonEl = document.getElementById("detail-panel-reason");
    timeEl = document.getElementById("detail-panel-time");
    requestEl = document.getElementById("detail-panel-request");
    actorEl = document.getElementById("detail-panel-actor");
    extraEl = document.getElementById("detail-panel-extra");

    if (closeBtn) closeBtn.addEventListener("click", closePanel);

    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        if (!codeEl) return;
        var text = codeEl.textContent;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            copyBtn.textContent = "복사 완료!";
          });
        } else {
          copyBtn.textContent = "복사 완료";
        }
      });
    }
  }

  document.addEventListener("click", function (e) {
    var btn = e.target ? e.target.closest(".audit-toggle-btn") : null;
    if (btn) {
      e.preventDefault();
      openPanel(btn);
    }
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
