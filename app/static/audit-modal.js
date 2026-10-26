(function () {
  var panel = null;
  var titleEl, badgeEl, codeEl, closeBtn, copyBtn;
  var reasonEl, timeEl, requestEl, actorEl, extraEl;
  var liveTag = null;
  var liveBadge = null, liveText = null, liveToggleBtn = null, liveToggleLabel = null;
  var activeRow = null;

  var isPaused = false;
  var userLockedRow = false;
  var evtSource = null;

  function closePanel() {
    if (!panel) return;
    panel.setAttribute("hidden", "");
    userLockedRow = false;
    if (activeRow) {
      activeRow.classList.remove("row-selected");
      activeRow = null;
    }
    if (liveTag) {
      liveTag.setAttribute("hidden", "");
    }
  }

  function setBadgeStyle(decision) {
    if (!badgeEl) return;
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

  function renderDataToPanel(data) {
    if (titleEl) titleEl.textContent = data.event_type || data.event || "보안 이벤트 상세";
    if (codeEl) codeEl.textContent = data.raw || "{}";
    if (reasonEl) reasonEl.textContent = data.reason || "-";
    if (timeEl) timeEl.textContent = data.time || "-";
    var methodPath = (data.method ? (data.method + " ") : "") + (data.path || "-");
    if (requestEl) requestEl.textContent = methodPath;
    var user = data.user || "-";
    var role = data.role || "-";
    var ip = data.src_ip || data.ip || "-";
    if (actorEl) actorEl.textContent = user !== "-" ? (user + " (" + role + ") · " + ip) : ip;
    if (extraEl) extraEl.textContent = data.extra || "(추가 파라미터 없음)";

    setBadgeStyle(data.decision || "INFO");

    if (copyBtn) {
      copyBtn.textContent = "JSON 복사";
      copyBtn.removeAttribute("disabled");
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

    userLockedRow = true;
    if (liveTag) liveTag.setAttribute("hidden", "");

    var data = {
      time: btn.getAttribute("data-time") || "-",
      event_type: btn.getAttribute("data-event") || "이벤트 상세",
      decision: btn.getAttribute("data-decision") || "-",
      user: btn.getAttribute("data-user") || "-",
      role: btn.getAttribute("data-role") || "-",
      src_ip: btn.getAttribute("data-ip") || "-",
      reason: btn.getAttribute("data-reason") || "-",
      method: btn.getAttribute("data-method") || "",
      path: btn.getAttribute("data-path") || "-",
      extra: btn.getAttribute("data-extra") || "(추가 파라미터 없음)",
      raw: rawText
    };

    renderDataToPanel(data);

    panel.removeAttribute("hidden");
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function appendTableRow(e) {
    var tbody = document.querySelector("table.audit tbody");
    if (!tbody) return;

    var tr = document.createElement("tr");
    tr.className = "new-row-flash";

    // 1. Time
    var tdTime = document.createElement("td");
    tdTime.className = "num mono";
    tdTime.textContent = e.time || "-";
    tr.appendChild(tdTime);

    // 2. Event type
    var tdEvent = document.createElement("td");
    var strong = document.createElement("strong");
    strong.textContent = e.event_type || "-";
    tdEvent.appendChild(strong);
    tr.appendChild(tdEvent);

    // 3. User
    var tdUser = document.createElement("td");
    tdUser.textContent = e.user || "-";
    tr.appendChild(tdUser);

    // 4. Role
    var tdRole = document.createElement("td");
    tdRole.textContent = e.role || "-";
    tr.appendChild(tdRole);

    // 5. Source IP
    var tdIp = document.createElement("td");
    tdIp.className = "mono";
    tdIp.textContent = (e.src_ip || "-") + " ";
    tr.appendChild(tdIp);

    // 6. Decision pill
    var tdDec = document.createElement("td");
    var pill = document.createElement("span");
    pill.textContent = e.decision || "INFO";
    pill.className = "pill";
    if (e.decision === "BLOCK") pill.classList.add("pill-block");
    else if (e.decision === "DENY") pill.classList.add("pill-deny");
    else if (e.decision === "WARN" || e.decision === "ERROR") pill.classList.add("pill-warn");
    else pill.classList.add("pill-allow");
    tdDec.appendChild(pill);
    if (e.threat_score !== undefined && e.threat_score !== null && e.threat_score !== '') {
      var aiPill = document.createElement('span');
      var score = parseInt(e.threat_score, 10);
      aiPill.className = 'pill';
      if (!isNaN(score) && score >= 80) {
        aiPill.classList.add('pill-ai-danger');
      } else if (!isNaN(score) && score >= 50) {
        aiPill.classList.add('pill-ai-warn');
      } else {
        aiPill.classList.add('pill-ai-safe');
      }
      aiPill.textContent = '🤖 AI ' + e.threat_score + '점';
      if (e.verdict) {
        aiPill.title = 'AI 판정: ' + e.verdict + ' (위협도 ' + e.threat_score + '점)';
      }
      tdDec.appendChild(aiPill);
    }
    tr.appendChild(tdDec);

    // 7. Reason
    var tdReason = document.createElement("td");
    tdReason.textContent = e.reason || "-";
    tr.appendChild(tdReason);

    // 8. Method & Path
    var tdPath = document.createElement("td");
    tdPath.className = "mono path-cell";
    tdPath.textContent = (e.method ? (e.method + " ") : "") + (e.path || "-");
    tr.appendChild(tdPath);

    // 9. Detail Action Button
    var tdAction = document.createElement("td");
    tdAction.className = "audit-action";
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "audit-toggle-btn";
    btn.textContent = "상세";
    btn.setAttribute("aria-haspopup", "dialog");
    btn.setAttribute("data-time", e.time || "-");
    btn.setAttribute("data-event", e.event_type || "-");
    btn.setAttribute("data-decision", e.decision || "-");
    btn.setAttribute("data-user", e.user || "-");
    btn.setAttribute("data-role", e.role || "-");
    btn.setAttribute("data-ip", e.src_ip || "-");
    btn.setAttribute("data-reason", e.reason || "-");
    btn.setAttribute("data-method", e.method || "");
    btn.setAttribute("data-path", e.path || "-");
    btn.setAttribute("data-extra", e.extra || "");

    var rawHidden = document.createElement("div");
    rawHidden.className = "audit-raw-hidden";
    var pre = document.createElement("pre");
    pre.className = "raw";
    pre.textContent = e.raw || "{}";
    rawHidden.appendChild(pre);

    tdAction.appendChild(btn);
    tdAction.appendChild(rawHidden);
    tr.appendChild(tdAction);

    // Prepend to table top
    tbody.insertBefore(tr, tbody.firstChild);

    // Maintain max 100 rows
    if (tbody.children.length > 100) {
      tbody.removeChild(tbody.lastChild);
    }
  }

  function updateDetailPanelLive(e) {
    if (!panel) panel = document.getElementById("audit-detail-panel");
    if (!panel) return;

    renderDataToPanel(e);

    if (liveTag) liveTag.removeAttribute("hidden");
    panel.removeAttribute("hidden");

    // Flash animation to indicate live stream update
    panel.classList.remove("panel-stream-flash");
    void panel.offsetWidth; // trigger reflow
    panel.classList.add("panel-stream-flash");
  }

  function initSSE() {
    if (!window.EventSource) {
      if (liveText) liveText.textContent = "SSE 미지원 브라우저";
      return;
    }

    try {
      evtSource = new EventSource("/admin/audit/stream");

      evtSource.onopen = function () {
        if (liveBadge) {
          liveBadge.classList.remove("is-disconnected");
          if (!isPaused) {
            liveBadge.classList.remove("is-paused");
            if (liveText) liveText.textContent = "실시간 감시 중 (LIVE)";
          }
        }
      };

      evtSource.onerror = function () {
        if (liveBadge) {
          liveBadge.classList.add("is-disconnected");
          if (liveText) liveText.textContent = "재연결 대기 중...";
        }
      };

      evtSource.onmessage = function (event) {
        if (!event || !event.data) return;
        try {
          var e = JSON.parse(event.data);
          if (!e || !e.event_type) return;

          if (isPaused) {
            return;
          }

          // 1. Update Table
          appendTableRow(e);

          // 2. Update Detail Panel if in LIVE mode (user has not locked a specific past row)
          if (!userLockedRow) {
            updateDetailPanelLive(e);
          }
        } catch (err) {
          // ignore parsing error
        }
      };
    } catch (e) {
      if (liveText) liveText.textContent = "연결 오류";
    }
  }

  function toggleLiveStream() {
    isPaused = !isPaused;
    if (isPaused) {
      if (liveBadge) liveBadge.classList.add("is-paused");
      if (liveText) liveText.textContent = "일시정지됨";
      if (liveToggleLabel) liveToggleLabel.textContent = "▶ 스트리밍 재개";
    } else {
      if (liveBadge) liveBadge.classList.remove("is-paused");
      if (liveText) liveText.textContent = "실시간 감시 중 (LIVE)";
      if (liveToggleLabel) liveToggleLabel.textContent = "⏸ 일시정지";
    }
  }

  function init() {
    panel = document.getElementById("audit-detail-panel");
    titleEl = document.getElementById("detail-panel-title");
    badgeEl = document.getElementById("detail-panel-badge");
    codeEl = document.getElementById("detail-panel-code");
    closeBtn = document.getElementById("detail-panel-close-btn");
    copyBtn = document.getElementById("detail-panel-copy-btn");
    liveTag = document.getElementById("detail-panel-live-tag");

    reasonEl = document.getElementById("detail-panel-reason");
    timeEl = document.getElementById("detail-panel-time");
    requestEl = document.getElementById("detail-panel-request");
    actorEl = document.getElementById("detail-panel-actor");
    extraEl = document.getElementById("detail-panel-extra");

    liveBadge = document.getElementById("audit-live-status");
    liveText = document.getElementById("live-text");
    liveToggleBtn = document.getElementById("live-toggle-btn");
    liveToggleLabel = document.getElementById("live-toggle-label");

    if (closeBtn) closeBtn.addEventListener("click", closePanel);

    if (liveToggleBtn) liveToggleBtn.addEventListener("click", toggleLiveStream);

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

    // Start SSE stream
    initSSE();
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
