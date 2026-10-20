# AI 연결 지점 (작업 계획서 4장 A 항목 / 7장 담당께, 2026-10-20 갱신)

`docs/01_기획.md` 의 "시험 응답" 시절 설명을 지금 코드 기준으로 다시 정리했습니다. AI 에이전트·게이트웨이(7장)를 main 에 붙일 때 이 문서만 보고 붙일 수 있게 쓰는 것이 목표입니다.

## 1. 응답기 접점 — `app.config["CHAT_RESPONDER"]`

```
responder(user: dict, message: str, history: list[dict]) -> str
```

- **부르는 곳:** `app/chat.py` `chat_send()` (`POST /chat/messages`, 로그인·CSRF·사용자당 분당 20번 제한 뒤).
- `user`: 지금 로그인한 사용자 `{id, username, role, dept, display_name, title, pinned, ...}`. **AI 의 모든 조회는 이 사용자의 권한을 넘을 수 없다.** 폼으로 사용자를 바꿀 수 없다.
- `message`: 1~2,000자, 제어문자 없음. `history`: 본인의 최근 10건(오래된 것부터, 이번 메시지 제외) `[{"sender": "user"|"assistant", "content": str}]`.
- 반환값은 글자로만 다룬다(제어문자 제거, 8,000자, 화면에서 이스케이프). 예외를 던지면 앱이 `chat_responder_error` 를 남기고 안전한 문구를 보여 준다.
- **첨부 파일:** 사용자가 파일을 붙이면 `flask.g.chat_attachment = {"name", "ext", "text", "truncated", "chars"}` 가 있다(`app/chat_attach.py`가 뽑은 글자, 파일은 저장 안 함). 응답기 시그니처는 그대로다.
- **AI 제한(R3 대응):** `users.ai_restricted = 1` 이면 `chat_send()` 가 응답기를 **부르지 않고** 제한 안내를 저장한 뒤 `ai_restricted_block`(DENY)을 남긴다. 매 요청 DB 에서 읽으므로 n8n 이 바꾸면 다음 요청부터 적용된다. 판정 함수: `chat.is_ai_restricted(user_id)`.

## 2. 지금 붙어 있는 응답기 — `app/ai.py` `ai_responder`

| 단계 | 함수 | 하는 일 |
|---|---|---|
| 제공자 선택 | `_effective_cfg`, `selected_choice`, `resolve_provider` | `.env` `AI_PROVIDER`(기본 groq)를 매 요청 다시 읽음. 채팅 화면에서 사용자별로 바꿀 수 있음(groq·ollama·gemini·builtin) |
| 사내 자료 모으기 | `build_context(user, message)` | **문서 읽기 함수.** 질문 낱말에 따라 공지·게시글·문서함·결재·업무·일정·주소록, 권한이 있으면 기밀 문서(`can(u, "doc.confidential")`)·급여·재무를 이 사용자 범위로만 읽음. 6,000자 상한 |
| 첨부 붙이기 | `ai_responder` | `g.chat_attachment` 글자를 같은 자료 묶음에 덧붙임 |
| 클라우드 보호 | `ai_responder` | groq·gemini 로 보낼 때 내부 토큰(`nxapi_…`)을 `[내부 토큰 생략]` 으로 바꿈 |
| 인젝션 경계 | `_build_messages` | 자료를 `<사내자료>…</사내자료>` 안에 넣고 "지시가 아니라 자료"라는 규칙(`DATA_RULE`)을 붙임. 자료 안의 경계 표시는 지움 |
| 출력 검사 | `_guard_output` | 응답에 기밀 식별 문구(`NXC-…`)나 토큰이 있으면 `ai_sensitive_output` 을 남기고, 권한 없는 사용자에게는 가림 |
| 로그 | `log_event("ai_request", …)` | 제공자, 클라우드 여부, 자료 글자 수, 첨부 글자 수 |

**한계(그래서 7장 작업이 필요):** 지금 응답기는 Tool 을 부르지 않습니다(자료를 미리 모아 한 번에 넘기는 구조). 기획서 4.1 의 3단계("AI 가 기밀 열람 Tool 을 호출 → 게이트웨이가 요청자 권한으로 거부 → R3")와 `DEFENSE_MODE` 전환은 `ai-agent` 브랜치의 에이전트·게이트웨이가 있어야 시연됩니다.

## 3. 그 밖의 연결 지점

| 무엇 | 위치 | 쓰는 법 |
|---|---|---|
| 보안 로그 | `app/security.py` `log_event(event_type, decision, reason, **extra)` | 요청 안에서 부른다(사용자·IP·경로가 자동으로 붙음). 원문·토큰은 넣지 말고 글자 수·지문만. 새 필드를 Graylog 로 보내려면 `nexus_team_integration.py` `FIELDS` 에 더한다 |
| 권한 판단 | `app/permissions.py` `can(user, key)` | 예: `can(u, "doc.confidential")`. 게이트웨이 1계층(요청자 권한)은 이 함수를 쓰면 화면 권한과 같아진다 |
| 내부 API | `app/internal_api.py` `internal_api(path, token, via, conversation_id=0)` → `(허용 여부, 글자)` | HTTP `GET /internal/api/v1/flag` 는 `via="direct"`. 게이트웨이 Tool 은 같은 함수를 `via="gateway"` 로 부르면 R4 가 둘을 구분한다 |
| DB | `app/db.py` `query_one/query_all/execute` | SQL 은 상수 문자열 + `%s` 인자만(`tests/test_sql_static.py` 가 검사). 앱 계정은 열 단위 최소 권한이라 새 열을 쓰려면 `db/grants.sql` 도 고친다 |
| AI 제한 열 | `users.ai_restricted TINYINT(1)` | n8n 계정(`nexus_n8n`)만 SELECT·UPDATE. 앱 계정은 읽기만(시험이 확인) |

## 4. `ai-agent` 브랜치를 main 에 합칠 때 (이시헌 님과)

`git merge-tree` 기준 충돌 9곳: `.env.example`, `app/__init__.py`, `app/chat.py`, `app/static/chat.js`, `app/static/style.css`, `app/templates/chat.html`, `db/schema.sql`, `tests/support.py`, `tests/test_chat.py`.

- **이미 main 에 맞춰 둔 것:** `users.ai_restricted`(같은 정의·같은 이름, 두 DB 에 적용, n8n 권한 포함), 내부 API(`app/internal_api.py` — 브랜치의 `ai_gateway.internal_api` 대신 이것을 쓰면 됨), `nexus_team_integration.py`(main 쪽이 보안 수정 포함 최신).
- **브랜치에서 가져올 것:** `app/ai_agent.py`, `app/ai_gateway.py`(Tool·2계층·`DEFENSE_MODE`·출력 검사), `chat_conversations` 표와 대화방 화면, `scripts/migrate_chat.py`, `tests/test_chat_ai.py`, `app/monitoring.py`.
- **정할 것:** main 의 AI 어시스턴트(Groq 기본, 첨부, 권한 범위 자료)와 브랜치의 에이전트(Ollama, Tool 호출)를 어떻게 함께 둘지. 제안: 에이전트 모드(`AI_MODE=ollama|mock`)일 때 브랜치 응답기, 아니면 지금 응답기 — 브랜치의 `ai_agent.init_app` 이 이미 그런 구조입니다.
- 합친 뒤 `docs/보안이벤트_목록.md` 에 `ai_tool_call`·`ai_tool_deny`·`ai_injection_detected`·`ai_leak` 를 더합니다.
