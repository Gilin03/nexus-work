# NEXUS WORK 보안 로그 명세 초안

- 상태: 초안 v1.1
- 작성일: 2026-10-19
- 목적: 앱·AI Gateway·Wazuh 이벤트를 Graylog에서 탐지하고 필요한 이벤트를 n8n Webhook으로 전달하기 위한 인터페이스 계약
- 범위: 로그 필드, Graylog 탐지 목표 R1–R12, Graylog→n8n payload, 담당자 간 작업 순서
- 주의: 계약 기준은 v1.1이다. 실제 앱/Graylog 적용 상태는 아래 구현 부록과 `docs/WORK_LOG`에 구분해 기록한다.

## 1. 현재 저장소 상태와 결정할 점

### 확인된 구현

| 항목 | 저장소에서 확인한 상태 |
|---|---|
| 앱 보안 로그 | logs/security.jsonl, JSON Lines 형식, 한 줄당 JSON 객체 |
| 공통 필드 | ts, event_type, user, role, src_ip, method, path, decision, reason |
| 구현 이벤트 예 | login_failure, login_success, account_locked, login_locked, authz_deny, not_found, confidential_access, chat_message, chat_reply, suspicious_input, prompt_injection_detected (R2 direct only) |
| AI 방어 이벤트 | R2 `prompt_injection_detected`는 `/chat/messages` 직접 입력 차단으로 구현됨. `prompt_injection_observed`, `agent_tool_call`, `internal_api_call`은 미구현 |
| AI/상관 필드 | `request_id`는 구현됨. R2 이벤트에 한해 `session_id`, `injection_type`, `source_type`, `pattern_id`, `severity`, `source_component`가 구현됨. 나머지 AI/Gateway 이벤트 필드는 미구현 |
| R9/R10 권한 거부 | authz_deny가 공통 role/path/reason과 이벤트별 required 또는 resource를 기록하므로 조건을 좁히면 기존 로그 사용 가능 |
| 게시·첨부 | post_created는 post_id, board, attachment 여부를 기록하고 attachment_download는 attachment_id를 기록. 업로드/AI 열람/Tool 실행을 잇는 공통 상관 ID는 없음 |
| 원격 수집 설정 | 저장소에 Wazuh 또는 Graylog 설정 파일·입력 설정은 확인되지 않음 |
| FIM 대상 | 설계 문서상 업로드 파일은 instance/uploads; 문서함의 DB 레코드는 파일 FIM 대상이 아님 |

현재 app/security.py는 UTC 시각을 ts에 기록하고, 요청 IP는 request.remote_addr에서 읽는다. path는 200자까지, 부가 문자열 필드는 200자까지 기록한다. 직접 Prompt Injection은 `/chat/messages`에서 responder와 채팅 DB 저장 전에 검사·차단하며 원문 없이 R2 이벤트를 기록한다. 간접 인젝션 탐지와 Tool 권한 검사는 아직 구현되어 있지 않다.

### 민감정보 기록 주의

현재 suspicious_input은 특정 필드 이름(message, body, reason) 외에 탐지된 입력값 앞부분을 최대 80자 기록할 수 있다. AI 대화, 게시글, 첨부파일 내용은 필드 이름이 달라도 원문이 남지 않도록 앱 담당자가 점검해야 한다. 새 인젝션 이벤트에는 원문 대신 pattern_id 또는 탐지 카테고리만 기록한다.

### 수집 경로 권고와 문서 간 차이

현재 저장소의 docs/01_기획.md는 JSONL을 Wazuh localfile 수집 대상으로 적고 있다. 팀원별 계획서는 포털 GELF 입력 12201, Wazuh syslog 입력 5140을 제시한다. 같은 앱 이벤트를 두 경로로 동시에 전달하면 Graylog에서 중복 집계될 수 있으므로 다음 구성을 권고한다.

1. 앱의 security.jsonl은 로컬 증적 원본으로 유지한다.
2. 앱·AI Gateway 이벤트는 한 번만 GELF 12201로 Graylog에 전달한다. 이 전송기는 현재 저장소에 없으므로 앱/Gateway 담당자가 구현해야 한다.
3. Wazuh Agent는 업로드 폴더 FIM을 수집하고, Wazuh Manager가 JSON Syslog 5140으로 Graylog에 전달한다.
4. 동일한 앱 이벤트를 Wazuh localfile 경로로도 Graylog에 전달하지 않는다. 팀이 JSONL→Wazuh 경로를 선택하면 GELF 경로를 끄고 한 가지 경로만 사용한다.
5. 실제 IP, 호스트명, 전송 프로토콜은 팀 연결표와 설치된 Graylog/Wazuh 버전으로 확정한다. 이 초안은 주소를 임의로 정하지 않는다.

이 수집 경로는 팀의 프로젝트·역할 계획을 우선 반영한 권고안이다. docs/01_기획.md의 수집 경로 문구는 구현 착수 전에 팀에서 일치시켜야 한다.

GELF 전송기는 GELF 1.1 필수 envelope(version, host, short_message)를 채우고, custom field는 wire 형식에 맞게 전달해야 한다. GELF custom field는 표준상 underscore prefix를 사용하며 값은 string 또는 number로 제한한다. short_message/full_message에 prompt나 게시글 본문을 넣지 않는다. Graylog에 시험 메시지 한 건을 보내 저장된 실제 field 이름과 검색 이름을 확인한 뒤 event definition을 만든다. 전송 프로토콜은 문서에 정해져 있지 않으므로 팀 연결표와 Graylog input 설정으로 결정한다.

### 발표용 수집 흐름과 화면 구성

```text
앱 / AI Gateway
  → GELF
  → Graylog Input
  → 간단한 필드 정규화
  → NEXUS_AUTH / NEXUS_AI_SECURITY / NEXUS_WEB Stream
  → R1–R12 Graylog Event
  → n8n Webhook

Wazuh Agent → uploads FIM → Wazuh Manager → Graylog Input → NEXUS_WEB
```

Stream은 아래 3개만 계획한다. Stream은 발표와 검색 화면에서 로그를 목적별로 묶는 기준이고, 배치 규칙은 현재 R1–R12와 Wazuh FIM만 사용한다.

| Stream | 규칙/이벤트 배치 | 발표용 한국어 설명 |
|---|---|---|
| `NEXUS_AUTH` | R1, R5, R6, R7 | 계정 탈취와 인증 이상 행위를 탐지합니다. |
| `NEXUS_AI_SECURITY` | R2, R3, R4, R11, R12 | Prompt Injection과 AI Tool 권한 남용, 내부 API 호출을 탐지합니다. |
| `NEXUS_WEB` | R8, R9, R10, Wazuh FIM 이벤트 | 웹 권한 위반과 비정상 경로 접근, 업로드 파일 변경을 확인합니다. |

현재 `NEXUS_AUTH`는 OR 조건으로 `event_type=login_success`, `account_locked`, `login_failure`, `account_compromise_suspected`, `login_locked`, `post_lock_retry_detected`를 분류한다. R1/R6 파생 이벤트도 이 Stream에서 검색한다.

### Pipeline 계획: 기본 필드 정규화만

- 우선 `ts`를 Graylog의 timestamp로 파싱한다. 시간 필드가 정상 처리되면 추가 변환은 만들지 않는다.
- `src_ip`, `user`, `event_type` 등 앱에서 이미 같은 이름으로 들어오는 필드는 그대로 쓴다.
- `severity`, `source_component`는 생산 로그에 값이 있을 때 보존한다. 현재 앱 공통 로그에 없는 값을 Pipeline에서 임의로 만들어 채우지 않는다.
- GELF 입력에서 Graylog에 저장된 실제 필드명을 시험 메시지로 확인하고, 필요한 이름 정리만 최소한으로 추가한다. Pipeline에서 탐지 조건, 복잡한 enrichment, 새 규칙을 만들지 않는다.
- Wazuh 이벤트는 uploads FIM에 한정한다. Graylog 입력에서 FIM 필드를 검색할 수 있게 하고 `NEXUS_WEB` Stream으로 분류한다.

### 간접 Prompt Injection 시나리오 정책과 기존 설계 문서

저장소의 docs/01_기획.md는 의도적 취약점을 만들지 않는다고 적고 있다. 이번 요청의 간접 Prompt Injection 시나리오 정책은 그 문구와 충돌하므로, 이 명세에서는 **간접 인젝션 탐지로 게시/업로드를 차단하지 않는 방어전 전용 예외**로 기록한다. 일반 인증·권한 검사, 업로드 형식/크기 검증, 파일 저장 보호는 그대로 유지한다. 구현 전 팀이 기존 설계 문서에도 이 제한된 예외를 반영해야 한다.

프로젝트 PDF의 기존 R2 설명은 게시글·첨부 등 인젝션 패턴 전반을 R2 대상으로 묶고 있다. 이번 사용자 정책에 따라 R2는 직접 인젝션 차단 이벤트만 대상으로 좁히고, 간접 인젝션 경로는 콘텐츠 단계에서 차단하지 않은 뒤 Tool 권한 거부를 R3로 탐지한다.

## 2. 로그 공통 계약

모든 앱/AI 이벤트는 기존 필드명을 유지하고 필요한 필드만 추가한다. 필드가 없는 경우 임의의 실제 값으로 채우지 않는다. 식별 불가 값은 기존 계약처럼 "-"를 사용하거나 필드를 생략한다.

| 필드 | 형식 | 적용 | 의미와 제한 | 현재 상태 |
|---|---|---|---|---|
| ts | ISO 8601 UTC 문자열 | 필수 | 이벤트 발생 시각, Z 또는 +00:00 | 구현됨 |
| event_type | 문자열 | 필수 | 아래 이벤트 이름 중 하나 | 일반 이벤트 구현됨 |
| user | 문자열 | 해당 시 | 계정 사용자명, 비로그인은 "-" | 구현됨 |
| role | 문자열 | 해당 시 | 이벤트 시점의 역할 | 구현됨 |
| src_ip | IP 문자열 | 해당 시 | 신뢰된 ingress가 관찰한 원 IP | 구현됨, 프록시 신뢰 설정은 별도 확인 |
| method | 문자열 | HTTP 요청 | HTTP method | 구현됨 |
| path | 문자열 | HTTP 요청 | 민감 쿼리/경로 값 제외한 경로 | 구현됨 |
| decision | 열거형 | 필수 | ALLOW, DENY, BLOCK, INFO, WARN, ERROR | 구현됨 |
| reason | 코드 문자열 | 필수 | direct_prompt_injection, insufficient_permission 등 안정된 코드; 원문 설명 금지 | 구현됨 |
| request_id | 불투명 ID | 새 이벤트 필수 | 한 요청/Tool 호출의 상관관계 ID. 비밀값이 아니며 재사용 가능한 인증 토큰이 아님 | 구현됨 |
| session_id | 불투명·가명 ID | AI 이벤트 필수, 로그인 이벤트 선택 | 같은 사용자 세션의 상관관계용. 쿠키, 세션 서명값, API token을 넣지 않음 | R2에서 서버 생성 opaque ID 구현됨; 그 외 AI 이벤트는 미구현 |
| source_component | 문자열 | 새 이벤트 권장 | portal, ai_gateway, security_gateway, wazuh 등 생성 구성요소 | R2는 `portal`로 구현됨 |
| severity | 문자열 | 보안 탐지 이벤트 | info, low, medium, high, critical | R2는 `high`로 구현됨 |
| pattern_id | 문자열 | 직접 인젝션 탐지 | 탐지 카테고리/룰 ID만 기록하고 입력 문구는 기록하지 않음 | R2의 3개 허용 ID로 구현됨 |
| injection_type | 열거형 | 인젝션 관련 이벤트 | direct 또는 indirect | R2 `direct` 구현됨; 간접 이벤트는 미구현 |
| source_type | 열거형 | 인젝션 관련 이벤트 | chat, post, attachment, document | R2 `chat` 구현됨 |
| trigger_source | 열거형 | AI Tool 호출 이벤트 | direct_prompt_injection, indirect_prompt_injection, user_request, unknown 등 | 미구현 |
| tool_name | 문자열 | Tool 호출 이벤트 | 호출 대상 Tool의 이름 | 미구현 |
| resource_class | 문자열 | 보호 자원 Tool 이벤트 | public, internal, confidential, restricted 등 등급 | 미구현 |
| resource | 문자열 | 필요 시 | 문서 내용 대신 승인된 식별자 또는 비민감한 이름만 기록 | 이벤트별 확인 필요 |
| resource_id | 불투명 ID | 콘텐츠 입력/AI 열람 이벤트 | 게시글·첨부·문서 ID. 파일명이나 본문 대신 불투명 식별자를 우선 | 일부 이벤트에서만 구현 |
| trigger_resource_id | 불투명 ID | agent_tool_call | 해당 Tool 호출을 유도한 콘텐츠의 resource_id. 보호 대상 Tool의 대상 resource와 구분 | 미구현 |
| required | 문자열 | authz_deny | 거부된 역할 조건. 예: admin 또는 manager,admin | role_required/admin 경로에서 추가 필드로 구현됨 |
| caller_service | 문자열 | 내부 API 이벤트 | 호출 서비스 식별자, 인증 토큰 원문 금지 | 미구현 |
| action_level | 열거형 | Graylog→n8n 계약 | observe, alert, contain 중 규칙별 권고 대응 강도. 실행 결과/자동 차단을 뜻하지 않음 | 신규 계약 |

### 공통 개인정보·비밀값 정책

- 비밀번호, API token, 세션 쿠키/서명값, Authorization 헤더 원문은 기록하지 않는다.
- 프롬프트·게시글·첨부·문서 본문을 로그, Graylog event backlog, n8n payload에 넣지 않는다.
- 공격 문자열을 남기는 대신 pattern_id, injection_type, source_type, decision, reason을 남긴다.
- session 상관관계가 필요하면 쿠키/토큰 값이 아닌 별도의 불투명 ID를 쓴다.
- 프록시가 있는 배포에서는 임의의 X-Forwarded-For를 신뢰하지 않는다. 알려진 프록시만 신뢰하도록 구성하고 그 결과를 src_ip로 사용한다.

## 3. 이벤트 예시

아래 예시는 인터페이스 모양을 설명하는 mock이다. 새 AI 이벤트가 현재 구현되어 있다는 의미는 아니다. IP와 사용자 값은 예시 데이터다.

### 3.1 R1 입력 이벤트: 로그인 실패 후 성공

    {
      "ts": "2026-10-19T02:00:00Z",
      "event_type": "login_failure",
      "source_component": "portal",
      "user": "kim",
      "role": "employee",
      "src_ip": "203.0.113.30",
      "method": "POST",
      "path": "/login",
      "decision": "DENY",
      "reason": "bad_password",
      "request_id": "req-r1-fail-001"
    }

    {
      "ts": "2026-10-19T02:02:00Z",
      "event_type": "login_success",
      "source_component": "portal",
      "user": "kim",
      "role": "employee",
      "src_ip": "203.0.113.30",
      "method": "POST",
      "path": "/login",
      "decision": "ALLOW",
      "reason": "ok",
      "request_id": "req-r1-success-001",
      "session_id": "sess-opaque-001"
    }

앱은 같은 user의 300초 내 `login_failure` 3회 이상 뒤 `login_success`가 확인되면 `account_compromise_suspected`를 추가 기록한다. Graylog R1은 그 파생 이벤트와 원본 `account_locked`를 한 Event Definition의 OR 조건으로 탐지한다. 실패 5회로 잠긴 경우에 account_locked 파생 이벤트를 중복 생성하지 않는다.

### 3.2 직접 Prompt Injection: R2 차단 이벤트

    {
      "ts": "2026-10-19T02:10:00Z",
      "event_type": "prompt_injection_detected",
      "source_component": "portal",
      "injection_type": "direct",
      "source_type": "chat",
      "pattern_id": "ignore_previous_instructions",
      "user": "kim",
      "role": "employee",
      "src_ip": "203.0.113.30",
      "session_id": "sess-opaque-001",
      "request_id": "req-r2-001",
      "decision": "DENY",
      "reason": "direct_prompt_injection",
      "severity": "high"
    }

현재 구현은 Flask `/chat/messages` 입력 경계에서 responder 호출, 채팅 이력 조회 및 DB 저장 전에 직접 입력을 검사한다. 매칭되면 HTTP 403으로 응답하고 사용자/assistant 채팅 행을 저장하지 않는다. R2 이벤트에는 원문 대신 `pattern_id`만 남기며, prompt 원문은 채팅 DB, JSONL, GELF에 기록하지 않는다. `session_id`는 서버가 생성한 opaque ID이고 Flask 세션 쿠키 값을 복사하지 않는다. 일반 질문/설명/분석 요청은 명령형 공개·우회 의도가 없으면 통과시킨다.

초기 탐지 집합은 다음 세 ID로 제한한다.

| pattern_id | 탐지 의도 | 오탐 방지 기준 |
|---|---|---|
| `ignore_previous_instructions` | 이전/시스템/개발자 지시를 무시·대체하라는 직접 명령 | 문장 시작의 명령형 지시를 요구하며, 주제 설명이나 문장 분석 질문은 차단하지 않음 |
| `reveal_hidden_prompt` | 숨겨진 시스템/개발자 프롬프트를 출력·공개하라는 직접 요청 | 공개 동사와 보호 프롬프트 대상이 함께 있어야 함 |
| `policy_bypass_protected_data` | 보안/접근 정책 우회와 기밀·관리자 데이터 취득을 함께 지시 | 문장 앞에서 시작하는 명령형 우회와 보호 데이터 요청이 같은 문장에 있어야 하며, 인용·설명 속 단어 일부 일치는 제외 |

탐지기는 정규화된 입력 문장을 평가하고 안정된 ID만 반환한다. 명령 의도는 문장 앞에서 시작해야 하며 단어 일부만 일치한 인용·설명은 차단하지 않는다. 직접 Prompt Injection이 아닌 교육·설명·분석 질문은 차단 대상이 아니다. Graylog R2 Event Definition은 `[NEXUS][R2] 직접 Prompt Injection 차단`이며 `NEXUS_AI_SECURITY` Stream에서 `event_type=prompt_injection_detected AND injection_type=direct AND decision=DENY`를 탐지한다. 이 구현 부록의 실환경 상태와 positive/negative 결과는 `docs/WORK_LOG/2026-10-19.md`에 기록한다.

실행 환경의 Graylog 6.1.16 Community에서 해당 Event Definition은 ENABLED 상태이며 ID는 `6ad5b4e09d0f6c101dafec4d`이다. 기존 `NEXUS_AI_SECURITY` Stream(ID `6ad58aad9d0f6c101daf8065`)을 사용하고 Stream 설정은 변경하지 않았다. 탐지 query는 위 조건과 같고 검색 창 및 실행 간격은 각각 15초다. 실제 positive/negative 검증은 작업 기록에 구분해 둔다.

### 3.3 간접 Prompt Injection: 관찰 이벤트(선택)

    {
      "ts": "2026-10-19T02:15:00Z",
      "event_type": "prompt_injection_observed",
      "source_component": "ai_gateway",
      "injection_type": "indirect",
      "source_type": "attachment",
      "resource_id": "att-opaque-001",
      "request_id": "req-indirect-001",
      "decision": "ALLOW",
      "reason": "lab_scenario",
      "severity": "info"
    }

이 이벤트는 관찰·증빙용이다. Graylog R2를 발생시키거나 게시/업로드를 차단하는 용도로 사용하지 않는다. 실제로는 파일 본문 대신 비민감한 resource ID를 우선 사용한다.

### 3.4 간접 Prompt Injection 이후 위험 Tool 거부: R3

    {
      "ts": "2026-10-19T02:16:00Z",
      "event_type": "agent_tool_call",
      "source_component": "security_gateway",
      "user": "kim",
      "role": "employee",
      "src_ip": "203.0.113.30",
      "session_id": "sess-opaque-001",
      "request_id": "req-r3-001",
      "tool_name": "restricted_document_read",
      "resource_class": "confidential",
      "injection_type": "indirect",
      "source_type": "attachment",
      "trigger_source": "indirect_prompt_injection",
      "decision": "DENY",
      "reason": "insufficient_permission",
      "severity": "high"
    }

Security Gateway는 직접/간접 인젝션 여부와 무관하게 매 Tool 호출마다 현재 사용자·역할·자원 권한을 검사한다. 이 검사가 최종 피해 방어선이다.

### 3.5 R4 비정상 Internal API 호출

    {
      "ts": "2026-10-19T02:20:00Z",
      "event_type": "internal_api_call",
      "source_component": "api_gateway",
      "caller_service": "ai-gateway",
      "user": "kim",
      "role": "employee",
      "src_ip": "203.0.113.44",
      "method": "POST",
      "path": "/internal/tools/read",
      "request_id": "req-r4-001",
      "decision": "ALLOW",
      "reason": "unexpected_source",
      "severity": "high"
    }

R4는 실제 포털/게이트웨이 허용 IP 목록과 src_ip를 비교한다. 허용 IP 목록은 팀 연결표에서 받아야 하며 코드/설정에 임의 IP를 넣지 않는다. 내부 API token 값은 필드로 제공하지 않는다.

### 3.6 Wazuh FIM 이벤트의 Graylog 정규화 예

    {
      "ts": "2026-10-19T02:30:00Z",
      "event_type": "file_integrity_change",
      "source_component": "wazuh",
      "agent_id": "portal-01",
      "file_path": "/srv/nexus/instance/uploads/opaque-file.pdf",
      "file_action": "modified",
      "file_hash": "sha256:example",
      "decision": "INFO",
      "reason": "fim_change",
      "severity": "medium"
    }

이 모양은 Wazuh 원본 필드와 Graylog field mapping을 합의하기 위한 정규화 예시다. 실제 Wazuh alert field 이름은 설치 버전과 alert 형식에서 확인한 뒤 매핑한다.

### 3.7 R6 앱 집계 이벤트: 잠금 후 3회 재시도

    {
      "ts": "2026-10-19T02:24:03.000000+00:00",
      "event_type": "post_lock_retry_detected",
      "source_component": "portal",
      "user": "kim",
      "role": "employee",
      "src_ip": "203.0.113.30",
      "request_id": "8f1825a7d7c54b0b9f27ac743b9c86a1",
      "lock_request_id": "5a34ea2dc07e4f6db9be1d598751a988",
      "trigger_event_type": "login_locked",
      "count": 3,
      "window_seconds": 300,
      "decision": "WARN",
      "reason": "post_lock_retry_threshold_reached",
      "severity": "high"
    }

위 이벤트는 `account_locked` 이후 같은 사용자/IP의 서로 다른 요청 3회를 확인한 뒤 한 번만 기록한다. 로그인 입력값과 비밀번호는 포함하지 않는다.

### 3.8 R1 앱 집계 이벤트: 실패 후 성공

    {
      "ts": "2026-10-19T02:12:00.000000+00:00",
      "event_type": "account_compromise_suspected",
      "source_component": "portal",
      "user": "kim",
      "role": "employee",
      "src_ip": "203.0.113.30",
      "request_id": "6a6f68c63dc94836b6e24b503e18ea22",
      "failed_attempts": 3,
      "window_seconds": 300,
      "decision": "WARN",
      "reason": "login_success_after_failures",
      "severity": "high"
    }

이 파생 이벤트는 같은 user의 300초 내 실패 3회 이상 뒤 성공이 확인된 경우에만 생성한다. R1의 잠금 분기는 기존 `account_locked` 원본을 직접 매칭하며 별도 파생 이벤트를 만들지 않는다.

## 4. Graylog 탐지 규칙 목표 R1–R12

아래 표는 최종 목표 12개다. 우선순위는 구현 순서 그룹(P1–P3)이고, Graylog alert priority와는 별개다. 구현 상태는 저장소와 실행 중인 Graylog 환경에서 각각 확인한다. 현재 R1/R2/R6 Event Definition은 활성화됐고, R3/R4/R11/R12는 해당 앱/Gateway 이벤트 준비 전이라 미구현이다.

| Rule ID | 한국어 표시 이름 | stable English name | 탐지 조건 | 필수 필드 | 현재 구현 가능 여부 | 필요한 추가 작업 | 우선순위 | action_level |
|---|---|---|---|---|---|---|---|---|
| R1 | [NEXUS][R1] 계정 침해 의심 | ACCOUNT_COMPROMISE | `event_type=account_compromise_suspected` 또는 원본 `event_type=account_locked` | ts, event_type, user, src_ip, decision, reason, request_id; 파생 이벤트에는 failed_attempts/window_seconds | 앱 집계 및 Graylog OR Event Definition 구현·검증 | 같은 user의 300초 내 실패 ≥3 후 성공은 앱이 파생 이벤트 생성; account_locked는 기존 원본 이벤트를 직접 매칭 | P1 | contain |
| R2 | [NEXUS][R2] 직접 Prompt Injection 차단 | DIRECT_PROMPT_INJECTION_BLOCKED | event_type=prompt_injection_detected AND injection_type=direct AND decision=DENY | event_type, injection_type, decision, user, role, src_ip, session_id, request_id, pattern_id, severity | Flask 입력 차단 및 Graylog Event Definition 구현·positive/negative 검증 완료 | 세 가지 보수적 pattern ID만 차단; 원문 미저장, HTTP 403, responder/DB 저장 전 차단 | P1 | alert |
| R3 | [NEXUS][R3] AI Tool 권한 위반 | AI_TOOL_PERMISSION_DENIED | event_type=agent_tool_call AND decision=DENY AND tool_name ∈ 보호 Tool 목록 | event_type, tool_name, resource_class, decision, user, role, session_id, request_id, trigger_source | Security Gateway 구현 후 가능 | 매 Tool 호출의 권한 재검사; DENY 로그 생성 | P1 | contain |
| R4 | [NEXUS][R4] 비정상 Internal API 호출 | UNEXPECTED_INTERNAL_API_CALL | event_type=internal_api_call AND (src_ip 또는 caller_service가 허용 목록에 없음). 방어 전 ALLOW와 방어 후 DENY 모두 탐지하되 decision으로 구분 | event_type, src_ip, caller_service, path, decision, request_id | 앱/Gateway 로그 추가 후 가능 | 실제 Docker/Proxy에서 관찰한 정상 호출 주소를 확인해 allowlist 작성; 보호 전·후 결과 별도 증빙 | P1 | contain |
| R5 | [NEXUS][R5] 계정 스프레이 | ACCOUNT_SPRAY | 같은 src_ip에서 5분 내 서로 다른 user ≥5의 login_failure | ts, event_type, src_ip, user, decision | Graylog 집계 필요. 원본 필드는 구현됨 | distinct user 집계와 5분 window | P2 | alert |
| R6 | [NEXUS][R6] 잠금 후 로그인 재시도 | POST_LOCK_RETRY | `account_locked` 이후 다른 `request_id`의 로그인 시도만 세며, 같은 user/src_ip에서 잠금 시점부터 300초 이내 후속 시도 ≥3. 세 번째 후속 시도에 `post_lock_retry_detected` 1회 생성 | ts, event_type, user, src_ip, request_id, lock_request_id, trigger_event_type, count, window_seconds, decision, reason | 앱/MySQL 집계 및 Graylog 단일 Event Definition 구현·검증 | 원본 login_failure/account_locked/login_locked 유지; 잠금을 유발한 request_id 제외; login_locked 1건만으로는 R6 발생 금지 | P2 | alert |
| R7 | [NEXUS][R7] 심야 로그인 성공 | OFF_HOURS_LOGIN_SUCCESS | KST 00:00 이상 05:00 미만의 login_success | Graylog timestamp, event_type, user, src_ip | 현재 로그로 가능. UTC→KST 시간 처리 필요 | JSONL ts를 Graylog timestamp로 파싱; 시간 변환 또는 UTC 경계 사용 | P3 | observe |
| R8 | [NEXUS][R8] 404 경로 스캔 | NOT_FOUND_SCAN | 같은 src_ip에서 60초 내 not_found ≥30 | ts, event_type, src_ip, path | Graylog 집계 필요. 원본 이벤트는 구현됨 | 60초 count 집계 및 임계값 설정 | P3 | alert |
| R9 | [NEXUS][R9] 관리자 권한 접근 거부 | ADMIN_PATH_ACCESS_DENIED | event_type=authz_deny AND role=employee/non-admin AND reason=insufficient_role AND required=admin. path는 조사·범위 확인용이며 단독 매칭 조건으로 쓰지 않음 | event_type, role, reason, required, path, user, src_ip, decision | 현재 로그로 가능 | Graylog 단일 이벤트 필터; 관리 경로의 `required=admin` 실제 저장값 확인 | P2 | alert |
| R10 | [NEXUS][R10] 기밀 문서 직접 접근 거부 | DIRECT_CONFIDENTIAL_ACCESS_DENIED | employee의 authz_deny 중 (reason=insufficient_role AND required에 manager/admin 포함 AND path가 `/confidential/*` 또는 `/finance/*`) 또는 (reason=out_of_scope AND resource가 payroll:로 시작). confidential_access는 현재 ALLOW만 기록 | event_type, role, reason, required 또는 resource, path, user, src_ip, decision | 현재 로그로 가능. authz_deny 분기 사용 | Graylog 조건 구성; 기밀 경로/자원 범위를 실제 로그로 확인하고 오탐 튜닝 | P2 | alert |
| R11 | [NEXUS][R11] AI Tool 반복 권한 위반 | REPEATED_AI_TOOL_PERMISSION_DENIAL | event_type=agent_tool_call AND decision=DENY AND 보호 Tool; 같은 session_id 또는 user 기준 5분 내 ≥3 | ts, event_type, session_id 또는 user, tool_name, resource_class, decision | AI Gateway 로그 추가 + Graylog 집계 필요 | R3 이벤트를 먼저 생성하고 5분 반복 횟수 집계 | P3 | contain |
| R12 | [NEXUS][R12] 콘텐츠 기반 위험 AI Tool 호출 | CONTENT_TRIGGERED_PROTECTED_TOOL_DENIAL | content_ingested→같은 resource_id의 ai_content_read→10분 내 같은 request_id의 보호 Tool DENY. Tool event의 trigger_resource_id가 resource_id와 일치해야 함. 간접 인젝션 존재만으로는 발생 금지 | event_type, request_id, session_id, source_type, resource_id, trigger_resource_id, tool_name, resource_class, decision, trigger_source | **B. 필드/이벤트 추가 후 구현 가능**; 현재만으로는 불가 | 콘텐츠 입력·AI 열람·Tool 거부 로그와 resource/request/session 연결값 추가; Graylog 이벤트 상관 기능 확인 | P3 | contain |

### 구현 가능 여부와 조건

- **현재 저장소의 로그로 조건을 만들 수 있는 범위:** R5–R10. R1/R6은 아래 앱 파생 이벤트로 순서 조건을 계산한다.
- **R1/R6 상관 기능 대체:** Graylog 6.1 Community/현재 환경의 상관 기능 제약 때문에 앱 집계 이벤트 방식으로 대체한다. Graylog는 파생 이벤트를 단일 Event Definition으로 탐지한다.
- **앱/AI 구현에 의존하는 규칙:** R2는 Flask 직접 입력 경로와 Graylog Event Definition까지 구현·검증됐다. R3/R4/R11은 필요한 앱/Gateway 이벤트가 없고, R12도 입력/AI 열람/Tool 이벤트와 상관 식별자가 없어 현재 로그만으로 체인을 입증할 수 없다.
- **R12 분류:** **B. 필드 추가 후 구현 가능.** 게시/첨부 로그는 일부 존재하지만 AI가 어떤 리소스를 읽었는지, 해당 읽기가 어떤 Tool 호출을 유발했는지 나타내는 로그와 공통 ID가 없다. `prompt_injection_observed` 단독 이벤트로 R12를 만들지 않는다.
- 현재 설치는 Graylog 6.1.16 Community이며 이 환경에서 `correlation-v1`을 사용할 수 없음을 확인했다. R1/R6 순서 조건은 위 앱 집계 계약으로 유지하고 Graylog는 단일 메시지 필터를 사용한다. 복수 이벤트를 직접 연결하는 기능은 R12의 구현 전 별도 확인한다: [Graylog Event Definitions](https://go2docs.graylog.org/current/interacting_with_your_log_data/event_definitions.html), [Graylog Correlation Engine](https://go2docs.graylog.org/current/interacting_with_your_log_data/correlation_engine.html).

### R9/R10 필드 판정

- 현재 `authz_deny`는 공통 `role`, `path`, `reason`과 이벤트별 추가 필드를 기록한다. `/admin/*` 거부는 `reason=insufficient_role`, `required=admin`으로 남으므로 R9는 문자열 경로만으로 추정하지 않고 `role + reason + required`를 주 조건으로 쓴다.
- 현재 `confidential_access`는 허용된 list/read 시점에 `decision=ALLOW`만 기록한다. 직원의 `/confidential/*`·`/finance/*` 역할 거부는 `authz_deny`의 `required=manager,admin`, 직원의 범위 밖 급여 조회는 `reason=out_of_scope`, `resource=payroll:<id>`로 구분한다. R10은 경로와 권한 메타데이터를 함께 조건으로 쓰며 `confidential_access`의 DENY를 가정하지 않는다.
- R12의 상관 시간창은 초기값으로 AI의 `ai_content_read` 뒤 10분으로 둔다. 체인은 `content_ingested(resource_id)` → `ai_content_read(resource_id, request_id, session_id)` → `agent_tool_call(trigger_resource_id, request_id, session_id, decision=DENY)` 순서이며, resource ID와 request ID가 맞아야 한다. 실제 시나리오 시간에 맞춰 테스트 후 조정한다.

### R1/R6 앱 집계 이벤트 계약

Graylog 6.1 Community/현재 환경의 상관 기능 제약 때문에 앱 집계 이벤트 방식으로 대체한다. 원본 이벤트는 증거로 계속 남기며, 파생 이벤트는 탐지에 필요한 집계 결과만 추가한다.

**R6**

- 앱은 `login_failure`, `account_locked`, `login_locked`를 MySQL의 짧은 보존 상태 테이블에 저장해 인증 이벤트 순서를 계산한다.
- `account_locked`의 `request_id`는 잠금을 유발한 로그인 요청이다. 이 요청의 `login_failure`는 후속 재시도 수에서 제외한다.
- 이후 다른 `request_id`만 계산하며, 같은 `user` + `src_ip`, 잠금 시각보다 뒤이고 `account_locked.ts + 300초` 이하인 `login_failure`/`login_locked`가 count 대상이다. 정확히 300초는 포함하고 300초 초과는 제외한다.
- `login_locked` 한 건은 count 1이며 단독으로 R6를 발생시키지 않는다. count가 3이 되는 요청에서 `post_lock_retry_detected`를 한 번만 생성한다. 같은 잠금 이벤트(`lock_request_id`)에 대한 재발행은 MySQL 상태로 막는다.
- Graylog R6는 `event_type:post_lock_retry_detected` 단일 검색이다. 앱이 조건을 계산하므로 Graylog에서 재시도 의미나 임계값을 다시 추정하지 않는다.

**R1**

- 실패 3회 후 같은 `user`의 `login_success`가 300초 이내에 발생하면 앱이 `account_compromise_suspected`를 생성한다. 각 실패의 `request_id`와 성공 요청의 `request_id`는 다르다.
- 실패 횟수는 사용자 기준이며 src_ip가 달라도 같은 계정이면 합산한다. 성공이 없는 경우에는 이 파생 이벤트를 만들지 않는다.
- 다섯 번째 실패로 잠금된 경우 이미 존재하는 원본 `account_locked`를 사용한다. account_locked 전용 파생 이벤트는 중복 생성하지 않는다.
- Graylog R1은 `event_type:account_compromise_suspected OR event_type:account_locked` 한 개의 Event Definition으로 처리한다.

| 규칙 | Positive | Negative |
|---|---|---|
| R6 | account_locked 이후 같은 user/src_ip의 다른 request_id로 login_locked 3회; 3번째에 파생 이벤트 1건 | 1–2회만 시도; 다른 user/IP; 300초 초과; 잠금을 일으킨 같은 request_id만 존재 |
| R6 경계/중복 | 3번째 시도가 잠금 시각 +300초이면 1건 생성; 같은 잠금 구간 추가 시도에도 파생 이벤트 1건 유지 | +301초 시도는 count에 미포함 |
| R1 실패 후 성공 | 같은 user 실패 3회 후 300초 안에 성공하면 account_compromise_suspected 1건 | 2회 실패 후 성공; 실패 후 성공 없음; 실패 window 300초 초과 |
| R1 잠금 분기 | 원본 account_locked가 R1 조건을 충족 | account_locked 파생 이벤트를 중복 생성하지 않음 |

### 현재 적용 상태 — R1/R6

- Graylog R1 `[NEXUS][R1] 계정 침해 의심` Event Definition ID: `6ad5ac319d0f6c101dafd65b`. query는 `event_type:account_compromise_suspected OR event_type:account_locked`; 상태는 ENABLED다.
- Graylog R6 `[NEXUS][R6] 잠금 후 로그인 재시도` Event Definition ID: `6ad5aa649d0f6c101dafd3cc`. query는 `event_type:post_lock_retry_detected`; 상태는 ENABLED다.
- 두 정의는 `NEXUS_AUTH` Stream ID `6ad58a859d0f6c101daf8032`로 한정한다. 각 정의의 query, group_by, 우선순위, 실행 주기는 유지했다. Stream 분류 후 실제 앱 양성 메시지와 비인증 이벤트 음성을 확인하고, 한정한 뒤에도 R1 파생/잠금 분기 및 R6 Event 양성과 비매칭 음성이 동작하는 것을 재검증했다. Stream 변경 전에 들어온 과거 메시지는 자동 재분류하지 않는다. 자세한 증빙은 `docs/WORK_LOG/2026-10-19.md`에 기록한다.

### R1, R4, R7 및 직접/간접 정책

- R1은 프로젝트/팀 계획의 조건을 유지한다. 같은 user의 300초 내 `login_failure` 3회 이상 후 `login_success`는 앱 집계 이벤트로 만들고, 다섯 번째 실패로 발생한 `account_locked`는 원본 이벤트를 Graylog OR 조건으로 직접 탐지한다. account_locked 전용 파생 이벤트는 만들지 않는다. 저장소의 `docs/실측_검증계획_A.md`에 있는 일반 브루트포스 제안은 R1 기준을 대체하지 않는다.
- R4는 미허용 출처라는 조건으로 이벤트를 탐지하고, `decision`은 그 호출이 실제 허용됐는지(ALLOW) 차단됐는지(DENY)를 보존한다. 방어 전 ALLOW는 노출/성공 재현 증거이고, 방어 후 DENY는 차단 증거다. 둘을 같은 결과로 보고하지 않는다. 허용 목록은 Docker/Proxy 경로에서 실제 관찰한 IP와 caller_service를 기준으로 확정한다.
- 앱 `ts`는 UTC ISO 8601이다. R7의 KST 00:00–05:00은 `[00:00, 05:00)`으로 정의한다. 로그 인입 때 `ts`를 Graylog timestamp로 파싱한 다음, Graylog 규칙에서 Asia/Seoul로 변환하거나 UTC `[15:00, 20:00)` 경계를 사용한다. 사용자 화면의 timezone 표시만으로 규칙 시간대가 바뀐다고 가정하지 않는다. Graylog 문서는 검색 날짜값이 UTC 기본이며 사용자 timezone은 검색 결과 표시 시간에 반영된다고 설명한다: [Search Syntax Reference](https://go2docs.graylog.org/current/making_sense_of_your_log_data/search_syntax_reference.htm), [Search Controls](https://go2docs.graylog.org/current/making_sense_of_your_log_data/search_controls.htm).
- 직접 인젝션은 R2에서 Agent/Tool 호출 전에 차단한다. 간접 인젝션 게시물·첨부는 업로드/게시 단계에서 인젝션 사유만으로 차단하지 않는다. 보호 Tool 호출은 Security Gateway가 다시 권한을 검사해 DENY하고 R3에 기록한다. R12는 이 입력/열람→위험 Tool DENY 사슬이 연결될 때만 발생한다.

### 우선순위와 action_level

1. **P1:** R3, R1, R2, R4
2. **P2:** R9, R10, R5, R6
3. **P3:** R11, R12, R7, R8

`action_level`은 n8n 분기 설계를 위한 권고값이지, Graylog나 n8n이 이미 자동 대응한다는 뜻이 아니다. 실제 n8n은 이벤트 `decision`과 증거를 확인한 뒤 안전한 조치를 정한다. 예를 들어 R4의 ALLOW는 방어 전 성공 재현이고 DENY는 방어 후 차단이므로 실행 결과 메시지를 구분한다. R2는 앱이 이미 입력을 거부하므로 추가 사용자 차단보다 alert를 기본값으로 둔다. R7은 운영 기준을 검토할 수 있도록 observe부터 시작한다. P1–P3는 위험/필요도 순위이고 구현 의존성 순서는 아니다. 기존 로그로 만들 수 있는 R5–R10은 앱 이벤트를 기다리는 동안 먼저 구성할 수 있다.

Snort/Suricata 포트 스캔, SYN flood, pfSense 상관 규칙은 이번 R1–R12 범위에 포함하지 않는다. Wazuh FIM은 별도 증적/관찰 입력으로 유지한다.

## 6. Graylog → n8n Webhook payload

### 계약

- R1–R12 Graylog Event가 생성될 때 HTTP POST로 n8n Webhook을 호출한다. 구현 단계별로 아직 만들지 않은 규칙의 알림은 발생하지 않는다.
- 전달 시각은 UTC ISO 8601이다. `rule.id`는 R1–R12, `rule.stable_name`은 기계 분기용 영문 식별자, `rule.display_name`과 `alert.title`은 한국어 표시명이다.
- `action_level`은 규칙별 권고 계약값(observe/alert/contain)이다. 실제 차단·계정 잠금·IP 차단 실행의 증거가 아니며, n8n은 `event.decision`도 함께 분기해야 한다.
- 현재 실행 환경 Graylog 6.1.16의 Alerts UI `EventDefinitionPriorityEnum`은 `1=LOW`, `2=NORMAL`, `3=HIGH`만 지원한다. 이 환경의 Event Definition 및 webhook 예시에서 HIGH는 `priority=3`을 사용한다. `priority=4`는 UI enum에 매핑되지 않아 Events 화면 렌더링 오류를 일으킨다. 이것은 규칙 구현 우선순위 P1–P3이나 `action_level`과 다른 값이다: [Graylog 6.1.16 EventDefinitionPriorityEnum](https://github.com/Graylog2/graylog2-server/blob/6.1.16/graylog2-web-interface/src/logic/alerts/EventDefinitionPriorityEnum.ts#L17-L25), [Events priority formatter](https://github.com/Graylog2/graylog2-server/blob/6.1.16/graylog2-web-interface/src/components/events/events/Events.jsx#L94-L96).
- n8n 중복 실행 방지를 위해 alert.id를 idempotency key로 사용한다.
- event는 아래 allowlist만 포함한다. backlog, 원본 message, prompt/post/attachment body, API token은 전달하지 않는다.
- `event.evidence`는 집계·상관 규칙에만 선택적으로 넣고 `event_count`, `distinct_users`, `retry_count`, `denied_calls`, `failed_attempts`, `success_after_failures`, `window_seconds`, `correlation_window_seconds`, `after_event`, `prior_event_type`, `source_resource_id`, `lock_request_id`, `timezone`, `local_time` 같은 비민감한 필드만 허용한다. 원본 이벤트 배열은 보내지 않는다.
- Graylog custom HTTP body template 사용 가능 여부는 설치 버전/에디션에서 확인한다. 지원되면 아래 canonical envelope로 렌더링한다. 그렇지 않으면 event backlog를 0으로 설정한 Graylog 기본 HTTP payload만 사용하고, n8n 담당자가 ingress에서 canonical 형태로 normalize한다. backlog를 비울 수 없거나 원문이 포함될 가능성이 있으면 n8n에 연결하기 전에 해결한다.
- Webhook URL과 인증정보는 payload가 아니라 n8n/Graylog credential 또는 보호된 환경변수에 둔다.

### Canonical envelope

    {
      "schema_version": "1.1",
      "action_level": "contain",
      "rule": {
        "id": "R3",
        "stable_name": "AI_TOOL_PERMISSION_DENIED",
        "display_name": "[NEXUS][R3] AI Tool 권한 위반"
      },
      "alert": {
        "id": "graylog-event-id",
        "event_definition_id": "graylog-definition-id",
        "title": "[NEXUS][R3] AI Tool 권한 위반",
        "timestamp": "2026-10-19T02:16:01Z",
        "priority": 3,
        "key": "kim|sess-opaque-001"
      },
      "event": {
        "event_type": "agent_tool_call",
        "user": "kim",
        "role": "employee",
        "src_ip": "203.0.113.30",
        "session_id": "sess-opaque-001",
        "request_id": "req-r3-001",
        "tool_name": "restricted_document_read",
        "resource_class": "confidential",
        "trigger_source": "indirect_prompt_injection",
        "decision": "DENY",
        "reason": "insufficient_permission",
        "severity": "high"
      }
    }

Graylog 기본 HTTP 알림은 event definition 정보, event 객체, 설정에 따라 backlog를 포함할 수 있다. Custom HTTP Notification은 JMTE 템플릿으로 body를 정할 수 있으므로 allowlist payload를 직접 만들 수 있는지 설치 환경에서 확인한다. 실제 payload를 캡처해 민감한 원문이나 backlog가 섞이지 않는지 검증한다. Graylog 문서: [Alert Types](https://go2docs.graylog.org/current/interacting_with_your_log_data/alert_types.htm).

## 7. n8n 담당자가 바로 사용할 R1–R12 Mock Payload

다음 payload는 앞의 canonical envelope를 사용한 시험 입력이다. 실제 Graylog ID/시간을 흉내 내기 위한 예시이며 n8n이 차단·잠금·토큰 폐기를 실행한다는 뜻은 아니다. n8n 담당자는 우선 Webhook 수신, rule 분기, 실행 이력 저장까지만 mock으로 확인할 수 있다.

### R1: 계정 침해 의심

    {
      "schema_version": "1.1",
      "action_level": "contain",
      "rule": {"id": "R1", "stable_name": "ACCOUNT_COMPROMISE", "display_name": "[NEXUS][R1] 계정 침해 의심"},
      "alert": {
        "id": "mock-r1-001",
        "event_definition_id": "mock-r1",
        "title": "[NEXUS][R1] 계정 침해 의심",
        "timestamp": "2026-10-19T02:02:01Z",
        "priority": 3,
        "key": "kim"
      },
      "event": {
        "event_type": "login_success",
        "user": "kim",
        "role": "employee",
        "src_ip": "203.0.113.30",
        "decision": "ALLOW",
        "reason": "ok",
        "request_id": "req-r1-success-001",
        "evidence": {"failed_attempts": 3, "window_seconds": 300, "success_after_failures": true}
      }
    }

R1의 잠금 분기 Mock은 다음과 같다. 실제 앱 로그에서는 다섯 번째 실패에 account_locked가 함께 남는다.

    {
      "schema_version": "1.1",
      "action_level": "contain",
      "rule": {"id": "R1", "stable_name": "ACCOUNT_COMPROMISE", "display_name": "[NEXUS][R1] 계정 침해 의심"},
      "alert": {
        "id": "mock-r1-lock-001",
        "event_definition_id": "mock-r1",
        "title": "[NEXUS][R1] 계정 침해 의심",
        "timestamp": "2026-10-19T02:05:00Z",
        "priority": 3,
        "key": "kim"
      },
      "event": {
        "event_type": "account_locked",
        "user": "kim",
        "src_ip": "203.0.113.30",
        "decision": "BLOCK",
        "reason": "max_failures",
        "evidence": {"failed_attempts": 5, "window_seconds": 300}
      }
    }

### R2: 직접 Prompt Injection 차단

    {
      "schema_version": "1.1",
      "action_level": "alert",
      "rule": {"id": "R2", "stable_name": "DIRECT_PROMPT_INJECTION_BLOCKED", "display_name": "[NEXUS][R2] 직접 Prompt Injection 차단"},
      "alert": {
        "id": "mock-r2-001",
        "event_definition_id": "mock-r2",
        "title": "[NEXUS][R2] 직접 Prompt Injection 차단",
        "timestamp": "2026-10-19T02:10:00Z",
        "priority": 3,
        "key": "kim|sess-opaque-001"
      },
      "event": {
        "event_type": "prompt_injection_detected",
        "injection_type": "direct",
        "source_type": "chat",
        "pattern_id": "ignore_previous_instructions",
        "user": "kim",
        "role": "employee",
        "src_ip": "203.0.113.30",
        "session_id": "sess-opaque-001",
        "request_id": "req-r2-001",
        "decision": "DENY",
        "reason": "direct_prompt_injection",
        "severity": "high"
      }
    }

### R3: 보호 Tool 권한 거부

    {
      "schema_version": "1.1",
      "action_level": "contain",
      "rule": {"id": "R3", "stable_name": "AI_TOOL_PERMISSION_DENIED", "display_name": "[NEXUS][R3] AI Tool 권한 위반"},
      "alert": {
        "id": "mock-r3-001",
        "event_definition_id": "mock-r3",
        "title": "[NEXUS][R3] AI Tool 권한 위반",
        "timestamp": "2026-10-19T02:16:01Z",
        "priority": 3,
        "key": "kim|sess-opaque-001"
      },
      "event": {
        "event_type": "agent_tool_call",
        "user": "kim",
        "role": "employee",
        "src_ip": "203.0.113.30",
        "session_id": "sess-opaque-001",
        "request_id": "req-r3-001",
        "tool_name": "restricted_document_read",
        "resource_class": "confidential",
        "injection_type": "indirect",
        "source_type": "attachment",
        "trigger_source": "indirect_prompt_injection",
        "decision": "DENY",
        "reason": "insufficient_permission",
        "severity": "high"
      }
    }

### R4: 비정상 Internal API 호출

    {
      "schema_version": "1.1",
      "action_level": "contain",
      "rule": {"id": "R4", "stable_name": "UNEXPECTED_INTERNAL_API_CALL", "display_name": "[NEXUS][R4] 비정상 Internal API 호출"},
      "alert": {
        "id": "mock-r4-001",
        "event_definition_id": "mock-r4",
        "title": "[NEXUS][R4] 비정상 Internal API 호출",
        "timestamp": "2026-10-19T02:20:00Z",
        "priority": 3,
        "key": "203.0.113.44|ai-gateway"
      },
      "event": {
        "event_type": "internal_api_call",
        "caller_service": "ai-gateway",
        "user": "kim",
        "role": "employee",
        "src_ip": "203.0.113.44",
        "method": "POST",
        "path": "/internal/tools/read",
        "request_id": "req-r4-001",
        "decision": "ALLOW",
        "reason": "unexpected_source",
        "severity": "high"
      }
    }

### R5–R12: 보조/신규 규칙 Mock Payload

아래는 한 개씩 Webhook 분기와 payload 검증을 시작할 수 있는 mock 예시다. 집계 규칙은 `event`에 대표 원본 이벤트를 넣고 `event.evidence`에는 비민감한 집계 수치만 전달한다. 원본 backlog는 전달하지 않는다. R2 mock은 계약 예시이고, 앱 차단과 Graylog R2 탐지는 2026-10-19에 별도로 실제 검증했다. R3/R4/R11/R12 앱/Gateway 이벤트는 아직 미구현이다.

    [
      {"schema_version":"1.1","action_level":"alert","rule":{"id":"R5","stable_name":"ACCOUNT_SPRAY","display_name":"[NEXUS][R5] 계정 스프레이"},"alert":{"id":"mock-r5-001","event_definition_id":"mock-r5","title":"[NEXUS][R5] 계정 스프레이","timestamp":"2026-10-19T02:30:00Z","priority":3,"key":"203.0.113.55"},"event":{"event_type":"login_failure","user":"user05","src_ip":"203.0.113.55","decision":"DENY","reason":"bad_password","evidence":{"distinct_users":5,"window_seconds":300}}},
      {"schema_version":"1.1","action_level":"alert","rule":{"id":"R6","stable_name":"POST_LOCK_RETRY","display_name":"[NEXUS][R6] 잠금 후 로그인 재시도"},"alert":{"id":"mock-r6-001","event_definition_id":"mock-r6","title":"[NEXUS][R6] 잠금 후 로그인 재시도","timestamp":"2026-10-19T02:35:00Z","priority":3,"key":"kim|203.0.113.30"},"event":{"event_type":"login_locked","user":"kim","src_ip":"203.0.113.30","decision":"DENY","reason":"account_locked","evidence":{"retry_count":3,"window_seconds":300,"after_event":"account_locked"}}},
      {"schema_version":"1.1","action_level":"observe","rule":{"id":"R7","stable_name":"OFF_HOURS_LOGIN_SUCCESS","display_name":"[NEXUS][R7] 심야 로그인 성공"},"alert":{"id":"mock-r7-001","event_definition_id":"mock-r7","title":"[NEXUS][R7] 심야 로그인 성공","timestamp":"2026-10-19T17:30:00Z","priority":1,"key":"kim"},"event":{"event_type":"login_success","user":"kim","src_ip":"203.0.113.30","decision":"ALLOW","reason":"ok","evidence":{"timezone":"Asia/Seoul","local_time":"2026-10-20T02:30:00+09:00"}}},
      {"schema_version":"1.1","action_level":"alert","rule":{"id":"R8","stable_name":"NOT_FOUND_SCAN","display_name":"[NEXUS][R8] 404 경로 스캔"},"alert":{"id":"mock-r8-001","event_definition_id":"mock-r8","title":"[NEXUS][R8] 404 경로 스캔","timestamp":"2026-10-19T02:40:00Z","priority":3,"key":"203.0.113.55"},"event":{"event_type":"not_found","user":"-","src_ip":"203.0.113.55","path":"/missing/route","decision":"INFO","reason":"no_such_path","evidence":{"event_count":30,"window_seconds":60}}},
      {"schema_version":"1.1","action_level":"alert","rule":{"id":"R9","stable_name":"ADMIN_PATH_ACCESS_DENIED","display_name":"[NEXUS][R9] 관리자 권한 접근 거부"},"alert":{"id":"mock-r9-001","event_definition_id":"mock-r9","title":"[NEXUS][R9] 관리자 권한 접근 거부","timestamp":"2026-10-19T02:45:00Z","priority":3,"key":"kim|/admin/users"},"event":{"event_type":"authz_deny","user":"kim","role":"employee","src_ip":"203.0.113.30","path":"/admin/users","decision":"DENY","reason":"insufficient_role","required":"admin"}},
      {"schema_version":"1.1","action_level":"alert","rule":{"id":"R10","stable_name":"DIRECT_CONFIDENTIAL_ACCESS_DENIED","display_name":"[NEXUS][R10] 기밀 문서 직접 접근 거부"},"alert":{"id":"mock-r10-001","event_definition_id":"mock-r10","title":"[NEXUS][R10] 기밀 문서 직접 접근 거부","timestamp":"2026-10-19T02:50:00Z","priority":3,"key":"kim|/confidential/42"},"event":{"event_type":"authz_deny","user":"kim","role":"employee","src_ip":"203.0.113.30","path":"/confidential/42","decision":"DENY","reason":"insufficient_role","required":"manager,admin"}},
      {"schema_version":"1.1","action_level":"contain","rule":{"id":"R11","stable_name":"REPEATED_AI_TOOL_PERMISSION_DENIAL","display_name":"[NEXUS][R11] AI Tool 반복 권한 위반"},"alert":{"id":"mock-r11-001","event_definition_id":"mock-r11","title":"[NEXUS][R11] AI Tool 반복 권한 위반","timestamp":"2026-10-19T02:55:00Z","priority":4,"key":"kim|sess-opaque-001"},"event":{"event_type":"agent_tool_call","user":"kim","role":"employee","session_id":"sess-opaque-001","request_id":"req-r11-003","tool_name":"restricted_document_read","resource_class":"confidential","decision":"DENY","reason":"insufficient_permission","evidence":{"denied_calls":3,"window_seconds":300}}},
      {"schema_version":"1.1","action_level":"contain","rule":{"id":"R12","stable_name":"CONTENT_TRIGGERED_PROTECTED_TOOL_DENIAL","display_name":"[NEXUS][R12] 콘텐츠 기반 위험 AI Tool 호출"},"alert":{"id":"mock-r12-001","event_definition_id":"mock-r12","title":"[NEXUS][R12] 콘텐츠 기반 위험 AI Tool 호출","timestamp":"2026-10-19T03:00:00Z","priority":4,"key":"kim|sess-opaque-001|req-r12-001"},"event":{"event_type":"agent_tool_call","user":"kim","role":"employee","session_id":"sess-opaque-001","request_id":"req-r12-001","tool_name":"restricted_document_read","resource_class":"confidential","source_type":"attachment","trigger_source":"indirect_prompt_injection","trigger_resource_id":"att-opaque-042","decision":"DENY","reason":"insufficient_permission","evidence":{"prior_event_type":"ai_content_read","source_resource_id":"att-opaque-042","correlation_window_seconds":600}}}
    ]

### 실제 5070 R1/R6 결과를 사용한 n8n payload 예시

아래 envelope는 실제 5070 인증 흐름과 Graylog Event/source message에서 확인한 값으로 schema_version 1.1 형태를 구성한 전달 예시다. n8n Webhook은 아직 연결하지 않았으므로 실제 HTTP 전달 body 캡처나 실행 이력 검증으로 간주하지 않는다. 테스트 계정은 검증 뒤 삭제했으며 보안 로그와 Graylog 증거는 보존돼 있다.

**R1 실패 3회 후 로그인 성공**

    {
      "schema_version": "1.1",
      "action_level": "contain",
      "rule": {"id": "R1", "stable_name": "ACCOUNT_COMPROMISE", "display_name": "[NEXUS][R1] 계정 침해 의심"},
      "alert": {
        "id": "01M59BBT2EHSY1VBST5MAM0H97",
        "event_definition_id": "6ad5ac319d0f6c101dafd65b",
        "title": "[NEXUS][R1] 계정 침해 의심",
        "timestamp": "2026-10-19T05:50:15.614Z",
        "priority": 3,
        "key": "account_compromise_suspected|nxr1stream_f5c33f|4861e75cab5a6fbd4fc215fd15a1a727"
      },
      "event": {
        "event_type": "account_compromise_suspected",
        "source_component": "portal",
        "user": "nxr1stream_f5c33f",
        "role": "employee",
        "src_ip": "127.0.0.1",
        "request_id": "4861e75cab5a6fbd4fc215fd15a1a727",
        "decision": "WARN",
        "reason": "login_success_after_failures",
        "severity": "high",
        "evidence": {"failed_attempts": 3, "window_seconds": 300}
      }
    }

**R1 잠금 원본 분기**

    {
      "schema_version": "1.1",
      "action_level": "contain",
      "rule": {"id": "R1", "stable_name": "ACCOUNT_COMPROMISE", "display_name": "[NEXUS][R1] 계정 침해 의심"},
      "alert": {
        "id": "01M59BBT2EM7FBF6G6RTAJ82BS",
        "event_definition_id": "6ad5ac319d0f6c101dafd65b",
        "title": "[NEXUS][R1] 계정 침해 의심",
        "timestamp": "2026-10-19T05:50:15.614Z",
        "priority": 3,
        "key": "account_locked|nxr6stream_f5c33f|11de0b50a5f4b995c0d0346f348ee78e"
      },
      "event": {
        "event_type": "account_locked",
        "source_component": "portal",
        "user": "nxr6stream_f5c33f",
        "role": "-",
        "src_ip": "127.0.0.1",
        "request_id": "11de0b50a5f4b995c0d0346f348ee78e",
        "decision": "BLOCK",
        "reason": "max_failures",
        "severity": "medium"
      }
    }

**R6 잠금 후 세 번째 재시도**

    {
      "schema_version": "1.1",
      "action_level": "alert",
      "rule": {"id": "R6", "stable_name": "POST_LOCK_RETRY", "display_name": "[NEXUS][R6] 잠금 후 로그인 재시도"},
      "alert": {
        "id": "01M59BC38NS87B7SQQ65BFY5G4",
        "event_definition_id": "6ad5aa649d0f6c101dafd3cc",
        "title": "[NEXUS][R6] 잠금 후 로그인 재시도",
        "timestamp": "2026-10-19T05:50:24.443Z",
        "priority": 3,
        "key": "11de0b50a5f4b995c0d0346f348ee78e"
      },
      "event": {
        "event_type": "post_lock_retry_detected",
        "source_component": "portal",
        "user": "nxr6stream_f5c33f",
        "role": "-",
        "src_ip": "127.0.0.1",
        "request_id": "bef1d0e937454d06c6c1384bce0fe8f4",
        "trigger_event_type": "login_locked",
        "decision": "WARN",
        "reason": "post_lock_retry_threshold_reached",
        "severity": "high",
        "evidence": {
          "retry_count": 3,
          "window_seconds": 300,
          "after_event": "account_locked",
          "lock_request_id": "11de0b50a5f4b995c0d0346f348ee78e"
        }
      }
    }

## 8. 앱/Gateway 담당자에게 요청할 구현 항목

1. 기존 공통 필드와 JSONL 형식은 유지하면서 앱/AI Gateway 이벤트를 Graylog GELF 12201로 한 번만 전송한다. logs/security.jsonl과 원격 Graylog에서 같은 이벤트를 식별할 수 있도록 request_id를 넣는다.
2. request_id 생성·전파와 AI 작업용 불투명 session_id를 추가한다. session cookie나 token 값을 재사용하지 않는다.
3. 직접 인젝션은 Agent/Tool 호출 전에 탐지·차단하고 prompt_injection_detected를 DENY로 기록한다. 원문 대신 pattern_id를 기록한다. 현재 Flask `/chat/messages` 경로는 구현됐으며, 추가 AI Gateway가 연결되면 동일한 정책을 유지한다.
4. 간접 인젝션 콘텐츠는 이번 시나리오에서 injection 검출만으로 차단하지 않는다. 필요하면 prompt_injection_observed를 ALLOW/info로 기록한다. 기존 로그인, 업로드 형식/크기, 권한 검증은 약화하지 않는다.
5. Tool 실행 직전에 Security Gateway가 사용자·역할·자원 권한을 재검사한다. 보호 자원 접근을 거부하면 agent_tool_call/DENY 이벤트를 기록하며 tool_name, resource_class, trigger_source, request_id, session_id를 포함한다.
6. R3 결과는 인젝션 유형과 무관하게 발생시킨다. 직접 R2가 우회되더라도 보호 Tool 호출은 Gateway에서 거부되어야 한다.
7. internal_api_call에 caller_service, src_ip, path, decision, request_id를 기록한다. 인증 token은 절대 포함하지 않는다.
8. suspicious_input의 value가 chat/post/attachment 문구를 남기지 않는지 확인한다. 안전한 기본값은 모든 입력에서 원문 value를 제거하고 kind/pattern ID만 남기는 것이다.
9. 프록시 뒤에서 실제 사용자 IP를 써야 한다면 신뢰된 proxy만 지정하고 임의 헤더 spoofing을 막는다.
10. R9/R10은 현재 `authz_deny`의 `role`, `path`, `reason`, `required`/`resource` 필드로 탐지할 계획이다. 앱 담당자는 관리자/기밀 자원 거부에서 이 값들이 안정적으로 기록되는지 확인하고 실제 필드 예시를 Graylog 담당자에게 제공한다. 이번 계획을 위해 새 event_type을 이미 구현된 것으로 취급하지 않는다.
11. R11을 위해 `agent_tool_call` DENY마다 session_id, user, tool_name, resource_class, request_id를 기록한다. session_id가 없을 때 user로 묶을 수 있게 하고, 보호 Tool 목록을 명시한다.
12. R12 상관을 위해 게시/첨부/문서 저장 또는 등록 이벤트에 안전한 `source_type`과 `resource_id`를 남기고, AI가 실제 해당 콘텐츠를 검색·열람한 시점에 `ai_content_read`(또는 합의된 동등 이벤트)를 기록한다. AI 열람 이벤트와 `agent_tool_call`에 request_id/session_id를 전파하고, Tool 이벤트에는 `trigger_resource_id`, `trigger_source`, tool_name, resource_class, decision을 기록한다. 본문, 파일 내용, 제목 등 민감할 수 있는 원문은 전달하지 않는다.
13. R12 상관을 위한 공통 ID나 실제 AI 열람 이벤트가 구현되기 전에는 R12를 끄고, `prompt_injection_observed`만으로 경보/차단하지 않는다.
14. Flask 직접 인젝션 R2는 구현·검증됐다. 별도 AI Gateway, 간접 인젝션 관찰, Security Gateway Tool 동작은 실제 연결 전까지 미구현으로 표시하고, 각 이벤트 positive/negative 샘플을 Graylog 담당자에게 제공한다.

## 9. Wazuh/Graylog 구현 순서와 완료 기준

1. 연결 정보 확정: 팀 연결표에서 Graylog 주소, portal/Gateway 주소, Wazuh Manager 주소, 허용 IP, 전달 프로토콜을 받는다. 저장소 문서의 JSONL→Wazuh 경로와 GELF 계획 중 한 가지 앱 로그 수집 경로를 합의한다.
2. Wazuh Agent와 FIM: 포털 호스트 Agent를 Manager에 등록하고 실제 업로드 폴더를 감시한다. 테스트 파일 생성·수정·삭제가 Wazuh FIM alert에 나타나는지 확인한다. DB 문서는 FIM 범위에서 제외한다.
3. Graylog 입력: 앱/Gateway GELF 12201, Wazuh Manager Syslog JSON 5140 입력을 준비한다. 연결 정보가 확정되지 않은 값은 placeholder로 유지한다.
4. 간단한 필드 정규화: `ts`→Graylog timestamp를 우선 적용하고, 이미 같은 이름인 `src_ip`, `user`, `event_type` 등은 그대로 유지한다. `severity`, `source_component`는 실제 입력에 있을 때만 사용한다.
5. Stream은 `NEXUS_AUTH`, `NEXUS_AI_SECURITY`, `NEXUS_WEB` 3개로 구성해 위 표의 이벤트를 분류한다. Wazuh는 uploads FIM만 수집해 `NEXUS_WEB`으로 보낸다.
6. 기존 로그 기반 R9/R10 및 R5–R8을 구성한다. R1의 account_locked 단일 분기를 구성하고, 설치된 Graylog 버전/에디션과 Event Correlation 기능·라이선스를 확인한다.
7. P1 순서로 앱/Gateway 이벤트 계약을 받아 R3, R1 실패→성공 분기, R4를 구현한다. R2 직접 입력 차단은 Flask 경로와 Graylog Event Definition까지 구현·검증했다. R4 allowlist에는 실제 Docker/Proxy 환경에서 관찰한 값을 사용한다. Graylog Event Definition 제목은 `[NEXUS][R#] 한국어 표시명`으로, payload의 stable_name은 영문 식별자로 고정한다.
8. AI 이벤트가 들어오면 R11 반복 횟수 집계를 구성하고, R12는 content read→protected tool deny 간 상관 필드와 Graylog correlation 기능이 검증된 후에만 활성화한다.
9. n8n 수신 검증: D 담당자의 Webhook URL/인증 방식이 준비되면 R1–R12 mock payload를 전달한다. 이 담당 범위에서는 n8n workflow를 구현하지 않고 수신·분기·idempotency 기록이 남는지 확인한다.
10. 증빙: Graylog input, 3개 Stream, 필드 검색, 각 구현된 규칙의 positive/negative 결과, uploads FIM 이벤트, n8n 실행 기록을 캡처한다. R4는 defense-before ALLOW와 defense-after DENY를 따로 증빙한다. n8n의 자동 잠금/차단/토큰 폐기 동작은 n8n 담당자가 별도로 검증한다.

### 종료 기준

- 최종 목표는 R1–R12이며, 각 규칙의 필수 필드·가능 상태·우선순위가 이 문서와 일치한다.
- 직접 인젝션은 prompt_injection_detected/direct/DENY로 기록되고 AI Agent/Tool에는 전달되지 않는다. Flask 구현은 입력을 HTTP 403으로 차단하고 prompt 원문을 DB/JSONL/GELF에 저장하지 않는다.
- 간접 인젝션 관찰 이벤트만으로 R2는 발생하지 않는다.
- 간접 인젝션 시나리오의 보호 Tool 호출은 Security Gateway가 권한을 재검사해 DENY하고 R3가 탐지한다.
- R12는 같은 콘텐츠 입력/열람과 보호 Tool DENY 사이의 상관이 증명될 때만 발생하며, 관찰 이벤트 하나만으로 발생하지 않는다.
- 구현된 각 규칙의 필드가 Graylog에서 검색 가능하고 양성/음성 결과가 구분된다. R2는 Flask와 현재 Graylog에서 검증됐으며, R3/R4/R11/R12는 실제 앱/Gateway 이벤트가 준비되기 전까지 구현 완료로 보고하지 않는다.
- 비밀번호, token, prompt/content 원문이 Graylog event 또는 n8n payload에 없다.
- Wazuh FIM 파일 이벤트가 Graylog에 도착하며 n8n Webhook 수신은 실행 이력으로 확인된다.

## 10. 근거 문서와 기술 문서

- 저장소 현황: ../app/security.py, 01_기획.md, 실측_검증계획_A.md
- 프로젝트/팀 요구: C:\Users\user\Downloads\NEXUS_WORK_프로젝트_기획서.pdf, C:\Users\user\Downloads\NEXUS_WORK_팀원별_작업_계획서.pdf
- Wazuh FIM 설정: https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html
- Wazuh Syslog 출력과 JSON 형식: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syslog-output.html
- Graylog GELF 형식: https://go2docs.graylog.org/current/getting_in_log_data/gelf_format.html
- Graylog Event Definitions: https://go2docs.graylog.org/current/interacting_with_your_log_data/event_definitions.html
- Graylog HTTP Alert payload/template: https://go2docs.graylog.org/current/interacting_with_your_log_data/alert_types.htm
- Graylog Correlation Engine: https://go2docs.graylog.org/current/interacting_with_your_log_data/correlation_engine.html
- 첨부 자료: C:\Users\user\Downloads\NEXUS_WORK_프로젝트_기획서.pdf, C:\Users\user\Downloads\NEXUS_WORK_팀원별_작업_계획서.pdf, C:\Users\user\Downloads\NEXUS_WORK_AI_Agent_방어전_시나리오 (1).md
