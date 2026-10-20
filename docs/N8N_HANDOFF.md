# NEXUS WORK 보안 이벤트 연동 전달서

작성 기준일: 2026-10-19

이 문서는 현재 저장소 문서와 실행 중인 Graylog/Wazuh 환경을 읽기 전용으로 확인해 n8n 담당자에게 전달하기 위한 자료다. 이번 작성에서 애플리케이션, Graylog, Wazuh, Event Definition, Stream, n8n 설정은 변경하지 않았다. 실제 Webhook 전달은 아직 검증하지 않았다.

## 1. 전체 아키텍처

현재 목표 흐름:

Flask 포털 및 보안 이벤트 → GELF/UDP 12201 → Graylog GELF Input → 기존 필드 수집 → NEXUS_AUTH / NEXUS_AI_SECURITY / NEXUS_WEB Stream → R1–R12 Event Definition → Graylog Notification/Webhook → n8n Webhook → rule.id Switch → 알림 또는 승인된 대응

파일 무결성 감시 흐름:

uploads 변경 → Windows Wazuh Agent → Wazuh Manager → Graylog Raw UDP Input 5140 → NEXUS_WEB → 필요 시 n8n

Graylog에서 확인한 버전은 6.1.16이며 컨테이너는 healthy다. Wazuh Manager 컨테이너는 4.9.0이고 실행 중이다. n8n 컨테이너도 5678 포트로 실행 중인 것을 확인했지만, 실행 중인 컨테이너가 구성된 workflow나 Webhook 연동을 뜻하지는 않는다.

## 2. Graylog 구조

### Inputs

| 용도 | 현재 이름 및 유형 | ID | 주소/포트 | 확인 사항 |
|---|---|---|---|---|
| 앱 GELF | hping3 lab, GELF UDP | 6aa9e606c20392644e906c72 | UDP 12201 | 현재 GELF input의 UI 이름은 앱 전용으로 표시되지 않는다. 앱 이벤트와 시험 이벤트가 이 GELF 포트로 수집되는 구조다. |
| Wazuh FIM | Wazuh Alerts (JSON over UDP 5140), Raw UDP | 6abc757f4be02351a9d74742 | 컨테이너 UDP 5140 | 실제 Input type은 Raw UDP다. 이름의 JSON 표현과 달리 Graylog field로 자동 파싱된다는 뜻은 아니다. |
| 기존 pfSense 시험 | pfsense syslog test, Syslog UDP | 6acdbce48d95d610e68c5566 | UDP 1514 | 이 전달 자료의 R1–R12 입력 범위 밖이다. |

### NEXUS Streams

| Stream | ID | 현재 분류 기준 | 발표 설명 |
|---|---|---|---|
| NEXUS_AUTH | 6ad58a859d0f6c101daf8032 | login_success, account_locked, login_failure, account_compromise_suspected, login_locked, post_lock_retry_detected | 계정 탈취와 인증 이상 행위를 탐지합니다. |
| NEXUS_AI_SECURITY | 6ad58aad9d0f6c101daf8065 | agent_tool_call, internal_api_call, ai_content_read, content_ingested, prompt_injection_detected, prompt_injection_observed | Prompt Injection 및 AI Tool 권한 남용을 탐지합니다. |
| NEXUS_WEB | 6ad58aad9d0f6c101daf807a | not_found, authz_deny, confidential_access, Wazuh input ID | 웹 권한 위반, 비정상 경로 접근, 파일 변경 이벤트를 확인합니다. |

Graylog에는 Default/All Events 같은 시스템 Stream과 기존 프로젝트 Stream도 함께 있다. 위 세 개만 NEXUS 업무 Stream이며, 실제 환경의 Stream 목록이 세 개뿐이라는 뜻은 아니다.

NEXUS_WEB은 Wazuh UDP Input의 gl2_source_input 값과 일치하는 메시지를 Stream에 분류한다. 이 조건은 uploads 경로를 검사하지 않는다. Wazuh Manager의 현재 전달 필터는 FIM rule ID 550/553/554지만, 이 rule ID는 Windows 기본 감시 경로에서도 발생할 수 있으므로 현재 Stream을 uploads 경로 전용이라고 단정하지 않는다.

### 구현/검증된 Event Definitions

현재 API에서 아래 NEXUS 정의가 ENABLED인 것을 확인했다. 테스트 유형과 Event 필드 제한은 N8N_RULE_MATRIX.md에 정리했다.

| Rule | Event Definition 이름 | Definition ID | 입력 Stream | Graylog priority |
|---|---|---|---|---:|
| R1 | [NEXUS][R1] 계정 침해 의심 | 6ad5ac319d0f6c101dafd65b | NEXUS_AUTH | 3 |
| R2 | [NEXUS][R2] 직접 Prompt Injection 차단 | 6ad5b4e09d0f6c101dafec4d | NEXUS_AI_SECURITY | 3 |
| R5 | [NEXUS][R5] 계정 스프레이 | 6ad592729d0f6c101daf9264 | NEXUS_AUTH | 3 |
| R6 | [NEXUS][R6] 잠금 후 로그인 재시도 | 6ad5aa649d0f6c101dafd3cc | NEXUS_AUTH | 3 |
| R7 | [NEXUS][R7] 심야 로그인 성공 | 6ad590929d0f6c101daf8edf | NEXUS_AUTH | 1 |
| R8 | [NEXUS][R8] 404 경로 스캔 | 6ad5911d9d0f6c101daf8ff2 | NEXUS_WEB | 3 |
| R9 | [NEXUS][R9] 관리자 권한 접근 거부 | 6ad58c2f9d0f6c101daf82f9 | NEXUS_WEB | 3 |
| R10 | [NEXUS][R10] 기밀 문서 직접 접근 거부 | 6ad58d029d0f6c101daf8541 | NEXUS_WEB | 3 |

R3, R4, R11, R12 Event Definition은 아직 구현되지 않았다. NEXUS_AI_SECURITY Stream에 해당 이벤트 유형을 받을 분류 조건이 있다는 사실은 Event Definition 또는 앱/Gateway 구현 완료를 의미하지 않는다.

R1/R2의 새 Event priority는 3이다. 과거 priority 4인 R1 8건과 R2 11건은 기존 이력으로 보존되어 있다. 일부 payload sample은 이 과거 R1 record를 사용하므로 해당 파일 설명을 확인한다.

## 3. 현재 Wazuh 구조

- Windows Wazuh Agent 서비스 WazuhSvc는 Running이다.
- Wazuh Manager의 Agent 목록에서 001 board-host와 003 DESKTOP-6KV0JDP가 Active였다. uploads 대상은 기존 작업에서 설정하고 검증한 Windows Agent 001 board-host다.
- uploads 감시 경로는 프로젝트의 instance/uploads다. 파일 생성, 수정, 삭제가 각각 Wazuh rule 554, 550, 553으로 Manager에서 확인됐다.
- Wazuh Manager의 syslog_output은 gl-graylog의 UDP 5140으로 rule ID 550, 553, 554를 default 형식으로 전달한다. Graylog와 Manager는 같은 Docker network에 연결되어 있다.
- Graylog의 Wazuh Input은 JSON 전용 parser가 아니라 Raw UDP Input이다. 이전 검증에서 FIM 이벤트는 Graylog 검색에서 확인됐고, 기본 저장 필드는 source, message, timestamp 중심이었다.
- 현재 Wazuh는 웹 요청의 404 경로 스캔을 직접 탐지하는 구조가 아니다. 웹, 인증, AI 탐지는 주로 Flask/GELF → Graylog에서 다룬다. 이번 Wazuh 범위는 파일 무결성 감시 중심이다.
- Wazuh FIM create/modify/delete는 Graylog에서 검색 가능하지만, 해당 이벤트를 R1–R12 payload 계약으로 n8n에 보내는 Webhook은 확인되지 않았다.

## 4. 전달 가능한 규칙

R1, R2, R5–R10은 현재 Graylog Event Definition이 활성화되어 있으며 positive/negative 검증 기록이 있다. R5, R7, R8, R9, R10의 일부 양성은 실제 포털 공격이 아니라 안전한 synthetic GELF 입력으로 재현했다. 실제 공격 행위가 운영 중 발생했다고 보고하면 안 된다.

각 규칙의 event_type, source severity/decision 의미, action_level, 분기 조건 및 권장 대응은 [N8N_RULE_MATRIX.md](N8N_RULE_MATRIX.md)를 기준으로 한다.

## 5. Payload 계약

### Canonical envelope 위치

- HTTP method: POST
- Content-Type: application/json
- schema_version: root의 schema_version이며 현재 계약값은 1.1
- rule.id: root.rule.id. n8n Switch는 이 값으로 분기한다.
- stable name: root.rule.stable_name
- action 권고: root.action_level. 실제 차단을 뜻하지 않는다.
- 실제 결과: root.event.decision. 존재하면 이 값을 확인한다.
- 중복 방지 키: root.alert.id
- 사용자/주소/요청 식별: root.event.user, root.event.src_ip, root.event.request_id
- 실제 Webhook URL은 문서에 기록하지 않고 Graylog credential/보호된 설정에 둔다.

### 현재 Event 필드의 제한

읽기 전용 Events API 응답에서 Event.fields는 Event Definition의 그룹 필드 위주로 제한되어 있었다. 현재 확인된 대표 형태:

| Rule | Graylog Event.fields에서 확인된 필드 | 별도 전달이 필요할 수 있는 필드 |
|---|---|---|
| R1 | event_type, user, src_ip, request_id, decision, reason, failed_attempts, window_seconds | severity. account_locked 원본에는 failed_attempts/window_seconds가 없음 |
| R2 | event_type, injection_type, decision, pattern_id, source_type, source_component, user, role, src_ip, request_id, session_id, reason, severity | 없음. Prompt 원문은 없음 |
| R5 | src_ip | event_type, distinct user 수, decision, severity, event_count |
| R6 | user, src_ip, lock_request_id, trigger_event_type, count, window_seconds | request_id, decision, reason, severity |
| R7 | user, src_ip | event_type, decision, severity 및 원본 로그인 시각 |
| R8 | src_ip, path. 집계 Event에서 path는 빈 값으로 확인됨 | event_type, 결정/심각도, 실제 탐지 count |
| R9 | user, path | event_type, role, src_ip, decision, reason, required |
| R10 | user, path, resource | event_type, role, src_ip, decision, reason, 그리고 분기에 따라 required |

JSON sample의 alert 메타데이터는 실제 Graylog Event ID, Event Definition ID, timestamp, priority를 사용했다. event는 원본 보안 로그 또는 검증된 GELF 입력에서 실제 존재가 확인된 allowlist 필드로 정규화한 개발용 Mock이다. 테스트 user/IP는 문서용 예시값으로 바꿨다. 현재 Graylog → n8n HTTP body를 캡처한 것이 아니므로 운영 payload와 동일하다고 간주하지 않는다.

특히 R5–R10처럼 집계 Event.fields에 decision이나 원본 event_type이 보이지 않는 경우, Graylog 기본 알림이 그 값을 반드시 포함한다고 가정하지 않는다. Webhook body를 만들 때 원문 message/backlog를 그대로 싣지 말고, 허용된 개별 필드만 별도 매핑한다. 안전한 매핑이 불가능하면 누락 필드에 근거한 자동 대응은 하지 않는다.

### Payload sample 목록

| 파일 | 실제 Event 기준 |
|---|---|
| [r1_account_compromise.json](n8n_payload_samples/r1_account_compromise.json) | 실제 5070 실패 후 성공 분기 Event. 기존 priority 4 이력 |
| [r1_account_locked.json](n8n_payload_samples/r1_account_locked.json) | 실제 5070 잠금 분기 Event. 기존 priority 4 이력 |
| [r2_direct_prompt_injection.json](n8n_payload_samples/r2_direct_prompt_injection.json) | priority 3인 R2 positive Event. source_component는 안전한 GELF priority 시험 |
| [r6_post_lock_retry.json](n8n_payload_samples/r6_post_lock_retry.json) | 실제 5070 잠금 후 세 번째 재시도 Event |
| [r7_off_hours_login.json](n8n_payload_samples/r7_off_hours_login.json) | R7 positive 시간대 시험 Event |
| [r8_path_scan.json](n8n_payload_samples/r8_path_scan.json) | 30건 synthetic GELF positive 집계 Event |
| [r9_admin_access_denied.json](n8n_payload_samples/r9_admin_access_denied.json) | NEXUS_WEB의 app-shaped GELF positive Event |
| [r10_confidential_access_denied.json](n8n_payload_samples/r10_confidential_access_denied.json) | payroll scope 거부의 app-shaped GELF positive Event |

## 6. n8n 구현 순서

1. n8n 담당자가 Webhook trigger를 POST와 JSON 입력으로 만들고 Webhook URL 및 인증 방식을 정한다. URL과 인증값은 저장소 문서/채팅에 남기지 않는다.
2. Graylog 담당자가 Event Notification 연결 전에 body template이 schema_version 1.1 allowlist envelope를 만들 수 있는지 확인한다. backlog 원문을 포함하지 않는 구성을 사용한다.
3. n8n에서 schema_version, rule.id, alert.id를 검증하고 alert.id를 idempotency key로 저장한다.
4. Switch는 rule.id만 사용한다. 각 분기에서 event.decision이 있으면 결과를 확인하고, 누락되면 자동 contain 대신 alert/observe로 제한한다.
5. 각 JSON sample의 positive Mock과 잘못된 rule.id/decision/missing field negative Mock으로 분기 및 실행 이력을 검증한다. 자동 차단·계정 조치·토큰 폐기는 별도 승인과 설계가 끝난 뒤에만 구현한다.

권장 연결 형태:

Graylog Event → HTTP Notification/Webhook → n8n Webhook → rule.id Switch → 승인된 알림 또는 대응 후보

## 7. 아직 미완료 항목

- Graylog → n8n 실제 Webhook 연결 및 HTTP delivery 검증은 미실행이다.
- n8n workflow는 미구현/미검증이다. 실행 중인 컨테이너만 확인됐다.
- Graylog Notification이 schema_version 1.1 body를 생성하는지, backlog를 배제하는지 아직 확인하지 않았다.
- Ollama는 미연결이다.
- AI Tool 실행기, Tool Gateway, Security Gateway는 미구현이다.
- R3, R4, R11, R12는 미구현이며 Event Definition도 없다.
- 자동 contain 동작은 실제 실행·승인·검증되지 않았다.
- Wazuh FIM input의 Graylog Stream 분류는 input ID 기준이다. uploads 경로만 분류하는지 보장되지 않는다.

## n8n 담당자가 먼저 할 5단계

1. n8n Webhook trigger와 인증 방법 결정
2. schema_version 1.1 envelope 입력 및 alert.id 중복 방지 구현
3. rule.id Switch 분기 구성
4. event.decision 누락 시 자동 조치를 막는 안전한 기본 처리 추가
5. 여덟 JSON sample로 positive/negative Mock, 분기 및 실행 이력 검증

## 추가로 전달받을 정보

이 전달 패키지를 읽고 Mock 개발을 시작하는 데 추가 정보는 필요하지 않다. 실제 연결 전에 n8n 담당자가 생성한 Webhook URL과 인증 방식을 안전한 비밀 전달 경로로 Graylog 담당자에게 전달해야 한다. 운영 알림 대상/수신자와 R1 contain 후보를 승인 없이 실행할지 여부도 정해야 한다. URL이나 인증값은 이 문서에 쓰지 않는다.

## 실제 필드와 예시 필드 일치 여부

alert.id, event_definition_id, timestamp, priority, key는 실제 Events API에서 확인했다. R2의 injection_type, pattern_id, session_id, decision, severity도 실제 Event fields에서 확인했다. R1/R6의 집계 근거 및 원본 이벤트 필드도 로그에서 확인했다. 단, R5/R6/R7/R8/R9/R10은 일부 필드가 생성된 Graylog Event.fields에 그대로 노출되지 않는다. JSON sample은 실제 Event metadata와 확인된 원본 로그 allowlist를 합친 Mock 계약 예시이지, 캡처된 실제 Webhook body는 아니다.
