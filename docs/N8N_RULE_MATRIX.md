# NEXUS WORK n8n Rule Matrix

이 표의 rule.id가 n8n Switch의 기준이다. Event Definition의 한국어 제목, Graylog priority, action_level은 분기 키로 사용하지 않는다. action_level은 권고값이고 실제 차단 여부는 event.decision이 있을 때 확인한다.

## 현재 전달 가능한 R1/R2/R5–R10

| rule.id | stable_name | 이벤트 / 심각도 | Stream / Event Definition | n8n 분기 조건 | 권장 대응 |
|---|---|---|---|---|---|
| R1 | ACCOUNT_COMPROMISE | account_compromise_suspected: high, WARN은 의심 파생 이벤트. account_locked: medium, BLOCK 또는 DENY는 잠금 결과 | NEXUS_AUTH / [NEXUS][R1] 계정 침해 의심 / 6ad5ac319d0f6c101dafd65b | rule.id=R1. event.event_type로 두 분기를 구분한다. 파생 분기는 failed_attempts≥3, window_seconds=300, decision=WARN을 증거로 확인한다. 잠금 분기는 account_locked와 decision=BLOCK/DENY를 확인한다. | alert. contain 후보이나 자동 잠금/차단을 action_level만으로 실행하지 않는다. account_locked의 실제 BLOCK/DENY와 파생 WARN을 구분한다. |
| R2 | DIRECT_PROMPT_INJECTION_BLOCKED | prompt_injection_detected, injection_type=direct, decision=DENY, severity=high | NEXUS_AI_SECURITY / [NEXUS][R2] 직접 Prompt Injection 차단 / 6ad5b4e09d0f6c101dafec4d | rule.id=R2 AND event.event_type=prompt_injection_detected AND event.injection_type=direct AND event.decision=DENY. 현재 pattern_id는 ignore_previous_instructions, reveal_hidden_prompt, policy_bypass_protected_data 중 하나다. | alert. 앱에서 이미 403으로 차단한 이벤트이므로 추가 contain은 기본 수행하지 않는다. |
| R5 | ACCOUNT_SPRAY | login_failure, source severity=medium, source decision=DENY | NEXUS_AUTH / [NEXUS][R5] 계정 스프레이 / 6ad592729d0f6c101daf9264 | rule.id=R5. Graylog가 같은 src_ip, 300초 안 서로 다른 user 5명 이상 조건을 이미 계산했다. event.evidence에 distinct_users/event_count가 없더라도 임계값을 n8n에서 재추정하지 않는다. | alert. contain 후보를 제안할 수 있으나 자동 IP 차단은 별도 승인 전 실행하지 않는다. |
| R6 | POST_LOCK_RETRY | post_lock_retry_detected, source severity=high, decision=WARN | NEXUS_AUTH / [NEXUS][R6] 잠금 후 로그인 재시도 / 6ad5aa649d0f6c101dafd3cc | rule.id=R6 AND event.event_type=post_lock_retry_detected AND count≥3 AND window_seconds=300. 앱 집계가 동일 user/src_ip, 잠금 이후 다른 request_id 조건을 계산한다. | alert. 이미 잠긴 계정의 재시도 증거다. 추가 contain은 별도 승인 전 실행하지 않는다. |
| R7 | OFF_HOURS_LOGIN_SUCCESS | login_success, source severity=info, decision=ALLOW | NEXUS_AUTH / [NEXUS][R7] 심야 로그인 성공 / 6ad590929d0f6c101daf8edf | rule.id=R7. Graylog가 KST 00:00 이상 05:00 미만 시간 조건을 적용했다. alert.timestamp는 집계 Event 생성/검색 구간 시각일 수 있으므로 원본 로그인 시각으로 혼동하지 않는다. | observe. 필요하면 담당자 확인 알림만 보낸다. |
| R8 | NOT_FOUND_SCAN | not_found, source severity=info, decision=INFO | NEXUS_WEB / [NEXUS][R8] 404 경로 스캔 / 6ad5911d9d0f6c101daf8ff2 | rule.id=R8. Graylog가 같은 src_ip의 60초 내 30회 이상 조건을 계산했다. path는 집계 Event에서 비어 있을 수 있다. | alert. 원본 URL/요청 본문을 전달하지 않고 IP와 집계 증거만 전달한다. |
| R9 | ADMIN_PATH_ACCESS_DENIED | authz_deny, source severity=medium, decision=DENY | NEXUS_WEB / [NEXUS][R9] 관리자 권한 접근 거부 / 6ad58c2f9d0f6c101daf82f9 | rule.id=R9. 정의 조건은 role=employee 또는 manager, reason=insufficient_role, required=admin이다. path는 조사 증거다. | alert. 권한 거부가 이미 발생했는지 event.decision이 전달된 경우 확인한다. |
| R10 | DIRECT_CONFIDENTIAL_ACCESS_DENIED | authz_deny, source severity=medium, decision=DENY | NEXUS_WEB / [NEXUS][R10] 기밀 문서 직접 접근 거부 / 6ad58d029d0f6c101daf8541 | rule.id=R10. confidential/finance 경로의 insufficient_role 또는 payroll resource의 out_of_scope 분기다. | alert. 자동 계정/네트워크 차단은 승인 없이 실행하지 않는다. |

R1–R10의 위 Event Definition ID와 Stream/priority는 현재 Graylog API에서 읽기 전용 확인했다. R1, R2, R5–R10은 각각 positive/negative 검증 기록이 있다. 일부 규칙의 positive 데이터는 synthetic GELF이며 운영자 공격이나 실사용자 오용 사례가 아니다.

## 아직 구현되지 않은 규칙

| rule.id | stable_name | 계획 이벤트 | 대상 Stream | 상태 / n8n 권장 처리 |
|---|---|---|---|---|
| R3 | AI_TOOL_PERMISSION_DENIED | agent_tool_call with protected tool and DENY | NEXUS_AI_SECURITY | Security Gateway와 Tool 권한 재검사 미구현. 실제 이벤트/Definition 없음. |
| R4 | UNEXPECTED_INTERNAL_API_CALL | internal_api_call from unapproved caller/source | NEXUS_AI_SECURITY | 실제 관찰값 기반 allowlist와 이벤트 미구현. 실제 이벤트/Definition 없음. |
| R11 | REPEATED_AI_TOOL_PERMISSION_DENIAL | 보호 Tool DENY가 5분 내 3회 이상 | NEXUS_AI_SECURITY | Tool/Gateway와 반복 집계 미구현. 실제 이벤트/Definition 없음. |
| R12 | CONTENT_TRIGGERED_PROTECTED_TOOL_DENIAL | resource_id 연결된 콘텐츠 읽기 후 보호 Tool DENY | NEXUS_AI_SECURITY | content_ingested/ai_content_read/agent_tool_call 연결 및 상관 기능 미구현. 실제 이벤트/Definition 없음. |

이 네 규칙의 계획 action_level은 contain이지만 미구현 상태다. 이를 실제 n8n Event 분기로 완료 처리하지 않는다.

## Sample과 실제 Event.fields 차이

| Rule | Events API에서 관찰된 fields | 주의 |
|---|---|---|
| R1 | event_type, user, src_ip, request_id, decision, reason, failed_attempts, window_seconds | severity는 Event.fields에 없을 수 있다. account_locked 원본에는 failed_attempts/window_seconds 값이 없다. |
| R2 | event_type, injection_type, decision, pattern_id, source_type, source_component, user, role, src_ip, request_id, session_id, reason, severity | 실제 확인됨. Prompt 원문은 포함하지 않는다. |
| R5 | src_ip | 집계 메시지의 event.fields만으로 distinct_users, event_count, decision을 가정하지 않는다. |
| R6 | user, src_ip, lock_request_id, trigger_event_type, count, window_seconds | request_id/decision/severity는 원본 파생 메시지에는 있지만 Events API fields에서는 확인되지 않았다. |
| R7 | user, src_ip | event_type/decision/severity와 원본 로그인 timestamp는 Event.fields에 없다. |
| R8 | src_ip, path | 집계 Event에서 path 값이 빈 문자열이었다. 개별 경로는 원본 로그에서만 조사한다. |
| R9 | user, path | role/reason/required/decision은 Event.fields에 포함되지 않았다. Event Definition query 자체는 이 조건들을 검사한다. |
| R10 | user, path, resource | role/reason/required/decision은 Event.fields에 포함되지 않았다. payroll 분기에서는 resource가 실제 표시됐다. |

JSON samples의 event는 원문이 아니라 확인된 source field allowlist를 사용한 Mock 정규화 객체다. 실제 HTTP Notification body는 아직 캡처되지 않았다. Graylog Notification이 필드 값을 제공하지 않으면 원문 backlog를 보내지 말고, alert-only로 제한하거나 안전한 필드 추출을 먼저 설계한다.

## 분기 구현 안전 기준

1. 첫 분기는 rule.id로 고정한다. title, stable_name 표시 문자열, priority만으로 분기하지 않는다.
2. action_level은 권고값이다. contain을 자동 실행 신호로 해석하지 않는다.
3. event.decision이 전달되면 실제 결과를 확인한다. DENY/BLOCK은 차단/거부 기록, WARN은 의심 또는 기준 충족 파생 신호, ALLOW는 허용, INFO는 정보 이벤트다.
4. event.decision이 없는 집계 Event에서 자동 contain하지 않는다. 현재 R5–R10 일부 fields에는 decision이 없다.
5. alert.id를 저장해 중복 실행을 막는다.
6. Prompt, 첨부/게시 본문, password, API token, cookie, raw HTTP body, raw message/backlog를 n8n으로 보내지 않는다.
7. Graylog Event priority는 1–3 범위로 다룬다. R1/R2 정의는 현재 3이며, 이전 priority 4 이벤트 이력은 sample 또는 이력 조회에만 나타날 수 있다.

## 구형 Wazuh Event Definition 주의

Graylog에는 NEXUS R7/R8과 별개인 구형 Wazuh 규칙도 남아 있다. 예를 들어 예전 정의의 “7- Wazuh 브루트포스”와 “8- Wazuh 웹 파일 변경”은 R7 심야 로그인, R8 404 경로 스캔과 다른 규칙이다. 이 구형 정의는 이번 schema_version 1.1 R1–R12 계약에 포함하지 않는다. n8n 분기는 이벤트 제목의 숫자가 아니라 정상화된 rule.id를 사용한다.
