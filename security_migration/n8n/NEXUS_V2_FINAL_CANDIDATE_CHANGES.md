# 원본 v2 기준 최종 후보 workflow 변경점

## 기준과 적용 범위

- 기준 파일은 `C:\Users\user\Downloads\NEXUS 탐지 알림 수신 v2 (1).json`이다.
- 15개 노드로 축소됐던 `nexus-alert-v2-dry-run-candidate.json`은 베이스로 사용하지 않았다.
- 원본의 노드 ID 30개를 모두 보존했다. workflow ID와 credential ID는 다른 n8n 환경을 가리키지 않도록 후보에서 제거했다.
- 후보는 inactive 상태다. n8n import/activation, Graylog Notification 변경, credential 생성·변경, Discord 전송, DB 쿼리 실행은 하지 않았다.

후보 파일: [nexus-alert-v2-final-candidate.json](nexus-alert-v2-final-candidate.json)

## 구조와 노드 수

- 원본: 30개 노드
- 후보: 36개 노드, 원본 노드 30개 유지 + 안전 설정 3개 + 중복/비지원 분기 1개 + 접수 응답 및 whitelist 분기 2개
- 연결: 방향성 연결 37개
- 삭제된 노드: 없음
- Code 노드: 7개
- Webhook 경로: `POST /nexus-alert`, `GET /nexus-tickets`, `POST /nexus-ticket-action`

안전 설정 노드를 Webhook마다 분리했다. 공용 설정 노드 하나가 모든 경로를 fan-out해 한 요청에서 티켓 조회와 티켓 조치까지 같이 실행하는 것을 막기 위한 구성이다.

## 추가된 노드

| 노드 | 역할 |
|---|---|
| NEXUS 안전 설정(수신) | 이벤트 경로의 `response_mode=dry-run`, `live_enabled=false`, `lock_minutes=15`, 빈 초기 whitelist 설정 |
| NEXUS 안전 설정(조회) | 티켓 조회에 같은 고정 설정 적용 |
| NEXUS 안전 설정(티켓 처리) | 티켓 조치 요청에 같은 고정 설정 적용 |
| 중복·비지원 이벤트 차단 | `alert.id` 중복 또는 안전하게 처리할 수 없는 이벤트를 티켓·Discord·DB 경로보다 먼저 분기 |
| 응답 200(티켓 기록 후 접수) | 정상 이벤트의 티켓 기록 직후 HTTP 200을 반환하고 Discord/Rule 처리를 이어감 |
| 화이트리스트 제외? | whitelist 제외 결과를 명시 응답으로 보내고 Discord/DB 분기로 보내지 않음 |

설정 노드는 들어온 `headers` 필드를 제외한다. alert 수신 경로에서는 앞선 정규화 Code 노드가 allowlist 필드만 내보낸다. Webhook 원본 입력은 n8n 실행 데이터 보존 설정에 따라 기록될 수 있으므로 Graylog Notification이 원문/backlog를 보내지 않는 것이 전제다.

## 수정된 기존 노드

| 노드 | 변경 |
|---|---|
| Webhook 3개 | Basic Auth로 바꾸지 않았다. 모두 n8n Header Auth(`httpHeaderAuth`) credential 참조를 사용하며, credential은 `x-webhook-token` 헤더 이름으로 다시 연결해야 한다. |
| 토큰 확인 IF | native Header Auth 이후 schema 1.1, `rule.id`, `alert.id`, `event` 객체를 검사한다. 실패는 기존 거부/응답 노드를 재사용해 HTTP 422로 보낸다. 잘못된 토큰은 Webhook 인증 단계에서 거부된다. |
| 정규화·대응 계획 | 원본 v2 payload를 기준으로 allowlist 정규화, Rule/event 형식 확인, priority 검증, `alert.id` 중복 표시, 대응 가능 여부 계산을 한다. `$env`나 요청 헤더의 live 지시는 읽지 않는다. |
| 티켓 기록(출발지별) | IP별 grouping과 ticket count 갱신을 유지한다. `src_ip`가 없는 R9/R10은 `user:<user>`를 내부 ticket key로 사용하고 ticket의 `src_ip`는 빈 값으로 둔다. |
| 티켓 목록/처리 Code | GET, close, false_positive, request_release, release, lock, whitelist_add/remove 기능을 보존했다. Webhook 인증은 native Header Auth로 옮겼고 환경변수/요청 헤더의 live 전환은 제거했다. |
| Discord 알림 2개 | 기존 HTTP Request 노드 자리를 유지하고 n8n Discord Webhook 노드로 바꿨다. URL secret 대신 `discordWebhookApi` credential 참조를 사용한다. |
| 대응 준비/결과 Code | DB 실행 조건에 고정 `live_enabled=false`와 명시적 대응 허용 조건을 추가했다. dry-run에서는 실제 SQL이 실행되지 않는다. |
| 응답 노드 | 계약 오류는 422, 중복/whitelist 제외는 200, fallback은 202, 정상 이벤트는 티켓 기록 후 200을 반환한다. 제외/오류 응답은 side-effect 경로와 분리되어 있고, 정상 접수 응답은 Discord/Rule 분기보다 앞에 있어 외부 호출 지연과 응답 경쟁을 피한다. |
| MySQL 노드 4개 | 노드는 모두 유지했다. 환경의 credential ID 대신 이름 기반 재연결 placeholder만 둔다. 쿼리 실행은 안전 게이트 뒤에 남아 있다. |

## payload 처리 계약

- `schema_version`은 문자열 `1.1`이어야 한다. 필수 envelope 식별자가 없거나 버전이 다르면 HTTP 422이며 이후 부작용 경로로 가지 않는다.
- `alert.priority`는 Graylog 값 1~3만 허용한다. 입력 숫자를 severity로 바꾸거나 priority를 재해석하지 않는다.
- `rule.severity`는 `rule` metadata에서 별도로 들어온 값만 사용한다. `alert.priority`로 만들어내지 않는다. severity/action_level/decision 누락, metadata 불일치, decision 불일치는 fallback으로 분류해 ticket/Discord/DB 부작용 없이 202 응답한다. 이 fallback의 alert.id는 dedupe seen map에 기록하지 않는다.
- R6 임계값은 `event.count`와 `event.window_seconds`만 사용한다. R6는 `event.count >= 3`, `window_seconds = 300`을 확인한다. `event.evidence.retry_count`로 대체하지 않는다.
- R9/R10에서 `event.src_ip`가 없으면 user 기준 ticket key를 쓰되 실제 `event.src_ip`/ticket `src_ip` 값을 만들어내지 않는다.

- 현재 workflow가 지원하지 않는 rule ID, stable name, event type은 HTTP 202 fallback으로 종료한다.
- 중복 `alert.id`는 HTTP 200 duplicate로 응답하고 ticket count, Discord, MySQL 경로로 보내지 않는다.
- `event`는 코드의 allowlist만 전달한다. Prompt 원문, body/message/backlog, password, API token, cookie, 임의의 Graylog 필드는 다음 Code 노드로 넘기지 않는다.

## 기존 기능 보존과 범위

- `/nexus-alert`, `/nexus-tickets`, `/nexus-ticket-action`을 유지했다.
- IP 기준 ticket 생성/갱신, ticket 목록, 처리 상태 변경, 오탐, 해제 요청, lock/release, whitelist 기능을 유지했다. 저장 방식은 원본과 같은 n8n `workflowStaticData`다. 이는 개발·발표용이며 DB 기반 영속 ticket 저장으로 바뀐 것이 아니다.
- R1~R12 Switch와 원본의 DB/Discord/결과 확인 경로, MySQL 노드 수를 유지했다.
- 이전 승인된 R1 안전 정책을 적용했다. `account_compromise_suspected`는 경보/ticket이고 자동 잠금하지 않는다. `account_locked`는 이미 발생한 잠금 결과 기록이며 추가 잠금하지 않는다. R1의 기존 lock 분기와 수동 ticket lock/release 기능은 구조상 남지만 이 후보의 자동 R1 이벤트 경로에서는 UPDATE가 허용되지 않는다.
- R3/R11/R12의 session_version 증가 경로는 유효한 DENY와 별도 live 설정이 있을 때만 후보상 실행 가능하다. 앱/Graylog 쪽 실제 이벤트는 아직 준비되지 않은 상태다.
- R4 내부 API token 폐기는 placeholder로 남겼다. AI Tool 제한도 pending 표시로 유지했다.

## dry-run과 향후 live 영향

현재 세 설정 노드는 모두 다음 값으로 고정되어 있다.

- `response_mode=dry-run`
- `live_enabled=false`
- `lock_minutes=15`
- `whitelist_ips=[]`

Webhook header나 payload에 `X-Response-Mode: live`, `response_mode=live`, `live_enabled=true`를 넣어도 설정 노드가 덮어쓰며 live가 되지 않는다. Code 노드의 `$env`/`process.env` 사용도 없다.

정적 gate 검토상, 이 후보를 나중에 import한 뒤 요청을 실행해도 현재 고정 설정에서는 다음과 같이 동작하도록 구성했다. 실제 runtime 실행 검증은 하지 않았다.

- ticket과 `alert.id` 중복 기록은 n8n workflowStaticData에 기록될 수 있다.
- MySQL 조치/확인 노드 4개는 실행 조건이 false여서 실행되지 않는다.
- Discord 알림 노드 2개는 실행 조건이 false여서 전송되지 않는다.
- NEXUS MySQL DB에는 변경이 없다.

향후 별도 승인 아래 설정을 실제 live로 바꾸면 MySQL 경로는 기존 SQL에 따라 `users.locked_until` 및 `users.session_version`에 영향을 줄 수 있다. 수동 ticket lock/release가 잠금값을 변경하고, R3/R11/R12 DENY 경로가 세션 버전을 올릴 수 있다. Discord 두 알림 노드도 실제 메시지를 보낼 수 있다. 이 후보에서는 R1 이벤트 자동 잠금은 허용하지 않는다.

## credential 재연결

후보 JSON에 credential ID와 secret 값을 넣지 않았다. 총 9개 node 참조는 credential 객체 3개를 재사용하도록 같은 이름으로 묶었다. import 후에는 각 노드에서 같은 환경 credential을 다시 선택해야 하며, 실제 credential 9개를 만들 필요는 없다.

| credential 종류 | 연결 노드 | node 참조 수 | 재사용할 credential 객체 수 |
|---|---|---:|---:|
| `httpHeaderAuth` | Webhook 3개 | 3 | 1 |
| `discordWebhookApi` | Discord 알림 2개 | 2 | 1 |
| `mySql` | MySQL 실행/확인 4개 | 4 | 1 |

Header Auth credential의 header name은 `x-webhook-token`이어야 한다. 값은 credential 저장소에서 입력한다. MySQL credential은 n8n 전용 최소 권한 계정을 연결해야 한다. 이 후보를 만들면서 credential을 생성/수정하지 않았다.

## import 전에 준비할 사항

1. 현재 n8n workflow 목록에서 세 경로와 충돌하는 **활성** workflow가 있는지 다시 조회한다. 저장소의 축소 후보도 같은 세 경로를 갖고 있으므로 두 후보를 함께 활성화하면 안 된다. 이번 작업에서는 실행 중 n8n의 workflow registry를 조회하지 않았다.
2. 후보는 inactive로 import하고 Webhook 3곳에는 같은 Header Auth credential 1개, Discord 2곳에는 같은 Discord credential 1개, MySQL 4곳에는 같은 MySQL credential 1개를 다시 연결한다. credential ID가 빠져 있으므로 import 자체가 자동으로 연결해주지는 않는다.
3. Graylog Notification template이 `schema_version`, rule metadata, `alert.id/timestamp/priority`, event allowlist만 보내는지 확인한다. raw message/backlog는 보내지 않는다. priority는 1~3, `rule.severity`는 별도 Rule metadata 값이어야 한다.
4. n8n과 `nexus-mysql`이 접근할 네트워크를 별도 확인한다. MySQL host port를 외부 전체에 공개하는 구성은 사용하지 않는다.
5. inactive 상태에서 정상/오류 schema, 중복 `alert.id`, R9/R10 IP 없음, R6 count, Discord/DB 미실행을 dry-run으로 검증한다.
6. 자동 대응 및 Discord 전송은 별도 승인 전까지 활성화하지 않는다.

## 정적 검증 결과

- JSON parse: 통과
- 원본 node ID 보존: 30/30
- 후보 node 수: 36
- 중복 node ID/name: 없음
- connection source/target 참조: 모두 존재, dangling edge 없음
- 방향성 connection 수: 37
- RespondToWebhook 경로: contract error는 422, duplicate/fallback은 격리된 200/202, whitelist 제외는 격리된 200, 정상은 ticket 기록 후 accepted 200
- duplicate/fallback/whitelist responder에는 outgoing edge가 없고, 정상 responder는 side-effect 분기 전에만 실행
- active=false: 확인
- 후보 내부 Webhook path 중복: 없음
- Code node JavaScript 문법: 7/7 통과 (n8n 2.37.7 컨테이너 Node v26.5.1에서 compile-only 검사)
- 원본 MySQL credential ID / Discord webhook URL / `$env` 참조: 후보에 없음
- 실제 n8n import/activation, workflow registry path 확인, Graylog 전송, Discord 전송, SQL 실행: 하지 않음

저장소의 축소 후보도 `nexus-alert`, `nexus-tickets`, `nexus-ticket-action`을 사용한다. 이는 파일 기준 경로 겹침이다. 실제 n8n에 등록된 활성 workflow와의 충돌 여부는 import 직전에 registry에서 별도 확인해야 한다.


## 연결 그래프 2차 검토 (n8n 2.37.7)

### 최종 /nexus-alert 경로

```text
POST /nexus-alert Webhook
→ 정규화·대응 계획
→ NEXUS 안전 설정(수신)
→ schema_version·필수 식별자 검증
  ├─ 계약 오류 → 응답 422(계약 오류) [종료]
  └─ 계약 정상 → 중복·비지원 이벤트 차단
       ├─ 중복 또는 fallback → 응답(중복·fallback·화이트리스트) [티켓/Discord/DB 없음, 종료]
       └─ 정상 → 티켓 기록(출발지별)
            ├─ whitelist 제외 → 응답(중복·fallback·화이트리스트, 200) [Discord/DB 없음, 종료]
            └─ 정상 티켓 → 응답 200(티켓 기록 후 접수)
                         → Discord 알림 분기 + R1~R12 대응 분기
```

정상 경로의 HTTP 응답은 티켓 기록 직후 보낸다. Respond to Webhook의 출력은 입력 item을 계속 전달하므로 응답 후 Discord/Rule 분기가 이어진다. DB/Discord 호출이 끝날 때까지 Graylog HTTP Notification을 붙잡지 않으며, n8n 실행에서 후속 대응 결과를 확인한다. 따라서 `accepted`는 n8n이 계약을 확인하고 티켓 상태를 기록해 처리를 접수했다는 뜻이며, Discord/DB 대응 완료를 뜻하지 않는다.

중복/fallback/whitelist 응답 노드는 outgoing edge가 없다. 정상 접수 responder와 별도 노드이므로 이 입력들이 Respond 노드 출력에서 부작용 분기로 재진입하지 않는다. whitelist 제외 상태는 기존대로 workflowStaticData의 skipped 목록에만 기록하고 ticket/Discord/DB 처리로 진행하지 않는다. 중복 판정은 ticket writer 전에 읽기 전용으로 하고, alert.id는 정상 ticket 생성/갱신 또는 whitelist skip 기록이 끝난 다음 seen map에 기록한다. 그래서 fallback/unsupported 요청은 seen 상태를 바꾸지 않고, ticket writer 실패 전에는 해당 alert.id를 중복 완료로 표시하지 않는다. 계약 검증 IF는 정상 출력에서 중복 판정만 실행하고 바로 200을 반환하는 우회 edge가 없다. 각 단일 HTTP 요청은 계약 오류, 중복/fallback, whitelist 제외, 정상의 상호 배타적인 경로 중 하나만 택한다.

n8n 문서는 Respond to Webhook이 첫 입력 item만 사용하고, 첫 응답 이후 다른 Respond to Webhook 실행은 무시한다고 설명한다. 또한 Respond 노드 없이 workflow가 끝나면 기본 200을 반환한다. 따라서 같은 responder를 병렬 경로의 완료 join으로 재사용하는 방식은 피했다. 이 후보는 응답을 side-effect 전에 보내므로 외부 처리 지연/실패가 HTTP 응답 뒤에 발생할 수 있다. n8n execution history를 운영 확인점으로 둔다. [n8n Respond to Webhook 문서](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.respondtowebhook/)와 [n8n 2.37.7 RespondToWebhook 구현](https://github.com/n8n-io/n8n/blob/n8n%402.37.7/packages/nodes-base/nodes/RespondToWebhook/RespondToWebhook.node.ts)를 참조했다.

### credential 재사용 판정

가능하다. n8n credential은 동일 credential type인 여러 node에서 재사용할 수 있다. 이 후보는 node credential reference가 9곳(3 + 2 + 4)이지만 아래 credential 객체 3개만 준비하면 된다.

- `NEXUS x-webhook-token` Header Auth 1개 → 세 Webhook에서 재사용
- `NEXUS Discord Webhook` 1개 → 두 Discord node에서 재사용
- `NEXUS MySQL 전용 계정` 1개 → 네 MySQL node에서 재사용

JSON에는 ID/secret이 없다. import 뒤 각 노드의 credential selector에서 동일 객체를 각각 다시 지정해야 한다. 환경별 credential 값은 이 문서와 후보에 기록하지 않는다.