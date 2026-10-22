# NEXUS 탐지 알림 수신 v2 안전 후보

작성일: 2026-10-20
원본: `C:\Users\user\Downloads\NEXUS 탐지 알림 수신 v2 (1).json`
후보: [`nexus-alert-v2-dry-run-candidate.json`](./nexus-alert-v2-dry-run-candidate.json)

> 검토용 후보만 만들었다. n8n import/activation, Graylog Notification 연결, Discord 전송, NEXUS DB 변경은 하지 않았다. 후보는 `active=false`이고 MySQL/외부 HTTP 부작용 노드가 없다. Webhook Basic Auth credential은 placeholder라 credential을 별도로 만들고 바인딩하기 전까지 실행 준비가 되지 않는다.

## 1. 현재 환경 확인

- n8n `2.37.7`, Docker `bridge` 네트워크(`172.17.0.2`). NEXUS alert workflow와 `/nexus-alert` 경로는 현재 등록되어 있지 않다.
- `N8N_BLOCK_ENV_ACCESS_IN_NODE`, `WEBHOOK_TOKEN`, `DISCORD_WEBHOOK_URL`, `RESPONSE_MODE`, `WHITELIST_IPS`, `LOCK_MINUTES`는 n8n 컨테이너에 설정되어 있지 않다. n8n v2.0 변경 안내는 Code node의 환경 변수 접근 기본값을 차단으로 변경했다. 이를 해제하지 않고 후보 Code node에서 `$env.*`를 모두 제거했다. [n8n v2 변경 안내](https://github.com/n8n-io/n8n-docs/blob/main/docs/changelog/v20-breaking-changes.md)
- MySQL `nexus-mysql`은 `nexus-work_default`(`172.23.0.2`)에 있다. 두 컨테이너는 현재 네트워크를 공유하지 않는다. MySQL host port는 `127.0.0.1:3307`로 loopback에만 바인딩되어 있다.
- Graylog Event Definition R1/R2/R5/R6/R7/R8/R9/R10은 활성 상태지만 Notification 연결은 없다. 현재 실제 HTTP Notification payload는 확인되지 않았다.

## 2. 후보 변경점

1. 새 후보 workflow로 분리하고 `active=false`; 원본 workflow ID를 제거해 기존 설정을 덮어쓰지 않게 했다.
2. `X-Response-Mode`와 `RESPONSE_MODE`를 제거했다. `X-Response-Mode: live`가 와도 응답은 항상 `mode=dry-run`이다.
3. R1을 구분했다.
   - `account_compromise_suspected`: 경보/티켓 계획만 기록. 계정 자동 잠금 없음.
   - `account_locked`: 이미 수행된 잠금 결과/티켓만 기록. 추가 잠금 없음.
4. R6은 Graylog Event의 직접 필드 `event.count`를 읽는다. `event.evidence.retry_count`로 대체하거나 기본값 1을 만들지 않는다. `count>=3`, `window_seconds=300`, `lock_request_id`, `trigger_event_type`가 없으면 fallback한다.
5. schema v1.1, required envelope, `rule.id`, `stable_name`, `action_level`, `rule.severity`, priority 1–3, 규칙별 필드를 검증한다. 오류/fallback 응답에는 원본 body를 포함하지 않는다.
6. 분기는 `rule.id` 기준이다. `action_level`은 권고만 한다. decision이 없거나 예상과 달라도 DB 조치는 없다.
7. 허용 필드만 downstream에 보낸다. Prompt/body/password/token/cookie/raw message/backlog는 복사하지 않는다. 다만 n8n execution 기록에 Webhook 입력이 남을 수 있으므로 Graylog도 allowlist payload만 보내야 한다.
8. Discord 전송 노드와 MySQL/SQL 노드를 후보에서 제거했다. `lock/release`는 dry-run 결과 기록뿐이다.
9. `/nexus-tickets` GET, `/nexus-ticket-action` POST를 보존했다. `close`, `false_positive`, `request_release`, `whitelist_add/remove`는 n8n workflow state만 갱신한다. 실제 계정 잠금/해제나 네트워크 차단은 하지 않는다.
10. 세 Webhook은 `NEXUS Graylog Webhook Basic Auth` 참조 placeholder를 사용한다. 실제 credential/secret은 JSON에 없다.

## 3. Graylog → n8n payload 계약

Graylog 기본 HTTP alert body는 `event_definition_id/title/description`, `event` 객체, 설정에 따른 `backlog`를 포함할 수 있다. 후보는 schema v1.1 canonical envelope만 처리한다. 실제 Notification은 연결되지 않았으므로 다음은 연결 전 계약이다.

```json
{
  "schema_version": "1.1",
  "rule": {
    "id": "R6",
    "stable_name": "POST_LOCK_RETRY",
    "display_name": "[NEXUS][R6] 잠금 후 로그인 재시도",
    "severity": "high"
  },
  "action_level": "alert",
  "alert": {"id": "<Graylog event.id>", "timestamp": "<Graylog event.timestamp>", "priority": 3},
  "event": {
    "user": "kim",
    "src_ip": "203.0.113.30",
    "lock_request_id": "<actual field>",
    "trigger_event_type": "<actual field>",
    "count": 3,
    "window_seconds": 300
  }
}
```

- `alert.id/timestamp/priority`는 Graylog Event의 `event.id/timestamp/priority`를 그대로 매핑한다. priority는 숫자 1/2/3이며 severity 문자열로 변환하지 않는다.
- 이 payload는 v1.1 envelope에 `rule.severity`를 추가 확장한다. `rule.severity`는 현재 Graylog Event field가 아니므로 규칙별 Notification의 고정 메타데이터로 명시해야 한다. `rule.id/stable_name/display_name/severity`와 `action_level`은 source Event.fields가 아니라 규칙별 Notification의 고정 메타데이터다. `rule.severity`는 기존 Rule Matrix에서 전달한다: R1 suspicion=high, R1 locked=medium, R2=high, R5=medium, R6=high, R7=info, R8=info, R9=medium, R10=medium. Graylog priority를 변환한 값이 아니다. `event.severity`는 source field에 실제 있을 때만 전달한다.
- `event.event_type`, `src_ip`, `user`, `decision`, `request_id`, `session_id`, `tool_name`, `evidence`는 실제 Event.fields에 있을 때만 넣는다. 필드가 없는 규칙은 생략한다.
- `event.evidence`는 확인된 비민감 증거만 허용한다. raw message/backlog와 prompt/body/password/token/cookie는 보내지 않는다.
- R2에서는 `pattern_id`만 전달하고 prompt 원문은 보내지 않는다. 후보가 허용하는 ID는 `ignore_previous_instructions`, `reveal_hidden_prompt`, `policy_bypass_protected_data` 세 개다.

Graylog 공식 문서는 HTTP alert body/template에서 Event와 backlog metadata를 사용할 수 있다고 설명한다. [Graylog Alert Types](https://go2docs.graylog.org/current/interacting_with_your_log_data/alert_types.htm), [Event Definitions](https://go2docs.graylog.org/current/interacting_with_your_log_data/event_definitions.html)

## 4. 현재 확인된 Event.fields

| Rule | 확인된 Event.fields | 없는 값/주의 |
|---|---|---|
| R1 | `event_type,user,src_ip,request_id,decision,reason,failed_attempts,window_seconds` | `account_locked`는 failed_attempts/window_seconds 없음 |
| R2 | `event_type,injection_type,decision,pattern_id,reason,request_id,role,session_id,severity,source_component,source_type,src_ip,user` | Prompt 원문 없음 |
| R5 | `src_ip` | distinct user/count/decision/event_type 없음 |
| R6 | `user,src_ip,lock_request_id,trigger_event_type,count,window_seconds` | `request_id/decision/severity/event_type` 없음; count는 직접 field |
| R7 | `user,src_ip` | event_type/decision/severity/원본 로그인 시각 없음 |
| R8 | `src_ip,path` | path는 빈 값일 수 있고 count는 Event.fields에서 확인되지 않음 |
| R9 | `user,path` | src_ip/decision/role/reason/required 없음 |
| R10 | `user,path,resource` | src_ip/decision/role 등 없음 |

## 5. Rule별 대응

| rule.id | 확인 조건 | 후보 동작 | DB/외부 대응 |
|---|---|---|---|
| R1 `account_compromise_suspected` | WARN, failed_attempts≥3, 300초 | 경보/티켓; Discord 예정만 표시 | 자동 잠금 없음 |
| R1 `account_locked` | BLOCK/DENY | 이미 잠금된 결과 티켓 | 추가 잠금 없음 |
| R2 | direct `prompt_injection_detected`, DENY | 경보/티켓 계획 | 추가 차단 없음 |
| R5 | 계정 스프레이 | IP 티켓/경보 계획 | IP 차단 없음 |
| R6 | count≥3, window=300, lock 참조 | 티켓/경보 계획 | 추가 잠금 없음 |
| R7 | observe | 관찰 티켓 계획 | 없음 |
| R8 | 404 scan | IP 티켓/경보 계획 | IP 차단 없음 |
| R9/R10 | 권한 거부 Event | IP가 있으면 IP ticket, 없으면 user fallback | 없음 |
| R3/R4/R11/R12 | 아직 미구현 | fallback만 | Tool 제한/토큰 폐기 미구현 |
| 미지원 rule.id | 불명 | fallback/error만 | 없음 |

decision이 없는 집계 Event는 차단 성공/실패로 추정하지 않는다. action_level이 미정/불일치하거나 event 필드 검증에 실패하면 fallback한다.

## 6. R9/R10 src_ip

현재 R9 Event.fields에는 `user,path`, R10에는 `user,path,resource`만 있어 Event record에서 src_ip를 바로 넘길 수 없다. 탐지 query는 바꾸지 않는다.

Graylog Notification body에서 backlog의 `fields.src_ip`만 골라 보낼 수는 있다. 원문/backlog 전체를 보내지 말고, 고유 IP가 하나일 때만 `event.src_ip`로 보낸다. 여러 IP이거나 backlog가 비면 src_ip를 생략한다. 대안으로 Event Definition의 field specification에 `src_ip`를 추가해 원본 필드를 Event에 싣는 방법이 있다. Graylog 문서는 custom event field가 원본 메시지 필드를 Event index에 담을 수 있다고 설명하지만, 현재 R9/R10 Notification body에서의 동작은 아직 검증되지 않았다.

후보는 `event.src_ip`가 있으면 `ip:<src_ip>`를 ticket key로 쓰고, 없으면 `user:<user>`로 fallback한다. 따라서 src_ip 없는 R9/R10은 서로 다른 IP라도 같은 user면 한 티켓으로 합쳐질 수 있다. 이는 현재 데이터 한계다. Graylog 설정은 변경하지 않았다.

## 7. n8n 환경변수 및 credential

- n8n `2.37.7`이며 `N8N_BLOCK_ENV_ACCESS_IN_NODE`는 컨테이너에 명시되지 않았다. v2.0 변경 안내 기준 기본 차단이므로 설정을 `false`로 완화하지 않는다. 후보 Code node에는 `$env` 참조가 없다.
- 후보에서 `WEBHOOK_TOKEN`, `RESPONSE_MODE`, `WHITELIST_IPS`, `LOCK_MINUTES`는 사용하지 않는다.
- 추후 import 전에 n8n UI에서 `NEXUS Graylog Webhook Basic Auth` credential을 생성해 별도 username/password를 설정한 뒤 세 Webhook에 연결해야 한다. Graylog HTTP Notification에도 같은 Basic Auth 값을 설정한다. secret은 workflow JSON/Git에 넣지 않는다. 티켓 API는 서버 측에서 호출하고 Basic Auth를 브라우저에 노출하지 않는다. 후보에서는 `allowedOrigins: "*"`를 제거했으므로 cross-origin UI가 필요하면 서버 proxy 또는 명시적 trusted origin을 별도 설정한다.
- 후보에 Discord node/URL이 없다. dry-run 동안 Discord는 보내지 않는다. 별도 승인 뒤 전송 credential/config를 추가해야 한다.
- MySQL 전용 credential은 현재 없고 후보는 참조하지 않는다.

## 8. MySQL 최소권한 준비안

후보에는 DB node와 UPDATE SQL이 없다. 아래는 향후 별도 승인 후 DBA가 검토할 설계 예시이며 실행하지 않았다.

```sql
GRANT SELECT (username, pinned, locked_until, session_version),
      UPDATE (locked_until, session_version)
ON nexus.users TO 'nexus_n8n'@'<n8n-dedicated-network-static-ip>';
```

읽기는 해당 네 필드만, 쓰기는 `locked_until`과 `session_version`만이다. 비밀번호/role/profile/다른 테이블/전체 DB 권한은 허용하지 않는다. MySQL column-level privilege는 [공식 GRANT 문서](https://dev.mysql.com/doc/refman/8.4/en/grant.html)에 명시되어 있다. 계정/권한/credential은 만들지 않았다. R1 자동 잠금은 제거됐고 R3/R11/R12의 세션 버전 처리는 미구현이다.

## 9. Docker 네트워크 연결안

n8n은 `bridge`, MySQL은 `nexus-work_default`라 서로 연결되지 않는다. host port를 외부에 열지 않는다. 추후 `nexus-n8n-db` 전용 user-defined network를 만들고 `n8n`과 `nexus-mysql`만 연결한다. DB host는 `nexus-mysql:3306`; 가능하면 n8n에 예약 IP를 주고 MySQL account host를 그 주소로 제한한다. `internal` 여부/대역은 Docker address pool과 Discord outbound 요구를 대조한 뒤 결정한다. n8n의 기존 bridge는 인터넷 outbound용으로 유지할 수 있다.

일회성 `docker network connect`는 컨테이너 재생성 때 사라진다. 영속화하려면 nexus compose와 현재 Compose label이 없는 n8n의 실제 시작 정의 양쪽에 external network를 선언해야 한다. 네트워크 변경은 하지 않았다.

## 10. Ticket 저장 추천

| 안 | 장점 | 한계 |
|---|---|---|
| A. workflowStaticData | 발표/초기 통합에 빠르고 별도 테이블 불필요 | 재시작·이관·동시 실행·감사 보장에 부적합 |
| B. NEXUS DB `security_incidents` | alert.id dedup, IP별 ticket, 처리 이력, 보존 및 UI/API 공용 조회 | migration·권한·동시성 설계 필요 |

**추천:** 개발/발표 검증은 A, 운영 전환은 B. 운영 incident ticket은 영속 이력과 중복 처리가 필요해 현재 규모에도 B가 적절하다. 이번 후보는 A를 유지했고 테이블/마이그레이션은 만들지 않았다. `src_ip`가 있으면 `ip:<src_ip>`, 없으면 `user:<user>`로 묶는다. R9/R10에서 IP가 없으면 서로 다른 IP라도 같은 user ticket에 합쳐질 수 있다. dedup은 staticData 최근 500 alert에 한정된다.

## 11. 미구현/미연결

- R4 내부 API token 폐기 미구현.
- R3/R11/R12 Security Gateway 및 AI Tool 제한 미구현.
- Graylog → n8n Notification, 실제 Discord 송신, DB credential/계정/권한/UPDATE 모두 미실행.
- 후보는 Discord 및 MySQL 노드가 없고, staticData ticket은 운영용 영속 저장소가 아니다.

## 12. dry-run 테스트 계획

테스트는 실행하지 않았다. 별도 승인 뒤 격리된 n8n 공간에 inactive로 import하고 Basic Auth credential을 바인딩한 다음 Mock POST로 수행한다. 운영 Graylog/DB는 연결하지 않는다.

| 케이스 | 기대 결과 |
|---|---|
| schema_version 1.0, required 누락, priority 4 | 422 fallback, ticket/DB/Discord 0 |
| action_level 누락/불일치 | 422 fallback |
| 미지원 R3/R4/R11/R12/임의 rule | 202 fallback, ticket/DB/Discord 0 |
| R1 suspicion WARN + 실패 3/300초 | ticket/경보 계획, 잠금 없음 |
| R1 account_locked BLOCK/DENY | 잠금 결과 ticket, 추가 잠금 없음 |
| R2 direct/DENY/pattern_id | ticket/경보 계획, prompt 원문 미포함 |
| R5/R7/R8/R9/R10 실제 fields | rule.id 분기, 없는 값 생성 없음 |
| R6 `event.count=3`, window 300, lock ref/type | count=3 그대로 보존 |
| R6 count 누락, evidence.retry_count만 존재 | 422 fallback |
| R9/R10 src_ip 누락 | `user:<user>` fallback 한계 확인 |
| 동일 alert.id 2회 | ticket 1건, 재전송은 duplicate 응답 |
| decision 누락 | DB 0, ticket/fallback만; decision 생략 |
| `X-Response-Mode: live` | 영향 없음, dry-run 유지 |
| ticket lock/release | dry-run 기록만, DB UPDATE 0 |
| 잘못된 Basic Auth | 401; 올바른 credential만 workflow 진입 |
| payload/execution data 검사 | prompt/raw body/password/token/cookie/backlog 미포함 |

### 추후 적용 순서

1. Rule별 Notification template에서 canonical allowlist body를 만들고 mock 수신 필드를 확인한다.
2. 후보를 새 workflow로 import하되 inactive 유지; Basic Auth credential을 UI에서 바인딩한다.
3. 위 positive/negative dry-run과 민감정보 미저장을 확인한다.
4. R9/R10 unique IP 및 user fallback을 확인한다.
5. Discord/DB 대응은 별도 설계·권한 검토·승인 후 추가한다.
6. Graylog Notification은 마지막에 연결하고 한 건씩 확인한다.
