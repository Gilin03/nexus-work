# R1/R6 앱 인증 이벤트 집계 설계

- 상태: 설계 검토용, 아직 구현되지 않음
- 기준 명세: docs/SECURITY_LOG_SPEC.md v1.1
- 설계 승인: 대화에서 MySQL 상태 저장 방식 승인됨
- 구현 전 검토: 이 문서의 인터페이스와 데이터 흐름 검토 필요

## 1. 목표와 범위

Graylog 6.1 Community 현재 설치에서는 이벤트 간 순서/상관 기능을 사용할 수 없다. R1과 R6의 의미나 임계값을 낮추지 않고, 포털 앱이 필요한 5분 상태를 계산해 파생 보안 이벤트를 추가 기록한다. Graylog는 각 파생 이벤트 종류에 대해 단일 메시지 필터 Event Definition을 사용한다.

요청된 구현/기록 문구:

> Graylog 6.1 Community/현재 환경의 상관 기능 제약 때문에 앱 집계 이벤트 방식으로 대체

이번 구현 범위:

- R6 잠금 후 로그인 재시도 집계 및 positive/negative 검증
- R6 확인 후 R1 실패 3회 이상 뒤 성공 집계 및 검증
- 원본 인증 이벤트 보존
- 파생 이벤트의 GELF/Graylog 검색 및 단일 Event Definition 확인
- SECURITY_LOG_SPEC.md와 WORK_LOG 갱신

이번 범위에서 다루지 않는 항목:

- R2/R3/R4/R11/R12 및 AI/Gateway 이벤트 구현
- 인증 동작, 잠금 한도, 계정 잠금 시간 변경
- Graylog Correlation Engine, Pipeline 또는 새 Stream 추가
- 비밀번호, 토큰, Prompt 원문 저장

## 2. 현재 저장소에서 확인한 사실

- app/auth.py는 계정 잠금 발생 시 account_locked를 기록하고, 이미 잠긴 계정의 후속 로그인은 login_locked로 기록한다.
- 잠금에 도달한 요청은 account_locked를 먼저 기록한 뒤 login_failure도 같은 HTTP 요청에서 기록한다. 이 실패 로그를 잠금 후 재시도로 세면 안 된다.
- 로그인 실패와 성공은 현재 인증 요청에서 user/src_ip를 기록하지만 request_id는 아직 이벤트에 포함하지 않는다.
- app/security.py는 JSONL과 선택적 GELF 기록을 담당한다. GELF 필드는 고정 allowlist를 사용한다.
- 앱 DB 연결은 요청 단위이며 실패 요청의 로그인 카운터 변경은 auth.py가 명시적으로 커밋한다. 새 상태도 해당 요청의 트랜잭션에 포함해야 한다.
- db/schema.sql과 db/grants.sql은 nexus와 nexus_test 양쪽에 init.sh가 적용한다. 기존 DB 볼륨에는 별도 additive migration이 필요하다.
- 기존 사용자 실패 횟수는 5분 이벤트 이력이 아니므로 R1/R6의 상관 상태로 재사용할 수 없다.

## 3. 탐지 의미와 경계

### R6 — POST_LOCK_RETRY

원래 조건을 그대로 유지한다.

- account_locked가 발생한다.
- 잠금 발생 시점부터 300초 이내에 같은 user와 같은 src_ip에서 다른 request_id의 로그인 시도가 3회 이상 발생한다.
- login_locked와 login_failure는 각각 후속 로그인 시도 1회로 계산한다. login_locked 1회만으로는 R6을 발생시키지 않는다.
- 세 번째 후속 시도에서 post_lock_retry_detected를 한 건 생성한다. 같은 account_locked 기준으로 그 뒤 시도가 더 있어도 파생 이벤트를 다시 생성하지 않는다.
- 잠금 요청과 같은 request_id의 login_failure는 후속 시도로 계산하지 않는다.
- user 또는 src_ip가 식별 불가이면 R6 상관에 사용하지 않는다.
- 다른 user/src_ip, 잠금보다 앞선 이벤트, 300초를 초과한 이벤트는 계산하지 않는다.

현재 앱의 잠긴 계정 경로는 login_locked를 기록하므로 login_locked 세 건이 count 1→2→3으로 누적되고, 세 번째 시도에서만 R6이 발생한다.

### R1 — ACCOUNT_COMPROMISE

원래 OR 조건과 임계값을 그대로 유지한다.

- 같은 user의 login_failure가 성공 시각보다 앞선 직전 300초 구간에 3회 이상이고, 그 뒤 login_success가 발생하면 파생 이벤트를 기록한다.
- 이 조건은 src_ip가 같아야 한다는 조건이 없다. 서로 다른 IP의 실패도 같은 user라면 집계한다.
- account_locked 분기는 이미 존재하는 원본 account_locked를 사용한다. R1용 account_compromise_suspected를 중복 생성하지 않는다.
- 2회 실패 후 성공, 다른 사용자의 실패, 성공 뒤의 실패, 300초 밖의 실패는 첫 번째 분기와 일치하지 않는다.

## 4. 제안 데이터 흐름

1. 각 Flask 요청에 불투명한 request_id를 한 번 생성하고 그 요청에서 기록되는 인증 원본 이벤트들에 재사용한다. 각 이벤트의 ts는 UTC 마이크로초 정밀도로 기록하고, 이 같은 ts 값을 상태 테이블의 occurred_at에 사용한다.
2. 원본 login_failure, login_success, account_locked, login_locked를 기존과 같이 security.jsonl 및 설정된 GELF 입력으로 보낸다.
3. 인증 이벤트 집계기가 해당 원본 이벤트의 최소 메타데이터를 앱 DB의 임시 상태 테이블에 기록한다.
4. R6은 세 번째 후속 시도에서만 잠금 기준 행을 원자적으로 완료 처리하고 post_lock_retry_detected를 한 건 추가한다. R1은 login_success 직전의 실패 3회 이상 조건만 account_compromise_suspected로 추가한다. account_locked는 원본을 R1에서 직접 탐지한다.
5. 파생 이벤트는 집계 입력 이벤트 종류가 아니므로 재귀 처리하지 않는다.
6. 원본/파생 이벤트는 모두 기존 JSONL 및 GELF 경로를 사용하고, Graylog에서는 NEXUS_AUTH Stream에 분류한다.
7. Graylog는 R6 파생 이벤트 종류와 R1의 두 OR 분기 조건을 각각 단일 Event Definition으로 탐지한다. 5분 순서/횟수 조건은 앱 집계기가 책임진다.

DB 상태 기록에 실패해도 로그인/잠금 동작은 바꾸지 않는다. 집계 실패는 event_type 같은 비민감 메타데이터만으로 서버 로그에 남기고, 파생 이벤트가 생성되지 않은 상태를 테스트/운영 결과에 명시한다. 인증을 Graylog나 보조 상태 저장소의 가용성에 종속시키지 않는다.

## 5. 요청 ID와 상태 테이블

request_id는 서버가 생성하는 요청 상관용 식별자이며 세션 쿠키, API 토큰, CSRF 토큰을 재사용하지 않는다. 한 HTTP 요청 안의 account_locked와 그 요청의 login_failure는 동일 request_id를 공유한다.

상태 테이블은 최근 인증 판정에 필요한 최소 필드만 저장한다.

| 필드 | 목적 |
|---|---|
| id | 상태 행 식별 |
| request_id | 같은 요청에서 발생한 이벤트를 구분 |
| event_type | login_failure, login_success, account_locked, login_locked 중 하나 |
| username | 동일 사용자 비교 |
| src_ip | R6 동일 IP 비교; R1에서는 비교 키로 사용하지 않음 |
| occurred_at | UTC 기준 이벤트 시각, 마이크로초 정밀도, 5분 경계 계산 |
| r6_emitted_at | 해당 account_locked 행의 R6 파생 이벤트를 이미 생성했는지 원자적으로 표시 |

설계 원칙:

- event_type에 따라 필요한 인증 이벤트만 보관한다.
- 파생 판단 뒤 현재 시각보다 오래된 300초 초과 행을 제거한다.
- ts와 occurred_at은 동일한 UTC 이벤트 시각을 사용한다. ts의 마이크로초 정밀도는 기존 ISO 8601 형식과 호환되며, 5분 경계 및 이벤트 순서 판정에 사용한다.
- 인덱스는 (username, occurred_at) 및 (username, src_ip, occurred_at)을 둔다.
- account_locked 상태 행은 r6_emitted_at을 처음에는 NULL로 둔다. 세 번째 적격 시도에서 NULL 조건부 UPDATE로 한 번만 완료 표시하고, 영향받은 행이 1개일 때만 R6 파생 이벤트를 기록한다.
- src_ip가 비어 있거나 '-'인 이벤트는 R6에서 제외한다. R1에는 유효한 username만 사용한다.
- 저장·검색·삭제는 기존 앱 DB 연결과 바인딩 SQL을 사용한다.
- 신규 테이블 권한은 nexus_app에 SELECT, INSERT, DELETE와 r6_emitted_at 열에 한정한 UPDATE만 부여한다. 그 밖의 열 수정 및 DDL 권한은 부여하지 않는다.
- db/schema.sql, db/grants.sql에 신규 설치 정의를 추가하고, 이미 실행 중인 nexus/nexus_test에는 재실행 가능한 additive migration을 적용한다.
- 보존 시간은 탐지 윈도와 동일한 5분을 기본으로 하며, 이 표에 원본 로그 전체나 비밀값을 복제하지 않는다.

## 6. 파생 이벤트 계약

### R6: post_lock_retry_detected

| 필드 | 값/의미 |
|---|---|
| event_type | post_lock_retry_detected |
| user, src_ip | 원본 account_locked와 후속 재시도에서 일치한 값 |
| request_id | 조건을 충족시킨 후속 요청 |
| lock_request_id | 잠금이 발생한 원래 요청 |
| trigger_event_type | 조건을 만족한 login_locked 또는 login_failure |
| count | 세 번째 적격 후속 로그인 시도이므로 3 |
| window_seconds | 300 |
| decision | WARN |
| reason | post_lock_retry_threshold_reached |
| severity | high |

### R1: account_compromise_suspected

| 필드 | 값/의미 |
|---|---|
| event_type | account_compromise_suspected |
| user | 조건을 만족한 동일 계정 |
| src_ip | login_success 또는 account_locked 이벤트의 출발 IP |
| request_id | 조건을 만족한 login_success 요청 |
| trigger_event_type | login_success |
| count | 직전 5분 login_failure 수, 3 이상 |
| window_seconds | 300 |
| decision | WARN |
| reason | failures_then_success |
| severity | high |

파생 이벤트는 원본 이벤트를 대체하지 않는다. GELF allowlist에는 필요한 새 평면 필드만 추가한다. 객체/프롬프트 본문은 필드에 넣지 않는다.

## 7. Graylog 규칙

두 규칙 모두 NEXUS_AUTH Stream에서 단일 메시지 필터 Event Definition으로 구성한다.

| 규칙 | 검색 조건 | 집계/상관 |
|---|---|---|
| R6 POST_LOCK_RETRY | event_type:post_lock_retry_detected | 없음. 앱에서 정확한 300초·동일 user/IP·후속 시도 3회 조건 계산 |
| R1 ACCOUNT_COMPROMISE | event_type:account_compromise_suspected OR event_type:account_locked | 없음. 앱에서 동일 user·5분·실패 3회 후 성공을 집계하고, 원본 account_locked를 OR 분기로 사용 |

이벤트 정의의 이름, 설명, priority는 기존 SECURITY_LOG_SPEC.md의 stable_name/우선순위 계약을 유지한다. Event Definition을 만들기 전에 Graylog에 파생 시험 이벤트가 실제 필드명으로 저장되는지 확인한다. 검색 결과가 없거나 필드 이름이 다르면 원인을 해결하기 전 정의 활성화나 다음 규칙 단계로 넘어가지 않는다.

## 8. 검증 계획

### R6

| 구분 | 입력 | 기대 결과 |
|---|---|---|
| Positive 1 | account_locked 후 같은 user/IP의 별도 request_id에서 5분 내 login_locked가 순서대로 3회 | count 1, 2에서는 파생 이벤트 없음; count 3에서 post_lock_retry_detected 1건 및 Graylog R6 Event |
| Positive 2 | account_locked 후 적격 login_failure/login_locked가 합계 3회, 같은 user/IP, 5분 이내 | 세 번째 후속 시도에서 파생 이벤트 1건 |
| Negative 1 | 잠금 발생과 같은 request_id의 login_failure만 존재 | 파생 이벤트 없음 |
| Negative 2 | 잠금 후 적격 후속 로그인 시도가 2회뿐 | 파생 이벤트 없음 |
| Negative 3 | 다른 IP 또는 다른 user의 후속 이벤트 | 해당 이벤트는 count에 포함되지 않음 |
| Negative 4 | 잠금 300초를 초과한 뒤의 시도 | count에 포함되지 않음 |
| Negative 5 | 같은 잠금 기준에서 세 번째 시도 후 네 번째/다섯 번째 시도 | 추가 post_lock_retry_detected 없음 |

Positive 1은 현재 앱의 login_locked 경로에서 1→2→3 누적을 확인한다. Positive 2는 login_failure도 한 번의 후속 로그인 시도로 계산하는 규칙을 확인한다.

### R1

| 구분 | 입력 | 기대 결과 |
|---|---|---|
| Positive 1 | 같은 user의 5분 내 login_failure 3회 뒤 login_success. 실패 IP와 성공 IP가 달라도 집계 | account_compromise_suspected 1건 및 Graylog R1 Event |
| Positive 2 | account_locked 원본 이벤트 1회 | 파생 이벤트 없이 원본 account_locked가 Graylog R1 Event를 발생시킴 |
| Negative 1 | 5분 내 login_failure 2회 뒤 login_success | 실패→성공 분기 파생 이벤트 없음 |
| Negative 2 | 3회 실패 중 일부가 login_success보다 300초 이전 | 실패→성공 분기 파생 이벤트 없음 |
| Negative 3 | 실패가 다른 user에 분산됨 | 실패→성공 분기 파생 이벤트 없음 |

### 공통 확인

- 앱 테스트 DB에서 이벤트 시각을 고정해 경계값과 순서를 결정적으로 테스트한다.
- 앱 JSONL에서 원본 이벤트가 계속 남고, 파생 이벤트가 별도 줄로 추가되는지 확인한다.
- 비밀번호·토큰·쿠키·Prompt 원문이 상태 테이블/JSONL/GELF에 없는지 검색한다.
- GELF 전송 후 Graylog에서 파생 이벤트의 실제 필드명과 NEXUS_AUTH 분류를 확인한다.
- Event Definition 실행 후 양성 Event가 생성되고 각 음성 사례에는 Event가 없는지 확인한다.
- 각 단계 실패 시 원인을 확인·수정·재검증한 뒤에만 다음 단계로 넘어간다.

## 9. 구현 순서

1. SECURITY_LOG_SPEC.md v1.1의 R1/R6 조건과 기존 저장소 상태를 다시 대조한다.
2. 새 상태 테이블, 최소 권한, 기존 DB용 additive migration을 준비한다.
3. 요청 ID 생성 및 인증 이벤트 집계기를 추가한다. 기존 원본 JSONL/GELF 이벤트와 로그인 동작은 유지한다.
4. R6 파생 이벤트를 구현하고 R6 positive/negative 앱 테스트를 실행한다.
5. R6 시험 이벤트를 Graylog에 보내 필드·Stream을 확인하고 단일 Event Definition 및 positive/negative 결과를 검증한다. 세 번째 시도에서만 Event가 생성되고 같은 잠금 기준의 추가 시도에서는 중복 Event가 없는지도 확인한다.
6. SECURITY_LOG_SPEC.md와 WORK_LOG에 R6 구현 및 검증 결과를 기록한다.
7. 동일 집계기를 사용해 R1 파생 이벤트를 구현하고 R1 positive/negative 앱 테스트를 실행한다.
8. R1 단일 Event Definition에서 파생 event_type과 원본 account_locked의 OR 조건이 모두 동작하는지 positive/negative 결과를 검증한다.
9. SECURITY_LOG_SPEC.md와 WORK_LOG에 R1 구현 및 검증 결과를 기록한다.

## 10. 검토할 위험/제약

- 새 MySQL 테이블과 기존 두 데이터베이스 migration이 필요하다. 배포 DB에 migration이 적용되지 않으면 앱은 기존 인증을 계속 처리하지만 R1/R6 파생 탐지는 동작하지 않는다.
- 상태 테이블은 request 내 기존 DB 트랜잭션에 참여한다. 인증 DB 오류와 이벤트 집계 오류가 얽히지 않도록 보안 로그의 best-effort 동작을 유지하고, 집계 오류는 안전한 코드형 메시지로 드러낸다.
- 현재 잠긴 계정의 각 로그인 시도는 login_locked 이벤트로 기록된다. 세 번째 후속 시도만 R6을 발생시키며, r6_emitted_at 원자적 표식으로 같은 잠금 기준에서 중복 파생 이벤트를 막는다.
- R1의 실패 임계값은 3이며 로그인 코드의 계정 잠금 임계값 5와 혼동하지 않는다.
- R1의 account_locked는 원본 로그 하나로 R1 OR 조건을 만족한다. 같은 원본에서 account_compromise_suspected를 추가 생성하지 않아 중복 Alert를 피한다.
