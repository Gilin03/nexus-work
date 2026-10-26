# Graylog Alerts UI 렌더링 실패 - Event priority 범위 오류

## 증상

- Alerts 화면에서 `Loading component failed: Cannot read properties of undefined (reading 'name')` 오류가 발생했다.
- Graylog 컨테이너는 healthy였고 `/api/system`, Event Definition API, `/search` 화면은 정상 응답했다.
- R1/R2/R6 Event 탐지는 동작하고 있었다. 실패 범위는 Alerts/Events 목록을 그리는 프론트엔드 화면이었다.
- 브라우저 Console stack trace는 `Events.jsx:95:84`, `Events.jsx:190:14`, `Events.jsx:284:31`을 가리켰다.

## 영향

- **서버 장애:** 확인되지 않았다. Graylog 컨테이너 상태와 시스템 API가 정상이었다.
- **탐지 장애:** 확인되지 않았다. R1/R2/R6 Event가 실제로 생성되고 positive/negative 결과도 확인됐다.
- **UI 장애:** Alerts/Events 화면이 특정 Event priority를 렌더링하다 실패했다. 화면 오류가 탐지 Event 생성 중단을 의미하지는 않았다.

## 조사 과정

1. Graylog 컨테이너 health와 실행 상태를 확인했다. 컨테이너는 healthy였다.
2. Graylog 6.1.16 `/api/system`이 HTTP 200으로 응답하고 Event Definition API도 동작하는 것을 확인했다. `/search` 등 다른 Graylog 화면도 열렸다.
3. R1/R6/R2 Event Definition을 비교했다. R1/R2는 priority=4였고 R6는 priority=3이었다. R1/R2 탐지 조건과 Event 생성은 동작 중이었다.
4. 브라우저 F12 Console에서 실제 렌더링 예외를 확인했다.
5. stack trace가 `Events.jsx`의 Event 목록 렌더 경로를 가리키는 것을 확인했다. 해당 소스는 `EventDefinitionPriorityEnum.properties[priority].name`을 fallback 없이 참조했다.
6. Graylog 6.1.16 UI의 `EventDefinitionPriorityEnum`을 확인했다. 지원하는 값은 LOW=1, NORMAL=2, HIGH=3이었다.
7. 저장된 Event record의 priority를 검색하고 기존 정상 Event와 비교했다.
8. priority=4 레코드가 R1 8개, R2 11개로 총 19개였고, R6는 priority=3, R7은 priority=1, R9는 priority=3인 것을 확인했다.
9. R1/R2 Event Definition과 실제 Event record에 priority=4가 있는 반면 비교 대상 R6/R7/R9에는 4가 없었다. UI 소스가 enum 밖 값을 안전하게 처리하지 않아 오류가 재현되는 데이터 경로를 원인으로 특정했다.

## 근본 원인

Graylog 6.1.16 UI가 지원하는 Event priority enum은 다음과 같다.

- `1` = LOW
- `2` = NORMAL
- `3` = HIGH

R1/R2 Event Definition이 `priority=4`로 생성되었고 Graylog API는 이 값을 저장했다. 하지만 UI enum에는 4가 없었다. `Events.jsx`는 아래처럼 해당 priority의 이름을 fallback 없이 읽는다.

```text
EventDefinitionPriorityEnum.properties[priority].name
```

`priority=4`이면 `properties[4]`가 `undefined`이므로 `.name` 접근에서 렌더링이 실패했다. 이는 Graylog 서버/API나 탐지 조건의 장애가 아니라, API에 저장된 enum 범위 밖 값과 UI의 예외 처리 부재가 결합한 문제였다.

## 확인된 데이터

| 규칙/정의 | 화면 오류 수정 전 priority | 확인된 Event 수 |
|---|---:|---:|
| R1 | 4 | 8 |
| R2 | 4 | 11 |
| 합계 |  | 19 |
| R6 | 3 | 기존 탐지 확인 |
| R7 | 1 | 기존 정상 값 |
| R9 | 3 | 기존 정상 값 |

## 수정

- R1 Event Definition `6ad5ac319d0f6c101dafd65b`와 R2 Event Definition `6ad5b4e09d0f6c101dafec4d`의 priority를 `4 → 3 (HIGH)`으로 변경했다.
- 수정 전후 DTO 비교에서 바뀐 경로는 두 정의 모두 `/priority` 하나였다. query, Stream, schedule, group_by, field_spec, key_spec, 알림 설정 및 ENABLED 상태는 유지됐다.
- `docs/SECURITY_LOG_SPEC.md`의 관련 Graylog priority 설명과 R1/R2 HIGH 예시를 3으로 정정했다.
- 앱 코드와 Stream은 수정하지 않았다.

## 수정 후 검증

- R1/R2 Event Definition 각각을 validation API로 검사해 `failed=false`, `errors={}`를 확인했다. 업데이트 후 상태는 ENABLED이고 priority는 3이었다.
- 새 R1 positive Event는 priority=3으로 생성됐고 R1 negative인 `login_success`는 Event 0건이었다. R1 원본 분기는 `NEXUS_AUTH`에 유지됐다.
- 새 R2 positive Event는 priority=3으로 생성됐고 R2 negative인 indirect `prompt_injection_observed`/ALLOW는 R2 Event 0건이었다. R2 원본은 `NEXUS_AI_SECURITY`에 유지됐다.
- R6 positive/negative 탐지도 기존과 같이 동작하는 것을 확인했다.
- Alerts 조회 범위를 최근 15분으로 좁혀 정상 렌더링되는 것을 확인했다.
- 긴 기간 Events 검색에서 `priority:[1 TO 3]` 조건을 적용하면 검색 결과가 1~3으로 제한되어 과거 priority=4 레코드를 제외하는 것을 확인했다.

## 과거 priority=4 Event 처리

- 과거 Event 19개는 삭제하지 않고 보존했다.
- Graylog 6.1.16 Events API 문서/리소스에서 확인한 경로는 검색 `POST /api/events/search`와 단건 조회 `GET /api/events/{event_id}`였다. Event 단건 삭제 경로는 확인되지 않았다.
- index 전체 삭제는 해당 인덱스의 정상 Event까지 영향을 줄 수 있어 사용하지 않았다.
- MongoDB/OpenSearch 직접 수정도 하지 않았다.

## 실제 UI 복구 방법

- Alerts 조회 범위를 최근 15분으로 설정했을 때 화면이 정상 렌더링되는 것을 확인했다.
- 긴 기간의 Events를 검색할 때 `priority:[1 TO 3]`을 검색 조건으로 사용하면 과거 priority=4 Event를 결과에서 제외할 수 있다. 검색 API와 Find Events 검색 입력에서 이 조건이 적용되는 것을 확인했다.
- 이 방법은 데이터를 변경하지 않는 조회 방식이다. 과거 priority=4 Event를 포함하는 기간을 필터 없이 조회하면 같은 UI 오류가 다시 나타날 수 있다.

## 최종 상태

- R1/R2 정의 priority 수정 완료: 3 (HIGH).
- 새 R1/R2 Event는 priority=3으로 생성된다.
- Alerts 화면은 최근 15분 조회에서 정상 렌더링된다.
- 긴 기간 Events 조회는 `priority:[1 TO 3]` 필터를 적용해 과거 잘못된 priority의 Event를 제외할 수 있다.
- 과거 priority=4 Event 19개는 삭제·수정하지 않고 보존 중이다.
- R1/R2/R6 탐지 결과와 Stream 분류는 유지됐다.

## 배운 점

- API validation 통과가 UI compatibility까지 보장하지 않는다.
- enum 범위를 벗어난 설정값이 프론트엔드 렌더링 장애를 만들 수 있다.
- 서버, API, 탐지, UI를 구분해 진단해야 한다.
- 자동 설정 생성 전 Graylog 버전별 enum과 schema 범위를 확인해야 한다.

## 재발 방지

- Graylog Event Definition priority는 1~3만 사용한다.
- 생성 또는 수정 API를 호출하기 전에 priority 허용값을 검증한다.
- 설정 적용 후 실제 생성된 Event의 priority를 확인한다.
- API 검증뿐 아니라 Alerts/Events UI까지 확인한다.
- Graylog 버전별 enum/schema 제약과 실제 검증 결과를 기록한다.
