# 메신저(nexus-messenger) 연동 API

별도 프로젝트 **nexus-messenger**(Flutter, 데스크톱+모바일)가 nexus-work 계정으로 로그인해
직원끼리 1:1·그룹 채팅을 하기 위한 API다. 이 문서만 읽고도 클라이언트를 처음부터 구현할 수
있게, 엔드포인트·요청/응답 모양·오류·실시간 프로토콜을 전부 적는다.

nexus-messenger 저장소 쪽 현재 상태와 다음 할 일은 그 프로젝트의
`작업내역_체크리스트.md`(`C:\Users\stuls\Desktop\Agent\nexus-messenger\작업내역_체크리스트.md`)에 있다.

## 1. 인증 모델 — 왜 쿠키가 아니라 토큰인가

웹 화면(`/login` 등)은 세션 쿠키 + CSRF 토큰을 쓰지만, 네이티브 앱은 브라우저가 아니라서
쿠키를 자동으로 들고 다니지 않는다. 그래서 메신저는 완전히 별도 인증 체계를 쓴다.

- 로그인하면 **토큰**(랜덤 문자열)을 한 번만 평문으로 받는다. 서버는 토큰의 sha256 해시만
  `api_tokens` 표에 저장한다(평문은 어디에도 남지 않는다).
- 이후 모든 요청에 `Authorization: Bearer <token>` 헤더를 싣는다.
- 토큰은 발급 후 **30일**(`TOKEN_TTL_DAYS`, `app/messenger_api.py`) 뒤 만료된다. 로그아웃하면
  그 자리에서 `revoked_at`이 찍혀 즉시 못 쓰게 된다.
- `/api/v1/*` 전체가 CSRF 검사에서 빠져 있다(`app/security.py`의 `check_csrf`). 쿠키를 전혀
  안 쓰므로 브라우저가 자동으로 실어 보내는 쿠키를 노리는 CSRF가 애초에 성립하지 않는다.
- 아이디·비밀번호 확인(잠금 5회, 15분, 계정 열거 방지, 타이밍 동일화)은 웹 로그인과 **완전히
  같은 코드**(`app/auth.py`의 `authenticate()`)를 쓴다. 로그인 IP 속도 제한(분당 20회)도 웹과
  공유한다.
- 사용자 역할·잠금 상태는 토큰을 쓸 때마다 DB에서 다시 읽는다(세션 쿠키 모델과 같은 원칙).
  관리자가 계정을 잠그면 이미 로그인된 메신저 세션도 다음 요청부터 거부된다.

## 2. 엔드포인트

모든 응답은 JSON. 실패는 `{"error": "<코드>", "message": "<화면에 보여줘도 되는 한국어 문구>"}`
모양에 HTTP 상태 코드를 함께 쓴다. 인증이 필요한 경로에서 토큰이 없거나 틀리면 `401
{"error": "unauthorized", ...}`.

### POST /api/v1/login — 로그인(토큰 발급)

요청 본문(JSON): `{"username": "kim", "password": "...", "device": "내 PC(선택)"}`

| 상태 | 의미 |
|---|---|
| 200 | `{"token": "...", "expires_at": "2026-11-17T...", "user": {"id":1,"username":"kim","display_name":"김민수","dept":"영업팀","role":"employee"}}` |
| 401 | 아이디·비밀번호가 틀렸거나 계정이 잠김(문구는 둘 다 동일 — 계정 열거 방지) |
| 429 | 이 IP에서 로그인 요청이 너무 많음(분당 20회, 웹 로그인과 공유하는 한도) |

### POST /api/v1/logout — 로그아웃(토큰 폐기)

인증 필요. 지금 쓴 토큰 하나만 폐기한다(다른 기기의 토큰은 그대로 유효 — 웹의
`session_version` 전체 폐기와 다르다). 성공: `200 {"ok": true}`.

### GET /api/v1/users?q=검색어 — 대화 상대 찾기

인증 필요. `q`를 생략하면 이름순 최대 50명, 있으면 이름·아이디·부서로 LIKE 검색(최대 50명,
본인 제외). 계정이 있는 사용자만 나온다(`employees` 주소록 전체가 아니라 `users` 표 기준).

응답: `{"users": [{"id":2,"username":"lee","display_name":"이영희","dept":"영업팀"}, ...]}`

### GET /api/v1/conversations — 내 대화방 목록

인증 필요. 최근 메시지가 있는 순서로 정렬(없는 방은 뒤로).

```json
{"conversations": [
  {"id": 1, "kind": "dm", "name": null,
   "last_body": "안녕하세요", "last_at": "Sun, 18 Oct 2026 02:56:32 GMT", "last_id": 5,
   "last_read_message_id": 3, "unread": true,
   "peer": {"id": 2, "display_name": "이영희", "dept": "영업팀"}},
  {"id": 2, "kind": "group", "name": "영업팀 공지", "last_body": null, "last_at": null,
   "last_id": null, "last_read_message_id": 0, "unread": false}
]}
```

- `kind`가 `"dm"`이면 `peer`(상대방 1명 정보)가 같이 온다. `"group"`이면 `peer`가 없다(그룹
  이름은 `name`).
- `unread`는 `last_id > last_read_message_id`로 서버가 계산해 준다. 클라이언트가 직접
  비교하지 않아도 된다.

### POST /api/v1/conversations — 대화방 만들기

요청(JSON): `{"member_ids": [2], "name": "선택, 그룹일 때만"}`

- `member_ids`가 1명이면 **1:1(dm)**, 2명 이상이면 **그룹**. 최대 50명(`MAX_GROUP_MEMBERS`).
- 본인 id는 넣지 않는다(자동 포함). 넣으면 400.
- 1:1은 **같은 두 사람 사이에 하나만** 존재한다 — 이미 있으면 새로 만들지 않고 그 방 id를
  `created: false`로 돌려준다.

| 상태 | 의미 |
|---|---|
| 201 | `{"conversation_id": 7, "created": true}` |
| 200 | `{"conversation_id": 3, "created": false}` (이미 있던 1:1 방을 재사용) |
| 400 | `member_ids`가 비었거나, 존재하지 않는 사용자가 섞였거나, 본인을 넣었거나, 50명 초과 |

### GET /api/v1/conversations/\<id\>/messages?after=0&limit=50 — 메시지 조회

인증 필요, 그 대화방 멤버만(아니면 403). `after`(기본 0, 그 id보다 큰 메시지만 — 이어받기용)
`limit`(기본 50, 최대 200). **조회하면 그 시점까지 읽음 처리된다**(`last_read_message_id` 갱신,
위 목록 API의 `unread` 계산에 쓰인다).

```json
{"messages": [
  {"id": 4, "sender_id": 1, "sender_name": "김민수", "body": "네 알겠습니다",
   "created_at": "Sun, 18 Oct 2026 02:50:00 GMT"}
]}
```

### POST /api/v1/conversations/\<id\>/messages — 메시지 보내기

그 대화방 멤버만(아니면 403). 사용자당 분당 20회(`CHAT_USER_LIMIT`, 넘으면 429). 본문은
1~4,000자, 제어문자 불가(`validators.text`).

요청: `{"body": "안녕하세요"}` → 성공 201, 응답은 메시지 조회와 같은 모양 한 건
(`{"message": {...}}`). 전송과 동시에 **같은 대화방의 다른 멤버에게 Socket.IO로도 바로
전달된다**(3절).

## 3. 실시간 전송(Socket.IO)

- 라이브러리: 서버는 `flask-socketio`(`app/realtime.py`), 클라이언트는 아무 Socket.IO 4.x
  호환 클라이언트(Flutter는 `socket_io_client` 패키지)면 된다. 경로는 기본값(`/socket.io/`),
  REST API와 **같은 포트**(5070)를 쓴다.
- 연결: `io(baseUrl, auth: {"token": "<로그인 때 받은 토큰>"})`. 토큰이 없거나 틀리면 서버가
  핸드셰이크 단계에서 바로 끊는다(붙었다가 쫓겨나는 게 아니라 애초에 연결이 안 됨).
- 연결에 성공하면 서버가 **그 순간 내가 속한 모든 대화방**에 자동으로 구독시킨다(클라이언트가
  방마다 `join`을 보낼 필요 없음).
- **접속해 있는 동안 새로 초대된 대화방**(`POST /api/v1/conversations`)도 재접속 없이 바로
  구독된다(서버가 user_id→연결 매핑을 들고 있다가 즉시 합류시킴, `app/realtime.py`의
  `join_new_conversation`).
- 이벤트는 `"message"` 하나뿐이다. payload는 `POST .../messages` 응답의 `message`와 완전히
  같은 모양(`id`, `conversation_id`, `sender_id`, `sender_name`, `body`, `created_at`).
  **본인이 보낸 메시지도 이 이벤트로 돌아온다**(REST 응답과 소켓 이벤트 둘 다 오므로, 클라이언트는
  메시지 id로 중복을 걸러야 한다).
- 재연결 전략은 클라이언트 라이브러리 기본값을 쓰면 된다(끊겼다 재연결하면 다시 로그인 때
  쓴 토큰으로 자동 재인증·재구독됨).

## 4. DB 표 (추가분, `db/schema.sql`)

기존 12개 표에 4개를 더했다(권한은 `db/grants.sql`, 전부 `nexus_app` 계정 — 메신저용 기밀
표는 없다).

| 표 | 역할 |
|---|---|
| `api_tokens` | 토큰 해시, 발급·만료 시각, `revoked_at`(로그아웃 시 채움). 평문 토큰은 저장 안 함 |
| `conversations` | `kind`(dm/group), `name`(그룹만), `created_by` |
| `conversation_members` | 대화방×사용자, `last_read_message_id`(읽음 위치) |
| `messenger_messages` | `conversation_id`, `sender_id`, `body`, `created_at`. 수정·삭제 없음(경비·결재와 같은 "이력 불변" 원칙) |

## 5. 보안 설계 요약 (nexus-work 기존 통제와 같은 수준)

- SQL은 전부 상수 문자열 + 파라미터(`tests/test_sql_static.py`가 강제). 가변 개수 id 조회는
  `IN (...)`을 동적으로 만들지 않고 기존 코드(erp.py 팀 범위 조회)와 같은 `FIND_IN_SET` 패턴을
  쓴다.
- 입력 검증은 기존 `app/validators.py` 그대로 재사용(메시지 길이·제어문자, id는
  `positive_int`, 검색어는 `like_pattern`).
- 보안 로그(`logs/security.jsonl`)에 새 이벤트: `messenger_login_success`,
  `messenger_logout`, `messenger_authz_deny`(토큰 없음/대화방 비멤버), `messenger_message_sent`,
  `messenger_conversation_created`, `messenger_ws_connect`/`messenger_ws_deny`. 대화 내용은
  기존 챗봇과 같은 원칙으로 **로그에 남기지 않는다**(길이도 남기지 않음 — 필요하면 추후 추가).
- 속도 제한은 로그인(IP, 웹과 공유)과 메시지 전송(사용자, 챗봇과 같은 한도 `CHAT_USER_LIMIT`)
  둘 다 있다. 기존 `ip_rate_limited`와 같은 프로세스 메모리 구현이라 **단일 프로세스 가정**이고
  (`# ponytail:` 주석 참고), Socket.IO 연결 매핑(`_sids_by_user`)도 마찬가지다.

## 6. 로컬에서 켜고 시험하기

```bash
pip install -r requirements.txt        # flask-socketio 포함
python run.py                          # 이제 Socket.IO도 같은 포트(5070)에서 돈다
```

`run.py`는 `werkzeug.serving.run_simple`을 직접 부르던 것에서
`flask_socketio.SocketIO.run()`으로 바뀌었다(내부적으로 여전히 같은 werkzeug 개발 서버와
`QuietHandler`를 쓰므로 `Server: NEXUS` 헤더·루프백 기본값은 그대로다). 대화형 터미널이 아닌
곳(nohup 등)에서 띄울 때 라이브러리가 "프로덕션 같다"며 거부하지 않도록
`allow_unsafe_werkzeug=True`를 줬다 — 이미 README에 개발 서버임을 명시했고 운영에는 WSGI
서버를 쓰라고 안내하므로 기존 방침과 같다.

빠른 확인(파이썬, `requests` + `python-socketio[client]` 필요):

```python
import requests, socketio
r = requests.post("http://127.0.0.1:5070/api/v1/login",
                  json={"username": "kim", "password": "..."})
token = r.json()["token"]
hdr = {"Authorization": f"Bearer {token}"}
print(requests.get("http://127.0.0.1:5070/api/v1/conversations", headers=hdr).json())
```

## 7. 알려진 한계 / 다음에 할 수 있는 것

- 메시지 검색·삭제·수정, 읽음 상태를 상대방에게 보여주기(현재는 본인 읽음 위치만 서버가 앎),
  그룹 멤버 추가·탈퇴, 알림(푸시) 미구현 — 전부 범위 밖(MVP).
- `scan_inputs`(의심 입력 탐지, `suspicious_input` 이벤트)는 `request.form`/`request.args`만
  보고 JSON 본문은 보지 않는다. 메신저 API는 전부 JSON이라 **의심 입력 탐지 대상이 아니다**
  (파라미터 바인딩으로 안전하게 처리되는 것은 동일하지만, C가 보는 신호에는 안 잡힌다).
  필요해지면 `scan_inputs`에 JSON 본문 처리를 추가해야 한다.
- 2절 "실시간 전송"의 room 매핑·속도 제한 모두 프로세스 메모리 기반(여러 워커로 확장하려면
  Redis 같은 공유 저장소로 교체 필요 — 기존 로그인 속도 제한과 같은 한계).
- `scripts/defense_check.py`식 블랙박스 점검은 아직 `/api/v1/*`를 다루지 않는다(기존 18항목은
  웹 화면 기준). 메신저 API 전용 점검은 다음 작업.
