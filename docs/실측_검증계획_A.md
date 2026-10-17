# 실측 검증 계획 — 역할 A(앱·DB 하드닝) · C(탐지)와 맞물리는 부분

작성일: 2026-10-17 · 담당: 홍주형(A) · 연계: 김태빈(C, 탐지 룰), 진혜정(D, 자동 대응·상황판)
이 문서는 "앱이 공격을 막는가"와 "막은 흔적이 탐지에 쓸 수 있는 로그로 남는가"를 **같은 절차로 반복해서 보여주는 방법**을 정한다. Wazuh·Graylog·n8n 쪽 설정은 각 담당 범위이고, A는 이벤트가 정확히 남는 데까지를 검증한다.

## 1. 어디서 무엇을 하면 통과인가 (30초, 3단계)

| 단계 | 할 일 | 통과 기준 |
|---|---|---|
| 1 | `docker compose up -d` 후 `python run.py` | `http://127.0.0.1:5070/healthz` 가 `{"status":"ok"}` |
| 2 | `python scripts/defense_check.py --report 결과.md` | 마지막 줄 `PASS 18 · FAIL 0` (루프백 주소가 아니면 실행을 거부한다) |
| 3 | `logs/security.jsonl` 을 열어 이벤트 확인 | 점검 직후 새 줄이 쌓이고 모두 JSON 한 줄, 표준 필드 포함 |

자동 시험은 `python -m pytest -q`(453개, DB 필요). 점검용 계정·글·경비·결재·급여·대화·업로드 파일은 스크립트가 끝에 모두 지우고 표별 건수가 점검 전과 같은지도 확인한다(D18).

## 2. 시스템별 정상 동작 확인 (A 파트)

| 대상 | 확인 방법 | 기대 결과 |
|---|---|---|
| MySQL(Docker) | `docker ps`, `pytest tests/test_db_privileges.py` | `nexus-mysql` 실행, 계정별 허용·거부 SQL 전부 기대대로 |
| 앱 | `python run.py`, `/healthz` | 200, 응답 헤더 `Server: NEXUS`(버전 없음) |
| 시드 | `python scripts/seed.py --db nexus`(비어 있을 때) | 계정 6개·문서·급여·경비·결재 적재 |
| 로그 출력 | 로그인 실패 한 번 후 `logs/security.jsonl` | `login_failure` 한 줄 |
| 계정 반영 | 관리자 화면 또는 SQL 로 잠금·역할 변경 | 다음 요청부터 즉시 반영 |

## 3. 공격·테스트 시나리오와 기대 결과

범례: **막음** = 방어 결과, **남는 이벤트** = `logs/security.jsonl`의 `event_type`(reason). C의 룰 제안은 4절.

| ID | 시나리오(보내는 시도) | 막음(기대 결과) | 남는 이벤트 |
|---|---|---|---|
| D01 | 응답 헤더 점검 | CSP(인라인 불가), X-Frame-Options, nosniff, no-store, 서버 버전 비노출 | — |
| D02 | 세션 쿠키 점검 | HttpOnly, SameSite=Lax(Secure는 `COOKIE_SECURE=1` 일 때) | — |
| D03 | 비로그인으로 보호 화면 14종·POST 6종 요청 | GET 은 로그인으로 303, POST 는 403 | `authz_deny`(not_logged_in), `csrf_fail` |
| D04 | 존재하는 계정·없는 계정으로 로그인 실패 | 둘 다 401, 응답 동일(계정 열거 불가) | `login_failure`(bad_password / unknown_user) |
| D05 | 같은 계정에 비밀번호 5회 실패 → 맞는 비밀번호 → 관리자 해제 | 잠금 중에는 맞는 비밀번호도 401, 해제 후 로그인 | `login_failure`×5, `account_locked`, `login_locked`, `admin_action`(unlock) |
| D06 | SQL 인젝션 탐침 12종을 로그인·직원검색·게시글·챗봇·ID·page 에 | 오류 정보·지연(시간 기반)·결과 확장·표 변경 없음 | `suspicious_input`(sqli), `login_failure`(invalid_format) |
| D07 | XSS 탐침 5종을 게시글·챗봇·경비·결재·검색에 | 모두 글자로만 표시(스크립트 실행 안 됨) | `suspicious_input`(xss) |
| D08 | 업로드 우회 8종(php, 이중 확장자, html, `.htaccess`, 위장 png, 2MB 초과) | 모두 거부, 업로드 폴더 변화 없음. 정상 파일은 첨부·nosniff 로만 다운로드 | `upload_reject`(extension_not_allowed / content_mismatch), `request_rejected`(http_413) |
| D09 | 경로 탐색·내부 파일 요청 13종(`../`, `.env`, `.git`, `logs/` 등) | 404, 설정·비밀 내용 없음 | `not_found`, `suspicious_input`(traversal) |
| D10 | 직원이 타인 급여·기밀·재무·관리자·타인 경비/결재 접근, 역할 변경·승인·삭제 시도 | 모두 403, 역할 불변 | `authz_deny`(out_of_scope / insufficient_role / not_party / not_approver / not_owner) |
| D11 | CSRF 위조 요청(토큰 없음·틀린 토큰) | 403, 세션 유지 | `csrf_fail` |
| D12 | 결재선 조작(본인·직원·중복·없는 결재자), 자기 승인, 사유 없는 반려 | 400 / 403 | `input_rejected`(approvers, reason), `authz_deny`(not_approver) |
| D13 | 변조·무작위 쿠키, 로그아웃·비밀번호 변경 뒤 이전 쿠키 재사용 | 모두 로그인으로 이동(이전 쿠키 무효) | `logout`, `password_changed` |
| D14 | 메서드 변조(PUT/DELETE/PATCH)·오류 화면 | 403/405, 오류 화면에 스택트레이스·버전 없음 | `csrf_fail`, `not_found` |
| D15 | 웹 스캔 흉내(흔한 경로 40개) | 모두 404 | `not_found`×40 |
| D16 | 로그인 연타, 챗봇 연타 | 429 | `rate_limited`(login_ip_limit / chat_user_limit) |
| D17 | 로그 자체 점검 | 모두 JSON·표준 필드, 필요한 이벤트 15종, 비밀번호·대화 내용 없음 | — |
| D18 | 정리 | 점검 데이터 전부 삭제, 건수 원상 | — |

최근 실행 결과: [검증결과_A_2026-10-17.md](검증결과_A_2026-10-17.md) (통과 18 · 실패 0).

## 4. 수집할 로그와 탐지 결과 (C와 맞춰야 할 부분)

**위치·형식:** `logs/security.jsonl`, 한 줄에 JSON 하나. 모든 이벤트의 공통 필드는 `ts, event_type, user, role, src_ip, method, path, decision, reason`이고 이벤트별 필드가 더 붙는다. 비밀번호·대화 내용·본문은 기록하지 않는다(`suspicious_input` 도 본문·대화·사유 필드는 종류만 남긴다).

| event_type | decision | reason / 추가 필드 |
|---|---|---|
| `login_success` / `logout` | ALLOW / INFO | — |
| `login_failure` | DENY | bad_password, unknown_user, invalid_format (`user`=시도한 아이디 64자) |
| `login_locked` / `account_locked` | DENY / BLOCK | account_locked / max_failures |
| `password_changed` / `password_change_failure` | ALLOW / DENY | 정책 위반 사유, bad_current_password |
| `rate_limited` / `request_rejected` | BLOCK | login_ip_limit, chat_user_limit / http_413, http_429 |
| `authz_deny` | DENY | not_logged_in, insufficient_role(`required`), out_of_scope(`resource`), not_owner, not_party, not_approver, not_your_turn(`step`), not_requester, approver_role_revoked, self_role_change |
| `csrf_fail` | BLOCK | csrf_token_invalid |
| `not_found` / `server_error` | INFO / ERROR | no_such_path / 예외 종류 |
| `input_rejected` | DENY | 검증 실패 사유, `field`(q, post, expense, approval, approvers, decision, reason, chat, role 등) |
| `suspicious_input` | WARN | `kind`(sqli, xss, traversal), `field`, `count`, `value`(80자, 본문·대화 제외). **차단하지 않고 신호만 남긴다** |
| `upload_reject` | BLOCK | extension_not_allowed, content_mismatch, empty_upload, `filename`, `size` |
| `confidential_access` | ALLOW | list / read, `resource`·`resource_id` |
| `admin_action` | ALLOW / DENY | role_change(`target`,`old`,`new`), unlock(`was_locked`), self_change, stale_form |
| `post_created/deleted`, `attachment_download`, `expense_created/submitted/invalid_transition`, `approval_created/decided/invalid_transition/withdrawn`, `chat_message`, `chat_reply`, `chat_responder_error` | INFO 등 | 업무 이력(식별자·글자 수) |

**C 룰 제안(최종 임계값은 C가 정함):** 브루트포스는 같은 `user` 5분 내 `login_failure` ≥ 5 또는 `account_locked` 1건, 웹 스캔은 같은 `src_ip` 1분 내 `not_found` ≥ 10, 인젝션·XSS·경로 탐색은 `suspicious_input` 1건 이상 경보·5분 내 ≥ 3건 고위험, 업로드는 10분 내 `upload_reject` ≥ 2, 권한 시도는 같은 `user` 5분 내 `authz_deny` ≥ 5, 과다 요청은 `rate_limited` 1건. 상관 룰 후보: `login_failure` 다수 뒤 같은 `user`의 `login_success`(계정 탈취 의심), 그 뒤 `authz_deny`·`confidential_access` 급증(권한 상승·조회).

## 5. 자동 대응(D)이 앱에서 성공했는지 확인하는 법

앱은 사용자·역할·잠금을 **요청마다 DB에서 다시 읽는다**. n8n이 아래를 바꾸면 해당 사용자의 다음 요청부터 반영된다.

| 대응 | 방법(앱 DB 계정이 수정 가능한 열만) | 확인 | 롤백 |
|---|---|---|---|
| 계정 잠금 | `UPDATE users SET locked_until = DATE_ADD(NOW(), INTERVAL 10 MINUTE) WHERE username='kim'` | kim 의 다음 요청이 로그인 화면으로, 로그인은 401 | `UPDATE users SET locked_until = NULL, failed_count = 0 WHERE username='kim'` 또는 관리자 화면 '잠금 해제' |
| 권한 회수 | `UPDATE users SET role='employee' WHERE username='lee'` | lee 가 재무·기밀 문서함·결재 처리에서 403 | 관리자 화면에서 역할 복구 |
| 강제 로그아웃 | `UPDATE users SET session_version = session_version + 1 WHERE username='kim'` | kim 의 기존 쿠키 전부 무효 | 다시 로그인 |

IP 차단(pfSense)과 티켓 생성은 B·D 범위이며, 앱은 `src_ip`를 기록한다(프록시 뒤에 두면 `X-Forwarded-For`를 신뢰하도록 따로 설정해야 한다).

## 6. 검증하지 못한 것과 한계 (숨기지 않고 적는다)

- **외부 도구 미사용:** sqlmap, ZAP, Burp, nmap, hydra 같은 도구는 내려받아 설치해야 해서 쓰지 않았다. 대신 직접 만든 탐침(SQLi 12종, XSS 5종, 경로 13종 등)을 썼고 이는 **대표 탐침이지 전수 검사가 아니다.** Kali의 도구로 같은 대상에 반복하는 것은 별도 확인 대상이다.
- 의존성 취약점 점검(`pip-audit` 등)은 하지 않았다(설치 필요). 푸시 전에 해 볼 수 있다.
- HTTPS·Secure 쿠키는 로컬 HTTP에서 검증하지 않았다(`COOKIE_SECURE=1` 은 TLS 종단 뒤에서 확인 필요).
- 속도 제한은 서버 프로세스 메모리 기반이라 다중 프로세스·재시작 시 공유·유지되지 않는다.
- 부하·가용성 시험, 로그 변조 방지·원격 전송, Wazuh·Graylog·n8n 연동 자체는 이 문서의 범위가 아니다.
- 챗봇의 실제 AI·Tool 호출은 연결 전이라 시험 응답으로만 검증했다(권한 우회 시나리오는 Gateway 연결 후 다시 한다).

## 7. C·D와 정할 것

1. 로그 필드·이벤트 이름이 C의 Graylog 입력 정의와 맞는지(맞지 않으면 앱 쪽을 바꾼다).
2. 4절의 임계값, 특히 `suspicious_input`을 즉시 경보로 쓸지.
3. `suspicious_input.value`(80자)를 그대로 수집해도 되는지(개인정보 우려가 있으면 `kind`만 쓰게 줄인다).
4. D의 자동 대응이 5절 방식(DB 열 수정)으로 앱과 맞물리는지.
