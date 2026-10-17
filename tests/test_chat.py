"""챗봇 화면·엔드포인트 통합 테스트. Docker MySQL(nexus_test) 필요, 접속 불가면 skip.
계정: zz_emp·zz_emp2(직원) / zz_mgr(팀장) / zz_adm(관리자)"""
import pytest

from support import as_user, post, sql, uid


def rows(root, name):
    return list(sql(root, "SELECT sender, content FROM chat_messages WHERE user_id=%s ORDER BY id", (uid(root, name),)))


def say(client, message="안녕하세요", **extra):
    return post(client, "/chat/messages", message=message, **extra)


def add_messages(root, name, count, prefix="zz_기록"):
    with root.cursor() as cur:
        for i in range(count):
            cur.execute("INSERT INTO chat_messages(user_id,sender,content) VALUES(%s,%s,%s)",
                        (uid(root, name), "user" if i % 2 == 0 else "assistant", f"{prefix}{i:03d}"))


def use_responder(app, fn):
    app.config["CHAT_RESPONDER"] = fn


# ---------- 로그인·CSRF ----------
def test_chat_requires_login(aapp):
    r = aapp.test_client().get("/chat")
    assert r.status_code == 303 and "/login" in r.headers["Location"]
    assert aapp.test_client().post("/chat/messages", data={"message": "x"}).status_code == 403   # CSRF 단계에서 차단


def test_send_needs_csrf_and_post(aapp, root):
    c = as_user(aapp, "zz_emp")
    assert c.post("/chat/messages", data={"message": "토큰 없음"}).status_code == 403
    assert c.get("/chat/messages").status_code == 405
    assert rows(root, "zz_emp") == []


# ---------- 대화와 기록 ----------
def test_send_stores_both_messages_for_the_current_user_and_shows_them(aapp, root, events):
    c = as_user(aapp, "zz_emp")
    r = say(c, "휴가 규정을 알려줘")
    assert r.status_code == 303 and r.headers["Location"].endswith("/chat")
    stored = rows(root, "zz_emp")
    assert [s for s, _ in stored] == ["user", "assistant"] and stored[0][1] == "휴가 규정을 알려줘"
    html = c.get("/chat").get_data(as_text=True)
    assert "휴가 규정을 알려줘" in html and "[시험 응답]" in html and "시험 응답이 표시됩니다" in html
    assert html.index("나</span>") < html.index("어시스턴트</span>")                   # 시간 순서
    ev = {e["event_type"]: e for e in events() if e["event_type"].startswith("chat_")}
    assert ev["chat_message"]["chars"] == len("휴가 규정을 알려줘") and ev["chat_reply"]["user"] == "zz_emp"


def test_empty_history_shows_a_starting_hint(aapp):
    assert "아직 대화가 없습니다" in as_user(aapp, "zz_emp").get("/chat").get_data(as_text=True)


def test_history_is_private_for_every_role(aapp, root):
    add_messages(root, "zz_emp", 2, "zz_직원기록")
    add_messages(root, "zz_emp2", 2, "zz_동료기록")
    add_messages(root, "zz_mgr", 2, "zz_팀장기록")
    add_messages(root, "zz_adm", 2, "zz_관리자기록")
    names = ("zz_직원기록", "zz_동료기록", "zz_팀장기록", "zz_관리자기록")
    for who, mine in (("zz_emp", "zz_직원기록"), ("zz_emp2", "zz_동료기록"), ("zz_mgr", "zz_팀장기록"), ("zz_adm", "zz_관리자기록")):
        html = as_user(aapp, who).get("/chat").get_data(as_text=True)
        assert mine in html and not any(n in html for n in names if n != mine), who   # 팀장·관리자도 남의 기록은 못 본다


def test_only_the_latest_fifty_messages_are_shown_in_order(aapp, root):
    add_messages(root, "zz_emp", 60)
    html = as_user(aapp, "zz_emp").get("/chat").get_data(as_text=True)
    assert html.count('class="msg msg-') == 50
    assert "zz_기록009" not in html and "zz_기록010" in html and "zz_기록059" in html
    assert html.index("zz_기록010") < html.index("zz_기록059")


def test_form_fields_cannot_spoof_user_or_sender(aapp, root):
    c = as_user(aapp, "zz_emp")
    say(c, "내 메시지", user_id=str(uid(root, "zz_emp2")), sender="assistant", id="1", created_at="2000-01-01")
    assert [s for s, _ in rows(root, "zz_emp")] == ["user", "assistant"]
    assert rows(root, "zz_emp2") == []


def test_sql_injection_text_is_stored_literally(aapp, root):
    evil = "'); DROP TABLE chat_messages; -- x' OR '1'='1"
    c = as_user(aapp, "zz_emp")
    say(c, evil)
    assert rows(root, "zz_emp")[0][1] == evil
    assert evil.replace("'", "&#39;") in c.get("/chat").get_data(as_text=True)


# ---------- 입력 검증 ----------
@pytest.mark.parametrize("message", [
    pytest.param("", id="empty"), pytest.param("   ", id="blank"), pytest.param("\n\t ", id="whitespace"),
    pytest.param("a" * 2001, id="2001-chars"), pytest.param("널\x00문자", id="nul"), pytest.param("제어\x07문자", id="bell"),
])
def test_invalid_messages_are_rejected_and_logged(aapp, root, events, message):
    r = say(as_user(aapp, "zz_emp"), message)
    assert r.status_code == 400 and "1~2,000자" in r.get_data(as_text=True)
    assert rows(root, "zz_emp") == []
    assert any(e["event_type"] == "input_rejected" and e["field"] == "chat" for e in events())


def test_boundary_length_and_multiline_are_accepted(aapp, root):
    c = as_user(aapp, "zz_emp")
    assert say(c, "a" * 2000).status_code == 303
    assert say(c, "첫 줄\n둘째 줄\t탭").status_code == 303
    assert rows(root, "zz_emp")[2][1] == "첫 줄\n둘째 줄\t탭"


# ---------- 출력 이스케이프 ----------
def test_user_text_and_reply_are_escaped(aapp, root):
    c = as_user(aapp, "zz_emp")
    say(c, "<script>alert(1)</script><img src=x onerror=alert(2)>")
    html = c.get("/chat").get_data(as_text=True)                       # 시험 응답은 입력을 그대로 되돌려 준다
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html and "&lt;img src=x onerror=alert(2)&gt;" in html
    assert "<script" not in html and "<img" not in html


def test_assistant_output_is_never_interpreted_as_html(aapp, root):
    use_responder(aapp, lambda user, message, history: '<a href="javascript:alert(1)">클릭</a><script>steal()</script>**굵게**')
    c = as_user(aapp, "zz_emp")
    say(c, "아무거나")
    html = c.get("/chat").get_data(as_text=True)
    assert "&lt;script&gt;steal()&lt;/script&gt;" in html and "&lt;a href=&#34;javascript:alert(1)&#34;&gt;" in html
    assert "<script" not in html and "<a href=\"javascript" not in html


# ---------- 응답기 접점 ----------
def test_responder_gets_the_current_user_and_only_own_history(aapp, root):
    add_messages(root, "zz_emp2", 4, "zz_남의기록")
    add_messages(root, "zz_emp", 2, "zz_내기록")
    seen = {}

    def responder(user, message, history):
        seen.update(user=user, message=message, history=history)
        return "확인"
    use_responder(aapp, responder)
    say(as_user(aapp, "zz_emp"), "새 질문", user_id=str(uid(root, "zz_adm")))
    assert (seen["user"]["username"], seen["user"]["role"], seen["user"]["dept"]) == ("zz_emp", "employee", "A팀")
    assert seen["user"]["id"] == uid(root, "zz_emp") and "password_hash" not in seen["user"]
    assert seen["message"] == "새 질문"
    assert [h["content"] for h in seen["history"]] == ["zz_내기록000", "zz_내기록001"]    # 본인 기록만, 이번 메시지는 제외
    assert all(set(h) == {"sender", "content"} for h in seen["history"])


def test_history_passed_to_the_responder_is_limited(aapp, root):
    add_messages(root, "zz_emp", 30)
    got = []
    use_responder(aapp, lambda user, message, history: got.append(history) or "ok")
    say(as_user(aapp, "zz_emp"), "질문")
    assert len(got[0]) == 10 and got[0][-1]["content"] == "zz_기록029"


def test_responder_exception_is_contained_and_not_leaked(aapp, root, events):
    def broken(user, message, history):
        raise RuntimeError("secret-internal-detail")
    use_responder(aapp, broken)
    c = as_user(aapp, "zz_emp")
    r = say(c, "질문")
    assert r.status_code == 303
    stored = rows(root, "zz_emp")
    assert stored[0] == ("user", "질문") and stored[1][0] == "assistant" and "답변을 만들지 못했습니다" in stored[1][1]
    assert "secret-internal-detail" not in c.get("/chat").get_data(as_text=True)
    ev = [e for e in events() if e["event_type"] == "chat_responder_error"][-1]
    assert ev["reason"] == "RuntimeError" and "secret-internal-detail" not in str(ev)
    assert c.get("/chat").status_code == 200                                              # 이후에도 정상 동작


def test_user_message_is_saved_before_the_responder_runs(aapp, root):
    before_reply = []

    def responder(user, message, history):
        before_reply.append(rows(root, "zz_emp"))
        return "ok"
    use_responder(aapp, responder)
    say(as_user(aapp, "zz_emp"), "먼저 저장")
    assert before_reply[0] == [("user", "먼저 저장")]                                      # 응답 생성 전에 이미 확정


@pytest.mark.parametrize("raw,expected", [
    pytest.param("가" * 20000, "가" * 8000, id="too-long"),             # 길이 제한
    pytest.param("앞\x00뒤\x07끝", "앞뒤끝", id="control-chars"),        # 제어문자 제거
    pytest.param("   ", "(빈 응답)", id="blank"),
    pytest.param("", "(빈 응답)", id="empty"),
    pytest.param(12345, "12345", id="not-a-string"),                   # 문자열이 아니어도 글자로 변환
])
def test_reply_is_normalised_before_storing(aapp, root, raw, expected):
    use_responder(aapp, lambda user, message, history: raw)
    say(as_user(aapp, "zz_emp"), "질문")
    assert rows(root, "zz_emp")[1][1] == expected


# ---------- 속도 제한 ----------
def test_per_user_rate_limit(aapp, root, events):
    aapp.config["CHAT_USER_LIMIT"] = 3
    emp, emp2 = as_user(aapp, "zz_emp"), as_user(aapp, "zz_emp2")
    assert [say(emp, f"메시지{i}").status_code for i in range(5)] == [303, 303, 303, 429, 429]
    assert len([r for r in rows(root, "zz_emp") if r[0] == "user"]) == 3                 # 제한된 요청은 저장·응답하지 않는다
    assert "너무 빠르게" in say(emp, "또").get_data(as_text=True)
    assert say(emp2, "다른 사람").status_code == 303                                       # 사용자별로 따로 센다
    assert any(e["event_type"] == "rate_limited" and e["reason"] == "chat_user_limit" and e["user"] == "zz_emp" for e in events())


# ---------- 로그에는 내용을 남기지 않는다 ----------
def test_security_log_has_lengths_but_not_message_text(aapp, root, app):
    say(as_user(aapp, "zz_emp"), "민감한-대화-내용-12345")
    log = app.log_path.read_text(encoding="utf-8")
    assert "민감한-대화-내용-12345" not in log and '"chars"' in log
