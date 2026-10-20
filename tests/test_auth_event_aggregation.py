"""R1/R6 인증 이벤트 집계 테스트. Docker MySQL(nexus_test)이 필요하다."""
from datetime import datetime, timedelta, timezone

from app import security
from support import PW, token


class FrozenDateTime(datetime):
    current = None

    @classmethod
    def now(cls, tz=None):
        value = cls.current
        if tz is not None:
            return value.astimezone(tz)
        return value.replace(tzinfo=None)


def post_login_at(client, at, username="zz_emp", password=PW, src_ip="203.0.113.10"):
    FrozenDateTime.current = at
    csrf = token(client)
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf},
        environ_overrides={"REMOTE_ADDR": src_ip},
    )


def r6_events(events):
    return [event for event in events() if event["event_type"] == "post_lock_retry_detected"]


def r1_events(events):
    return [event for event in events() if event["event_type"] == "account_compromise_suspected"]


def lock_user(client, events, monkeypatch, src_ip="203.0.113.10"):
    monkeypatch.setattr(security, "datetime", FrozenDateTime)
    start = datetime.now(timezone.utc).replace(microsecond=0)
    for offset in range(5):
        response = post_login_at(client, start + timedelta(seconds=offset), password="wrong-Password-1!", src_ip=src_ip)
        assert response.status_code == 401
    locked = [event for event in events() if event["event_type"] == "account_locked" and event["user"] == "zz_emp"]
    assert len(locked) == 1
    return start, locked[0]


def test_r6_emits_once_on_third_post_lock_attempt(aapp, events, monkeypatch):
    client = aapp.test_client()
    start, lock_event = lock_user(client, events, monkeypatch)

    for attempt in range(1, 4):
        response = post_login_at(client, start + timedelta(seconds=10 + attempt))
        assert response.status_code == 401
        assert len(r6_events(events)) == (1 if attempt == 3 else 0)

    for attempt in range(4, 6):
        response = post_login_at(client, start + timedelta(seconds=10 + attempt))
        assert response.status_code == 401

    derived = r6_events(events)
    assert len(derived) == 1
    assert derived[0]["count"] == 3
    assert derived[0]["window_seconds"] == 300
    assert derived[0]["reason"] == "post_lock_retry_threshold_reached"
    assert derived[0]["user"] == "zz_emp"
    assert derived[0]["src_ip"] == "203.0.113.10"
    assert derived[0]["lock_request_id"] == lock_event["request_id"]
    assert derived[0]["request_id"] != lock_event["request_id"]
    assert derived[0]["trigger_event_type"] == "login_locked"

    raw_failures = [
        event for event in events()
        if event["event_type"] == "login_failure" and event["user"] == "zz_emp"
    ]
    assert raw_failures[-1]["request_id"] == lock_event["request_id"]
    assert len([event for event in events() if event["event_type"] == "login_locked"]) == 5


def test_r6_ignores_other_users_and_source_ips(aapp, events, monkeypatch):
    client = aapp.test_client()
    start, _ = lock_user(client, events, monkeypatch)

    for offset in (10, 11):
        assert post_login_at(client, start + timedelta(seconds=offset)).status_code == 401
    assert post_login_at(
        client, start + timedelta(seconds=12), src_ip="203.0.113.11"
    ).status_code == 401
    assert post_login_at(
        client, start + timedelta(seconds=13), username="zz_mgr", password="wrong-Password-1!",
        src_ip="203.0.113.10",
    ).status_code == 401
    assert r6_events(events) == []

    assert post_login_at(client, start + timedelta(seconds=14)).status_code == 401
    assert len(r6_events(events)) == 1


def test_r6_ignores_attempts_after_300_seconds(aapp, events, monkeypatch):
    client = aapp.test_client()
    _, lock_event = lock_user(client, events, monkeypatch)
    locked_at = datetime.fromisoformat(lock_event["ts"])

    for offset in (301, 302, 303):
        assert post_login_at(client, locked_at + timedelta(seconds=offset)).status_code == 401
    assert r6_events(events) == []


def test_r6_accepts_third_attempt_at_exact_300_seconds_once(aapp, events, monkeypatch):
    client = aapp.test_client()
    _, lock_event = lock_user(client, events, monkeypatch)
    locked_at = datetime.fromisoformat(lock_event["ts"])

    for offset in (298, 299, 300):
        assert post_login_at(client, locked_at + timedelta(seconds=offset)).status_code == 401
        assert len(r6_events(events)) == (1 if offset == 300 else 0)

    assert post_login_at(client, locked_at + timedelta(seconds=300)).status_code == 401
    assert len(r6_events(events)) == 1


def test_r1_emits_after_three_failures_then_success_across_source_ips(aapp, events, monkeypatch):
    client = aapp.test_client()
    monkeypatch.setattr(security, "datetime", FrozenDateTime)
    start = datetime.now(timezone.utc).replace(microsecond=0)

    for offset, src_ip in enumerate(("203.0.113.10", "203.0.113.11", "203.0.113.12")):
        assert post_login_at(
            client, start + timedelta(seconds=offset), password="wrong-Password-1!", src_ip=src_ip
        ).status_code == 401
        assert r1_events(events) == []

    assert post_login_at(
        client, start + timedelta(seconds=3), password=PW, src_ip="203.0.113.13"
    ).status_code == 303

    derived = r1_events(events)
    assert len(derived) == 1
    assert derived[0]["user"] == "zz_emp"
    assert derived[0]["failed_attempts"] == 3
    assert derived[0]["window_seconds"] == 300
    assert derived[0]["reason"] == "login_success_after_failures"
    success = [event for event in events() if event["event_type"] == "login_success"][-1]
    assert derived[0]["request_id"] == success["request_id"]


def test_r1_does_not_emit_after_only_two_failures(aapp, events, monkeypatch):
    client = aapp.test_client()
    monkeypatch.setattr(security, "datetime", FrozenDateTime)
    start = datetime.now(timezone.utc).replace(microsecond=0)

    for offset in (0, 1):
        assert post_login_at(client, start + timedelta(seconds=offset), password="wrong-Password-1!").status_code == 401
    assert post_login_at(client, start + timedelta(seconds=2), password=PW).status_code == 303
    assert r1_events(events) == []


def test_r1_includes_failure_at_exact_300_seconds(aapp, events, monkeypatch):
    client = aapp.test_client()
    monkeypatch.setattr(security, "datetime", FrozenDateTime)
    start = datetime.now(timezone.utc).replace(microsecond=0)

    for offset in (0, 1, 2):
        assert post_login_at(client, start + timedelta(seconds=offset), password="wrong-Password-1!").status_code == 401
    assert post_login_at(client, start + timedelta(seconds=300), password=PW).status_code == 303
    assert len(r1_events(events)) == 1


def test_r1_excludes_failures_older_than_300_seconds(aapp, events, monkeypatch):
    client = aapp.test_client()
    monkeypatch.setattr(security, "datetime", FrozenDateTime)
    start = datetime.now(timezone.utc).replace(microsecond=0)

    for offset in (0, 1, 2):
        assert post_login_at(client, start + timedelta(seconds=offset), password="wrong-Password-1!").status_code == 401
    assert post_login_at(client, start + timedelta(seconds=303), password=PW).status_code == 303
    assert r1_events(events) == []


def test_r1_uses_original_account_locked_without_derived_duplicate(aapp, events, monkeypatch):
    client = aapp.test_client()
    lock_user(client, events, monkeypatch)

    assert len([event for event in events() if event["event_type"] == "account_locked"]) == 1
    assert r1_events(events) == []
