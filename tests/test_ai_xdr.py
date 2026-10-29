import json
from datetime import datetime, timezone

import pytest

from app import ai_xdr


def payload(alert_id="alert-1", rule_id="R8", src_ip="192.168.7.77", severity_location="rule"):
    event = {
        "event_type": "not_found",
        "src_ip": src_ip,
        "user": "scanner",
        "path": "/r8-test-1",
        "count": 4,
        "severity": "info",
        "message": "must not be retained",
        "prompt": "must not be retained",
    }
    rule = {"id": rule_id}
    if severity_location == "rule":
        rule["severity"] = "info"
    return {
        "schema_version": "1.1",
        "alert_id": alert_id,
        "rule_id": rule_id,
        "timestamp": "2026-10-26T01:00:00Z",
        "ticket_id": "NX-DB-000025",
        "rule": rule,
        "event": event,
        "message": "must not be retained",
    }


def test_normalize_accepts_rule_or_event_severity_and_only_keeps_allowlisted_fields():
    base = datetime(2026, 10, 26, 1, 2, tzinfo=timezone.utc)
    from_rule = ai_xdr.normalize_event_payload(payload(), received_at=base)
    from_event = ai_xdr.normalize_event_payload(
        payload(alert_id="alert-2", severity_location="event"), received_at=base
    )

    assert from_rule["severity"] == from_event["severity"] == "info"
    assert from_rule["event"]["path"] == "/r8-test-1"
    assert "message" not in from_rule["event"]
    assert "prompt" not in from_rule["event"]
    assert "message" not in from_rule
    assert from_rule["ticket_db_id"] == 25
    assert from_rule["window_key"] == from_event["window_key"]


def test_normalize_rejects_missing_identity_and_bad_timestamp():
    bad_identity = payload()
    bad_identity.pop("alert_id")
    with pytest.raises(ValueError):
        ai_xdr.normalize_event_payload(bad_identity)

    bad_time = payload()
    bad_time["timestamp"] = "not-a-date"
    with pytest.raises(ValueError):
        ai_xdr.normalize_event_payload(bad_time)


@pytest.mark.parametrize("ticket_id", ["NX-DB-000025", "external-ticket-25"])
def test_ingest_preserves_ticket_reference_outside_ai_event_payload(app, monkeypatch, ticket_id):
    from app import db

    writes = []
    monkeypatch.setattr(db, "execute_rowcount", lambda sql, params=(): writes.append((sql, params)) or 1)
    event = payload()
    event["ticket_id"] = ticket_id

    with app.app_context():
        ai_xdr.ingest_event(event)

    stored = json.loads(writes[0][1][12])
    assert stored["_ticket_id"] == ticket_id
    assert "ticket_id" not in stored


@pytest.mark.parametrize("external_ticket_id", ["NX-DB-000042", "external-ticket-42"])
def test_window_processor_returns_external_ticket_when_local_fk_is_stale(app, monkeypatch, external_ticket_id):
    from app import db, security

    now = datetime(2026, 10, 26, 11, 30, tzinfo=timezone.utc)
    window_key = "f" * 64
    rows = [{
        "alert_id": "alert-external-ticket", "window_key": window_key, "group_key": "ip:192.0.2.77",
        "incident_ticket_id": 42, "rule_id": "R1", "event_type": "account_compromise_suspected",
        "src_ip": "192.0.2.77", "user_name": "test-user", "severity": "medium", "event_count": 1,
        "occurred_at": now, "event_payload": json.dumps({
            "event_type": "account_compromise_suspected", "_ticket_id": external_ticket_id,
        }),
    }]
    queries = iter(([{"window_key": window_key, "window_start": now}], rows))
    monkeypatch.setattr(db, "query_all", lambda *_args, **_kwargs: next(queries))
    monkeypatch.setattr(db, "query_one", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(db, "execute_rowcount", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(security, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(security, "log_xdr_process_debug", lambda **_kwargs: None)
    monkeypatch.setattr(security, "block_ip", lambda *_args, **_kwargs: pytest.fail("R1 must not block"))
    def triage(summary, assessment_id):
        model_input = ai_xdr._model_input(summary, "x" * 32)
        assert "ticket_ids" not in model_input
        assert all("ticket_id" not in event for event in model_input["events"])
        return {"assessment_id": assessment_id, "threat_score": 85, "confidence": 0.9,
                "verdict": "MALICIOUS", "reasoning": "Synthetic metadata", "recommended_actions": ["review"]}

    monkeypatch.setattr(ai_xdr, "triage", triage)
    app.config.update({"XDR_AUTO_ENABLED": False, "XDR_RESPONSE_MODE": "dry-run"})

    with app.app_context():
        result = ai_xdr.process_ready_windows(now=now)

    assert result["processed"] == 1
    assessment = result["assessments"][0]
    assert assessment["incident_ticket_id"] is None
    assert assessment["ticket_ids"] == [external_ticket_id]


def test_different_ips_do_not_share_aggregation_window():
    now = datetime(2026, 10, 26, 1, 2, tzinfo=timezone.utc)
    first = ai_xdr.normalize_event_payload(payload(), received_at=now)
    second = ai_xdr.normalize_event_payload(
        payload(alert_id="alert-2", src_ip="192.168.7.78"), received_at=now
    )
    same_ip = ai_xdr.normalize_event_payload(payload(alert_id="alert-3"), received_at=now)

    assert first["window_key"] != second["window_key"]
    assert first["window_key"] == same_ip["window_key"]


def test_triage_window_is_bounded_and_invalid_setting_uses_default():
    assert ai_xdr._triage_window_seconds(-10) == 60
    assert ai_xdr._triage_window_seconds(3600) == 900
    assert ai_xdr._triage_window_seconds("invalid") == 180


def test_aggregate_events_keeps_counts_and_metadata_without_raw_content():
    rows = [
        {"alert_id": "a1", "rule_id": "R8", "event_type": "not_found", "src_ip": "192.168.7.77",
         "user_name": "scanner", "severity": "info", "event_count": 3,
         "occurred_at": "2026-10-26T01:00:00+00:00", "event_payload": '{"path":"/a","event_type":"not_found"}',
         "incident_ticket_id": 25},
        {"alert_id": "a2", "rule_id": "R5", "event_type": "login_failure", "src_ip": "192.168.7.77",
         "user_name": "scanner", "severity": "medium", "event_count": 1,
         "occurred_at": "2026-10-26T01:01:00+00:00", "event_payload": '{"event_type":"login_failure","decision":"DENY"}',
         "incident_ticket_id": 25},
    ]
    result = ai_xdr.aggregate_events(rows)

    assert result["event_count"] == 4
    assert result["rule_ids"] == ["R5", "R8"]
    assert result["ticket_db_ids"] == [25]
    assert all("message" not in event and "prompt" not in event for event in result["events"])


def test_ai_result_schema_rejects_malformed_range_verdict_and_action():
    valid = '{"assessment_id":"xdr-1","threat_score":85,"confidence":0.91,"verdict":"MALICIOUS","reasoning":"Repeated hostile metadata","recommended_actions":["block_ip"]}'
    assert ai_xdr.parse_model_result(valid, "xdr-1")["threat_score"] == 85

    for value in (
        "not json",
        valid.replace('"threat_score":85', '"threat_score":101'),
        valid.replace('"verdict":"MALICIOUS"', '"verdict":"EXECUTE"'),
        valid.replace('"block_ip"', '"shell_command"'),
        valid.replace('"assessment_id":"xdr-1"', '"assessment_id":"other"'),
    ):
        with pytest.raises(ValueError):
            ai_xdr.parse_model_result(value, "xdr-1")


def test_model_input_omits_identity_and_resource_values():
    summary = {
        "src_ip": "192.168.7.77", "users": ["alice"], "ticket_db_ids": [25],
        "rule_ids": ["R8"], "event_types": ["not_found"], "event_count": 4,
        "first_seen": "2026-10-26T01:00:00+00:00", "last_seen": "2026-10-26T01:02:00+00:00",
        "group_key": "ip:192.168.7.77", "window_key": "a" * 64,
        "events": [{"rule_id": "R8", "event_type": "not_found", "event": {
            "src_ip": "192.168.7.77", "user": "alice", "path": "/confidential/path",
            "resource_id": "secret-doc-id", "tool_name": "restricted_document_read",
            "decision": "DENY", "severity": "high", "count": 3, "message": "raw body",
        }}],
    }

    model_input = ai_xdr._model_input(summary, actor_secret="unit-test-correlation-key-0123456789")
    encoded = str(model_input)
    assert "192.168.7.77" not in encoded
    assert "alice" not in encoded
    assert "confidential/path" not in encoded
    assert "secret-doc-id" not in encoded
    assert "raw body" not in encoded
    assert model_input["rule_ids"] == ["R8"]
    assert model_input["events"][0]["event"]["tool_name"] == "restricted_document_read"
    assert model_input["same_source"] is True
    assert model_input["correlation_basis"] == "src_ip"
    assert model_input["actor_id"] != "192.168.7.77"


def test_model_actor_id_is_stable_pseudonymous_and_scoped():
    summary = {
        "src_ip": "192.168.7.77", "users": ["alice"], "ticket_db_ids": [25],
        "rule_ids": ["R8"], "event_types": ["not_found"], "event_count": 2,
        "first_seen": "2026-10-26T01:00:00+00:00", "last_seen": "2026-10-26T01:02:00+00:00",
        "group_key": "ip:192.168.7.77", "window_key": "a" * 64, "events": [],
    }
    first = ai_xdr._model_input(summary, actor_secret="unit-test-correlation-key-0123456789")
    same_actor = ai_xdr._model_input(summary, actor_secret="unit-test-correlation-key-0123456789")
    rotated_key = ai_xdr._model_input(summary, actor_secret="rotated-test-correlation-key-0123456789")
    next_window = dict(summary, window_key="b" * 64)
    next_window_actor = ai_xdr._model_input(next_window, actor_secret="unit-test-correlation-key-0123456789")

    assert first["actor_id"] == same_actor["actor_id"]
    assert first["actor_id"] != rotated_key["actor_id"]
    assert first["actor_id"] != next_window_actor["actor_id"]
    assert len(first["actor_id"]) == 32
    assert first["same_source"] is True
    assert first["correlation_basis"] == "src_ip"
    assert "192.168.7.77" not in str(first)


@pytest.mark.parametrize(
    "now, expected_phase",
    [
        (datetime(2026, 10, 26, 0, 30, tzinfo=timezone.utc), "day"),  # Monday 09:30 KST
        (datetime(2026, 10, 26, 11, 30, tzinfo=timezone.utc), "night"),  # Monday 20:30 KST
        (datetime(2026, 10, 24, 11, 30, tzinfo=timezone.utc), "weekend_approval"),
    ],
)
def test_policy_classifies_kst_day_night_and_weekend(now, expected_phase):
    result = ai_xdr.evaluate_policy(
        {"threat_score": 90, "confidence": 0.95, "verdict": "MALICIOUS", "recommended_actions": ["block_ip"]},
        {"rule_ids": ["R8"], "src_ip": "192.168.7.77", "last_seen": now.isoformat()},
        {"XDR_AUTO_ENABLED": True, "XDR_RESPONSE_MODE": "live", "XDR_AUTO_MIN_SCORE": 80,
         "XDR_AUTO_MIN_CONFIDENCE": 0.8, "XDR_MAX_EVENT_AGE_SECONDS": 300,
         "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval"},
        now=now,
    )
    assert result["phase"] == expected_phase
    assert result["auto_allowed"] is (expected_phase == "night")


@pytest.mark.parametrize(
    "reason,status,expected",
    [
        ("daytime_requires_approval", "PENDING", "DAYTIME_APPROVAL"),
        ("weekend_requires_approval", "PENDING", "WEEKEND_APPROVAL"),
        ("dry_run", "PENDING", "DRY_RUN"),
        ("auto_disabled", "PENDING", "AUTO_DISABLED"),
        ("score_below_threshold", "PENDING", "LOW_SCORE"),
        ("confidence_below_threshold", "PENDING", "LOW_CONFIDENCE"),
        ("confidence_threshold_unset", "PENDING", "CONFIDENCE_THRESHOLD_UNSET"),
        ("rule_not_allowed", "PENDING", "RULE_NOT_ALLOWED"),
        ("verdict_not_malicious", "PENDING", "VERDICT_NOT_MALICIOUS"),
        ("verdict_not_malicious", "NO_ACTION", "NO_ACTION"),
        ("policy_passed", "AUTO_EXECUTED", "POLICY_PASSED"),
    ],
)
def test_policy_reason_response_codes_preserve_gate_reason(reason, status, expected):
    fields = ai_xdr._policy_reason_fields({"reason": reason}, status)
    assert fields == {"policy_reason": expected, "policy_reason_detail": reason}


@pytest.mark.parametrize(
    "now,expected_reason,expected_code",
    [
        (datetime(2026, 10, 26, 0, 30, tzinfo=timezone.utc),
         "daytime_requires_approval", "DAYTIME_APPROVAL"),
        (datetime(2026, 10, 24, 11, 30, tzinfo=timezone.utc),
         "weekend_requires_approval", "WEEKEND_APPROVAL"),
    ],
)
def test_r1_approval_policy_is_separate_from_auto_response(now, expected_reason, expected_code):
    assessment = {"threat_score": 95, "confidence": 0.99, "verdict": "MALICIOUS", "recommended_actions": ["review"]}
    policy = ai_xdr.evaluate_policy(
        assessment,
        {"rule_ids": ["R1"], "src_ip": "192.0.2.80", "last_seen": now.isoformat()},
        {"XDR_AUTO_ENABLED": False, "XDR_RESPONSE_MODE": "dry-run", "XDR_AUTO_MIN_SCORE": 80,
         "XDR_AUTO_MIN_CONFIDENCE": 0.8, "XDR_MAX_EVENT_AGE_SECONDS": 300,
         "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval"},
        now=now,
    )

    assert policy["auto_allowed"] is False
    assert policy["approval_allowed"] is True
    assert policy["reason"] == expected_reason
    assert ai_xdr._assessment_status(assessment, policy) == "PENDING"
    assert ai_xdr._policy_reason_fields(policy, "PENDING")["policy_reason"] == expected_code


@pytest.mark.parametrize(
    "score,confidence,expected_reason",
    [(79, 0.99, "score_below_threshold"), (95, 0.79, "confidence_below_threshold")],
)
def test_r1_approval_requires_score_and_confidence(score, confidence, expected_reason):
    now = datetime(2026, 10, 26, 0, 30, tzinfo=timezone.utc)
    policy = ai_xdr.evaluate_policy(
        {"threat_score": score, "confidence": confidence, "verdict": "MALICIOUS", "recommended_actions": ["review"]},
        {"rule_ids": ["R1"], "src_ip": "192.0.2.80", "last_seen": now.isoformat()},
        {"XDR_AUTO_ENABLED": True, "XDR_RESPONSE_MODE": "live", "XDR_AUTO_MIN_SCORE": 80,
         "XDR_AUTO_MIN_CONFIDENCE": 0.8, "XDR_MAX_EVENT_AGE_SECONDS": 300,
         "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval"},
        now=now,
    )

    assert policy["auto_allowed"] is False
    assert policy["approval_allowed"] is False
    assert policy["reason"] == expected_reason


@pytest.mark.parametrize("confidence,expected", [(0.79, False), (0.80, True), (0.81, True)])
@pytest.mark.parametrize("rule_id", ["R5", "R6", "R8"])
def test_confidence_threshold_boundary_for_auto_rule_candidates(rule_id, confidence, expected):
    now = datetime(2026, 10, 26, 13, 0, tzinfo=timezone.utc)  # 22:00 KST
    result = ai_xdr.evaluate_policy(
        {"threat_score": 90, "confidence": confidence, "verdict": "MALICIOUS",
         "recommended_actions": ["block_ip"]},
        {"rule_ids": [rule_id], "src_ip": "203.0.113.55", "last_seen": now.isoformat()},
        {"XDR_AUTO_ENABLED": True, "XDR_RESPONSE_MODE": "live", "XDR_AUTO_MIN_SCORE": 80,
         "XDR_AUTO_MIN_CONFIDENCE": 0.80, "XDR_MAX_EVENT_AGE_SECONDS": 300,
         "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval"},
        now=now,
    )

    assert result["auto_candidate"] is expected
    assert result["auto_allowed"] is expected


@pytest.mark.parametrize(
    "recommended_actions",
    [["review"], ["block_ip"], ["notify_only"], ["block_ip", "notify_only"],
     ["review", "block_ip", "notify_only"]],
)
def test_r1_supported_recommendations_allow_approval_without_auto_execution(recommended_actions):
    now = datetime(2026, 10, 26, 0, 30, tzinfo=timezone.utc)
    assessment = {"threat_score": 80, "confidence": 0.85, "verdict": "MALICIOUS",
                  "recommended_actions": list(recommended_actions)}
    policy = ai_xdr.evaluate_policy(
        assessment,
        {"rule_ids": ["R1"], "src_ip": "192.0.2.80", "last_seen": now.isoformat()},
        {"XDR_AUTO_ENABLED": True, "XDR_RESPONSE_MODE": "live", "XDR_AUTO_MIN_SCORE": 80,
         "XDR_AUTO_MIN_CONFIDENCE": 0.80, "XDR_MAX_EVENT_AGE_SECONDS": 300,
         "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval"},
        now=now,
    )

    assert policy["approval_allowed"] is True
    assert policy["auto_allowed"] is False
    assert policy["reason"] == "daytime_requires_approval"
    assert assessment["recommended_actions"] == recommended_actions
    assert ai_xdr._assessment_status(assessment, policy, rule_ids=["R1"]) == "PENDING"


@pytest.mark.parametrize("score,confidence", [(79, 0.85), (80, 0.79)])
def test_r1_below_threshold_is_not_left_pending(score, confidence):
    now = datetime(2026, 10, 26, 0, 30, tzinfo=timezone.utc)
    assessment = {"threat_score": score, "confidence": confidence, "verdict": "MALICIOUS",
                  "recommended_actions": ["block_ip"]}
    policy = ai_xdr.evaluate_policy(
        assessment,
        {"rule_ids": ["R1"], "src_ip": "192.0.2.80", "last_seen": now.isoformat()},
        {"XDR_AUTO_ENABLED": True, "XDR_RESPONSE_MODE": "live", "XDR_AUTO_MIN_SCORE": 80,
         "XDR_AUTO_MIN_CONFIDENCE": 0.80, "XDR_MAX_EVENT_AGE_SECONDS": 300,
         "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval"},
        now=now,
    )

    assert policy["approval_allowed"] is False
    assert policy["auto_allowed"] is False
    assert ai_xdr._assessment_status(assessment, policy, rule_ids=["R1"]) == "NO_ACTION"


@pytest.mark.parametrize("confidence,expected_approval", [(0.79, False), (0.80, True), (0.81, True)])
def test_r1_confidence_gate_allows_approval_only_never_auto_lock(confidence, expected_approval):
    now = datetime(2026, 10, 26, 0, 30, tzinfo=timezone.utc)  # 09:30 KST
    result = ai_xdr.evaluate_policy(
        {"threat_score": 95, "confidence": confidence, "verdict": "MALICIOUS",
         "recommended_actions": ["review"]},
        {"rule_ids": ["R1"], "src_ip": "192.0.2.80", "last_seen": now.isoformat()},
        {"XDR_AUTO_ENABLED": True, "XDR_RESPONSE_MODE": "live", "XDR_AUTO_MIN_SCORE": 80,
         "XDR_AUTO_MIN_CONFIDENCE": 0.80, "XDR_MAX_EVENT_AGE_SECONDS": 300,
         "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval"},
        now=now,
    )

    assert result["auto_allowed"] is False
    assert result["approval_allowed"] is expected_approval
    assert result["reason"] == ("daytime_requires_approval" if expected_approval else "confidence_below_threshold")


@pytest.mark.parametrize("rule_id", ["R2", "R3", "R4", "R7", "R9", "R10", "R11", "R12"])
def test_confidence_threshold_does_not_expand_rule_allowlist(rule_id):
    now = datetime(2026, 10, 26, 13, 0, tzinfo=timezone.utc)
    result = ai_xdr.evaluate_policy(
        {"threat_score": 99, "confidence": 0.99, "verdict": "MALICIOUS",
         "recommended_actions": ["block_ip"]},
        {"rule_ids": [rule_id], "src_ip": "203.0.113.55", "last_seen": now.isoformat()},
        {"XDR_AUTO_ENABLED": True, "XDR_RESPONSE_MODE": "live", "XDR_AUTO_MIN_SCORE": 80,
         "XDR_AUTO_MIN_CONFIDENCE": 0.80, "XDR_MAX_EVENT_AGE_SECONDS": 300,
         "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval"},
        now=now,
    )

    assert result["auto_allowed"] is False
    assert result["approval_allowed"] is False
    assert result["reason"] == "rule_not_allowed"


def test_night_policy_exposes_dry_run_candidate_without_allowing_execution():
    now = datetime(2026, 10, 26, 11, 30, tzinfo=timezone.utc)
    result = ai_xdr.evaluate_policy(
        {"threat_score": 91, "confidence": 0.95, "verdict": "MALICIOUS", "recommended_actions": ["block_ip"]},
        {"rule_ids": ["R5", "R8"], "src_ip": "203.0.113.55", "last_seen": now.isoformat()},
        {"XDR_AUTO_ENABLED": True, "XDR_RESPONSE_MODE": "dry-run", "XDR_AUTO_MIN_SCORE": 80,
         "XDR_AUTO_MIN_CONFIDENCE": 0.8, "XDR_MAX_EVENT_AGE_SECONDS": 300,
         "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval"},
        now=now,
    )

    assert result["auto_candidate"] is True
    assert result["auto_allowed"] is False
    assert result["reason"] == "dry_run"


@pytest.mark.parametrize(
    "now,rule_ids,src_ip,score,expected_reason",
    [
        (datetime(2026, 10, 26, 0, 30, tzinfo=timezone.utc), ["R8"], "203.0.113.55", 65,
         "daytime_requires_approval"),
        (datetime(2026, 10, 26, 11, 30, tzinfo=timezone.utc), ["R5"], "192.168.3.10", 95,
         "whitelisted_ip"),
    ],
)
def test_daytime_low_score_and_whitelist_are_not_auto_candidates(now, rule_ids, src_ip, score, expected_reason):
    result = ai_xdr.evaluate_policy(
        {"threat_score": score, "confidence": 0.95, "verdict": "MALICIOUS", "recommended_actions": ["block_ip"]},
        {"rule_ids": rule_ids, "src_ip": src_ip, "last_seen": now.isoformat()},
        {"XDR_AUTO_ENABLED": True, "XDR_RESPONSE_MODE": "live", "XDR_AUTO_MIN_SCORE": 80,
         "XDR_AUTO_MIN_CONFIDENCE": 0.8, "XDR_MAX_EVENT_AGE_SECONDS": 300,
         "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval"},
        now=now,
    )

    assert result["auto_candidate"] is False
    assert result["auto_allowed"] is False
    assert result["reason"] == expected_reason


def test_stale_event_is_not_an_auto_candidate():
    now = datetime(2026, 10, 26, 11, 30, tzinfo=timezone.utc)
    result = ai_xdr.evaluate_policy(
        {"threat_score": 95, "confidence": 0.99, "verdict": "MALICIOUS", "recommended_actions": ["block_ip"]},
        {"rule_ids": ["R8"], "src_ip": "203.0.113.55", "last_seen": "2026-10-26T10:00:00Z"},
        {"XDR_AUTO_ENABLED": True, "XDR_RESPONSE_MODE": "dry-run", "XDR_AUTO_MIN_SCORE": 80,
         "XDR_AUTO_MIN_CONFIDENCE": 0.8, "XDR_MAX_EVENT_AGE_SECONDS": 300,
         "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval"},
        now=now,
    )

    assert result["auto_candidate"] is False
    assert result["reason"] == "stale_event"


def test_admin_xdr_page_marks_dry_run_auto_candidate(app):
    from flask import render_template

    assessment = {
        "assessment_id": "assessment-test", "last_seen_kst": "2026-10-26 20:30:00 KST",
        "src_ip": "203.0.113.55", "user_names": [], "rule_ids": ["R5", "R8"],
        "event_types": ["login_failure", "not_found"], "event_count": 4, "verdict": "MALICIOUS",
        "threat_score": 91, "confidence": 0.95, "reasoning": "metadata only", "status": "PENDING",
        "policy_mode": "night", "policy_reason": "dry_run", "recommended_actions": ["block_ip"],
        "incident_ticket_id": None, "ticket_ids": ["NX-DB-000025"],
        "response_result": {"blocked": False, "auto_candidate": True},
    }
    with app.test_request_context("/admin/xdr"):
        html = render_template("admin_xdr.html", xdr_enabled=True, unavailable=False, result=None,
                               assessments=[assessment], csrf_token=lambda: "test-csrf")

    assert "자동 차단 후보" in html
    assert "NX-DB-000025" in html
    assert "연결 없음" not in html


def test_list_assessments_returns_external_ticket_ids_without_local_fk(app, monkeypatch):
    from app import db

    row = {
        "assessment_id": "assessment-test", "incident_ticket_id": None,
        "ticket_ids": '["NX-DB-000066"]', "user_names": "[]", "rule_ids": '["R1"]',
        "event_types": '["account_compromise_suspected"]', "recommended_actions": '["review"]',
        "response_result": '{"reason":"dry_run"}', "first_seen": None, "last_seen": None,
    }
    monkeypatch.setattr(db, "query_all", lambda *_args, **_kwargs: [dict(row)])

    with app.app_context():
        assessments = ai_xdr.list_assessments()

    assert assessments[0]["incident_ticket_id"] is None
    assert assessments[0]["ticket_ids"] == ["NX-DB-000066"]


@pytest.mark.parametrize(
    "rule_ids,src_ip,extra,expected",
    [
        (["R8"], "192.168.7.77", {}, True),
        (["R3"], "192.168.7.77", {}, False),
        (["R8"], "192.168.3.10", {}, False),
        (["R8"], "not-an-ip", {}, False),
        (["R8"], "192.168.7.77", {"XDR_AUTO_MIN_CONFIDENCE": None}, False),
        (["R8"], "192.168.7.77", {"XDR_RESPONSE_MODE": "dry-run"}, False),
    ],
)
def test_policy_fails_closed_for_rule_whitelist_ip_and_unset_or_dry_run(rule_ids, src_ip, extra, expected):
    now = datetime(2026, 10, 26, 11, 30, tzinfo=timezone.utc)
    cfg = {"XDR_AUTO_ENABLED": True, "XDR_RESPONSE_MODE": "live", "XDR_AUTO_MIN_SCORE": 80,
           "XDR_AUTO_MIN_CONFIDENCE": 0.8, "XDR_MAX_EVENT_AGE_SECONDS": 300,
           "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval"}
    cfg.update(extra)
    result = ai_xdr.evaluate_policy(
        {"threat_score": 90, "confidence": 0.95, "verdict": "MALICIOUS", "recommended_actions": ["block_ip"]},
        {"rule_ids": rule_ids, "src_ip": src_ip, "last_seen": now.isoformat()}, cfg, now=now
    )
    assert result["auto_allowed"] is expected


@pytest.mark.parametrize(
    "config_override",
    [
        {"XDR_DAY_START_HOUR": 22, "XDR_DAY_END_HOUR": 8, "XDR_WEEKEND_MODE": "night_auto"},
        {"XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 8},
        {"XDR_AUTO_MIN_SCORE": -1},
        {"XDR_AUTO_MIN_SCORE": 101},
    ],
)
def test_invalid_auto_policy_settings_fail_closed(config_override):
    now = datetime(2026, 10, 26, 11, 30, tzinfo=timezone.utc)
    config = {"XDR_AUTO_ENABLED": True, "XDR_RESPONSE_MODE": "live", "XDR_AUTO_MIN_SCORE": 80,
              "XDR_AUTO_MIN_CONFIDENCE": 0.8, "XDR_MAX_EVENT_AGE_SECONDS": 300,
              "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval"}
    config.update(config_override)
    result = ai_xdr.evaluate_policy(
        {"threat_score": 90, "confidence": 0.95, "verdict": "MALICIOUS", "recommended_actions": ["block_ip"]},
        {"rule_ids": ["R8"], "src_ip": "192.168.7.77", "last_seen": now.isoformat()}, config, now=now,
    )
    assert result["auto_allowed"] is False


def test_invalid_ai_output_has_review_required_fail_safe():
    result = ai_xdr.fail_safe_result("xdr-1")
    assert result["assessment_id"] == "xdr-1"
    assert result["verdict"] == "REVIEW_REQUIRED"
    assert result["threat_score"] == 0
    assert result["confidence"] == 0
    assert result["recommended_actions"] == []
    assert ai_xdr._assessment_status(result, {"auto_candidate": False}) == "NO_ACTION"


def test_model_timeout_and_malformed_response_fail_closed(monkeypatch):
    monkeypatch.setattr(ai_xdr, "_model_response", lambda *_: (_ for _ in ()).throw(TimeoutError()))
    assert ai_xdr.triage({}, "xdr-timeout")["verdict"] == "REVIEW_REQUIRED"
    monkeypatch.setattr(ai_xdr, "_model_response", lambda *_: "not json")
    assert ai_xdr.triage({}, "xdr-malformed")["recommended_actions"] == []


@pytest.mark.parametrize("rule_id", [f"R{i}" for i in range(1, 13)])
def test_window_processor_reuses_block_ip_only_for_allowed_rules(app, monkeypatch, rule_id, events):
    from app import db, security

    now = datetime(2026, 10, 26, 11, 30, tzinfo=timezone.utc)
    window_key = "a" * 64
    rows = [{
        "alert_id": "alert-processor", "window_key": window_key, "group_key": "ip:192.168.7.77",
        "incident_ticket_id": 25, "rule_id": rule_id, "event_type": "test_event",
        "src_ip": "192.168.7.77", "user_name": "scanner", "severity": "high", "event_count": 1,
        "occurred_at": now, "event_payload": '{"event_type":"test_event","decision":"DENY"}',
    }]
    queries = iter(([{"window_key": window_key, "window_start": now}], rows))
    writes = []
    blocked = []
    monkeypatch.setattr(db, "query_all", lambda *_args, **_kwargs: next(queries))
    monkeypatch.setattr(db, "query_one", lambda _sql, params=(), **_kwargs: {"id": params[0]})
    monkeypatch.setattr(db, "execute_rowcount", lambda sql, params=(): writes.append((sql, params)) or 1)
    monkeypatch.setattr(security, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(security, "block_ip", lambda *args, **kwargs: blocked.append((args, kwargs)) or True)
    monkeypatch.setattr(ai_xdr, "triage", lambda *_args: {
        "assessment_id": "ignored", "threat_score": 95, "confidence": 0.99,
        "verdict": "MALICIOUS", "reasoning": "Repeated malicious activity",
        "recommended_actions": ["review"] if rule_id == "R1" else ["block_ip"],
    })
    app.config.update({
        "XDR_TRIAGE_WINDOW_SECONDS": 180, "XDR_AUTO_ENABLED": True, "XDR_RESPONSE_MODE": "live",
        "XDR_AUTO_MIN_SCORE": 80, "XDR_AUTO_MIN_CONFIDENCE": 0.8, "XDR_MAX_EVENT_AGE_SECONDS": 300,
        "XDR_DAY_START_HOUR": 8, "XDR_DAY_END_HOUR": 20, "XDR_WEEKEND_MODE": "approval",
    })

    with app.app_context():
        result = ai_xdr.process_ready_windows(now=now)

    assert result["processed"] == 1
    debug = next(event for event in events() if event["event_type"] == "xdr_process_debug")
    assert debug["selected_window_key"] == window_key
    assert debug["selected_window_start"] == "2026-10-26 11:30:00+00:00"
    assert debug["event_rows_count"] == 1
    assert debug["assessment_insert_affected_rows"] == 1
    assert "reason" not in debug
    assessment_update = next((sql, params) for sql, params in writes
                             if sql.startswith("UPDATE security_xdr_assessments SET"))
    assert "auto_allowed = %s" in assessment_update[0]
    assert "approval_allowed = %s" in assessment_update[0]
    assert bool(blocked) is (rule_id in {"R5", "R6", "R8"})
    assert len(writes) == 3
    assessment = result["assessments"][0]
    assert assessment["incident_ticket_id"] == 25
    assert assessment["ticket_ids"] == ["NX-DB-000025"]
    assert assessment["rule_ids"] == [rule_id]
    assert assessment["threat_score"] == 95
    assert assessment["confidence"] == 0.99
    expected_action = ["review"] if rule_id == "R1" else ["block_ip"]
    assert assessment["recommended_actions"] == expected_action
    assert assessment["auto_allowed"] is (rule_id in {"R5", "R6", "R8"})
    assert assessment["approval_allowed"] is (rule_id == "R1")
    assert assessment_update[1][7:9] == (assessment["auto_allowed"], assessment["approval_allowed"])
    if rule_id == "R1":
        assert assessment["status"] == "PENDING"
    expected_reason = "R1_APPROVAL_REQUIRED" if rule_id == "R1" else (
        "POLICY_PASSED" if rule_id in {"R5", "R6", "R8"} else "RULE_NOT_ALLOWED"
    )
    assert assessment["policy_reason"] == expected_reason
    assert assessment["policy_reason_detail"] == expected_reason.lower()
    assert not {"src_ip", "user_names", "reasoning"} & assessment.keys()


@pytest.mark.parametrize(
    "event_ticket_id, existing_ticket_ids, expected_ticket_id, expected_ticket_ids",
    [
        (25, {25}, 25, ["NX-DB-000025"]),
        (None, set(), None, []),
        (42, set(), None, []),
    ],
)
def test_window_processor_only_keeps_valid_ticket_foreign_keys(
    app, monkeypatch, event_ticket_id, existing_ticket_ids, expected_ticket_id, expected_ticket_ids
):
    from app import db, security

    now = datetime(2026, 10, 26, 11, 30, tzinfo=timezone.utc)
    window_key = "e" * 64
    rows = [{
        "alert_id": "alert-ticket-fk", "window_key": window_key, "group_key": "ip:192.0.2.77",
        "incident_ticket_id": event_ticket_id, "rule_id": "R1", "event_type": "account_locked",
        "src_ip": "192.0.2.77", "user_name": "test-user", "severity": "medium", "event_count": 1,
        "occurred_at": now, "event_payload": "{\"event_type\":\"account_locked\"}",
    }]
    queries = iter(([{"window_key": window_key, "window_start": now}], rows))
    writes = []
    monkeypatch.setattr(db, "query_all", lambda *_args, **_kwargs: next(queries))
    monkeypatch.setattr(db, "query_one", lambda _sql, params=(), **_kwargs: ({"id": params[0]} if params[0] in existing_ticket_ids else None))
    monkeypatch.setattr(db, "execute_rowcount", lambda sql, params=(): writes.append((sql, params)) or 1)
    monkeypatch.setattr(security, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(security, "block_ip", lambda *_args, **_kwargs: pytest.fail("R1 must not block"))
    monkeypatch.setattr(ai_xdr, "triage", lambda _summary, assessment_id: {
        "assessment_id": assessment_id, "threat_score": 70, "confidence": 0.9,
        "verdict": "REVIEW_REQUIRED", "reasoning": "Synthetic metadata", "recommended_actions": ["review"],
    })
    app.config.update({"XDR_AUTO_ENABLED": False, "XDR_RESPONSE_MODE": "dry-run"})

    with app.app_context():
        result = ai_xdr.process_ready_windows(now=now)

    assert result["processed"] == 1
    assessment = result["assessments"][0]
    assert assessment["incident_ticket_id"] == expected_ticket_id
    assert assessment["ticket_ids"] == expected_ticket_ids
    assert writes[0][1][3] == expected_ticket_id
    assert json.loads(writes[0][1][11])["ticket_db_ids"] == ([expected_ticket_id] if expected_ticket_id else [])


def test_window_processor_returns_all_ticket_correlations(app, monkeypatch):
    from app import db, security

    now = datetime(2026, 10, 26, 11, 30, tzinfo=timezone.utc)
    window_key = "c" * 64
    rows = [
        {"alert_id": "alert-ticket-25", "window_key": window_key, "group_key": "ip:192.0.2.77",
         "incident_ticket_id": 25, "rule_id": "R1", "event_type": "account_locked",
         "src_ip": "192.0.2.77", "user_name": "test-user", "severity": "medium", "event_count": 1,
         "occurred_at": now, "event_payload": "{\"event_type\":\"account_locked\"}"},
        {"alert_id": "alert-ticket-26", "window_key": window_key, "group_key": "ip:192.0.2.77",
         "incident_ticket_id": 26, "rule_id": "R2", "event_type": "prompt_injection_detected",
         "src_ip": "192.0.2.77", "user_name": "test-user", "severity": "high", "event_count": 1,
         "occurred_at": now, "event_payload": "{\"event_type\":\"prompt_injection_detected\"}"},
    ]
    queries = iter(([{"window_key": window_key, "window_start": now}], rows))
    monkeypatch.setattr(db, "query_all", lambda *_args, **_kwargs: next(queries))
    monkeypatch.setattr(db, "query_one", lambda _sql, params=(), **_kwargs: {"id": params[0]})
    monkeypatch.setattr(db, "execute_rowcount", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(security, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ai_xdr, "triage", lambda _summary, assessment_id: {
        "assessment_id": assessment_id, "threat_score": 72, "confidence": 0.88,
        "verdict": "SUSPICIOUS", "reasoning": "Synthetic test", "recommended_actions": ["review"],
    })
    app.config.update({"XDR_AUTO_ENABLED": False, "XDR_RESPONSE_MODE": "dry-run"})

    with app.app_context():
        result = ai_xdr.process_ready_windows(now=now)

    assessment = result["assessments"][0]
    assert assessment["incident_ticket_id"] is None
    assert assessment["ticket_ids"] == ["NX-DB-000025", "NX-DB-000026"]
    assert assessment["rule_ids"] == ["R1", "R2"]


def test_window_processor_deduplicates_reserved_window_before_model_call(app, monkeypatch, events):
    from app import db

    now = datetime(2026, 10, 26, 11, 30, tzinfo=timezone.utc)
    window_key = "b" * 64
    rows = [{
        "alert_id": "alert-reserved", "window_key": window_key, "group_key": "ip:192.168.7.77",
        "incident_ticket_id": 25, "rule_id": "R8", "event_type": "not_found", "src_ip": "192.168.7.77",
        "user_name": "scanner", "severity": "info", "event_count": 1, "occurred_at": now,
        "event_payload": '{"event_type":"not_found"}',
    }]
    queries = iter(([{"window_key": window_key, "window_start": now}], rows))
    monkeypatch.setattr(db, "query_all", lambda *_args, **_kwargs: next(queries))
    monkeypatch.setattr(db, "query_one", lambda _sql, params=(), **_kwargs: {"id": params[0]})
    monkeypatch.setattr(db, "execute_rowcount", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(ai_xdr, "triage", lambda *_args: pytest.fail("reserved window must not call AI"))

    with app.app_context():
        result = ai_xdr.process_ready_windows(now=now)

    assert result == {"processed": 0, "assessments": []}
    debug = next(event for event in events() if event["event_type"] == "xdr_process_debug")
    assert debug["selected_window_key"] == window_key
    assert debug["event_rows_count"] == 1
    assert debug["assessment_insert_affected_rows"] == 0
    assert debug["reason"] == "assessment_insert_ignored"


def test_window_processor_logs_no_ready_window(app, monkeypatch, events):
    from app import db

    monkeypatch.setattr(db, "query_all", lambda *_args, **_kwargs: [])
    with app.app_context():
        result = ai_xdr.process_ready_windows()

    assert result == {"processed": 0, "assessments": []}
    debug = next(event for event in events() if event["event_type"] == "xdr_process_debug")
    assert debug["selected_window_key"] == "none"
    assert debug["selected_window_start"] == "none"
    assert debug["event_rows_count"] == 0
    assert debug["assessment_insert_affected_rows"] == "not_attempted"
    assert debug["reason"] == "no_ready_window"


def test_window_processor_logs_empty_window_events(app, monkeypatch, events):
    from app import db

    now = datetime(2026, 10, 26, 11, 30, tzinfo=timezone.utc)
    window_key = "d" * 64
    queries = iter(([{"window_key": window_key, "window_start": now}], []))
    monkeypatch.setattr(db, "query_all", lambda *_args, **_kwargs: next(queries))
    monkeypatch.setattr(db, "execute_rowcount", lambda *_args, **_kwargs: pytest.fail("empty window must not be inserted"))

    with app.app_context():
        result = ai_xdr.process_ready_windows(now=now)

    assert result == {"processed": 0, "assessments": []}
    debug = next(event for event in events() if event["event_type"] == "xdr_process_debug")
    assert debug["selected_window_key"] == window_key
    assert debug["selected_window_start"] == "2026-10-26 11:30:00+00:00"
    assert debug["event_rows_count"] == 0
    assert debug["assessment_insert_affected_rows"] == "not_attempted"
    assert debug["reason"] == "empty_window_events"


def test_assessment_approval_in_dry_run_records_decision_without_blocking(app, monkeypatch):
    from app import db, security

    now = datetime(2026, 10, 26, 1, 30, tzinfo=timezone.utc)
    row = {
        "assessment_id": "assessment-1", "incident_ticket_id": 25, "src_ip": "192.168.7.77",
        "rule_ids": '["R8"]', "user_names": '["scanner"]', "event_count": 3,
        "last_seen": now.isoformat(), "verdict": "MALICIOUS", "threat_score": 90, "confidence": 0.95,
        "reasoning": "Repeated scan metadata", "recommended_actions": '["block_ip"]',
        "event_summary": json.dumps({"rule_ids": ["R8"], "src_ip": "192.168.7.77", "last_seen": now.isoformat()}),
        "status": "PENDING",
    }
    writes = []
    blocks = []
    monkeypatch.setattr(db, "query_one", lambda *_args, **_kwargs: row)
    monkeypatch.setattr(db, "execute_rowcount", lambda sql, params=(): writes.append((sql, params)) or 1)
    monkeypatch.setattr(security, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(security, "block_ip", lambda *args, **kwargs: blocks.append((args, kwargs)) or True)
    app.config.update({"XDR_RESPONSE_MODE": "dry-run", "XDR_MAX_EVENT_AGE_SECONDS": 300})

    with app.app_context():
        result = ai_xdr.decide_assessment("assessment-1", "APPROVED", 7, "admin", now=now)

    assert result["status"] == "APPROVED"
    assert result["response"]["reason"] == "dry_run"
    assert blocks == []
    assert len(writes) == 1
    assert writes[0][1][0] == "APPROVED"


def _block_approval_row(**overrides):
    row = {
        "assessment_id": "assessment-block-1", "incident_ticket_id": None,
        "src_ip": "198.51.100.77", "rule_ids": '["R1"]', "user_names": '["testuser"]',
        "event_count": 1, "last_seen": "2026-10-26T01:30:00+00:00",
        "verdict": "MALICIOUS", "threat_score": 90, "confidence": 0.95,
        "reasoning": "synthetic metadata", "recommended_actions": '["block_ip"]',
        "event_summary": json.dumps({"rule_ids": ["R1"], "src_ip": "198.51.100.77",
                                      "last_seen": "2026-10-26T01:30:00+00:00",
                                      "ticket_ids": ["NX-DB-000046"]}),
        "status": "PENDING", "approval_allowed": 1, "auto_allowed": 0,
        "policy_reason": "DAYTIME_APPROVAL", "response_result": None,
    }
    row.update(overrides)
    return row


def test_explicit_block_approval_dry_run_records_without_registering_ip(app, monkeypatch):
    from app import db, security

    now = datetime(2026, 10, 26, 1, 30, tzinfo=timezone.utc)
    row = _block_approval_row()
    writes, blocks = [], []
    monkeypatch.setattr(db, "query_one", lambda *_args, **_kwargs: row)
    monkeypatch.setattr(db, "execute_rowcount", lambda sql, params=(): writes.append((sql, params)) or 1)
    monkeypatch.setattr(security, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(security, "block_ip", lambda *args, **kwargs: blocks.append((args, kwargs)) or True)
    app.config.update({"XDR_RESPONSE_MODE": "dry-run", "XDR_IP_BLOCK_ENABLED": False,
                       "XDR_AUTO_MIN_SCORE": 80, "XDR_AUTO_MIN_CONFIDENCE": 0.8})

    with app.app_context():
        result = ai_xdr.decide_assessment("assessment-block-1", "APPROVED", 7, "admin", now=now,
                                          approved_action="block_ip")

    assert result["status"] == "APPROVED"
    assert result["response"]["reason"] == "dry_run"
    assert blocks == []
    assert len(writes) == 1


def test_explicit_block_approval_live_uses_existing_block_ip_with_trace(app, monkeypatch):
    from app import db, security

    now = datetime(2026, 10, 26, 1, 30, tzinfo=timezone.utc)
    row = _block_approval_row()
    writes, blocks = [], []
    monkeypatch.setattr(db, "query_one", lambda *_args, **_kwargs: row)
    monkeypatch.setattr(db, "execute_rowcount", lambda sql, params=(): writes.append((sql, params)) or 1)
    monkeypatch.setattr(security, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(security, "block_ip", lambda *args, **kwargs: blocks.append((args, kwargs)) or True)
    app.config.update({"XDR_RESPONSE_MODE": "live", "XDR_IP_BLOCK_ENABLED": True,
                       "XDR_AUTO_MIN_SCORE": 80, "XDR_AUTO_MIN_CONFIDENCE": 0.8,
                       "XDR_MAX_EVENT_AGE_SECONDS": 300})

    with app.app_context():
        result = ai_xdr.decide_assessment("assessment-block-1", "APPROVED", 7, "admin", now=now,
                                          approved_action="block_ip")

    assert result["status"] == "APPROVED"
    assert result["response"]["reason"] == "block_succeeded"
    assert blocks[0][0] == ("198.51.100.77",)
    assert blocks[0][1]["minutes"] == 15
    assert blocks[0][1]["created_by"] == "ai_xdr_admin"
    assert "assessment-block-1" in blocks[0][1]["reason"]
    assert "NX-DB-000046" in blocks[0][1]["reason"]
    assert "R1" in blocks[0][1]["reason"]
    assert len(writes) == 1


def test_explicit_block_approval_allows_192_168_3_11_test_target(app, monkeypatch):
    from app import db, security

    row = _block_approval_row(
        src_ip="192.168.3.11",
        event_summary=json.dumps({"rule_ids": ["R1"], "src_ip": "192.168.3.11",
                                  "last_seen": "2026-10-26T01:30:00+00:00",
                                  "ticket_ids": ["NX-DB-000046"]}),
    )
    calls = []
    monkeypatch.setattr(db, "query_one", lambda *_args, **_kwargs: row)
    monkeypatch.setattr(db, "execute_rowcount", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(security, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(security, "block_ip", lambda *args, **kwargs: calls.append((args, kwargs)) or True)
    app.config.update({"XDR_RESPONSE_MODE": "live", "XDR_IP_BLOCK_ENABLED": True,
                       "XDR_AUTO_MIN_SCORE": 80, "XDR_AUTO_MIN_CONFIDENCE": 0.8,
                       "XDR_MAX_EVENT_AGE_SECONDS": 300})

    with app.app_context():
        result = ai_xdr.decide_assessment("assessment-block-1", "APPROVED", 7, "admin",
                                          approved_action="block_ip")

    assert result["response"]["blocked"] is True
    assert calls[0][0] == ("192.168.3.11",)
    assert calls[0][1]["minutes"] == 15


def test_block_approval_live_requires_both_live_gates(app, monkeypatch):
    from app import db, security

    row = _block_approval_row()
    writes, blocks = [], []
    monkeypatch.setattr(db, "query_one", lambda *_args, **_kwargs: row)
    monkeypatch.setattr(db, "execute_rowcount", lambda sql, params=(): writes.append((sql, params)) or 1)
    monkeypatch.setattr(security, "block_ip", lambda *args, **kwargs: blocks.append((args, kwargs)) or True)
    app.config.update({"XDR_RESPONSE_MODE": "live", "XDR_IP_BLOCK_ENABLED": False,
                       "XDR_AUTO_MIN_SCORE": 80, "XDR_AUTO_MIN_CONFIDENCE": 0.8})

    with app.app_context(), pytest.raises(RuntimeError, match="ip_block_gate_closed"):
        ai_xdr.decide_assessment("assessment-block-1", "APPROVED", 7, "admin",
                                 approved_action="block_ip")

    assert blocks == []
    assert writes == []


@pytest.mark.parametrize("overrides,expected", [
    ({"approval_allowed": 0}, "approval_not_allowed"),
    ({"verdict": "SUSPICIOUS"}, "verdict_not_malicious"),
    ({"threat_score": 79}, "score_below_threshold"),
    ({"confidence": 0.79}, "confidence_below_threshold"),
    ({"recommended_actions": '["notify_only"]'}, "action_not_recommended"),
    ({"src_ip": "invalid-ip"}, "invalid_or_missing_ip"),
    ({"src_ip": "192.168.3.14"}, "protected_ip"),
])
def test_block_approval_rejects_ineligible_assessments(app, monkeypatch, overrides, expected):
    from app import db, security

    row = _block_approval_row(**overrides)
    writes, blocks = [], []
    monkeypatch.setattr(db, "query_one", lambda *_args, **_kwargs: row)
    monkeypatch.setattr(db, "execute_rowcount", lambda sql, params=(): writes.append((sql, params)) or 1)
    monkeypatch.setattr(security, "block_ip", lambda *args, **kwargs: blocks.append((args, kwargs)) or True)
    app.config.update({"XDR_RESPONSE_MODE": "live", "XDR_IP_BLOCK_ENABLED": True,
                       "XDR_AUTO_MIN_SCORE": 80, "XDR_AUTO_MIN_CONFIDENCE": 0.8})

    with app.app_context(), pytest.raises(RuntimeError, match=expected):
        ai_xdr.decide_assessment("assessment-block-1", "APPROVED", 7, "admin",
                                 approved_action="block_ip")

    assert blocks == []
    assert writes == []


def test_general_approval_never_registers_recommended_block_ip(app, monkeypatch):
    from app import db, security

    row = _block_approval_row()
    writes, blocks = [], []
    monkeypatch.setattr(db, "query_one", lambda *_args, **_kwargs: row)
    monkeypatch.setattr(db, "execute_rowcount", lambda sql, params=(): writes.append((sql, params)) or 1)
    monkeypatch.setattr(security, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(security, "block_ip", lambda *args, **kwargs: blocks.append((args, kwargs)) or True)
    app.config.update({"XDR_RESPONSE_MODE": "live", "XDR_IP_BLOCK_ENABLED": True,
                       "XDR_AUTO_MIN_SCORE": 80, "XDR_AUTO_MIN_CONFIDENCE": 0.8})

    with app.app_context():
        result = ai_xdr.decide_assessment("assessment-block-1", "APPROVED", 7, "admin")

    assert result["response"]["reason"] == "no_block_action"
    assert blocks == []
    assert len(writes) == 1


def test_admin_xdr_template_shows_separate_block_approval_only_when_recommended(app):
    from flask import render_template

    def item(assessment_id, actions, error=""):
        return {
            "assessment_id": assessment_id, "last_seen_kst": "2026-10-29 10:00:00 KST",
            "first_seen_kst": "2026-10-29 10:00:00 KST", "src_ip": "198.51.100.77",
            "user_names": [], "rule_ids": ["R1"], "event_types": ["account_compromise_suspected"],
            "event_count": 1, "verdict": "MALICIOUS", "threat_score": 90, "confidence": 0.95,
            "reasoning": "synthetic", "status": "PENDING", "policy_mode": "day",
            "policy_reason": "DAYTIME_APPROVAL", "response_result": {}, "ticket_ids": [],
            "recommended_actions": actions, "decided_at": None, "block_approval_error": error,
        }

    with app.test_request_context("/admin/xdr"):
        html = render_template("admin_xdr.html", assessments=[
            item("eligible", ["block_ip"]),
            item("protected", ["block_ip"], "protected_ip"),
            item("notify-only", ["notify_only"]),
        ], xdr_enabled=True, unavailable=False, result="")

    assert html.count('value="APPROVED_BLOCK_IP"') == 2
    assert 'value="APPROVED_BLOCK_IP" disabled title="protected_ip"' in html


def test_ip_block_gate_configuration_is_opt_in(monkeypatch):
    from app.config import Config

    monkeypatch.delenv("XDR_IP_BLOCK_ENABLED", raising=False)
    assert Config().XDR_IP_BLOCK_ENABLED is False
    monkeypatch.setenv("XDR_IP_BLOCK_ENABLED", "1")
    assert Config().XDR_IP_BLOCK_ENABLED is True


def test_assessment_approval_dry_run_is_idempotent_for_same_approval_ref(app, monkeypatch):
    from app import db, security

    now = datetime(2026, 10, 26, 1, 30, tzinfo=timezone.utc)
    row = {
        "assessment_id": "assessment-1", "incident_ticket_id": None, "src_ip": "198.51.100.77",
        "rule_ids": '["R1"]', "user_names": '["testuser"]', "event_count": 1,
        "last_seen": now.isoformat(), "verdict": "MALICIOUS", "threat_score": 80, "confidence": 0.85,
        "reasoning": "synthetic metadata", "recommended_actions": '["block_ip"]',
        "event_summary": json.dumps({"rule_ids": ["R1"], "src_ip": "198.51.100.77", "last_seen": now.isoformat()}),
        "status": "PENDING", "response_result": None,
    }
    writes = []
    blocks = []
    monkeypatch.setattr(db, "query_one", lambda *_args, **_kwargs: row)

    def update(sql, params=()):
        writes.append((sql, params))
        row["status"] = params[0]
        row["response_result"] = params[3]
        return 1

    monkeypatch.setattr(db, "execute_rowcount", update)
    monkeypatch.setattr(security, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(security, "block_ip", lambda *args, **kwargs: blocks.append((args, kwargs)) or True)
    app.config.update({"XDR_RESPONSE_MODE": "dry-run", "XDR_MAX_EVENT_AGE_SECONDS": 300})

    with app.app_context():
        first = ai_xdr.decide_assessment("assessment-1", "APPROVED", None, "n8n", now=now,
                                         approval_ref="assessment-1:NX-DB-000046")
        second = ai_xdr.decide_assessment("assessment-1", "APPROVED", None, "n8n", now=now,
                                          approval_ref="assessment-1:NX-DB-000046")

    assert first["status"] == second["status"] == "APPROVED"
    assert first["response"]["reason"] == "dry_run"
    assert second["idempotent"] is True
    assert json.loads(row["response_result"])["approval_ref"] == "assessment-1:NX-DB-000046"
    assert len(writes) == 1
    assert blocks == []


def test_ingest_event_deduplicates_alert_id(app, monkeypatch):
    from app import db

    app.config["XDR_TRIAGE_WINDOW_SECONDS"] = 180
    rowcounts = iter((1, 0))
    statements = []
    monkeypatch.setattr(db, "execute_rowcount", lambda sql, params=(): statements.append((sql, params)) or next(rowcounts))
    with app.app_context():
        first = ai_xdr.ingest_event(payload())
        duplicate = ai_xdr.ingest_event(payload())
    assert first["duplicate"] is False
    assert duplicate["duplicate"] is True
    assert "message" not in statements[0][1][-1]
    assert "prompt" not in statements[0][1][-1]


def test_internal_xdr_api_requires_token_and_opt_in(app, client, monkeypatch):
    monkeypatch.setenv("LAB_INTERNAL_API_TOKEN", "test-only-token")
    url = "/internal/api/v1/ai-xdr/events"
    payload_data = payload()
    app.config["XDR_ENABLED"] = False
    assert client.post(url, json=payload_data, headers={"Authorization": "Bearer test-only-token"}).status_code == 503
    app.config["XDR_ENABLED"] = True
    monkeypatch.setattr(ai_xdr, "ingest_event", lambda data: {"accepted": True, "duplicate": False, "alert_id": data["alert_id"]})
    response = client.post(url, json=payload_data, headers={"Authorization": "Bearer test-only-token"})
    assert response.status_code == 202
    assert response.json["alert_id"] == "alert-1"
    assert client.post(url, json=payload_data).status_code == 401


def test_internal_xdr_api_rejects_wrong_schema_without_writing(app, client, monkeypatch):
    monkeypatch.setenv("LAB_INTERNAL_API_TOKEN", "test-only-token")
    app.config["XDR_ENABLED"] = True
    bad_payload = payload()
    bad_payload["schema_version"] = "1.0"
    response = client.post(
        "/internal/api/v1/ai-xdr/events", json=bad_payload,
        headers={"Authorization": "Bearer test-only-token"},
    )
    assert response.status_code == 422
    assert response.json["error"] == "unsupported_schema_version"


def test_internal_xdr_process_api_requires_token_and_opt_in(app, client, monkeypatch):
    monkeypatch.setenv("LAB_INTERNAL_API_TOKEN", "test-only-token")
    app.config["XDR_ENABLED"] = False
    url = "/internal/api/v1/ai-xdr/process"
    headers = {"Authorization": "Bearer test-only-token"}
    assert client.post(url, headers=headers).status_code == 503
    app.config["XDR_ENABLED"] = True
    assessment = {
        "assessment_id": "xdr-test", "status": "PENDING", "verdict": "SUSPICIOUS",
        "threat_score": 72, "confidence": 0.88, "recommended_actions": ["review"],
        "rule_ids": ["R1"], "incident_ticket_id": 25, "ticket_ids": ["NX-DB-000025"],
        "policy_reason": "DAYTIME_APPROVAL", "policy_reason_detail": "daytime_requires_approval",
        "auto_allowed": False, "approval_allowed": True,
    }
    monkeypatch.setattr(ai_xdr, "process_ready_windows", lambda: {"processed": 1, "assessments": [assessment]})
    assert client.post(url, headers=headers).json == {"ok": True, "processed": 1, "assessments": [assessment]}
    assert client.post(url).status_code == 401
