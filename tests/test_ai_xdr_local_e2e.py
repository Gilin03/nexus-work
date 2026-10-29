import json
import uuid
from datetime import datetime, timezone

import pytest

from app import ai_xdr, db, security


def test_graylog_payload_links_existing_ticket_and_dry_run_assessment(app, client, monkeypatch):
    app.config.update({
        "DB_NAME": "nexus_test", "XDR_ENABLED": True, "XDR_AUTO_ENABLED": True,
        "XDR_RESPONSE_MODE": "dry-run", "XDR_AUTO_MIN_SCORE": 80,
        "XDR_AUTO_MIN_CONFIDENCE": 0.8, "XDR_MAX_EVENT_AGE_SECONDS": 300,
        "XDR_TRIAGE_WINDOW_SECONDS": 180, "XDR_WEEKEND_MODE": "night_auto",
    })
    monkeypatch.setenv("LAB_INTERNAL_API_TOKEN", "xdr-dry-run-integration-test-token")
    token = "xdr-dry-run-integration-test-token"
    alert_id = "xdr-e2e-" + uuid.uuid4().hex
    ticket_key = "xdr-e2e:" + uuid.uuid4().hex
    assessment_id = None
    now = datetime.now(timezone.utc)
    local_hour = (now.hour + 9) % 24
    if local_hour < 23:
        app.config.update({"XDR_DAY_START_HOUR": local_hour + 1, "XDR_DAY_END_HOUR": 24})
    else:
        app.config.update({"XDR_DAY_START_HOUR": 0, "XDR_DAY_END_HOUR": 23})

    with app.app_context():
        try:
            db.query_one("SELECT 1 FROM security_xdr_events LIMIT 1")
            columns = {row["Field"] for row in db.query_all("SHOW COLUMNS FROM security_xdr_assessments")}
        except Exception as exc:
            pytest.skip(f"nexus_test XDR migration unavailable: {type(exc).__name__}")
        if not {"approval_allowed", "auto_allowed"}.issubset(columns):
            pytest.skip("nexus_test XDR policy migration is incomplete")
        ticket_id = db.execute(
            "INSERT INTO security_incident_tickets "
            "(ticket_key, status, src_ip, ticket_type, type_rank, event_count, rule_ids, user_names, "
            "first_seen, last_seen, latest_event, responses) "
            "VALUES (%s, 'open', %s, 'R8', 1, 1, %s, %s, %s, %s, %s, %s)",
            (ticket_key, "203.0.113.77", '["R8"]', '["xdr-test"]', now.replace(tzinfo=None),
             now.replace(tzinfo=None), json.dumps({"event_type": "not_found"}), "[]"),
        )
        db.commit()

    payload = {
        "schema_version": "1.1", "alert_id": alert_id, "ticket_id": f"NX-DB-{ticket_id:06d}",
        "rule": {"id": "R8", "severity": "high"},
        "alert": {"id": alert_id, "timestamp": now.isoformat()},
        "timestamp": now.isoformat(),
        "event": {"event_type": "not_found", "src_ip": "203.0.113.77", "user": "xdr-test",
                  "path": "/safe-test", "severity": "high"},
    }
    headers = {"Authorization": f"Bearer {token}"}
    try:
        first = client.post("/internal/api/v1/ai-xdr/events", json=payload, headers=headers)
        duplicate = client.post("/internal/api/v1/ai-xdr/events", json=payload, headers=headers)
        assert first.status_code == 202 and first.json["duplicate"] is False
        assert duplicate.status_code == 202 and duplicate.json["duplicate"] is True

        with app.app_context():
            db.execute_rowcount(
                "UPDATE security_xdr_events SET window_start = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 4 MINUTE) "
                "WHERE alert_id = %s", (alert_id,),
            )
            db.commit()

        def fake_triage(summary, current_assessment_id):
            nonlocal assessment_id
            assessment_id = current_assessment_id
            return {
                "assessment_id": current_assessment_id, "threat_score": 91, "confidence": 0.95,
                "verdict": "MALICIOUS", "reasoning": "synthetic metadata only",
                "recommended_actions": ["block_ip"],
            }

        monkeypatch.setattr(ai_xdr, "triage", fake_triage)
        monkeypatch.setattr(security, "block_ip", lambda *_args, **_kwargs: pytest.fail("dry-run attempted block"))
        processed = client.post("/internal/api/v1/ai-xdr/process", headers=headers)
        assert processed.status_code == 200
        assert processed.json["processed"] == 1

        with app.app_context():
            row = db.query_one(
                "SELECT status, incident_ticket_id, policy_reason, response_result FROM security_xdr_assessments "
                "WHERE assessment_id = %s", (assessment_id,),
            )
            event = db.query_one(
                "SELECT assessment_id, incident_ticket_id FROM security_xdr_events WHERE alert_id = %s", (alert_id,),
            )
            visible = next(item for item in ai_xdr.list_assessments(100) if item["assessment_id"] == assessment_id)
        response_result = json.loads(row["response_result"])
        assert row["status"] == "PENDING" and row["incident_ticket_id"] == ticket_id
        assert row["policy_reason"] == "dry_run" and response_result["auto_candidate"] is True
        assert event["assessment_id"] == assessment_id and event["incident_ticket_id"] == ticket_id
        assert visible["response_result"]["auto_candidate"] is True
    finally:
        with app.app_context():
            if assessment_id:
                db.execute_rowcount("DELETE FROM security_xdr_events WHERE alert_id = %s", (alert_id,))
                db.execute_rowcount("DELETE FROM security_xdr_assessments WHERE assessment_id = %s", (assessment_id,))
            db.execute_rowcount("DELETE FROM security_xdr_events WHERE alert_id = %s", (alert_id,))
            db.execute_rowcount("DELETE FROM security_incident_tickets WHERE ticket_key = %s", (ticket_key,))
            db.commit()


def test_approved_block_registers_in_test_db_admin_view_and_feed_then_expires(aapp, root, monkeypatch):
    """Mock only the assessment row; use nexus_test + TEST-NET for the real block table and feed."""
    from tests.support import as_user, post

    test_ip = "203.0.113.88"
    dry_id, live_id = str(uuid.uuid4()), str(uuid.uuid4())
    ticket_key = "NX-DB-000046"
    monkeypatch.setenv("LAB_INTERNAL_API_TOKEN", "xdr-block-feed-test-token")
    aapp.config.update({"DB_NAME": "nexus_test", "XDR_ENABLED": True, "XDR_RESPONSE_MODE": "dry-run",
                        "XDR_IP_BLOCK_ENABLED": False, "XDR_AUTO_MIN_SCORE": 80,
                        "XDR_AUTO_MIN_CONFIDENCE": 0.8})
    client = as_user(aapp, "zz_sec")

    with aapp.app_context():
        try:
            db.query_one("SELECT ip_address FROM blocked_ips LIMIT 1")
        except Exception as exc:
            pytest.skip(f"nexus_test blocked_ips table unavailable: {type(exc).__name__}")
        security.unblock_ip(test_ip)

    def assessment_row(assessment_id):
        return {
            "assessment_id": assessment_id, "incident_ticket_id": None, "src_ip": test_ip,
            "rule_ids": '["R1"]', "user_names": '["xdr-test"]', "event_count": 1,
            "last_seen": datetime.now(timezone.utc).isoformat(), "verdict": "MALICIOUS",
            "threat_score": 90, "confidence": 0.95, "reasoning": "synthetic test only",
            "recommended_actions": '["block_ip"]',
            "event_summary": json.dumps({"rule_ids": ["R1"], "src_ip": test_ip, "ticket_ids": [ticket_key]}),
            "status": "PENDING", "approval_allowed": 1, "auto_allowed": 0,
            "policy_reason": "DAYTIME_APPROVAL", "response_result": None,
        }

    rows = {dry_id: assessment_row(dry_id), live_id: assessment_row(live_id)}
    original_query_one, original_execute_rowcount = db.query_one, db.execute_rowcount

    def query_one(sql, params=(), conf=False):
        if "FROM security_xdr_assessments WHERE assessment_id = %s FOR UPDATE" in sql:
            return rows.get(params[0])
        return original_query_one(sql, params, conf=conf)

    def execute_rowcount(sql, params=()):
        if sql.startswith("UPDATE security_xdr_assessments SET status = %s"):
            row = rows.get(params[4])
            if row and row["status"] == "PENDING":
                row["status"] = params[0]
                row["response_result"] = params[3]
                return 1
            return 0
        return original_execute_rowcount(sql, params)

    monkeypatch.setattr(db, "query_one", query_one)
    monkeypatch.setattr(db, "execute_rowcount", execute_rowcount)
    monkeypatch.setattr(ai_xdr, "list_assessments", lambda _limit: [
        {**rows[live_id], "ticket_ids": [ticket_key], "rule_ids": ["R1"],
         "user_names": ["xdr-test"], "event_types": ["account_compromise_suspected"],
         "recommended_actions": ["block_ip"], "response_result": {}, "event_count": 1,
         "last_seen_kst": "2026-10-29 10:00:00 KST", "first_seen_kst": "2026-10-29 10:00:00 KST",
         "policy_mode": "day", "created_at": "2026-10-29", "decided_at": None,
         "block_approval_error": ai_xdr._block_approval_error(rows[live_id], aapp.config)}
    ])

    try:
        dry_result = post(client, f"/admin/xdr/assessments/{dry_id}/decision", decision="APPROVED_BLOCK_IP")
        assert dry_result.status_code == 303
        assert rows[dry_id]["status"] == "APPROVED"
        assert json.loads(rows[dry_id]["response_result"])["reason"] == "dry_run"
        with aapp.app_context():
            assert db.query_one("SELECT ip_address FROM blocked_ips WHERE ip_address = %s", (test_ip,)) is None

        # The live gate is set only on the nexus_test app instance; no production assessment/DB is used.
        aapp.config.update({"XDR_RESPONSE_MODE": "live", "XDR_IP_BLOCK_ENABLED": True})
        pending_page = client.get("/admin/xdr")
        pending_html = pending_page.get_data(as_text=True)
        assert pending_page.status_code == 200
        assert live_id in pending_html and 'value="APPROVED_BLOCK_IP"' in pending_html
        live_result = post(client, f"/admin/xdr/assessments/{live_id}/decision", decision="APPROVED_BLOCK_IP")
        assert live_result.status_code == 303
        assert rows[live_id]["status"] == "APPROVED"
        assert json.loads(rows[live_id]["response_result"])["reason"] == "block_succeeded"

        with aapp.app_context():
            blocked = db.query_one(
                "SELECT ip_address, reason, created_by, TIMESTAMPDIFF(SECOND, NOW(), blocked_until) AS seconds_left "
                "FROM blocked_ips WHERE ip_address = %s", (test_ip,),
            )
            assert blocked["ip_address"] == test_ip
            assert live_id in blocked["reason"] and ticket_key in blocked["reason"] and "R1" in blocked["reason"]
            assert blocked["created_by"] == "ai_xdr_admin"
            assert 14 * 60 <= blocked["seconds_left"] <= 15 * 60

        blocked_page = client.get("/admin/blocked-ips")
        assert blocked_page.status_code == 200
        assert test_ip in blocked_page.get_data(as_text=True)

        headers = {"Authorization": "Bearer xdr-block-feed-test-token"}
        json_feed = client.get("/internal/api/v1/blocked-ips", headers=headers)
        text_feed = client.get("/internal/api/v1/blocked-ips?format=txt", headers=headers)
        assert json_feed.status_code == text_feed.status_code == 200
        assert any(item["ip_address"] == test_ip for item in json_feed.json["items"])
        assert test_ip in text_feed.get_data(as_text=True).splitlines()

        with aapp.app_context():
            db.execute_rowcount(
                "UPDATE blocked_ips SET blocked_until = DATE_SUB(NOW(), INTERVAL 1 SECOND) WHERE ip_address = %s",
                (test_ip,),
            )
            db.commit()
            security._blocked_ip_cache.pop(test_ip, None)
            assert security.is_ip_blocked(test_ip)[0] is False
        expired_feed = client.get("/internal/api/v1/blocked-ips?format=txt", headers=headers)
        assert expired_feed.status_code == 200
        assert test_ip not in expired_feed.get_data(as_text=True).splitlines()
    finally:
        with aapp.app_context():
            security.unblock_ip(test_ip)
