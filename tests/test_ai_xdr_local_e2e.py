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
        except Exception as exc:
            pytest.skip(f"nexus_test XDR migration unavailable: {type(exc).__name__}")
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
