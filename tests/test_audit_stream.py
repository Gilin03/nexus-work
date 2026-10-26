import json
import queue
from app import audit
from app.security import log_event


def test_audit_event_subscription_and_broadcast():
    q = audit.subscribe_audit_events()
    try:
        sample_record = {
            "ts": "2026-10-22T08:00:00.000000+00:00",
            "event_type": "test_broadcast_event",
            "user": "test_user",
            "role": "admin",
            "src_ip": "192.168.7.77",
            "decision": "BLOCK",
            "reason": "malicious_payload",
            "method": "POST",
            "path": "/api/test",
            "extra_param": "val123"
        }
        audit.broadcast_audit_event(sample_record)

        event = q.get_nowait()
        assert event["event_type"] == "test_broadcast_event"
        assert event["decision"] == "BLOCK"
        assert event["src_ip"] == "192.168.7.77"
        assert "raw" in event
        raw_obj = json.loads(event["raw"])
        assert raw_obj["event_type"] == "test_broadcast_event"
    finally:
        audit.unsubscribe_audit_events(q)


def test_audit_stream_requires_permission(client):
    # Unauthenticated client cannot access /admin/audit/stream
    resp = client.get("/admin/audit/stream")
    # Redirects to login (302/303) or Forbidden (403)
    assert resp.status_code in (302, 303, 403)


def test_audit_event_ai_fields_shaping():
    record = {
        'ts': '2026-10-26T10:00:00+00:00',
        'event_type': 'ip_blocked',
        'decision': 'BLOCK',
        'src_ip': '203.0.113.88',
        'threat_score': 88,
        'verdict': 'MALICIOUS'
    }
    shaped = audit._shape(record)
    assert shaped['threat_score'] == 88
    assert shaped['verdict'] == 'MALICIOUS'
