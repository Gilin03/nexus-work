"""Short-lived authentication-event aggregation for Graylog R6."""
from datetime import datetime, timedelta, timezone

from . import db

R1_INPUT_EVENTS = frozenset({"login_failure", "login_success"})
R6_INPUT_EVENTS = frozenset({"login_failure", "account_locked", "login_locked"})
AUTH_INPUT_EVENTS = R1_INPUT_EVENTS | R6_INPUT_EVENTS
RETRY_EVENTS = frozenset({"login_failure", "login_locked"})
WINDOW_SECONDS = 300


def _event_time(ts):
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _valid_identity(event):
    username = event.get("user")
    request_id = event.get("request_id")
    if not isinstance(username, str) or not username or username == "-" or len(username) > 64:
        return None
    if not isinstance(request_id, str) or len(request_id) != 32:
        return None
    return username.lower(), request_id


def collect_auth_events(event):
    """Persist one raw auth signal and return derived events newly claimed by this request."""
    event_type = event.get("event_type")
    if event_type not in AUTH_INPUT_EVENTS:
        return []

    identity = _valid_identity(event)
    if identity is None:
        return []
    username, request_id = identity
    occurred_at = _event_time(event["ts"])
    src_ip = event.get("src_ip") or "-"
    if not isinstance(src_ip, str) or len(src_ip) > 45:
        src_ip = "-"

    db.execute(
        "DELETE FROM security_auth_events WHERE occurred_at < %s",
        (occurred_at - timedelta(seconds=WINDOW_SECONDS),),
    )
    event_id = db.execute(
        "INSERT INTO security_auth_events "
        "(request_id, event_type, username, src_ip, occurred_at) "
        "VALUES (%s, %s, %s, %s, %s)",
        (request_id, event_type, username, src_ip, occurred_at),
    )

    derived = []
    if event_type == "login_success":
        failed_attempts = db.query_one(
            "SELECT COUNT(DISTINCT request_id) AS failed_attempts FROM security_auth_events "
            "WHERE event_type = 'login_failure' AND username = %s AND request_id <> %s "
            "AND occurred_at >= %s AND occurred_at < %s",
            (
                username,
                request_id,
                occurred_at - timedelta(seconds=WINDOW_SECONDS),
                occurred_at,
            ),
        )["failed_attempts"]
        if failed_attempts >= 3:
            claimed = db.execute_rowcount(
                "UPDATE security_auth_events SET r1_emitted_at = %s "
                "WHERE id = %s AND r1_emitted_at IS NULL",
                (occurred_at, event_id),
            )
            if claimed == 1:
                derived.append({
                    "event_type": "account_compromise_suspected",
                    "failed_attempts": failed_attempts,
                    "window_seconds": WINDOW_SECONDS,
                    "trigger_event_type": "login_success",
                    "decision": "WARN",
                    "reason": "login_success_after_failures",
                    "severity": "high",
                })

    if event_type not in RETRY_EVENTS or src_ip == "-":
        return derived

    anchors = db.query_all(
        "SELECT id, request_id, occurred_at FROM security_auth_events "
        "WHERE event_type = 'account_locked' AND username = %s AND src_ip = %s "
        "AND request_id <> %s AND occurred_at >= %s AND occurred_at < %s "
        "AND r6_emitted_at IS NULL ORDER BY occurred_at FOR UPDATE",
        (
            username,
            src_ip,
            request_id,
            occurred_at - timedelta(seconds=WINDOW_SECONDS),
            occurred_at,
        ),
    )

    for anchor in anchors:
        retry_count = db.query_one(
            "SELECT COUNT(DISTINCT request_id) AS retry_count FROM security_auth_events "
            "WHERE event_type IN ('login_failure', 'login_locked') "
            "AND username = %s AND src_ip = %s AND request_id <> %s "
            "AND occurred_at > %s AND occurred_at <= %s "
            "AND occurred_at <= DATE_ADD(%s, INTERVAL 300 SECOND)",
            (
                username,
                src_ip,
                anchor["request_id"],
                anchor["occurred_at"],
                occurred_at,
                anchor["occurred_at"],
            ),
        )["retry_count"]
        if retry_count < 3:
            continue

        claimed = db.execute_rowcount(
            "UPDATE security_auth_events SET r6_emitted_at = %s "
            "WHERE id = %s AND r6_emitted_at IS NULL",
            (occurred_at, anchor["id"]),
        )
        if claimed == 1:
            derived.append({
                "event_type": "post_lock_retry_detected",
                "user": username,
                "src_ip": src_ip,
                "lock_request_id": anchor["request_id"],
                "trigger_event_type": event_type,
                "count": 3,
                "window_seconds": WINDOW_SECONDS,
                "decision": "WARN",
                "reason": "post_lock_retry_threshold_reached",
                "severity": "high",
            })
    return derived
