import json
import uuid
from datetime import datetime, timezone, timedelta
import pymysql
import os

KST = timezone(timedelta(hours=9))

def seed_dummy():
    now_utc = datetime.now(timezone.utc)
    t1_seen = now_utc - timedelta(minutes=5)
    t2_seen = now_utc - timedelta(hours=2)

    con = pymysql.connect(
        host="127.0.0.1", port=3307, user="root",
        password=os.environ["MYSQL_ROOT_PASSWORD"],
        database="nexus", autocommit=True
    )

    with con.cursor() as cur:
        # Dummy Item 1: PENDING 승인 대기 (주간 모드)
        id1 = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO security_xdr_assessments (
                assessment_id, window_key, group_key, incident_ticket_id, src_ip,
                user_names, rule_ids, event_types, event_count, first_seen, last_seen,
                event_summary, threat_score, confidence, verdict, reasoning,
                recommended_actions, policy_mode, policy_reason, status, response_result, created_at
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
        """, (
            id1, f"win-{id1[:8]}", "dummy_spray_group", None, "192.168.7.88",
            json.dumps(["admin", "kim", "lee", "root"], ensure_ascii=False),
            json.dumps(["R5", "R8"]),
            json.dumps(["login_failure", "decoy_triggered"]),
            8, t1_seen, now_utc,
            json.dumps({"pattern": "Multi-stage Account Spray & Decoy Recon"}, ensure_ascii=False),
            88, 0.940, "MALICIOUS",
            "단순 오타가 아닌 5분 내 4개 계정 순차 대입 후 /.env 디코이 탐색 확인됨. 주간 모드 정책에 따라 관제사 승인 대기 중.",
            json.dumps(["block_ip", "lock_targeted_users"], ensure_ascii=False),
            "day", "daytime_requires_approval", "PENDING",
            json.dumps({"auto_candidate": True, "blocked": False}, ensure_ascii=False),
            now_utc
        ))

        # Dummy Item 2: APPROVED 처리 완료 건 (야간 자동 격리 시뮬레이션)
        id2 = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO security_xdr_assessments (
                assessment_id, window_key, group_key, incident_ticket_id, src_ip,
                user_names, rule_ids, event_types, event_count, first_seen, last_seen,
                event_summary, threat_score, confidence, verdict, reasoning,
                recommended_actions, policy_mode, policy_reason, status, response_result,
                created_at, decided_at
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s
            )
        """, (
            id2, f"win-{id2[:8]}", "dummy_scan_group", None, "198.51.100.99",
            json.dumps(["-"], ensure_ascii=False),
            json.dumps(["R8"]),
            json.dumps(["web_path_scan"]),
            24, t2_seen - timedelta(minutes=3), t2_seen,
            json.dumps({"pattern": "Automated Web Vulnerability Scan"}, ensure_ascii=False),
            94, 0.985, "MALICIOUS",
            "웹 디렉토리 및 설정 파일 무차별 전수 스캔(24건) 포착. 야간 자동 격리 정책에 의해 즉시 포털 및 방화벽 차단 완료.",
            json.dumps(["block_ip"], ensure_ascii=False),
            "night", "night_auto_executed", "APPROVED",
            json.dumps({"auto_candidate": True, "blocked": True, "rule_id": "R8", "minutes": 15}, ensure_ascii=False),
            t2_seen, t2_seen
        ))

    print(f"SUCCESS: Inserted dummy assessments {id1[:8]} and {id2[:8]}")

if __name__ == "__main__":
    seed_dummy()
