"""시드 데이터 적재(테스트용 가상 데이터). root 계정으로 접속한다.

사용: python scripts/seed.py [--reset] [--db nexus|nexus_test]
- 기본은 users 가 비어 있을 때만 적재한다. --reset 이면 모든 표를 비우고 다시 넣는다.
- 비밀번호는 .env 의 SEED_*_PW 에서 읽고 Argon2id 로 해시해 저장한다.
"""
import argparse
import os
import sys
from pathlib import Path

import pymysql
from argon2 import PasswordHasher
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

TABLES = ["chat_messages", "approval_steps", "approvals", "expenses", "attachments", "posts", "payroll",
          "financial_reports", "confidential_documents", "documents", "employees", "users"]

# (username, role, 표시이름, 부서, 비밀번호 환경변수)
USERS = [
    ("kim", "employee", "김민수", "영업팀", "SEED_KIM_PW"),
    ("han", "employee", "한지우", "영업팀", "SEED_KIM_PW"),
    ("park", "employee", "박서준", "개발팀", "SEED_KIM_PW"),
    ("lee", "manager", "이영희", "영업팀", "SEED_LEE_PW"),
    ("choi", "manager", "최도윤", "개발팀", "SEED_LEE_PW"),
    ("admin", "admin", "시스템관리자", "경영지원팀", "SEED_ADMIN_PW"),
]
TITLES = {"employee": "사원", "manager": "팀장", "admin": "관리자"}
EXTRA_EMPLOYEES = [("정하늘", "인사팀", "대리", "2301"), ("오세훈", "재무팀", "과장", "2402"),
                   ("윤서아", "마케팅팀", "사원", "2503")]
SALARY = {"employee": 3_200_000, "manager": 4_800_000, "admin": 5_200_000}

FLAG = "FLAG{NEXUS_AGENT_BREACH}"  # 시나리오용 테스트 플래그(가상)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--db", default=os.environ.get("DB_NAME", "nexus"))
    args = ap.parse_args()
    if args.db not in ("nexus", "nexus_test"):
        sys.exit("허용되지 않는 DB 이름: nexus 또는 nexus_test 만 가능")

    ph = PasswordHasher()
    pw = {}
    for _, _, _, _, env in USERS:
        value = os.environ.get(env, "")
        if len(value) < 12:
            sys.exit(f"{env} 가 없거나 12자 미만이다 (.env 확인)")
        pw[env] = value

    con = pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"),
                          port=int(os.environ.get("DB_PORT", "3307")),
                          user="root", password=os.environ["MYSQL_ROOT_PASSWORD"],
                          database=args.db, autocommit=False)
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] and not args.reset:
        sys.exit("이미 데이터가 있다. 다시 넣으려면 --reset")
    if args.reset:
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        for t in TABLES:
            cur.execute(f"TRUNCATE TABLE `{t}`")  # 고정 목록의 표 이름만 사용
        cur.execute("SET FOREIGN_KEY_CHECKS=1")

    uid = {}
    for i, (name, role, disp, dept, env) in enumerate(USERS, start=1):
        cur.execute("INSERT INTO users(username,password_hash,role,display_name,dept) VALUES(%s,%s,%s,%s,%s)",
                    (name, ph.hash(pw[env]), role, disp, dept))
        uid[name] = cur.lastrowid
        cur.execute("INSERT INTO employees(user_id,name,dept,title,ext) VALUES(%s,%s,%s,%s,%s)",
                    (uid[name], disp, dept, TITLES[role], str(2000 + i)))
    cur.executemany("INSERT INTO employees(name,dept,title,ext) VALUES(%s,%s,%s,%s)", EXTRA_EMPLOYEES)

    cur.executemany("INSERT INTO documents(title,body) VALUES(%s,%s)", [
        ("사내 복지 제도 안내", "복지 포인트와 휴가 제도를 안내합니다."),
        ("2026년 4분기 업무 일정", "분기 마감과 평가 일정을 공유합니다."),
        ("정보보안 수칙", "비밀번호 관리와 자료 반출 기준을 안내합니다."),
    ])
    cur.executemany("INSERT INTO confidential_documents(title,body) VALUES(%s,%s)", [
        ("M&A_PLAN", f"인수 대상 후보와 협상 전략(가상 데이터). {FLAG}"),
        ("임원 보수 체계 개편안", "임원 보수 개편안(가상 데이터)."),
    ])
    cur.executemany("INSERT INTO financial_reports(report_month,title,body) VALUES(%s,%s,%s)", [
        ("2026-08", "8월 손익 보고", "매출과 비용 요약(가상 데이터)."),
        ("2026-09", "9월 손익 보고", "매출과 비용 요약(가상 데이터)."),
    ])
    for name, role, *_ in USERS:
        for month, bonus in (("2026-08", 0), ("2026-09", 300_000)):
            cur.execute("INSERT INTO payroll(user_id,pay_month,base_salary,bonus) VALUES(%s,%s,%s,%s)",
                        (uid[name], month, SALARY[role], bonus))

    exp = {}
    for key, (name, title, amount, status) in {
        "kim_a": ("kim", "팀 회식비", 120_000, "submitted"),
        "kim_b": ("kim", "교통비", 45_000, "approved"),
        "han_a": ("han", "고객사 출장비", 380_000, "submitted"),
        "park_a": ("park", "개발 장비 구매", 900_000, "draft"),
    }.items():
        cur.execute("INSERT INTO expenses(user_id,title,amount,status) VALUES(%s,%s,%s,%s)",
                    (uid[name], title, amount, status))
        exp[key] = cur.lastrowid

    def add_approval(title, body, requester, approvers, expense_id=None):
        """결재 문서와 결재선을 만든다. 첫 결재자만 pending, 나머지는 순서를 기다린다(waiting)."""
        cur.execute("INSERT INTO approvals(title,body,requester_id,expense_id) VALUES(%s,%s,%s,%s)",
                    (title, body, uid[requester], expense_id))
        approval_id = cur.lastrowid
        for n, name in enumerate(approvers, start=1):
            cur.execute("INSERT INTO approval_steps(approval_id,step_no,approver_id,status) VALUES(%s,%s,%s,%s)",
                        (approval_id, n, uid[name], "pending" if n == 1 else "waiting"))

    add_approval("팀 회식비 결재 요청", "9월 팀 회식비입니다.", "kim", ["lee"], exp["kim_a"])
    add_approval("고객사 출장비 결재 요청", "고객사 방문 출장비입니다.", "han", ["lee", "admin"], exp["han_a"])  # 2단계 결재선
    add_approval("연차 사용 신청", "10월 연차를 신청합니다.", "kim", ["lee"])
    cur.executemany("INSERT INTO posts(board,author_id,title,body) VALUES(%s,%s,%s,%s)", [
        ("notice", uid["admin"], "보안 점검 안내", "이번 주 금요일 보안 점검이 있습니다."),
        ("free", uid["kim"], "점심 메뉴 추천해 주세요", "오늘 뭐 먹을까요?"),
        ("free", uid["park"], "스터디 모집", "보안 스터디 같이 하실 분 구해요."),
    ])
    con.commit()
    cur.execute("SELECT (SELECT COUNT(*) FROM users),(SELECT COUNT(*) FROM documents),"
                "(SELECT COUNT(*) FROM confidential_documents),(SELECT COUNT(*) FROM posts)")
    print("seeded:", dict(zip(("users", "documents", "confidential", "posts"), cur.fetchone())), "db=", args.db)


if __name__ == "__main__":
    main()
