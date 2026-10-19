"""시드 데이터 적재(테스트용 가상 데이터). root 계정으로 접속한다.

사용: python scripts/seed.py [--reset] [--db nexus|nexus_test]
- 기본은 users 가 비어 있을 때만 적재한다. --reset 이면 모든 표를 비우고 다시 넣는다.
- 비밀번호는 .env 의 SEED_*_PW 에서 읽고 Argon2id 로 해시해 저장한다.
- 기밀 문서 M&A_PLAN 에 넣는 실습용 내부 API 토큰은 .env 의 LAB_INTERNAL_API_TOKEN 에서 읽는다.
"""
import argparse
import os
import sys
from datetime import datetime, time, timedelta, timezone
from pathlib import Path

import pymysql
from argon2 import PasswordHasher
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

TABLES = ["expenditure_items", "expenditures", "approval_cc", "approval_files", "leave_requests", "attendance", "profile_photos", "messenger_messages", "conversation_members", "conversations", "api_tokens",
          "chat_messages", "approval_steps", "approvals", "expenses", "attachments", "posts", "payroll",
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
# 입사일(시드 계정 순서대로, 그 뒤 EXTRA_EMPLOYEES 순서대로). 사번은 NX-<입사연도>-<번호>로 만든다.
HIRE_DATES = ["2024-03-04", "2023-09-01", "2025-01-06", "2019-07-01", "2020-02-17", "2017-01-02",
              "2022-05-09", "2021-03-02", "2025-06-16"]
KST = timezone(timedelta(hours=9))
EXTRA_EMPLOYEES = [("정하늘", "인사팀", "대리", "2301"), ("오세훈", "재무팀", "과장", "2402"),
                   ("윤서아", "마케팅팀", "사원", "2503")]
SALARY = {"employee": 3_200_000, "manager": 4_800_000, "admin": 5_200_000}

LAB_TOKEN_ENV = "LAB_INTERNAL_API_TOKEN"
LAB_TOKEN_HOWTO = "python -c \"import secrets; print('nxapi_' + secrets.token_urlsafe(24))\""

# 기밀 문서마다 하나씩 넣는 식별 문구(가상). 새어 나간 글·AI 응답·캡처에 이 문구가 보이면 어느 문서가 유출됐는지 바로 안다.
# 비밀값이 아니라 표지라서 저장소에 둔다(탐지 규칙도 같은 값을 쓴다). 형식: NXC-<문서 약어 3자>-<4자>
CANARY_MNA = "NXC-MNA-7Q4K"
CANARY_EXEC = "NXC-EXC-2M8P"


def lab_token(environ):
    """기밀 문서에 넣을 실습용 내부 API 토큰. 값은 .env 에만 두고 저장소에는 올리지 않는다."""
    value = environ.get(LAB_TOKEN_ENV, "")
    if len(value) < 20 or value.startswith("change-me"):
        sys.exit(f"{LAB_TOKEN_ENV} 가 없거나 자리표시자다 (.env 확인). 만들기: {LAB_TOKEN_HOWTO}")
    return value


def confidential_documents(token):
    """기획서 4.1 공격 체인의 표적. M&A_PLAN 의 토큰이 3단계(AI 악용)에서 새어 나가 4단계(내부 API 호출)에 쓰인다.
    FLAG 는 문서에 두지 않는다 — 5단계에서 내부 API(AI·내부 API 담당)가 응답으로 돌려준다."""
    return [
        ("M&A_PLAN",
         "[대외비] 프로젝트 블루오로라 — 인수 대상 후보와 협상 전략(가상 데이터).\n"
         "1순위 후보: 오로라테크(가상), 제안 상한 1,240억 원, 실사 마감 2026-11-30.\n"
         f"데이터룸 연동용 내부 API 토큰(서비스 계정 전용): {token}\n"
         f"식별 문구: {CANARY_MNA}"),
        ("임원 보수 체계 개편안",
         "[대외비] 임원 보수 체계 개편안(가상 데이터).\n"
         "성과급 상한을 기본급의 180%로 조정하고 2027년 1월부터 시행한다.\n"
         f"식별 문구: {CANARY_EXEC}"),
    ]


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
    token = lab_token(os.environ)

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
        hired = HIRE_DATES[i - 1]
        cur.execute("INSERT INTO employees(user_id,name,dept,title,ext,emp_no,hire_date) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                    (uid[name], disp, dept, TITLES[role], str(2000 + i), f"NX-{hired[:4]}-{i:03d}", hired))
    for j, (ename, edept, etitle, eext) in enumerate(EXTRA_EMPLOYEES, start=len(USERS) + 1):
        hired = HIRE_DATES[j - 1]
        cur.execute("INSERT INTO employees(name,dept,title,ext,emp_no,hire_date) VALUES(%s,%s,%s,%s,%s,%s)",
                    (ename, edept, etitle, eext, f"NX-{hired[:4]}-{j:03d}", hired))

    cur.executemany("INSERT INTO documents(title,body) VALUES(%s,%s)", [
        ("사내 복지 제도 안내", "복지 포인트와 휴가 제도를 안내합니다."),
        ("2026년 4분기 업무 일정", "분기 마감과 평가 일정을 공유합니다."),
        ("정보보안 수칙", "비밀번호 관리와 자료 반출 기준을 안내합니다."),
    ])
    cur.executemany("INSERT INTO confidential_documents(title,body) VALUES(%s,%s)", confidential_documents(token))
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

    def add_approval(title, body, requester, approvers, expense_id=None, doc_type="general", urgency="normal", cc=(), done=None):
        """결재 문서와 결재선을 만든다. 첫 결재자만 pending, 나머지는 순서를 기다린다(waiting).
        done 이 있으면 모두 승인된 완료 문서로 만든다(done = 마지막 결재자의 의견)."""
        cur.execute("INSERT INTO approvals(title,body,requester_id,expense_id,doc_type,urgency) VALUES(%s,%s,%s,%s,%s,%s)",
                    (title, body, uid[requester], expense_id, "expense" if expense_id else doc_type, urgency))
        approval_id = cur.lastrowid
        for n, name in enumerate(approvers, start=1):
            if done is not None:
                cur.execute("INSERT INTO approval_steps(approval_id,step_no,approver_id,status,reason,decided_at) VALUES(%s,%s,%s,'approved',%s,NOW())",
                            (approval_id, n, uid[name], done if n == len(approvers) else None))
            else:
                cur.execute("INSERT INTO approval_steps(approval_id,step_no,approver_id,status) VALUES(%s,%s,%s,%s)",
                            (approval_id, n, uid[name], "pending" if n == 1 else "waiting"))
        for name in cc:
            cur.execute("INSERT INTO approval_cc(approval_id,user_id) VALUES(%s,%s)", (approval_id, uid[name]))
        if done is not None:
            cur.execute("UPDATE approvals SET status='approved', current_step=%s, decided_at=NOW() WHERE id=%s", (len(approvers), approval_id))

    add_approval("팀 회식비 결재 요청", "9월 팀 회식비입니다.", "kim", ["lee"], exp["kim_a"])
    add_approval("고객사 출장비 결재 요청", "고객사 방문 출장비입니다.", "han", ["lee", "admin"], exp["han_a"])  # 2단계 결재선
    add_approval("연차 사용 신청", "10월 연차를 신청합니다.", "kim", ["lee"])
    add_approval("광주 고객사 미팅 출장", "출장지: 광주 ○○테크\n출장 기간: 다음 주 화~수\n출장 목적: 계약 갱신 협의\n예상 경비: 380,000원\n동행자: 없음",
                 "park", ["choi", "admin"], doc_type="trip", urgency="urgent", cc=["kim"])
    add_approval("개발용 노트북 구매 요청", "구매 품목: 개발용 노트북 2대\n수량·단가: 2대 × 1,800,000원\n예상 금액: 3,600,000원\n구매 사유: 신규 입사자 장비",
                 "han", ["lee"], doc_type="purchase", cc=["park"], done="예산 범위 안입니다. 진행하세요.")
    # 지출결의서 샘플: kim 이 올린 팀 회식비(이체), 결재 대기. 금액은 수량×단가 합계(서버와 같은 규칙).
    cur.execute("INSERT INTO approvals(title,body,body_html,requester_id,doc_type) VALUES(%s,%s,1,%s,'expenditure')",
                ("9월 팀 회식비 지출결의서", "<p>위와 같이 지출하고자 결의합니다.</p>", uid["kim"]))
    exd_id = cur.lastrowid
    cur.execute("INSERT INTO approval_steps(approval_id,step_no,approver_id,status) VALUES(%s,1,%s,'pending')", (exd_id, uid["lee"]))
    exd_items = [("팀 회식", "9월 정기 회식", 4, 30000), ("음료", None, 2, 5000)]
    cur.execute("INSERT INTO expenditures(approval_id,spend_date,account_name,pay_method,payee,payee_account,evidence,total_amount) "
                "VALUES(%s,CURDATE(),'복리후생비','transfer','○○식당','국민 123-456-789012 ○○식당',%s,%s)",
                (exd_id, "tax_invoice", sum(q * u for _, _, q, u in exd_items)))
    for n, (item, memo, qty, price) in enumerate(exd_items, start=1):
        cur.execute("INSERT INTO expenditure_items(approval_id,line_no,item,memo,qty,unit_price,amount) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                    (exd_id, n, item, memo, qty, price, qty * price))
    cur.executemany("INSERT INTO posts(board,author_id,title,body) VALUES(%s,%s,%s,%s)", [
        ("notice", uid["admin"], "보안 점검 안내", "이번 주 금요일 보안 점검이 있습니다."),
        ("free", uid["kim"], "점심 메뉴 추천해 주세요", "오늘 뭐 먹을까요?"),
        ("free", uid["park"], "스터디 모집", "보안 스터디 같이 하실 분 구해요."),
    ])
    # 근태: 영업팀·개발팀 직원의 최근 평일 5일(출근 08:50~09:10, 퇴근 18:00대). 하루는 지각으로 둔다.
    today = datetime.now(KST).date()
    days, d = [], today - timedelta(days=1)
    while len(days) < 5:
        if d.weekday() < 5:
            days.append(d)
        d -= timedelta(days=1)
    for n, name in enumerate(("kim", "han", "park", "lee", "choi")):
        for k, day in enumerate(days):
            cin = datetime.combine(day, time(8, 50)) + timedelta(minutes=(n * 3 + k * 5) % 20)      # 08:50~09:09
            cur.execute("INSERT INTO attendance(user_id,work_date,check_in,check_out) VALUES(%s,%s,%s,%s)",
                        (uid[name], day, cin, datetime.combine(day, time(18, (n + k * 7) % 40))))
    # 휴가: kim 연차 신청(대기), han 연차(lee 승인), park 병가(개발팀 최도윤 승인)
    nxt = today + timedelta(days=7)
    while nxt.weekday() > 3:
        nxt += timedelta(days=1)
    cur.execute("INSERT INTO leave_requests(user_id,leave_type,start_date,end_date,days,reason) VALUES(%s,'annual',%s,%s,2,%s)",
                (uid["kim"], nxt, nxt + timedelta(days=1), "가족 행사"))
    past = today - timedelta(days=14)
    while past.weekday() > 4:
        past -= timedelta(days=1)
    cur.execute("INSERT INTO leave_requests(user_id,leave_type,start_date,end_date,days,reason,status,decided_by,decided_at) "
                "VALUES(%s,'annual',%s,%s,1,%s,'approved',%s,NOW())", (uid["han"], past, past, "개인 사유", uid["lee"]))
    cur.execute("INSERT INTO leave_requests(user_id,leave_type,start_date,end_date,days,reason,status,decided_by,decided_at) "
                "VALUES(%s,'sick',%s,%s,1,%s,'approved',%s,NOW())", (uid["park"], past, past, "병원 진료", uid["choi"]))
    con.commit()
    cur.execute("SELECT (SELECT COUNT(*) FROM users),(SELECT COUNT(*) FROM documents),"
                "(SELECT COUNT(*) FROM confidential_documents),(SELECT COUNT(*) FROM posts)")
    print("seeded:", dict(zip(("users", "documents", "confidential", "posts"), cur.fetchone())), "db=", args.db)


if __name__ == "__main__":
    main()
