# NEXUS WORK — 김태빈 작업 전체 정리

> 목적: 지금까지 내가 무엇을 구현했고, 현재 무엇을 진행 중이며, 발표에서 무엇을 설명해야 하는지 한 번에 확인하기 위한 개인 기준 문서  
> 기준일: 2026-10-26  
> 담당: 김태빈 — 보안 관제 / Wazuh / Graylog / n8n / AI-XDR

---

# 1. 내 역할 한 줄 요약

**NEXUS WORK에서 발생하는 보안 이벤트를 Wazuh·Graylog로 수집/탐지하고, n8n으로 자동화한 뒤, 현재는 여러 탐지 이벤트를 AI가 2차 분석하여 주간에는 승인형, 야간에는 제한적 자동 대응까지 이어지는 AI-XDR 관제 파이프라인을 구현하고 있다.**

발표용으로 더 짧게 말하면:

> **“Wazuh·Graylog 기반 탐지와 n8n 자동 대응을 구축하고, 이를 AI-XDR 구조로 확장해 여러 보안 이벤트를 상관분석하고 위험도에 따라 대응하도록 구현했습니다.”**

---

# 2. 현재 전체 시스템 구조

## 2.1 장비 역할

- `192.168.3.10` : pfSense / 외부 진입점
- `192.168.3.14` : NEXUS Flask 포털 서버
- `192.168.3.15` : Graylog / Wazuh Manager / n8n 관제 환경

> 예전 문서 일부에는 `.10`이 Flask처럼 적힌 내용이 있으므로 현재 기준은 위 구조로 통일한다.

## 2.2 기존 관제 흐름

```text
공격자 / Kali
    ↓
pfSense / NEXUS Flask / Wazuh Agent
    ↓
Graylog / Wazuh
    ↓
R1~R12 탐지
    ↓
n8n
    ↓
Ticket / Discord / 일부 자동 대응
```

## 2.3 현재 확장 중인 AI-XDR 흐름

```text
보안 이벤트 발생
    ↓
Graylog / Wazuh 1차 탐지
    ↓
n8n / AI-XDR 수집 경로
    ↓
같은 출발지 기준 일정 시간 이벤트 집계
    ↓
AI 2차 분석
    ↓
threat_score / confidence / verdict / reasoning
    ↓
정책 Gate
    ↓
주간 : 관리자 승인형 대응
야간 : 조건 충족 시 제한적 자동 대응
    ↓
기존 Ticket / Discord / IP 차단 체계 재사용
```

핵심 변화:

```text
기존
룰 탐지 → 바로 대응

AI-XDR
룰 탐지 → 여러 이벤트 묶음 → AI 2차 판단 → 정책 검사 → 대응
```

---

# 3. 지금까지 내가 한 작업

## 3.1 Wazuh Agent / Manager 연동

### 구현한 내용

- Windows NEXUS 서버 Wazuh Agent 연동
- Wazuh Manager와 Agent 통신 확인
- 문서함 / 업로드 영역 FIM 설정
- 파일 생성 / 수정 / 삭제 이벤트 확인

### 문제 해결

Wazuh 이벤트를 Graylog로 UDP 전달할 때 JSON이 잘리는 문제가 있어 필요한 Rule만 선별하여 전달하고 Wazuh 입력 포트를 별도로 분리했다.

### 발표 포인트

> “호스트 및 파일 변경 이벤트는 Wazuh Agent가 감시하며, 필요한 탐지 이벤트만 SIEM으로 전달하도록 구성했습니다.”

---

## 3.2 Graylog 입력 구조 구성

### 주요 입력

- Flask App → GELF UDP `12201`
- Wazuh → Raw/Plaintext UDP `5140`
- pfSense → Syslog UDP `1514` 계열 구조 사용/검토

### 구현·확인 내용

- Flask 보안 로그 Graylog 수신 확인
- `event_type`, `src_ip`, `severity`, `source_component`, timestamp 등 필드 기반 검색
- Wazuh / Flask / pfSense 입력 분리

### 발표 포인트

> “네트워크·애플리케이션·호스트 로그를 Graylog에 모으되 입력 경로를 분리하고 공통 필드로 정규화해 탐지 룰에서 사용할 수 있도록 구성했습니다.”

---

## 3.3 R1~R12 보안 탐지 룰

- **R1** 로그인 실패 반복 / 계정 잠금
- **R2** 직접 Prompt Injection
- **R3** AI Tool 권한 위반 / 거부
- **R4** 비정상 내부 API 접근
- **R5** Account Spray
- **R6** 잠금 이후 재시도
- **R7** 비업무시간 로그인 성공
- **R8** 반복 404 / 웹 경로 스캔
- **R9** 비인가 관리자 경로 접근
- **R10** 기밀 접근 거부
- **R11** 반복 AI Tool 권한 거부
- **R12** 간접 콘텐츠 기반 보호 Tool 거부

### 내가 특히 검증한 영역

- Graylog 실제 필드 기반 탐지
- 반복 이벤트 집계
- R8 반복 404 테스트
- src_ip별 탐지 흐름
- n8n Webhook 연계

---

## 3.4 R8 반복 404 탐지 검증

Kali / 테스트 PC에서 존재하지 않는 경로를 반복 요청해 탐지를 검증했다.

예:

```bash
for i in $(seq 1 35); do
  curl -s -o /dev/null -w "%{http_code}\n" \
  "http://192.168.3.10:5070/r8-test-$i"
  sleep 0.3
done
```

흐름:

```text
Kali / 테스트 PC
    ↓
404 반복 요청
    ↓
NEXUS 로그
    ↓
Graylog R8
    ↓
n8n
    ↓
Ticket / Discord
```

추가 검증:
- `ip_block_enabled=false`에서 실제 차단 없음 확인
- Ticket / Discord 경로 유지 확인
- 이후 실제 자동 차단 E2E도 별도 검증

---

## 3.5 n8n 자동 대응 Workflow

기존 흐름:

```text
Graylog Event
    ↓
Webhook
    ↓
정규화
    ↓
Ticket 처리
    ↓
Discord
    ↓
조건에 따라 자동 대응
```

구현/검증:
- 탐지 payload 정규화
- Rule ID / src_ip / user / event_type 필드 처리
- 중복 Alert 방지
- `skip_side_effects`
- Ticket 생성/갱신
- Discord 알림
- IP block gate
- whitelist
- R5/R6/R8 자동 차단 조건

---

## 3.6 IP 자동 차단 API 연동

최종 구조:

```text
n8n
  ↓ REST API
Flask
  ↓
block_ip()
  ↓
blocked_ips
```

장점:
- MySQL 3307 외부 노출 불필요
- 기존 Flask 보안 로직 재사용
- whitelist 적용
- 차단/해제 로직 중앙화

검증:
- TEST-NET IP block
- list
- unblock
- R5/R6/R8 15분 자동 차단 흐름 검증

### 발표 포인트

> “SOAR가 DB를 직접 수정하지 않고 Flask의 인증된 REST API를 호출하도록 설계해 데이터베이스 노출을 줄이고 기존 차단 정책을 재사용했습니다.”

---

## 3.7 whitelist 안전장치

자동 차단 시 정상 운영 장비가 차단되지 않도록 whitelist 사용.

목적:
- 핵심 관리 장비 보호
- 자동화/AI 오탐 시 안전장치 확보

---

## 3.8 Incident Ticket 기본 구조

현재 Ticket은 이벤트 한 건마다 새로 생성하지 않는다.

```text
같은 src_ip
    ↓
열린 Ticket 존재
    ↓
기존 Ticket 갱신
```

누적:
- `event_count`
- `first_seen`
- `last_seen`
- `rule_ids`
- `user_names`
- `src_ip`
- 상태
- latest event

중복 방지:
- `alert_id` 기반 별도 alerts 테이블
- unique 조건
- 중복 시 `skip_side_effects`

현재 한계:
- IP 중심 grouping
- 같은 IP의 서로 다른 Rule도 같은 열린 Ticket으로 합쳐질 수 있음
- Incident 시간 만료 기준 개선 가능
- AI assessment 연결은 AI-XDR에서 확장 중

---

## 3.9 Discord 탐지 알림 포맷 개선

기존 한 줄 메시지를 관제형 여러 줄 메시지로 개선.

개선:
- Rule ID 중복 제거
- 빈 필드 행 생략
- severity / decision 대문자 표시
- KST 표시
- Ticket 신규/업데이트 표시

---

# 4. 현재 하고 있는 작업 — AI-XDR

## 4.1 왜 추가하는가

기존 룰 방식은 각각의 이벤트는 잘 탐지하지만 여러 행위를 하나의 공격 흐름으로 이해하는 데 한계가 있다.

예:

```text
로그인 대입
→ 404 경로 스캔
→ 디코이 접근
→ 관리자 경로 접근
→ AI Tool 권한 위반
```

그래서:

```text
여러 보안 이벤트
→ 상관분석
→ AI 2차 판단
→ 위험도 산정
→ 대응
```

구조로 확장 중이다.

---

## 4.2 AI-XDR에서 새로 구현한 것

Codex 로컬 구현 기준:

- AI-XDR 이벤트 수집 구조
- 3분 aggregation window
- `src_ip` 중심 grouping
- `alert_id` dedup
- AI 입력 metadata allowlist
- AI 응답 JSON Schema 검증
- `assessment_id`
- `threat_score`
- `confidence`
- `verdict`
- `reasoning`
- `recommended_actions`
- malformed JSON fail-safe
- timeout fail-safe
- unknown action 차단
- KST 주간/야간 gate
- 관리자 승인 상태
- 야간 자동 대응 gate
- 기존 Ticket과 AI assessment 연결 구조
- 관리자 AI-XDR 화면 초안
- XDR DB schema/migration 초안
- n8n AI-XDR 후보 JSON
- 관련 테스트 추가

---

## 4.3 이벤트 집계 방식

기본 3분 window.

```text
src_ip 존재 → ip:<src_ip>
src_ip 없음 → user:<user>
둘 다 없음 → alert 단위
```

목적:
이벤트를 하나씩 AI에게 보내는 것이 아니라 같은 공격 주체로 보이는 이벤트를 한 묶음으로 전달.

---

## 4.4 AI에 보내는 데이터

예:

```json
{
  "rule_ids": ["R5", "R8"],
  "event_types": ["login_failure", "not_found"],
  "event_count": 20,
  "first_seen": "...",
  "last_seen": "...",
  "same_source": true,
  "events": []
}
```

제외:
- prompt 원문
- 문서 본문
- token
- cookie
- credential
- 불필요한 개인정보

현재 실제 IP 자체도 모델 입력에서 제외하도록 설계되어 있고 서버 측 grouping으로 동일 출발지 여부를 관리한다.

---

## 4.5 AI가 반환하는 결과

```json
{
  "assessment_id": "AI-...",
  "threat_score": 91,
  "confidence": 0.95,
  "verdict": "MALICIOUS",
  "reasoning": "계정 대입 후 경로 스캔이 연속 발생",
  "recommended_actions": ["block_ip"]
}
```

검증:
- threat_score : 0~100
- confidence : 0~1
- verdict allowlist
- action allowlist
- reasoning 길이 제한
- assessment_id 일치

잘못된 응답은 자동 조치하지 않는다.

---

## 4.6 현재 점수 방식

현재는 코드가 룰별 점수를 직접 합산하지 않는다.

```text
이벤트 묶음
→ AI가 threat_score 제시
→ 코드가 형식/범위 검증
→ 추가 정책 조건 검사
```

즉 점수는 AI가 제시하지만 대응 결정은 점수 하나만으로 하지 않는다.

---

## 4.7 대응 Policy Gate

자동 대응 전 확인:
- Rule 자동 대응 허용 범위
- IP 유효성
- whitelist
- Event 최신성
- AI `block_ip` 권고
- `verdict == MALICIOUS`
- `XDR_AUTO_ENABLED`
- live 모드
- 시간대 정책
- confidence 기준
- threat_score 기준

핵심:

```text
AI 95점 ≠ 바로 차단
```

반드시 Policy Gate 통과 필요.

---

## 4.8 주간 / 야간 대응

### 주간
`08:00 ~ 20:00 KST`

```text
AI 분석
→ PENDING
→ 관리자 확인
→ 승인 / 거부 / 오탐
```

### 야간

```text
MALICIOUS
+ 높은 score
+ confidence 충족
+ R5/R6/R8
+ whitelist 아님
+ 최신 이벤트
+ live
→ 15분 IP 차단
```

주말 정책은 최종 확정 필요.

---

## 4.9 AI 오류 시 Fail-Safe

다음 상황에서 실제 차단 금지:
- timeout
- JSON 파싱 오류
- 필수 필드 누락
- score/confidence 범위 오류
- unknown verdict
- unknown action

결과:
- `REVIEW_REQUIRED`
- 또는 `NO_ACTION`

### 발표 포인트

> “생성형 AI의 판단을 직접 실행 권한으로 연결하지 않고, 구조화된 출력 검증과 결정적 정책 Gate를 한 번 더 통과하도록 설계했습니다.”

---

# 5. 현재 AI-XDR 구현 상태

## 로컬 구현됨
- AI-XDR 핵심 Python 코드
- 3분 집계
- 중복 방지
- AI 응답 검증
- fail-safe
- 주간/야간 정책
- 승인 상태
- 자동 차단 정책
- 관리자 XDR 화면 초안
- XDR DB schema
- migration script
- n8n AI-XDR candidate
- 관련 테스트

현재 보고 기준 관련 테스트 **127개 통과**.

## 아직 운영 반영 안 됨
- `.14` 실제 서버 배포
- 실제 DB migration
- 실제 Published n8n AI-XDR 반영
- 실제 Groq/Ollama E2E
- 실제 Graylog → AI-XDR E2E
- 실제 관리자 승인 E2E
- 실제 AI 야간 자동차단

---

# 6. n8n AI-XDR 상태

후보:
`nexus-alert-v2-ai-xdr-candidate.json`

특징:
- 기존 Ticket 유지
- 기존 Discord 유지
- AI-XDR 전달 경로 추가
- 기존 직접 차단과 AI 차단 중복 방지 고려
- `active=false`
- 아직 import/publish 안 함

중요 문제:

```text
기존 R5/R6/R8 즉시 차단
+
AI-XDR R5/R6/R8 차단
```

이 두 경로가 동시에 실행되면 안 된다.

AI-XDR 후보에서는 기존 gate 비활성화 방향이지만 실제 Published n8n에는 아직 미반영.

---

# 7. pfSense / 네트워크 연동 예정

예정 구조:

```text
AI-XDR / n8n
    ↓
Flask blocked_ips
    ↓
차단 IP Feed
    ↓
pfSense XDR_BLOCKED_IPS Alias
    ↓
Firewall Block
```

권장:
- Flask plain-text 차단 IP feed
- pfSense URL Table Alias 사용
- 실제 방화벽 Rule/Alias 적용은 네트워크 담당과 연동

---

# 8. 앞으로 남은 작업

1. 최신 n8n 기준 AI-XDR candidate 정리
2. severity 입력 호환 보완
3. AI 입력 상관정보 점검
4. migration 안전성 검증
5. 실제 Groq/Ollama provider 검증
6. 테스트 DB migration 검증
7. n8n Dry-Run E2E
8. `.14` 실제 배포
9. DB migration
10. n8n import / test / publish
11. 실제 주간 승인 E2E
12. 실제 야간 자동대응 E2E
13. pfSense XDR 차단 연동
14. Incident Ticket 고도화
15. 발표용 캡처 / 영상

---

# 9. 발표에서 내가 말해야 할 핵심

## 기존 관제

> “NEXUS 포털과 Wazuh에서 발생하는 보안 이벤트를 Graylog로 통합하고, R1~R12 룰을 이용해 로그인 공격, 웹 스캔, 권한 위반, AI Tool 오남용 등을 탐지했습니다.”

## SOAR 자동화

> “Graylog 탐지 결과는 n8n으로 전달되며, 중복 제거 후 Incident Ticket과 Discord 알림을 생성하고, 일부 고위험 이벤트는 Flask REST API를 통해 IP를 자동 차단하도록 구성했습니다.”

## AI-XDR 추가 이유

> “기존 룰 방식은 각각의 이벤트는 잘 탐지하지만 여러 행위를 하나의 공격 흐름으로 이해하는 데 한계가 있었습니다. 그래서 같은 출발지의 이벤트를 일정 시간 묶어 AI가 공격 의도와 위험도를 2차 판정하도록 확장했습니다.”

## AI가 바로 차단하지 않는 이유

> “AI가 낸 점수를 그대로 실행하면 오탐 위험이 있으므로, 실제 대응 전에는 Rule allowlist, whitelist, confidence, 이벤트 최신성, 시간대 등을 코드 기반 Policy Gate에서 다시 검사합니다.”

## 주간 / 야간

> “주간에는 Human-in-the-Loop 방식으로 승인 후 대응하고, 야간에는 엄격한 조건을 만족하는 고위험 이벤트만 제한적으로 자동 대응하도록 설계했습니다.”

## XDR 설명

> “XDR은 단순히 점수를 매기는 시스템이 아니라, 네트워크·애플리케이션·호스트 등 서로 다른 보안 소스의 이벤트를 연결해 하나의 공격 흐름으로 판단하고 대응하는 구조입니다.”

---

# 10. 발표 시연 추천 흐름

```text
1. Kali 공격
2. NEXUS 보안 로그 발생
3. Graylog Rule 탐지
4. n8n 실행
5. Incident Ticket / Discord
6. AI-XDR 이벤트 집계
7. AI threat_score / verdict
8. 주간 승인 또는 야간 자동 대응
9. IP 차단 확인
10. 차단 해제 후 정상 복구
```

추천 데모 케이스:
- R8 반복 404
- R5 + R8 복합 흐름
- whitelist 차단 방지
- AI 오류 시 REVIEW_REQUIRED

---

# 11. 발표용 핵심 용어

### SIEM
여러 로그를 모으고 검색·상관분석·탐지. NEXUS에서는 주로 Graylog.

### EDR / Host Monitoring
호스트 파일/이벤트 감시. NEXUS에서는 Wazuh.

### SOAR
탐지 이후 대응 자동화. NEXUS에서는 n8n.

### XDR
서로 다른 보안 영역의 이벤트를 연결해 하나의 공격 흐름으로 판단하고 대응.

### AI-XDR
기존 XDR 상관분석에 생성형 AI의 2차 분석을 추가한 구조.

### Threat Score
AI가 제시하는 위험도. 자동 대응은 점수 하나만으로 결정하지 않음.

### Confidence
AI 판정 신뢰도.

### Verdict
- BENIGN
- SUSPICIOUS
- MALICIOUS
- REVIEW_REQUIRED

### Fail-Safe
AI 오류 시 차단하지 않고 검토 상태로 보내는 안전장치.

### Human-in-the-Loop
AI가 권고하더라도 사람이 최종 승인.

---

# 12. 현재 미검증 사항

완료라고 말하면 안 되는 것:
- 실제 Groq/Ollama AI-XDR 운영 호출
- 운영 DB XDR migration
- 실제 Published n8n AI-XDR
- 실제 야간 AI 자동차단
- pfSense XDR Alias 연동
- Wazuh Active Response
- AI-XDR 전체 실환경 E2E

---

# 13. 완료 / 진행 중 / 예정 구분

## 완료 또는 실제 검증 경험 있음
- Wazuh Agent / FIM
- Flask GELF → Graylog
- Graylog 탐지 규칙
- R1~R12 기반 탐지 구조
- R8 404 재현
- n8n Webhook
- Ticket
- Discord
- duplicate 처리
- TEST-NET Block/List/Unblock
- R5/R6/R8 차단 API 기반
- whitelist
- R8 실제 E2E 차단 검증

## 로컬 구현 완료 / 운영 미반영
- AI-XDR Python
- AI 이벤트 aggregation
- AI response validator
- threat_score/confidence/verdict 구조
- AI fail-safe
- KST 주간/야간 gate
- 승인 workflow 기반
- XDR DB schema/migration
- 관리자 XDR 화면
- n8n AI-XDR candidate

## 진행 중
- AI-XDR 통합 검증
- 실제 provider 연동 확인
- n8n 최신본과 candidate 통합
- DB migration 검증
- dry-run E2E

## 이후 예정
- 실제 운영 배포
- 실제 AI 판정
- 주간 승인 E2E
- 야간 자동대응 E2E
- pfSense XDR 차단 연동
- Incident Ticket 고도화
- 최종 발표용 캡처/영상

---

# 14. 포트폴리오식 표현

### 보안 관제 환경 구축
- Wazuh Agent/Manager 기반 파일 무결성 모니터링
- Graylog GELF/Raw/Syslog 입력 분리 및 보안 이벤트 정규화
- 애플리케이션/호스트/네트워크 로그 통합 관제

### 탐지 엔지니어링
- 계정 공격, 경로 스캔, 인증/인가 위반, AI Tool 오남용 등 R1~R12 탐지 정책 구현 및 검증
- 반복 이벤트 기반 상관 탐지와 출발지 IP별 분류

### SOAR
- Graylog Webhook → n8n 자동 대응
- Incident Ticket / Discord 알림
- REST API 기반 IP 차단 및 해제
- whitelist / duplicate / fail-safe 정책

### AI-XDR
- 보안 이벤트 시간창 집계
- 생성형 AI 기반 2차 위협 판정
- structured JSON validation
- Threat Score / Confidence / Verdict
- 주간 Human-in-the-Loop
- 야간 제한 자동화
- Policy Gate 및 Fail-Safe

---

# 15. 최종 한 문장

**내가 NEXUS WORK에서 한 일은 단순히 보안 로그를 보는 것이 아니라, 공격을 실제로 수집·탐지하고 여러 이벤트를 사건 단위로 연결하며 n8n과 AI-XDR을 통해 대응까지 이어지는 관제 자동화 체계를 구축한 것이다.**
