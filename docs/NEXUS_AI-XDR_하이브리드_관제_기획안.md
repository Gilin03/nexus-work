# 🛡️ NEXUS 차세대 AI-XDR 아키텍처 및 하이브리드 자동대응 기획안

> **문서 버전:** v2.0 (AI-Augmented XDR)  
> **기획자:** 홍주형 (포털 아키텍트 & 보안 총괄)  
> **협업 대상:** 김태빈 (보안 관제 / Wazuh / Graylog / n8n 분석가), 이시헌 (네트워크 / pfSense 엔지니어), 진혜정 (시스템 관리자)  
> **문서 목적:** 실시간 네트워크/웹 트래픽을 룰셋으로 1차 필터링한 후, **AI가 주기적으로 위협을 심층 판정**하며, **일반 시간(주간)은 반자동(승인형), 특정 시간(심야/부재중)은 완전 자동**으로 능동 대응을 집행하는 차세대 AI-SOC & XDR 파이프라인 수립

---

## 1. 추진 배경 및 핵심 콘셉트

### 1.1 기존 단일 룰 기반 관제의 한계
- **오탐(False Positive)과 알람 피로:** 정적 임계치(예: 5분 내 5회 실패 시 무조건 차단) 방식은 정상 사용자의 오타나 일시적 네트워크 오류까지 차단할 위험이 존재.
- **문맥(Context) 파악 불가:** 공격자가 탐지 룰을 회피하기 위해 시간 간격을 늘리거나 완곡한 표현으로 프롬프트 인젝션을 시도할 때 정적 룰은 무력화됨.
- **야간 관제 공백:** 24시간 상주 보안 인력이 없는 환경에서는 야간 침투 시 골든타임(Golden Hour)을 놓침.

### 1.2 사용자 요구사항 반영: AI 기반 하이브리드 XDR 콘셉트
```
1. [실시간 트래픽 수집] ➔ pfSense(네트워크) + 포털(웹/계정) + Wazuh(호스트) 실시간 스트림
2. [룰셋 1차 필터링]   ➔ R1~R12 및 디코이(허니팟) 시그니처로 의심 트래픽 급속 선별
3. [AI 주기적 심층 판정]➔ 걸러진 이벤트 버스트를 AI(Groq/Ollama)에 전달하여 공격 의도/위협도 종합 판정
4. [시간대별 대응 모드] ➔ 일반 업무시간: '반자동(Human-in-the-Loop)' / 심야·특정시간: '완전 자동(Zero-Touch)'
```

---

## 2. NEXUS AI-XDR 전체 아키텍처

```mermaid
flowchart TD
    subgraph Layer1_Traffic ["1. 실시간 트래픽 & 텔레메트리 (Ingestion)"]
        direction LR
        PFS["[Network] pfSense 트래픽<br/>• 방화벽 통과/드롭 트래픽<br/>• HAProxy HTTP 접근 로그"]
        WEB["[Web Portal] NEXUS 앱<br/>• 계정 인증 / 권한 검사<br/>• 디코이(/.env) 접근<br/>• AI 채팅 / 첨부파일 입력"]
        HOST["[Host/EDR] Wazuh Agent<br/>• FIM 소스코드/업로드 감시<br/>• 시스템 이상 프로세스"]
    end

    subgraph Layer2_RuleFilter ["2. 룰셋 1차 고속 필터링 (Rule-based Fast Filter)"]
        direction TB
        GL["Graylog Stream & Ruleset (R1~R12)<br/>• 비인가 시도 선별<br/>• 임계치 기반 의심 후보군 추출"]
        DEC["Decoy / Honeytrap Sensor<br/>• 비정상 스캔 즉시 태깅"]
    end

    subgraph Layer3_AIEngine ["3. AI 주기적 심층 판정 엔진 (AI Assessment Engine)"]
        direction TB
        Collector["이벤트 버퍼 & 컨텍스트 집계기<br/>(5분 주기 / 버스트 발생 시 트리거)"]
        AIBrain["NEXUS AI 보안 분석가 (Groq / Ollama)<br/>• 공격자 킬체인 의도 분석<br/>• 오탐 여부 검증 (정상 행위 배제)<br/>• 위협 점수(0~100) 및 신뢰도 산출"]
    end

    subgraph Layer4_HybridResponse ["4. 시간대별 하이브리드 대응 집행 (Hybrid Response Engine)"]
        direction TB
        TimeCheck{"시간대 판정<br/>(Scheduler / Time Gate)"}
        
        subgraph DayMode ["일반 업무 시간 (08:00 ~ 20:00)"]
            SemiAuto["[반자동 모드 (Semi-Auto)]<br/>• 관제 대시보드 권고 티켓 발행<br/>• Discord 알림 ('차단 승인' 버튼)<br/>• 보안관제사 확인 후 1클릭 집행"]
        end
        
        subgraph NightMode ["야간 / 주말 / 특정 시간 (20:00 ~ 익일 08:00)"]
            FullAuto["[완전 자동 모드 (Full-Auto)]<br/>• AI 위협점수 80점 이상 즉시 집행<br/>• 사전 격리 후 사후 보고 티켓 생성"]
        end
    end

    subgraph Layer5_Remediation ["5. 다계층 통합 격리 집행 (Multi-Tier Enforcement)"]
        Act_PFS["pfSense 방화벽 IP 차단 (Alias API)"]
        Act_Portal["포털 blocked_ips 등록 & 세션 즉시 만료"]
        Act_Wazuh["Wazuh 악성 파일 격리 / 프로세스 종료"]
    end

    Layer1_Traffic -->|Syslog / GELF| Layer2_RuleFilter
    Layer2_RuleFilter -->|선별된 의심 이벤트| Collector
    Collector --> AIBrain
    AIBrain -->|종합 판정 결과 (JSON)| TimeCheck
    TimeCheck -->|일반 시간| SemiAuto
    TimeCheck -->|야간/특정시간| FullAuto
    SemiAuto -->|관리자 승인| Layer5_Remediation
    FullAuto -->|즉시 자동 트리거| Layer5_Remediation
```

---

## 3. 세부 동작 프로세스

### 3.1 1단계: 룰셋 1차 필터링 (Fast Path)
대량의 정상 트래픽을 AI에 모두 보내면 API 비용 및 지연이 발생하므로, 기존 구축된 **Graylog 룰셋(R1~R12)**으로 1차 필터링합니다.

* **수집 대상:**
  - `R1/R5/R6`: 비정상 로그인 실패 및 계정 대입 의심
  - `R8`: 404 경로 대량 스캔
  - `R2`: 완화된 표현을 포함한 프롬프트 인젝션 의심
  - `R3/R11`: 기밀 문서 Tool 반복 호출 및 권한 거부
  - `Decoy`: `/.env`, `/backup.sql` 등 허니팟 타격

---

### 3.2 2단계: AI 심층 판정 엔진 (AI Deep Triage)
1차 필터링된 이벤트를 묶어(배치 윈도우 1~5분 또는 10건 이상 버스트 시) AI 분석 모델(Groq Llama-3.3-70b / Ollama qwen2.5)에 전달합니다.

#### AI 분석 프롬프트 및 응답 구조 (JSON Schema)
```json
{
  "assessment_id": "AI-TRG-20261026-0042",
  "attacker_ip": "192.168.7.77",
  "attack_type": "Multi-Stage Account Spray & Decoy Recon",
  "threat_score": 88,
  "confidence": 0.94,
  "verdict": "MALICIOUS", 
  "reasoning": "단순 오타가 아닌 5분 내 6개 서로 다른 계정 순차 대입 후 /.env 디코이 경로 접근 확인됨. 고의적 침투 시도로 판정.",
  "mitre_technique": ["T1110.003", "T1595.002"],
  "recommended_actions": [
    {"target": "portal", "action": "block_ip", "duration_minutes": 180},
    {"target": "pfsense", "action": "drop_ip"},
    {"target": "account", "action": "lock_targeted_users"}
  ]
}
```

---

### 3.3 3단계: 시간대별 하이브리드 대응 모드 (Daytime vs Nighttime)

```mermaid
sequenceDiagram
    autonumber
    participant AI as AI 심층 판정 엔진
    participant SOAR as n8n SOAR 오케스트레이터
    participant Admin as 보안관제사 (홍주형/김태빈)
    participant Core as 포털/방화벽 집행 엔진

    AI->>SOAR: AI 판정 결과 전송 (Threat Score: 88 / MALICIOUS)
    
    alt 일반 업무시간 (08:00 ~ 20:00) ➔ 반자동 모드
        SOAR->>Admin: Discord 알림 & 대시보드 승인 대기 카드 표시<br/>[판정: 악성 88점 / 대상: 192.168.7.77]<br/>🔘 [즉시 차단 승인]  🔘 [오탐 예외 처리]
        Admin->>SOAR: "즉시 차단 승인" 클릭
        SOAR->>Core: 포털 /internal/api/v1/blocked-ips 등록 & 방화벽 차단
        SOAR->>Admin: 집행 완료 및 티켓 종결 보고
    else 야간 / 특정 시간 (20:00 ~ 08:00) ➔ 완전 자동 모드
        Note over SOAR: [야간 무인 관제 모드 발동]<br/>AI 점수 80점 이상 ➔ 즉시 자동 차단 집행!
        SOAR->>Core: 포털 /internal/api/v1/ip-block 호출 (즉시 15~180분 격리)
        SOAR->>Core: pfSense Alias 차단 IP 추가
        SOAR->>Admin: [야간 긴급 자동 격리 완료 보고서] Discord 전송
    end
```

| 구분 | 주간 / 일반 업무시간 (08:00 ~ 20:00) | 야간 / 특정 시간 (20:00 ~ 익일 08:00 & 주말) |
| :--- | :--- | :--- |
| **운영 모드** | **반자동 (Semi-Automated)** | **완전 자동 (Fully Automated)** |
| **의사 결정권** | **Human-in-the-Loop** (AI 분석 권고 + 관제사 최종 승인) | **Zero-Touch AI** (AI 판정 점수 기반 즉시 집행) |
| **대응 속도** | 승인 후 1초 내 집행 (평균 검토 1~2분 소요) | **실시간 즉시 집행 (< 2초)** |
| **오탐 방지책** | 관제사가 컨텍스트 및 AI 추론 근거 확인 후 승인 | • 화이트리스트(`192.168.3.10` 등) 원천 차단 방지<br/>• AI 점수 80점 이상 임계치 엄격 적용<br/>• 임시 차단(최대 30~60분) 후 관리자 출근 시 재검토 |

---

## 4. 팀원별 상세 설정 가이드 및 전용 AI 입력 프롬프트 (R&R Playbook)

본 장은 각 담당자가 본인의 인프라를 신속하게 구성하고, 각자의 개발/운영 보조 AI(ChatGPT, Claude, Cursor, Copilot 등)에 **그대로 복사하여 입력(Copy & Paste)**할 수 있도록 구체적인 파라미터와 프롬프트를 제공합니다.

---

### 4.1 김태빈 (보안 관제 / Wazuh / Graylog / n8n 분석가)

> **운영 환경:** `192.168.3.15` (Ubuntu Linux)  
> **운영 서비스:** Wazuh Manager (1514/1515), Graylog OpenSearch (9000, GELF UDP 12201), n8n SOAR (5678)  
> **주요 역할:** 1차 룰셋 스트림 필터링 ➔ 주기적 AI 심층 분석 파이프라인 구축 ➔ 주간/야간 분기 및 다계층 능동 대응 오케스트레이션

#### 1) 세부 엔지니어링 설정 사양
1. **Graylog Stream & Alerting (1차 룰셋 필터)**
   - **Stream 이름:** `AI_TRIAGE_QUEUE`
   - **수집 조건:**
     - 포털 GELF 로그 중 `event_type IN ("login_failure", "decoy_triggered", "prompt_injection_observed", "authz_deny", "file_rejected")`
     - 또는 pfSense 방화벽 드롭 로그 중 동일 IP에서 분당 10회 이상 차단된 건
   - **전송 대상:** n8n Webhook (`POST http://192.168.3.15:5678/webhook/xdr-ingest`) 또는 3분 단위 Elastic/OpenSearch 쿼리 노드.
2. **n8n AI 심층 판정 워크플로우 구성**
   - **Trigger:** Schedule Trigger (3분 주기 배치) 또는 Webhook 버스트 수신
   - **이벤트 집계(Aggregation):** 최근 3분간 유입된 로그를 `src_ip` 기준으로 그룹화하여 시도 횟수, 접근 URL, 입력 페이로드, 실패 사유를 압축 JSON으로 구성.
   - **AI Brain 호출 노드 (HTTP Request):**
     - Endpoint: `https://api.groq.com/openai/v1/chat/completions` (Bearer 토큰) 또는 로컬 Ollama `http://127.0.0.1:11434/api/chat`
     - Model: `llama-3.3-70b-versatile` 또는 `qwen2.5:7b`
     - Response Format: `json_object` 강제 (`threat_score`, `verdict`, `reasoning`, `recommended_actions`).
3. **Time-Gate(시간대 분기) 및 대응 집행 노드**
   - **Function Node 판정:** 현재 한국 표준시(KST) 기준 `hour = (new Date().getUTCHours() + 9) % 24`.
     - `hour >= 8 && hour < 20`: **주간 모드 (Semi-Auto)**
     - `hour < 8 || hour >= 20` (또는 주말): **야간 모드 (Full-Auto)**
   - **주간 대응 분기:** Discord Webhook 노드로 카드 전송. `[즉시 차단 승인]` 버튼 링크(`http://192.168.3.15:5678/webhook/approve-block?ip=...`) 포함.
   - **야간 대응 분기:** `threat_score >= 80` 시 즉시 HTTP Request 노드로 포털 API 호출:
     - URL: `POST http://192.168.3.10:5070/internal/api/v1/ip-block`
     - Header: `Authorization: Bearer nxapi_GPTw5VbeL6x5glQUl8mg7ML-yxmKWpwi`
     - Body: `{"ip_address": "{{$json.attacker_ip}}", "rule_id": "R5", "reason": "account_spray", "duration_minutes": 15}`
     - pfSense 및 Wazuh 격리 명령 동시 호출 후 사후 보고 티켓 생성.

---

#### 🤖 [김태빈 전용 AI 입력 프롬프트 - 복사용]
아래 코드블록의 내용을 김태빈 분석가의 AI(ChatGPT, Claude, Cursor 등)에 그대로 복사하여 붙여넣으세요:

```markdown
[역할 정의]
너는 Wazuh, Graylog, n8n 기반의 Open XDR 구축 및 보안 자동화 전문 엔지니어 AI야.
현재 NEXUS 프로젝트의 보안 관제(192.168.3.15) 인프라를 담당하고 있어.

[인프라 정보]
- 관제 서버 IP: 192.168.3.15 (Wazuh Manager, Graylog, n8n 실행 중)
- 포털 서버 IP: 192.168.3.10:5070 (NEXUS 웹 포털, GELF UDP 12201로 로그 전송 중)
- 네트워크 방화벽: pfSense (Syslog 514 포워딩 수신)
- 포털 차단 API: POST http://192.168.3.10:5070/internal/api/v1/ip-block
  * Bearer 토큰: nxapi_GPTw5VbeL6x5glQUl8mg7ML-yxmKWpwi
  * Payload 예시: {"ip_address": "1.2.3.4", "rule_id": "R5", "reason": "account_spray", "duration_minutes": 15}
  * 지원되는 rule_id/reason: R5(account_spray), R6(post_lock_retry), R8(web_path_scan)

[수행할 작업 요구사항]
1. Graylog에서 포털 로그(GELF) 및 pfSense Syslog 중 R1~R12 및 디코이(/.env) 탐지 이벤트를 선별하는 Stream/Pipeline Rule 구성 방안을 알려줘.
2. n8n에서 3분 주기로 의심 로그를 집계(Aggregate)하여 Groq API(llama-3.3-70b-versatile)에 전달하고 위협 점수(threat_score: 0~100)를 JSON으로 받아오는 워크플로우를 작성해줘.
3. n8n 워크플로우 내에서 KST(한국 시간) 기준 주간(08:00~20:00)과 야간(20:00~익일 08:00)을 분기하는 Function 노드 코드를 작성해줘.
4. 주간에는 Discord로 [차단 승인] 인터랙티브 버튼이 포함된 메시지를 발송하고, 야간에는 threat_score가 80점 이상일 때 즉시 포털 API(POST /internal/api/v1/ip-block)를 호출하는 n8n 전체 워크플로우 JSON 청사진을 제공해줘.
```

---

### 4.2 이시헌 (네트워크 / pfSense 엔지니어)

> **운영 환경:** `192.168.3.1` (pfSense Firewall Appliance)  
> **운영 서비스:** Packet Filter (PF), HAProxy (L7 Reverse Proxy & WAF), pfBlockerNG / URL Table Alias  
> **주요 역할:** 방화벽/HAProxy 트래픽 로그 실시간 포워딩 ➔ XDR 동적 차단 Alias(`XDR_BLOCKED_IPS`) 연동 ➔ 보안망 L3/L4 접근 제어

#### 1) 세부 엔지니어링 설정 사양
1. **pfSense 원격 Syslog 포워딩 설정 (Remote Syslog)**
   - **경로:** pfSense WebGUI ➔ `Status` ➔ `System Logs` ➔ `Settings`
   - **설정 항목:**
     - `Enable Remote Logging`: 체크 (활성화)
     - `Remote log servers`: `192.168.3.15:514` (김태빈 관제 서버 UDP 포트)
     - `Remote Syslog Contents`:
       - [x] `Firewall Events` (방화벽 패킷 드롭/통과 이벤트)
       - [x] `HAProxy Web Proxy Events` (포털 5070 접근 트래픽 및 WAF 차단 이벤트)
2. **동적 차단 Alias (`XDR_BLOCKED_IPS`) 구축**
   - **경로:** `Firewall` ➔ `Aliases` ➔ `IP` ➔ `+ Add`
   - **설정 값:**
     - **Name:** `XDR_BLOCKED_IPS`
     - **Description:** `AI-XDR Dynamic Blacklist Synced from NEXUS Portal`
     - **Type:** `URL Table (IPs)`
     - **URL:** `http://192.168.3.10:5070/internal/api/v1/blocked-ips?format=txt&token=nxapi_GPTw5VbeL6x5glQUl8mg7ML-yxmKWpwi`
     - **Update Frequency:** `1` (또는 pfSense cron 패키지로 매 1분마다 동기화)
3. **방화벽 최상위 차단 규칙 (Quick Drop Rule)**
   - **경로:** `Firewall` ➔ `Rules` ➔ `WAN` (및 필요 시 DMZ/LAN)
   - **규칙 순서:** **최상단 1순위 (Rule 0)**
   - **Action:** `Block` 또는 `Reject`
   - **Interface:** `WAN`
   - **Address Family:** `IPv4+IPv6`
   - **Protocol:** `Any`
   - **Source:** `Single host or alias` ➔ `XDR_BLOCKED_IPS`
   - **Destination:** `Any`
   - **Log:** `Log packets handled by this rule` 체크 (차단 로그 실시간 Syslog 전송)
4. **내부망 보안 라우팅 및 허용 정책 (Inter-VLAN ACL)**
   - `192.168.3.10` (포털) ➔ `192.168.3.15` (관제): UDP 12201 (GELF) 허용
   - `192.168.3.15` (관제) ➔ `192.168.3.10` (포털): TCP 5070 (내부 차단 API) 허용
   - 관리자 PC (`192.168.3.14` 등) 및 서버 대역은 차단 대상에서 영구 예외(Bypass) 보장.

---

#### 🤖 [이시헌 전용 AI 입력 프롬프트 - 복사용]
아래 코드블록의 내용을 이시헌 엔지니어의 AI(ChatGPT, Claude, Cursor 등)에 그대로 복사하여 붙여넣으세요:

```markdown
[역할 정의]
너는 pfSense 방화벽 및 HAProxy, FreeBSD 패킷 필터링(pf) 네트워크 보안 전문가 AI야.
현재 NEXUS 프로젝트의 네트워크 인프라 및 경계 보안(192.168.3.1)을 담당하고 있어.

[인프라 정보]
- 방화벽 장비: pfSense CE (게이트웨이 IP: 192.168.3.1)
- 관제 서버 IP: 192.168.3.15 (김태빈 담당, Wazuh/Graylog, Syslog 수신 UDP 514)
- 웹 포털 서버 IP: 192.168.3.10:5070 (홍주형 담당, NEXUS 포털)
  * 차단 IP 텍스트 피드 URL: http://192.168.3.10:5070/internal/api/v1/blocked-ips?format=txt&token=nxapi_GPTw5VbeL6x5glQUl8mg7ML-yxmKWpwi
  * 피드 반환 형태: 한 줄에 하나씩 IP가 출력되는 plain/text 규격

[수행할 작업 요구사항]
1. pfSense WebGUI 및 CLI에서 방화벽 필터 로그와 HAProxy L7 접근 로그를 192.168.3.15:514(UDP)로 실시간 원격 포워딩하는 상세 설정 절차를 안내해줘.
2. pfSense의 URL Table (IPs) Alias 기능을 사용하여 `XDR_BLOCKED_IPS`라는 별칭을 만들고, 포털의 차단 IP 피드를 주기적으로 동기화하는 설정법을 단계별로 작성해줘.
3. WAN/DMZ 인터페이스 최상단에 `XDR_BLOCKED_IPS` 출발지 트래픽을 즉시 드롭하고 Syslog로 기록하는 방화벽 룰 설정 가이드를 작성해줘.
4. 만약 URL Table 갱신 지연을 줄이기 위해 pfSense CLI나 FauxAPI, 또는 ssh 상에서 `pfctl` 명령어로 악성 IP를 즉시 테이블에 삽입/삭제하는 쉘 스크립트 작성법을 제시해줘.
```

---

### 4.3 홍주형 (포털 아키텍트 & 보안 총괄)

> **운영 환경:** `192.168.3.10:5070` (Windows Server / Dev Host)  
> **운영 서비스:** Flask App (Waitress WSGI), Docker MySQL (3307 로컬 바인딩), Wazuh Agent  
> **주요 역할:** 애플리케이션 L7 보안 통제 ➔ 실시간 감사로그 스트리밍 ➔ XDR 능동 대응 수신 REST API ➔ AI Tool 및 DEFENSE_MODE 제어

#### 1) 세부 엔지니어링 설정 사양
1. **차단 및 해제 REST API 인터페이스 유지 (`app/internal_api.py`)**
   - `POST /internal/api/v1/ip-block`:
     - n8n/SOAR가 R5, R6, R8 등 침해 탐지 시 호출.
     - 필수 JSON 파라미터: `ip_address`, `rule_id`, `reason`, `duration_minutes`.
     - 화이트리스트(`127.0.0.1`, `192.168.3.10/11/14/15`) 원천 차단 방지.
   - `GET /internal/api/v1/blocked-ips?format=txt&token=...`:
     - pfSense URL Table 연동 전용 plain-text IP 리스트 피드 제공.
2. **실시간 감사 이벤트 SSE 스트림 (`/admin/audit/stream`)**
   - 관리자 보안 대시보드에서 트래픽 버스트 및 침해 시도를 실시간 모니터링할 수 있는 SSE 채널 개방.
3. **DEFENSE_MODE 핫토글 및 공격 시나리오 제어**
   - `scripts/toggle_defense.py` 및 바탕화면 배치 파일(`defense_mode_on.bat` / `off.bat`)을 통해 시연 시 3단계 데이터 유출 실습과 실시간 방어 모드를 즉각 전환.

---

#### 🤖 [홍주형 전용 AI 입력 프롬프트 - 복사용]
아래 코드블록의 내용을 홍주형 아키텍트의 AI(Antigravity, Cursor, Claude 등)에 그대로 복사하여 붙여넣으세요:

```markdown
[역할 정의]
너는 NEXUS 웹 포털(Python Flask, Waitress, MySQL, EDR Agent)의 보안 아키텍트 AI야.
현재 팀의 포털 애플리케이션 계층(192.168.3.10:5070)과 XDR 연동 백엔드를 총괄하고 있어.

[현재 구현 상태]
- Flask 백엔드: app/internal_api.py에서 SOAR 연동용 차단 API(/internal/api/v1/ip-block, /blocked-ips) 구현 완료.
- pfSense 연동: format=txt 파라미터 및 token 쿼리 스트링으로 URL Table용 줄바꿈 IP 목록 제공 지원.
- 보안 화이트리스트: 127.0.0.1, 192.168.3.10, 192.168.3.11, 192.168.3.14, 192.168.3.15 차단 불가 보장.
- DEFENSE_MODE: scripts/toggle_defense.py를 통해 .env 무중단 핫토글 연동 완료.
- 감사로그 스트림: /admin/audit/stream (SSE)로 실시간 보안 이벤트 브로드캐스트 지원.

[수행할 작업 요구사항]
1. n8n SOAR 및 pfSense 방화벽과의 E2E 연동 테스트 시나리오(모의 IP 차단 -> 포털 차단 확인 -> 방화벽 드롭 확인 -> 만료 후 자동 해제)를 점검하는 pytest 자동화 스크립트를 작성해줘.
2. 관제 대시보드(/admin/audit) 화면에서 실시간 AI 심층 분석 결과(threat_score, verdict)를 시각적인 배지 형태로 표출하는 방안을 제시해줘.
3. 무단 DB 접근 차단을 위해 로컬 loopback(127.0.0.1:3307)을 유지하면서도 n8n이 안전하게 API로만 통신하는 보안 원칙을 지속 검증해줘.
```

---

## 5. 기대 효과

1. **오탐(False Positive)의 획기적 감축**:
   - 기존 정적 룰은 단순 실수도 기계적으로 차단했으나, AI가 페이로드와 연속 행동 문맥을 읽어 "오타인지 공격 의도인지"를 정확히 분별.
2. **24/7 빈틈없는 무인 방어 체계 실현**:
   - 관제 인력이 있는 주간에는 사람의 통제권(안전성)을 확보하고, 인력이 부재한 야간/주말에는 AI가 침투 즉시 선제 격리(신속성)를 수행하여 인프라 보호.
3. **공방전 및 최종 발표 평가 극대화**:
   - "단순 오픈소스 솔루션 나열"을 탈피하여, **"실시간 트래픽 필터링 ➔ 생성형 AI 심층 분석 ➔ 시간대별 지능형 능동 대응"**으로 이어지는 차세대 보안관제(AI-Driven SOC) 모델 완비.
