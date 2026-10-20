# NEXUS Wazuh/Graylog 이식 패키지

이 패키지는 현재 프로젝트에서 사용 중인 NEXUS 범위만 다른 로컬 Graylog/Wazuh 설치에 재현하기 위한 도구입니다. Docker 컨테이너, 볼륨, 전체 설정 파일, API 토큰은 옮기지 않습니다. Import는 기존 설정을 삭제하거나 덮어쓰지 않습니다.

## 포함 범위

### Graylog

- 앱 GELF UDP Input (`hping3 lab`, UDP 12201)
- Wazuh Raw UDP Input (`Wazuh Alerts (JSON over UDP 5140)`, UDP 5140)
- `NEXUS_AUTH`, `NEXUS_AI_SECURITY`, `NEXUS_WEB` Stream과 Stream rule
- R1, R2, R5, R6, R7, R8, R9, R10 Event Definition
- Stream과 Event Definition 연결은 이름으로 다시 찾습니다. 서버 내부 ID, API 토큰, 인증정보는 패키지에 저장하지 않습니다.
- Event Definition priority는 Graylog 6.1 계열 UI 범위인 1~3인지 확인합니다.

NEXUS Stream에 연결되지 않은 Notification과 Pipeline은 제외했습니다. 기존 Wazuh JSON/FIM 파이프라인은 별도 `Wazuh 경보` Stream에 연결되어 있어 이 최소 패키지에 포함하지 않았습니다. 따라서 NEXUS_WEB은 Wazuh Raw Input ID로 메시지를 분류하지만, 별도 파이프라인의 JSON 필드 변환/정규화까지 복제하지는 않습니다.

### Wazuh

- Windows Wazuh Agent의 `{{PROJECT_ROOT}}\instance\uploads` FIM 항목
- Wazuh Manager에서 Graylog로 보내는 uploads FIM 내장 rule 550, 553, 554 전달 항목
- 프로젝트 uploads 디렉터리는 대상 PC의 `-ProjectRoot`에서 계산합니다.
- 프로젝트 전용 custom rule/decoder는 현재 사용하지 않아 비어 있는 폴더 안내만 포함합니다. 다른 실습/프로젝트의 rule과 decoder는 내보내지 않았습니다.

전달 대상 `{{GRAYLOG_HOST}}`는 Manager 컨테이너가 접근할 수 있는 이름/IP로 설정해야 합니다. 현재 PC의 Docker DNS 별칭이 대상 PC에서도 유효하다고 가정하지 마세요.

## 파일 구조

```text
security_migration/
  export/
    graylog/
      inputs.json
      streams.json
      event_definitions.json
    wazuh/
      rules/README.md
      decoders/README.md
      agent_fim_template.xml
      manager_syslog_output_template.xml
  scripts/
    export_graylog.ps1
    import_graylog.ps1
    export_wazuh.ps1
    import_wazuh.ps1
    verify_security_stack.ps1
```

`export_graylog.ps1`와 `export_wazuh.ps1`는 원본 환경에서 읽은 설정을 다시 추출할 때 사용합니다. 현재 `export/` 파일은 실제 실행 중인 환경에서 생성했습니다.

## 적용 전 확인

1. 대상 PC의 Graylog와 Wazuh가 이미 실행 중인지 확인합니다.
2. 대상 Graylog에서 Input/Stream/Event Definition 조회와 생성 권한이 있는 API Token을 만들고 해당 PowerShell 세션의 환경변수로 설정합니다. 토큰은 JSON/XML 패키지에 저장되지 않습니다.
3. 대상 PC의 프로젝트 `instance\uploads` 폴더가 실제로 존재하는지 확인합니다.
4. Manager 컨테이너가 접근할 수 있는 Graylog 주소와 UDP 포트를 확인합니다.
5. `-DryRun` 결과에서 생성/무변경 항목과 충돌을 확인합니다.
6. 승인한 대상에서만 `-Apply`를 사용합니다.

Wazuh Apply는 Windows Agent 설정 파일과 Docker의 Manager 설정 파일을 백업하고 서비스를 재시작하므로 관리자 권한 PowerShell에서 실행해야 합니다.

API Token을 PowerShell에 설정하는 예:

```powershell
$env:GRAYLOG_API_TOKEN = "<Graylog API token>"
```

실제 토큰 문자열을 명령 기록, 채팅, 문서, 로그에 붙여 넣지 마세요. 아래 예시는 환경변수 참조만 전달합니다.

## Graylog Dry-run / Apply

저장소 루트에서 실행합니다.

```powershell
.\security_migration\scripts\import_graylog.ps1 `
  -GraylogUrl "http://127.0.0.1:9000" `
  -ApiToken $env:GRAYLOG_API_TOKEN `
  -DryRun
```

Dry-run에서 같은 이름과 같은 설정은 `NO-OP`, 없는 설정은 `CREATE`로 표시합니다. 같은 이름의 설정이 있지만 내용이 다르거나 필요한 UDP 포트가 이미 점유된 경우 전체 사전 검사를 중단합니다. 기존 설정은 수정하거나 삭제하지 않습니다.

검토 후 실제 대상에 적용할 때만:

```powershell
.\security_migration\scripts\import_graylog.ps1 `
  -GraylogUrl "http://127.0.0.1:9000" `
  -ApiToken $env:GRAYLOG_API_TOKEN `
  -Apply
```

단일 노드 GELF Input을 만들 때 Graylog가 노드를 하나로 반환하지 않으면 명시적으로 선택합니다:

```powershell
.\security_migration\scripts\import_graylog.ps1 `
  -GraylogUrl "http://127.0.0.1:9000" `
  -ApiToken $env:GRAYLOG_API_TOKEN `
  -NodeId "<target Graylog node ID>" `
  -DryRun
```

`-DryRun`과 `-Apply` 중 정확히 하나를 지정해야 합니다. Apply는 Input → Stream/rule → Event Definition 순서로 만들고 이름, 상태, priority, Stream 연결을 다시 읽어 확인합니다. API 오류가 발생하면 진행을 멈춥니다. 이미 만들어진 항목을 자동 삭제하거나 되돌리지 않으므로, 부분 적용 메시지를 확인하고 다음 실행 전에 대상 API를 다시 조회하세요.

## Wazuh Dry-run / Apply

`ProjectRoot`는 상대 PC의 실제 프로젝트 경로입니다. 해당 경로 아래 `instance\uploads` 폴더가 있어야 합니다.

```powershell
.\security_migration\scripts\import_wazuh.ps1 `
  -ProjectRoot "D:\team\nexus-work" `
  -GraylogHost "graylog-container-or-host" `
  -DryRun
```

대상 Manager 컨테이너 이름이 다르면 `-ManagerContainerName`을 지정합니다. Manager가 접근할 수 있는 Graylog 주소를 `-GraylogHost`로 지정하세요. 기본 UDP 포트는 5140입니다.

Dry-run에서 Agent uploads 항목과 Manager syslog rule 550/553/554를 비교합니다. 동일 항목은 건너뛰고, 같은 경로/rule ID가 다른 설정으로 이미 있으면 덮어쓰지 않고 중단합니다. 다른 `syscheck` 경로, Agent 설정, Manager 설정은 보존합니다.

검토 후 실제 대상에 적용할 때만:

```powershell
.\security_migration\scripts\import_wazuh.ps1 `
  -ProjectRoot "D:\team\nexus-work" `
  -GraylogHost "graylog-container-or-host" `
  -Apply
```

Apply는 변경 전 Agent/Manager 설정 백업을 남기고, Wazuh Manager를 재시작하기 전에 `wazuh-analysisd -t`를 실행합니다. 검증 실패 시 Manager 원본 설정을 되돌립니다. 성공 후 Wazuh Manager 컨테이너, Windows Agent 서비스, Agent 연결 상태를 확인합니다. 컨테이너/볼륨은 이동하거나 재생성하지 않습니다.

## 검증

기본 확인은 읽기 전용이며 Graylog Input/Stream/Event Definition, uploads FIM 경로, Manager 전달 rule, Agent 연결 상태를 확인합니다. `-AgentName`은 Manager에 등록된 이름이 로컬 PC 이름과 다를 때 지정합니다.

```powershell
.\security_migration\scripts\verify_security_stack.ps1 `
  -GraylogUrl "http://127.0.0.1:9000" `
  -ApiToken $env:GRAYLOG_API_TOKEN `
  -ManagerContainerName "wazuh-manager" `
  -GraylogHost "gl-graylog" `
  -AgentName "<Manager에 등록된 Windows Agent 이름>"
```

GELF Input 실제 분류를 확인하려면 명시적으로 시험 메시지를 전송합니다. 이 메시지는 `login_locked` event type과 테스트 marker를 사용하므로 NEXUS_AUTH 분류를 확인할 수 있습니다.

```powershell
.\security_migration\scripts\verify_security_stack.ps1 `
  -GraylogUrl "http://127.0.0.1:9000" `
  -ApiToken $env:GRAYLOG_API_TOKEN `
  -InputHost "127.0.0.1" `
  -TestGelf
```

Uploads FIM 생성/수정/삭제를 재현하려면 명시적으로 실행합니다. 테스트 파일은 실행 후 제거되며, Wazuh rule 554/550/553 로그를 확인합니다.

```powershell
.\security_migration\scripts\verify_security_stack.ps1 `
  -GraylogUrl "http://127.0.0.1:9000" `
  -ApiToken $env:GRAYLOG_API_TOKEN `
  -ProjectRoot "D:\team\nexus-work" `
  -ManagerContainerName "wazuh-manager" `
  -RunFimSmokeTest
```

포털 DB와 데이터, 다른 uploads 파일은 이 스크립트가 변경하지 않습니다. FIM 시험용 고유 파일 하나를 생성/수정/삭제합니다. Wazuh 경보와 Graylog NEXUS_WEB 전달은 스크립트 출력의 marker를 사용해 각 UI에서 확인합니다.

## 알려진 범위

- n8n Webhook/Workflow는 포함하거나 연결하지 않았습니다.
- R3/R4/R11/R12 Event Definition은 포함하지 않았습니다.
- Notifications와 Pipelines는 NEXUS Stream에 직접 연결되지 않아 제외했습니다.
- 별도 `Wazuh 경보` Stream과 그에 연결된 JSON/FIM parser Pipeline은 포함하지 않았습니다.
- 프로젝트 custom Wazuh rule/decoder는 현재 확인되지 않아 XML 파일을 내보내지 않았습니다. 따라서 custom rule ID/decoder 충돌 검사는 적용 대상이 없으며, Manager의 기존 `syslog_output` rule ID 550/553/554 중복/설정 충돌을 확인합니다.
- Windows Agent 경로와 Manager 컨테이너명은 대상 PC 환경에 맞게 전달해야 합니다.
- Input 포트 충돌, 같은 이름의 상이한 설정, Wazuh rule ID 충돌은 자동 변경하지 않고 중단합니다.
- 이 패키지는 대상 환경에 적용하지 않았습니다. 생성된 JSON/XML/PowerShell 파일의 정적 형식 검증만 수행합니다.
