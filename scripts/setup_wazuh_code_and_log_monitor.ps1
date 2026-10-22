param(
    [switch]$NoWait
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
cmd.exe /c chcp 65001 >$null

$ErrorActionPreference = "Stop"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "[NEXUS] 14번 PC 로그 & 코드변경 실시간 관제 설정 (15번 연동)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$agentDir = "C:\Program Files (x86)\ossec-agent"
$confPath = "$agentDir\ossec.conf"

if (-not (Test-Path $confPath)) {
    Write-Host "[오류] ossec.conf 파일을 찾을 수 없습니다: $confPath" -ForegroundColor Red
    if (-not $NoWait) { Read-Host "Enter 키를 눌러 종료하십시오" }
    exit 1
}

# 1. ossec.conf 백업
$backupPath = "$confPath.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
Copy-Item $confPath $backupPath -Force
Write-Host "1. 기존 ossec.conf 백업 완료: $backupPath" -ForegroundColor Yellow

$content = [System.IO.File]::ReadAllText($confPath, [System.Text.Encoding]::UTF8)

# 2. 코드 변경 실시간 감시 (FIM / Syscheck) 블록 준비
$fimMarker = "<!-- [NEXUS WORK] 웹 소스코드 및 주요 설정파일 실시간 변경 감시 (FIM) -->"
if ($content -notcontains $fimMarker -and -not $content.Contains($fimMarker)) {
    Write-Host "2. 소스코드 실시간 변경 감시(FIM with diff) 및 로그 수집 규칙 추가 중..." -ForegroundColor Yellow

    $fimBlock = @"
    $fimMarker
    <directories realtime="yes" report_changes="yes" check_all="yes">C:\Users\user\Desktop\nexus-work\app</directories>
    <directories realtime="yes" report_changes="yes" check_all="yes">C:\Users\user\Desktop\nexus-work\scripts</directories>
    <directories realtime="yes" report_changes="yes" check_all="yes">C:\Users\user\Desktop\nexus-work\.env</directories>
    <ignore>C:\Users\user\Desktop\nexus-work\.venv</ignore>
    <ignore>C:\Users\user\Desktop\nexus-work\__pycache__</ignore>
    <ignore>C:\Users\user\Desktop\nexus-work\logs</ignore>
    <ignore>C:\Users\user\Desktop\nexus-work\.pytest_cache</ignore>
    <ignore>C:\Users\user\Desktop\nexus-work\.git</ignore>
  </syscheck>
"@

    $logBlock = @"
    <!-- [NEXUS WORK] 포털 보안 감사 로그(security.jsonl) 실시간 전송 -->
    <localfile>
      <location>C:\Users\user\Desktop\nexus-work\logs\security.jsonl</location>
      <log_format>syslog</log_format>
    </localfile>

    <!-- Policy monitoring -->
"@

    # syscheck 블록 닫는 태그 앞에 FIM 규칙 삽입
    $content = $content.Replace("  </syscheck>", $fimBlock)
    # Policy monitoring 주석 앞에 localfile 삽입
    $content = $content.Replace("    <!-- Policy monitoring -->", $logBlock)

    [System.IO.File]::WriteAllText($confPath, $content, [System.Text.Encoding]::UTF8)
    Write-Host "   -> ossec.conf 설정 갱신 완료!" -ForegroundColor Green
} else {
    Write-Host "2. 이미 FIM 및 로그 수집 규칙이 ossec.conf에 적용되어 있습니다." -ForegroundColor Green
}

# 3. WazuhSvc 서비스 재시작
Write-Host "3. WazuhSvc 서비스 재시작 중..." -ForegroundColor Yellow
Restart-Service -Name WazuhSvc -Force
Start-Sleep -Seconds 3

# 4. 최근 동작 로그 확인
$logPath = "$agentDir\ossec.log"
if (Test-Path $logPath) {
    Write-Host "`n--- [ossec.log 최근 15줄] ---" -ForegroundColor Cyan
    Get-Content -Tail 15 $logPath
    Write-Host "----------------------------`n" -ForegroundColor Cyan
}

Write-Host "========================================================" -ForegroundColor Green
Write-Host "[완료] 14번 PC 코드변경 및 로그 수집 설정이 정상 적용되었습니다!" -ForegroundColor Green
Write-Host "  - 코드 변경 감시: app/, scripts/, .env (실시간 diff 포함)" -ForegroundColor White
Write-Host "  - 포털 감사 로그: logs/security.jsonl -> Wazuh 매니저 전송" -ForegroundColor White
Write-Host "  - Graylog GELF : 192.168.3.15:12201 (UDP) 실시간 발송 중" -ForegroundColor White
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""
if (-not $NoWait) {
    Read-Host "계속하려면 Enter 키를 누르십시오..."
}
