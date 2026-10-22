[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
cmd.exe /c chcp 65001 >$null

$ErrorActionPreference = "Stop"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "[NEXUS] Wazuh Agent 이름 변경 및 재등록 (192.168.3.15)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$agentDir = "C:\Program Files (x86)\ossec-agent"
$confPath = "$agentDir\ossec.conf"
$keysPath = "$agentDir\client.keys"

if (-not (Test-Path $confPath)) {
    Write-Host "[오류] ossec.conf 파일을 찾을 수 없습니다: $confPath" -ForegroundColor Red
    Read-Host "계속하려면 Enter 키를 누르십시오..."
    exit 1
}

# 1. ossec.conf에서 에이전트 이름을 nexus-board-14로 변경 (중복 회피)
Write-Host "1. Agent 이름 중복 회피를 위해 nexus-board-14 로 변경 중..." -ForegroundColor Yellow
$content = [System.IO.File]::ReadAllText($confPath, [System.Text.Encoding]::UTF8)
$newContent = $content.Replace("<agent_name>board-host</agent_name>", "<agent_name>nexus-board-14</agent_name>")
$newContent = $newContent.Replace("<address>127.0.0.1</address>", "<address>192.168.3.15</address>")
$newContent = $newContent.Replace("<manager_address>127.0.0.1</manager_address>", "<manager_address>192.168.3.15</manager_address>")

[System.IO.File]::WriteAllText($confPath, $newContent, [System.Text.Encoding]::UTF8)
Write-Host "   -> ossec.conf 변경 완료 (이름: nexus-board-14)" -ForegroundColor Green

# 2. 기존 키 백업 및 초기화 (새 Manager로부터 신규 키 수신을 위해)
if (Test-Path $keysPath) {
    Copy-Item $keysPath "$keysPath.bak_old" -Force
    Clear-Content $keysPath -Force
    Write-Host "2. 기존 키 초기화 완료 (새 매니저로부터 자동 키 발급 대기)" -ForegroundColor Yellow
}

# 3. 서비스 재시작
Write-Host "3. WazuhSvc 서비스 재시작 중..." -ForegroundColor Yellow
Restart-Service -Name WazuhSvc -Force
Start-Sleep -Seconds 3

# 4. 등록 및 연결 로그 확인
Write-Host "4. 15번 매니저 자동 등록 및 연결 상태 확인 (8초 대기)..." -ForegroundColor Yellow
Start-Sleep -Seconds 8

$logPath = "$agentDir\ossec.log"
if (Test-Path $logPath) {
    Write-Host "`n--- [ossec.log 최근 15줄] ---" -ForegroundColor Cyan
    Get-Content -Tail 15 $logPath
    Write-Host "----------------------------`n" -ForegroundColor Cyan
}

Write-Host "========================================================" -ForegroundColor Green
Write-Host "[완료] 15번 매니저 등록 작업이 완료되었습니다!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""
Read-Host "계속하려면 Enter 키를 누르십시오..."
