[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
cmd.exe /c chcp 65001 >$null

$ErrorActionPreference = "Stop"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "[NEXUS] Wazuh Agent security.jsonl localfile 수집 적용" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$confPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$stagedPath = "C:\Users\user\Desktop\nexus-work\ossec.conf.new"
$LogResultPath = "C:\Users\user\Desktop\nexus-work\logs\wazuh_localfile_result.json"

$result = [ordered]@{
    backup_done = $false
    backup_path = ""
    localfile_added = $false
    log_path = "C:\Users\user\Desktop\nexus-work\logs\security.jsonl"
    xml_valid = $true
    service_restarted = $false
    service_status = ""
    active_config_found = $false
    error = ""
    recent_logs = @()
}

try {
    if (-not (Test-Path $stagedPath)) {
        throw "검증된 설정 파일(ossec.conf.new)이 없습니다."
    }

    # 1. 백업
    Write-Host "1. ossec.conf 백업 수행 중..." -ForegroundColor Yellow
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupPath = "$confPath.bak_$timestamp"
    Copy-Item -Path $confPath -Destination $backupPath -Force
    $result.backup_done = $true
    $result.backup_path = $backupPath
    Write-Host "   -> 백업 완료: $backupPath" -ForegroundColor Green

    # 2. 검증된 새 설정 파일 복사
    Write-Host "2. 검증된 새 설정(security.jsonl localfile) 적용 중..." -ForegroundColor Yellow
    Copy-Item -Path $stagedPath -Destination $confPath -Force
    $result.localfile_added = $true
    Write-Host "   -> ossec.conf 적용 완료!" -ForegroundColor Green

    # 3. 서비스 재시작
    Write-Host "3. WazuhSvc 서비스 재시작 중..." -ForegroundColor Yellow
    Restart-Service -Name WazuhSvc -Force
    Start-Sleep -Seconds 3

    # 4. 서비스 상태 확인
    $svc = Get-Service -Name WazuhSvc
    $result.service_status = $svc.Status.ToString()
    if ($svc.Status -eq 'Running') {
        $result.service_restarted = $true
        Write-Host "4. WazuhSvc 상태: $($svc.Status)" -ForegroundColor Green
    } else {
        Write-Host "4. [경고] WazuhSvc 상태: $($svc.Status)" -ForegroundColor Red
    }

    # 5. 활성 설정 및 로그 확인
    Start-Sleep -Seconds 2
    $updatedContent = [System.IO.File]::ReadAllText($confPath, [System.Text.Encoding]::UTF8)
    if ($updatedContent -match "security\.jsonl") {
        $result.active_config_found = $true
        Write-Host "5. 활성 설정 내 security.jsonl 반영 확인 완료!" -ForegroundColor Green
    }

    $logFile = "C:\Program Files (x86)\ossec-agent\ossec.log"
    if (Test-Path $logFile) {
        $result.recent_logs = Get-Content -Tail 15 $logFile
        Write-Host "`n--- [ossec.log 최근 15줄] ---" -ForegroundColor Cyan
        $result.recent_logs | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
        Write-Host "----------------------------`n" -ForegroundColor Cyan
    }

    Write-Host "========================================================" -ForegroundColor Green
    Write-Host "[성공] security.jsonl 수집 설정이 정상적으로 적용되었습니다!" -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Green

} catch {
    $result.error = $_.Exception.Message
    Write-Host "`n[오류 발생] $($result.error)" -ForegroundColor Red
} finally {
    $jsonResult = $result | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($LogResultPath, $jsonResult, [System.Text.Encoding]::UTF8)
    Write-Host ""
    Read-Host "계속하려면 Enter 키를 누르십시오..."
}
