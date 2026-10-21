$null = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
cmd.exe /c chcp 65001 >$null

Write-Host "========================================================" -ForegroundColor Yellow
Write-Host "[NEXUS] 포털 직접 접속 차단 방화벽 해제 (복구)" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Yellow
Write-Host ""

& "$PSScriptRoot\portal_pfsense_only.ps1" -Remove

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "[성공] 차단 규칙이 삭제되었습니다." -ForegroundColor Green
Write-Host "192.168.3.14:5070 직접 접속이 다시 정상 허용됩니다."
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""
Read-Host "계속하려면 Enter 키를 누르십시오..."
