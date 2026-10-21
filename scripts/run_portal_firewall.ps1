$null = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
cmd.exe /c chcp 65001 >$null

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "[NEXUS] 포털 직접 접속 차단 방화벽 적용 (pfSense만 허용)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "대상 포트 : TCP 5070"
Write-Host "허용 IP   : 192.168.3.10 (pfSense)"
Write-Host "차단 대상 : pfSense(192.168.3.10) 외 모든 직접 접속 IP"
Write-Host ""

& "$PSScriptRoot\portal_pfsense_only.ps1" -AllowIp 192.168.3.10

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "[성공] 방화벽 규칙이 적용되었습니다!" -ForegroundColor Green
Write-Host "- 맥북/외부에서 192.168.3.14:5070 직접 접속 시 차단됩니다."
Write-Host "- pfSense(192.168.3.10:5070)를 통한 접속만 허용됩니다."
Write-Host ""
Write-Host "문제 발생 시 바탕화면의 [포털_직접접속차단_방화벽규칙_해제.bat]을 실행하세요."
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""
Read-Host "계속하려면 Enter 키를 누르십시오..."
