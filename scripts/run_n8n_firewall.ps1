$null = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
cmd.exe /c chcp 65001 >$null

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "[NEXUS] n8n DB(3307) 방화벽 허용 IP 교체 (김태빈 님: 192.168.3.15)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "대상 포트 : TCP 3307"
Write-Host "허용 IP   : 192.168.3.15 (김태빈 님 n8n 장비)"
Write-Host "차단 대상 : 192.168.3.15 외 모든 원격 IP"
Write-Host ""

& "$PSScriptRoot\n8n_db_firewall.ps1" -AllowIp 192.168.3.15

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "[성공] n8n DB 방화벽 규칙이 192.168.3.15 로 갱신되었습니다!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""
Read-Host "계속하려면 Enter 키를 누르십시오..."
