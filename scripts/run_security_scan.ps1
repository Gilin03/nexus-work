# NEXUS WORK - 정적 코드 보안 분석(SAST) 및 의존성 취약점(SCA) 점검 스크립트
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [NEXUS SOC] 정적 코드 보안 분석(SAST) & 라이브러리 점검" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$VenvPython = ".\.venv\Scripts\python.exe"
$BanditExe = ".\.venv\Scripts\bandit.exe"
$PipAuditExe = ".\.venv\Scripts\pip-audit.exe"

if (-not (Test-Path $BanditExe) -or -not (Test-Path $PipAuditExe)) {
    Write-Host "[*] bandit 또는 pip-audit 이 설치되지 않아 자동 설치를 진행합니다..." -ForegroundColor Yellow
    & $VenvPython -m pip install bandit pip-audit --quiet
}

Write-Host "`n[1/2] 파이썬 소스코드 보안 정적 분석 (Bandit SAST)..." -ForegroundColor Green
& $BanditExe -r app/ -ll -q
if ($LASTEXITCODE -eq 0) {
    Write-Host " -> Bandit SAST 검사 통과: High/Medium 심각도 보안 취약점 미발견!" -ForegroundColor Green
} else {
    Write-Host " -> Bandit SAST 검사: 잠재적 보안 주의 항목이 발견되었습니다. 위 상세 내용을 확인하세요." -ForegroundColor Yellow
}

Write-Host "`n[2/2] 오픈소스 의존성 패키지 CVE 취약점 점검 (pip-audit SCA)..." -ForegroundColor Green
& $PipAuditExe
if ($LASTEXITCODE -eq 0) {
    Write-Host " -> pip-audit 검사 통과: 설치된 패키지에 알려진 CVE 취약점이 없습니다!" -ForegroundColor Green
} else {
    Write-Host " -> pip-audit 검사: 보안 패치가 필요한 취약 패키지가 감지되었습니다." -ForegroundColor Red
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " 보안 점검 완료!" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
