<#
n8n 장비만 포털 DB 포트(3307)에 닿게 하는 Windows 방화벽 차단 규칙. **관리자 PowerShell** 에서 실행한다. 여러 번 실행해도 된다(이전 규칙을 지우고 다시 만든다).

  powershell -ExecutionPolicy Bypass -File scripts\n8n_db_firewall.ps1 -AllowIp 192.168.7.77
  powershell -ExecutionPolicy Bypass -File scripts\n8n_db_firewall.ps1 -Remove        # 규칙 제거(포트를 다시 닫을 때는 .env 의 DB_BIND 도 127.0.0.1 로)

왜 '허용'이 아니라 '차단'인가: Docker Desktop 이 설치될 때 com.docker.backend.exe 에 "모든 원격 주소 허용" 규칙을 만든다.
Windows 방화벽은 허용 규칙끼리는 하나만 맞아도 통과시키므로 n8n IP 허용 규칙을 더해도 아무 효과가 없다. 차단 규칙은 허용보다 우선하므로
"n8n IP 를 뺀 모든 주소 차단"을 걸어야 실제로 제한된다. 이 PC 안(127.0.0.1)의 접속은 방화벽을 거치지 않아 포털은 영향이 없다.
MySQL 계정 쪽에서는 Docker 의 주소 변환 때문에 실제 출발지 IP 를 볼 수 없으므로, 장비 제한은 이 규칙이 유일한 수단이다.
#>
param(
    [string]$AllowIp = "192.168.7.77",
    [int]$Port = 3307,
    [switch]$Remove
)
$ErrorActionPreference = "Stop"
$Group = "NEXUS n8n DB"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "관리자 PowerShell 에서 실행하세요(시작 메뉴 > PowerShell 우클릭 > 관리자 권한으로 실행)." }

Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($Remove) { "규칙을 지웠습니다($Group)."; return }

function ToUInt([string]$ip) { $b = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0) }
function ToIp([uint32]$n) { $b = [BitConverter]::GetBytes($n); [Array]::Reverse($b); ([System.Net.IPAddress]::new($b)).ToString() }

$n = ToUInt $AllowIp
$ranges = @()
if ($n -gt 0) { $ranges += "0.0.0.0-" + (ToIp ($n - 1)) }
if ($n -lt [uint32]::MaxValue) { $ranges += (ToIp ($n + 1)) + "-255.255.255.255" }

New-NetFirewallRule -DisplayName "NEXUS DB $Port - n8n($AllowIp) 외 IPv4 차단" -Group $Group -Direction Inbound -Protocol TCP -LocalPort $Port `
    -Action Block -Profile Any -RemoteAddress $ranges | Out-Null
New-NetFirewallRule -DisplayName "NEXUS DB $Port - IPv6 전체 차단" -Group $Group -Direction Inbound -Protocol TCP -LocalPort $Port `
    -Action Block -Profile Any -RemoteAddress "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" | Out-Null

Get-NetFirewallRule -Group $Group | ForEach-Object {
    "{0} | {1} | {2}" -f $_.DisplayName, $_.Action, (($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ", ")
}
"완료: 3307 은 $AllowIp 에서만 닿습니다(이 PC 안의 접속은 영향 없음)."
