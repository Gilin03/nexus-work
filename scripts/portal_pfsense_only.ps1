<#
포털(5070)을 pfSense(192.168.3.10)를 거친 요청만 허용하고 나머지는 차단하는 Windows 방화벽 규칙.
**관리자 PowerShell** 에서 실행한다. 여러 번 실행해도 된다(이전 규칙을 지우고 다시 만든다).

  powershell -ExecutionPolicy Bypass -File scripts\portal_pfsense_only.ps1                  # 적용 (pfSense 192.168.3.10 외 차단)
  powershell -ExecutionPolicy Bypass -File scripts\portal_pfsense_only.ps1 -Remove          # 해제 (직접 접속 다시 허용)

동작 원리:
- Windows 방화벽은 차단(Block) 규칙이 허용 규칙보다 우선 적용된다.
- pfSense IP(192.168.3.10)를 제외한 모든 IPv4 주소 범위(0.0.0.0~192.168.3.9, 192.168.3.11~255.255.255.255) 및
  IPv6 전체를 차단 규칙으로 등록한다.
- 맥북 등 팀원이 포털 PC(192.168.3.14:5070)로 직접 접속하면 차단 규칙에 걸려 접속이 거부된다.
- 팀원이 pfSense(192.168.3.10:5070)로 접속하면 pfSense가 포털로 중계하며 출발지 IP가 192.168.3.10이 되므로
  차단 규칙을 통과하여 정상 접속된다.
- 로컬 루프백(127.0.0.1) 트래픽은 방화벽 영향을 받지 않는다.
#>
param(
    [string]$AllowIp = "192.168.3.10",
    [int]$Port = 5070,
    [switch]$Remove
)
$ErrorActionPreference = "Stop"
$Group = "NEXUS portal pfSense only"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "관리자 PowerShell 에서 실행하세요(시작 메뉴 > PowerShell 우클릭 > 관리자 권한으로 실행)." }

Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($Remove) { "규칙을 지웠습니다($Group). 포털 $Port 직접 접속이 다시 허용됩니다."; return }

function ToUInt([string]$ip) { $b = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0) }
function ToIp([uint32]$n) { $b = [BitConverter]::GetBytes($n); [Array]::Reverse($b); ([System.Net.IPAddress]::new($b)).ToString() }

$n = ToUInt $AllowIp
$ranges = @()
if ($n -gt 0) { $ranges += "0.0.0.0-" + (ToIp ($n - 1)) }
if ($n -lt [uint32]::MaxValue) { $ranges += (ToIp ($n + 1)) + "-255.255.255.255" }

New-NetFirewallRule -DisplayName "NEXUS 포털 $Port - pfSense($AllowIp) 외 IPv4 차단" -Group $Group -Direction Inbound -Protocol TCP -LocalPort $Port `
    -Action Block -Profile Any -RemoteAddress $ranges | Out-Null
New-NetFirewallRule -DisplayName "NEXUS 포털 $Port - IPv6 전체 차단" -Group $Group -Direction Inbound -Protocol TCP -LocalPort $Port `
    -Action Block -Profile Any -RemoteAddress "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" | Out-Null

Get-NetFirewallRule -Group $Group | ForEach-Object {
    "{0} | {1} | {2}" -f $_.DisplayName, $_.Action, (($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ", ")
}
"완료: 포털($Port)은 pfSense($AllowIp)에서 온 요청만 허용됩니다. 해제는 -Remove."
