<#
포털(5070)을 pfSense 를 거친 요청만 받게 하는 Windows 방화벽 차단 규칙(이시헌 요청, 2026-10-20). **관리자 PowerShell** 에서 실행한다.
여러 번 실행해도 된다(이전 규칙을 지우고 다시 만든다).

  powershell -ExecutionPolicy Bypass -File scripts\portal_pfsense_only.ps1                      # 적용
  powershell -ExecutionPolicy Bypass -File scripts\portal_pfsense_only.ps1 -OnlyFromPfSense     # + 출발지도 pfSense 로 제한(pfSense 가 출발지 NAT 를 할 때)
  powershell -ExecutionPolicy Bypass -File scripts\portal_pfsense_only.ps1 -Remove              # 해제(직접 접속 다시 허용)

구성: pfSense 는 이 PC 의 VMware 가상머신이고, 포털 서버는 VMnet2(172.16.50.10)와 실제 망(이더넷, 192.168.3.14) 두 주소를 갖는다.
같은 물리망이라 출발지 IP 로는 직접 접속과 pfSense 경유를 가릴 수 없으므로, "어느 주소·어느 인터페이스로 들어왔나"로 가른다.
  1) 받는 주소가 포털 주소(172.16.50.10)가 아닌 5070 연결 차단 → 192.168.3.14:5070 직접 접속 거부
  2) pfSense 쪽 인터페이스(VMnet2)가 아닌 곳으로 들어온 5070 연결 차단 → 다른 인터페이스로 172.16.50.10 을 노리는 우회 방지
  3) IPv6 5070 전체 차단
  4) (선택 -OnlyFromPfSense) VMnet2 에서도 출발지가 pfSense(172.16.50.2)가 아니면 차단
차단 규칙은 허용 규칙(Python 허용 등)보다 우선한다. 이 PC 안(127.0.0.1)의 접속은 방화벽을 거치지 않아 영향이 없다.

주의: pfSense 가 포트 포워딩만 하고 출발지 주소를 바꾸지 않으면(출발지 NAT 없음), 포털의 응답이 pfSense 가 아니라 이더넷으로 나가려다
버려진다(Windows 는 받은 주소의 인터페이스로만 보낸다). pfSense 에서 출발지 NAT(아웃바운드 NAT/LAN 쪽 SNAT)를 켜거나, 반환 경로를 pfSense 로
두어야 경유 접속이 된다. 적용 뒤 확인: 다른 PC 에서 192.168.3.14:5070 거부, 172.16.50.2:5070(또는 pfSense WAN 주소) 경유 정상.
메신저·팀원 접속 주소도 pfSense 경유 주소로 바꿔야 한다(메신저 기본 주소는 192.168.3.14:5070).
#>
param(
    [string]$PortalIp = "172.16.50.10",
    [string]$Interface = "VMware Network Adapter VMnet2",
    [string]$PfSenseIp = "172.16.50.2",
    [int]$Port = 5070,
    [switch]$OnlyFromPfSense,
    [switch]$Remove
)
$ErrorActionPreference = "Stop"
$Group = "NEXUS portal pfSense only"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "관리자 PowerShell 에서 실행하세요(시작 메뉴 > PowerShell 우클릭 > 관리자 권한으로 실행)." }

Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($Remove) { "규칙을 지웠습니다($Group). 포털 5070 직접 접속이 다시 열립니다."; return }

if (-not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $PortalIp -ErrorAction SilentlyContinue)) { throw "이 PC 에 $PortalIp 주소가 없습니다(VMware VMnet2 확인)." }
if (-not (Get-NetAdapter -Name $Interface -IncludeHidden -ErrorAction SilentlyContinue)) { throw "인터페이스 '$Interface' 가 없습니다." }

function ToUInt([string]$ip) { $b = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0) }
function ToIp([uint32]$n) { $b = [BitConverter]::GetBytes($n); [Array]::Reverse($b); ([System.Net.IPAddress]::new($b)).ToString() }
function AllExcept([string]$ip) {
    $n = ToUInt $ip; $r = @()
    if ($n -gt 0) { $r += "0.0.0.0-" + (ToIp ($n - 1)) }
    if ($n -lt [uint32]::MaxValue) { $r += (ToIp ($n + 1)) + "-255.255.255.255" }
    return $r
}

New-NetFirewallRule -DisplayName "NEXUS 포털 $Port - $PortalIp 외 주소로 온 접속 차단" -Group $Group -Direction Inbound -Protocol TCP -LocalPort $Port `
    -Action Block -Profile Any -LocalAddress (AllExcept $PortalIp) | Out-Null
$others = Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -ne $Interface } | Select-Object -ExpandProperty Name
if ($others) {
    New-NetFirewallRule -DisplayName "NEXUS 포털 $Port - $Interface 외 인터페이스 차단" -Group $Group -Direction Inbound -Protocol TCP -LocalPort $Port `
        -Action Block -Profile Any -InterfaceAlias $others | Out-Null
}
New-NetFirewallRule -DisplayName "NEXUS 포털 $Port - IPv6 전체 차단" -Group $Group -Direction Inbound -Protocol TCP -LocalPort $Port `
    -Action Block -Profile Any -RemoteAddress "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" | Out-Null
if ($OnlyFromPfSense) {
    New-NetFirewallRule -DisplayName "NEXUS 포털 $Port - pfSense($PfSenseIp) 외 출발지 차단" -Group $Group -Direction Inbound -Protocol TCP -LocalPort $Port `
        -Action Block -Profile Any -RemoteAddress (AllExcept $PfSenseIp) | Out-Null
}

Get-NetFirewallRule -Group $Group | ForEach-Object { "{0} | {1}" -f $_.DisplayName, $_.Action }
"완료: 5070 은 $Interface 의 $PortalIp 로 들어온 연결만 받습니다(이 PC 안의 접속은 영향 없음). 해제는 -Remove."
