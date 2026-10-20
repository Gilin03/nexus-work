[CmdletBinding()]
param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$ManagerContainerName = "wazuh-manager",
    [string]$OutputRoot = (Join-Path $PSScriptRoot "..\export\wazuh")
)

$ErrorActionPreference = "Stop"

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

$rootPath = (Resolve-Path -LiteralPath $ProjectRoot).Path.TrimEnd("\")
$uploadsPath = Join-Path $rootPath "instance\uploads"
if (-not (Test-Path -LiteralPath $uploadsPath -PathType Container)) {
    throw "Project uploads directory does not exist. No Wazuh export was written."
}

$service = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
if (-not $service) { throw "Windows Wazuh Agent service WazuhSvc was not found." }
$exePath = [string]$service.PathName
if ($exePath.StartsWith('"')) { $exePath = ($exePath -split '"')[1] }
else { $exePath = ($exePath -split '\s+')[0] }
$agentConfigPath = Join-Path (Split-Path -Parent $exePath) "ossec.conf"
if (-not (Test-Path -LiteralPath $agentConfigPath)) { throw "The local Wazuh Agent ossec.conf was not found." }

[xml]$agentXml = Get-Content -LiteralPath $agentConfigPath -Raw
$expectedFullPath = [System.IO.Path]::GetFullPath($uploadsPath).TrimEnd("\")
$foundDirectory = $null
foreach ($node in $agentXml.SelectNodes("/ossec_config/syscheck/directories")) {
    $configuredPath = ([string]$node.InnerText).Trim().Replace("/", "\").TrimEnd("\")
    if ([string]::Equals([System.IO.Path]::GetFullPath($configuredPath).TrimEnd("\"), $expectedFullPath, [StringComparison]::OrdinalIgnoreCase)) {
        $foundDirectory = $node
        break
    }
}
if (-not $foundDirectory) {
    throw "The running Agent config does not contain the requested ProjectRoot uploads path. No Wazuh export was written."
}
if ($foundDirectory.GetAttribute("check_all") -ne "yes" -or $foundDirectory.GetAttribute("realtime") -ne "yes") {
    throw "The uploads FIM attributes differ from the expected check_all=yes and realtime=yes settings."
}

$managerText = & docker exec $ManagerContainerName cat /var/ossec/etc/ossec.conf 2>$null | Out-String
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($managerText)) {
    throw "Could not read Wazuh Manager ossec.conf from container '$ManagerContainerName'."
}
$requiredRuleIds = @("550", "553", "554")
$blocks = [regex]::Matches($managerText, '(?s)<syslog_output>\s*(.*?)\s*</syslog_output>')
$exportedSyslog = @()
foreach ($ruleId in $requiredRuleIds) {
    $matches = @()
    foreach ($match in $blocks) {
        $body = $match.Groups[1].Value
        $idMatch = [regex]::Match($body, '<rule_id>\s*(.*?)\s*</rule_id>')
        if ($idMatch.Success -and $idMatch.Groups[1].Value.Trim() -eq $ruleId) { $matches += $body }
    }
    if ($matches.Count -ne 1) { throw "Expected exactly one Manager syslog_output for built-in FIM rule $ruleId, found $($matches.Count)." }
    $body = $matches[0]
    function Read-TagValue([string]$Xml, [string]$Tag) {
        $m = [regex]::Match($Xml, ('<' + $Tag + '>\s*(.*?)\s*</' + $Tag + '>'))
        if ($m.Success) { return $m.Groups[1].Value.Trim() }
        return ""
    }
    $port = Read-TagValue $body "port"
    $level = Read-TagValue $body "level"
    $format = Read-TagValue $body "format"
    if ($port -ne "5140" -or $level -ne "1" -or $format -ne "default") {
        throw "FIM syslog_output for rule $ruleId does not match the observed 5140/level 1/default contract."
    }
    $exportedSyslog += [ordered]@{
        server = "{{GRAYLOG_HOST}}"
        port = [int]$port
        level = [int]$level
        rule_id = [int]$ruleId
        format = $format
    }
}

$agentTemplate = @"
<?xml version="1.0" encoding="utf-8"?>
<nexus_wazuh_migration>
  <agent_fim>
    <syscheck>
      <directories check_all="yes" realtime="yes">{{PROJECT_ROOT}}\instance\uploads</directories>
    </syscheck>
  </agent_fim>
</nexus_wazuh_migration>
"@
$managerTemplate = New-Object System.Text.StringBuilder
[void]$managerTemplate.AppendLine('<?xml version="1.0" encoding="utf-8"?>')
[void]$managerTemplate.AppendLine("<nexus_wazuh_migration>")
[void]$managerTemplate.AppendLine("  <manager_syslog_output>")
foreach ($entry in $exportedSyslog) {
    [void]$managerTemplate.AppendLine("    <syslog_output>")
    [void]$managerTemplate.AppendLine("      <server>$($entry.server)</server>")
    [void]$managerTemplate.AppendLine("      <port>$($entry.port)</port>")
    [void]$managerTemplate.AppendLine("      <level>$($entry.level)</level>")
    [void]$managerTemplate.AppendLine("      <rule_id>$($entry.rule_id)</rule_id>")
    [void]$managerTemplate.AppendLine("      <format>$($entry.format)</format>")
    [void]$managerTemplate.AppendLine("    </syslog_output>")
}
[void]$managerTemplate.AppendLine("  </manager_syslog_output>")
[void]$managerTemplate.AppendLine("</nexus_wazuh_migration>")

Write-Utf8NoBom (Join-Path $OutputRoot "agent_fim_template.xml") $agentTemplate
Write-Utf8NoBom (Join-Path $OutputRoot "manager_syslog_output_template.xml") $managerTemplate.ToString()
$rulesDir = Join-Path $OutputRoot "rules"
$decodersDir = Join-Path $OutputRoot "decoders"
if (-not (Test-Path $rulesDir)) { New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null }
if (-not (Test-Path $decodersDir)) { New-Item -ItemType Directory -Path $decodersDir -Force | Out-Null }
Write-Utf8NoBom (Join-Path $rulesDir "README.md") @"
# NEXUS Wazuh rules

No NEXUS-specific custom Wazuh rule is required for uploads FIM.
The current uploads create/modify/delete detections use Wazuh built-in rule IDs 554, 550, and 553.
Unrelated rules from other lab projects are intentionally not exported.
"@
Write-Utf8NoBom (Join-Path $decodersDir "README.md") @"
# NEXUS Wazuh decoders

No NEXUS-specific custom decoder is required for uploads FIM.
Unrelated decoders from other lab projects are intentionally not exported.
"@

Write-Output "Exported the uploads FIM fragment and 3 Wazuh Manager forwarding fragments."
Write-Output "Absolute project paths, container/volume data, custom rules from other projects, and secrets were excluded."
