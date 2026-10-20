[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ProjectRoot,
    [string]$GraylogHost = "gl-graylog",
    [int]$GraylogPort = 5140,
    [string]$ManagerContainerName = "wazuh-manager",
    [string]$AgentName = $env:COMPUTERNAME,
    [switch]$DryRun,
    [switch]$Apply,
    [string]$PackageRoot = (Join-Path $PSScriptRoot "..\export\wazuh")
)

$ErrorActionPreference = "Stop"
if ($DryRun -eq $Apply) { throw "Select exactly one mode: -DryRun or -Apply." }
if ($GraylogPort -lt 1 -or $GraylogPort -gt 65535) { throw "GraylogPort must be between 1 and 65535." }
$rootPath = (Resolve-Path -LiteralPath $ProjectRoot).Path.TrimEnd("\")
$uploadsPath = Join-Path $rootPath "instance\uploads"
if (-not (Test-Path -LiteralPath $uploadsPath -PathType Container)) { throw "Project uploads path does not exist: $uploadsPath" }
if ([string]::IsNullOrWhiteSpace($GraylogHost) -or $GraylogHost -match '[<>"\s]') { throw "GraylogHost must be a resolvable host name or IP address." }

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-Docker([string[]]$Arguments, [switch]$AllowFailure) {
    $output = & docker @Arguments 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0 -and -not $AllowFailure) { throw "Docker operation failed (exit $code): docker $($Arguments[0]) ..." }
    return [pscustomobject]@{ ExitCode = $code; Output = ($output | Out-String) }
}

function Escape-XmlText([string]$Value) {
    return [System.Security.SecurityElement]::Escape($Value)
}

function Add-AgentUploadsEntry([string]$Text, [string]$Path) {
    [xml]$xml = $Text
    $desiredPath = [System.IO.Path]::GetFullPath($Path).TrimEnd("\")
    foreach ($node in $xml.SelectNodes("/ossec_config/syscheck/directories")) {
        $currentPath = ([string]$node.InnerText).Trim().Replace("/", "\").TrimEnd("\")
        if ([string]::Equals([System.IO.Path]::GetFullPath($currentPath).TrimEnd("\"), $desiredPath, [StringComparison]::OrdinalIgnoreCase)) {
            if ($node.GetAttribute("check_all") -ne "yes" -or $node.GetAttribute("realtime") -ne "yes") {
                throw "The uploads FIM entry already exists with different attributes. No config was changed."
            }
            return [pscustomobject]@{ Text = $Text; Changed = $false }
        }
    }
    $escaped = Escape-XmlText $desiredPath
    $entry = "`r`n    <directories check_all=`"yes`" realtime=`"yes`">$escaped</directories>"
    $syscheckMatch = [regex]::Match($Text, '(?is)<syscheck(?:\s[^>]*)?>.*?</syscheck>')
    if ($syscheckMatch.Success) {
        $replacement = $syscheckMatch.Value -replace '(?is)</syscheck>\s*$', ($entry + "`r`n  </syscheck>")
        $updated = $Text.Substring(0, $syscheckMatch.Index) + $replacement + $Text.Substring($syscheckMatch.Index + $syscheckMatch.Length)
    } else {
        $rootClose = [regex]::Match($Text, '(?is)</ossec_config>\s*$')
        if (-not $rootClose.Success) { throw "Could not locate the closing ossec_config tag in Agent configuration." }
        $block = "`r`n  <syscheck>`r`n    <directories check_all=`"yes`" realtime=`"yes`">$escaped</directories>`r`n  </syscheck>`r`n"
        $updated = $Text.Substring(0, $rootClose.Index) + $block + $Text.Substring($rootClose.Index)
    }
    [xml]$validation = $updated
    return [pscustomobject]@{ Text = $updated; Changed = $true }
}

function Get-ManagerSyslogBlocks([string]$Text) {
    $result = @{}
    foreach ($match in [regex]::Matches($Text, '(?is)<syslog_output>\s*(.*?)\s*</syslog_output>')) {
        $body = $match.Groups[1].Value
        $rule = [regex]::Match($body, '(?is)<rule_id>\s*(.*?)\s*</rule_id>')
        if (-not $rule.Success) { continue }
        $ruleId = $rule.Groups[1].Value.Trim()
        if (-not $result.ContainsKey($ruleId)) { $result[$ruleId] = @() }
        $get = { param($tag) $m = [regex]::Match($body, ('(?is)<' + $tag + '>\s*(.*?)\s*</' + $tag + '>')); if ($m.Success) { $m.Groups[1].Value.Trim() } else { "" } }
        $result[$ruleId] += [pscustomobject]@{
            server = (& $get "server")
            port = (& $get "port")
            level = (& $get "level")
            rule_id = $ruleId
            format = (& $get "format")
        }
    }
    return $result
}

function Build-ManagerCandidate([string]$Text, [int[]]$RuleIds, [string]$HostName, [int]$Port) {
    $existing = Get-ManagerSyslogBlocks $Text
    $missing = @()
    foreach ($ruleId in $RuleIds) {
        $key = [string]$ruleId
        if ($existing.ContainsKey($key)) {
            $items = @($existing[$key])
            if ($items.Count -ne 1) { throw "Manager has duplicate syslog_output blocks for rule $ruleId." }
            $item = $items[0]
            if ($item.server -cne $HostName -or $item.port -cne [string]$Port -or $item.level -cne "1" -or $item.format -cne "default") {
                throw "Manager rule $ruleId already has a different syslog_output. Existing values will not be overwritten."
            }
        } else {
            $missing += $ruleId
        }
    }
    if ($missing.Count -eq 0) { return [pscustomobject]@{ Text = $Text; Changed = $false; Added = @() } }
    $rootCloses = [regex]::Matches($Text, '(?is)</ossec_config>')
    if ($rootCloses.Count -eq 0) { throw "Could not locate an ossec_config block in Manager configuration." }
    $insertAt = $rootCloses[$rootCloses.Count - 1].Index
    $builder = New-Object System.Text.StringBuilder
    foreach ($ruleId in $missing) {
        [void]$builder.AppendLine("  <syslog_output>")
        [void]$builder.AppendLine("    <server>$(Escape-XmlText $HostName)</server>")
        [void]$builder.AppendLine("    <port>$Port</port>")
        [void]$builder.AppendLine("    <level>1</level>")
        [void]$builder.AppendLine("    <rule_id>$ruleId</rule_id>")
        [void]$builder.AppendLine("    <format>default</format>")
        [void]$builder.AppendLine("  </syslog_output>")
    }
    $candidate = $Text.Substring(0, $insertAt) + "`r`n" + $builder.ToString() + $Text.Substring($insertAt)
    $wrapped = "<nexus_validation_root>" + [regex]::Replace($candidate, '(?is)^\s*<\?xml[^>]*\?>', "") + "</nexus_validation_root>"
    [xml]$xmlCheck = $wrapped
    return [pscustomobject]@{ Text = $candidate; Changed = $true; Added = $missing }
}

$agentService = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
if (-not $agentService) { throw "Windows Wazuh Agent service WazuhSvc was not found." }
$agentExe = [string]$agentService.PathName
if ($agentExe.StartsWith('"')) { $agentExe = ($agentExe -split '"')[1] } else { $agentExe = ($agentExe -split '\s+')[0] }
$agentConfigPath = Join-Path (Split-Path -Parent $agentExe) "ossec.conf"
if (-not (Test-Path -LiteralPath $agentConfigPath)) { throw "Wazuh Agent config was not found: $agentConfigPath" }

$agentOriginal = Get-Content -LiteralPath $agentConfigPath -Raw
$agentTemplatePath = Join-Path $PackageRoot "agent_fim_template.xml"
[xml]$agentTemplate = Get-Content -LiteralPath $agentTemplatePath -Raw
$templateDirectory = $agentTemplate.SelectSingleNode("/nexus_wazuh_migration/agent_fim/syscheck/directories")
if (-not $templateDirectory -or $templateDirectory.GetAttribute("check_all") -ne "yes" -or $templateDirectory.GetAttribute("realtime") -ne "yes" -or [string]$templateDirectory.InnerText -cne "{{PROJECT_ROOT}}\instance\uploads") {
    throw "Agent FIM template differs from the expected uploads-only contract."
}
$agentResult = Add-AgentUploadsEntry $agentOriginal $uploadsPath
$managerRead = Invoke-Docker @("exec", $ManagerContainerName, "cat", "/var/ossec/etc/ossec.conf")
$managerOriginal = $managerRead.Output
if ([string]::IsNullOrWhiteSpace($managerOriginal)) { throw "Wazuh Manager ossec.conf could not be read." }
$wazuhPackagePath = Join-Path $PackageRoot "manager_syslog_output_template.xml"
[xml]$fragment = Get-Content -LiteralPath $wazuhPackagePath -Raw
$managerEntries = @($fragment.SelectNodes("/nexus_wazuh_migration/manager_syslog_output/syslog_output"))
$templateIds = @($managerEntries | ForEach-Object { [int]$_.SelectSingleNode("rule_id").InnerText })
if (@($templateIds | Sort-Object -Unique).Count -ne 3 -or (@($templateIds | Sort-Object -Unique) -join ",") -ne "550,553,554") { throw "Wazuh export must contain exactly FIM rules 550, 553, and 554." }
foreach ($entry in $managerEntries) {
    if ([string]$entry.SelectSingleNode("server").InnerText -cne "{{GRAYLOG_HOST}}" -or [int]$entry.SelectSingleNode("port").InnerText -ne 5140 -or [int]$entry.SelectSingleNode("level").InnerText -ne 1 -or [string]$entry.SelectSingleNode("format").InnerText -cne "default") {
        throw "Manager forwarding template differs from the observed Graylog 5140 / level 1 / default format contract."
    }
}
$managerResult = Build-ManagerCandidate $managerOriginal $templateIds $GraylogHost $GraylogPort

Write-Output "Wazuh Agent: $agentConfigPath"
Write-Output "Uploads FIM: $uploadsPath"
Write-Output ("Agent config: {0}" -f $(if ($agentResult.Changed) { "ADD uploads entry" } else { "already exact; no-op" }))
Write-Output ("Manager config: {0}" -f $(if ($managerResult.Changed) { "ADD rule IDs $($managerResult.Added -join ',') to syslog_output" } else { "FIM forwarding already exact; no-op" }))
Write-Output "Manager validation: wazuh-analysisd -t will run before restart. Existing unrelated Agent/Manager config is retained."
if ($DryRun) { Write-Output "Dry run complete. No Agent/Manager files or services were changed."; return }
if (-not $agentResult.Changed -and -not $managerResult.Changed) { Write-Output "Wazuh configuration already matches the package; nothing was written or restarted."; return }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$agentBackup = if ($agentResult.Changed) { "$agentConfigPath.nexus-migration-$stamp.bak" } else { $null }
$managerBackup = if ($managerResult.Changed) { "/var/ossec/etc/ossec.conf.nexus-migration-$stamp.bak" } else { $null }
$stagedManager = Join-Path $env:TEMP "nexus-manager-ossec-$stamp.conf"
if ($agentResult.Changed) { Copy-Item -LiteralPath $agentConfigPath -Destination $agentBackup -ErrorAction Stop }
if ($managerResult.Changed) {
    $backupResult = Invoke-Docker @("exec", $ManagerContainerName, "cp", "/var/ossec/etc/ossec.conf", $managerBackup)
    if ($backupResult.ExitCode -ne 0) { throw "Manager config backup failed; Agent config was not changed." }
    Write-Utf8NoBom $stagedManager $managerResult.Text
}

try {
    if ($managerResult.Changed) {
        $copy = Invoke-Docker @("cp", $stagedManager, ("{0}:/var/ossec/etc/ossec.conf" -f $ManagerContainerName))
        if ($copy.ExitCode -ne 0) { throw "Could not stage the Manager config." }
        $validation = Invoke-Docker @("exec", $ManagerContainerName, "/var/ossec/bin/wazuh-analysisd", "-t") -AllowFailure
        if ($validation.ExitCode -ne 0) {
            Invoke-Docker @("exec", $ManagerContainerName, "cp", $managerBackup, "/var/ossec/etc/ossec.conf") | Out-Null
            throw "wazuh-analysisd -t failed. The original Manager config was restored; see the container log for detail."
        }
    }
    if ($agentResult.Changed) { Write-Utf8NoBom $agentConfigPath $agentResult.Text }
    if ($managerResult.Changed) {
        $restartManager = Invoke-Docker @("restart", $ManagerContainerName) -AllowFailure
        if ($restartManager.ExitCode -ne 0) {
            Invoke-Docker @("exec", $ManagerContainerName, "cp", $managerBackup, "/var/ossec/etc/ossec.conf") -AllowFailure | Out-Null
            throw "Wazuh Manager container restart failed. The original Manager config was restored; backups remain at $managerBackup and $agentBackup."
        }
    }
    if ($agentResult.Changed) { Restart-Service -Name "WazuhSvc" -ErrorAction Stop }
} catch {
    if ($agentResult.Changed -and (Test-Path -LiteralPath $agentBackup)) { Copy-Item -LiteralPath $agentBackup -Destination $agentConfigPath -Force }
    throw
} finally {
    if (Test-Path -LiteralPath $stagedManager) { Remove-Item -LiteralPath $stagedManager -Force }
}

$agentCurrent = Get-Service -Name "WazuhSvc"
if ($agentCurrent.Status -ne "Running") { throw "WazuhSvc is not running after apply. Config backups: $agentBackup; $managerBackup" }
$managerState = Invoke-Docker @("inspect", "--format", "{{.State.Running}}", $ManagerContainerName) -AllowFailure
if ($managerState.ExitCode -ne 0 -or $managerState.Output.Trim() -ne "true") { throw "Wazuh Manager container is not running after apply. Config backups: $agentBackup; $managerBackup" }
$agentList = Invoke-Docker @("exec", $ManagerContainerName, "/var/ossec/bin/agent_control", "-lc") -AllowFailure
if ([string]::IsNullOrWhiteSpace($AgentName)) { throw "Could not determine local Agent name. Pass -AgentName to verify the Manager connection." }
$activeAgentPattern = '(?im).*Name:\s*' + [regex]::Escape($AgentName) + '.*Active.*'
if ($agentList.ExitCode -ne 0 -or $agentList.Output -notmatch $activeAgentPattern) { throw "Agent '$AgentName' is not shown active on the Manager. Inspect Wazuh Dashboard and retained backups." }
Write-Output "Wazuh migration changes applied and local Agent/Manager running state checked."
Write-Output "Backups retained: $agentBackup and $managerBackup"
