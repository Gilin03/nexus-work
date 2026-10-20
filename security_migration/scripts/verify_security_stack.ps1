[CmdletBinding()]
param(
    [string]$GraylogUrl = "http://127.0.0.1:9000",
    [string]$ApiToken = $env:GRAYLOG_API_TOKEN,
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$InputHost,
    [string]$GraylogHost = "gl-graylog",
    [string]$ManagerContainerName = "wazuh-manager",
    [string]$AgentName = $env:COMPUTERNAME,
    [switch]$TestGelf,
    [switch]$RunFimSmokeTest,
    [string]$PackageRoot = (Join-Path $PSScriptRoot "..\export")
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($ApiToken)) { throw "Provide -ApiToken or set GRAYLOG_API_TOKEN. The token is never printed." }
if ($RunFimSmokeTest -and [string]::IsNullOrWhiteSpace($ProjectRoot)) { throw "-ProjectRoot is required with -RunFimSmokeTest." }
$baseUri = $GraylogUrl.TrimEnd("/") + "/api"
$basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:token" -f $ApiToken)))
$headers = @{ Authorization = "Basic $basic"; "X-Requested-By" = "NEXUS-security-migration-verify"; Accept = "application/json" }

function Invoke-GraylogGet([string]$Path) {
    try { return Invoke-RestMethod -Method Get -Uri ($baseUri + $Path) -Headers $headers -TimeoutSec 30 }
    catch {
        $status = "unknown"
        if ($_.Exception.Response) { $status = [string][int]$_.Exception.Response.StatusCode }
        throw "Graylog read failed: GET $Path (HTTP $status). Credentials and response content were omitted."
    }
}

function Invoke-DockerText([string[]]$Arguments) {
    $output = & docker @Arguments 2>$null
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "Docker read failed (exit $code): docker $($Arguments[0]) ..." }
    return ($output | Out-String)
}

function Get-TitleMatches($Items, [string]$Title) { return @($Items | Where-Object { [string]$_.title -ceq $Title }) }

function Get-SyslogRuleBlocks([string]$Text, [string]$RuleId) {
    $found = @()
    foreach ($match in [regex]::Matches($Text, '(?is)<syslog_output>\s*(.*?)\s*</syslog_output>')) {
        $body = $match.Groups[1].Value
        $ruleMatch = [regex]::Match($body, '(?is)<rule_id>\s*(.*?)\s*</rule_id>')
        if (-not $ruleMatch.Success -or $ruleMatch.Groups[1].Value.Trim() -ne $RuleId) { continue }
        $values = @{}
        foreach ($tag in @("server", "port", "level", "format")) {
            $valueMatch = [regex]::Match($body, ('(?is)<' + $tag + '>\s*(.*?)\s*</' + $tag + '>'))
            $values[$tag] = if ($valueMatch.Success) { $valueMatch.Groups[1].Value.Trim() } else { "" }
        }
        $found += [pscustomobject]$values
    }
    return @($found)
}

function Get-RelativeSearch([string]$Query, [string]$StreamId, [int]$RangeSeconds = 180) {
    $queryEncoded = [uri]::EscapeDataString($Query)
    $filterEncoded = [uri]::EscapeDataString(("streams:{0}" -f $StreamId))
    $fieldsEncoded = [uri]::EscapeDataString("event_type,test_marker,message,gl2_source_input")
    $uri = "{0}/search/universal/relative?query={1}&range={2}&limit=20&filter={3}&fields={4}&sort=timestamp%3Adesc" -f $baseUri, $queryEncoded, $RangeSeconds, $filterEncoded, $fieldsEncoded
    try { return Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -TimeoutSec 30 }
    catch {
        $status = "unknown"
        if ($_.Exception.Response) { $status = [string][int]$_.Exception.Response.StatusCode }
        throw "Graylog message search failed (HTTP $status). Use Graylog Search to verify the marker if this endpoint is disabled."
    }
}

function Get-SearchMessages($SearchResponse) {
    if ($SearchResponse.messages) { return @($SearchResponse.messages) }
    if ($SearchResponse.results) { return @($SearchResponse.results) }
    return @()
}

$system = Invoke-GraylogGet "/system"
$inputs = @((Invoke-GraylogGet "/system/inputs").inputs)
$streams = @((Invoke-GraylogGet "/streams").streams)
$definitions = @((Invoke-GraylogGet "/events/definitions").event_definitions)
$inputPackage = Get-Content -LiteralPath (Join-Path $PackageRoot "graylog\inputs.json") -Raw | ConvertFrom-Json
$streamPackage = Get-Content -LiteralPath (Join-Path $PackageRoot "graylog\streams.json") -Raw | ConvertFrom-Json
$definitionPackage = Get-Content -LiteralPath (Join-Path $PackageRoot "graylog\event_definitions.json") -Raw | ConvertFrom-Json
$streamIdByName = @{}
$streamNameById = @{}
$results = @()

foreach ($desired in @($inputPackage.inputs)) {
    $found = Get-TitleMatches $inputs ([string]$desired.title)
    $valid = $found.Count -eq 1 -and [string]$found[0].type -ceq [string]$desired.type -and [bool]$found[0].global -eq [bool]$desired.global -and [int]$found[0].attributes.port -eq [int]$desired.configuration.port
    $results += [pscustomobject]@{ Check = "Input $($desired.title)"; Result = $(if ($valid) { "PASS" } else { "FAIL" }) }
}

$indexSets = @((Invoke-GraylogGet "/system/indices/index_sets").index_sets)
foreach ($desired in @($streamPackage.streams)) {
    $found = Get-TitleMatches $streams ([string]$desired.title)
    if ($found.Count -ne 1) {
        $results += [pscustomobject]@{ Check = "Stream $($desired.title)"; Result = "FAIL" }
        continue
    }
    $detail = Invoke-GraylogGet ("/streams/" + [uri]::EscapeDataString([string]$found[0].id))
    $streamIdByName[[string]$desired.title] = [string]$detail.id
    $streamNameById[[string]$detail.id] = [string]$detail.title
    $rulesOkay = @($detail.rules).Count -eq @($desired.rules).Count
    if ($rulesOkay) {
        foreach ($rule in @($desired.rules)) {
            if ($rule.input_ref) {
                $inputSpec = @($inputPackage.inputs | Where-Object { [string]$_.key -eq [string]$rule.input_ref } | Select-Object -First 1)
                $inputTitle = if ($inputSpec.Count -eq 1) { [string]$inputSpec[0].title } else { "" }
                $inputMatches = Get-TitleMatches $inputs $inputTitle
                $ruleOkay = $inputMatches.Count -eq 1 -and @($detail.rules | Where-Object { $_.field -eq $rule.field -and [int]$_.type -eq [int]$rule.type -and [string]$_.value -eq [string]$inputMatches[0].id -and [bool]$_.inverted -eq [bool]$rule.inverted }).Count -eq 1
            } else {
                $ruleOkay = @($detail.rules | Where-Object { $_.field -eq $rule.field -and [int]$_.type -eq [int]$rule.type -and [string]$_.value -ceq [string]$rule.value -and [bool]$_.inverted -eq [bool]$rule.inverted }).Count -eq 1
            }
            if (-not $ruleOkay) { $rulesOkay = $false; break }
        }
    }
    $valid = -not [bool]$detail.disabled -and $rulesOkay
    $results += [pscustomobject]@{ Check = "Stream $($desired.title) enabled/rules"; Result = $(if ($valid) { "PASS" } else { "FAIL" }) }
}

foreach ($desired in @($definitionPackage.event_definitions)) {
    $found = Get-TitleMatches $definitions ([string]$desired.display_name)
    $streamNames = @()
    if ($found.Count -eq 1) {
        foreach ($id in @($found[0].config.streams)) {
            if (-not $streamNameById.ContainsKey([string]$id)) {
                $stream = Invoke-GraylogGet ("/streams/" + [uri]::EscapeDataString([string]$id))
                $streamNameById[[string]$id] = [string]$stream.title
            }
            $streamNames += $streamNameById[[string]$id]
        }
    }
    $valid = $found.Count -eq 1 -and [string]$found[0].state -eq "ENABLED" -and [int]$found[0].priority -ge 1 -and [int]$found[0].priority -le 3 -and @($streamNames | Where-Object { $_ -eq [string]$desired.config.stream_names[0] }).Count -gt 0
    $results += [pscustomobject]@{ Check = "$($desired.rule_id) Event Definition enabled/priority/Stream"; Result = $(if ($valid) { "PASS" } else { "FAIL" }) }
}

Write-Output ("Graylog version: {0}" -f [string]$system.version)

$rootPath = (Resolve-Path -LiteralPath $ProjectRoot).Path
$uploadsPath = (Join-Path $rootPath "instance\uploads").TrimEnd("\")
$agentCim = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
$agentConfigPath = $null
if ($agentCim) {
    $agentExe = [string]$agentCim.PathName
    if ($agentExe.StartsWith('"')) { $agentExe = ($agentExe -split '"')[1] } else { $agentExe = ($agentExe -split '\s+')[0] }
    $agentConfigPath = Join-Path (Split-Path -Parent $agentExe) "ossec.conf"
}
$agentFimOkay = $false
if ($agentConfigPath -and (Test-Path -LiteralPath $agentConfigPath) -and (Test-Path -LiteralPath $uploadsPath -PathType Container)) {
    [xml]$agentXml = Get-Content -LiteralPath $agentConfigPath -Raw
    foreach ($entry in $agentXml.SelectNodes("/ossec_config/syscheck/directories")) {
        $path = ([string]$entry.InnerText).Trim().Replace("/", "\").TrimEnd("\")
        if ([string]::Equals([System.IO.Path]::GetFullPath($path).TrimEnd("\"), [System.IO.Path]::GetFullPath($uploadsPath).TrimEnd("\"), [StringComparison]::OrdinalIgnoreCase) -and $entry.GetAttribute("check_all") -eq "yes" -and $entry.GetAttribute("realtime") -eq "yes") { $agentFimOkay = $true }
    }
}
$results += [pscustomobject]@{ Check = "Wazuh Agent uploads FIM path"; Result = $(if ($agentFimOkay) { "PASS" } else { "FAIL" }) }

$agentService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
$managerState = Invoke-DockerText @("inspect", "--format", "{{.State.Running}}", $ManagerContainerName)
$agentControl = Invoke-DockerText @("exec", $ManagerContainerName, "/var/ossec/bin/agent_control", "-lc")
$managerConfig = Invoke-DockerText @("exec", $ManagerContainerName, "cat", "/var/ossec/etc/ossec.conf")
$forwardingOkay = $true
foreach ($ruleId in @("550", "553", "554")) {
    $entries = Get-SyslogRuleBlocks $managerConfig $ruleId
    if ($entries.Count -ne 1 -or $entries[0].server -cne $GraylogHost -or $entries[0].port -ne "5140" -or $entries[0].level -ne "1" -or $entries[0].format -cne "default") { $forwardingOkay = $false }
}
$results += [pscustomobject]@{ Check = "Wazuh Manager forwards FIM rules 550/553/554"; Result = $(if ($forwardingOkay) { "PASS" } else { "FAIL" }) }
$activeAgentPattern = '(?im).*Name:\s*' + [regex]::Escape($AgentName) + '.*Active.*'
$agentConnected = $agentService -and $agentService.Status -eq "Running" -and $managerState.Trim() -eq "true" -and $agentControl -match $activeAgentPattern
$results += [pscustomobject]@{ Check = "Wazuh Manager/Agent running and active"; Result = $(if ($agentConnected) { "PASS" } else { "FAIL" }) }

if ($TestGelf) {
    $inputConfig = $inputPackage.inputs | Where-Object key -eq "app_gelf_udp" | Select-Object -First 1
    $inputEntry = Get-TitleMatches $inputs ([string]$inputConfig.title) | Select-Object -First 1
    if (-not $inputEntry) { throw "GELF Input is missing; synthetic event was not sent." }
    if ([string]::IsNullOrWhiteSpace($InputHost)) {
        $apiHost = ([uri]$GraylogUrl).Host
        $InputHost = $apiHost
    }
    $marker = "nexus_migration_" + [guid]::NewGuid().ToString("N")
    $payload = [ordered]@{
        version = "1.1"
        host = "nexus-migration-verify"
        short_message = "NEXUS migration GELF stream classification check"
        timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
        level = 6
        _event_type = "login_locked"
        _user = "migration_test"
        _source_component = "security_migration"
        _test_marker = $marker
    } | ConvertTo-Json -Compress
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
        [void]$udp.Send($bytes, $bytes.Length, $InputHost, [int]$inputConfig.configuration.port)
    } finally { $udp.Dispose() }
    if (-not $streamIdByName.ContainsKey("NEXUS_AUTH")) { throw "NEXUS_AUTH Stream is missing; GELF message was sent but cannot confirm classification." }
    $foundMessage = $false
    for ($attempt = 0; $attempt -lt 15; $attempt++) {
        Start-Sleep -Seconds 2
        $search = Get-RelativeSearch ("test_marker:{0}" -f $marker) $streamIdByName["NEXUS_AUTH"]
        if ((Get-SearchMessages $search).Count -gt 0) { $foundMessage = $true; break }
    }
    $results += [pscustomobject]@{ Check = "GELF synthetic message classified into NEXUS_AUTH"; Result = $(if ($foundMessage) { "PASS" } else { "FAIL" }) }
    Write-Output "GELF verification marker: $marker"
}

if ($RunFimSmokeTest) {
    $root = (Resolve-Path -LiteralPath $ProjectRoot).Path
    $uploads = Join-Path $root "instance\uploads"
    if (-not (Test-Path -LiteralPath $uploads -PathType Container)) { throw "uploads directory does not exist; FIM smoke test was not run." }
    $fileName = "nexus-fim-verify-" + [guid]::NewGuid().ToString("N") + ".txt"
    $filePath = Join-Path $uploads $fileName
    $expectedIds = @{ create = "554"; modify = "550"; delete = "553" }
    $observed = @{}
    try {
        [System.IO.File]::WriteAllText($filePath, "create marker")
        Start-Sleep -Seconds 2
        [System.IO.File]::WriteAllText($filePath, "modified marker " + [guid]::NewGuid().ToString("N"))
        Start-Sleep -Seconds 2
        Remove-Item -LiteralPath $filePath -Force
    } finally {
        if (Test-Path -LiteralPath $filePath) { Remove-Item -LiteralPath $filePath -Force }
    }
    $remaining = @("create", "modify", "delete")
    for ($attempt = 0; $attempt -lt 30 -and $remaining.Count -gt 0; $attempt++) {
        $grep = Invoke-DockerText @("exec", $ManagerContainerName, "sh", "-lc", ("grep -F -- '{0}' /var/ossec/logs/alerts/alerts.json | tail -n 100" -f $fileName))
        foreach ($line in ($grep -split "`r?`n")) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try { $alert = $line | ConvertFrom-Json } catch { continue }
            $ruleId = [string]$alert.rule.id
            foreach ($action in @($remaining)) {
                if ($ruleId -eq $expectedIds[$action]) { $observed[$action] = $ruleId }
            }
        }
        $remaining = @(@("create", "modify", "delete") | Where-Object { -not $observed.ContainsKey($_) })
        if ($remaining.Count -gt 0) { Start-Sleep -Seconds 2 }
    }
    foreach ($action in @("create", "modify", "delete")) {
        $results += [pscustomobject]@{ Check = "Wazuh uploads FIM $action (rule $($expectedIds[$action]))"; Result = $(if ($observed.ContainsKey($action)) { "PASS" } else { "FAIL" }) }
    }
    $webId = $streamIdByName["NEXUS_WEB"]
    $forwarded = $false
    if (-not [string]::IsNullOrWhiteSpace($webId)) {
        for ($attempt = 0; $attempt -lt 15; $attempt++) {
            Start-Sleep -Seconds 2
            $search = Get-RelativeSearch ('message:"{0}"' -f $fileName) $webId
            if ((Get-SearchMessages $search).Count -gt 0) { $forwarded = $true; break }
        }
    }
    $results += [pscustomobject]@{ Check = "Wazuh FIM message reached Graylog NEXUS_WEB"; Result = $(if ($forwarded) { "PASS" } else { "FAIL" }) }
    Write-Output "FIM verification path marker: $fileName"
    Write-Output "The FIM test file was removed after the test. Search Graylog NEXUS_WEB for the Wazuh Input source to confirm forwarding."
}

$results | Format-Table -AutoSize | Out-String | Write-Output
$failed = @($results | Where-Object Result -eq "FAIL")
if ($failed.Count -gt 0) { throw "$($failed.Count) verification check(s) failed." }
Write-Output "Security stack checks passed. Optional GELF/FIM probes ran only because their switches were supplied."
