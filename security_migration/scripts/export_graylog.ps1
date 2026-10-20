[CmdletBinding()]
param(
    [string]$GraylogUrl = "http://127.0.0.1:9000",
    [string]$ApiToken,
    [string]$OutputRoot = (Join-Path $PSScriptRoot "..\export\graylog")
)

$ErrorActionPreference = "Stop"

function Get-ApiToken {
    if (-not [string]::IsNullOrWhiteSpace($ApiToken)) { return $ApiToken }
    if (-not [string]::IsNullOrWhiteSpace($env:GRAYLOG_API_TOKEN)) { return $env:GRAYLOG_API_TOKEN }

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $envFile = Join-Path $repoRoot ".env"
    if (Test-Path -LiteralPath $envFile) {
        $line = Get-Content -LiteralPath $envFile | Where-Object { $_ -match '^\s*GRAYLOG_API_TOKEN\s*=' } | Select-Object -First 1
        if ($line) {
            return (($line -replace '^\s*GRAYLOG_API_TOKEN\s*=\s*', "").Trim().Trim('"').Trim("'"))
        }
    }
    throw "Graylog API token was not provided. Set GRAYLOG_API_TOKEN or pass -ApiToken."
}

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

$token = Get-ApiToken
$basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:token" -f $token)))
$headers = @{ Authorization = "Basic $basic"; "X-Requested-By" = "NEXUS-security-migration-export" }
$baseUri = $GraylogUrl.TrimEnd("/") + "/api"

function Invoke-GraylogGet([string]$Path) {
    try {
        return Invoke-RestMethod -Method Get -Uri ($baseUri + $Path) -Headers $headers -TimeoutSec 30
    } catch {
        $status = "unknown"
        if ($_.Exception.Response) { $status = [string][int]$_.Exception.Response.StatusCode }
        throw "Graylog read failed: GET $Path returned HTTP $status. The API token value was not logged."
    }
}

$system = Invoke-GraylogGet "/system"
if (-not $system.version) { throw "Graylog system version was not returned." }
$inputsResponse = Invoke-GraylogGet "/system/inputs"
$streamsResponse = Invoke-GraylogGet "/streams"
$indexSetsResponse = Invoke-GraylogGet "/system/indices/index_sets"
$definitionsResponse = Invoke-GraylogGet "/events/definitions"

$allInputs = @($inputsResponse.inputs)
$allStreams = @($streamsResponse.streams)
$allIndexSets = @($indexSetsResponse.index_sets)
$allDefinitions = @($definitionsResponse.event_definitions)

$inputSelectors = @(
    [ordered]@{
        key = "app_gelf_udp"
        title = "hping3 lab"
        type = "org.graylog2.inputs.gelf.udp.GELFUDPInput"
        port = 12201
        global = $false
    },
    [ordered]@{
        key = "wazuh_raw_udp"
        title = "Wazuh Alerts (JSON over UDP 5140)"
        type = "org.graylog2.inputs.raw.udp.RawUDPInput"
        port = 5140
        global = $true
    }
)
$safeInputFields = @(
    "recv_buffer_size", "port", "number_worker_threads", "override_source",
    "charset_name", "decompress_size_limit", "bind_address"
)
$inputIdByKey = @{}
$exportedInputs = @()
foreach ($selector in $inputSelectors) {
    $matches = @($allInputs | Where-Object {
        $_.title -eq $selector.title -and $_.type -eq $selector.type -and
        [int]$_.attributes.port -eq [int]$selector.port
    })
    if ($matches.Count -ne 1) {
        throw "Expected one Graylog input for selector '$($selector.key)' but found $($matches.Count). No export was written."
    }
    $input = $matches[0]
    $inputIdByKey[$selector.key] = [string]$input.id
    $configuration = [ordered]@{}
    foreach ($field in $safeInputFields) {
        $property = $input.attributes.PSObject.Properties[$field]
        if ($property) { $configuration[$field] = $property.Value }
    }
    $exportedInputs += [ordered]@{
        key = $selector.key
        title = [string]$input.title
        type = [string]$input.type
        global = [bool]$input.global
        node_selector = $(if ($input.global) { "global" } else { "single_node" })
        configuration = $configuration
    }
}

$streamNames = @("NEXUS_AUTH", "NEXUS_AI_SECURITY", "NEXUS_WEB")
$streamIdToName = @{}
foreach ($stream in $allStreams) { $streamIdToName[[string]$stream.id] = [string]$stream.title }
$indexSetById = @{}
foreach ($indexSet in $allIndexSets) { $indexSetById[[string]$indexSet.id] = $indexSet }
$streamIdByName = @{}
foreach ($streamName in $streamNames) {
    $matches = @($allStreams | Where-Object title -eq $streamName)
    if ($matches.Count -ne 1) { throw "Expected one Stream named '$streamName', found $($matches.Count)." }
    $streamIdByName[$streamName] = [string]$matches[0].id
}

$exportedStreams = @()
foreach ($streamName in $streamNames) {
    $stream = $allStreams | Where-Object title -eq $streamName | Select-Object -First 1
    $detail = Invoke-GraylogGet ("/streams/" + [uri]::EscapeDataString([string]$stream.id))
    $indexSet = $indexSetById[[string]$detail.index_set_id]
    if (-not $indexSet) { throw "Stream '$streamName' references an index set that could not be resolved." }
    $rules = @()
    foreach ($rule in @($detail.rules)) {
        if ($rule.field -eq "gl2_source_input" -and [string]$rule.value -eq $inputIdByKey["wazuh_raw_udp"]) {
            $rules += [ordered]@{
                field = [string]$rule.field
                type = [int]$rule.type
                input_ref = "wazuh_raw_udp"
                inverted = [bool]$rule.inverted
            }
        } else {
            $rules += [ordered]@{
                field = [string]$rule.field
                type = [int]$rule.type
                value = [string]$rule.value
                inverted = [bool]$rule.inverted
            }
        }
    }
    $exportedStreams += [ordered]@{
        title = [string]$detail.title
        description = [string]$detail.description
        matching_type = [string]$detail.matching_type
        index_set_selector = [ordered]@{ title = [string]$indexSet.title; use_default_if_missing = [bool]$indexSet.default }
        disabled = [bool]$detail.disabled
        remove_matches_from_default_stream = [bool]$detail.remove_matches_from_default_stream
        rules = $rules
    }
}

$stableNames = @{
    "R1" = "ACCOUNT_COMPROMISE"
    "R2" = "DIRECT_PROMPT_INJECTION_BLOCKED"
    "R5" = "ACCOUNT_SPRAY"
    "R6" = "POST_LOCK_RETRY"
    "R7" = "OFF_HOURS_LOGIN_SUCCESS"
    "R8" = "NOT_FOUND_SCAN"
    "R9" = "ADMIN_PATH_ACCESS_DENIED"
    "R10" = "DIRECT_CONFIDENTIAL_ACCESS_DENIED"
}
$expectedRuleIds = @("R1", "R2", "R5", "R6", "R7", "R8", "R9", "R10")
$exportedDefinitions = @()
foreach ($ruleId in $expectedRuleIds) {
    $matches = @($allDefinitions | Where-Object {
        $_.title -match ('^\[NEXUS\]\[' + [regex]::Escape($ruleId) + '\]')
    })
    if ($matches.Count -ne 1) { throw "Expected one Event Definition for $ruleId, found $($matches.Count)." }
    $listed = $matches[0]
    $detail = Invoke-GraylogGet ("/events/definitions/" + [uri]::EscapeDataString([string]$listed.id))
    if (@($detail.notifications).Count -gt 0) {
        throw "Event Definition '$($detail.title)' has Notification references. Review and export those separately; no Notification secrets are included automatically."
    }

    $config = $detail.config | ConvertTo-Json -Depth 40 -Compress | ConvertFrom-Json
    $resolvedStreamNames = @()
    foreach ($streamId in @($detail.config.streams)) {
        if (-not $streamIdToName.ContainsKey([string]$streamId)) {
            throw "Event Definition '$($detail.title)' references an unresolved Stream."
        }
        $resolvedStreamNames += $streamIdToName[[string]$streamId]
    }
    $config.PSObject.Properties.Remove("streams")
    $config | Add-Member -MemberType NoteProperty -Name "stream_names" -Value $resolvedStreamNames

    $storage = @()
    foreach ($storageEntry in @($detail.storage)) {
        $storageStreamNames = @()
        foreach ($storageStreamId in @($storageEntry.streams)) {
            if (-not $streamIdToName.ContainsKey([string]$storageStreamId)) {
                $storageStream = Invoke-GraylogGet ("/streams/" + [uri]::EscapeDataString([string]$storageStreamId))
                $streamIdToName[[string]$storageStreamId] = [string]$storageStream.title
            }
            $storageStreamNames += $streamIdToName[[string]$storageStreamId]
        }
        $storage += [ordered]@{ type = [string]$storageEntry.type; stream_names = $storageStreamNames }
    }

    $exportedDefinitions += [ordered]@{
        rule_id = $ruleId
        stable_name = $stableNames[$ruleId]
        display_name = [string]$detail.title
        state = [string]$detail.state
        priority = [int]$detail.priority
        alert = [bool]$detail.alert
        description = [string]$detail.description
        remediation_steps = [string]$detail.remediation_steps
        config = $config
        field_spec = $detail.field_spec
        key_spec = @($detail.key_spec)
        notification_settings = $detail.notification_settings
        notifications = @()
        storage = $storage
    }
}

foreach ($definition in $exportedDefinitions) {
    if ([int]$definition.priority -lt 1 -or [int]$definition.priority -gt 3) {
        throw "Event Definition '$($definition.display_name)' has priority outside Graylog 6.1.16 range 1..3."
    }
}

$root = [ordered]@{
    schema_version = 1
    source_graylog_version = [string]$system.version
    inputs = $exportedInputs
}
Write-Utf8NoBom (Join-Path $OutputRoot "inputs.json") ($root | ConvertTo-Json -Depth 40)
$streamRoot = [ordered]@{ schema_version = 1; streams = $exportedStreams }
Write-Utf8NoBom (Join-Path $OutputRoot "streams.json") ($streamRoot | ConvertTo-Json -Depth 40)
$definitionRoot = [ordered]@{
    schema_version = 1
    source_graylog_version = [string]$system.version
    event_definitions = $exportedDefinitions
}
Write-Utf8NoBom (Join-Path $OutputRoot "event_definitions.json") ($definitionRoot | ConvertTo-Json -Depth 50)

Write-Output "Exported 2 project Inputs, 3 NEXUS Streams, and 8 Event Definitions."
Write-Output "Graylog API credentials and server-internal object IDs were excluded."
