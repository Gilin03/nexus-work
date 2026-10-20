[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$GraylogUrl,
    [string]$ApiToken = $env:GRAYLOG_API_TOKEN,
    [switch]$DryRun,
    [switch]$Apply,
    [string]$NodeId,
    [string]$PackageRoot = (Join-Path $PSScriptRoot "..\export\graylog")
)

$ErrorActionPreference = "Stop"
if ($DryRun -eq $Apply) { throw "Select exactly one mode: -DryRun or -Apply." }
if ([string]::IsNullOrWhiteSpace($ApiToken)) { throw "Provide -ApiToken or set GRAYLOG_API_TOKEN. The token is never printed." }

$baseUri = $GraylogUrl.TrimEnd("/") + "/api"
$basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:token" -f $ApiToken)))
$headers = @{ Authorization = "Basic $basic"; "X-Requested-By" = "NEXUS-security-migration-import" }

function Invoke-Graylog([string]$Method, [string]$Path, $Body = $null) {
    try {
        $requestArgs = @{ Method = $Method; Uri = ($baseUri + $Path); Headers = $headers; TimeoutSec = 45 }
        if ($null -ne $Body) {
            $requestArgs.ContentType = "application/json"
            $requestArgs.Body = $Body | ConvertTo-Json -Depth 50 -Compress
        }
        return Invoke-RestMethod @requestArgs
    } catch {
        $status = "unknown"
        if ($_.Exception.Response) { $status = [string][int]$_.Exception.Response.StatusCode }
        throw "Graylog API request failed: $Method $Path (HTTP $status). Response and credentials were omitted."
    }
}

function Get-Items($Response, [string]$Property) {
    if ($null -eq $Response -or $null -eq $Response.$Property) { return @() }
    return @($Response.$Property)
}

function Get-CanonicalValue($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in @($Value.Keys | Sort-Object)) { $result[[string]$key] = Get-CanonicalValue $Value[$key] }
        return $result
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $result = [ordered]@{}
        foreach ($property in @($Value.PSObject.Properties | Sort-Object Name)) { $result[$property.Name] = Get-CanonicalValue $property.Value }
        return $result
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $result = @()
        foreach ($item in $Value) { $result += ,(Get-CanonicalValue $item) }
        return ,$result
    }
    return $Value
}

function Get-CanonicalJson($Value) {
    return (Get-CanonicalValue $Value | ConvertTo-Json -Depth 50 -Compress)
}

function Get-TitleMatches($Items, [string]$Title) {
    return @($Items | Where-Object { [string]$_.title -ceq $Title })
}

function Get-StreamNamesById($Streams, $IndexSets) {
    $result = @{}
    foreach ($stream in $Streams) { $result[[string]$stream.id] = [string]$stream.title }
    return $result
}

function Resolve-InputByKey($Inputs, [string]$Key) {
    return $Inputs | Where-Object { $_.key -eq $Key } | Select-Object -First 1
}

function Test-InputEquivalent($Existing, $Desired) {
    if ([string]$Existing.title -cne [string]$Desired.title -or [string]$Existing.type -cne [string]$Desired.type -or [bool]$Existing.global -ne [bool]$Desired.global) { return $false }
    foreach ($property in $Desired.configuration.PSObject.Properties) {
        $current = $Existing.attributes.PSObject.Properties[$property.Name]
        if (-not $current) { return $false }
        if ((Get-CanonicalJson $current.Value) -cne (Get-CanonicalJson $property.Value)) { return $false }
    }
    return $true
}

function Convert-DesiredRule($Rule, $InputIdByKey) {
    $value = [string]$Rule.value
    if ($Rule.input_ref) {
        $value = [string]$InputIdByKey[[string]$Rule.input_ref]
        if ([string]::IsNullOrWhiteSpace($value)) { return $null }
    }
    return [ordered]@{ field = [string]$Rule.field; type = [int]$Rule.type; value = $value; inverted = [bool]$Rule.inverted }
}

function Convert-ExistingRules($Rules) {
    $result = @()
    foreach ($rule in @($Rules)) {
        $result += [ordered]@{ field = [string]$rule.field; type = [int]$rule.type; value = [string]$rule.value; inverted = [bool]$rule.inverted }
    }
    return @($result | Sort-Object { Get-CanonicalJson $_ })
}

function Convert-DesiredRules($Rules, $InputIdByKey) {
    $result = @()
    foreach ($rule in @($Rules)) {
        $converted = Convert-DesiredRule $rule $InputIdByKey
        if ($null -eq $converted) { return $null }
        $result += $converted
    }
    return @($result | Sort-Object { Get-CanonicalJson $_ })
}

function Test-IndexSetSelector($IndexSetId, $Selector, $IndexSets) {
    $item = $IndexSets | Where-Object { [string]$_.id -eq [string]$IndexSetId } | Select-Object -First 1
    if (-not $item) { return $false }
    if ([string]$item.title -ceq [string]$Selector.title) { return $true }
    return ([bool]$Selector.use_default_if_missing -and [bool]$item.default)
}

function Test-StreamEquivalent($Existing, $Desired, $InputIdByKey, $IndexSets) {
    if ([string]$Existing.title -cne [string]$Desired.title -or [string]$Existing.description -cne [string]$Desired.description -or [string]$Existing.matching_type -cne [string]$Desired.matching_type) { return $false }
    if ([bool]$Existing.disabled -ne [bool]$Desired.disabled -or [bool]$Existing.remove_matches_from_default_stream -ne [bool]$Desired.remove_matches_from_default_stream) { return $false }
    if (-not (Test-IndexSetSelector $Existing.index_set_id $Desired.index_set_selector $IndexSets)) { return $false }
    $expectedRules = Convert-DesiredRules $Desired.rules $InputIdByKey
    if ($null -eq $expectedRules) { return $false }
    $actualRules = Convert-ExistingRules $Existing.rules
    return ((Get-CanonicalJson $actualRules) -ceq (Get-CanonicalJson $expectedRules))
}

function Convert-ExistingDefinitionToComparable($Definition, $StreamNameById) {
    $config = $Definition.config | ConvertTo-Json -Depth 50 -Compress | ConvertFrom-Json
    $names = @()
    foreach ($id in @($Definition.config.streams)) {
        if (-not $StreamNameById.ContainsKey([string]$id)) { $names += "<unresolved>" }
        else { $names += $StreamNameById[[string]$id] }
    }
    $config.PSObject.Properties.Remove("streams")
    $config | Add-Member -MemberType NoteProperty -Name "stream_names" -Value @($names)
    $storage = @()
    foreach ($entry in @($Definition.storage)) {
        $storageNames = @()
        foreach ($id in @($entry.streams)) {
            if (-not $StreamNameById.ContainsKey([string]$id)) { $storageNames += "<unresolved>" }
            else { $storageNames += $StreamNameById[[string]$id] }
        }
        $storage += [ordered]@{ type = [string]$entry.type; stream_names = @($storageNames) }
    }
    return [ordered]@{
        title = [string]$Definition.title
        description = [string]$Definition.description
        remediation_steps = [string]$Definition.remediation_steps
        priority = [int]$Definition.priority
        alert = [bool]$Definition.alert
        config = $config
        field_spec = $Definition.field_spec
        key_spec = @($Definition.key_spec)
        notification_settings = $Definition.notification_settings
        notifications = @($Definition.notifications)
        storage = @($storage)
        state = [string]$Definition.state
    }
}

function Convert-DesiredDefinitionToComparable($Definition) {
    return [ordered]@{
        title = [string]$Definition.display_name
        description = [string]$Definition.description
        remediation_steps = [string]$Definition.remediation_steps
        priority = [int]$Definition.priority
        alert = [bool]$Definition.alert
        config = $Definition.config
        field_spec = $Definition.field_spec
        key_spec = @($Definition.key_spec)
        notification_settings = $Definition.notification_settings
        notifications = @($Definition.notifications)
        storage = @($Definition.storage)
        state = [string]$Definition.state
    }
}

function Resolve-DefinitionDto($Definition, $StreamIdByName) {
    $config = $Definition.config | ConvertTo-Json -Depth 50 -Compress | ConvertFrom-Json
    $streamIds = @()
    foreach ($name in @($config.stream_names)) {
        if (-not $StreamIdByName.ContainsKey([string]$name)) { throw "Event Definition '$($Definition.display_name)' references missing Stream '$name'." }
        $streamIds += $StreamIdByName[[string]$name]
    }
    $config.PSObject.Properties.Remove("stream_names")
    $config | Add-Member -MemberType NoteProperty -Name "streams" -Value @($streamIds)
    $storage = @()
    foreach ($entry in @($Definition.storage)) {
        $storageIds = @()
        foreach ($name in @($entry.stream_names)) {
            if (-not $StreamIdByName.ContainsKey([string]$name)) { throw "Event Definition '$($Definition.display_name)' references missing storage Stream '$name'." }
            $storageIds += $StreamIdByName[[string]$name]
        }
        $storage += [ordered]@{ type = [string]$entry.type; streams = @($storageIds) }
    }
    return [ordered]@{
        title = [string]$Definition.display_name
        description = [string]$Definition.description
        remediation_steps = [string]$Definition.remediation_steps
        priority = [int]$Definition.priority
        alert = [bool]$Definition.alert
        config = $config
        field_spec = $Definition.field_spec
        key_spec = @($Definition.key_spec)
        notification_settings = $Definition.notification_settings
        notifications = @()
        storage = @($storage)
        state = "ENABLED"
    }
}

$inputsPackage = Get-Content -LiteralPath (Join-Path $PackageRoot "inputs.json") -Raw | ConvertFrom-Json
$streamsPackage = Get-Content -LiteralPath (Join-Path $PackageRoot "streams.json") -Raw | ConvertFrom-Json
$definitionsPackage = Get-Content -LiteralPath (Join-Path $PackageRoot "event_definitions.json") -Raw | ConvertFrom-Json
if ($inputsPackage.schema_version -ne 1 -or $streamsPackage.schema_version -ne 1 -or $definitionsPackage.schema_version -ne 1) { throw "Unsupported migration package schema_version." }
foreach ($definition in $definitionsPackage.event_definitions) {
    if ([int]$definition.priority -lt 1 -or [int]$definition.priority -gt 3) { throw "Priority for $($definition.rule_id) is outside Graylog 6.1.16 range 1..3." }
    if (@($definition.notifications).Count -gt 0) { throw "Unexpected Notification references in $($definition.rule_id); review them explicitly before import." }
}

$system = Invoke-Graylog GET "/system"
$inputsResponse = Invoke-Graylog GET "/system/inputs"
$streamsResponse = Invoke-Graylog GET "/streams"
$indexSetsResponse = Invoke-Graylog GET "/system/indices/index_sets"
$definitionsResponse = Invoke-Graylog GET "/events/definitions"
$nodesResponse = Invoke-Graylog GET "/system/cluster/nodes"
$allInputs = Get-Items $inputsResponse "inputs"
$allStreams = Get-Items $streamsResponse "streams"
$allIndexSets = Get-Items $indexSetsResponse "index_sets"
$allDefinitions = Get-Items $definitionsResponse "event_definitions"
$streamNames = Get-StreamNamesById $allStreams $allIndexSets
$plannedStreamNames = @($allStreams | ForEach-Object { [string]$_.title }) + @($streamsPackage.streams | ForEach-Object { [string]$_.title })
$plan = @()
$conflicts = @()
$inputIdByKey = @{}
$inputStatusByKey = @{}

foreach ($desired in @($inputsPackage.inputs)) {
    $matches = Get-TitleMatches $allInputs ([string]$desired.title)
    if ($matches.Count -gt 1) { $conflicts += "Input '$($desired.title)' has duplicate titles."; continue }
    if ($matches.Count -eq 1) {
        $existing = $matches[0]
        if (Test-InputEquivalent $existing $desired) {
            $inputIdByKey[[string]$desired.key] = [string]$existing.id
            $inputStatusByKey[[string]$desired.key] = "exists"
            $plan += "NO-OP Input $($desired.title): exact same-name configuration exists."
        } else {
            $conflicts += "Input '$($desired.title)' exists but differs; it will not be updated."
        }
    } else {
        $port = [int]$desired.configuration.port
        $portOwners = @($allInputs | Where-Object { [int]$_.attributes.port -eq $port })
        if ($portOwners.Count -gt 0) {
            $conflicts += "Input '$($desired.title)' needs UDP port $port, already used by another input."
        } else {
            $inputStatusByKey[[string]$desired.key] = "create"
            $plan += "CREATE Input $($desired.title) ($($desired.type), UDP $port)."
        }
    }
}

$nodeCandidates = @()
if ($nodesResponse.nodes) { $nodeCandidates = @($nodesResponse.nodes | ForEach-Object { if ($_.node_id) { [string]$_.node_id } elseif ($_.id) { [string]$_.id } }) }
if ([string]::IsNullOrWhiteSpace($NodeId)) {
    if ($nodeCandidates.Count -eq 1) { $NodeId = $nodeCandidates[0] }
    elseif (@($inputStatusByKey.Values | Where-Object { $_ -eq "create" }).Count -gt 0 -and @($inputsPackage.inputs | Where-Object { -not $_.global }).Count -gt 0) {
        $conflicts += "A single-node Input needs -NodeId because Graylog exposes $($nodeCandidates.Count) nodes."
    }
}

$streamIdByName = @{}
$streamStatusByName = @{}
foreach ($desired in @($streamsPackage.streams)) {
    $matches = Get-TitleMatches $allStreams ([string]$desired.title)
    if ($matches.Count -gt 1) { $conflicts += "Stream '$($desired.title)' has duplicate titles."; continue }
    if ($matches.Count -eq 1) {
        $listed = $matches[0]
        $detail = Invoke-Graylog GET ("/streams/" + [uri]::EscapeDataString([string]$listed.id))
        if (Test-StreamEquivalent $detail $desired $inputIdByKey $allIndexSets) {
            $streamIdByName[[string]$desired.title] = [string]$detail.id
            $streamStatusByName[[string]$desired.title] = "exists"
            $plan += "NO-OP Stream $($desired.title): same name and rules exist."
        } else {
            $conflicts += "Stream '$($desired.title)' exists but differs; it will not be updated."
        }
    } else {
        $indexMatches = Get-TitleMatches $allIndexSets ([string]$desired.index_set_selector.title)
        if ($indexMatches.Count -eq 0 -and -not $desired.index_set_selector.use_default_if_missing) {
            $conflicts += "Stream '$($desired.title)' requires missing index set '$($desired.index_set_selector.title)'."
        } elseif ($indexMatches.Count -gt 1) {
            $conflicts += "Index set title '$($desired.index_set_selector.title)' is ambiguous."
        } else {
            $streamStatusByName[[string]$desired.title] = "create"
            $plan += "CREATE Stream $($desired.title) with $(@($desired.rules).Count) rules."
        }
    }
}

foreach ($definition in @($definitionsPackage.event_definitions)) {
    foreach ($referencedName in (@($definition.config.stream_names) + @($definition.storage | ForEach-Object { $_.stream_names }))) {
        if ($plannedStreamNames -cnotcontains [string]$referencedName) { $conflicts += "Event Definition '$($definition.display_name)' references missing Stream '$referencedName'." }
    }
    $matches = Get-TitleMatches $allDefinitions ([string]$definition.display_name)
    if ($matches.Count -gt 1) { $conflicts += "Event Definition '$($definition.display_name)' has duplicate titles."; continue }
    if ($matches.Count -eq 1) {
        $existingComparable = Convert-ExistingDefinitionToComparable $matches[0] $streamNames
        $desiredComparable = Convert-DesiredDefinitionToComparable $definition
        if ((Get-CanonicalJson $existingComparable) -ceq (Get-CanonicalJson $desiredComparable)) {
            $plan += "NO-OP $($definition.rule_id) Event Definition: same-name definition matches package."
        } else {
            $conflicts += "Event Definition '$($definition.display_name)' exists but differs; it will not be updated."
        }
    } else {
        $plan += "CREATE $($definition.rule_id) Event Definition $($definition.display_name) (priority $($definition.priority), ENABLED)."
    }
}

Write-Output ("Target Graylog version: {0}" -f [string]$system.version)
Write-Output ("Mode: {0}" -f $(if ($Apply) { "APPLY" } else { "DRY RUN" }))
foreach ($line in $plan) { Write-Output $line }
if ($conflicts.Count -gt 0) {
    foreach ($conflict in $conflicts) { Write-Output "CONFLICT $conflict" }
    throw "Preflight found $($conflicts.Count) conflict(s). No Graylog changes were made."
}
if ($DryRun) { Write-Output "Dry run complete. No Graylog changes were made."; return }

# Writes start only after every object and dependency passed preflight.
foreach ($desired in @($inputsPackage.inputs)) {
    if ($inputStatusByKey[[string]$desired.key] -ne "create") { continue }
    $configuration = [ordered]@{}
    foreach ($property in $desired.configuration.PSObject.Properties) { $configuration[$property.Name] = $property.Value }
    $body = [ordered]@{ title = [string]$desired.title; type = [string]$desired.type; global = [bool]$desired.global; configuration = $configuration }
    if (-not $desired.global) { $body.node = $NodeId }
    $created = Invoke-Graylog POST "/system/inputs" $body
    $inputIdByKey[[string]$desired.key] = [string]$created.id
    if ([string]::IsNullOrWhiteSpace($inputIdByKey[[string]$desired.key])) {
        $refreshedInputs = Get-Items (Invoke-Graylog GET "/system/inputs") "inputs"
        $createdMatches = Get-TitleMatches $refreshedInputs ([string]$desired.title)
        if ($createdMatches.Count -ne 1) { throw "Input '$($desired.title)' creation response could not be resolved; stop and inspect Graylog." }
        $inputIdByKey[[string]$desired.key] = [string]$createdMatches[0].id
    }
    Write-Output "Created Input $($desired.title)."
}

foreach ($desired in @($streamsPackage.streams)) {
    if ($streamStatusByName[[string]$desired.title] -eq "create") {
        $indexMatches = Get-TitleMatches $allIndexSets ([string]$desired.index_set_selector.title)
        $indexSetId = if ($indexMatches.Count -eq 1) { [string]$indexMatches[0].id } else { [string](@($allIndexSets | Where-Object default | Select-Object -First 1)[0].id) }
        if ([string]::IsNullOrWhiteSpace($indexSetId)) { throw "No usable index set resolved for Stream '$($desired.title)'." }
        $body = [ordered]@{
            title = [string]$desired.title
            description = [string]$desired.description
            matching_type = [string]$desired.matching_type
            index_set_id = $indexSetId
            remove_matches_from_default_stream = [bool]$desired.remove_matches_from_default_stream
        }
        $created = Invoke-Graylog POST "/streams" $body
        $streamId = [string]$created.stream_id
        if ([string]::IsNullOrWhiteSpace($streamId)) { $streamId = [string]$created.id }
        if ([string]::IsNullOrWhiteSpace($streamId)) {
            $refreshed = Get-Items (Invoke-Graylog GET "/streams") "streams"
            $createdMatches = Get-TitleMatches $refreshed ([string]$desired.title)
            if ($createdMatches.Count -ne 1) { throw "Stream '$($desired.title)' creation response could not be resolved; stop and inspect Graylog." }
            $streamId = [string]$createdMatches[0].id
        }
        $streamIdByName[[string]$desired.title] = $streamId
        foreach ($rule in @($desired.rules)) {
            $converted = Convert-DesiredRule $rule $inputIdByKey
            if ($null -eq $converted) { throw "Stream '$($desired.title)' has an unresolved input reference." }
            Invoke-Graylog POST ("/streams/{0}/rules" -f [uri]::EscapeDataString($streamId)) $converted | Out-Null
        }
        if (-not [bool]$desired.disabled) { Invoke-Graylog POST ("/streams/{0}/resume" -f [uri]::EscapeDataString($streamId)) | Out-Null }
        Write-Output "Created Stream $($desired.title) and its rules."
    }
}

$refreshedStreams = Get-Items (Invoke-Graylog GET "/streams") "streams"
foreach ($stream in $refreshedStreams) { $streamNames[[string]$stream.id] = [string]$stream.title }
foreach ($streamName in @($streamIdByName.Keys)) { }
foreach ($definition in @($definitionsPackage.event_definitions)) {
    $existingNow = Get-Items (Invoke-Graylog GET "/events/definitions") "event_definitions"
    if ((Get-TitleMatches $existingNow ([string]$definition.display_name)).Count -gt 0) { continue }
    $dto = Resolve-DefinitionDto $definition $streamIdByName
    Invoke-Graylog POST "/events/definitions?schedule=true" $dto | Out-Null
    Write-Output "Created and scheduled $($definition.rule_id) Event Definition."
}

# Read-after-write verification by human-readable names; no destructive repair is attempted.
$verifyInputs = Get-Items (Invoke-Graylog GET "/system/inputs") "inputs"
$verifyStreams = Get-Items (Invoke-Graylog GET "/streams") "streams"
$verifyDefs = Get-Items (Invoke-Graylog GET "/events/definitions") "event_definitions"
$verifyStreamNames = Get-StreamNamesById $verifyStreams $allIndexSets
foreach ($desired in @($inputsPackage.inputs)) {
    $found = Get-TitleMatches $verifyInputs ([string]$desired.title)
    if ($found.Count -ne 1 -or -not (Test-InputEquivalent $found[0] $desired)) { throw "Post-import verification failed for Input '$($desired.title)'." }
}
foreach ($desired in @($streamsPackage.streams)) {
    $found = Get-TitleMatches $verifyStreams ([string]$desired.title)
    if ($found.Count -ne 1) { throw "Post-import verification failed for Stream '$($desired.title)'." }
    $detail = Invoke-Graylog GET ("/streams/" + [uri]::EscapeDataString([string]$found[0].id))
    if (-not (Test-StreamEquivalent $detail $desired $inputIdByKey $allIndexSets) -or [bool]$detail.disabled) { throw "Post-import verification failed for Stream '$($desired.title)'." }
}
foreach ($desired in @($definitionsPackage.event_definitions)) {
    $found = Get-TitleMatches $verifyDefs ([string]$desired.display_name)
    if ($found.Count -ne 1) { throw "Post-import verification failed for Event Definition '$($desired.rule_id)'." }
    $actualComparable = Convert-ExistingDefinitionToComparable $found[0] $verifyStreamNames
    $desiredComparable = Convert-DesiredDefinitionToComparable $desired
    if ([int]$found[0].priority -ne [int]$desired.priority -or [string]$found[0].state -ne "ENABLED" -or (Get-CanonicalJson $actualComparable) -cne (Get-CanonicalJson $desiredComparable)) {
        throw "Post-import verification failed for Event Definition '$($desired.rule_id)' settings, status, priority, or Stream link."
    }
}
Write-Output "Graylog migration import and read-after-write checks completed."
