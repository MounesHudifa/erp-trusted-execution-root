$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot '..\probes\Get-WhpxReadiness.ps1'
$tokens=$null; $errors=$null
[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$errors) | Out-Null
if ($errors.Count) { throw 'PARSE_FAILURE' }
$global:SEC02WhpxResourceFail=$false; $global:SEC02WhpxTestState='Enabled'; $global:SEC02WhpxTestDll=$true; $global:SEC02WhpxTestQueries=@()
function global:Get-WindowsOptionalFeature {
    param([switch]$Online,[string]$FeatureName,$ErrorAction)
    $global:SEC02WhpxTestQueries += $FeatureName
    if ($FeatureName -eq 'VirtualMachinePlatform') { return [pscustomobject]@{State='Enabled'} }
    if ($FeatureName -cne 'HypervisorPlatform') { throw 'UNEXPECTED_QUERY' }
    if ($global:SEC02WhpxTestState -eq 'THROW') { throw 'private-path-or-username-must-not-escape' }
    [pscustomobject]@{State=$global:SEC02WhpxTestState}
}
function global:Test-Path { param($LiteralPath,$PathType) return $global:SEC02WhpxTestDll }
function global:Get-CimInstance {
    param($ClassName,$Property,$ErrorAction)
    if ($global:SEC02WhpxResourceFail) { throw 'private-path-or-username-must-not-escape' }
    if ($ClassName -eq 'Win32_OperatingSystem') { return [pscustomobject]@{TotalVisibleMemorySize=33554432;FreePhysicalMemory=16777216} }
    if ($ClassName -eq 'Win32_ComputerSystem') { return [pscustomobject]@{NumberOfLogicalProcessors=12} }
    throw 'QUERY_SCOPE'
}
function global:Get-PSDrive { param($Name,$ErrorAction) return [pscustomobject]@{Free=107374182400} }
try {
    $count=0
    foreach ($case in @(
        @('Enabled',$true,'WHP_FEATURE_PRESENT_LIVE_VM_PROOF_REQUIRED'),
        @('Enabled',$false,'WHP_CAPABILITY_UNPROVEN_STOP'),
        @('Disabled',$true,'WHP_FEATURE_DISABLED_CHANGE_AUTHORIZATION_REQUIRED'),
        @('DisabledWithPayloadRemoved',$false,'WHP_FEATURE_DISABLED_CHANGE_AUTHORIZATION_REQUIRED'),
        @('EnablePending',$true,'WHP_FEATURE_TRANSITION_PENDING_STOP'),
        @('DisablePending',$true,'WHP_FEATURE_TRANSITION_PENDING_STOP'),
        @('THROW',$true,'WHP_CAPABILITY_UNPROVEN_STOP'),
        @('unexpected',$true,'WHP_CAPABILITY_UNPROVEN_STOP')
    )) {
        $global:SEC02WhpxTestState=$case[0]; $global:SEC02WhpxTestDll=$case[1]; $global:SEC02WhpxTestQueries=@()
        $raw = & $scriptPath
        $r = $raw | ConvertFrom-Json
        if ($r.decision -cne $case[2]) { throw 'WRONG_DECISION' }
        if (-not $r.resources.known -or $r.resources.logicalProcessors -ne 12 -or $r.resources.totalMemoryBytes -ne 34359738368) { throw 'RESOURCE_NUMBERS' }
        if ($r.candidateExecutionAllowed -or $r.isolationProven -or $r.whpxExecutionProven -or $r.changesRequested -or $r.rebootAllowed) { throw 'FALSE_AUTHORITY' }
        if (($global:SEC02WhpxTestQueries -join ',') -cne 'HypervisorPlatform') { throw 'QUERY_SCOPE' }
        if ($raw -match 'private-path|username|C:\\|Users') { throw 'PRIVACY_FAILURE' }
        $count++
    }
    $global:SEC02WhpxResourceFail=$true
    $raw = & $scriptPath
    $r = $raw | ConvertFrom-Json
    if ($r.resources.known -or $null -ne $r.resources.totalMemoryBytes -or $raw -match 'private-path|username|C:\\\\|Users') { throw 'RESOURCE_FAILURE_PRIVACY' }
    $count++
    Write-Output "WHP_READINESS_POLICY_CASES=$count; SKIPPED=0; LIVE_DEVICE_PROOF=NO"
} finally {
    Remove-Item Function:\Get-WindowsOptionalFeature
    Remove-Item Function:\Test-Path
    Remove-Item Function:\Get-CimInstance
    Remove-Item Function:\Get-PSDrive
    Remove-Variable SEC02WhpxResourceFail,SEC02WhpxTestState,SEC02WhpxTestDll,SEC02WhpxTestQueries -Scope Global
}
