$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot '..\probes\Get-WhpxReadiness.ps1'
$tokens=$null; $errors=$null
[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$errors) | Out-Null
if ($errors.Count) { throw 'PARSE_FAILURE' }
$global:SEC02WhpxTestState='Enabled'; $global:SEC02WhpxTestDll=$true; $global:SEC02WhpxTestQueries=@()
function global:Get-WindowsOptionalFeature {
    param([switch]$Online,[string]$FeatureName,$ErrorAction)
    $global:SEC02WhpxTestQueries += $FeatureName
    if ($FeatureName -eq 'VirtualMachinePlatform') { return [pscustomobject]@{State='Enabled'} }
    if ($FeatureName -cne 'HypervisorPlatform') { throw 'UNEXPECTED_QUERY' }
    if ($global:SEC02WhpxTestState -eq 'THROW') { throw 'private-path-or-username-must-not-escape' }
    [pscustomobject]@{State=$global:SEC02WhpxTestState}
}
function global:Test-Path { param($LiteralPath,$PathType) return $global:SEC02WhpxTestDll }
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
        if ($r.vmpFeatureState -cne 'Enabled') { throw 'VMP_FIXTURE_FAILED' }
        if ($r.candidateExecutionAllowed -or $r.isolationProven -or $r.whpxExecutionProven -or $r.changesRequested -or $r.rebootAllowed) { throw 'FALSE_AUTHORITY' }
        if (($global:SEC02WhpxTestQueries -join ',') -cne 'HypervisorPlatform,VirtualMachinePlatform') { throw 'QUERY_SCOPE' }
        if ($raw -match 'private-path|username|C:\\|Users') { throw 'PRIVACY_FAILURE' }
        $count++
    }
    Write-Output "WHP_READINESS_POLICY_CASES=$count; SKIPPED=0; LIVE_DEVICE_PROOF=NO"
} finally {
    Remove-Item Function:\Get-WindowsOptionalFeature
    Remove-Item Function:\Test-Path
    Remove-Variable SEC02WhpxTestState,SEC02WhpxTestDll,SEC02WhpxTestQueries -Scope Global
}
