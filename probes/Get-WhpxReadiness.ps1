# Read-only capability inventory. Does not launch QEMU/WSL, elevate, install or enable features.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Read-FeatureState([string]$Name) {
    try {
        $state = [string](Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction Stop).State
        if ($state -notin @('Enabled','Disabled','EnablePending','DisablePending','DisabledWithPayloadRemoved')) { return 'UNKNOWN' }
        return $state
    } catch { return 'UNKNOWN' }
}
$whp = Read-FeatureState 'HypervisorPlatform'
$vmp = Read-FeatureState 'VirtualMachinePlatform'
$dllPresent = Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\WinHvPlatform.dll') -PathType Leaf
$decision = 'WHP_CAPABILITY_UNPROVEN_STOP'
if ($whp -eq 'Enabled' -and $dllPresent) { $decision = 'WHP_FEATURE_PRESENT_LIVE_VM_PROOF_REQUIRED' }
elseif ($whp -eq 'Disabled' -or $whp -eq 'DisabledWithPayloadRemoved') { $decision = 'WHP_FEATURE_DISABLED_CHANGE_AUTHORIZATION_REQUIRED' }
elseif ($whp -eq 'EnablePending' -or $whp -eq 'DisablePending') { $decision = 'WHP_FEATURE_TRANSITION_PENDING_STOP' }
[ordered]@{
    schemaVersion = 1
    whpFeatureState = $whp
    vmpFeatureState = $vmp
    whpSystemDllPresent = [bool]$dllPresent
    decision = $decision
    whpxExecutionProven = $false
    isolationProven = $false
    candidateExecutionAllowed = $false
    changesRequested = $false
    rebootAllowed = $false
} | ConvertTo-Json -Compress
