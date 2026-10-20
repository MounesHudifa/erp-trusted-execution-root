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
$resources = [ordered]@{ known = $false; logicalProcessors = $null; totalMemoryBytes = $null; availableMemoryBytes = $null; systemDiskFreeBytes = $null }
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property TotalVisibleMemorySize,FreePhysicalMemory -ErrorAction Stop
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -Property NumberOfLogicalProcessors -ErrorAction Stop
    $disk = Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':')) -ErrorAction Stop
    if ([long]$os.TotalVisibleMemorySize -le 0 -or [long]$os.FreePhysicalMemory -lt 0 -or [int]$computer.NumberOfLogicalProcessors -le 0 -or [long]$disk.Free -lt 0) { throw 'RESOURCE_VALUES_INVALID' }
    $resources.logicalProcessors = [int]$computer.NumberOfLogicalProcessors
    $resources.totalMemoryBytes = [long]$os.TotalVisibleMemorySize * 1024
    $resources.availableMemoryBytes = [long]$os.FreePhysicalMemory * 1024
    $resources.systemDiskFreeBytes = [long]$disk.Free
    $resources.known = $true
} catch { }

$whp = Read-FeatureState 'HypervisorPlatform'
$dllPresent = Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\WinHvPlatform.dll') -PathType Leaf
$decision = 'WHP_CAPABILITY_UNPROVEN_STOP'
if ($whp -eq 'Enabled' -and $dllPresent) { $decision = 'WHP_FEATURE_PRESENT_LIVE_VM_PROOF_REQUIRED' }
elseif ($whp -eq 'Disabled' -or $whp -eq 'DisabledWithPayloadRemoved') { $decision = 'WHP_FEATURE_DISABLED_CHANGE_AUTHORIZATION_REQUIRED' }
elseif ($whp -eq 'EnablePending' -or $whp -eq 'DisablePending') { $decision = 'WHP_FEATURE_TRANSITION_PENDING_STOP' }
[ordered]@{
    schemaVersion = 2
    whpFeatureState = $whp
    resources = $resources
    whpSystemDllPresent = [bool]$dllPresent
    decision = $decision
    whpxExecutionProven = $false
    isolationProven = $false
    candidateExecutionAllowed = $false
    changesRequested = $false
    rebootAllowed = $false
} | ConvertTo-Json -Compress
