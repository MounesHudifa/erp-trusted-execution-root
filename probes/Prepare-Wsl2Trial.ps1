#requires -Version 5.1
# Not an authorization issuer. Default Plan is read-only. Install/Rollback require
# an exact, fresh external governance permit and platform approval before invocation.
[CmdletBinding()]
param(
    [ValidateSet('Plan','Install','Rollback')][string]$Action = 'Plan',
    [Parameter(Mandatory=$true)][string]$ExpectedComputerName
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -cne $ExpectedComputerName) { throw 'HOST_IDENTITY_MISMATCH' }
$root = Join-Path $env:ProgramData 'TrustedExecution-WslTrial'
$receipt = Join-Path $root 'installation-receipt.json'
$msi = Join-Path $root 'wsl.3.0.3.0.x64.msi'
$url = 'https://github.com/microsoft/WSL/releases/download/3.0.3/wsl.3.0.3.0.x64.msi'
$hash = 'ae977286974255bd26bf925f00f40f5692c6b2084155cbc0563c09aea091f211'
function Assert-Package {
    if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) { throw 'MSI_HASH_MISMATCH' }
    $sig = Get-AuthenticodeSignature -LiteralPath $msi
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw 'MSI_SIGNATURE_MISMATCH' }
}
function Write-Receipt($data) {
    [IO.File]::WriteAllText($receipt, ($data | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
}
function Run-Msi([string]$operation) {
    $p = Start-Process msiexec.exe -ArgumentList @($operation,('"'+$msi+'"'),'/qn','/norestart') -Wait -PassThru
    if ($p.ExitCode -notin @(0,3010)) { throw "MSI_OPERATION_FAILED:$($p.ExitCode)" }
    return $p.ExitCode
}
if ($Action -eq 'Rollback') {
    if (-not (Test-Path $receipt)) { throw 'NO_OWN_INSTALLATION_RECEIPT' }
    $r = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
    if ($r.host -cne $ExpectedComputerName -or $r.packageSha256 -ne $hash -or $r.existingWsl -ne $false) { throw 'ROLLBACK_PREIMAGE_MISMATCH' }
    Assert-Package
    $distros = ((& wsl.exe --list --quiet 2>$null) -join "`n").Replace([string][char]0,'').Trim()
    if ($distros -and $distros -notmatch 'no installed distributions') { throw 'DISTROS_EXIST_REFUSE_GLOBAL_ROLLBACK' }
    if ($r.installedByThisTrial) { $code = Run-Msi '/x'; $r.installedByThisTrial = $false; Write-Receipt $r }
    if ($r.vmpEnabledByThisTrial) {
        $result = Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
        $r.vmpEnabledByThisTrial = $false
        Write-Receipt $r
    }
    # Retain receipt and package for audit. Do not erase records or reboot.
    Write-Output 'OWN_TRIAL_PREREQUISITES_ROLLED_BACK_REBOOT_NOT_PERFORMED'
    return
}
$feature = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
$apps = @(Get-AppxPackage -Name MicrosoftCorporationII.WindowsSubsystemForLinux)
$packages = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -match 'Windows Subsystem for Linux' })
$hasWsl = ($apps.Count -gt 0 -or $packages.Count -gt 0)
$plan = [ordered]@{
    host=$ExpectedComputerName; action=$Action; packageUrl=$url; packageSha256=$hash
    vmpBefore=[string]$feature.State; existingWsl=$hasWsl
    rebootPerformed=$false; changesAuthorizedByScript=$false
    candidateExecutionAllowed=$false; runnerChangesAllowed=$false
}
if ($Action -eq 'Plan') { $plan | ConvertTo-Json; return }
if ($hasWsl -or (Test-Path $root)) { throw 'EXISTING_RUNTIME_OR_TRIAL_PRESERVED_STOP_FOR_EXACT_REBASELINE' }
if ($feature.State -notin @('Enabled','Disabled')) { throw 'FEATURE_PENDING_OR_UNKNOWN_STOP' }
New-Item -ItemType Directory -Path $root | Out-Null
$r = [ordered]@{host=$ExpectedComputerName;packageSha256=$hash;existingWsl=$false;
    vmpBefore=[string]$feature.State;vmpEnabledByThisTrial=$false;installedByThisTrial=$false}
Write-Receipt $r
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $msi
Assert-Package
if ($feature.State -eq 'Disabled') {
    $result = Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart
    $r.vmpEnabledByThisTrial = $true
    Write-Receipt $r
}
$code = Run-Msi '/i'
$r.installedByThisTrial = $true
Write-Receipt $r
Write-Output 'PINNED_WSL_INSTALLED_NO_DISTRO_NO_REBOOT_NO_RUNNER_CHANGE'
Write-Output ('MSI_EXIT_CODE=' + $code)
Write-Output 'IF_REBOOT_REQUIRED_STOP_FOR_SEPARATE_OWNER_AUTHORIZATION'
