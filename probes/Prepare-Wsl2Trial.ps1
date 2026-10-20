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
$ProgressPreference = 'SilentlyContinue'
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
    if ($r.vmpEnabledByThisTrial) { throw 'LEGACY_FEATURE_ROLLBACK_REQUIRES_SEPARATE_AUTHORITY' }
    if ($r.installedByThisTrial) { $code = Run-Msi '/x'; $r.installedByThisTrial = $false; Write-Receipt $r }
    # Retain receipt and package for audit. Do not erase records or reboot.
    Write-Output 'OWN_TRIAL_PREREQUISITES_ROLLED_BACK_REBOOT_NOT_PERFORMED'
    return
}
$plan = (& (Join-Path $PSScriptRoot 'Get-Wsl2TrialPlan.ps1') -ExpectedComputerName $ExpectedComputerName) | ConvertFrom-Json
if ($Action -eq 'Plan') { $plan | ConvertTo-Json -Depth 6; return }
# Fail before downloads, receipts, MSI, or feature changes. No attempt is made
# to predict a reboot-free VMP activation; Disabled/Unknown/Pending all stop.
if ($plan.vmpState -ne 'Enabled') { throw 'VMP_NOT_ALREADY_ENABLED_NO_PARTIAL_CHANGE' }
if ($plan.installBlockReasons.Count) { throw ('INSTALL_PREFLIGHT_BLOCKED:' + ($plan.installBlockReasons -join ',')) }
New-Item -ItemType Directory -Path $root | Out-Null
$r = [ordered]@{host=$ExpectedComputerName;packageSha256=$hash;existingWsl=$false;
    vmpBefore=[string]$plan.vmpState;vmpEnabledByThisTrial=$false;installedByThisTrial=$false}
Write-Receipt $r
Invoke-WebRequest -UseBasicParsing -TimeoutSec 180 -Uri $url -OutFile $msi
Assert-Package
$code = Run-Msi '/i'
$r.installedByThisTrial = $true
Write-Receipt $r
Write-Output 'PINNED_WSL_INSTALLED_NO_DISTRO_NO_REBOOT_NO_RUNNER_CHANGE'
Write-Output ('MSI_EXIT_CODE=' + $code)
Write-Output 'IF_REBOOT_REQUIRED_STOP_FOR_SEPARATE_OWNER_AUTHORIZATION'
