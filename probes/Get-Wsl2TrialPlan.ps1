#requires -Version 5.1
# Read-only inventory. Does not invoke wsl.exe (including its installer stub),
# start a distribution, enumerate credentials, or print configuration contents.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ExpectedComputerName)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -cne $ExpectedComputerName) { throw 'HOST_IDENTITY_MISMATCH' }
$featureState = 'UNKNOWN'
try { $featureState = [string](Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State } catch {}
$appxKnown = $false
$apps = @()
try { $apps = @(Get-AppxPackage -AllUsers -Name MicrosoftCorporationII.WindowsSubsystemForLinux); $appxKnown = $true } catch {}
$packages = @()
foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
    $packages += @(Get-ItemProperty $key -ErrorAction SilentlyContinue | Where-Object {
        $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -match 'Windows Subsystem for Linux'
    })
}
$distroKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
$distros = @()
if (Test-Path $distroKey) {
    $distros = @(Get-ChildItem $distroKey | ForEach-Object {
        $v = Get-ItemProperty $_.PSPath
        if ($v.PSObject.Properties['DistributionName']) {
            [ordered]@{name=[string]$v.DistributionName;version=if($v.PSObject.Properties['Version']){[int]$v.Version}else{$null}}
        }
    })
}
$config = Join-Path $env:USERPROFILE '.wslconfig'
$pending = @()
foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
    if (Test-Path $key) { $pending += ($key.Split('\')[-1]) }
}
$session = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
if ($session.PSObject.Properties['PendingFileRenameOperations'] -and $session.PendingFileRenameOperations) { $pending += 'PendingFileRenameOperations' }
$reasons = @()
if ($featureState -ne 'Enabled') { $reasons += 'VMP_NOT_ALREADY_ENABLED_NO_FEATURE_CHANGE_ALLOWED' }
if ($pending.Count) { $reasons += 'PENDING_REBOOT_PRESERVE_STOP' }
if (-not $appxKnown) { $reasons += 'ALL_USER_RUNTIME_INVENTORY_UNKNOWN' }
if ($apps.Count -or $packages.Count) { $reasons += 'EXISTING_RUNTIME_PRESERVE_REBASELINE' }
if ($distros.Count) { $reasons += 'EXISTING_DISTRIBUTIONS_PRESERVE_STOP' }
if (Test-Path $config) { $reasons += 'EXISTING_CONFIGURATION_PRESERVE_STOP' }
if (Test-Path (Join-Path $env:ProgramData 'TrustedExecution-WslTrial')) { $reasons += 'EXISTING_TRIAL_RECEIPT_PRESERVE_STOP' }
[ordered]@{
    host=$ExpectedComputerName;mode='READ_ONLY_PLAN';vmpState=$featureState
    allUserAppxInventoryKnown=$appxKnown
    appxVersions=@($apps | ForEach-Object { [string]$_.Version })
    msiVersions=@($packages | ForEach-Object { [string]$_.DisplayVersion })
    currentUserDistributions=$distros;otherUserDistributionInventory='NOT_READ'
    currentUserWslConfigExists=(Test-Path $config)
    currentUserWslConfigSha256=if(Test-Path $config){(Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}
    pendingRebootIndicators=$pending;installBlockReasons=$reasons
    mutationAuthorized=$false;featureActivationAllowed=$false;rebootAllowed=$false
    serviceMutationAuthorized=$false;candidateExecutionAllowed=$false
} | ConvertTo-Json -Depth 6
