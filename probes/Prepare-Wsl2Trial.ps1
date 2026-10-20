#requires -Version 5.1
# Governed installation candidate. A local JSON file is not an authority issuer.
# The caller must authenticate its owner decision against live Control BEFORE
# invocation. No remote mutation is allowed under the current Product authority.
[CmdletBinding()]
param(
 [ValidateSet('Plan','Install','Rollback')][string]$Action='Plan',
 [Parameter(Mandatory=$true)][string]$ExpectedComputerName,
 [string]$AuthorizationEvidencePath
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME -cne $ExpectedComputerName){throw 'HOST_IDENTITY_MISMATCH'}
if($Action -eq 'Rollback'){throw 'ROLLBACK_REQUIRES_SEPARATE_AUTHORITY_NO_AUTOMATIC_ACTION'}
. (Join-Path $PSScriptRoot 'Wsl2TrialPolicy.ps1')
$plan=(& (Join-Path $PSScriptRoot 'Get-Wsl2TrialPlan.ps1') -ExpectedComputerName $ExpectedComputerName)|ConvertFrom-Json
if($Action -eq 'Plan'){$plan|ConvertTo-Json -Depth 6;return}
Assert-WslTrialPreconditions $plan $ExpectedComputerName
if(-not $AuthorizationEvidencePath){throw 'INDEPENDENT_LOCAL_AUTHORITY_REQUIRED'}
$authority=Get-Content -LiteralPath $AuthorizationEvidencePath -Raw|ConvertFrom-Json
$scriptHash=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
Assert-WslTrialAuthorityBinding $authority $ExpectedComputerName $scriptHash
foreach($entry in @(@('policySha256','Wsl2TrialPolicy.ps1'),@('planSha256','Get-Wsl2TrialPlan.ps1'))){
 $actual=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $entry[1]) -Algorithm SHA256).Hash.ToLowerInvariant()
 if($authority.($entry[0]) -cne $actual){throw 'DEPENDENCY_HASH_MISMATCH'}
}
$root=Join-Path $env:ProgramData 'TrustedExecution-WslTrial'
if(Test-Path $root){throw 'EXISTING_TRIAL_RECEIPT_PRESERVE_STOP'}
# Create-new evidence prevents accidental retry. No cleanup or uninstall follows
# any outcome. Preserve MSI's native transaction semantics; never call /x.
New-Item -ItemType Directory -Path $root -ErrorAction Stop|Out-Null
$receipt=Join-Path $root 'installation-receipt.json'
$msi=Join-Path $root 'wsl.3.0.3.0.x64.msi'
$log=Join-Path $root 'installation-private.log'
$r=[ordered]@{status='PREPARING';host=$ExpectedComputerName;ownerDecisionReference=$authority.ownerDecisionReference;controlSha=$authority.controlSha;scriptSha256=$scriptHash;packageSha256=$authority.packageSha256;msiAttempted=$false;msiExitCode=$null;failureCode=$null;candidateExecutionAllowed=$false;linuxExecutionAllowed=$false;rebootAllowed=$false;automaticRollbackAllowed=$false;isolationProven=$false;pendingRenameClassification='UNKNOWN_NOT_DECLARED_SAFE';existingComponentsRemoved=$false}
function Write-TrialReceipt { [IO.File]::WriteAllText($receipt,($r|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false)) }
$stage='RECEIPT'
try {
 Write-TrialReceipt
 $stage='DOWNLOAD'
 & curl.exe --fail --location --silent --show-error --connect-timeout 15 --max-time 120 --output $msi 'https://github.com/microsoft/WSL/releases/download/3.0.3/wsl.3.0.3.0.x64.msi' 2>$null
 if($LASTEXITCODE -ne 0){throw 'DOWNLOAD_FAILED'}
 $stage='PACKAGE_HASH'
 if((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() -cne $authority.packageSha256){throw 'MSI_HASH_MISMATCH'}
 $stage='PACKAGE_SIGNATURE'
 $sig=Get-AuthenticodeSignature -LiteralPath $msi
 if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation'){throw 'MSI_SIGNATURE_MISMATCH'}
 $stage='MSI'
 $r.msiAttempted=$true;$r.status='INSTALL_ATTEMPT_STARTED';Write-TrialReceipt
 $p=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32/msiexec.exe') -ArgumentList @('/i',('"'+$msi+'"'),'/qn','/norestart','REBOOT=ReallySuppress','/L*v',('"'+$log+'"')) -Wait -PassThru
 $outcome=Get-WslTrialOutcome $p.ExitCode
 foreach($k in $outcome.Keys){$r[$k]=$outcome[$k]}
 Write-TrialReceipt
} catch {
 $r.status='FAILED_OR_UNEXPECTED_STOP';$r.failureCode=$stage+'_FAILED'
 # Do not emit exception text or MSI logs, which can contain private paths.
 try {Write-TrialReceipt} catch {Write-Output 'PRIVATE_RECEIPT_WRITE_FAILED_STOP'}
}
$r|Select-Object status,msiAttempted,msiExitCode,failureCode,candidateExecutionAllowed,linuxExecutionAllowed,rebootAllowed,automaticRollbackAllowed,isolationProven|ConvertTo-Json
# Every outcome terminates this stage. No WSL command, reboot, runner change,
# registry write, uninstall, retry or candidate execution is implemented here.
if($r.status -eq 'REBOOT_REQUIRED_STOP'){exit 3010}
if($r.status -ne 'INSTALLED_UNVALIDATED_STOP'){exit 1}
