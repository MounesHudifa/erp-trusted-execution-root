# Real entry-point execution with synthetic IO adapters; never invokes MSI/WSL.
$ErrorActionPreference='Stop';$count=0
$base=Join-Path $env:RUNNER_TEMP ('wsl-policy-tests-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $base|Out-Null
try {
 foreach($case in @('zero','reboot','failure','unexpected','hash','signature','download','missing-authority','existing-receipt','rollback')){
  $dir=Join-Path $base $case;New-Item -ItemType Directory $dir|Out-Null
  Copy-Item "$PSScriptRoot/../probes/Prepare-Wsl2Trial.ps1","$PSScriptRoot/../probes/Wsl2TrialPolicy.ps1" $dir
  $plan=[ordered]@{host=$env:COMPUTERNAME;vmpState='Enabled';allUserAppxInventoryKnown=$true;msiInventoryKnown=$true;appxVersions=@();msiVersions=@();currentUserDistributions=@();currentUserWslConfigExists=$false;pendingRebootIndicators=@('PendingFileRenameOperations');installBlockReasons=@()}
  $plan|ConvertTo-Json|Set-Content (Join-Path $dir 'fixture-plan.json')
  'param($ExpectedComputerName); Get-Content (Join-Path $PSScriptRoot "fixture-plan.json") -Raw'|Set-Content (Join-Path $dir 'Get-Wsl2TrialPlan.ps1')
  $a=[ordered]@{status='OWNER_AUTHORIZED_SINGLE_INSTALL';host=$env:COMPUTERNAME;scriptSha256=(Get-FileHash (Join-Path $dir 'Prepare-Wsl2Trial.ps1')).Hash.ToLowerInvariant();policySha256=(Get-FileHash (Join-Path $dir 'Wsl2TrialPolicy.ps1')).Hash.ToLowerInvariant();planSha256=(Get-FileHash (Join-Path $dir 'Get-Wsl2TrialPlan.ps1')).Hash.ToLowerInvariant();packageSha256='ae977286974255bd26bf925f00f40f5692c6b2084155cbc0563c09aea091f211';controlSha=('b'*40);ownerDecisionReference='https://github.com/example/synthetic/issues/1#issuecomment-1';maxInstallAttempts=1;allowPendingRenameRisk=$true;allowReboot=$false;allowLinuxExecution=$false;allowRollback=$false}
  $a|ConvertTo-Json|Set-Content (Join-Path $dir 'synthetic-authority.json')
  $child=@'
$ErrorActionPreference='Stop'
# Get-FileHash is an exported module function. Load it BEFORE installing the
# adapter so later module auto-loading cannot replace our synthetic adapter.
Import-Module Microsoft.PowerShell.Utility
$env:ProgramData=Join-Path $PSScriptRoot 'synthetic-programdata'
New-Item -ItemType Directory $env:ProgramData|Out-Null
function global:curl.exe {
 $arguments=@($args);$index=[Array]::IndexOf($arguments,'--output')
 if($index -lt 0){throw 'OUTPUT_ARGUMENT_MISSING'}
 'synthetic-not-an-msi'|Set-Content $arguments[$index+1]
 $global:LASTEXITCODE=if($env:TRIAL_CASE -eq 'download'){22}else{0}
}
function global:Get-FileHash {
 param($LiteralPath,$Algorithm)
 if($LiteralPath -like '*.msi'){
  [pscustomobject]@{Hash=if($env:TRIAL_CASE -eq 'hash'){'bad'}else{'ae977286974255bd26bf925f00f40f5692c6b2084155cbc0563c09aea091f211'}}
 }else{Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256}
}
function global:Get-AuthenticodeSignature {
 param($LiteralPath)
 [pscustomobject]@{Status=if($env:TRIAL_CASE -eq 'signature'){'NotSigned'}else{'Valid'};SignerCertificate=[pscustomobject]@{Subject='O=Microsoft Corporation'}}
}
function global:Start-Process {
 param($FilePath,$ArgumentList,[switch]$Wait,[switch]$PassThru)
 if($FilePath -notlike '*System32\msiexec.exe' -or $ArgumentList -notcontains '/norestart' -or $ArgumentList -notcontains 'REBOOT=ReallySuppress' -or $ArgumentList -contains '/x'){throw 'UNSAFE_MSI_ARGUMENTS'}
 'MOCK_MSI_ONCE'|Add-Content (Join-Path $PSScriptRoot 'attempts.txt')
 $code=switch($env:TRIAL_CASE){'zero'{0};'reboot'{3010};'unexpected'{1641};default{1603}}
 [pscustomobject]@{ExitCode=[int]$code}
}
function global:Restart-Computer {throw 'FORBIDDEN_REBOOT'}
function global:wsl.exe {throw 'FORBIDDEN_LINUX'}
if($env:TRIAL_CASE -eq 'existing-receipt'){
 New-Item -ItemType Directory (Join-Path $env:ProgramData 'TrustedExecution-WslTrial')|Out-Null
}
$action=if($env:TRIAL_CASE -eq 'rollback'){'Rollback'}else{'Install'}
$auth=if($env:TRIAL_CASE -eq 'missing-authority'){''}else{Join-Path $PSScriptRoot 'synthetic-authority.json'}
& (Join-Path $PSScriptRoot 'Prepare-Wsl2Trial.ps1') -Action $action -ExpectedComputerName $env:COMPUTERNAME -AuthorizationEvidencePath $auth
exit $LASTEXITCODE
'@
  $child|Set-Content (Join-Path $dir 'child.ps1')
  $env:TRIAL_CASE=$case
  # Executing a separate PowerShell validates the install script's exit codes.
  $ErrorActionPreference='Continue'
  $output=& "$PSHOME/powershell.exe" -NoProfile -NonInteractive -File (Join-Path $dir 'child.ps1') 2>&1
  $code=$LASTEXITCODE
  $ErrorActionPreference='Stop'
  $expected=if($case -eq 'zero'){0}elseif($case -eq 'reboot'){3010}else{1}
  if($code -ne $expected){$output|Write-Output;throw "EXIT_MISMATCH:$case"};$count++
  $attempts=Join-Path $dir 'attempts.txt'
  $shouldAttempt=$case -in @('zero','reboot','failure','unexpected')
  if((Test-Path $attempts) -ne $shouldAttempt){
   $output|Write-Output
   Get-ChildItem -LiteralPath $dir -Recurse -File|ForEach-Object {Write-Output ('SYNTHETIC_TEST_FILE='+$_.FullName)}
   throw "ATTEMPT_MISMATCH:$case"
  };$count++
  if($shouldAttempt -and @(Get-Content $attempts).Count -ne 1){throw 'RETRY_DETECTED'}
  $receipt=Join-Path $dir 'synthetic-programdata/TrustedExecution-WslTrial/installation-receipt.json'
  if(Test-Path $receipt){
   $r=Get-Content $receipt -Raw|ConvertFrom-Json
   $status=if($case -eq 'zero'){'INSTALLED_UNVALIDATED_STOP'}elseif($case -eq 'reboot'){'REBOOT_REQUIRED_STOP'}else{'FAILED_OR_UNEXPECTED_STOP'}
   if($r.status -ne $status -or $r.candidateExecutionAllowed -or $r.linuxExecutionAllowed -or $r.rebootAllowed -or $r.automaticRollbackAllowed -or $r.isolationProven){throw "RECEIPT_MISMATCH:$case"};$count++
   $reported=($output -join [Environment]::NewLine)|ConvertFrom-Json
   if($reported.status -cne $r.status -or $null -eq $reported.candidateExecutionAllowed){throw 'PUBLIC_RESULT_MUST_MATCH_RECEIPT'};$count++
  }
  Write-Output "SYNTHETIC_ENTRY_CASE_PASS=$case"
 }
} finally {Remove-Item Env:TRIAL_CASE -ErrorAction SilentlyContinue;Remove-Item -LiteralPath $base -Recurse -Force}
Write-Output "WSL_TRIAL_INSTALLER_ASSERTIONS_PASS=$count"
Write-Output 'REAL_MSI_EXECUTIONS=0; REAL_WSL_EXECUTIONS=0; TARGET_DEVICE_ACCESSED=NO'
# Expected negative child exit codes must not become the suite's exit code.
# Any failed assertion above terminates before reaching this success return.
exit 0
