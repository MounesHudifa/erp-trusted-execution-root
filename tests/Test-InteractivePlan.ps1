$ErrorActionPreference='Stop'
. "$PSScriptRoot/../probes/Interactive-ReadOnlyPlan.ps1" -LoadFunctionsOnly
$count=0
function Assert($Condition,$Label){if(-not $Condition){throw $Label};$script:count++}
foreach($code in @('HOST_IDENTITY_MISMATCH','DIFFERENT_ACCOUNT_REFUSED','ELEVATION_REQUIRED','PLAN_HASH_MISMATCH','PLAN_OUTPUT_INVALID')){
 try{throw $code}catch{$r=Get-SafePlanError $_ 'VERIFY_AND_PLAN'}
 Assert ($r.code -ceq $code) ('lost '+$code)
}
try{throw [ComponentModel.Win32Exception]::new(1223,'secret-user token=synthetic')}catch{$r=Get-SafePlanError $_ 'UAC'}
Assert ($r.code -eq 'UAC_CANCELLED' -and $r.nativeErrorCode -eq 1223) 'cancel'
try{throw [ComponentModel.Win32Exception]::new(5,'private-path synthetic')}catch{$r=Get-SafePlanError $_ 'UAC'}
Assert ($r.code -eq 'UAC_REQUEST_FAILED' -and $r.nativeErrorCode -eq 5) 'access denied'
try{throw [Net.WebException]::new('https://secret.invalid/?token=synthetic')}catch{$r=Get-SafePlanError $_ 'DOWNLOAD'}
Assert ($r.code -eq 'PLAN_DOWNLOAD_FAILED' -and $null -ne $r.hresult) 'network'
Assert (($r|ConvertTo-Json) -notmatch 'secret|synthetic|token=') 'message disclosure'
$child=New-PlanChild 'synthetic-host' 'S-1-5-21-111-222-333-1001'
$tokens=$null;$errors=$null
$null=[Management.Automation.Language.Parser]::ParseInput($child,[ref]$tokens,[ref]$errors)
Assert ($errors.Count -eq 0) 'child syntax'
$null=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path "$PSScriptRoot/../probes/Interactive-ReadOnlyPlan.ps1"),[ref]$tokens,[ref]$errors)
Assert ($errors.Count -eq 0) 'launcher syntax'
$rejected=$false
try{New-PlanChild "bad';host" 'S-1-5-21-1'|Out-Null}catch{$rejected=$true}
Assert $rejected 'injection binding'
$actual=& "$PSScriptRoot/../probes/Interactive-ReadOnlyPlan.ps1" -ExpectedComputerName 'not-this-ci-host'
$r=($actual -join "`n")|ConvertFrom-Json
Assert ($r.code -eq 'HOST_IDENTITY_MISMATCH' -and $r.stage -eq 'IDENTITY') 'actual entry rejection'
# Real function identity/hash checks on the disposable CI host; synthetic payload only.
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$bytes=[Text.Encoding]::UTF8.GetBytes('param($ExpectedComputerName) @{mode="READ_ONLY_PLAN";host=$ExpectedComputerName}|ConvertTo-Json')
$hash=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-','').ToLowerInvariant()
$r=Invoke-PinnedPlan $bytes $hash $env:COMPUTERNAME $sid
Assert ($r.status -eq 'COMPLETE') 'synthetic acceptance'
foreach($case in @(@{sid='S-1-0-0';hash=$hash;code='DIFFERENT_ACCOUNT_REFUSED'},@{sid=$sid;hash=('0'*64);code='PLAN_HASH_MISMATCH'})){
 $rejected=$false
 try{Invoke-PinnedPlan $bytes $case.hash $env:COMPUTERNAME $case.sid|Out-Null}catch{$r=Get-SafePlanError $_ 'VERIFY_AND_PLAN';$rejected=$r.code -eq $case.code}
 Assert $rejected $case.code
}
Write-Output "INTERACTIVE_PLAN_REGRESSIONS_PASS=$count"
Write-Output 'UAC_INTERACTION_TESTED=NO; DEVICE_PLAN_EXECUTED=NO; PRIVATE_DATA_USED=NO'
