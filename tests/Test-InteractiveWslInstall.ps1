$ErrorActionPreference='Stop'
. "$PSScriptRoot/../probes/Interactive-WslInstall.ps1" -LoadFunctionsOnly
$count=0
function Assert($ok){if(-not $ok){throw 'ASSERTION_FAILED'};$script:count++}
function Reject($p,$code){$caught=$false;try{Assert-InstallPayload $p|Out-Null}catch{if($_.Exception.Message -cne $code){throw};$caught=$true};Assert $caught}
$bytes=[Text.Encoding]::UTF8.GetBytes('synthetic-never-executed')
$hash=Get-TrialBytesHash $bytes
$a=[ordered]@{status='OWNER_AUTHORIZED_SINGLE_INSTALL';host='synthetic-host';consumed=$false;attemptsExecuted=0;executionMode='OWNER_INTERACTIVE_SAME_ACCOUNT_UAC';remoteMutationAuthorized=$false;scriptSha256=$hash;policySha256=$hash;planSha256=$hash}
function Payload($auth){
 $b=[Text.Encoding]::UTF8.GetBytes(($auth|ConvertTo-Json -Compress))
 [pscustomobject]@{host='synthetic-host';registeredControlSha=('a'*40);authorityBase64=[Convert]::ToBase64String($b);authoritySha256=(Get-TrialBytesHash $b);files=[pscustomobject]@{'Prepare-Wsl2Trial.ps1'=[Convert]::ToBase64String($bytes);'Wsl2TrialPolicy.ps1'=[Convert]::ToBase64String($bytes);'Get-Wsl2TrialPlan.ps1'=[Convert]::ToBase64String($bytes)}}
}
$p=Payload $a;Assert ((Assert-InstallPayload $p).host -ceq 'synthetic-host')
$p=Payload $a;$p.authoritySha256='bad';Reject $p 'AUTHORITY_HASH_MISMATCH'
$p=Payload $a;$p.files.'Prepare-Wsl2Trial.ps1'=[Convert]::ToBase64String([byte[]]@(0));Reject $p 'SCRIPT_HASH_MISMATCH'
$a.consumed=$true;Reject (Payload $a) 'AUTHORITY_NOT_EXECUTABLE';$a.consumed=$false
$a.attemptsExecuted=1;Reject (Payload $a) 'AUTHORITY_NOT_EXECUTABLE';$a.attemptsExecuted=0
$a.remoteMutationAuthorized=$true;Reject (Payload $a) 'AUTHORITY_NOT_EXECUTABLE';$a.remoteMutationAuthorized=$false
$a.status='REQUESTED_NOT_AUTHORIZED';Reject (Payload $a) 'AUTHORITY_NOT_EXECUTABLE'
$t=$null;$e=$null
$null=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path "$PSScriptRoot/../probes/Interactive-WslInstall.ps1"),[ref]$t,[ref]$e)
Assert ($e.Count -eq 0)
Write-Output "INTERACTIVE_INSTALL_PAYLOAD_ASSERTIONS_PASS=$count"
Write-Output 'UAC_REQUESTS=0; MSI_EXECUTIONS=0; TARGET_DEVICE_ACCESSED=NO'
