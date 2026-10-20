#requires -Version 5.1
[CmdletBinding()]
param([string]$ExpectedComputerName, [switch]$LoadFunctionsOnly)
function Get-SafePlanError {
 param([System.Management.Automation.ErrorRecord]$Record,[string]$Stage)
 $known=@('HOST_IDENTITY_MISMATCH','DIFFERENT_ACCOUNT_REFUSED','ELEVATION_REQUIRED','PLAN_HASH_MISMATCH','PLAN_OUTPUT_INVALID')
 $code='OPERATION_FAILED'
 if($known -ccontains $Record.Exception.Message){$code=$Record.Exception.Message}
 $native=$null;$http=$null;$e=$Record.Exception
 while($e){
  if($e -is [ComponentModel.Win32Exception]){$native=$e.NativeErrorCode}
  if($e -is [Net.WebException] -and $e.Response -is [Net.HttpWebResponse]){$http=[int]$e.Response.StatusCode}
  $e=$e.InnerException
 }
 if($Stage -eq 'UAC') {if($native -eq 1223){$code='UAC_CANCELLED'}else{$code='UAC_REQUEST_FAILED'}}
 elseif($Stage -eq 'DOWNLOAD'){$code='PLAN_DOWNLOAD_FAILED'}
 [ordered]@{status='FAILED';stage=$Stage;code=$code;exceptionType=$Record.Exception.GetType().FullName;hresult=$Record.Exception.HResult;nativeErrorCode=$native;httpStatus=$http}
}
function Invoke-PinnedPlan {
 param([byte[]]$Bytes,[string]$ExpectedHash,[string]$ExpectedHost,[string]$OriginalSid)
 if($env:COMPUTERNAME -cne $ExpectedHost){throw 'HOST_IDENTITY_MISMATCH'}
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 if($identity.User.Value -cne $OriginalSid){throw 'DIFFERENT_ACCOUNT_REFUSED'}
 if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ELEVATION_REQUIRED'}
 $algorithm=[Security.Cryptography.SHA256]::Create()
 try {$hash=[BitConverter]::ToString($algorithm.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$algorithm.Dispose()}
 if($hash -cne $ExpectedHash){throw 'PLAN_HASH_MISMATCH'}
 $json=(& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($Bytes))) -ExpectedComputerName $ExpectedHost) -join [Environment]::NewLine
 $result=$json|ConvertFrom-Json -ErrorAction Stop
 if($result.mode -cne 'READ_ONLY_PLAN' -or $result.host -cne $ExpectedHost){throw 'PLAN_OUTPUT_INVALID'}
 [ordered]@{status='COMPLETE';scriptSha256=$hash;plan=$result}
}
function New-PlanChild {
 param([string]$ExpectedHost,[string]$OriginalSid)
 if($ExpectedHost -notmatch '^[A-Za-z0-9-]{1,63}$' -or $OriginalSid -notmatch '^S-[0-9-]+$'){throw 'INVALID_LAUNCH_BINDING'}
 $definitions="function Get-SafePlanError {`n"+${function:Get-SafePlanError}.ToString()+"`n}`nfunction Invoke-PinnedPlan {`n"+${function:Invoke-PinnedPlan}.ToString()+"`n}`n"
 $body=@'
$ErrorActionPreference='Stop'
$stage='IDENTITY'
try {
 if($env:COMPUTERNAME -cne '__HOST__'){throw 'HOST_IDENTITY_MISMATCH'}
 $i=[Security.Principal.WindowsIdentity]::GetCurrent()
 if($i.User.Value -cne '__SID__'){throw 'DIFFERENT_ACCOUNT_REFUSED'}
 if(-not ([Security.Principal.WindowsPrincipal]::new($i)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ELEVATION_REQUIRED'}
 $stage='DOWNLOAD'
 $client=[Net.WebClient]::new()
 try {$bytes=$client.DownloadData('https://raw.githubusercontent.com/MounesHudifa/erp-trusted-execution-root/f52076544f5d3ccf35409a12d05015551f6e2af5/probes/Get-Wsl2TrialPlan.ps1')}finally{$client.Dispose()}
 $stage='VERIFY_AND_PLAN'
 Invoke-PinnedPlan -Bytes $bytes -ExpectedHash '116179266dd4672f3632a582c2f63be331086edd4ca3aba4f8c03f7b0588b3ed' -ExpectedHost '__HOST__' -OriginalSid '__SID__' | ConvertTo-Json -Depth 10
} catch {Get-SafePlanError -Record $_ -Stage $stage | ConvertTo-Json -Depth 4}
$null=Read-Host 'Copy the JSON result, then press Enter to close this one-off elevated process'
'@
 $definitions+$body.Replace('__HOST__',$ExpectedHost).Replace('__SID__',$OriginalSid)
}
if($LoadFunctionsOnly){return}
$ErrorActionPreference='Stop';$stage='IDENTITY'
try {
 if($env:COMPUTERNAME -cne $ExpectedComputerName){throw 'HOST_IDENTITY_MISMATCH'}
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $child=New-PlanChild -ExpectedHost $ExpectedComputerName -OriginalSid $sid
 $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
 $stage='UAC'
 Write-Host 'Approve Windows PowerShell for the SAME account only. Cancel a different-account prompt.'
 Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -ArgumentList ('-NoProfile -EncodedCommand '+$encoded) -Wait
} catch {Get-SafePlanError -Record $_ -Stage $stage | ConvertTo-Json -Depth 4}
