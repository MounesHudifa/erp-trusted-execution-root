#requires -Version 5.1
[CmdletBinding()]
param([switch]$Elevated,[string]$OriginalIdentityHash,[string]$LauncherHash,[switch]$LoadFunctionsOnly)
function Get-TrialBytesHash([byte[]]$Bytes){
 $a=[Security.Cryptography.SHA256]::Create()
 try{[BitConverter]::ToString($a.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$a.Dispose()}
}
function Assert-InstallPayload($Payload){
 if($Payload.host -notmatch '^[A-Za-z0-9-]{1,63}$' -or $Payload.registeredControlSha -notmatch '^[a-f0-9]{40}$'){throw 'PAYLOAD_BINDING_INVALID'}
 $a=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload.authorityBase64))
 if((Get-TrialBytesHash ([Text.Encoding]::UTF8.GetBytes($a))) -cne $Payload.authoritySha256){throw 'AUTHORITY_HASH_MISMATCH'}
 $auth=$a|ConvertFrom-Json
 if($auth.status -cne 'OWNER_AUTHORIZED_SINGLE_INSTALL' -or $auth.host -cne $Payload.host -or $auth.consumed -ne $false -or $auth.attemptsExecuted -ne 0 -or $auth.executionMode -cne 'OWNER_INTERACTIVE_SAME_ACCOUNT_UAC' -or $auth.remoteMutationAuthorized -ne $false){throw 'AUTHORITY_NOT_EXECUTABLE'}
 foreach($item in @(@('Prepare-Wsl2Trial.ps1','scriptSha256'),@('Wsl2TrialPolicy.ps1','policySha256'),@('Get-Wsl2TrialPlan.ps1','planSha256'))){
  $bytes=[Convert]::FromBase64String($Payload.files.($item[0]))
  if((Get-TrialBytesHash $bytes) -cne $auth.($item[1])){throw 'SCRIPT_HASH_MISMATCH'}
 }
 return $auth
}
if($LoadFunctionsOnly){return}
$ErrorActionPreference='Stop';$stage='PAYLOAD';$staging=$null
try {
 # Replaced only in the private owner delivery; no authority is embedded publicly.
 $packed='__PRIVATE_PAYLOAD_BASE64__'
 $payload=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($packed))|ConvertFrom-Json
 $authority=Assert-InstallPayload $payload
 if($env:COMPUTERNAME -cne $payload.host){throw 'HOST_IDENTITY_MISMATCH'}
 $stage='IDENTITY'
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $identityHash=Get-TrialBytesHash ([Text.Encoding]::UTF8.GetBytes($identity.User.Value))
 $selfHash=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
 if(-not $Elevated){
  $stage='UAC'
  Write-Host 'Approve UAC for the SAME account only; cancel if another account is requested.'
  $arguments=@('-NoProfile','-File',('"'+$PSCommandPath+'"'),'-Elevated','-OriginalIdentityHash',$identityHash,'-LauncherHash',$selfHash)
  $null=Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -ArgumentList $arguments -Wait -PassThru
  return
 }
 if($identityHash -cne $OriginalIdentityHash){throw 'DIFFERENT_ACCOUNT_REFUSED'}
 if($selfHash -cne $LauncherHash){throw 'LAUNCHER_CHANGED'}
 if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ELEVATION_REQUIRED'}
 $stage='STAGING'
 $staging=Join-Path ([IO.Path]::GetTempPath()) ('sec02-owner-install-'+[guid]::NewGuid().ToString('N'))
 New-Item -ItemType Directory -Path $staging|Out-Null
 foreach($name in @('Prepare-Wsl2Trial.ps1','Wsl2TrialPolicy.ps1','Get-Wsl2TrialPlan.ps1')){[IO.File]::WriteAllBytes((Join-Path $staging $name),[Convert]::FromBase64String($payload.files.$name))}
 $authPath=Join-Path $staging 'owner-authority.json'
 [IO.File]::WriteAllBytes($authPath,[Convert]::FromBase64String($payload.authorityBase64))
 $stage='INSTALL'
 & (Join-Path $staging 'Prepare-Wsl2Trial.ps1') -Action Install -ExpectedComputerName $payload.host -AuthorizationEvidencePath $authPath
 Write-Host 'STOP: no Linux, candidate, retry, rollback or reboot is authorized by this launcher.'
} catch {
 $native=$null;$e=$_.Exception
 while($e){if($e -is [ComponentModel.Win32Exception]){$native=$e.NativeErrorCode};$e=$e.InnerException}
 [ordered]@{status='STOP';stage=$stage;hresult=$_.Exception.HResult;nativeErrorCode=$native;automaticRetry=$false;automaticRollback=$false}|ConvertTo-Json
} finally {
 if($staging){Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue}
 if($Elevated){$null=Read-Host 'Copy the JSON result, then press Enter to close'}
}
