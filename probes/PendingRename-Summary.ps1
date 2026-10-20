#requires -Version 5.1
[CmdletBinding()]
param([string]$ExpectedComputerName,[switch]$LoadFunctionsOnly)
function Get-PendingRenameSummary {
 param([AllowNull()][object]$Raw)
 $result=[ordered]@{status='UNKNOWN';operationCount=0;deleteCount=0;renameCount=0;categories=[ordered]@{windowsServicingHint=0;wslHint=0;installerHint=0;ambiguous=0;otherUnknown=0};classification='PATH_HINTS_ONLY';ownershipProven=$false;wslConflict='UNKNOWN';age='UNKNOWN';rebootRequired='UNKNOWN';registryChanged=$false;referencedFilesOpened=$false}
 if($null -eq $Raw){$result.status='ABSENT';return $result}
 if($Raw -isnot [string[]] -or $Raw.Count -gt 20000 -or ($Raw.Count % 2) -ne 0){return $result}
 for($n=0;$n -lt $Raw.Count;$n+=2){if([string]::IsNullOrEmpty($Raw[$n])){return $result}}
 $result.status='READ'
 for($n=0;$n -lt $Raw.Count;$n+=2){
  $result.operationCount++
  if($Raw[$n+1].Length -eq 0){$result.deleteCount++}else{$result.renameCount++}
  $joined=$Raw[$n]+'|'+$Raw[$n+1]
  $hints=@()
  if($joined -match '(?i)\\Windows\\(SoftwareDistribution|WinSxS|servicing)\\'){$hints+='windowsServicingHint'}
  if($joined -match '(?i)(\\WSL\\|\\(wsl|wslservice|wslhost)\.exe(?:$|\|)|MicrosoftCorporationII\.WindowsSubsystemForLinux)'){$hints+='wslHint'}
  if($joined -match '(?i)(\\Windows\\Installer\\|\\Package Cache\\|\.(msi|msp)(?:$|\|))'){$hints+='installerHint'}
  if($hints.Count -gt 1){$result.categories.ambiguous++}elseif($hints.Count -eq 1){$result.categories[$hints[0]]++}else{$result.categories.otherUnknown++}
 }
 return $result
}
if($LoadFunctionsOnly){return}
$ErrorActionPreference='Stop';$key=$null
try {
 if($env:COMPUTERNAME -cne $ExpectedComputerName){throw 'HOST_MISMATCH'}
 $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager',$false)
 if($null -eq $key){throw 'KEY_UNAVAILABLE'}
 $raw=$key.GetValue('PendingFileRenameOperations',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
 Get-PendingRenameSummary -Raw $raw|ConvertTo-Json -Depth 4
} catch { [ordered]@{status='UNKNOWN';code='READ_OR_HOST_VALIDATION_FAILED';registryChanged=$false;referencedFilesOpened=$false}|ConvertTo-Json }
finally {if($key){$key.Dispose()}}
