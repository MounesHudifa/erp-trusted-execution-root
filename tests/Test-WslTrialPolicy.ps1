$ErrorActionPreference='Stop'
. "$PSScriptRoot/../probes/Wsl2TrialPolicy.ps1"
$script:count=0
function Assert($ok,$label){if(-not $ok){throw $label};$script:count++}
function Reject([scriptblock]$code,[string]$expected){
 $caught=$false
 try {& $code} catch {if($_.Exception.Message -cne $expected){throw};$caught=$true}
 Assert $caught $expected
}
function Plan {
 [pscustomobject]@{host='synthetic-host';vmpState='Enabled';allUserAppxInventoryKnown=$true;msiInventoryKnown=$true;appxVersions=@();msiVersions=@();currentUserDistributions=@();currentUserWslConfigExists=$false;pendingRebootIndicators=@('PendingFileRenameOperations');installBlockReasons=@('PENDING_REBOOT_PRESERVE_STOP')}
}
$p=Plan;Assert-WslTrialPreconditions $p 'synthetic-host';Assert $true 'reviewed-marker-eligible-not-authorized'
Reject {Assert-WslTrialAuthorityBinding $null 'synthetic-host' ('a'*64)} 'INDEPENDENT_LOCAL_AUTHORITY_REQUIRED'
$p=Plan;Reject {Assert-WslTrialPreconditions $p 'wrong-host'} 'HOST_IDENTITY_MISMATCH'
foreach($state in @('Disabled','UNKNOWN','EnablePending')){$p=Plan;$p.vmpState=$state;Reject {Assert-WslTrialPreconditions $p 'synthetic-host'} 'VMP_NOT_ALREADY_ENABLED_NO_PARTIAL_CHANGE'}
$p=Plan;$p.allUserAppxInventoryKnown=$false;Reject {Assert-WslTrialPreconditions $p 'synthetic-host'} 'ALL_USER_RUNTIME_INVENTORY_UNKNOWN'
$p=Plan;$p.msiInventoryKnown=$false;Reject {Assert-WslTrialPreconditions $p 'synthetic-host'} 'MSI_INVENTORY_UNKNOWN'
$p=Plan;$p.PSObject.Properties.Remove('msiInventoryKnown');Reject {Assert-WslTrialPreconditions $p 'synthetic-host'} 'MSI_INVENTORY_UNKNOWN'
$p=Plan;$p.allUserAppxInventoryKnown='true';Reject {Assert-WslTrialPreconditions $p 'synthetic-host'} 'ALL_USER_RUNTIME_INVENTORY_UNKNOWN'
foreach($field in @('appxVersions','msiVersions','currentUserDistributions')){$p=Plan;$p.$field=@('existing');Reject {Assert-WslTrialPreconditions $p 'synthetic-host'} 'EXISTING_COMPONENTS_PRESERVE_STOP'}
$p=Plan;$p.currentUserWslConfigExists=$true;Reject {Assert-WslTrialPreconditions $p 'synthetic-host'} 'EXISTING_COMPONENTS_PRESERVE_STOP'
foreach($indicator in @('RebootPending','RebootRequired','UNKNOWN')){$p=Plan;$p.pendingRebootIndicators+= $indicator;Reject {Assert-WslTrialPreconditions $p 'synthetic-host'} 'OTHER_REBOOT_INDICATOR_PRESERVE_STOP'}
$p=Plan;$p.PSObject.Properties.Remove('pendingRebootIndicators');Reject {Assert-WslTrialPreconditions $p 'synthetic-host'} 'INCOMPLETE_PLAN'
$p=Plan;$p.installBlockReasons+= 'EXISTING_TRIAL_RECEIPT_PRESERVE_STOP';Reject {Assert-WslTrialPreconditions $p 'synthetic-host'} 'INSTALL_PREFLIGHT_BLOCKED'
$p=Plan;$p.pendingRebootIndicators=@();Reject {Assert-WslTrialPreconditions $p 'synthetic-host'} 'INSTALL_PREFLIGHT_BLOCKED'
$p=Plan;$p.installBlockReasons=@();Assert-WslTrialPreconditions $p 'synthetic-host';Assert $true 'new-plan-pending-policy'
$p=Plan;$p.pendingRebootIndicators=@();$p.installBlockReasons=@();Assert-WslTrialPreconditions $p 'synthetic-host';Assert $true 'clean-plan'
foreach($code in @(0,3010,1603,1618,1641,-1,$null,'0')){
 $r=Get-WslTrialOutcome $code
 $expected=if($code -is [int] -and $code -eq 0){'INSTALLED_UNVALIDATED_STOP'}elseif($code -is [int] -and $code -eq 3010){'REBOOT_REQUIRED_STOP'}else{'FAILED_OR_UNEXPECTED_STOP'}
 Assert ($r.status -ceq $expected) 'exit-status'
 Assert (-not $r.candidateExecutionAllowed -and -not $r.linuxExecutionAllowed -and -not $r.rebootAllowed -and -not $r.automaticRollbackAllowed -and -not $r.isolationProven) 'no-next-stage'
}
# Synthetic binding fixture only, never a Control record or a real permit.
$a=[pscustomobject]@{status='OWNER_AUTHORIZED_SINGLE_INSTALL';host='synthetic-host';scriptSha256=('a'*64);packageSha256='ae977286974255bd26bf925f00f40f5692c6b2084155cbc0563c09aea091f211';controlSha=('b'*40);ownerDecisionReference='https://github.com/example/synthetic/issues/1#issuecomment-1';maxInstallAttempts=1;allowPendingRenameRisk=$true;allowReboot=$false;allowLinuxExecution=$false;allowRollback=$false}
Assert-WslTrialAuthorityBinding $a 'synthetic-host' ('a'*64);Assert $true 'synthetic-binding-only'
foreach($field in @('host','scriptSha256','packageSha256')){$b=$a|ConvertTo-Json|ConvertFrom-Json;$b.$field='bad';Reject {Assert-WslTrialAuthorityBinding $b 'synthetic-host' ('a'*64)} 'AUTHORITY_BINDING_MISMATCH'}
foreach($field in @('allowReboot','allowLinuxExecution','allowRollback')){$b=$a|ConvertTo-Json|ConvertFrom-Json;$b.$field=$true;Reject {Assert-WslTrialAuthorityBinding $b 'synthetic-host' ('a'*64)} 'AUTHORITY_SCOPE_MISMATCH'}
$a.status='REQUESTED_NOT_AUTHORIZED';Reject {Assert-WslTrialAuthorityBinding $a 'synthetic-host' ('a'*64)} 'INDEPENDENT_LOCAL_AUTHORITY_REQUIRED'
Write-Output "WSL_TRIAL_POLICY_ASSERTIONS_PASS=$script:count"
Write-Output 'DEVICE_ACCESSED=NO; ACTUAL_AUTHORITY_ISSUED=NO'
