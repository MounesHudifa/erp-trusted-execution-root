#requires -Version 5.1
# Pure policy. This module cannot issue authority or perform device IO.
function Assert-WslTrialPreconditions {
 param($Plan,[string]$ExpectedHost)
 if(-not $Plan -or $Plan.host -cne $ExpectedHost){throw 'HOST_IDENTITY_MISMATCH'}
 if($Plan.vmpState -ne 'Enabled'){throw 'VMP_NOT_ALREADY_ENABLED_NO_PARTIAL_CHANGE'}
 if($Plan.allUserAppxInventoryKnown -isnot [bool] -or $Plan.allUserAppxInventoryKnown -ne $true){throw 'ALL_USER_RUNTIME_INVENTORY_UNKNOWN'}
 if(-not $Plan.PSObject.Properties['msiInventoryKnown'] -or $Plan.msiInventoryKnown -isnot [bool] -or $Plan.msiInventoryKnown -ne $true){throw 'MSI_INVENTORY_UNKNOWN'}
 foreach($name in @('appxVersions','msiVersions','currentUserDistributions','pendingRebootIndicators','installBlockReasons')){
  if(-not $Plan.PSObject.Properties[$name] -or $null -eq $Plan.$name){throw 'INCOMPLETE_PLAN'}
 }
 if(@($Plan.appxVersions).Count -or @($Plan.msiVersions).Count -or @($Plan.currentUserDistributions).Count -or $Plan.currentUserWslConfigExists -ne $false){throw 'EXISTING_COMPONENTS_PRESERVE_STOP'}
 foreach($indicator in @($Plan.pendingRebootIndicators)){
  if($indicator -cne 'PendingFileRenameOperations'){throw 'OTHER_REBOOT_INDICATOR_PRESERVE_STOP'}
 }
 # Legacy Plan may report this aggregate reason; it is conditional only when
 # the complete indicator list contains exactly the reviewed registry marker.
 foreach($reason in @($Plan.installBlockReasons)){
  if($reason -cne 'PENDING_REBOOT_PRESERVE_STOP' -or @($Plan.pendingRebootIndicators).Count -ne 1 -or $Plan.pendingRebootIndicators[0] -cne 'PendingFileRenameOperations'){throw 'INSTALL_PREFLIGHT_BLOCKED'}
 }
}
function Assert-WslTrialAuthorityBinding {
 param($Authority,[string]$HostName,[string]$ScriptHash)
 # This is binding validation, NOT issuer authentication. The governed caller
 # must independently verify the live owner decision before invoking Install.
 if(-not $Authority -or $Authority.status -cne 'OWNER_AUTHORIZED_SINGLE_INSTALL'){throw 'INDEPENDENT_LOCAL_AUTHORITY_REQUIRED'}
 if($Authority.host -cne $HostName -or $Authority.scriptSha256 -cne $ScriptHash -or $Authority.packageSha256 -cne 'ae977286974255bd26bf925f00f40f5692c6b2084155cbc0563c09aea091f211'){throw 'AUTHORITY_BINDING_MISMATCH'}
 if($Authority.controlSha -notmatch '^[a-f0-9]{40}$' -or $Authority.ownerDecisionReference -notmatch '^https://github\.com/[^/]+/[^/]+/(issues|pull)/[0-9]+#issuecomment-[0-9]+$'){throw 'AUTHORITY_SOURCE_REQUIRED'}
 if($Authority.maxInstallAttempts -ne 1 -or $Authority.allowPendingRenameRisk -ne $true -or $Authority.allowReboot -ne $false -or $Authority.allowLinuxExecution -ne $false -or $Authority.allowRollback -ne $false){throw 'AUTHORITY_SCOPE_MISMATCH'}
}
function Get-WslTrialOutcome {
 param([AllowNull()][object]$ExitCode)
 $state='FAILED_OR_UNEXPECTED_STOP'
 if($ExitCode -is [int] -and $ExitCode -eq 0){$state='INSTALLED_UNVALIDATED_STOP'}
 if($ExitCode -is [int] -and $ExitCode -eq 3010){$state='REBOOT_REQUIRED_STOP'}
 [ordered]@{status=$state;msiExitCode=$ExitCode;candidateExecutionAllowed=$false;linuxExecutionAllowed=$false;rebootAllowed=$false;automaticRollbackAllowed=$false;isolationProven=$false}
}
