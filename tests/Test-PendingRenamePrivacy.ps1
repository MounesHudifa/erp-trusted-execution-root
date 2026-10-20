$ErrorActionPreference='Stop'
. "$PSScriptRoot/../probes/PendingRename-Summary.ps1" -LoadFunctionsOnly
$count=0
function Assert($ok,$label){if(-not $ok){throw $label};$script:count++}
$cases=@(
 @{raw=[string[]]@('C:\Windows\SoftwareDistribution\secret-user','');category='windowsServicingHint'},
 @{raw=[string[]]@('C:\Program Files\WSL\synthetic-secret','');category='wslHint'},
 @{raw=[string[]]@('C:\Windows\Installer\secret.msi','');category='installerHint'},
 @{raw=[string[]]@('C:\Users\secret-user\private-token','C:\private-database');category='otherUnknown'},
 @{raw=[string[]]@('C:\Program Files\WSL\secret.msi','');category='ambiguous'}
)
foreach($case in $cases){
 $r=Get-PendingRenameSummary -Raw $case.raw
 Assert ($r.status -eq 'READ' -and $r.operationCount -eq 1 -and $r.categories[$case.category] -eq 1) 'classification'
 $json=$r|ConvertTo-Json -Depth 4 -Compress
 Assert ($json -notmatch 'secret|private|token|C:|\\') 'private output'
 Assert ($r.age -eq 'UNKNOWN' -and $r.wslConflict -eq 'UNKNOWN' -and $r.rebootRequired -eq 'UNKNOWN' -and -not $r.ownershipProven) 'unjustified inference'
}
foreach($raw in @('single-secret-value',[string[]]@('odd-secret'),[string[]]@('',''))){
 $r=Get-PendingRenameSummary -Raw $raw
 Assert ($r.status -eq 'UNKNOWN' -and $r.operationCount -eq 0) 'malformed'
 Assert (($r|ConvertTo-Json -Depth 4) -notmatch 'secret') 'malformed disclosure'
}
$r=Get-PendingRenameSummary -Raw $null
Assert ($r.status -eq 'ABSENT') 'absent'
$r=Get-PendingRenameSummary -Raw ([string[]]@())
Assert ($r.status -eq 'READ' -and $r.operationCount -eq 0) 'empty'
$r=Get-PendingRenameSummary -Raw ([string[]]@('C:\x','','C:\y','C:\z'))
Assert ($r.deleteCount -eq 1 -and $r.renameCount -eq 1) 'pair ordering'
# Schema is fixed: no path-derived keys/strings, even for malicious input.
$r=Get-PendingRenameSummary -Raw ([string[]]@('$(Write-Output synthetic-secret)"\nuser-name',''))
Assert ($r.categories.otherUnknown -eq 1 -and ($r|ConvertTo-Json -Depth 4) -notmatch 'synthetic|user-name|Write-Output') 'untrusted path'
$tokens=$null;$errors=$null
$null=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path "$PSScriptRoot/../probes/PendingRename-Summary.ps1"),[ref]$tokens,[ref]$errors)
Assert ($errors.Count -eq 0) 'syntax'
$r=(& "$PSScriptRoot/../probes/PendingRename-Summary.ps1" -ExpectedComputerName 'not-this-ci-host')|ConvertFrom-Json
Assert ($r.status -eq 'UNKNOWN' -and -not $r.registryChanged) 'wrong host entry'
Write-Output "PENDING_RENAME_PRIVACY_ASSERTIONS_PASS=$count"
Write-Output 'TARGET_REGISTRY_READ=NO; RAW_PATHS_EMITTED=NO'
