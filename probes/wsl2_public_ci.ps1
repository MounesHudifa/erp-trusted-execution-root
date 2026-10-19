# Synthetic-only experiment. DeviceTrial requires separate exact authorization.
# No private candidate execution or production deployment authority.
#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$DeviceTrial,
    [string]$ExpectedComputerName,
    [string]$SourceRoot = $env:GITHUB_WORKSPACE
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$PSNativeCommandUseErrorActionPreference = $false
if ($DeviceTrial) {
    # This switch is NOT authorization. Caller must obtain an exact new adopted
    # governance permit and platform consent before this separately approved trial.
    if (-not $ExpectedComputerName -or $env:COMPUTERNAME -cne $ExpectedComputerName) { throw 'DEVICE_IDENTITY_MISMATCH' }
    if (-not $SourceRoot -or -not (Test-Path (Join-Path $SourceRoot 'trustroot/controller.py'))) { throw 'PINNED_PUBLIC_SOURCE_REQUIRED' }
    if (Test-Path (Join-Path $env:USERPROFILE '.wslconfig')) { throw 'EXISTING_WSL_CONFIG_PRESERVED_STOP' }
} elseif ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
          $env:TRUSTROOT_DISPOSABLE_PUBLIC_VM -ne '1') {
    throw 'PUBLIC_DISPOSABLE_CI_OR_SEPARATELY_AUTHORIZED_DEVICE_TRIAL_ONLY'
}
$trialId = [guid]::NewGuid().ToString('N')
$distro = 'public-isolation-' + $trialId
$work = Join-Path ([IO.Path]::GetTempPath()) $distro
$config = Join-Path $env:USERPROFILE '.wslconfig'
$originalConfig = if (Test-Path $config) { [IO.File]::ReadAllBytes($config) } else { $null }
$registered = $false
$configChanged = $false
New-Item -ItemType Directory -Path $work -ErrorAction Stop | Out-Null

function Invoke-Guest([string]$Script) {
    # Native PowerShell pipelines append CRLF on Windows, corrupting final
    # shell tokens (measured in the first run). Write exact LF UTF-8 stdin.
    $start = [Diagnostics.ProcessStartInfo]::new('wsl.exe')
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    # Fixed UUID-derived distribution name, no shell interpolation from a caller.
    $start.Arguments = "--distribution $distro --user root --exec /bin/bash --noprofile --norc -s"
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdinBytes = [Text.UTF8Encoding]::new($false).GetBytes($Script.Replace("`r", '') + "`n")
        $process.StandardInput.BaseStream.Write($stdinBytes, 0, $stdinBytes.Length)
        $process.StandardInput.BaseStream.Close()
        if (-not $process.WaitForExit(180000)) { $process.Kill(); throw 'WSL_COMMAND_TIMEOUT' }
        if ($process.ExitCode -ne 0) { throw "WSL_GUEST_COMMAND_FAILED:$($process.ExitCode)" }
    } finally { $process.Dispose() }
}

try {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
    Write-Output ('PUBLIC_VMP_STATE=' + $feature.State)
    if ($feature.State -ne 'Enabled') {
        throw 'PUBLIC_HOST_WSL2_PREREQUISITE_NOT_ENABLED_NO_REBOOT_OR_WSL1_FALLBACK'
    }
    if (-not $DeviceTrial) {
    $msi = Join-Path $work 'wsl.3.0.3.0.x64.msi'
    Write-Output 'WSL_MSI_DOWNLOAD_START'
    Invoke-WebRequest -UseBasicParsing -TimeoutSec 180 'https://github.com/microsoft/WSL/releases/download/3.0.3/wsl.3.0.3.0.x64.msi' -OutFile $msi
    Write-Output 'WSL_MSI_DOWNLOAD_COMPLETE'
    if ((Get-FileHash $msi -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'ae977286974255bd26bf925f00f40f5692c6b2084155cbc0563c09aea091f211') { throw 'WSL_MSI_DIGEST_MISMATCH' }
    $signature = Get-AuthenticodeSignature $msi
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw 'WSL_MSI_SIGNATURE_INVALID' }
    Write-Output 'WSL_MSI_INSTALL_START'
    $install = Start-Process msiexec.exe -ArgumentList @('/i', $msi, '/qn', '/norestart') -Wait -PassThru
    if ($install.ExitCode -ne 0) { throw "PUBLIC_WSL_MSI_FAILED_OR_REBOOT_REQUIRED:$($install.ExitCode)" }
    }
    & wsl.exe --version
    if ($LASTEXITCODE -ne 0) { throw 'PUBLIC_WSL_RUNTIME_NOT_READY' }
    $version = ((& wsl.exe --version) -join "`n").Replace([string][char]0, '')
    if ($version -notmatch '3\.0\.3\.0') { throw 'EXACT_WSL_VERSION_REQUIRED_NO_AUTOMATIC_UPDATE' }
    $existing = ((& wsl.exe --list --quiet) -join "`n").Replace([string][char]0, '').Trim()
    if ($existing -and $existing -notmatch 'no installed distributions') { throw 'PUBLIC_VM_HAS_OTHER_DISTROS_NO_GLOBAL_CONFIGURATION_CHANGE' }
    $archive = Join-Path $work 'ubuntu-base.tar.gz'
    Write-Output 'UBUNTU_ROOTFS_DOWNLOAD_START'
    Invoke-WebRequest -UseBasicParsing -TimeoutSec 180 'https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/ubuntu-base-24.04.3-base-amd64.tar.gz' -OutFile $archive
    Write-Output 'UBUNTU_ROOTFS_DOWNLOAD_COMPLETE'
    if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne '6bc2cde3930ad088b3bb46fa45279e96d25bc3810f209850ecbe4722711874f9') { throw 'ROOTFS_DIGEST_MISMATCH' }
    & wsl.exe --import $distro (Join-Path $work 'distro') $archive --version 2
    if ($LASTEXITCODE -ne 0) { throw 'PUBLIC_WSL2_IMPORT_OR_VIRTUALIZATION_UNAVAILABLE' }
    $registered = $true
    $inventory = ((& wsl.exe --list --verbose) -join "`n").Replace([string][char]0, '')
    Write-Output $inventory
    if ($inventory -notmatch ([regex]::Escape($distro) + '\s+\S+\s+2')) { throw 'NOT_WSL2' }
    Invoke-Guest @'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 bubblewrap
mkdir -p /opt/probe/trustroot /opt/probe/tests /opt/probe/scripts
'@
    Invoke-Guest @'
set -eu
test -d /opt/probe/scripts
test ! -d "$(printf '/opt/probe/scripts\r')"
echo WSL_STDIN_LF_REGRESSION=PASS
'@
    foreach ($relative in @('trustroot/__init__.py','trustroot/verify.py','trustroot/controller.py','trustroot/backends.py','tests/test_trustroot.py','tests/test_controller.py','tests/test_controller_isolation.py','tests/test_backends.py','scripts/build_probe_runtime.py')) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $SourceRoot $relative))
        $encoded = [Convert]::ToBase64String($bytes)
        Invoke-Guest ("printf '%s' '$encoded' | base64 -d > '/opt/probe/$relative'")
    }
    Invoke-Guest @'
set -eu
cat >/etc/wsl.conf <<'EOF'
[automount]
enabled=false
mountFsTab=false
[interop]
enabled=false
appendWindowsPath=false
[boot]
systemd=false
[gpu]
enabled=false
EOF
'@
    [IO.File]::WriteAllText($config, "[wsl2]`nmemory=3GB`nprocessors=2`nswap=0`nnetworkingMode=none`nlocalhostForwarding=false`ndnsTunneling=false`nautoProxy=false`nguiApplications=false`nnestedVirtualization=false`n", [Text.UTF8Encoding]::new($false))
    $configChanged = $true
    & wsl.exe --terminate $distro
    if ($LASTEXITCODE -ne 0) { throw 'TERMINATE_FAILED' }
    # No other distro exists in this disposable public VM (checked above).
    & wsl.exe --shutdown
    if ($LASTEXITCODE -ne 0) { throw 'PUBLIC_VM_SHUTDOWN_FAILED' }
    Invoke-Guest @'
set -eu
uname -a
test ! -e /mnt/c/Windows
test -z "${WSL_INTEROP:-}"
if command -v cmd.exe; then exit 41; fi
python3 - <<'PY'
import socket
for target in [('192.0.2.1',443), ('1.1.1.1',443)]:
    s=socket.socket();s.settimeout(1)
    try:s.connect(target)
    except OSError:pass
    else:raise AssertionError('UNAUTHORIZED_NETWORK_REACHABLE')
    finally:s.close()
print('WSL2_NETWORK_DENIAL=PASS')
PY
# Deliberate negative control: automount=false does NOT prohibit a root manual mount.
# Inspect only existence of a public Windows system directory, never file contents.
mkdir -p /tmp/public-mount-probe
if mount -t drvfs C: /tmp/public-mount-probe; then
  test -d /tmp/public-mount-probe/Windows
  umount /tmp/public-mount-probe
  echo WSL2_AUTOMOUNT_FALSE_IS_NOT_SECURITY_BOUNDARY=CONFIRMED
else
  echo WSL2_MANUAL_MOUNT_RESULT=DENIED_IN_THIS_RUNTIME
fi
cd /opt/probe
python3 -I -B scripts/build_probe_runtime.py /tmp/public-probe-runtime
TRUSTROOT_REQUIRE_ISOLATION=1 TRUSTROOT_PROBE_RUNTIME=/tmp/public-probe-runtime python3 -B - <<'PY'
import unittest,time
t=time.monotonic()
r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.discover('tests'))
assert r.wasSuccessful() and not r.skipped
print('REAL_WSL2_CONFINED_SYNTHETIC_TESTS=PASS')
print('WSL2_TEST_SECONDS='+str(round(time.monotonic()-t,3)))
print('SKIPPED_TESTS=0')
print('PRIVATE_SOURCE_ACCESSED=NO')
PY
'@
} finally {
    if ($registered) {
        & wsl.exe --terminate $distro
        & wsl.exe --unregister $distro
        if ($LASTEXITCODE -ne 0) { throw 'TEST_DISTRO_DESTRUCTION_FAILED' }
        $remaining = ((& wsl.exe --list --quiet) -join "`n").Replace([string][char]0, '')
        if ($remaining.Contains($distro)) { throw 'TEST_DISTRO_PERSISTED' }
        Write-Output 'DISPOSABLE_WSL2_DISTRO_DESTROYED=YES'
    }
    if ($configChanged) {
        if ($null -ne $originalConfig) { [IO.File]::WriteAllBytes($config,$originalConfig) }
        else { Remove-Item -LiteralPath $config }
    }
    # Only this job-created directory; never a pre-existing/user distribution.
    Remove-Item -LiteralPath $work -Recurse -Force
}
