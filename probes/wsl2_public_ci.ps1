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
    throw 'DEVICE_TRIAL_NOT_AUTHORIZED_WSL_IS_NOT_A_HOST_SECURITY_BOUNDARY'
}
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:TRUSTROOT_DISPOSABLE_PUBLIC_VM -ne '1') {
    throw 'PUBLIC_DISPOSABLE_CI_ONLY'
}
$trialId = [guid]::NewGuid().ToString('N')
$distro = 'public-isolation-' + $trialId
$work = Join-Path ([IO.Path]::GetTempPath()) $distro
$config = Join-Path $env:USERPROFILE '.wslconfig'
$originalConfig = if (Test-Path $config) { [IO.File]::ReadAllBytes($config) } else { $null }
$registered = $false
New-Item -ItemType Directory -Path $work -ErrorAction Stop | Out-Null

function Invoke-Guest([string]$Script) {
    # Native PowerShell pipelines append CRLF on Windows, corrupting final
    # shell tokens (measured in the first run). Write exact LF UTF-8 stdin.
    $start = [Diagnostics.ProcessStartInfo]::new('wsl.exe')
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    # Fixed UUID-derived distribution name, no shell interpolation from a caller.
    $start.Arguments = "--distribution $distro --user root --exec /bin/bash --noprofile --norc -e -u -s"
    # .NET Framework constructs StandardInput using Console.InputEncoding and
    # can emit its BOM before a BaseStream write. Control that process-local
    # encoding before Start, then restore it; never change system settings.
    $previousInputEncoding = [Console]::InputEncoding
    try {
        [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
        $process = [Diagnostics.Process]::Start($start)
    } finally { [Console]::InputEncoding = $previousInputEncoding }
    try {
        if ($process.StandardInput.Encoding.GetPreamble().Length -ne 0) { throw 'STDIN_BOM_NOT_ALLOWED' }
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
    $propagated = $false
    try { Invoke-Guest "exit 17`necho MUST_NOT_RUN" } catch {
        if ($_.Exception.Message -ne 'WSL_GUEST_COMMAND_FAILED:17') { throw }
        $propagated = $true
    }
    if (-not $propagated) { throw 'FIRST_COMMAND_ERROR_NOT_PROPAGATED' }
    Write-Output 'WSL_STDIN_BOM_AND_FIRST_COMMAND_FAILURE_REGRESSION=PASS'
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
    & wsl.exe --terminate $distro
    if ($LASTEXITCODE -ne 0) { throw 'TERMINATE_FAILED' }
    Invoke-Guest @'
set -eu
uname -a
test ! -e /mnt/c/Windows
test -z "${WSL_INTEROP:-}"
if command -v cmd.exe; then exit 41; fi
# Network denial is enforced and tested in the candidate namespace, not
# assumed for the whole distribution. Trusted provisioning used networking.
# Mount-denial probes run only inside the capability-dropped candidate namespace.
# They use synthetic Linux paths, never a Windows drive or a host file.
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
        $running = ((& wsl.exe --list --running --quiet) -join "`n").Replace([string][char]0, '')
        if ($running.Contains($distro)) { throw 'TEST_DISTRO_STILL_RUNNING' }
        Write-Output 'DISPOSABLE_WSL2_DISTRO_DESTROYED=YES'
    }
    $afterConfig = if (Test-Path $config) { [IO.File]::ReadAllBytes($config) } else { $null }
    if (($null -eq $originalConfig) -ne ($null -eq $afterConfig)) { throw 'GLOBAL_CONFIG_PRESENCE_CHANGED' }
    if ($null -ne $originalConfig -and [Convert]::ToBase64String($originalConfig) -cne [Convert]::ToBase64String($afterConfig)) { throw 'GLOBAL_CONFIG_BYTES_CHANGED' }
    # Only this job-created directory; never a pre-existing/user distribution.
    Remove-Item -LiteralPath $work -Recurse -Force
    if (Test-Path -LiteralPath $work) { throw 'TRIAL_DIRECTORY_PERSISTED' }
    Write-Output 'TRIAL_DIRECTORY_CLEANED_GLOBAL_CONFIG_UNCHANGED=YES'
}
