"""Actual hardware-accelerated guest test with PUBLIC fixed synthetic payloads.

Not a private-candidate launcher. No guest-supplied assertion grants authority.
No TCG fallback; no KVM means failure, never a skipped/pretend isolation pass.
"""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from trustroot.backends import qemu_probe_argv


def cpio_entry(name, data, mode, inode):
    name = name.encode() + b'\0'
    fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
    header = b'070701' + ''.join(f'{n:08x}' for n in fields).encode()
    result = header + name
    result += b'\0' * (-len(result) % 4)
    result += data
    return result + b'\0' * (-len(data) % 4)


def make_initrd(path, payload):
    init = '''#!/bin/busybox sh
export PATH=/bin
busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec >/dev/console 2>&1
'''+payload+'''
rc=$?
echo SYNTHETIC_GUEST_EXIT=$rc
sync
poweroff -f
'''
    entries = [(p, b'', stat.S_IFDIR | 0o755) for p in ('bin', 'dev', 'proc', 'sys', 'tmp', 'mnt')]
    entries += [('bin/busybox', Path('/bin/busybox').read_bytes(), stat.S_IFREG | 0o755),
                ('init', init.encode(), stat.S_IFREG | 0o755)]
    path.write_bytes(b''.join(cpio_entry(n, d, m, i + 1) for i, (n, d, m) in enumerate(entries))
                     + cpio_entry('TRAILER!!!', b'', 0, len(entries) + 1))


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**2, 2 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (40, 40))


def run_guest(kernel, script, timeout=40):
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='public-guest-') as root:
        root = Path(root)
        initrd = root / 'probe.cpio'
        make_initrd(initrd, script)
        argv = qemu_probe_argv(shutil.which('qemu-system-x86_64'), kernel, initrd, 'kvm')
        trace = root / 'kvm-trace.log'
        argv = ['strace', '-f', '-e', 'trace=openat,ioctl', '-o', str(trace)] + argv
        with (root / 'serial.log').open('wb') as stream:
            p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream,
                                 stderr=subprocess.STDOUT, env={'PATH': '/usr/bin:/bin'},
                                 close_fds=True, start_new_session=True, preexec_fn=limits)
            timed_out = False
            try:
                p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=5)
        output = (root / 'serial.log').read_bytes().decode(errors='replace')
        if p.returncode != 0 and not timed_out:
            details = '\n'.join(l for l in trace.read_text().splitlines()
                                if '/dev/kvm' in l or 'EACCES' in l or 'EPERM' in l)
            raise AssertionError('QEMU failed: ' + output[-6000:] + '\n' + details)
        result = {'seconds': round(time.monotonic() - started, 3), 'timedOut': timed_out,
                  'output': output, 'initrdSha256': hashlib.sha256(initrd.read_bytes()).hexdigest()}
    assert not root.exists(), 'guest staging not destroyed'
    return result


def main():
    assert os.geteuid() != 0, 'QEMU must run unprivileged'
    assert os.access('/dev/kvm', os.R_OK | os.W_OK), 'HARDWARE_KVM_UNAVAILABLE_NO_TCG_FALLBACK'
    # Pinpoint open versus ioctl versus executable-specific denial; never relax
    # LSM or substitute TCG after a host-policy rejection.
    print('KVM_FILE_MODE=' + oct(os.stat('/dev/kvm').st_mode), flush=True)
    print('HOST_LSM=' + Path('/proc/self/attr/current').read_text().strip(), flush=True)
    fd = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
    try:
        print('KVM_API_VERSION=' + str(fcntl.ioctl(fd, 0xAE00, 0)), flush=True)
        vm = fcntl.ioctl(fd, 0xAE01, 0)
        os.close(vm)
        print('KVM_CREATE_VM=PASS', flush=True)
    finally:
        os.close(fd)
    kernel = Path(sys.argv[1]).resolve()
    os.environ['SYNTHETIC_CONTROLLER_SECRET'] = 'public-dummy-host-marker'
    with tempfile.TemporaryDirectory(prefix='public-host-') as host:
        marker = Path(host) / 'host-only-marker'
        marker.write_text('public-dummy-host-marker')
        payload = '''(
set -eu
test -z "${SYNTHETIC_CONTROLLER_SECRET:-}"
test ! -e /mnt/c
test ! -e /dev/dxg
test ! -e /run/docker.sock
test ! -e /tmp/persist
test "$(ls /sys/class/net)" = lo
test ! -e HOST_MARKER
if mount -t 9p -o trans=virtio host /mnt 2>/dev/null; then exit 91; fi
if nc -w 1 192.0.2.1 443 </dev/null; then exit 92; fi
echo disposable >/tmp/persist
echo SYNTHETIC_DENIALS=PASS
)'''.replace('HOST_MARKER', str(marker))
        runs = [run_guest(kernel, payload) for _ in range(2)]
        for r in runs:
            assert 'SYNTHETIC_DENIALS=PASS' in r['output'], r['output'][-6000:]
            assert 'SYNTHETIC_GUEST_EXIT=0' in r['output'], r['output'][-6000:]
        assert marker.read_text() == 'public-dummy-host-marker'
        failure = run_guest(kernel, '(exit 17)')
        assert 'SYNTHETIC_GUEST_EXIT=17' in failure['output']
        assert 'SYNTHETIC_GUEST_EXIT=0' not in failure['output']
        timeout = run_guest(kernel, 'sleep 90', timeout=2)
        assert timeout['timedOut']
    print(json.dumps({'result': 'PUBLIC_QEMU_KVM_SYNTHETIC_GUEST_TESTS_PASS',
                      'realGuestBoots': 3, 'timeoutProcessKilled': True,
                      'freshGuestRepeats': 2, 'seconds': [r['seconds'] for r in runs],
                      'kernelSha256': hashlib.sha256(kernel.read_bytes()).hexdigest(),
                      'initrdSha256': runs[0]['initrdSha256'],
                      'windowsWhpxProven': False, 'privateExecutionAuthorized': False,
                      'productionSecurityCertified': False, 'skippedTests': 0}))


if __name__ == '__main__':
    main()
