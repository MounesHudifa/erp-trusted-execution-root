"""Real Linux namespace payloads; require explicit CI activation, never fake pass."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from trustroot import controller as c


@unittest.skipUnless(os.environ.get("TRUSTROOT_REQUIRE_ISOLATION") == "1",
                     "REAL_OS_ISOLATION_NOT_EXECUTED: requires a capable disposable Linux host")
class ActualIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = Path(os.environ["TRUSTROOT_PROBE_RUNTIME"])
        cls.runtime_id = c.runtime_hash(cls.runtime)

    def permit(self, source, command=None):
        return c.Permit("demo-owner/internal-project", "a"*40, "b"*40, "c"*40,
                        101, 102, "9"*40, self.runtime_id,
                        command or ("/usr/bin/python3", "-I", "-B", "/candidate/main.py"),
                        tuple((p, c.blob_hash(v)) for p, v in source.items()), 2345)

    def run_source(self, script, timeout=15):
        # Syntax-check only these fixed public synthetic test payloads. The
        # production controller never compiles target source on the host.
        compile(script, '<public-synthetic-fixture>', 'exec')
        source = {"main.py": script.encode()}
        try:
            return c.isolated_probe(self.permit(source), source, self.runtime, timeout=timeout)
        except c.IsolationFailed as exc:
            # This suite has synthetic PUBLIC payloads exclusively. Production
            # controller exceptions never include candidate output in their text.
            print('PUBLIC_SYNTHETIC_ISOLATION_DIAGNOSTIC=' + exc.diagnostic.decode('utf-8', errors='replace'))
            raise

    def test_actual_payload_has_no_host_network_credentials_or_writes(self):
        host_net = os.readlink("/proc/self/ns/net")
        script = '''import os, pathlib, ctypes
assert os.readlink('/proc/self/ns/net') != __EXPECTED_NETWORK_NAMESPACE__
assert 'GITHUB_TOKEN' not in os.environ and 'GH_TOKEN' not in os.environ
assert 'SYNTHETIC_CONTROLLER_SECRET' not in os.environ
for p in ('/home/runner', '/workspace', '/run/docker.sock', '/etc/shadow'):
    assert not pathlib.Path(p).exists(), p
for p in ('/candidate/main.py', '/usr/bin/python3'):
    try:
        pathlib.Path(p).write_text('changed')
    except OSError:
        pass
    else:
        raise AssertionError('read-only mount writable: ' + p)
caps = [l for l in pathlib.Path('/proc/self/status').read_text().splitlines() if l.startswith('CapEff:')][0]
assert int(caps.split()[1],16) == 0
assert ctypes.CDLL(None).unshare(0x10000000) == -1
pathlib.Path('/work/temporary.txt').write_text('disposable')
print('HOST_NETWORK_CREDENTIAL_WRITE_DENIAL=PASS')
'''.replace("__EXPECTED_NETWORK_NAMESPACE__", repr(host_net))
        with patch.dict(os.environ, {"SYNTHETIC_CONTROLLER_SECRET": "dummy-not-a-secret"}):
            result = self.run_source(script)
        self.assertIn(b"DENIAL=PASS", result["output"])
        self.assertFalse(Path(result["disposableWorkspace"]).exists())
        self.assertFalse(result["adoptionAllowed"])

    def test_actual_candidate_network_and_windows_interop_denied(self):
        result = self.run_source("""import socket, pathlib, subprocess
for target in [('127.0.0.1', 445), ('192.0.2.1', 443), ('1.1.1.1', 443)]:
    with socket.socket() as sock:
        sock.settimeout(1)
        try: sock.connect(target)
        except OSError: pass
        else: raise AssertionError('NETWORK_REACHABLE')
assert not pathlib.Path('/proc/sys/fs/binfmt_misc/WSLInterop').exists()
try: subprocess.run(['/mnt/c/Windows/System32/cmd.exe', '/c', 'exit'], check=True)
except OSError: pass
else: raise AssertionError('WINDOWS_INTEROP_REACHABLE')
print('CANDIDATE_NETWORK_AND_WINDOWS_INTEROP_DENIED=PASS')
""")
        self.assertIn(b'INTEROP_DENIED=PASS', result['output'])

    def test_actual_second_process_has_fresh_disposable_storage(self):
        script = "from pathlib import Path\np=Path('/work/persist')\nassert not p.exists()\np.write_text('one run')\nprint('FRESH=PASS')\n"
        for _ in range(2):
            result = self.run_source(script)
            self.assertIn(b"FRESH=PASS", result["output"])
            self.assertFalse(Path(result["disposableWorkspace"]).exists())

    def test_actual_confined_mount_and_synthetic_host_file_denied(self):
        # Canary is created in this disposable Linux test environment only.
        # No Windows drive is mounted and no real host file is opened.
        with tempfile.TemporaryDirectory(prefix='synthetic-host-canary-') as outer:
            canary = Path(outer) / 'dummy.txt'
            canary.write_text('public synthetic canary')
            script = '''import ctypes, errno, pathlib
canary = pathlib.Path(__CANARY__)
assert not canary.exists()
try:
    canary.read_bytes()
except (FileNotFoundError, PermissionError):
    pass
else:
    raise AssertionError('synthetic outside file accessible')
for path in ('/mnt/c', '/mnt/wsl', '/mnt/wslg', '/dev/dxg', '/run/docker.sock'):
    assert not pathlib.Path(path).exists(), path
target = pathlib.Path('/work/mount-test')
target.mkdir()
libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
libc.mount.restype = ctypes.c_int
for source, fs, flags in ((b'tmpfs', b'tmpfs', 0), (b'/candidate', None, 4096)):
    ctypes.set_errno(0)
    result = libc.mount(source, bytes(target), fs, flags, None)
    assert result == -1 and ctypes.get_errno() == errno.EPERM, (result, ctypes.get_errno())
print('CONFINED_MOUNT_AND_SYNTHETIC_HOST_FILE_DENIAL=PASS')
'''.replace('__CANARY__', repr(str(canary)))
            result = self.run_source(script)
            self.assertIn(b'CONFINED_MOUNT_AND_SYNTHETIC_HOST_FILE_DENIAL=PASS', result['output'])
            self.assertEqual(canary.read_text(), 'public synthetic canary')
            self.assertFalse(Path(result['disposableWorkspace']).exists())

    def test_actual_timeout_kills_sandbox(self):
        with self.assertRaisesRegex(c.Denied, "ISOLATED_VALIDATION_TIMEOUT"):
            self.run_source("import time\ntime.sleep(60)\n", timeout=1)

    def test_actual_candidate_failure_does_not_pass(self):
        with self.assertRaisesRegex(c.Denied, "ISOLATION_OR_CANDIDATE_FAILED"):
            self.run_source("raise SystemExit(17)\n")

    def test_actual_signed_synthetic_admission_and_execution_sequence(self):
        import base64
        from test_controller import ControllerTests
        fixture = ControllerTests()
        fixture.setUp()
        try:
            baseline = b"synthetic baseline\n"
            payload = b"print('FULL_SYNTHETIC_ADMISSION_AND_ISOLATION=PASS')\n"
            gh = fixture.gh
            gh.before = {"README.md": ("100644", c.blob_hash(baseline))}
            gh.after = dict(gh.before, **{gh.src_path: ("100644", c.blob_hash(payload))})
            gh.auth["approvedChangedBlobs"] = {gh.src_path: {"mode": "100644", "blob": c.blob_hash(payload)}}
            gh._approval_comment()
            fixture.runtime = self.runtime_id
            fixture.command = ("/usr/bin/python3", "-I", "-B", "/candidate/" + gh.src_path)
            fixture.execution["runtimeImageSha256"] = self.runtime_id
            fixture.execution["commandSha256"] = c.digest(list(fixture.command))
            fixture.sign()
            original = fixture.api
            blobs = {c.blob_hash(b): b for b in (baseline, payload)}
            def api(path):
                if "/git/blobs/" in path:
                    key = path.rsplit('/', 1)[1]
                    return {"sha": key, "encoding": "base64", "content": base64.b64encode(blobs[key]).decode()}
                return original(path)
            result = c.validate_once(api, runtime=self.runtime, repository=gh.repo,
                                     main=gh.main, candidate=gh.candidate, control=gh.control,
                                     pr=gh.pr_number, issue=gh.approval_issue,
                                     installed_root_sha=fixture.root, runtime_digest=self.runtime_id,
                                     command=fixture.command)
            self.assertIn(b"FULL_SYNTHETIC_ADMISSION_AND_ISOLATION=PASS", result["output"])
            self.assertFalse(Path(result["disposableWorkspace"]).exists())
        finally:
            fixture.doCleanups()
