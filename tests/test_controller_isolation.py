"""Real Linux namespace payloads; require explicit CI activation, never fake pass."""
import os
from pathlib import Path
import tempfile
import unittest

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
        source = {"main.py": script.encode()}
        return c.isolated_probe(self.permit(source), source, self.runtime, timeout=timeout)

    def test_actual_payload_has_no_host_network_credentials_or_writes(self):
        host_net = os.readlink("/proc/self/ns/net")
        script = '''import os, pathlib, ctypes
assert os.readlink('/proc/self/ns/net') != HOST_NET
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
'''.replace("HOST_NET", repr(host_net))
        with unittest.mock.patch.dict(os.environ, {"SYNTHETIC_CONTROLLER_SECRET": "dummy-not-a-secret"}):
            result = self.run_source(script)
        self.assertIn(b"DENIAL=PASS", result["output"])
        self.assertFalse(Path(result["disposableWorkspace"]).exists())
        self.assertFalse(result["adoptionAllowed"])

    def test_actual_second_process_has_fresh_disposable_storage(self):
        script = "from pathlib import Path\np=Path('/work/persist')\nassert not p.exists()\np.write_text('one run')\nprint('FRESH=PASS')\n"
        for _ in range(2):
            result = self.run_source(script)
            self.assertIn(b"FRESH=PASS", result["output"])
            self.assertFalse(Path(result["disposableWorkspace"]).exists())

    def test_actual_timeout_kills_sandbox(self):
        with self.assertRaisesRegex(c.Denied, "ISOLATED_VALIDATION_TIMEOUT"):
            self.run_source("import time\ntime.sleep(60)\n", timeout=1)

    def test_actual_candidate_failure_does_not_pass(self):
        with self.assertRaisesRegex(c.Denied, "ISOLATION_OR_CANDIDATE_FAILED"):
            self.run_source("raise SystemExit(17)\n")
