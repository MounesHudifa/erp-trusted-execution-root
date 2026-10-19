"""Synthetic independent execution-authority fixtures; no real approvals."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_trustroot import FakePrivateGitHub, make_blob
from trustroot import controller as c
from trustroot import verify as ro


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.gh = FakePrivateGitHub(Path(self.temp.name) / "sentinel")
        self.root = "9" * 40
        self.runtime = "8" * 64
        self.command = ("/usr/bin/python3", "-I", "-B", "/candidate/main.py")
        self.runners = {"total_count": 0, "runners": []}
        self.inventory_reads = 0
        self.execution = {
            "schemaVersion": 1, "authority": c.EXEC_TAG, "status": "APPROVED",
            "repository": self.gh.repo, "mainSha": self.gh.main,
            "candidateSha": self.gh.candidate, "controlParentSha": self.gh.parent,
            "prNumber": self.gh.pr_number, "securityRootSha": self.root,
            "runtimeImageSha256": self.runtime, "commandSha256": c.digest(list(self.command)),
            "network": "NONE", "hostMounts": "NONE", "credentials": "NONE",
            "adoptionPermission": "NONE", "ownerApprovalCommentId": 2345,
        }
        self.sign()

    def sign(self):
        expected = {k: v for k, v in self.execution.items() if k != "ownerApprovalCommentId"}
        self.comment = {
            "user": {"id": self.gh.owner_id}, "author_association": "OWNER",
            "issue_url": f"https://api.github.com/repos/{self.gh.repo}/issues/{self.gh.approval_issue}",
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
            "body": "\n".join((f"MESSAGE_TYPE={c.EXEC_TAG}", "STATUS=APPROVED",
                                "EXECUTION_PERMISSION=DISPOSABLE_ISOLATED_VALIDATION_ONLY",
                                "ADOPTION_PERMISSION=NONE", "AUTHORITY_SHA256=" + c.digest(expected))),
        }

    def api(self, path):
        if path.endswith("/actions/runners?per_page=100"):
            self.inventory_reads += 1
            return self.runners
        if path.endswith(f"/contents/{c.EXEC_PATH}?ref={self.gh.control}"):
            return make_blob(self.execution)
        if path.endswith("/issues/comments/2345"):
            return copy.deepcopy(self.comment)
        return self.gh(path)

    def admit(self):
        return c.admit(self.api, repository=self.gh.repo, main=self.gh.main,
                       candidate=self.gh.candidate, control=self.gh.control,
                       pr=self.gh.pr_number, issue=self.gh.approval_issue,
                       installed_root_sha=self.root, runtime_digest=self.runtime,
                       command=self.command)

    def denied(self, message):
        with patch.object(c.subprocess, "Popen", side_effect=AssertionError("must not execute")):
            with self.assertRaisesRegex((c.Denied, ro.Refusal), message):
                self.admit()
        self.assertFalse(self.gh.sentinel.exists())

    def test_separate_signed_authorities_admit_only_disposable_validation(self):
        permit = self.admit()
        self.assertEqual(permit.candidate, self.gh.candidate)
        self.assertEqual(self.inventory_reads, 2)

    def test_even_offline_persistent_runner_denies_before_reading_candidate(self):
        self.runners = {"total_count": 1, "runners": [{"status": "offline"}]}
        self.denied("PRIVATE_RUNNER_SCHEDULING_BOUNDARY_OPEN")
        self.assertEqual(self.gh.main_read_count, 0)

    def test_inconsistent_runner_inventory_denies(self):
        self.runners = {"total_count": 0, "runners": [{"status": "offline"}]}
        self.denied("PRIVATE_RUNNER_SCHEDULING_BOUNDARY_OPEN")

    def test_unreadable_runner_inventory_cannot_impute_safety(self):
        self.runners = {}
        self.denied("PRIVATE_RUNNER_SCHEDULING_BOUNDARY_OPEN")

    def test_readonly_approval_alone_never_grants_execution(self):
        self.execution["status"] = "PENDING"
        self.denied("EXECUTION_AUTHORITY_ABSENT_OR_MISMATCHED")

    def test_forged_execution_owner_denied(self):
        self.comment["user"]["id"] = 999
        self.denied("EXECUTION_OWNER_PROVENANCE_INVALID")

    def test_edited_execution_approval_denied(self):
        self.comment["updated_at"] = "2026-01-02T00:00:00Z"
        self.denied("EXECUTION_OWNER_PROVENANCE_INVALID")

    def test_unbound_runtime_change_denied(self):
        self.execution["runtimeImageSha256"] = "f" * 64
        self.denied("EXECUTION_AUTHORITY_ABSENT_OR_MISMATCHED")

    def test_unbound_command_change_denied(self):
        self.command = ("/usr/bin/python3", "-c", "print('tampered')")
        self.denied("EXECUTION_AUTHORITY_ABSENT_OR_MISMATCHED")

    def test_root_sha_change_denied(self):
        self.root = "f" * 40
        self.denied("EXECUTION_AUTHORITY_ABSENT_OR_MISMATCHED")

    def test_network_even_owner_signed_not_supported(self):
        self.execution["network"] = "PUBLIC"
        self.sign()
        self.denied("EXECUTION_AUTHORITY_ABSENT_OR_MISMATCHED")

    def test_host_mount_even_owner_signed_not_supported(self):
        self.execution["hostMounts"] = "/"
        self.sign()
        self.denied("EXECUTION_AUTHORITY_ABSENT_OR_MISMATCHED")

    def test_candidate_cannot_gain_adoption(self):
        self.execution["adoptionPermission"] = "YES"
        self.sign()
        self.denied("EXECUTION_AUTHORITY_ABSENT_OR_MISMATCHED")

    def test_submodule_in_unchanged_baseline_denies(self):
        self.gh.before["README.md"] = ("160000", "e" * 40)
        self.gh.after["README.md"] = ("160000", "e" * 40)
        self.denied("CANDIDATE_TREE_MODE_OR_SIZE_INVALID")

    def test_new_runner_during_attestation_denies(self):
        original = self.api
        def racing(path):
            if path.endswith("/actions/runners?per_page=100") and self.inventory_reads:
                return {"total_count": 1, "runners": [{}]}
            return original(path)
        with self.assertRaisesRegex(c.Denied, "PRIVATE_RUNNER_SCHEDULING_BOUNDARY_OPEN"):
            c.admit(racing, repository=self.gh.repo, main=self.gh.main,
                    candidate=self.gh.candidate, control=self.gh.control,
                    pr=self.gh.pr_number, issue=self.gh.approval_issue,
                    installed_root_sha=self.root, runtime_digest=self.runtime, command=self.command)

    def test_source_drift_refused_before_subprocess(self):
        root = Path(self.temp.name) / "runtime"
        root.mkdir()
        (root / "runtime.txt").write_text("synthetic")
        from dataclasses import replace
        permit = replace(self.admit(), runtime_digest=c.runtime_hash(root))
        with patch.object(c.subprocess, "Popen", side_effect=AssertionError("must not execute")):
            with self.assertRaisesRegex(c.Denied, "CANDIDATE_FILE_SET_DRIFT"):
                c.isolated_probe(permit, {}, root)

    def test_backend_requires_explicit_user_namespace_not_optional_unshare_all(self):
        # bwrap 0.9.0 treats --unshare-all's user namespace as optional;
        # --disable-userns requires an explicit --unshare-user. Do not fix
        # that runtime refusal by dropping the nested-namespace protection.
        from dataclasses import replace
        root = Path(self.temp.name) / "runtime"
        root.mkdir()
        (root / "runtime.txt").write_text("synthetic")
        files = {"main.py": b"print('synthetic')\n"}
        permit = replace(self.admit(), runtime_digest=c.runtime_hash(root),
                         tree=(("main.py", c.blob_hash(files["main.py"])),))
        with patch.object(c.subprocess, "Popen") as launch:
            launch.return_value.returncode = 0
            launch.return_value.poll.return_value = 0
            c.isolated_probe(permit, files, root)
        argv = launch.call_args.args[0]
        self.assertIn("--unshare-user", argv)
        self.assertIn("--disable-userns", argv)
        self.assertIn("--unshare-all", argv)
        self.assertEqual(launch.call_args.kwargs["env"], {})
        self.assertTrue(launch.call_args.kwargs["close_fds"])

    def test_runtime_bytes_changed_refused_before_process(self):
        from dataclasses import replace
        root = Path(self.temp.name) / "runtime"
        root.mkdir()
        item = root / "runtime.txt"
        item.write_text("synthetic")
        permit = replace(self.admit(), runtime_digest=c.runtime_hash(root))
        item.write_text("changed")
        with patch.object(c.subprocess, "Popen", side_effect=AssertionError("must not execute")):
            with self.assertRaisesRegex(c.Denied, "RUNTIME_IDENTITY_DRIFT"):
                c.isolated_probe(permit, {}, root)


if __name__ == "__main__":
    unittest.main()
