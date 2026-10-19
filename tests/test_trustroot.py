"""Behavioral, negative GitHub API fixtures; untrusted content never executed."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from trustroot import verify as trust


def make_blob(data):
    content = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return {"encoding": "base64", "content": base64.b64encode(content).decode(),
            "sha": hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()}


class FakePrivateGitHub:
    def __init__(self, sentinel: Path):
        self.repo = "demo-owner/internal-project"
        self.main = "a" * 40
        self.candidate = "b" * 40
        self.control = "c" * 40
        self.parent = "d" * 40
        self.owner_id = 444
        self.pr_number = 101
        self.approval_issue = 102
        self.sentinel = sentinel
        self.untrusted_content = (
            "from pathlib import Path\n"
            f"Path({str(sentinel)!r}).write_text('untrusted ran')\n"
        ).encode()
        self.untrusted_sha = hashlib.sha1(b"blob " + str(len(self.untrusted_content)).encode() + b"\0" + self.untrusted_content).hexdigest()
        self.src_path = "tools/source/untrusted.py"
        self.before = {"README.md": ("100644", "e"*40)}
        self.after = dict(self.before, **{self.src_path: ("100644", self.untrusted_sha)})
        self.state = {"repository": self.repo, "controlBranch": "project-control-state", "stateVersion": 7}
        self.policy = {"repository": self.repo, "policyVersion": 1}
        self.scope = {
            "schemaVersion": 1, "authority": "CONTROL_SCOPE",
            "allowedComponents": [{"globs": ["tools/**", "config/governance/**"]}],
            "forbiddenGlobs": ["private-data/**", "restricted/**"],
        }
        self.auth = {
            "schemaVersion": 1, "authority": "TRUSTED_READONLY_PREEXECUTION_V1",
            "status": "APPROVED", "repository": self.repo,
            "mainSha": self.main, "candidateSha": self.candidate,
            "controlParentSha": self.parent, "controlStateVersion": 7,
            "prNumber": self.pr_number, "ownerApprovalCommentId": 1234,
            "approvedChangedBlobs": {self.src_path: {"mode": "100644", "blob": self.untrusted_sha}},
        }
        self.main_read_count = 0
        self.control_read_count = 0
        self.head_read_count = 0
        self._approval_comment()

    def _approval_comment(self):
        fields = {
            "MESSAGE_TYPE": "TRUSTED_READONLY_PREEXECUTION_V1",
            "STATUS": "APPROVED", "REPOSITORY": self.repo,
            "PR_NUMBER": str(self.pr_number), "MAIN_SHA": self.main,
            "CANDIDATE_SHA": self.candidate, "CONTROL_PARENT_SHA": self.parent,
            "CONTROL_STATE_VERSION": str(self.state["stateVersion"]),
            "APPROVED_CHANGED_BLOBS_SHA256": trust.manifest_hash(self.auth["approvedChangedBlobs"]),
            "EXECUTION_PERMISSION": "NONE", "ADOPTION_PERMISSION": "NONE",
        }
        self.comment = {
            "user": {"id": self.owner_id}, "author_association": "OWNER",
            "issue_url": f"https://api.github.com/repos/{self.repo}/issues/{self.approval_issue}",
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
            "body": "\n".join(f"{k}={v}" for k, v in fields.items()),
        }

    @staticmethod
    def make_tree(files, tree_sha):
        return {
            "sha": tree_sha, "truncated": False,
            "tree": [{"path": k, "type": "blob", "mode": m, "sha": h} for k, (m, h) in files.items()],
        }

    def __call__(self, path: str):
        pre = f"repos/{self.repo}"
        if path == pre:
            return {"full_name": self.repo, "owner": {"id": self.owner_id}}
        if path == pre + "/git/ref/heads/main":
            self.main_read_count += 1
            return {"object": {"sha": self.main}}
        if path == pre + "/git/ref/heads/project-control-state":
            self.control_read_count += 1
            return {"object": {"sha": self.control}}
        if path == pre + f"/pulls/{self.pr_number}":
            self.head_read_count += 1
            return {"state": "open", "draft": False,
                    "head": {"sha": self.candidate, "repo": {"full_name": self.repo}},
                    "base": {"sha": self.main, "ref": "main"}}
        if path == pre + f"/compare/{self.main}...{self.candidate}":
            return {"status": "ahead", "merge_base_commit": {"sha": self.main}}
        if path == pre + f"/git/commits/{self.control}":
            return {"parents": [{"sha": self.parent}]}
        if path == pre + f"/git/commits/{self.main}":
            return {"tree": {"sha": "1"*40}}
        if path == pre + f"/git/commits/{self.candidate}":
            return {"tree": {"sha": "2"*40}}
        if path == pre + "/git/trees/" + "1"*40 + "?recursive=1":
            return self.make_tree(self.before, "1"*40)
        if path == pre + "/git/trees/" + "2"*40 + "?recursive=1":
            return self.make_tree(self.after, "2"*40)
        if path == pre + "/issues/comments/1234":
            return copy.deepcopy(self.comment)
        values = {
            ("PROJECT_CURRENT_CONTROL.json", self.control): self.state,
            ("PROJECT_CONTROL_ROLE_POLICY.json", self.control): self.policy,
            ("config/governance/SIGNED_CANDIDATE_PREEXECUTION.v1.json", self.control): self.auth,
            ("config/governance/CONTROL_SCOPE_MANIFEST.v1.json", self.main): self.scope,
        }
        for (name, commit), value in values.items():
            if path == f"{pre}/contents/{name}?ref={commit}":
                return make_blob(value)
        raise AssertionError("unexpected fake endpoint: " + path)


class PublicTrustRootRealBehaviorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.sentinel = Path(temp.name) / "untrusted_marker.txt"
        self.gh = FakePrivateGitHub(self.sentinel)

    def verify(self):
        f = self.gh
        return trust.verify(
            f, repository=f.repo, pr_number=f.pr_number,
            main_sha=f.main, candidate_sha=f.candidate,
            control_sha=f.control, approval_issue_number=f.approval_issue,
        )

    def denied(self, code):
        with self.assertRaisesRegex(trust.Refusal, code):
            self.verify()
        self.assertFalse(self.sentinel.exists(), "candidate code ran before trust was established")

    def test_approved_candidate_is_read_only_not_code_execution(self):
        result = self.verify()
        self.assertEqual(result["status"], "VERIFIED_READ_ONLY")
        self.assertFalse(result["candidateExecutionAllowed"])
        self.assertFalse(result["adoptionAllowed"])
        self.assertFalse(self.sentinel.exists())

    def test_cannot_impute_protection_to_private_main(self):
        result = self.verify()
        self.assertTrue(result["mainProtectionNotAttested"])
        self.assertFalse(result["candidateExecutionAllowed"])

    def test_owner_impersonation_denied(self):
        self.gh.comment["user"]["id"] = 777
        self.denied("OWNER_APPROVAL_PROVENANCE_INVALID")

    def test_non_owner_association_denied(self):
        self.gh.comment["author_association"] = "CONTRIBUTOR"
        self.denied("OWNER_APPROVAL_PROVENANCE_INVALID")

    def test_approval_posted_on_wrong_issue_denied(self):
        self.gh.comment["issue_url"] = self.gh.comment["issue_url"].replace("/102", "/103")
        self.denied("OWNER_APPROVAL_PROVENANCE_INVALID")

    def test_edited_owner_comment_denied(self):
        self.gh.comment["updated_at"] = "2026-01-02T00:00:00Z"
        self.denied("OWNER_APPROVAL_PROVENANCE_INVALID")

    def test_duplicated_approval_field_denied(self):
        self.gh.comment["body"] += "\nSTATUS=APPROVED"
        self.denied("DUPLICATE_APPROVAL_FIELD")

    def test_unsigned_extra_python_denied(self):
        self.gh.after["tools/other.py"] = ("100644", "f" * 40)
        self.denied("CHANGED_FILE_SET_UNAPPROVED")

    def test_candidate_blob_changed_denied(self):
        self.gh.after[self.gh.src_path] = ("100644", "f" * 40)
        self.denied("SIGNED_MODE_OR_BLOB_MISMATCH")

    def test_symlink_candidate_denied_even_if_signed(self):
        self.gh.after[self.gh.src_path] = ("120000", self.gh.untrusted_sha)
        self.gh.auth["approvedChangedBlobs"][self.gh.src_path]["mode"] = "120000"
        self.gh._approval_comment()
        self.denied("SIGNED_MODE_OR_BLOB_MISMATCH")

    def test_submodule_candidate_denied_even_if_signed(self):
        self.gh.after[self.gh.src_path] = ("160000", self.gh.untrusted_sha)
        self.gh.auth["approvedChangedBlobs"][self.gh.src_path]["mode"] = "160000"
        self.gh._approval_comment()
        self.denied("SIGNED_MODE_OR_BLOB_MISMATCH")

    def test_forbidden_source_even_if_owner_signed_denied(self):
        self.gh.after["private-data/secret.txt"] = ("100644", "f" * 40)
        self.gh.auth["approvedChangedBlobs"]["private-data/secret.txt"] = {"mode": "100644", "blob": "f"*40}
        self.gh._approval_comment()
        self.denied("FILE_OUTSIDE_MAIN_CONTROL_SCOPE")

    def test_scope_widening_from_candidate_denied(self):
        # Changing the candidate copy of the policy is inert. Even when
        # signed, it cannot authorize a Product path forbidden by Main.
        target = "config/governance/CONTROL_SCOPE_MANIFEST.v1.json"
        product = "restricted/Unsafe.cs"
        self.gh.after[target] = ("100644", "f" * 40)
        self.gh.after[product] = ("100644", "f" * 40)
        self.gh.auth["approvedChangedBlobs"][target] = {"mode": "100644", "blob": "f" * 40}
        self.gh.auth["approvedChangedBlobs"][product] = {"mode": "100644", "blob": "f" * 40}
        self.gh._approval_comment()
        self.denied("FILE_OUTSIDE_MAIN_CONTROL_SCOPE")

    def test_truncated_github_tree_denied(self):
        original = self.gh.__call__
        class Tamper:
            def __call__(self, path):
                v = original(path)
                if "/git/trees/" in path:
                    v = dict(v, truncated=True)
                return v
        self.gh = TamperGH(self.gh, Tamper())
        self.denied("GIT_TREE_UNVERIFIED_OR_TRUNCATED")

    def test_candidate_not_descendant_of_main_denied(self):
        original = self.gh.__call__
        def tamper(path):
            if "/compare/" in path:
                return {"status": "diverged", "merge_base_commit": {"sha": "f"*40}}
            return original(path)
        self.gh = TamperGH(self.gh, tamper)
        self.denied("CANDIDATE_ANCESTRY_NOT_PROVEN")

    def test_stale_control_parent_denied(self):
        self.gh.auth["controlParentSha"] = "f" * 40
        self.denied("CONTROL_AUTHORIZATION_ABSENT_OR_STALE")

    def test_no_owner_approval_denied(self):
        self.gh.auth["ownerApprovalCommentId"] = None
        self.denied("CONTROL_AUTHORIZATION_METADATA_INVALID")

    def test_fake_approved_status_denied(self):
        self.gh.auth["status"] = "PENDING"
        self.denied("CONTROL_AUTHORIZATION_ABSENT_OR_STALE")

    def test_changed_manifest_digest_denied(self):
        self.gh.auth["approvedChangedBlobs"][self.gh.src_path]["blob"] = "f" * 40
        self.denied("OWNER_APPROVAL_BINDING_INVALID")

    def test_fake_owner_grants_execution_denied(self):
        self.gh.comment["body"] = self.gh.comment["body"].replace(
            "EXECUTION_PERMISSION=NONE", "EXECUTION_PERMISSION=YES")
        self.denied("OWNER_APPROVAL_BINDING_INVALID")

    def test_main_moved_denied(self):
        original = self.gh.__call__
        def tamper(path):
            if path.endswith("/git/ref/heads/main"):
                return {"object": {"sha": "f" * 40}}
            return original(path)
        self.gh = TamperGH(self.gh, tamper)
        self.denied("MAIN_MOVED")

    def test_control_moved_denied(self):
        original = self.gh.__call__
        def tamper(path):
            if path.endswith("/git/ref/heads/project-control-state"):
                return {"object": {"sha": "f" * 40}}
            return original(path)
        self.gh = TamperGH(self.gh, tamper)
        self.denied("CONTROL_MOVED")

    def test_main_toctou_after_verification_denied(self):
        original = self.gh.__call__
        counts = {"n": 0}
        def tamper(path):
            if path.endswith("/git/ref/heads/main"):
                counts["n"] += 1
                if counts["n"] >= 2:
                    return {"object": {"sha": "f" * 40}}
            return original(path)
        self.gh = TamperGH(self.gh, tamper)
        self.denied("SOURCE_EPOCH_MOVED_AFTER_ATTESTATION")

    def test_path_case_collision_denied(self):
        self.gh.after["TOOLS/source/untrusted.py"] = ("100644", "f" * 40)
        self.denied("COLLIDING_GIT_TREE_PATH")

    def test_tree_traversal_denied(self):
        self.gh.after["../escape.py"] = ("100644", "f" * 40)
        self.denied("UNSAFE_GIT_TREE_PATH")

    def test_bad_sha_denied_before_api_call(self):
        with self.assertRaisesRegex(trust.Refusal, "INVALID_SHA"):
            trust.verify(self.gh, repository=self.gh.repo, pr_number=101, main_sha="not-a-sha",
                         candidate_sha=self.gh.candidate, control_sha=self.gh.control,
                         approval_issue_number=102)
        self.assertFalse(self.sentinel.exists())

    def test_reader_never_invokes_candidate_process(self):
        with patch.object(subprocess, "run", side_effect=AssertionError("process execution forbidden")):
            self.assertEqual(self.verify()["status"], "VERIFIED_READ_ONLY")
        self.assertFalse(self.sentinel.exists())

    def test_wrong_event_cli_denied_without_access_token(self):
        with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "pull_request", "GH_TOKEN": ""}):
            with patch.object(trust, "Reader", side_effect=AssertionError("must not access network")):
                with patch("sys.argv", ["verify.py", "--repository", self.gh.repo,
                                        "--pr-number", "101", "--main-sha", self.gh.main,
                                        "--candidate-sha", self.gh.candidate,
                                        "--control-sha", self.gh.control,
                                        "--approval-issue-number", "102"]):
                    self.assertEqual(trust.main(), 2)
        self.assertFalse(self.sentinel.exists())


class TamperGH:
    """Proxy fake preserving signed caller identity while altering responses."""
    def __init__(self, actual: FakePrivateGitHub, replacement):
        self.__dict__.update(actual.__dict__)
        self._fn = replacement
    def __call__(self, path):
        return self._fn(path)


if __name__ == "__main__":
    unittest.main()
