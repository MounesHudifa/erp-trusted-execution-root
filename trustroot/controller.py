"""Generic external-controller prototype. No installation or adoption authority.

Run only from an independently installed, OS-owned reviewed root, never from
a target checkout. Public CI uses synthetic data exclusively. Linux backend
is a namespace test backend, NOT a certified Windows production cutover.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from collections.abc import Callable, Mapping

from trustroot import verify as readonly

EXEC_PATH = "config/governance/ISOLATED_VALIDATION_AUTHORITY.v1.json"
EXEC_TAG = "TRUSTED_ISOLATED_VALIDATION_V1"


class Denied(ValueError):
    pass


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode()).hexdigest()


def blob_hash(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def require_no_registered_runners(api, repository: str) -> None:
    """All old registrations must be removed at separately approved cutover.

    Empty offline/busy flags or renamed labels are not adequate. This GET
    requires runner inventory permission; missing permission fails closed.
    This snapshot is necessary, not sufficient: OS isolation/ownership and
    prevention of re-registration also require external deployment proof.
    """
    data = api(f"repos/{readonly.repo_name(repository)}/actions/runners?per_page=100")
    if (type(data.get("total_count")) is not int or data["total_count"] != 0 or
            data.get("runners") != []):
        raise Denied("PRIVATE_RUNNER_SCHEDULING_BOUNDARY_OPEN")


@dataclass(frozen=True)
class Permit:
    repository: str
    main: str
    candidate: str
    control: str
    pr: int
    issue: int
    root_sha: str
    runtime_digest: str
    command: tuple[str, ...]
    tree: tuple[tuple[str, str], ...]
    approval_comment: int


def admit(api: Callable, *, repository: str, main: str, candidate: str,
          control: str, pr: int, issue: int, installed_root_sha: str,
          runtime_digest: str, command: tuple[str, ...]) -> Permit:
    """A read-only attestation NEVER becomes execution permission by itself."""
    installed_root_sha = readonly.sha(installed_root_sha, "ROOT")
    if (not isinstance(runtime_digest, str) or len(runtime_digest) != 64 or
            any(c not in "0123456789abcdef" for c in runtime_digest)):
        raise Denied("RUNTIME_DIGEST_INVALID")
    if (not isinstance(command, tuple) or not command or len(command) > 64 or
            any(not isinstance(a, str) or not a or "\0" in a for a in command) or
            not command[0].startswith("/")):
        raise Denied("TRUSTED_COMMAND_INVALID")
    repository = readonly.repo_name(repository)
    require_no_registered_runners(api, repository)
    result = readonly.verify(api, repository=repository, main_sha=main,
                             candidate_sha=candidate, control_sha=control,
                             pr_number=pr, approval_issue_number=issue)
    if (result.get("status") != "VERIFIED_READ_ONLY" or
            result.get("candidateExecutionAllowed") is not False):
        raise Denied("READONLY_ATTESTATION_NOT_VALID")
    prefix = f"repos/{repository}"
    auth, _ = readonly._jblob(api, prefix, EXEC_PATH, control)
    metadata = api(prefix)
    parents = api(f"{prefix}/git/commits/{control}").get("parents", [])
    if len(parents) != 1:
        raise Denied("EXEC_CONTROL_PARENT_AMBIGUOUS")
    expected = {
        "schemaVersion": 1, "authority": EXEC_TAG, "status": "APPROVED",
        "repository": repository, "mainSha": main, "candidateSha": candidate,
        "controlParentSha": parents[0].get("sha"), "prNumber": pr,
        "securityRootSha": installed_root_sha, "runtimeImageSha256": runtime_digest,
        "commandSha256": digest(list(command)), "network": "NONE",
        "hostMounts": "NONE", "credentials": "NONE", "adoptionPermission": "NONE",
    }
    if any(type(auth.get(k)) is not type(v) or auth.get(k) != v for k, v in expected.items()):
        raise Denied("EXECUTION_AUTHORITY_ABSENT_OR_MISMATCHED")
    comment_id = auth.get("ownerApprovalCommentId")
    if type(comment_id) is not int or comment_id <= 0:
        raise Denied("EXECUTION_OWNER_APPROVAL_ABSENT")
    comment = api(f"{prefix}/issues/comments/{comment_id}")
    if ((comment.get("user") or {}).get("id") != (metadata.get("owner") or {}).get("id") or
            comment.get("author_association") != "OWNER" or
            comment.get("issue_url") != f"https://api.github.com/{prefix}/issues/{issue}" or
            not comment.get("created_at") or comment.get("created_at") != comment.get("updated_at")):
        raise Denied("EXECUTION_OWNER_PROVENANCE_INVALID")
    fields = readonly.comment_fields(comment.get("body", ""))
    required = {"MESSAGE_TYPE": EXEC_TAG, "STATUS": "APPROVED",
                "EXECUTION_PERMISSION": "DISPOSABLE_ISOLATED_VALIDATION_ONLY",
                "ADOPTION_PERMISSION": "NONE", "AUTHORITY_SHA256": digest(expected)}
    if any(fields.get(k) != v for k, v in required.items()):
        raise Denied("EXECUTION_OWNER_BINDING_INVALID")
    tree = readonly._git_tree(api, prefix, candidate)
    if any(mode != "100644" for mode, _ in tree.values()) or len(tree) > 20000:
        raise Denied("CANDIDATE_TREE_MODE_OR_SIZE_INVALID")
    require_no_registered_runners(api, repository)
    if (api(prefix + "/git/ref/heads/main")["object"]["sha"] != main or
            api(prefix + "/git/ref/heads/project-control-state")["object"]["sha"] != control or
            api(f"{prefix}/pulls/{pr}")["head"]["sha"] != candidate):
        raise Denied("EXECUTION_EPOCH_MOVED")
    return Permit(repository, main, candidate, control, pr, issue, installed_root_sha,
                  runtime_digest, command, tuple(sorted((p, s) for p, (_, s) in tree.items())),
                  comment_id)


def read_candidate(api: Callable, permit: Permit) -> dict[str, bytes]:
    files = {}
    total = 0
    for path, expected in permit.tree:
        readonly.sha(expected, "BLOB")
        doc = api(f"repos/{permit.repository}/git/blobs/{expected}")
        if doc.get("encoding") != "base64":
            raise Denied("CANDIDATE_BLOB_ENCODING")
        data = base64.b64decode(doc.get("content", ""), validate=False)
        total += len(data)
        if doc.get("sha") != expected or blob_hash(data) != expected or total > 100_000_000:
            raise Denied("CANDIDATE_BLOB_MISMATCH_OR_LIMIT")
        files[path] = data
    return files


def runtime_hash(root: Path) -> str:
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise Denied("RUNTIME_ROOT_INVALID")
    entries = {}
    for item in sorted(root.rglob("*")):
        mode = item.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise Denied("RUNTIME_SPECIAL_FILE_REFUSED")
        if item.is_file():
            entries[str(item.relative_to(root))] = {
                "sha256": hashlib.sha256(item.read_bytes()).hexdigest(),
                "mode": stat.S_IMODE(mode),
            }
    if not entries:
        raise Denied("RUNTIME_EMPTY")
    return digest(entries)


def _limits():
    for kind, value in ((resource.RLIMIT_CPU, 10), (resource.RLIMIT_AS, 512*1024*1024),
                        (resource.RLIMIT_FSIZE, 1024*1024), (resource.RLIMIT_NOFILE, 64),
                        (resource.RLIMIT_NPROC, 64), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(kind, (value, value))


def isolated_probe(permit: Permit, source: Mapping[str, bytes], runtime: Path,
                   *, bwrap: str = "/usr/bin/bwrap", timeout: float = 15) -> dict:
    """Prototype backend; caller must independently admit immediately before use.

    Does not certify OS ownership, runner cutover, Windows support or deployment.
    No shell, network, host root, cache, control worktree or credential mounts.
    """
    if os.name != "posix" or not Path(bwrap).is_absolute() or not Path(bwrap).is_file():
        raise Denied("ISOLATION_BACKEND_UNAVAILABLE")
    if not 0 < timeout <= 120:
        raise Denied("TIMEOUT_INVALID")
    if runtime_hash(runtime) != permit.runtime_digest:
        raise Denied("RUNTIME_IDENTITY_DRIFT")
    if set(source) != {p for p, _ in permit.tree}:
        raise Denied("CANDIDATE_FILE_SET_DRIFT")
    for path, expected in permit.tree:
        if (not path or path.startswith("/") or "\\" in path or
                any(p in ("", ".", "..") for p in path.split("/")) or
                type(source[path]) is not bytes or blob_hash(source[path]) != expected):
            raise Denied("CANDIDATE_BYTES_OR_PATH_DRIFT")
    with tempfile.TemporaryDirectory(prefix="trustroot-disposable-") as temp:
        staging = Path(temp) / "source"
        staging.mkdir(mode=0o700)
        for path, data in source.items():
            target = staging / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o444)
        argv = [bwrap, "--unshare-all", "--die-with-parent", "--new-session",
                "--disable-userns", "--cap-drop", "ALL", "--clearenv",
                "--ro-bind", str(runtime), "/", "--proc", "/proc", "--dev", "/dev",
                "--tmpfs", "/tmp", "--tmpfs", "/work", "--ro-bind", str(staging), "/candidate",
                "--setenv", "HOME", "/work", "--setenv", "PATH", "/usr/bin",
                "--chdir", "/work", "--", *permit.command]
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=subprocess.STDOUT, env={}, close_fds=True,
                                       start_new_session=True, preexec_fn=_limits)
            expired = False
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                expired = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            output.seek(0)
            raw = output.read(1024*1024)
            if expired:
                raise Denied("ISOLATED_VALIDATION_TIMEOUT")
            if process.returncode != 0:
                raise Denied("ISOLATION_OR_CANDIDATE_FAILED:" + str(process.returncode))
            return {"status": "ISOLATED_PROBE_PASS", "output": raw,
                    "disposableWorkspace": str(staging), "adoptionAllowed": False}
