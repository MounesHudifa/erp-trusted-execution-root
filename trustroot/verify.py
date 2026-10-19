"""Public-only, reusable read-only verifier. NEVER executes code from a target PR."""
from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

_SHA = re.compile(r"[a-f0-9]{40}\Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_AUTH_PATH = "config/governance/SIGNED_CANDIDATE_PREEXECUTION.v1.json"
_SCOPE_PATH = "config/governance/CONTROL_SCOPE_MANIFEST.v1.json"
_STATE_PATH = "PROJECT_CURRENT_CONTROL.json"
_POLICY_PATH = "PROJECT_CONTROL_ROLE_POLICY.json"
_TAG = "TRUSTED_READONLY_PREEXECUTION_V1"
_MAX_BLOB_SIZE = 3_000_000


class Refusal(ValueError):
    """Reject candidate without executing any of its files."""


def sha(value: str, field: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value.lower()):
        raise Refusal(field + "_INVALID_SHA")
    return value.lower()


def repo_name(value: str) -> str:
    if not isinstance(value, str) or not _REPO.fullmatch(value):
        raise Refusal("REPOSITORY_IDENTITY_INVALID")
    return value


class Reader:
    """GitHub REST read API only. Never uses subprocess, eval, or shell."""

    def __init__(self, token: str):
        if not isinstance(token, str) or not token:
            raise Refusal("READONLY_TOKEN_UNAVAILABLE")
        self._token = token

    def __call__(self, endpoint: str) -> dict:
        if not endpoint.startswith("repos/") or ".." in endpoint or "#" in endpoint:
            raise Refusal("UNSAFE_GITHUB_ENDPOINT")
        url = "https://api.github.com/" + endpoint
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self._token,
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "trusted-readonly-preexecution-root",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                if response.status != 200:
                    raise Refusal("GITHUB_READ_FAILED")
                raw = response.read(4_000_001)
        except (urllib.error.URLError, TimeoutError) as exc:
            raise Refusal("GITHUB_READ_FAILED") from exc
        if len(raw) > 4_000_000:
            raise Refusal("GITHUB_RESPONSE_TOO_LARGE")
        try:
            result = json.loads(raw)
        except ValueError as exc:
            raise Refusal("GITHUB_RESPONSE_NOT_JSON") from exc
        if not isinstance(result, dict):
            raise Refusal("GITHUB_RESPONSE_NOT_OBJECT")
        return result


def _jblob(api: Callable[[str], dict], prefix: str, path: str, commit: str) -> tuple[dict, str]:
    query = urllib.parse.quote(path, safe="/")
    result = api(f"{prefix}/contents/{query}?ref={commit}")
    if result.get("encoding") != "base64" or not isinstance(result.get("content"), str):
        raise Refusal("TRUSTED_SOURCE_NOT_BASE64")
    try:
        raw = base64.b64decode(result["content"], validate=False)
    except ValueError as exc:
        raise Refusal("TRUSTED_SOURCE_BAD_ENCODING") from exc
    if len(raw) > _MAX_BLOB_SIZE:
        raise Refusal("TRUSTED_SOURCE_TOO_LARGE")
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    if result.get("sha") != blob:
        raise Refusal("TRUSTED_SOURCE_HASH_DRIFT")
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeError) as exc:
        raise Refusal("TRUSTED_SOURCE_INVALID_JSON") from exc
    if not isinstance(doc, dict):
        raise Refusal("TRUSTED_SOURCE_NOT_OBJECT")
    return doc, blob


def _git_tree(api: Callable[[str], dict], prefix: str, commit_sha: str) -> dict[str, tuple[str, str]]:
    commit = api(f"{prefix}/git/commits/{commit_sha}")
    tree_sha = sha((commit.get("tree") or {}).get("sha", ""), "TREE")
    listing = api(f"{prefix}/git/trees/{tree_sha}?recursive=1")
    if listing.get("sha") != tree_sha or listing.get("truncated") is not False:
        raise Refusal("GIT_TREE_UNVERIFIED_OR_TRUNCATED")
    paths = {}
    folded = set()
    for item in listing.get("tree", []):
        if item.get("type") == "tree":
            continue
        path = item.get("path")
        if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or any(
            segment in ("", ".", "..") for segment in path.split("/")
        ):
            raise Refusal("UNSAFE_GIT_TREE_PATH")
        casefold = path.casefold()
        if path in paths or casefold in folded:
            raise Refusal("COLLIDING_GIT_TREE_PATH")
        folded.add(casefold)
        paths[path] = (item.get("mode"), item.get("sha"))
    return paths


def manifest_hash(changes: dict) -> str:
    raw = json.dumps(changes, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def comment_fields(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    if not isinstance(body, str) or len(body) > 16000:
        raise Refusal("APPROVAL_BODY_INVALID")
    for line in body.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key in fields:
                raise Refusal("DUPLICATE_APPROVAL_FIELD")
            fields[key] = value.strip()
    return fields


def verify(
    api: Callable[[str], dict], *, repository: str, pr_number: int,
    main_sha: str, candidate_sha: str, control_sha: str, approval_issue_number: int,
) -> dict:
    repository = repo_name(repository)
    main_sha = sha(main_sha, "MAIN")
    candidate_sha = sha(candidate_sha, "CANDIDATE")
    control_sha = sha(control_sha, "CONTROL")
    if not all(isinstance(n, int) and n > 0 for n in (pr_number, approval_issue_number)):
        raise Refusal("NUMBER_INVALID")
    if len({main_sha, candidate_sha, control_sha}) != 3:
        raise Refusal("SELF_AUTHORIZED_EPOCH")
    prefix = f"repos/{repository}"
    metadata = api(prefix)
    owner_id = (metadata.get("owner") or {}).get("id")
    if metadata.get("full_name") != repository or not isinstance(owner_id, int):
        raise Refusal("REPOSITORY_PROVENANCE_INVALID")
    if sha(api(prefix + "/git/ref/heads/main")["object"]["sha"], "MAIN") != main_sha:
        raise Refusal("MAIN_MOVED")
    live_control = sha(api(prefix + "/git/ref/heads/project-control-state")["object"]["sha"], "CONTROL")
    if live_control != control_sha:
        raise Refusal("CONTROL_MOVED")
    pr = api(f"{prefix}/pulls/{pr_number}")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (pr.get("state") != "open" or pr.get("draft") is True or
        head.get("sha") != candidate_sha or (head.get("repo") or {}).get("full_name") != repository or
        base.get("sha") != main_sha or base.get("ref") != "main"):
        raise Refusal("EXACT_SAME_REPOSITORY_PR_NOT_CONFIRMED")
    ancestry = api(f"{prefix}/compare/{main_sha}...{candidate_sha}")
    if ancestry.get("status") != "ahead" or (ancestry.get("merge_base_commit") or {}).get("sha") != main_sha:
        raise Refusal("CANDIDATE_ANCESTRY_NOT_PROVEN")
    state, _ = _jblob(api, prefix, _STATE_PATH, control_sha)
    policy, _ = _jblob(api, prefix, _POLICY_PATH, control_sha)
    if (state.get("repository") != repository or state.get("controlBranch") != "project-control-state" or
        not isinstance(state.get("stateVersion"), int) or policy.get("repository") != repository):
        raise Refusal("CONTROL_CONTRACT_INVALID")
    parent = api(f"{prefix}/git/commits/{control_sha}").get("parents") or []
    if len(parent) != 1:
        raise Refusal("CONTROL_PARENT_AMBIGUOUS")
    parent_sha = sha(parent[0].get("sha", ""), "CONTROL_PARENT")
    authorization, _ = _jblob(api, prefix, _AUTH_PATH, control_sha)
    if (authorization.get("schemaVersion") != 1 or authorization.get("authority") != _TAG or
        authorization.get("status") != "APPROVED" or authorization.get("repository") != repository or
        authorization.get("mainSha") != main_sha or authorization.get("candidateSha") != candidate_sha or
        authorization.get("controlParentSha") != parent_sha or
        authorization.get("controlStateVersion") != state["stateVersion"] or
        authorization.get("prNumber") != pr_number):
        raise Refusal("CONTROL_AUTHORIZATION_ABSENT_OR_STALE")
    comment_id = authorization.get("ownerApprovalCommentId")
    approved = authorization.get("approvedChangedBlobs")
    if (not isinstance(comment_id, int) or comment_id <= 0 or
        not isinstance(approved, dict) or not approved or len(approved) > 150):
        raise Refusal("CONTROL_AUTHORIZATION_METADATA_INVALID")
    comment = api(f"{prefix}/issues/comments/{comment_id}")
    if ((comment.get("user") or {}).get("id") != owner_id or
        comment.get("author_association") != "OWNER" or
        comment.get("issue_url") != f"https://api.github.com/{prefix}/issues/{approval_issue_number}" or
        comment.get("created_at") != comment.get("updated_at")):
        raise Refusal("OWNER_APPROVAL_PROVENANCE_INVALID")
    fields = comment_fields(comment.get("body") or "")
    required = {
        "MESSAGE_TYPE": _TAG, "STATUS": "APPROVED", "REPOSITORY": repository,
        "PR_NUMBER": str(pr_number), "MAIN_SHA": main_sha,
        "CANDIDATE_SHA": candidate_sha, "CONTROL_PARENT_SHA": parent_sha,
        "CONTROL_STATE_VERSION": str(state["stateVersion"]),
        "APPROVED_CHANGED_BLOBS_SHA256": manifest_hash(approved),
        "EXECUTION_PERMISSION": "NONE", "ADOPTION_PERMISSION": "NONE",
    }
    if any(fields.get(key) != value for key, value in required.items()):
        raise Refusal("OWNER_APPROVAL_BINDING_INVALID")
    scope, _ = _jblob(api, prefix, _SCOPE_PATH, main_sha)
    if scope.get("schemaVersion") != 1 or scope.get("authority") != "CONTROL_SCOPE":
        raise Refusal("MAIN_SCOPE_UNTRUSTED")
    allow_globs = [g for c in scope.get("allowedComponents", []) for g in c.get("globs", [])]
    denied_globs = scope.get("forbiddenGlobs", [])
    before, after = _git_tree(api, prefix, main_sha), _git_tree(api, prefix, candidate_sha)
    changed = {path for path in before.keys() | after.keys() if before.get(path) != after.get(path)}
    if not changed or changed != set(approved):
        raise Refusal("CHANGED_FILE_SET_UNAPPROVED")
    for path in sorted(changed):
        if (any(fnmatch.fnmatchcase(path, g) for g in denied_globs) or
            not any(fnmatch.fnmatchcase(path, g) for g in allow_globs)):
            raise Refusal("FILE_OUTSIDE_MAIN_CONTROL_SCOPE")
        signed = approved[path]
        if (not isinstance(signed, dict) or set(signed) != {"mode", "blob"} or
            signed["mode"] not in ("100644", "100755") or
            after.get(path) != (signed["mode"], signed["blob"])):
            raise Refusal("SIGNED_MODE_OR_BLOB_MISMATCH")
    # TOCTOU rejection: both protected evidence epochs and the PR must still match.
    if (api(prefix + "/git/ref/heads/main")["object"]["sha"] != main_sha or
        api(prefix + "/git/ref/heads/project-control-state")["object"]["sha"] != control_sha or
        (api(f"{prefix}/pulls/{pr_number}").get("head") or {}).get("sha") != candidate_sha):
        raise Refusal("SOURCE_EPOCH_MOVED_AFTER_ATTESTATION")
    return {"status": "VERIFIED_READ_ONLY", "files": len(changed),
            "candidateExecutionAllowed": False, "adoptionAllowed": False,
            "mainProtectionNotAttested": True}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", type=int, required=True)
    parser.add_argument("--main-sha", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--approval-issue-number", type=int, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request_target":
        print("TRUST_ROOT=REFUSED:WRONG_CALLER_EVENT", file=sys.stderr)
        return 2
    try:
        result = verify(Reader(os.environ.get("GH_TOKEN", "")), repository=args.repository,
                        pr_number=args.pr_number, main_sha=args.main_sha,
                        candidate_sha=args.candidate_sha, control_sha=args.control_sha,
                        approval_issue_number=args.approval_issue_number)
    except (Refusal, KeyError, TypeError, ValueError) as exc:
        print("TRUST_ROOT=REFUSED:" + type(exc).__name__, file=sys.stderr)
        return 2
    print("TRUST_ROOT=VERIFIED_READ_ONLY")
    print("EXECUTION_GRANTED=NO")
    print("ADOPTION_GRANTED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
