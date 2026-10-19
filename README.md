# Trusted Execution Root (public / generic)

A minimal, **read-only** GitHub Actions verification engine for a **separate, private caller repository**. No private repository content, names, keys, credentials, tokens, or project code belongs in this repository.

## Security boundaries

- Source: a **public, branch-protected** repository; a reusable workflow may be pinned to its exact commit SHA.
- Execution: GitHub-hosted ephemeral Linux; never runs a PR checkout, its scripts, dependency installers, tests or artifacts.
- Private source inspection: uses the caller's **read-only** `GITHUB_TOKEN` to fetch GitHub API metadata / Git trees and blob hashes, inside a private caller workflow run. No private data is uploaded to the public repository.
- Approval: independent Control branch authorization **AND** owner-authored approval comment must bind the same base, control parent, head SHA and canonical changed-file manifest digest. No self-approval, no privileged checkout.
- Outcome: `verified_readonly=true` is a statement about an immutable candidate's file integrity and approval provenance. It **NEVER grants execution, merge, deployment or Product adoption.**

## Limits

This repository does **not** enforce the caller's unprotected `main` or disable unsafe caller PR workflows. Even a protected security root cannot prevent a writer from changing an unprotected private caller workflow. The private caller must separately remove untrusted PR execution, restrict automation write privileges, and isolate code execution. The private caller's unprotected Main remains an explicit residual risk.

**Do not claim the private repository security boundary closed or autonomous product building restored** until the private caller and Windows/CI/Roslyn/E2E validation are independently proven.

## Activation

1. Create this as a standalone **public** GitHub repository (no private source).
2. Run public workflow `Trust Root Unit and Adversarial Tests`; require its job `trust-root-tests` as a status check and protect the `main` branch (including administrators / no bypass, prevent force push and deletion). Verify `GET /repos/{owner}/{repo}/branches/main` responds `protected: true`.
3. Pin the **published commit SHA** in the private caller's **Main-owned** workflow: `owner/security-repo/.github/workflows/trusted-attestation.yml@40_HEX_SHA`. Do not run the caller's candidate job before this gate; the caller workflow itself remains a distinct governance and security review boundary.
4. A private `pull_request_target` caller may use the reusable workflow only as read-only attestation (no candidate checkout). The independent owner approval and Control authorization must exist; no fake approvals.
5. Keep **untrusted unit/build CI** on an ephemeral GitHub-hosted runner with no secrets/credentials and within the account's free quota, or use a demonstrably ephemeral isolated self-hosted environment. Never run PR code on a persistent Windows runner by default.

## Test locally

`python3 -m unittest discover -s tests -v`

The verifier uses Python standard library only. Fake test data is intentionally unrelated to any real private repository.
