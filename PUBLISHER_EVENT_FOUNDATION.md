# SEC-02 publisher event foundation: bounded adoption

This is a non-activating foundation in the existing SEC-02 program. No App key,
installation token, private repository content, publisher API call or candidate
checkout is included. Existing attestation and required CI workflows are unchanged.

## Exact runtime evidence

The new workflow handles pull_request, pull_request_target and workflow_dispatch.
There is no workflow_call entry point, inputs, or reusable caller secret interface.
GitHub automatically issues a restricted GITHUB_TOKEN even with permissions: {}.
The job setup permissions log, not an environment-variable check, establishes its
effective grants (the previous run showed Metadata: read). The inline test code
does not consume that token or request/use a privileged Publisher credential.
The environment-variable tripwire only detects listed variables if exported; it
cannot establish the absence of tokens or inherited secrets in GitHub contexts.

The first job emits a DENY diagnostic, never an independent attestation. On
pull_request, GitHub executes candidate-controlled workflow code: the candidate
can forge this output. No checkout does not mean no candidate code execution.
The receipt explicitly records candidate_workflow_executed=true for that event
and independent_attestation=false for every event. It is not an authority gate.
An independent reviewer must inspect the exact workflow SHA, job setup grants,
and GitHub server-side deployment rejection; candidate logs alone prove neither
non-use of a credential nor isolation. No Publisher key has been provisioned.
The second job deliberately requests the protected publisher environment only for
pull_request. GitHub must reject deployment before any step starts. Its failure
is expected evidence, NOT a green run or an ignored failing security test.

The pull_request_target event executes only the default-branch workflow. Therefore
a pre-merge PR cannot establish its live result. After protected adoption, a
synthetic PR event must demonstrate the refusal on that adopted SHA. Do not label
a skipped job, a local fixture or the pre-merge run as that proof.

## Reviewed current main paths

At base 31188e80894553c0c1cb8ac262863deca966e7bb:
- trust-root-ci.yml: public checkout/tests; no environment or secrets.
- trusted-attestation.yml: workflow_call, read-only permissions; no environment
  or secret-context references. A reusable caller can still use secrets: inherit
  without declarations; this workflow's code does not consume those secrets.
  This is a code-path observation, not proof that inheritance is impossible.
  It does not publish PRs or request Publisher credentials.

## Remaining security gate

Environment branch filtering does NOT independently reject pull_request_target on
main. This foundation keeps every publication request denied and deliberately
does not introduce an environment-consuming privileged publisher. It does not
prove the isolation of a future credential-bearing publisher.

Before credentials, the adopted publisher and its event/authority preflight,
all reusable-workflow entry points and actual environment denial tests (including
tags) must be reviewed and exercised. If a hostile main-context event can reach
the credential job, stop. Do not solve that by asserting main-only means trusted.

App creation/installation alone is not authentication proof or Product progress.
ERP Actions remain disabled; no ERP Main, Control, Product, old secret or runner
registration changes are part of this PR. Existing Product authorization is not
consumed. Required independent PR approval and trust-root-tests must pass; never
self-approve, bypass protection, or merge a wider support branch.

## Adoption and rollback

Only this foundation's listed files may be adopted through the protected PR.
No deployment or credential side effect occurs on merge. If the live denial test
fails, preserve evidence, keep credentials absent and propose a normal reviewed
revert PR. Never force-push or change protection.
