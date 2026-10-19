# Security policy

Do not submit internal repository names, identifiers, SHA manifests of proprietary files, tokens, Approval IDs, screenshots, or private logs here. Keep test fixtures generic.

A reused workflow is trusted **only at an exact reviewed public commit SHA** and after branch protection has been independently observed. The security root has no power to authorize executable CI or Product adoption; it is solely an attestation input to a separate, protected execution controller.

Threats in scope: malicious PR files, YAML/script substitution, unsigned extra changes, symlinks/submodules, stale branch identities, forged approval comments, candidate-controlled scope contracts, and TOCTOU changes.

Out of scope until separately remediated: privileged humans/bots with direct write to the private caller Main, permanent self-hosted runner state, privilege escalation in the private controller, deployment credentials, exfiltration via a legitimately privileged private job, and budget overruns.
