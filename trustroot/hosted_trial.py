"""Exact synthetic hosted-trial definition review. NOT dispatch authorization.

Generic security contract only: no target repository source, grants or identities.
A static policy approval cannot enforce one use. An independent dispatcher must
atomically reserve a verified governance grant before submission; absent that
integration execution remains disabled. This module never dispatches a job.
"""
from __future__ import annotations
import hashlib

TRIAL_PATH = '.github/workflows/sec02-private-hosted-canary.yml'
TRIAL_BYTES = b'''name: SEC02 Private Hosted Availability Canary
on:
  workflow_dispatch:
permissions: {}
jobs:
  availability:
    runs-on: ubuntu-24.04
    timeout-minutes: 2
    steps:
      - name: Synthetic availability only
        shell: bash
        run: |
          set -euo pipefail
          test "$RUNNER_ENVIRONMENT" = github-hosted
          test "$RUNNER_OS" = Linux
          printf 'PRIVATE_HOSTED_CANARY=PASS\\n'
          printf 'CANDIDATE_EXECUTED=NO\\n'
'''
TRIAL_SHA256 = hashlib.sha256(TRIAL_BYTES).hexdigest()
PROFILE = {
    'profileId': 'EXACT_PRIVATE_HOSTED_CANARY_V1',
    'workflowPath': TRIAL_PATH,
    'workflowSha256': TRIAL_SHA256,
    'runner': 'ubuntu-24.04',
    'maxRuns': 1,
    'timeoutMinutes': 2,
    'maxAdditionalCostUSD': 0,
    'privateRepositoryRequired': True,
    'checkoutAllowed': False,
    'secretsAllowed': False,
    'writePermissionsAllowed': False,
    'oidcAllowed': False,
    'artifactsAllowed': False,
    'cacheAllowed': False,
    'automaticRetryAllowed': False,
    'candidateCodeAllowed': False,
    'externalAtomicReservationRequired': True,
    'externalRunnerReachabilityProofRequired': True,
    'executionEnabled': False,
}

class TrialDenied(ValueError):
    pass


def validate_profile(profile: dict) -> None:
    # JSON equality alone would accept True == 1 and False == 0. Exact types
    # and keys matter for grant limits and fail-closed policy parsing.
    if not isinstance(profile, dict) or set(profile) != set(PROFILE):
        raise TrialDenied('TRIAL_PROFILE_KEYS_INVALID')
    for key, expected in PROFILE.items():
        value = profile[key]
        if type(value) is not type(expected) or value != expected:
            raise TrialDenied('TRIAL_PROFILE_VALUE_INVALID:' + key)


def review_definition(path: str, raw: bytes, profile: dict) -> dict:
    validate_profile(profile)
    if path != TRIAL_PATH or type(raw) is not bytes or raw != TRIAL_BYTES:
        raise TrialDenied('TRIAL_DEFINITION_NOT_EXACT')
    return {
        'definitionReviewed': True,
        'workflowSha256': TRIAL_SHA256,
        'executionAuthorized': False,
        'requiredNextGate': 'INDEPENDENT_GOVERNANCE_RESERVATION_AND_SAFE_ROUTING',
    }


def require_execution_integration() -> None:
    # Deliberately fail closed until the real governance source, atomic ledger
    # and platform routing barrier have been integrated and independently adopted.
    # No caller-provided APPROVED string or boolean can activate this candidate.
    raise TrialDenied('TRIAL_EXECUTION_NOT_ADOPTED')
