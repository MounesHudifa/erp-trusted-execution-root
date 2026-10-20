import copy
import unittest
from trustroot.hosted_trial import (PROFILE, TRIAL_BYTES, TRIAL_PATH,
    TrialDenied, review_definition, validate_profile, require_execution_integration)

class HostedTrialTests(unittest.TestCase):
    def test_exact_definition_is_review_only(self):
        result = review_definition(TRIAL_PATH, TRIAL_BYTES, copy.deepcopy(PROFILE))
        self.assertTrue(result['definitionReviewed'])
        self.assertFalse(result['executionAuthorized'])

    def test_all_profile_fields_fail_closed_on_mutation(self):
        for key, value in PROFILE.items():
            with self.subTest(field=key):
                p = copy.deepcopy(PROFILE)
                p[key] = not value if type(value) is bool else value + 1 if type(value) is int else value + '-changed'
                with self.assertRaises(TrialDenied): validate_profile(p)

    def test_number_boolean_confusion_rejected(self):
        for key, value in [('maxRuns',True),('maxAdditionalCostUSD',False),('executionEnabled',0)]:
            with self.subTest(field=key):
                p=copy.deepcopy(PROFILE);p[key]=value
                with self.assertRaises(TrialDenied): validate_profile(p)

    def test_extra_missing_keys_and_claimed_authority_rejected(self):
        for key in list(PROFILE):
            p=copy.deepcopy(PROFILE);del p[key]
            with self.assertRaises(TrialDenied): validate_profile(p)
        p=copy.deepcopy(PROFILE);p['status']='APPROVED'
        with self.assertRaises(TrialDenied): validate_profile(p)

    def test_all_out_of_scope_workflow_changes_rejected(self):
        mutations=[
            TRIAL_BYTES.replace(b'ubuntu-24.04', b'windows-2025'),
            TRIAL_BYTES.replace(b'ubuntu-24.04', b'self-hosted'),
            TRIAL_BYTES.replace(b'ubuntu-24.04', b'${{ inputs.runner }}'),
            TRIAL_BYTES.replace(b'timeout-minutes: 2', b'timeout-minutes: 3'),
            TRIAL_BYTES.replace(b'permissions: {}', b'permissions: write-all'),
            TRIAL_BYTES.replace(b'permissions: {}', b'permissions: {id-token: write}'),
            TRIAL_BYTES.replace(b'workflow_dispatch:', b'push:'),
            TRIAL_BYTES+b'\n# even extra content requires review\n',
            b'\xef\xbb\xbf'+TRIAL_BYTES,
            TRIAL_BYTES.replace(b'\n', b'\r\n'),
        ]
        for extra in [b'actions/checkout@v6',b'actions/upload-artifact@v6',b'actions/cache@v4',b'${{ secrets.TOKEN }}',b'curl https://example.invalid',b'git clone private',b'retry']:
            mutations.append(TRIAL_BYTES+b'      - run: '+extra+b'\n')
        for raw in mutations:
            with self.subTest(raw=raw):
                with self.assertRaises(TrialDenied): review_definition(TRIAL_PATH,raw,PROFILE)

    def test_copied_definition_cannot_authorize_another_path(self):
        for path in ['.github/workflows/other.yml',TRIAL_PATH.upper(),'../'+TRIAL_PATH]:
            with self.assertRaises(TrialDenied): review_definition(path,TRIAL_BYTES,PROFILE)

    def test_no_execution_or_single_use_claim_from_static_scan(self):
        for _ in range(2):
            with self.assertRaisesRegex(TrialDenied,'TRIAL_EXECUTION_NOT_ADOPTED'):
                require_execution_integration()

if __name__=='__main__': unittest.main()
