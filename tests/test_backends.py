from dataclasses import replace
import unittest
from trustroot.backends import BackendDenied, Evidence, require_backend, qemu_probe_argv


class BackendAdmissionTests(unittest.TestCase):
    def fixture(self, **changes):
        # Synthetic assertions only, never real deployment evidence or authority.
        e = Evidence('qemu', 'kvm', True, True, True, True, True, True,
                     True, True, 0, True)
        return replace(e, **changes)

    def test_synthetic_hardware_evidence_acceptance(self):
        for accelerator in ('kvm', 'whpx'):
            require_backend(self.fixture(accelerator=accelerator))

    def test_tcg_and_fallback_rejected(self):
        for accelerator in ('tcg', 'kvm:tcg', 'whpx:tcg', '', None):
            with self.assertRaises(BackendDenied):
                require_backend(self.fixture(accelerator=accelerator))
            with self.assertRaises(BackendDenied):
                qemu_probe_argv('qemu', 'kernel', 'initrd', accelerator)

    def test_each_missing_live_boundary_denies(self):
        for field in ('live_host_proof', 'dedicated_identity', 'broker_write_protected',
                      'network_denied', 'host_files_denied', 'credentials_absent',
                      'disposable_verified', 'resource_limits_verified',
                      'registration_control_verified'):
            with self.subTest(field=field), self.assertRaises(BackendDenied):
                require_backend(self.fixture(**{field: False}))

    def test_all_eight_permanent_runners_deny_individually(self):
        for count in range(1, 9):
            with self.subTest(count=count), self.assertRaises(BackendDenied):
                require_backend(self.fixture(permanent_runner_count=count))

    def test_runner_inventory_unknown_or_coerced_denies(self):
        for count in (None, '0', False, -1):
            with self.assertRaises(BackendDenied):
                require_backend(self.fixture(permanent_runner_count=count))

    def test_bare_wsl_config_is_not_confinement(self):
        with self.assertRaisesRegex(BackendDenied, 'WSL2_NOT_A_WINDOWS_HOST_SECURITY_BOUNDARY'):
            require_backend(self.fixture(backend='wsl2', accelerator='wsl2'))

    def test_namespace_success_cannot_authorize_wsl_host_boundary(self):
        with self.assertRaisesRegex(BackendDenied, 'WSL2_NOT_A_WINDOWS_HOST_SECURITY_BOUNDARY'):
            require_backend(self.fixture(backend='wsl2', accelerator='wsl2',
                                         wsl_namespace_confinement=True))

    def test_wsl1_fallback_denies(self):
        with self.assertRaises(BackendDenied):
            require_backend(self.fixture(backend='wsl2', accelerator='wsl1',
                                         wsl_namespace_confinement=True))

    def test_qemu_command_has_no_default_network_shares_or_monitor(self):
        args = qemu_probe_argv('qemu', 'kernel', 'initrd', 'whpx')
        for key in ('-monitor', '-display', '-nic'):
            self.assertEqual(args[args.index(key) + 1], 'none')
        for key in ('-virtfs', '-fsdev', '-netdev', '-qmp', '-drive', '-usb', '-spice'):
            self.assertNotIn(key, args)
