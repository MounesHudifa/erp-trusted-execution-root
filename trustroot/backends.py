"""Backend admission predicates. Evidence must come from an independent broker.

These predicates never create authority, install software, or schedule a runner.
TCG is deliberately not a security fallback. WSL automount=false is insufficient.
"""
from dataclasses import dataclass


class BackendDenied(ValueError):
    pass


@dataclass(frozen=True)
class Evidence:
    backend: str
    accelerator: str
    live_host_proof: bool
    dedicated_identity: bool
    broker_write_protected: bool
    network_denied: bool
    host_files_denied: bool
    credentials_absent: bool
    disposable_verified: bool
    resource_limits_verified: bool
    permanent_runner_count: int
    registration_control_verified: bool
    wsl_namespace_confinement: bool = False


def require_backend(e: Evidence) -> None:
    if e.backend == 'qemu':
        if e.accelerator not in {'kvm', 'whpx'}:
            raise BackendDenied('QEMU_HARDWARE_ACCELERATOR_REQUIRED_NO_TCG')
    elif e.backend == 'wsl2':
        # Microsoft explicitly excludes WSL distributions as host security boundaries.
        # Namespace test success cannot override this production admission decision.
        raise BackendDenied('WSL2_NOT_A_WINDOWS_HOST_SECURITY_BOUNDARY')
    else:
        raise BackendDenied('UNKNOWN_BACKEND')
    for field in ('live_host_proof', 'dedicated_identity', 'broker_write_protected',
                  'network_denied', 'host_files_denied', 'credentials_absent',
                  'disposable_verified', 'resource_limits_verified',
                  'registration_control_verified'):
        if getattr(e, field) is not True:
            raise BackendDenied('UNPROVEN_' + field.upper())
    if type(e.permanent_runner_count) is not int or e.permanent_runner_count != 0:
        raise BackendDenied('PERMANENT_RUNNER_BYPASS_OPEN')


def qemu_probe_argv(executable, kernel, initrd, accelerator):
    if accelerator not in {'kvm', 'whpx'}:
        raise BackendDenied('QEMU_HARDWARE_ACCELERATOR_REQUIRED_NO_TCG')
    return [str(executable), '-no-user-config', '-nodefaults', '-machine', 'q35',
            '-accel', accelerator, '-m', '256', '-smp', '1', '-display', 'none',
            '-monitor', 'none', '-serial', 'stdio', '-nic', 'none', '-no-reboot',
            '-kernel', str(kernel), '-initrd', str(initrd),
            '-append', 'console=ttyS0 rdinit=/init panic=-1 quiet']
