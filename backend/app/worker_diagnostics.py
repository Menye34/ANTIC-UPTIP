"""Non-sensitive identities of loaded release policies; never dispatch authority."""
from . import service_start_preparation
from .dispatch_policy import authority as host_authority
from .nmap_service_profile import authority as service_authority


def diagnostics():
    def identity(policy):
        return {key: policy[key] for key in ('id', 'version', 'digest')}

    result = {
        'schema_version': 1,
        'worker_version': 'execution-worker-dispatch-diagnostics-v1',
        'service_scheduling_current_version': service_start_preparation.VERSION,
    }
    try:
        result.update(
            service_scheduling_policies=[identity(service_start_preparation.policy(version))
                for version in service_start_preparation.SUPPORTED_VERSIONS],
            dispatch_policies=[identity(host_authority()), identity(service_authority())],
            policy_diagnostics_available=True,
        )
    except (ValueError, KeyError, TypeError):
        # Diagnostics must not prevent a fail-closed denial from being audited.
        # Never echo exception/input strings or imply invalid policy is approved.
        result.update(service_scheduling_policies=[], dispatch_policies=[], policy_diagnostics_available=False)
    return result
