"""Report builder — assembles the final FDA report.

Combines gate results, scan data, and attestation into a single
signed JSON document ready for user review and personal computer
provisioning submission.
"""

import time

from fda import __version__
from fda.attest.machine_id import get_machine_id
from fda.attest.hmac_sign import compute_environment_hash, sign_report


def build_report(
    gates: dict,
    scan: dict,
    nonce: str,
    identity_key: str | None = None,
) -> dict:
    """Build the complete FDA report.

    Args:
        gates: Hard gate check results from gates.run_all_gates()
        scan: Environment scan results from scan.run_full_scan()
        nonce: Platform-issued challenge nonce
        identity_key: User's identity lock key for HMAC signing.
                      If None, report is unsigned (preview mode).

    Returns:
        Complete report dict ready for display and submission.
    """
    machine_id = get_machine_id()
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # The scan data that gets hashed — gates + scan combined
    hashable_data = {
        "hard_gates": gates,
        **scan,
    }
    environment_hash = compute_environment_hash(hashable_data)

    # HMAC signature (if identity key provided)
    hmac_signature = None
    if identity_key:
        hmac_signature = sign_report(nonce, machine_id, environment_hash, identity_key)

    report = {
        "version": __version__,
        "attestation": {
            "nonce": nonce,
            "machine_id": machine_id,
            "timestamp": timestamp,
            "environment_hash": environment_hash,
            "hmac": hmac_signature,
        },
        "hard_gates": gates,
        **scan,
    }

    return report


def report_to_json(report: dict, indent: int = 2) -> str:
    """Serialize report to JSON string for display or transmission."""
    import json
    return json.dumps(report, indent=indent, default=str)
