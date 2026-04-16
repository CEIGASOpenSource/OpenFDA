"""HMAC-SHA256 report signing and environment hash generation.

The attestation flow:
1. Platform issues a challenge nonce
2. FDA assembles the full scan report
3. environment_hash = SHA256(canonical scan JSON)
4. hmac = HMAC-SHA256(key=identity_lock_key, msg=nonce + machine_id + environment_hash)

The environment_hash is the cryptographic anchor for the entire
policy chain. If anyone modifies the scan results between FDA
and provisioning, the hash chain breaks and the personal computer
is rejected.
"""

import hashlib
import hmac
import json


def compute_environment_hash(scan_data: dict) -> str:
    """Compute SHA256 hash of the canonical scan results.

    This hash anchors the policy chain:
    environment_hash → policy_hash → container_hash

    Any tampering at any stage breaks the chain.
    """
    canonical = _canonicalize(scan_data)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def sign_report(
    nonce: str,
    machine_id: str,
    environment_hash: str,
    identity_key: str,
) -> str:
    """HMAC-SHA256 sign the attestation payload.

    Args:
        nonce: Challenge nonce from platform (prevents replay)
        machine_id: OS install UUID (binds to machine)
        environment_hash: SHA256 of scan results (binds to environment)
        identity_key: User's identity lock key (binds to user)

    Returns:
        HMAC signature as hex string
    """
    message = f"{nonce}|{machine_id}|{environment_hash}"
    signature = hmac.new(
        identity_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{signature}"


def verify_report(
    nonce: str,
    machine_id: str,
    environment_hash: str,
    identity_key: str,
    signature: str,
) -> bool:
    """Verify an HMAC-SHA256 signed report.

    Used server-side to verify the FDA report hasn't been tampered
    with and was produced by the claimed user on the claimed machine.
    """
    expected = sign_report(nonce, machine_id, environment_hash, identity_key)
    return hmac.compare_digest(expected, signature)


def _canonicalize(data: dict) -> str:
    """Produce a canonical JSON string for hashing.

    Sorted keys, no whitespace variation — ensures the same data
    always produces the same hash regardless of dict ordering or
    formatting differences.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
