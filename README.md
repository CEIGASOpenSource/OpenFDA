# CeigasFDA — Forward Deployed Agent

**Open-source environment scanner for CEIGAS personal computer provisioning.**

CeigasFDA is a lightweight, read-only agent that scans a user's desktop environment before a [CEIGAS](https://github.com/CEIGASOpenSource)-governed personal computer is provisioned. It gathers environment intelligence so the entity can build an informed, scoped automation policy — and produces a cryptographic hash chain that prevents any tampering between scan and deployment.

## What It Does

1. **Scans** your desktop environment (OS, drives, resources, installed tools)
2. **Detects** managed/corporate environments and **hard-rejects** them (MDM, SAML/SSO, PIV/CAC, government banners, domain-joined machines)
3. **Generates** a structured report you can read before sending
4. **Signs** the report with HMAC-SHA256 attestation tied to your identity
5. **Produces** an environment hash that anchors the entire policy chain

## What It Does NOT Do

- Read file contents
- Access credentials, keychains, or browser data
- Scan your network
- Persist after the scan completes
- Send anything without your explicit approval
- Require elevated privileges (no sudo/admin)

## Security Model

CeigasFDA exists so you don't have to trust anyone's claims about security. Read the code.

### Hard Gates

These are structural rejections. No entity, no platform operator, no override can bypass them:

| Signal | What It Means |
|--------|--------------|
| MDM enrolled | Machine is managed by an organization (Intune, JAMF, Workspace ONE) |
| SAML/SSO agent | Enterprise identity provider detected (Okta, Azure AD) |
| PIV/CAC | Government smart card authentication present |
| GOV login banner | Government/military use notice detected |
| Domain joined | Machine belongs to an Active Directory or Azure AD domain |
| Hypervisor | Running inside a virtual machine |

If any hard gate triggers, CeigasFDA reports `REJECT` and no personal computer can be provisioned. The platform cannot override this.

### Hash Chain of Custody

```
FDA scan (ground truth on your machine)
    │
    ├── environment_hash = SHA256(scan_results)
    │
    ▼
Entity receives report + environment_hash
    │
    ├── Entity proposes scoped policy
    ├── You approve or narrow the scope
    │
    ├── policy_hash = SHA256(approved_policy + environment_hash)
    │
    ▼
CEIGAS mints personal computer with signed policy
    │
    ├── container_hash = SHA256(container_contents + policy_hash)
    │
    ▼
Personal computer connects to platform
    │
    ├── Platform verifies: container_hash → policy_hash → environment_hash
    │
    ▼
Chain intact? → CONNECT
Any link broken? → REJECT
```

Nobody in the loop can manipulate the policy — not the entity, not the platform, not an intermediary. The FDA's environment hash is the cryptographic anchor. If the personal computer doesn't match what your machine reported, it's rejected.

### SSH Elimination

CEIGAS personal computers do not use SSH. All communication flows through a governed tunnel where every action is policy-checked, auditable, and revocable. SSH would bypass the domain model entirely. CeigasFDA verifies the environment so the personal computer can operate through a governed channel instead of an ungoverned pipe.

## Supported Platforms

- **macOS** 12+ (Intel and Apple Silicon)
- **Windows** 10/11

Desktop only. Servers, mobile devices, and virtual machines are not supported.

## Usage

### From source (recommended for auditing)

```bash
git clone https://github.com/CEIGASOpenSource/CeigasFDA.git
cd CeigasFDA
python3 -m fda --challenge <nonce_from_platform>
```

### From binary

Download the latest release for your platform from [Releases](https://github.com/CEIGASOpenSource/CeigasFDA/releases).

```bash
# macOS
./ceigasfda --challenge <nonce_from_platform>

# Windows
ceigasfda.exe --challenge <nonce_from_platform>
```

The FDA will:
1. Run all gate checks
2. Scan your environment
3. Display the full report for your review
4. Ask for confirmation before sending anything

## Report Format

The FDA produces a JSON report. You see the full report before it's sent. Example:

```json
{
  "version": "1.5.0",
  "attestation": {
    "nonce": "platform-issued-challenge",
    "machine_id": "os-install-uuid",
    "timestamp": "2026-04-06T12:00:00Z",
    "environment_hash": "sha256:abc123...",
    "hmac": "sha256-hmac:def456..."
  },
  "hard_gates": {
    "mdm": false,
    "saml_sso": false,
    "piv_cac": false,
    "gov_banner": false,
    "domain_joined": false,
    "hypervisor": false,
    "verdict": "CLEAN"
  },
  "platform": {
    "os": "macOS 15.2",
    "arch": "arm64",
    "hostname": "users-macbook",
    "local_account": "username",
    "account_type": "admin"
  },
  "drives": [
    {"mount": "/", "filesystem": "apfs", "total_gb": 494, "free_gb": 187}
  ],
  "resources": {
    "cpu_cores": 10,
    "ram_gb": 32,
    "gpu": "Apple M2 Pro"
  },
  "user_profile": {
    "home": "/Users/username",
    "documents": true,
    "downloads": true,
    "desktop": true
  },
  "tools": {
    "git": "2.43.0",
    "python": "3.12.1",
    "node": "20.11.0",
    "docker": "24.0.7"
  }
}
```

## Project Structure

```
fda/
├── __main__.py          # Entry point and orchestrator
├── gates/
│   ├── __init__.py
│   ├── mdm.py           # MDM enrollment detection
│   ├── domain.py         # Domain join, SAML/SSO detection
│   ├── gov.py            # PIV/CAC, government login banners
│   └── hypervisor.py     # Virtual machine detection
├── scan/
│   ├── __init__.py
│   ├── account.py        # Local account verification
│   ├── drives.py         # Volume mapping, disk space
│   ├── resources.py      # CPU, RAM, GPU detection
│   ├── profile.py        # User directory structure
│   ├── tools.py          # Installed developer tools
│   └── ai_environment.py # AI/ML environment detection
├── attest/
│   ├── __init__.py
│   ├── machine_id.py     # OS install UUID extraction
│   └── hmac_sign.py      # HMAC-SHA256 report signing
└── report/
    ├── __init__.py
    ├── builder.py         # Assembles the JSON report
    └── display.py         # User-facing report display
```

## Contributing

CeigasFDA is the public security surface of the CEIGAS personal computer system. Contributions that improve detection accuracy, add platform support, or identify bypass vectors are welcome.

## License

Apache 2.0
