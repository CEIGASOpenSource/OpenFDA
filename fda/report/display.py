"""User-facing report display.

Shows the FDA report in a readable format before the user
decides whether to send it. Full transparency — the user sees
exactly what will be transmitted.
"""

import json


def display_report(report: dict) -> str:
    """Format the report for terminal display."""
    lines = []
    lines.append("")
    lines.append("=" * 60)
    lines.append("  CeigasFDA — Personal Computer Report")
    lines.append("=" * 60)
    lines.append("")

    # Verdict
    verdict = report.get("hard_gates", {}).get("verdict", "UNKNOWN")
    if verdict == "REJECT":
        lines.append("  VERDICT: REJECT")
        lines.append("")
        lines.append("  This environment cannot host a personal computer.")
        lines.append("  Reason(s):")
        gates = report.get("hard_gates", {})
        for gate, triggered in gates.items():
            if gate == "verdict":
                continue
            if triggered:
                lines.append(f"    - {_gate_label(gate)}")
        lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)

    lines.append("  VERDICT: CLEAN")
    lines.append("")

    # Platform
    plat = report.get("platform", {})
    lines.append("  System")
    lines.append(f"    OS:       {plat.get('os', 'unknown')}")
    lines.append(f"    Arch:     {plat.get('arch', 'unknown')}")
    lines.append(f"    Hostname: {plat.get('hostname', 'unknown')}")
    lines.append(f"    Account:  {plat.get('local_account', 'unknown')} ({plat.get('account_type', 'standard')})")
    lines.append(f"    Source:   {plat.get('account_source', 'unknown')}")
    lines.append("")

    # Resources
    res = report.get("resources", {})
    lines.append("  Resources")
    cpu_display = res.get('cpu_model') or f"{res.get('cpu_cores', '?')} cores"
    lines.append(f"    CPU:  {cpu_display}")
    lines.append(f"    RAM:  {res.get('ram_gb', '?')} GB")
    lines.append(f"    GPU:  {res.get('gpu', 'unknown')}")
    lines.append("")

    # Drives
    drives = report.get("drives", [])
    if drives:
        lines.append("  Drives")
        for d in drives:
            lines.append(
                f"    {d['mount']:20s}  {d.get('filesystem', '?'):8s}  "
                f"{d.get('free_gb', '?'):>6} GB free / {d.get('total_gb', '?')} GB total  "
                f"({d.get('used_percent', '?')}% used)"
            )
        lines.append("")

    # User profile
    prof = report.get("user_profile", {})
    if prof:
        lines.append("  User Profile")
        lines.append(f"    Home: {prof.get('home', '?')}")
        dirs = []
        for d in ("documents", "downloads", "desktop", "pictures", "music", "movies", "videos"):
            if prof.get(d):
                dirs.append(d)
        if dirs:
            lines.append(f"    Directories: {', '.join(dirs)}")
        est = prof.get("estimated_files")
        if est is not None:
            lines.append(f"    Estimated files: ~{est:,}")
        lines.append("")

    # Tools
    tools = report.get("tools", {})
    if tools:
        lines.append("  Installed Tools")
        for name, version in sorted(tools.items()):
            if name == "editors":
                if version:
                    lines.append(f"    Editors: {', '.join(version)}")
            elif isinstance(version, bool):
                lines.append(f"    {name}: installed")
            else:
                lines.append(f"    {name}: {version}")
        lines.append("")

    # Attestation
    att = report.get("attestation", {})
    lines.append("  Attestation")
    lines.append(f"    Machine ID: {att.get('machine_id', '?')[:16]}...")
    lines.append(f"    Env Hash:   {att.get('environment_hash', '?')[:24]}...")
    lines.append(f"    Signed:     {'yes' if att.get('hmac') else 'no (preview mode)'}")
    lines.append(f"    Timestamp:  {att.get('timestamp', '?')}")
    lines.append("")

    # Hard gates (all clean)
    lines.append("  Security Gates (all clear)")
    gates = report.get("hard_gates", {})
    for gate, triggered in sorted(gates.items()):
        if gate == "verdict":
            continue
        status = "CLEAR" if not triggered else "TRIGGERED"
        lines.append(f"    {_gate_label(gate):30s} {status}")
    lines.append("")

    lines.append("=" * 60)
    lines.append("")
    lines.append("  This report will be sent to your entity for personal")
    lines.append("  computer provisioning. You can review the full JSON below.")
    lines.append("")

    # Full JSON (user can inspect everything)
    lines.append("-" * 60)
    lines.append(json.dumps(report, indent=2, default=str))
    lines.append("-" * 60)
    lines.append("")

    return "\n".join(lines)


def _gate_label(gate: str) -> str:
    """Human-readable label for a gate name."""
    labels = {
        "mdm": "MDM Enrollment (Intune/JAMF/etc.)",
        "saml_sso": "Enterprise SSO (Okta/AzureAD/etc.)",
        "piv_cac": "PIV/CAC Smart Card",
        "gov_banner": "Government Login Banner",
        "domain_joined": "Domain Joined (AD/AzureAD)",
        "hypervisor": "Virtual Machine",
    }
    return labels.get(gate, gate)
