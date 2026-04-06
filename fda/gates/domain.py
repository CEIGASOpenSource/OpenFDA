"""Domain join and SAML/SSO detection.

Detects: Active Directory membership, Azure AD join,
enterprise SSO agents (Okta, Ping, OneLogin).

Hard gate: domain-joined machines are organizationally owned.
SAML/SSO presence indicates enterprise identity management.
"""

import os
import platform
import subprocess


def detect_domain_join() -> bool:
    """Returns True if machine is joined to any domain (AD, Azure AD)."""
    system = platform.system()
    if system == "Darwin":
        return _detect_domain_macos()
    elif system == "Windows":
        return _detect_domain_windows()
    return False


def detect_saml_sso() -> bool:
    """Returns True if enterprise SSO/SAML agents are detected."""
    system = platform.system()
    if system == "Darwin":
        return _detect_sso_macos()
    elif system == "Windows":
        return _detect_sso_windows()
    return False


# ── macOS ────────────────────────────────────────────────────

def _detect_domain_macos() -> bool:
    """Detect AD/directory binding on macOS."""

    # 1. dsconfigad — Active Directory binding
    try:
        result = subprocess.run(
            ["dsconfigad", "-show"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout.lower()
        # If AD is configured, output contains "Active Directory Domain"
        if "active directory" in output and "domain" in output:
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 2. dscl — check for network directory nodes
    try:
        result = subprocess.run(
            ["dscl", "-list", "/"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout
        # Network-bound directories beyond Local and Contact
        network_indicators = ["Active Directory", "LDAPv3"]
        for indicator in network_indicators:
            if indicator in output:
                return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return False


def _detect_sso_macos() -> bool:
    """Detect enterprise SSO agents on macOS."""

    # Known SSO agent application paths
    sso_paths = [
        "/Applications/Okta Verify.app",
        "/Library/Application Support/Okta",
        "/Applications/Ping Identity.app",
        "/Applications/OneLogin.app",
    ]
    for path in sso_paths:
        if os.path.exists(path):
            return True

    # Kerberos SSO extension (Apple Enterprise SSO)
    sso_extension_dir = "/Library/Managed Preferences"
    if os.path.isdir(sso_extension_dir):
        try:
            for entry in os.listdir(sso_extension_dir):
                if "sso" in entry.lower() or "kerberos" in entry.lower():
                    return True
        except PermissionError:
            pass

    # Platform SSO configuration
    try:
        result = subprocess.run(
            ["app-sso", "-l", "--json"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip() not in ("", "[]", "{}"):
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return False


# ── Windows ──────────────────────────────────────────────────

def _detect_domain_windows() -> bool:
    """Detect AD/Azure AD join on Windows."""

    # 1. dsregcmd — definitive domain join status
    try:
        result = subprocess.run(
            ["dsregcmd", "/status"],
            capture_output=True, text=True, timeout=10,
        )
        # Parse key-value pairs properly
        for line in result.stdout.splitlines():
            stripped = line.strip().lower().replace(" ", "")
            if stripped.startswith("domainjoined:") and "yes" in stripped:
                return True
            if stripped.startswith("azureadjoined:") and "yes" in stripped:
                # Azure AD joined — but check if it's a personal Microsoft account
                # vs actual org enrollment. Personal accounts show "AzureAdJoined: YES"
                # but TenantName will be empty or personal
                pass  # Fall through to tenant check below
            if stripped.startswith("enterprisejoined:") and "yes" in stripped:
                return True

        # If Azure AD joined, verify it's an org tenant not personal
        output_lower = result.stdout.lower()
        if "azureadjoined" in output_lower and "yes" in output_lower:
            for line in result.stdout.splitlines():
                stripped = line.strip().lower()
                if stripped.startswith("tenantname") and ":" in stripped:
                    tenant = stripped.split(":", 1)[1].strip()
                    # Personal Microsoft accounts won't have an org tenant
                    if tenant and tenant not in ("", "none"):
                        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 2. Environment variable check
    userdomain = os.environ.get("USERDOMAIN", "")
    computername = os.environ.get("COMPUTERNAME", "")
    # If USERDOMAIN differs from COMPUTERNAME, machine is domain-joined
    if userdomain and computername and userdomain.upper() != computername.upper():
        # Exclude "MicrosoftAccount" which shows up for personal MS accounts
        if userdomain.upper() != "MICROSOFTACCOUNT":
            return True

    return False


def _detect_sso_windows() -> bool:
    """Detect enterprise SSO agents on Windows."""

    # Known SSO agent installations (look for actual SSO product directories)
    sso_products = [
        "Okta", "Okta Verify",
        "OneLogin",
        "CyberArk Identity",
        "Ping Identity",
    ]
    program_dirs = [
        os.environ.get("PROGRAMFILES", r"C:\Program Files"),
        os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
    ]
    for prog_dir in program_dirs:
        if not prog_dir or not os.path.isdir(prog_dir):
            continue
        try:
            entries = os.listdir(prog_dir)
            for entry in entries:
                entry_lower = entry.lower()
                if any(sso.lower() == entry_lower for sso in sso_products):
                    return True
        except PermissionError:
            pass

    return False
