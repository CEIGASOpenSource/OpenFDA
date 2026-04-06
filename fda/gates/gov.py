"""Government/military environment detection.

Detects: PIV/CAC smart card infrastructure, government login banners,
.mil/.gov domain indicators.

Hard gate: government machines have strict security requirements that
preclude third-party automation agents.
"""

import os
import platform
import subprocess


def detect_piv_cac() -> bool:
    """Returns True if PIV/CAC smart card infrastructure is detected."""
    system = platform.system()
    if system == "Darwin":
        return _detect_piv_macos()
    elif system == "Windows":
        return _detect_piv_windows()
    return False


def detect_gov_banner() -> bool:
    """Returns True if government/military login banners are detected."""
    system = platform.system()
    if system == "Darwin":
        return _detect_gov_banner_macos()
    elif system == "Windows":
        return _detect_gov_banner_windows()
    return False


# ── macOS ────────────────────────────────────────────────────

def _detect_piv_macos() -> bool:
    """Detect PIV/CAC smart card services on macOS."""

    # 1. sc_auth paired identities (actual smart card pairing)
    try:
        result = subprocess.run(
            ["sc_auth", "list"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 2. PIV middleware (OpenSC, CACKey)
    piv_paths = [
        "/Library/OpenSC",
        "/Library/CACKey",
        "/usr/lib/pkcs11/cackey.dylib",
    ]
    for path in piv_paths:
        if os.path.exists(path):
            return True

    return False


def _detect_gov_banner_macos() -> bool:
    """Detect government login banners on macOS."""

    # Login window policy text
    banner_paths = [
        "/Library/Security/PolicyBanner.txt",
        "/Library/Security/PolicyBanner.rtf",
        "/Library/Security/PolicyBanner.rtfd",
    ]
    for path in banner_paths:
        if os.path.exists(path):
            try:
                if os.path.isfile(path):
                    with open(path, "r", errors="replace") as f:
                        content = f.read(4096).lower()
                    if _has_gov_keywords(content):
                        return True
                elif os.path.isdir(path):
                    return True
            except (PermissionError, OSError):
                pass

    return False


# ── Windows ──────────────────────────────────────────────────

def _detect_piv_windows() -> bool:
    """Detect PIV/CAC smart card infrastructure on Windows.

    Note: SCardSvr (smart card service) runs by default on most Windows
    installs and is NOT an indicator of PIV/CAC. We only flag actual
    PIV middleware or DoD certificate infrastructure.
    """

    # 1. PIV middleware (ActivClient, 90Meter, HID Global)
    piv_paths = [
        os.path.join(os.environ.get("PROGRAMFILES", ""), "ActivIdentity"),
        os.path.join(os.environ.get("PROGRAMFILES", ""), "HID Global", "ActivClient"),
        os.path.join(os.environ.get("PROGRAMFILES", ""), "90Meter"),
        os.path.join(os.environ.get("PROGRAMFILES", ""), "Charismathics"),
    ]
    for path in piv_paths:
        if path and os.path.isdir(path):
            return True

    # 2. DoD root certificates in machine store
    try:
        result = subprocess.run(
            ["certutil", "-store", "Root"],
            capture_output=True, text=True, timeout=10,
        )
        # Look for actual DoD certificate issuers, not substring matches
        for line in result.stdout.splitlines():
            line_lower = line.lower().strip()
            if "issuer:" in line_lower or "subject:" in line_lower:
                if "department of defense" in line_lower or "dod root ca" in line_lower:
                    return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return False


def _detect_gov_banner_windows() -> bool:
    """Detect government login banners on Windows."""

    # Registry: legal notice text shown at logon
    try:
        import winreg
        policy_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, policy_path) as key:
            try:
                caption, _ = winreg.QueryValueEx(key, "legalnoticecaption")
                if caption and _has_gov_keywords(caption.lower()):
                    return True
            except OSError:
                pass
            try:
                text, _ = winreg.QueryValueEx(key, "legalnoticetext")
                if text and _has_gov_keywords(text.lower()):
                    return True
            except OSError:
                pass
    except (ImportError, OSError):
        pass

    return False


# ── Shared ───────────────────────────────────────────────────

def _has_gov_keywords(text: str) -> bool:
    """Check text for government/military use notice keywords."""
    indicators = [
        "department of defense",
        "u.s. government",
        "united states government",
        "dod information system",
        "consent to monitoring",
        "you are accessing a u.s. government",
        "controlled unclassified",
        "for official use only",
        "federal computer",
    ]
    return any(indicator in text for indicator in indicators)
