"""MDM (Mobile Device Management) enrollment detection.

Detects: Intune, JAMF, Workspace ONE, Kandji, Mosyle, Addigy,
and generic MDM enrollment indicators.

Hard gate: if MDM is detected, the machine is organizationally managed
and personal computer provisioning is rejected.
"""

import os
import platform
import subprocess


def detect_mdm() -> bool:
    """Returns True if MDM enrollment is detected."""
    system = platform.system()
    if system == "Darwin":
        return _detect_mdm_macos()
    elif system == "Windows":
        return _detect_mdm_windows()
    return False


def _detect_mdm_macos() -> bool:
    """Detect MDM enrollment on macOS."""

    # 1. profiles command — definitive MDM enrollment check
    try:
        result = subprocess.run(
            ["profiles", "status", "-type", "enrollment"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
        # "MDM enrollment: Yes" or similar indicates enrollment
        if "yes" in output.lower() and "mdm" in output.lower():
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 2. Configuration profiles directory
    mdm_profile_paths = [
        "/var/db/ConfigurationProfiles",
        "/var/db/ConfigurationProfiles/Settings",
    ]
    for path in mdm_profile_paths:
        if os.path.isdir(path):
            try:
                entries = os.listdir(path)
                # Empty dir is normal; populated means profiles are installed
                if len(entries) > 1:
                    return True
            except PermissionError:
                pass

    # 3. Known MDM agent paths
    mdm_agents = [
        "/Library/Application Support/JAMF",
        "/usr/local/jamf",
        "/Library/Intune",
        "/Library/Application Support/AirWatch",
        "/Library/Application Support/Kandji",
        "/Library/Application Support/Mosyle",
        "/Library/Addigy",
    ]
    for agent_path in mdm_agents:
        if os.path.exists(agent_path):
            return True

    # 4. MDM-related LaunchDaemons
    launch_daemon_dir = "/Library/LaunchDaemons"
    mdm_daemon_prefixes = [
        "com.jamf", "com.microsoft.intune", "com.airwatch",
        "com.kandji", "com.mosyle", "io.addigy",
        "com.apple.mdmclient",
    ]
    if os.path.isdir(launch_daemon_dir):
        try:
            for entry in os.listdir(launch_daemon_dir):
                entry_lower = entry.lower()
                if any(entry_lower.startswith(prefix) for prefix in mdm_daemon_prefixes):
                    return True
        except PermissionError:
            pass

    return False


def _detect_mdm_windows() -> bool:
    """Detect MDM enrollment on Windows."""

    # 1. dsregcmd — check specifically for MDM enrollment URL
    try:
        result = subprocess.run(
            ["dsregcmd", "/status"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout.lower()
        # MdmUrl with an actual value (not empty) = enrolled
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("mdmurl") and ":" in stripped:
                value = stripped.split(":", 1)[1].strip()
                if value and value != "none":
                    return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 2. Registry: actual MDM enrollment profiles with provider ID
    try:
        import winreg
        key_path = r"SOFTWARE\Microsoft\Enrollments"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            subkey_count = winreg.QueryInfoKey(key)[0]
            # Check each subkey for actual MDM provider data
            for i in range(subkey_count):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        try:
                            provider, _ = winreg.QueryValueEx(subkey, "ProviderId")
                            # Built-in Windows providers are NOT MDM
                            builtin = {"local authority", "deploy authority", "cloud authority"}
                            if provider and provider.strip().lower() not in builtin:
                                return True
                        except OSError:
                            pass
                except OSError:
                    pass
    except (ImportError, OSError):
        pass

    # 3. Known MDM agent services (specific to MDM, not generic Windows)
    mdm_services = [
        "IntuneManagementExtension",
        "AirWatchService",
    ]
    for service in mdm_services:
        try:
            result = subprocess.run(
                ["sc", "query", service],
                capture_output=True, text=True, timeout=5,
            )
            if "running" in result.stdout.lower():
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    return False
