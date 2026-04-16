"""Hypervisor / virtual machine detection.

Detects: VMware, VirtualBox, Hyper-V, Parallels, QEMU/KVM,
and generic virtualization indicators.

Hard gate: virtual machines are rejected because they obscure the
true host environment. The FDA must scan the actual hardware the
personal computer will operate on.

IMPORTANT: Hyper-V enabled on the HOST (for Docker, WSL2, etc.) is
NOT a virtual machine. We only flag when running AS a guest VM.
"""

import os
import platform
import subprocess


def detect_hypervisor() -> bool:
    """Returns True if running inside a virtual machine."""
    system = platform.system()
    if system == "Darwin":
        return _detect_hypervisor_macos()
    elif system == "Windows":
        return _detect_hypervisor_windows()
    return False


def _detect_hypervisor_macos() -> bool:
    """Detect hypervisor on macOS."""

    # 1. sysctl kern.hv_vmm_present (hardware virtualization flag)
    try:
        result = subprocess.run(
            ["sysctl", "-n", "kern.hv_vmm_present"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout.strip() == "1":
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 2. Hardware model string
    try:
        result = subprocess.run(
            ["sysctl", "-n", "hw.model"],
            capture_output=True, text=True, timeout=5,
        )
        model = result.stdout.strip().lower()
        vm_models = ["vmware", "virtualbox", "parallels", "qemu"]
        if any(vm in model for vm in vm_models):
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 3. VMware/Parallels tools presence
    vm_paths = [
        "/Library/Application Support/VMware Tools",
        "/Library/Parallels Guest Tools",
        "/usr/local/bin/VBoxClient",
    ]
    for path in vm_paths:
        if os.path.exists(path):
            return True

    return False


def _detect_hypervisor_windows() -> bool:
    """Detect if running AS a virtual machine guest on Windows.

    Hyper-V running on the HOST (for Docker/WSL2) is NOT a VM.
    We check the hardware model and VM guest tools, not just
    whether Hyper-V is installed.
    """

    # 1. WMI model string — most reliable VM guest indicator
    try:
        result = subprocess.run(
            ["wmic", "computersystem", "get", "Model", "/value"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if line.strip().lower().startswith("model="):
                model = line.split("=", 1)[1].strip().lower()
                vm_models = ["vmware", "virtualbox", "virtual machine", "qemu", "kvm"]
                if any(vm in model for vm in vm_models):
                    return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 2. WMI manufacturer — "Microsoft Corporation" + "Virtual Machine" model = Hyper-V guest
    try:
        result = subprocess.run(
            ["wmic", "computersystem", "get", "Manufacturer", "/value"],
            capture_output=True, text=True, timeout=10,
        )
        manufacturer = ""
        for line in result.stdout.splitlines():
            if line.strip().lower().startswith("manufacturer="):
                manufacturer = line.split("=", 1)[1].strip().lower()
        # Known VM manufacturers (as guest)
        if manufacturer in ("vmware, inc.", "innotek gmbh", "qemu", "xen"):
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 3. VM guest tools installed
    try:
        import winreg
        vm_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Parallels\Parallels Tools"),
        ]
        for hive, key_path in vm_keys:
            try:
                with winreg.OpenKey(hive, key_path):
                    return True
            except OSError:
                pass
    except ImportError:
        pass

    # 4. VM guest services (NOT host services like vmicheartbeat)
    vm_guest_services = [
        "VMTools",       # VMware guest
        "VBoxService",   # VirtualBox guest
    ]
    for service in vm_guest_services:
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
