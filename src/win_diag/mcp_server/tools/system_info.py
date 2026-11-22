from __future__ import annotations

import platform
import sys
import time
from datetime import UTC, datetime
from typing import Any

import psutil


def _read_windows_build_and_reboot() -> tuple[dict[str, Any], dict[str, bool], list[str]]:
    """Odczytuje dokładny build Windows oraz flagi oczekującego restartu (wyłącznie KEY_READ)."""
    os_extra: dict[str, Any] = {}
    reboot_flags = {
        "cbs_reboot_pending": False,
        "windows_update_reboot_required": False,
        "pending_file_rename_operations": False,
    }
    warnings: list[str] = []

    if sys.platform != "win32":
        return os_extra, reboot_flags, ["Pominięto odczyt rejestru (system inny niż Windows)."]

    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            0,
            winreg.KEY_READ,
        ) as key:
            for field in ("ProductName", "DisplayVersion", "CurrentBuild", "UBR"):
                try:
                    val, _ = winreg.QueryValueEx(key, field)
                    os_extra[field] = val
                except OSError:
                    pass
    except OSError as exc:
        warnings.append(f"Nie udało się odczytać CurrentVersion z rejestru: {exc}")

    # Sprawdzenie standardowych kluczy pending reboot (tylko KEY_READ)
    reboot_key_checks = [
        (
            "cbs_reboot_pending",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        ),
        (
            "windows_update_reboot_required",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        ),
    ]
    for flag_name, subkey in reboot_key_checks:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ):
                reboot_flags[flag_name] = True
        except FileNotFoundError:
            reboot_flags[flag_name] = False
        except OSError:
            pass

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            0,
            winreg.KEY_READ,
        ) as key:
            pending_ops, _ = winreg.QueryValueEx(key, "PendingFileRenameOperations")
            reboot_flags["pending_file_rename_operations"] = bool(pending_ops)
    except FileNotFoundError:
        reboot_flags["pending_file_rename_operations"] = False
    except OSError:
        pass

    return os_extra, reboot_flags, warnings


def collect_system_snapshot() -> tuple[dict[str, Any], list[str]]:
    """Zbiera kompaktowy obraz zasobów i stanu bazowego systemu Windows."""
    warnings: list[str] = []
    os_extra, reboot_flags, reg_warnings = _read_windows_build_and_reboot()
    warnings.extend(reg_warnings)

    boot_ts = psutil.boot_time()
    uptime_seconds = max(0, int(time.time() - boot_ts))

    # CPU
    cpu_percent = psutil.cpu_percent(interval=0.5)
    cpu_freq = psutil.cpu_freq()

    # RAM i Pagefile
    vmem = psutil.virtual_memory()
    smem = psutil.swap_memory()

    # Wolumeny dyskowe
    volumes: list[dict[str, Any]] = []
    for part in psutil.disk_partitions(all=False):
        if "cdrom" in part.opts.lower() or not part.fstype:
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
            free_gb = round(usage.free / (1024**3), 2)
            total_gb = round(usage.total / (1024**3), 2)
            volumes.append(
                {
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total_gb": total_gb,
                    "used_percent": usage.percent,
                    "free_gb": free_gb,
                    "low_space_warning": usage.percent >= 90.0 or free_gb < 10.0,
                }
            )
        except OSError as exc:
            warnings.append(f"Pominięto wolumen {part.mountpoint}: {exc}")

    snapshot = {
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            **os_extra,
        },
        "uptime": {
            "boot_time_utc": datetime.fromtimestamp(boot_ts, tz=UTC).isoformat(),
            "uptime_hours": round(uptime_seconds / 3600, 2),
        },
        "cpu": {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "usage_percent": cpu_percent,
            "current_mhz": round(cpu_freq.current, 1) if cpu_freq else None,
            "max_mhz": round(cpu_freq.max, 1) if cpu_freq else None,
        },
        "memory": {
            "ram_total_gb": round(vmem.total / (1024**3), 2),
            "ram_used_gb": round(vmem.used / (1024**3), 2),
            "ram_available_gb": round(vmem.available / (1024**3), 2),
            "ram_used_percent": vmem.percent,
            "pagefile_total_gb": round(smem.total / (1024**3), 2),
            "pagefile_used_gb": round(smem.used / (1024**3), 2),
            "pagefile_used_percent": smem.percent,
        },
        "volumes": volumes,
        "pending_reboot": {
            "any_pending": any(reboot_flags.values()),
            "details": reboot_flags,
        },
    }

    return snapshot, warnings