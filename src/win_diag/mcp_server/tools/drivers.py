from __future__ import annotations

from enum import Enum
from typing import Any

from win_diag.mcp_server.guards import (
    ReadOnlyCommandError,
    parse_powershell_json_list,
    run_readonly_powershell,
)


class DriverClassFilter(str, Enum):
    ALL_KEY = "all_key"
    DISPLAY = "display"
    NET = "net"
    DISK = "disk"
    MEDIA = "media"
    USB = "usb"
    BLUETOOTH = "bluetooth"
    SYSTEM = "system"


_CLASS_MAP: dict[DriverClassFilter, list[str]] = {
    DriverClassFilter.ALL_KEY: ["DISPLAY", "NET", "SCSIADAPTER", "DISKDRIVE", "MEDIA", "BLUETOOTH"],
    DriverClassFilter.DISPLAY: ["DISPLAY"],
    DriverClassFilter.NET: ["NET"],
    DriverClassFilter.DISK: ["DISKDRIVE", "SCSIADAPTER", "HDC"],
    DriverClassFilter.MEDIA: ["MEDIA", "AUDIOENDPOINT"],
    DriverClassFilter.USB: ["USB"],
    DriverClassFilter.BLUETOOTH: ["BLUETOOTH"],
    DriverClassFilter.SYSTEM: ["SYSTEM"],
}


def collect_drivers_and_devices(
    *,
    device_class: str = "all_key",
    limit: int = 30,
) -> tuple[dict[str, Any], list[str]]:
    """Zwraca urządzenia z błędami w Device Managerze oraz wersje i daty sterowników wybranej klasy."""
    warnings: list[str] = []
    try:
        selected_class = DriverClassFilter(device_class.strip().lower())
    except ValueError as exc:
        allowed = ", ".join(m.value for m in DriverClassFilter)
        raise ValueError(f"Nieprawidłowa klasa '{device_class}'. Dozwolone: {allowed}") from exc

    safe_limit = max(1, min(int(limit), 40))
    ps_classes = ",".join(f"'{c}'" for c in _CLASS_MAP[selected_class])

    # 1. Urządzenia z błędem (ConfigManagerErrorCode != 0)
    ps_problem_devices = """
Get-CimInstance Win32_PnPEntity -Filter "ConfigManagerErrorCode <> 0" | Select-Object -First 30 | ForEach-Object {
    [PSCustomObject]@{
        name = [string]$_.Name
        pnp_class = [string]$_.PNPClass
        manufacturer = [string]$_.Manufacturer
        status = [string]$_.Status
        error_code = [int]$_.ConfigManagerErrorCode
        device_id = [string]$_.PNPDeviceID
    }
} | ConvertTo-Json -Compress -Depth 2
"""

    # 2. Podpisane sterowniki dla wybranej klasy urządzeń
    ps_drivers = f"""
$targetClasses = @({ps_classes})
Get-CimInstance Win32_PnPSignedDriver |
    Where-Object {{ $_.DeviceClass -and ($targetClasses -contains $_.DeviceClass.ToUpper()) -and $_.DeviceName }} |
    Sort-Object DriverDate -Descending |
    Select-Object -First {safe_limit} |
    ForEach-Object {{
        $dDate = if ($_.DriverDate) {{ $_.DriverDate.ToString('yyyy-MM-dd') }} else {{ $null }}
        [PSCustomObject]@{{
            device_name = [string]$_.DeviceName
            device_class = [string]$_.DeviceClass
            provider = [string]$_.DriverProviderName
            version = [string]$_.DriverVersion
            driver_date = $dDate
            is_signed = [bool]$_.IsSigned
            inf_name = [string]$_.InfName
        }}
    }} | ConvertTo-Json -Compress -Depth 2
"""

    problem_devices: list[dict[str, Any]] = []
    drivers: list[dict[str, Any]] = []

    try:
        problem_devices = parse_powershell_json_list(run_readonly_powershell(ps_problem_devices))
    except ReadOnlyCommandError as exc:
        warnings.append(f"Błąd odczytu urządzeń z błędami (Win32_PnPEntity): {exc}")

    try:
        drivers = parse_powershell_json_list(run_readonly_powershell(ps_drivers))
    except ReadOnlyCommandError as exc:
        warnings.append(f"Błąd odczytu listy sterowników (Win32_PnPSignedDriver): {exc}")

    return {
        "device_class_filter": selected_class.value,
        "problem_devices_count": len(problem_devices),
        "problem_devices": problem_devices,
        "drivers_count": len(drivers),
        "drivers": drivers,
    }, warnings