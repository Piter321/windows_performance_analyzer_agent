from __future__ import annotations

import sys
from typing import Any

import psutil

from win_diag.mcp_server.guards import (
    ReadOnlyCommandError,
    parse_powershell_json_list,
    run_readonly_powershell,
)


def _read_startup_run_keys() -> tuple[list[dict[str, str]], list[str]]:
    """Odczytuje wpisy autostartu z kluczy Run (wyłącznie KEY_READ)."""
    entries: list[dict[str, str]] = []
    warnings: list[str] = []
    if sys.platform != "win32":
        return entries, warnings

    import winreg

    targets = [
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for hive_name, hive, subkey in targets:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                idx = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, idx)
                        entries.append(
                            {
                                "scope": hive_name,
                                "name": str(name),
                                "command": str(value)[:240],
                            }
                        )
                        idx += 1
                    except OSError:
                        break
        except OSError as exc:
            warnings.append(f"Nie udało się odczytać autostartu {hive_name}: {exc}")

    return entries, warnings


def collect_services_and_tasks() -> tuple[dict[str, Any], list[str]]:
    """Zbiera zatrzymane usługi automatyczne, błędy Harmonogramu Zadań oraz wpisy autostartu."""
    warnings: list[str] = []

    # 1. Usługi z StartMode=Auto, które aktualnie NIE działają (State != Running)
    ps_services = """
Get-CimInstance Win32_Service -Filter "StartMode = 'Auto' AND State <> 'Running'" |
    Select-Object -First 30 | ForEach-Object {
        [PSCustomObject]@{
            name = [string]$_.Name
            display_name = [string]$_.DisplayName
            state = [string]$_.State
            delayed_auto_start = [bool]$_.DelayedAutoStart
            exit_code = [int]$_.ExitCode
            service_specific_exit_code = [int]$_.ServiceSpecificExitCode
        }
    } | ConvertTo-Json -Compress -Depth 2
"""

    # 2. Harmonogram Zadań: zadania spoza \Microsoft\Windows\ oraz wszystkie z błędem LastTaskResult != 0
    ps_tasks = """
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' }
$results = foreach ($t in $tasks) {
    $isNonMs = -not $t.TaskPath.StartsWith('\Microsoft\Windows\')
    $info = $null
    try { $info = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue } catch {}
    $lastRes = if ($info) { [int64]$info.LastTaskResult } else { 0 }
    # Ignorujemy kody sukcesu/działania: 0, 267009 (running), 267011 (not yet run)
    $hasError = ($lastRes -ne 0) -and ($lastRes -ne 267009) -and ($lastRes -ne 267011)
    if ($isNonMs -or $hasError) {
        [PSCustomObject]@{
            task_path = [string]$t.TaskPath
            task_name = [string]$t.TaskName
            state = [string]$t.State
            last_run_utc = if ($info -and $info.LastRunTime -and $info.LastRunTime.Year -gt 2000) {
                $info.LastRunTime.ToUniversalTime().ToString('o')
            } else { $null }
            last_result = $lastRes
            missed_runs = if ($info) { [int]$info.NumberOfMissedRuns } else { 0 }
            has_error = $hasError
        }
    }
}
$results | Sort-Object @{Expression='has_error';Descending=$true}, last_run_utc -Descending |
    Select-Object -First 25 | ConvertTo-Json -Compress -Depth 2
"""

    stopped_auto_services: list[dict[str, Any]] = []
    scheduled_tasks: list[dict[str, Any]] = []

    try:
        stopped_auto_services = parse_powershell_json_list(run_readonly_powershell(ps_services))
    except ReadOnlyCommandError as exc:
        warnings.append(f"Błąd odczytu Win32_Service: {exc}")

    try:
        scheduled_tasks = parse_powershell_json_list(run_readonly_powershell(ps_tasks, timeout=20))
    except ReadOnlyCommandError as exc:
        warnings.append(f"Błąd odczytu Harmonogramu Zadań: {exc}")

    startup_entries, reg_warnings = _read_startup_run_keys()
    warnings.extend(reg_warnings)

    return {
        "stopped_automatic_services": stopped_auto_services,
        "notable_scheduled_tasks": scheduled_tasks,
        "startup_run_entries": startup_entries[:25],
    }, warnings


def collect_power_and_thermal() -> tuple[dict[str, Any], list[str]]:
    """Zbiera plan zasilania, ostatnie źródło wybudzenia, blokady uśpienia, baterię i czujniki ACPI."""
    warnings: list[str] = []

    ps_power = """
$scheme = (powercfg.exe /getactivescheme 2>&1) -join "`n"
$lastwake = (powercfg.exe /lastwake 2>&1) -join "`n"
$requests = (powercfg.exe /requests 2>&1) -join "`n"
[PSCustomObject]@{
    active_scheme = $scheme.Trim()
    last_wake = $lastwake.Trim()
    power_requests = $requests.Trim()
} | ConvertTo-Json -Compress -Depth 2
"""
    power_data: dict[str, Any] = {}
    try:
        parsed = parse_powershell_json_list(run_readonly_powershell(ps_power))
        if parsed:
            power_data = parsed[0]
            for k in ("active_scheme", "last_wake", "power_requests"):
                val = str(power_data.get(k) or "")
                if len(val) > 1200:
                    power_data[k] = val[:1200] + "..."
    except ReadOnlyCommandError as exc:
        warnings.append(f"Błąd odczytu powercfg (read-only): {exc}")

    # Bateria (laptop/UPS)
    battery_info: dict[str, Any] | None = None
    try:
        bat = psutil.sensors_battery()
        if bat:
            battery_info = {
                "percent": round(bat.percent, 1),
                "power_plugged": bat.power_plugged,
                "secs_left": bat.secsleft if bat.secsleft >= 0 else None,
            }
    except Exception:
        pass

    # Temperatury ze stref ACPI (część płyt desktopowych ich nie raportuje — degradacja bez błędu)
    ps_thermal = """
$zones = Get-CimInstance -Namespace root\\wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue
if (-not $zones) { exit 0 }
$zones | ForEach-Object {
    [PSCustomObject]@{
        instance = [string]$_.InstanceName
        temp_celsius = [math]::Round(($_.CurrentTemperature / 10.0) - 273.15, 1)
    }
} | ConvertTo-Json -Compress -Depth 2
"""
    thermal_zones: list[dict[str, Any]] = []
    try:
        thermal_zones = parse_powershell_json_list(run_readonly_powershell(ps_thermal))
    except ReadOnlyCommandError:
        warnings.append("Płyta główna/ACPI nie udostępnia stref termicznych przez WMI (normalne na części desktopów).")

    return {
        "powercfg": power_data,
        "battery": battery_info,
        "acpi_thermal_zones": thermal_zones,
    }, warnings