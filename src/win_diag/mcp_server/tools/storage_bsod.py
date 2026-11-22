from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from win_diag.mcp_server.guards import (
    ReadOnlyCommandError,
    parse_powershell_json_list,
    run_readonly_powershell,
)


def collect_storage_and_crash_summary(*, crash_days: int = 30) -> tuple[dict[str, Any], list[str]]:
    """Zbiera zdrowie dysków fizycznych (CIM/S.M.A.R.T.), metadane Minidump i zdarzenia BSOD/Kernel-Power."""
    warnings: list[str] = []
    safe_days = max(1, min(int(crash_days), 90))

    # 1. Dyski fizyczne + liczniki niezawodności (temperatura, błędy odczytu/zapisu, zużycie SSD)
    ps_disks = """
Get-PhysicalDisk | ForEach-Object {
    $disk = $_
    $rel = $null
    try { $rel = $disk | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue } catch {}
    [PSCustomObject]@{
        friendly_name = [string]$disk.FriendlyName
        media_type = [string]$disk.MediaType
        bus_type = [string]$disk.BusType
        health_status = [string]$disk.HealthStatus
        operational_status = [string]$disk.OperationalStatus
        size_gb = [math]::Round($disk.Size / 1GB, 1)
        temperature_c = if ($rel) { $rel.Temperature } else { $null }
        wear_percent = if ($rel) { $rel.Wear } else { $null }
        read_errors_uncorrected = if ($rel) { $rel.ReadErrorsUncorrected } else { $null }
        write_errors_uncorrected = if ($rel) { $rel.WriteErrorsUncorrected } else { $null }
        power_on_hours = if ($rel) { $rel.PowerOnHours } else { $null }
    }
} | ConvertTo-Json -Compress -Depth 2
"""
    disks: list[dict[str, Any]] = []
    try:
        disks = parse_powershell_json_list(run_readonly_powershell(ps_disks))
    except ReadOnlyCommandError as exc:
        warnings.append(f"Nie udało się odczytać Get-PhysicalDisk: {exc}")

    # 2. Metadane plików Minidump (tylko stat(), zero otwierania zawartości binarnej)
    win_dir = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    minidump_dir = win_dir / "Minidump"
    minidumps: list[dict[str, Any]] = []
    if minidump_dir.exists() and minidump_dir.is_dir():
        try:
            dmp_files = sorted(
                minidump_dir.glob("*.dmp"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for p in dmp_files[:15]:
                st = p.stat()
                minidumps.append(
                    {
                        "filename": p.name,
                        "size_kb": round(st.st_size / 1024, 1),
                        "modified_utc": datetime.fromtimestamp(st.st_mtime, tz=UTC).isoformat(),
                    }
                )
        except OSError as exc:
            warnings.append(f"Brak dostępu do katalogu Minidump: {exc}")

    # 3. Zdarzenia BSOD (BugCheck 1001), nagłych restartów (Kernel-Power 41) i błędów zrzutu (volmgr 161)
    ps_crashes = f"""
$filter = @{{
    LogName = 'System'
    Id = @(41, 1001, 161, 6008)
    StartTime = (Get-Date).AddDays(-{safe_days})
}}
$events = Get-WinEvent -FilterHashtable $filter -MaxEvents 25 -ErrorAction SilentlyContinue
if (-not $events) {{ exit 0 }}
$events | ForEach-Object {{
    $msg = if ($_.Message) {{ ($_.Message -replace '\\r?\\n', ' ').Trim() }} else {{ '' }}
    if ($msg.Length -gt 350) {{ $msg = $msg.Substring(0, 350) + '...' }}
    [PSCustomObject]@{{
        event_id = [int]$_.Id
        provider = [string]$_.ProviderName
        time_utc = $_.TimeCreated.ToUniversalTime().ToString('o')
        message = $msg
    }}
}} | ConvertTo-Json -Compress -Depth 2
"""
    crash_events: list[dict[str, Any]] = []
    try:
        crash_events = parse_powershell_json_list(run_readonly_powershell(ps_crashes))
    except ReadOnlyCommandError as exc:
        warnings.append(f"Błąd odczytu zdarzeń BSOD/Kernel-Power: {exc}")

    return {
        "physical_disks": disks,
        "minidump_directory_exists": minidump_dir.exists(),
        "minidumps_count": len(minidumps),
        "minidumps": minidumps,
        "crash_events_window_days": safe_days,
        "crash_events": crash_events,
    }, warnings