from __future__ import annotations

from collections import defaultdict
from enum import Enum
from typing import Any

from win_diag.mcp_server.guards import (
    ReadOnlyCommandError,
    parse_powershell_json_list,
    run_readonly_powershell,
)


class EventLogChannel(str, Enum):
    """Allowlista dzienników zdarzeń Windows dostępnych w trybie read-only."""

    SYSTEM = "System"
    APPLICATION = "Application"
    SECURITY = "Security"
    SETUP = "Setup"
    DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
    WHEA = "Microsoft-Windows-Kernel-WHEA/Operational"
    DIAGNOSTICS_PERFORMANCE = "Microsoft-Windows-Diagnostics-Performance/Operational"
    TASK_SCHEDULER = "Microsoft-Windows-TaskScheduler/Operational"
    WLAN_AUTOCONFIG = "Microsoft-Windows-WLAN-AutoConfig/Operational"


class EventLevelFilter(str, Enum):
    """Minimalny poziom ważności pobieranych zdarzeń."""

    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"


_LEVEL_MAP: dict[EventLevelFilter, str] = {
    EventLevelFilter.CRITICAL: "@(1)",
    EventLevelFilter.ERROR: "@(1,2)",
    EventLevelFilter.WARNING: "@(1,2,3)",
}

_LEVEL_NAME_MAP: dict[int, str] = {
    0: "Audit/Info",
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
}


def _resolve_channel(channel_name: str) -> EventLogChannel:
    """Waliduje nazwę dziennika względem allowlisty (obsługuje nazwę kanału i alias Enum)."""
    cleaned = channel_name.strip()
    for member in EventLogChannel:
        if cleaned.lower() in (member.value.lower(), member.name.lower()):
            return member
    allowed = ", ".join(m.value for m in EventLogChannel)
    raise ValueError(f"Niedozwolony dziennik '{channel_name}'. Dozwolone: {allowed}")


def _resolve_level(min_level: str) -> EventLevelFilter:
    try:
        return EventLevelFilter(min_level.strip().lower())
    except ValueError as exc:
        allowed = ", ".join(m.value for m in EventLevelFilter)
        raise ValueError(f"Niedozwolony poziom '{min_level}'. Dozwolone: {allowed}") from exc


def collect_event_log_summary(
    *,
    channel: str = "System",
    hours: int = 24,
    min_level: str = "error",
    max_groups: int = 25,
) -> tuple[dict[str, Any], list[str]]:
    """Pobiera i deterministycznie deduplikuje zdarzenia z dziennika Windows Event Log."""
    warnings: list[str] = []
    valid_channel = _resolve_channel(channel)
    valid_level = _resolve_level(min_level)
    safe_hours = max(1, min(int(hours), 168))
    safe_max_groups = max(1, min(int(max_groups), 40))

    # Dziennik Security używa głównie Audit Failure (Keywords = 0x10000000000000) zamiast Level 1-3
    if valid_channel == EventLogChannel.SECURITY:
        filter_expr = (
            f"@{{ LogName = '{valid_channel.value}'; "
            f"StartTime = (Get-Date).AddHours(-{safe_hours}); "
            "Keywords = 4503599627370496 }"
        )
        warnings.append("Dla dziennika Security zastosowano filtr Audit Failure.")
    else:
        levels_ps = _LEVEL_MAP[valid_level]
        filter_expr = (
            f"@{{ LogName = '{valid_channel.value}'; "
            f"StartTime = (Get-Date).AddHours(-{safe_hours}); "
            f"Level = {levels_ps} }}"
        )

    ps_script = f"""
$events = Get-WinEvent -FilterHashtable {filter_expr} -MaxEvents 1500 -ErrorAction SilentlyContinue
if (-not $events) {{ exit 0 }}
$events | ForEach-Object {{
    $msg = if ($_.Message) {{
        ($_.Message -replace '\\r?\\n', ' ').Trim()
    }} else {{ '' }}
    if ($msg.Length -gt 320) {{ $msg = $msg.Substring(0, 320) + '...' }}
    [PSCustomObject]@{{
        id = [int]$_.Id
        provider = [string]$_.ProviderName
        level = [int]$_.Level
        time_utc = $_.TimeCreated.ToUniversalTime().ToString('o')
        message = $msg
    }}
}} | ConvertTo-Json -Compress -Depth 2
"""

    try:
        raw_out = run_readonly_powershell(ps_script)
        events = parse_powershell_json_list(raw_out)
    except ReadOnlyCommandError as exc:
        warnings.append(f"Błąd odczytu dziennika {valid_channel.value}: {exc}")
        return {
            "channel": valid_channel.value,
            "hours": safe_hours,
            "min_level": valid_level.value,
            "total_events_scanned": 0,
            "unique_groups_total": 0,
            "groups": [],
        }, warnings

    # Programistyczna deduplikacja po (provider, event_id, level)
    grouped: dict[tuple[str, int, int], dict[str, Any]] = defaultdict(dict)
    for ev in events:
        provider = str(ev.get("provider") or "Unknown")
        ev_id = int(ev.get("id") or 0)
        level = int(ev.get("level") or 0)
        time_utc = str(ev.get("time_utc") or "")
        msg = str(ev.get("message") or "")

        key = (provider, ev_id, level)
        if not grouped[key]:
            grouped[key] = {
                "provider": provider,
                "event_id": ev_id,
                "level": level,
                "level_name": _LEVEL_NAME_MAP.get(level, str(level)),
                "count": 1,
                "first_seen_utc": time_utc,
                "last_seen_utc": time_utc,
                "sample_message": msg,
            }
        else:
            entry = grouped[key]
            entry["count"] += 1
            if time_utc and (not entry["first_seen_utc"] or time_utc < entry["first_seen_utc"]):
                entry["first_seen_utc"] = time_utc
            if time_utc and time_utc > entry["last_seen_utc"]:
                entry["last_seen_utc"] = time_utc
                if msg:
                    entry["sample_message"] = msg

    # Sortowanie: najpierw Critical (1) i Error (2), potem najwyższa liczba wystąpień
    def _sort_key(item: dict[str, Any]) -> tuple[int, int]:
        lvl = item["level"]
        severity_rank = lvl if lvl in (1, 2, 3) else 4
        return (severity_rank, -item["count"])

    sorted_groups = sorted(grouped.values(), key=_sort_key)

    return {
        "channel": valid_channel.value,
        "hours": safe_hours,
        "min_level": valid_level.value,
        "total_events_scanned": len(events),
        "unique_groups_total": len(sorted_groups),
        "groups": sorted_groups[:safe_max_groups],
    }, warnings


def collect_event_log_details(
    *,
    channel: str,
    event_id: int,
    hours: int = 72,
    limit: int = 5,
) -> tuple[dict[str, Any], list[str]]:
    """Zwraca pełniejsze szczegóły maksymalnie 5 ostatnich wystąpień konkretnego EventID."""
    warnings: list[str] = []
    valid_channel = _resolve_channel(channel)
    safe_event_id = int(event_id)
    if safe_event_id < 0 or safe_event_id > 65535:
        raise ValueError("Parametr event_id musi być liczbą całkowitą z zakresu 0..65535.")

    safe_hours = max(1, min(int(hours), 336))
    safe_limit = max(1, min(int(limit), 5))

    ps_script = f"""
$filter = @{{
    LogName = '{valid_channel.value}'
    Id = {safe_event_id}
    StartTime = (Get-Date).AddHours(-{safe_hours})
}}
$events = Get-WinEvent -FilterHashtable $filter -MaxEvents {safe_limit} -ErrorAction SilentlyContinue
if (-not $events) {{ exit 0 }}
$events | ForEach-Object {{
    $msg = if ($_.Message) {{ $_.Message.Trim() }} else {{ '' }}
    if ($msg.Length -gt 1200) {{ $msg = $msg.Substring(0, 1200) + '...' }}
    [PSCustomObject]@{{
        record_id = [long]$_.RecordId
        id = [int]$_.Id
        provider = [string]$_.ProviderName
        level = [int]$_.Level
        level_name = [string]$_.LevelDisplayName
        time_utc = $_.TimeCreated.ToUniversalTime().ToString('o')
        process_id = $_.ProcessId
        message = $msg
    }}
}} | ConvertTo-Json -Compress -Depth 2
"""

    try:
        raw_out = run_readonly_powershell(ps_script)
        events = parse_powershell_json_list(raw_out)
    except ReadOnlyCommandError as exc:
        warnings.append(f"Błąd pobierania szczegółów EventID {safe_event_id}: {exc}")
        events = []

    return {
        "channel": valid_channel.value,
        "event_id": safe_event_id,
        "hours": safe_hours,
        "returned_count": len(events),
        "events": events,
    }, warnings