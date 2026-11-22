from __future__ import annotations

from collections import defaultdict
from typing import Any

from win_diag.mcp_server.guards import (
    ReadOnlyCommandError,
    parse_powershell_json_list,
    run_readonly_powershell,
)


def collect_reliability_and_updates(
    *,
    days: int = 14,
    max_updates: int = 15,
) -> tuple[dict[str, Any], list[str]]:
    """Zbiera zdarzenia z Reliability Monitora (crashe, awarie aktualizacji) oraz ostatnie poprawki KB."""
    warnings: list[str] = []
    safe_days = max(1, min(int(days), 60))
    safe_updates = max(1, min(int(max_updates), 30))

    # 1. Reliability Monitor (odfiltrowujemy wyłącznie awarie aplikacji, systemu, sterowników i aktualizacji)
    ps_reliability = f"""
$cutoff = (Get-Date).AddDays(-{safe_days})
$records = Get-CimInstance Win32_ReliabilityRecords -ErrorAction SilentlyContinue |
    Where-Object {{ $_.TimeGenerated -and ($_.TimeGenerated -ge $cutoff) }} |
    Sort-Object TimeGenerated -Descending |
    Select-Object -First 150
if (-not $records) {{ exit 0 }}
$records | ForEach-Object {{
    $msg = if ($_.Message) {{ ($_.Message -replace '\\r?\\n', ' ').Trim() }} else {{ '' }}
    if ($msg.Length -gt 280) {{ $msg = $msg.Substring(0, 280) + '...' }}
    [PSCustomObject]@{{
        source = [string]$_.SourceName
        product = [string]$_.ProductName
        event_id = [int]$_.EventIdentifier
        time_utc = $_.TimeGenerated.ToUniversalTime().ToString('o')
        message = $msg
    }}
}} | ConvertTo-Json -Compress -Depth 2
"""

    # 2. Ostatnie zainstalowane poprawki Windows (KB)
    ps_updates = f"""
Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue |
    Sort-Object InstalledOn -Descending |
    Select-Object -First {safe_updates} |
    ForEach-Object {{
        $d = if ($_.InstalledOn) {{ $_.InstalledOn.ToString('yyyy-MM-dd') }} else {{ '' }}
        [PSCustomObject]@{{
            hotfix_id = [string]$_.HotFixID
            description = [string]$_.Description
            installed_on = $d
        }}
    }} | ConvertTo-Json -Compress -Depth 2
"""

    raw_records: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []

    try:
        raw_records = parse_powershell_json_list(run_readonly_powershell(ps_reliability, timeout=20))
    except ReadOnlyCommandError as exc:
        warnings.append(f"Nie udało się odczytać Win32_ReliabilityRecords: {exc}")

    try:
        updates = parse_powershell_json_list(run_readonly_powershell(ps_updates))
    except ReadOnlyCommandError as exc:
        warnings.append(f"Nie udało się odczytać Win32_QuickFixEngineering: {exc}")

    # Deduplikacja wpisów Reliability Monitora po (source, product, event_id)
    grouped: dict[tuple[str, str, int], dict[str, Any]] = defaultdict(dict)
    for rec in raw_records:
        source = str(rec.get("source") or "Unknown")
        product = str(rec.get("product") or "")
        ev_id = int(rec.get("event_id") or 0)
        ts = str(rec.get("time_utc") or "")
        msg = str(rec.get("message") or "")

        key = (source, product, ev_id)
        if not grouped[key]:
            grouped[key] = {
                "source": source,
                "product": product,
                "event_id": ev_id,
                "count": 1,
                "first_seen_utc": ts,
                "last_seen_utc": ts,
                "sample_message": msg,
            }
        else:
            entry = grouped[key]
            entry["count"] += 1
            if ts and (not entry["first_seen_utc"] or ts < entry["first_seen_utc"]):
                entry["first_seen_utc"] = ts
            if ts and ts > entry["last_seen_utc"]:
                entry["last_seen_utc"] = ts
                if msg:
                    entry["sample_message"] = msg

    sorted_reliability = sorted(
        grouped.values(),
        key=lambda item: (item["count"], item["last_seen_utc"]),
        reverse=True,
    )

    return {
        "window_days": safe_days,
        "reliability_records_scanned": len(raw_records),
        "reliability_groups": sorted_reliability[:25],
        "recent_kb_updates": updates,
    }, warnings