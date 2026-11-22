from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from win_diag.mcp_server.guards import PathJailError, build_tool_response
from win_diag.mcp_server.tools.drivers import collect_drivers_and_devices
from win_diag.mcp_server.tools.event_logs import (
    collect_event_log_details,
    collect_event_log_summary,
)
from win_diag.mcp_server.tools.external_logs import (
    collect_external_logs_inventory,
    search_external_log_file,
)
from win_diag.mcp_server.tools.network import collect_network_diagnostics
from win_diag.mcp_server.tools.processes import (
    collect_process_details,
    collect_top_processes,
)
from win_diag.mcp_server.tools.reliability_updates import collect_reliability_and_updates
from win_diag.mcp_server.tools.services_power import (
    collect_power_and_thermal,
    collect_services_and_tasks,
)
from win_diag.mcp_server.tools.storage_bsod import collect_storage_and_crash_summary
from win_diag.mcp_server.tools.system_info import collect_system_snapshot

mcp = MCPServer(
    name="win-diag-mcp",
    instructions=(
        "Serwer diagnostyczny Windows działający wyłącznie w trybie Strict Read-Only. "
        "Wszystkie narzędzia zwracają zdeduplikowany JSON z twardym limitem rozmiaru."
    ),
)


def _wrap(fn, *args, **kwargs) -> str:
    """Jednolita obsługa błędów i budowania odpowiedzi dla wszystkich narzędzi MCP."""
    try:
        data, warnings = fn(*args, **kwargs)
        status = "partial_access" if warnings else "ok"
        return build_tool_response(data, status=status, warnings=warnings)
    except (ValueError, PathJailError, FileNotFoundError) as exc:
        return build_tool_response({"error": str(exc)}, status="validation_error")
    except Exception as exc:
        return build_tool_response({"error": str(exc)}, status="error")


@mcp.tool()
def get_system_snapshot() -> str:
    """Zwraca szybki snapshot stanu systemu Windows: wersja/build OS, uptime, CPU, RAM, Pagefile, wolumeny i pending reboot."""
    return _wrap(collect_system_snapshot)


@mcp.tool()
def query_event_logs(
    channel: str = "System",
    hours: int = 24,
    min_level: str = "error",
    max_groups: int = 25,
) -> str:
    """Pobiera i deduplikuje zdarzenia z dziennika Windows Event Log po parze (Provider, EventID).

    Args:
        channel: Kanał z allowlisty (System, Application, Security, Setup, Defender, WHEA, Diagnostics_Performance, Task_Scheduler, WLAN_AutoConfig).
        hours: Okno czasowe wstecz w godzinach (1..168).
        min_level: Minimalny poziom: critical, error lub warning.
        max_groups: Maksymalna liczba unikalnych grup (1..40).
    """
    return _wrap(
        collect_event_log_summary,
        channel=channel,
        hours=hours,
        min_level=min_level,
        max_groups=max_groups,
    )


@mcp.tool()
def get_event_log_details(
    channel: str,
    event_id: int,
    hours: int = 72,
    limit: int = 5,
) -> str:
    """Pobiera szczegóły ostatnich wystąpień (maks. 5) konkretnego EventID ze wskazanego kanału Event Log."""
    return _wrap(
        collect_event_log_details,
        channel=channel,
        event_id=event_id,
        hours=hours,
        limit=limit,
    )


@mcp.tool()
def get_top_processes(sort_by: str = "cpu", limit: int = 15) -> str:
    """Zwraca ranking top N uruchomionych procesów wg metryki: cpu, memory, io_read, io_write lub handles."""
    return _wrap(collect_top_processes, sort_by=sort_by, limit=limit)


@mcp.tool()
def inspect_process_details(pid: int) -> str:
    """Zwraca szczegóły pojedynczego procesu (PID): ścieżkę exe, cmdline, powiązane usługi Windows, I/O i połączenia sieciowe."""
    return _wrap(collect_process_details, pid=pid)


@mcp.tool()
def get_network_diagnostics(include_connections: bool = True) -> str:
    """Zbiera status kart sieciowych, błędy/odrzucone pakiety, konfigurację DNS/bramy oraz podsumowanie połączeń TCP/UDP."""
    return _wrap(collect_network_diagnostics, include_connections=include_connections)


@mcp.tool()
def get_drivers_and_devices(device_class: str = "all_key", limit: int = 30) -> str:
    """Wykrywa urządzenia z błędami w Menedżerze Urządzeń oraz zwraca wersje/daty sterowników (all_key, display, net, disk, media, usb, bluetooth, system)."""
    return _wrap(collect_drivers_and_devices, device_class=device_class, limit=limit)


@mcp.tool()
def get_storage_and_crash_summary(crash_days: int = 30) -> str:
    """Zbiera stan zdrowia fizycznych dysków (S.M.A.R.T./CIM), metadane plików Minidump (BSOD) i zdarzenia BugCheck/Kernel-Power."""
    return _wrap(collect_storage_and_crash_summary, crash_days=crash_days)


@mcp.tool()
def get_reliability_and_updates(days: int = 14, max_updates: int = 15) -> str:
    """Zwraca zdeduplikowaną historię awarii z Windows Reliability Monitor oraz listę ostatnio zainstalowanych aktualizacji KB."""
    return _wrap(collect_reliability_and_updates, days=days, max_updates=max_updates)


@mcp.tool()
def get_services_and_tasks() -> str:
    """Wykrywa zatrzymane usługi automatyczne, zadania z błędami w Harmonogramie Zadań oraz wpisy autostartu (Run)."""
    return _wrap(collect_services_and_tasks)


@mcp.tool()
def get_power_and_thermal() -> str:
    """Zbiera aktywny plan zasilania, ostatnie źródło wybudzenia (powercfg /lastwake), blokady uśpienia (/requests), baterię i strefy ACPI."""
    return _wrap(collect_power_and_thermal)


@mcp.tool()
def list_external_logs() -> str:
    """Listuje pliki logów wrzucone przez użytkownika do katalogu workspace/external_logs/."""
    return _wrap(collect_external_logs_inventory)


@mcp.tool()
def search_external_log(
    filename: str,
    min_severity: str = "error",
    keywords: list[str] | None = None,
    regex_pattern: str | None = None,
    context_lines: int = 2,
    max_patterns: int = 20,
) -> str:
    """Programistycznie przeszukuje i deduplikuje log z workspace/external_logs/, zwracając wyłącznie wartościowe wzorce błędów z kontekstem.

    Args:
        filename: Względna ścieżka pliku z list_external_logs (Path Jail).
        min_severity: Poziom: critical, error, warning lub all.
        keywords: Opcjonalna lista słów kluczowych (OR).
        regex_pattern: Opcjonalny bezpieczny wzorzec regex (do 200 znaków).
        context_lines: Liczba linii kontekstu przed i po błędzie (0..3).
        max_patterns: Maksymalna liczba unikalnych wzorców w odpowiedzi (1..30).
    """
    return _wrap(
        search_external_log_file,
        filename=filename,
        min_severity=min_severity,
        keywords=keywords,
        regex_pattern=regex_pattern,
        context_lines=context_lines,
        max_patterns=max_patterns,
    )


def main() -> None:
    """Uruchamia serwer MCP w trybie transportu stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()