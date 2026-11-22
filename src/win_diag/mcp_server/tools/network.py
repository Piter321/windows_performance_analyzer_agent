from __future__ import annotations

from collections import Counter
from typing import Any

import psutil

from win_diag.mcp_server.guards import (
    ReadOnlyCommandError,
    parse_powershell_json_list,
    run_readonly_powershell,
)


def collect_network_diagnostics(*, include_connections: bool = True) -> tuple[dict[str, Any], list[str]]:
    """Zbiera stan interfejsów sieciowych, błędy pakietów, konfigurację DNS oraz podsumowanie połączeń."""
    warnings: list[str] = []

    stats = psutil.net_if_stats()
    io_counters = psutil.net_io_counters(pernic=True)
    addrs = psutil.net_if_addrs()

    interfaces: list[dict[str, Any]] = []
    for nic_name, nic_stat in stats.items():
        nic_io = io_counters.get(nic_name)
        ip_list: list[str] = []
        mac_addr: str | None = None
        for a in addrs.get(nic_name, []):
            fam_name = getattr(a.family, "name", str(a.family))
            if fam_name in ("AF_INET", "AF_INET6"):
                ip_list.append(a.address)
            elif fam_name == "AF_LINK":
                mac_addr = a.address

        # Pomijamy nieaktywne interfejsy bez żadnego ruchu i bez błędów
        has_traffic = bool(nic_io and (nic_io.bytes_sent > 0 or nic_io.bytes_recv > 0))
        if not nic_stat.isup and not has_traffic:
            continue

        interfaces.append(
            {
                "name": nic_name,
                "is_up": nic_stat.isup,
                "speed_mbps": nic_stat.speed,
                "mtu": nic_stat.mtu,
                "mac": mac_addr,
                "ips": ip_list[:4],
                "io": {
                    "sent_mb": round(nic_io.bytes_sent / (1024**2), 2),
                    "recv_mb": round(nic_io.bytes_recv / (1024**2), 2),
                    "err_in": nic_io.errin,
                    "err_out": nic_io.errout,
                    "drop_in": nic_io.dropin,
                    "drop_out": nic_io.dropout,
                }
                if nic_io
                else None,
            }
        )

    # Konfiguracja DNS i bramy domyślnej przez CIM (read-only)
    ps_dns = """
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" | ForEach-Object {
    [PSCustomObject]@{
        description = [string]$_.Description
        dhcp_enabled = [bool]$_.DHCPEnabled
        default_gateway = @($_.DefaultIPGateway)
        dns_servers = @($_.DNSServerSearchOrder)
    }
} | ConvertTo-Json -Compress -Depth 3
"""
    adapter_configs: list[dict[str, Any]] = []
    try:
        adapter_configs = parse_powershell_json_list(run_readonly_powershell(ps_dns))
    except ReadOnlyCommandError as exc:
        warnings.append(f"Nie udało się odczytać konfiguracji DNS/bramy z CIM: {exc}")

    connections_summary: dict[str, Any] = {}
    if include_connections:
        try:
            conns = psutil.net_connections(kind="inet")
            by_status = Counter(c.status for c in conns)
            by_pid = Counter(c.pid for c in conns if c.pid)

            top_pids: list[dict[str, Any]] = []
            for pid, count in by_pid.most_common(10):
                try:
                    pname = psutil.Process(pid).name()
                except Exception:
                    pname = "unknown"
                top_pids.append({"pid": pid, "name": pname, "connections": count})

            listening_ports: list[dict[str, Any]] = []
            for c in conns:
                if c.status == "LISTEN" and c.laddr:
                    listening_ports.append(
                        {
                            "pid": c.pid,
                            "ip": c.laddr.ip,
                            "port": c.laddr.port,
                        }
                    )

            connections_summary = {
                "total_inet_connections": len(conns),
                "by_status": dict(by_status),
                "top_processes_by_connections": top_pids,
                "listening_ports_sample": listening_ports[:25],
            }
        except psutil.AccessDenied:
            warnings.append("Brak uprawnień do pełnej listy połączeń sieciowych.")
        except Exception as exc:
            warnings.append(f"Błąd zbierania połączeń sieciowych: {exc}")

    return {
        "interfaces": interfaces,
        "ip_dns_configs": adapter_configs,
        "connections": connections_summary,
    }, warnings