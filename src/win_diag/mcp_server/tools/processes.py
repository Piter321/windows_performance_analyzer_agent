from __future__ import annotations

import time
from datetime import UTC, datetime
from enum import Enum
from typing import Any

import psutil

from win_diag.privacy.sanitizer import redact_secrets


class ProcessSortField(str, Enum):
    CPU = "cpu"
    MEMORY = "memory"
    IO_READ = "io_read"
    IO_WRITE = "io_write"
    HANDLES = "handles"


def _safe_cmdline(proc: psutil.Process) -> str:
    try:
        parts = proc.cmdline()
        if not parts:
            return ""
        joined = " ".join(parts)
        cleaned = redact_secrets(joined)
        return cleaned[:260] + ("..." if len(cleaned) > 260 else "")
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return ""


def collect_top_processes(
    *,
    sort_by: str = "cpu",
    limit: int = 15,
) -> tuple[dict[str, Any], list[str]]:
    """Zwraca top N procesów wg wybranej metryki zasobów (Strict Read-Only)."""
    warnings: list[str] = []
    try:
        sort_field = ProcessSortField(sort_by.strip().lower())
    except ValueError as exc:
        allowed = ", ".join(m.value for m in ProcessSortField)
        raise ValueError(f"Nieprawidłowy sort_by '{sort_by}'. Dozwolone: {allowed}") from exc

    safe_limit = max(1, min(int(limit), 25))
    logical_cores = psutil.cpu_count(logical=True) or 1

    # Przebieg 1: inicjalizacja liczników CPU, aby drugi odczyt zwrócił realne zużycie
    procs: list[psutil.Process] = []
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
            procs.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    time.sleep(0.3)

    records: list[dict[str, Any]] = []
    access_denied_count = 0

    for proc in procs:
        try:
            with proc.oneshot():
                pid = proc.pid
                if pid == 0:  # System Idle Process zaburza ranking CPU
                    continue
                name = proc.name()
                raw_cpu = proc.cpu_percent(interval=None)
                cpu_norm = round(raw_cpu / logical_cores, 2)
                mem_info = proc.memory_info()
                rss_mb = round(mem_info.rss / (1024**2), 2)
                mem_pct = round(proc.memory_percent(), 2)
                status = proc.status()

                try:
                    io = proc.io_counters()
                    io_read_mb = round(io.read_bytes / (1024**2), 2)
                    io_write_mb = round(io.write_bytes / (1024**2), 2)
                except (psutil.AccessDenied, AttributeError, OSError):
                    io_read_mb = 0.0
                    io_write_mb = 0.0

                try:
                    handles = proc.num_handles()  # Windows-specific
                except (psutil.AccessDenied, AttributeError, OSError):
                    handles = 0

                records.append(
                    {
                        "pid": pid,
                        "ppid": proc.ppid(),
                        "name": name,
                        "status": status,
                        "cpu_percent_total": cpu_norm,
                        "memory_rss_mb": rss_mb,
                        "memory_percent": mem_pct,
                        "io_read_mb": io_read_mb,
                        "io_write_mb": io_write_mb,
                        "handles": handles,
                        "cmdline": _safe_cmdline(proc),
                    }
                )
        except psutil.AccessDenied:
            access_denied_count += 1
        except (psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            continue

    if access_denied_count:
        warnings.append(f"Brak pełnego dostępu do {access_denied_count} procesów chronionych.")

    key_map = {
        ProcessSortField.CPU: lambda r: r["cpu_percent_total"],
        ProcessSortField.MEMORY: lambda r: r["memory_rss_mb"],
        ProcessSortField.IO_READ: lambda r: r["io_read_mb"],
        ProcessSortField.IO_WRITE: lambda r: r["io_write_mb"],
        ProcessSortField.HANDLES: lambda r: r["handles"],
    }
    sorted_records = sorted(records, key=key_map[sort_field], reverse=True)

    return {
        "sort_by": sort_field.value,
        "logical_cores": logical_cores,
        "total_processes_inspected": len(records),
        "processes": sorted_records[:safe_limit],
    }, warnings


def collect_process_details(*, pid: int) -> tuple[dict[str, Any], list[str]]:
    """Zwraca szczegółowe informacje diagnostyczne o jednym procesie (PID)."""
    warnings: list[str] = []
    safe_pid = int(pid)
    if safe_pid <= 0:
        raise ValueError("Parametr pid musi być dodatnią liczbą całkowitą.")

    try:
        proc = psutil.Process(safe_pid)
    except psutil.NoSuchProcess as exc:
        raise ValueError(f"Proces o PID {safe_pid} już nie istnieje.") from exc

    details: dict[str, Any] = {"pid": safe_pid}

    def _try_read(label: str, fn: Any, default: Any = None) -> Any:
        try:
            return fn()
        except psutil.AccessDenied:
            warnings.append(f"AccessDenied przy odczycie pola '{label}' dla PID {safe_pid}.")
            return default
        except (psutil.NoSuchProcess, psutil.ZombieProcess, AttributeError, OSError) as exc:
            warnings.append(f"Nie udało się odczytać '{label}': {exc}")
            return default

    details["name"] = _try_read("name", proc.name)
    details["exe"] = _try_read("exe", proc.exe)
    details["cmdline"] = _safe_cmdline(proc)
    details["status"] = _try_read("status", proc.status)
    details["username"] = _try_read("username", proc.username)
    details["ppid"] = _try_read("ppid", proc.ppid)
    details["num_threads"] = _try_read("num_threads", proc.num_threads)
    details["num_handles"] = _try_read("num_handles", proc.num_handles)

    create_ts = _try_read("create_time", proc.create_time)
    if create_ts:
        details["created_utc"] = datetime.fromtimestamp(create_ts, tz=UTC).isoformat()

    mem = _try_read("memory_info", proc.memory_info)
    if mem:
        details["memory_rss_mb"] = round(mem.rss / (1024**2), 2)
        details["memory_vms_mb"] = round(mem.vms / (1024**2), 2)

    io = _try_read("io_counters", proc.io_counters)
    if io:
        details["io"] = {
            "read_mb": round(io.read_bytes / (1024**2), 2),
            "write_mb": round(io.write_bytes / (1024**2), 2),
            "read_count": io.read_count,
            "write_count": io.write_count,
        }

    # Powiązane usługi Windows (Strict Read-Only przez win_service_iter)
    related_services: list[dict[str, Any]] = []
    try:
        for svc in psutil.win_service_iter():
            try:
                if svc.pid() == safe_pid:
                    related_services.append(
                        {
                            "name": svc.name(),
                            "display_name": svc.display_name(),
                            "status": svc.status(),
                            "start_type": svc.start_type(),
                        }
                    )
            except Exception:
                continue
    except Exception:
        pass
    details["windows_services"] = related_services

    # Połączenia sieciowe procesu (limit 25)
    raw_conns = _try_read("net_connections", lambda: proc.net_connections(kind="inet"), default=[])
    conns_summary: list[dict[str, Any]] = []
    for c in (raw_conns or [])[:25]:
        conns_summary.append(
            {
                "status": c.status,
                "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
            }
        )
    details["network_connections_total"] = len(raw_conns or [])
    details["network_connections_sample"] = conns_summary

    return details, warnings