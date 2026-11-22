from __future__ import annotations

from pathlib import Path

import pytest

from win_diag.mcp_server.guards import PathJailError
from win_diag.mcp_server.tools.external_logs import (
    collect_external_logs_inventory,
    search_external_log_file,
)


def test_external_log_deduplication_and_context(tmp_path: Path) -> None:
    """Powtarzające się błędy z innymi timestampami i GUID-ami powinny złożyć się w 1 wzorzec."""
    log_file = tmp_path / "app.log"
    lines = [
        "2026-11-22T10:00:00Z INFO Booting worker",
        "2026-11-22T10:00:01Z INFO Connecting to cache",
        "2026-11-22T10:00:02Z ERROR Connection timeout to shard 0x1A2B3C req=123e4567-e89b-12d3-a456-426614174000",
        "2026-11-22T10:00:03Z INFO Retrying connection",
        "2026-11-22T10:00:04Z INFO Backoff 500ms",
    ]
    # Dodajemy 200 powtórzeń tego samego błędu z różnymi datami i UUID
    for i in range(200):
        lines.append(
            f"2026-11-22T10:01:{i % 60:02d}Z ERROR Connection timeout to shard 0x{i + 100:X} "
            f"req=123e4567-e89b-12d3-a456-42661417{i:04d}"
        )
    lines.append("2026-11-22T10:05:00Z FATAL Out of memory allocating buffer 4096 --token=SuperSecret999")
    log_file.write_text("\n".join(lines), encoding="utf-8")

    inv, _ = collect_external_logs_inventory(base_dir=tmp_path)
    assert inv["files_count"] == 1
    assert inv["files"][0]["relative_path"] == "app.log"

    result, warnings = search_external_log_file(
        filename="app.log",
        min_severity="error",
        context_lines=2,
        base_dir=tmp_path,
    )

    assert not warnings
    assert result["stats"]["total_matches"] == 202
    assert result["stats"]["unique_patterns_total"] == 2

    # FATAL musi być pierwszy (wyższy priorytet niż ERROR) i mieć zamaskowany sekret
    first_pattern = result["patterns"][0]
    assert first_pattern["severity"] == "critical"
    assert first_pattern["count"] == 1
    assert "SuperSecret999" not in first_pattern["sample_line"]
    assert "[SECRET_REDACTED]" in first_pattern["sample_line"]

    # 201 identycznych błędów timeoutu złożone w 1 wzorzec z zachowanym kontekstem
    second_pattern = result["patterns"][1]
    assert second_pattern["severity"] == "error"
    assert second_pattern["count"] == 201
    assert len(second_pattern["context_before"]) == 2
    assert len(second_pattern["context_after"]) == 2


def test_external_log_blocks_path_traversal(tmp_path: Path) -> None:
    outside = tmp_path.parent / "secret_outside.log"
    outside.write_text("ERROR secret", encoding="utf-8")
    try:
        with pytest.raises(PathJailError):
            search_external_log_file(filename="../secret_outside.log", base_dir=tmp_path)
    finally:
        outside.unlink(missing_ok=True)


def test_external_log_performance_on_large_file(tmp_path: Path) -> None:
    """50 000 linii logu (ok. 4 MB) powinno przeskanować się strumieniowo i szybko."""
    big_log = tmp_path / "large_service.log"
    with big_log.open("w", encoding="utf-8") as fh:
        for i in range(50_000):
            if i % 1000 == 0:
                fh.write(f"2026-11-22T12:00:00Z ERROR Disk latency spike {i}ms on device 1\n")
            else:
                fh.write(f"2026-11-22T12:00:00Z INFO Heartbeat tick {i} ok\n")

    result, _ = search_external_log_file(
        filename="large_service.log",
        min_severity="error",
        base_dir=tmp_path,
    )

    assert result["stats"]["lines_scanned"] == 50_000
    assert result["stats"]["total_matches"] == 50
    assert result["stats"]["unique_patterns_total"] == 1
    assert result["stats"]["scan_duration_ms"] < 3000