from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ALLOWED_LOG_EXTENSIONS = frozenset({".log", ".txt", ".csv", ".json", ".xml", ".out", ".err"})


class PathJailError(ValueError):
    """Błąd próby dostępu poza dozwolony katalog external_logs lub do niedozwolonego pliku."""


class ReadOnlyCommandError(RuntimeError):
    """Błąd wykonania lokalnego polecenia diagnostycznego w trybie read-only."""


def get_max_output_chars() -> int:
    """Zwraca skonfigurowany limit znaków odpowiedzi pojedynczego narzędzia MCP."""
    try:
        return max(1000, int(os.environ.get("TOOL_OUTPUT_MAX_CHARS", "7000")))
    except ValueError:
        return 7000


def get_wmi_timeout() -> int:
    """Zwraca skonfigurowany timeout zapytań WMI/CIM/EventLog."""
    try:
        return max(3, int(os.environ.get("WMI_TIMEOUT_SECONDS", "15")))
    except ValueError:
        return 15


def resolve_jailed_path(
    base_dir: Path,
    relative_file: str,
    *,
    require_allowed_extension: bool = True,
) -> Path:
    """Waliduje i rozwiązuje ścieżkę pliku wyłącznie w obrębie dozwolonego katalogu (Path Jail)."""
    if not relative_file or not relative_file.strip():
        raise PathJailError("Nazwa pliku nie może być pusta.")
    if "\x00" in relative_file:
        raise PathJailError("Ścieżka zawiera niedozwolony znak NUL.")

    candidate_input = Path(relative_file.strip())
    if candidate_input.is_absolute():
        raise PathJailError("Ścieżki bezwzględne są zabronione — podaj ścieżkę względną.")

    base_resolved = base_dir.resolve()
    raw_target = base_resolved / candidate_input
    resolved_target = raw_target.resolve()

    if not resolved_target.is_relative_to(base_resolved):
        raise PathJailError("Wykryto próbę wyjścia poza dozwolony katalog (path traversal).")

    if resolved_target == base_resolved:
        raise PathJailError("Wskazana ścieżka jest katalogiem bazowym, a nie plikiem.")

    if require_allowed_extension:
        ext = resolved_target.suffix.lower()
        if ext not in ALLOWED_LOG_EXTENSIONS:
            allowed = ", ".join(sorted(ALLOWED_LOG_EXTENSIONS))
            raise PathJailError(
                f"Niedozwolone rozszerzenie '{ext or '(brak)'}'. Dozwolone: {allowed}"
            )

    return resolved_target


def run_readonly_powershell(script_body: str, timeout: int | None = None) -> str:
    """Uruchamia zahardkodowany skrypt odczytu PowerShell bez powłoki shell=True i z UTF-8.

    UWAGA BEZPIECZEŃSTWA: Ta funkcja NIGDY nie może przyjmować surowych ciągów od LLM.
    Wszystkie parametry wstawiane do `script_body` muszą być wcześniej zwalidowane
    przez Enum lub rzutowanie na int w kodzie narzędzia.
    """
    if sys.platform != "win32":
        raise ReadOnlyCommandError("Narzędzie wymaga systemu Windows.")

    effective_timeout = timeout or get_wmi_timeout()
    wrapped_script = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$ErrorActionPreference = 'Stop'; "
        f"{script_body}"
    )

    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                wrapped_script,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=effective_timeout,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReadOnlyCommandError(
            f"Przekroczono limit czasu ({effective_timeout}s) zapytania diagnostycznego."
        ) from exc
    except OSError as exc:
        raise ReadOnlyCommandError(f"Nie udało się uruchomić powershell.exe: {exc}") from exc

    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "").strip()
        raise ReadOnlyCommandError(err[:500] or f"PowerShell zakończył się kodem {completed.returncode}")

    return completed.stdout.strip()


def parse_powershell_json_list(raw_output: str) -> list[dict[str, Any]]:
    """Normalizuje wynik ConvertTo-Json z PowerShella (0, 1 lub N obiektów -> zawsze lista)."""
    cleaned = raw_output.strip()
    if not cleaned:
        return []
    parsed = json.loads(cleaned)
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    if isinstance(parsed, dict):
        return [parsed]
    return []


def build_tool_response(
    data: Any,
    *,
    status: str = "ok",
    warnings: list[str] | None = None,
    max_chars: int | None = None,
) -> str:
    """Pakuje wynik narzędzia w jednolity JSON i wymusza twardy limit rozmiaru (hard cap)."""
    budget = max_chars or get_max_output_chars()
    warn_list = list(warnings or [])

    envelope: dict[str, Any] = {
        "status": status,
        "collected_at": datetime.now(UTC).isoformat(),
        "truncated": False,
        "warnings": warn_list,
        "data": data,
    }

    serialized = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
    if len(serialized) <= budget:
        return serialized

    # Próba inteligentnego przycięcia list w słowniku data przed twardym obcięciem
    envelope["truncated"] = True
    warn_list.append(f"Odpowiedź została przycięta do limitu {budget} znaków.")
    envelope["warnings"] = warn_list

    if isinstance(data, dict):
        trimmed = dict(data)
        list_keys = sorted(
            [k for k, v in trimmed.items() if isinstance(v, list)],
            key=lambda k: len(trimmed[k]),
            reverse=True,
        )
        for _ in range(50):
            serialized = json.dumps(
                {**envelope, "data": trimmed}, ensure_ascii=False, separators=(",", ":")
            )
            if len(serialized) <= budget:
                return serialized
            changed = False
            for key in list_keys:
                if len(trimmed[key]) > 1:
                    new_len = max(1, int(len(trimmed[key]) * 0.7))
                    trimmed[key] = trimmed[key][:new_len]
                    changed = True
            if not changed:
                break

    # Fallback: twarde przycięcie podglądu danych wewnątrz poprawnego JSON-a
    preview_raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    shell_empty = json.dumps({**envelope, "data": {"preview": ""}}, ensure_ascii=False, separators=(",", ":"))
    available = max(100, budget - len(shell_empty) - 10)
    envelope["data"] = {"preview": preview_raw[:available]}
    return json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))