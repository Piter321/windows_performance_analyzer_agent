from __future__ import annotations

import hashlib
import os
import re
import time
from collections import deque
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from win_diag.mcp_server.guards import ALLOWED_LOG_EXTENSIONS, resolve_jailed_path
from win_diag.privacy.sanitizer import redact_secrets


class LogSeverityFilter(str, Enum):
    ALL = "all"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


_SEVERITY_PATTERNS: dict[LogSeverityFilter, re.Pattern[str]] = {
    LogSeverityFilter.CRITICAL: re.compile(
        r"(?i)\b(FATAL|CRITICAL|CRIT|PANIC|BUGCHECK|BSOD|UNHANDLED|SEGFAULT|OUT\s+OF\s+MEMORY|OOM)\b"
    ),
    LogSeverityFilter.ERROR: re.compile(
        r"(?i)\b(FATAL|CRITICAL|CRIT|PANIC|ERROR|ERR|EXCEPTION|TRACEBACK|FAILED|FAIL|CRASH|TIMEOUT|TIMED\s+OUT|DENIED|REFUSED|CORRUPT)\b"
    ),
    LogSeverityFilter.WARNING: re.compile(
        r"(?i)\b(FATAL|CRITICAL|CRIT|PANIC|ERROR|ERR|EXCEPTION|TRACEBACK|FAILED|FAIL|CRASH|TIMEOUT|DENIED|WARN|WARNING|RETRY|THROTTL|SLOW|DEGRADED)\b"
    ),
    LogSeverityFilter.ALL: re.compile(r".+"),
}

_SEVERITY_RANK_PATTERNS: list[tuple[int, str, re.Pattern[str]]] = [
    (1, "critical", _SEVERITY_PATTERNS[LogSeverityFilter.CRITICAL]),
    (2, "error", _SEVERITY_PATTERNS[LogSeverityFilter.ERROR]),
    (3, "warning", _SEVERITY_PATTERNS[LogSeverityFilter.WARNING]),
]

# Wzorce do normalizacji sygnatury błędu (usuwają zmienne liczby/daty/UUID dla skutecznej deduplikacji)
_NORM_TIMESTAMP_RE = re.compile(
    r"\b\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
    r"|\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"
)
_NORM_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_NORM_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
_NORM_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NORM_NUM_RE = re.compile(r"(?<![A-Za-z_])\d+(?:\.\d+)?")
_NORM_SPACES_RE = re.compile(r"\s+")


def get_external_logs_dir() -> Path:
    """Zwraca katalog dropzone na logi zewnętrzne."""
    return Path(os.environ.get("EXTERNAL_LOGS_DIR", "workspace/external_logs"))


def _normalize_signature(line: str) -> str:
    """Tworzy znormalizowaną sygnaturę komunikatu błędu do grupowania duplikatów."""
    s = _NORM_TIMESTAMP_RE.sub("<TS>", line)
    s = _NORM_UUID_RE.sub("<UUID>", s)
    s = _NORM_HEX_RE.sub("<HEX>", s)
    s = _NORM_IP_RE.sub("<IP>", s)
    s = _NORM_NUM_RE.sub("<N>", s)
    s = _NORM_SPACES_RE.sub(" ", s).strip().lower()
    return s[:220]


def _classify_severity(line: str) -> tuple[int, str]:
    for rank, name, pat in _SEVERITY_RANK_PATTERNS:
        if pat.search(line):
            return rank, name
    return 4, "info"


def _estimate_lines(path: Path, size_bytes: int) -> int:
    if size_bytes == 0:
        return 0
    try:
        # Dla mniejszych plików liczymy dokładnie strumieniowo; dla dużych estymujemy z próbki 64 KB
        if size_bytes <= 5 * 1024 * 1024:
            with path.open("rb") as fh:
                return sum(chunk.count(b"\n") for chunk in iter(lambda: fh.read(65536), b"")) + 1
        with path.open("rb") as fh:
            sample = fh.read(65536)
        newlines = sample.count(b"\n")
        if newlines == 0:
            return 1
        return max(1, int(size_bytes / (len(sample) / newlines)))
    except OSError:
        return 0


def collect_external_logs_inventory(base_dir: Path | None = None) -> tuple[dict[str, Any], list[str]]:
    """Zwraca inwentarz plików logów wrzuconych przez użytkownika do katalogu dropzone."""
    warnings: list[str] = []
    dropzone = (base_dir or get_external_logs_dir()).resolve()
    dropzone.mkdir(parents=True, exist_ok=True)

    files: list[dict[str, Any]] = []
    for path in sorted(dropzone.rglob("*")):
        if not path.is_file():
            continue
        if path.name.startswith("."):
            continue
        # Weryfikacja, czy symlink nie wyprowadza poza dropzone
        try:
            resolved = path.resolve()
            if not resolved.is_relative_to(dropzone):
                warnings.append(f"Pominięto plik spoza katalogu dropzone (symlink): {path.name}")
                continue
        except OSError:
            continue

        ext = path.suffix.lower()
        if ext not in ALLOWED_LOG_EXTENSIONS:
            continue

        try:
            st = path.stat()
            rel = path.relative_to(dropzone).as_posix()
            files.append(
                {
                    "relative_path": rel,
                    "extension": ext,
                    "size_bytes": st.st_size,
                    "size_mb": round(st.st_size / (1024**2), 3),
                    "estimated_lines": _estimate_lines(path, st.st_size),
                    "modified_utc": datetime.fromtimestamp(st.st_mtime, tz=UTC).isoformat(),
                }
            )
        except OSError as exc:
            warnings.append(f"Nie udało się odczytać metadanych pliku {path.name}: {exc}")

    return {
        "dropzone_hint": "workspace/external_logs",
        "allowed_extensions": sorted(ALLOWED_LOG_EXTENSIONS),
        "files_count": len(files),
        "files": files[:50],
    }, warnings


def search_external_log_file(
    *,
    filename: str,
    min_severity: str = "error",
    keywords: list[str] | None = None,
    regex_pattern: str | None = None,
    context_lines: int = 2,
    max_patterns: int = 20,
    max_scan_seconds: float = 10.0,
    base_dir: Path | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Programistycznie skanuje, filtruje i deduplikuje log zewnętrzny, oszczędzając tokeny."""
    warnings: list[str] = []
    dropzone = base_dir or get_external_logs_dir()
    target_path = resolve_jailed_path(dropzone, filename, require_allowed_extension=True)

    if not target_path.exists() or not target_path.is_file():
        raise FileNotFoundError(f"Plik '{filename}' nie istnieje w katalogu external_logs.")

    try:
        severity_enum = LogSeverityFilter(min_severity.strip().lower())
    except ValueError as exc:
        allowed = ", ".join(m.value for m in LogSeverityFilter)
        raise ValueError(f"Nieprawidłowy min_severity '{min_severity}'. Dozwolone: {allowed}") from exc

    safe_context = max(0, min(int(context_lines), 3))
    safe_max_patterns = max(1, min(int(max_patterns), 30))

    clean_keywords = [kw.strip().lower() for kw in (keywords or []) if kw and kw.strip()]
    compiled_custom_re: re.Pattern[str] | None = None
    if regex_pattern and regex_pattern.strip():
        raw_re = regex_pattern.strip()
        if len(raw_re) > 200:
            raise ValueError("Wzorzec regex_pattern nie może przekraczać 200 znaków.")
        try:
            compiled_custom_re = re.compile(raw_re, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"Błędny wzorzec regex: {exc}") from exc

    severity_re = _SEVERITY_PATTERNS[severity_enum]
    has_explicit_filter = bool(clean_keywords or compiled_custom_re)

    # Struktury strumieniowego skanera
    prev_buffer: deque[tuple[int, str]] = deque(maxlen=safe_context)
    pending_after: list[dict[str, Any]] = []
    patterns: dict[str, dict[str, Any]] = {}

    lines_scanned = 0
    total_matches = 0
    timed_out = False
    started_at = time.monotonic()

    with target_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            lines_scanned = line_no
            if line_no % 5000 == 0 and (time.monotonic() - started_at) > max_scan_seconds:
                timed_out = True
                warnings.append(
                    f"Przerwano skanowanie po {max_scan_seconds:.1f}s (przeskanowano {line_no} linii)."
                )
                break

            line = raw_line.rstrip("\r\n")
            trimmed_line = redact_secrets(line[:400] + ("..." if len(line) > 400 else ""))

            # Uzupełnianie kontekstu PO dopasowaniu dla wcześniej wykrytych unikalnych wzorców
            if pending_after:
                still_pending: list[dict[str, Any]] = []
                for item in pending_after:
                    item["after"].append(f"L{line_no}: {trimmed_line}")
                    item["remaining"] -= 1
                    if item["remaining"] > 0:
                        still_pending.append(item)
                pending_after = still_pending

            # Dopasowanie linii
            matched = False
            if has_explicit_filter:
                kw_ok = (not clean_keywords) or any(kw in line.lower() for kw in clean_keywords)
                re_ok = (compiled_custom_re is None) or bool(compiled_custom_re.search(line))
                sev_ok = (severity_enum == LogSeverityFilter.ALL) or bool(severity_re.search(line))
                matched = kw_ok and re_ok and sev_ok
            else:
                matched = bool(severity_re.search(line))

            if matched:
                total_matches += 1
                sig = _normalize_signature(line)
                sig_hash = hashlib.sha1(sig.encode("utf-8")).hexdigest()[:10]
                sev_rank, sev_name = _classify_severity(line)

                if sig_hash not in patterns:
                    after_ctx: list[str] = []
                    entry: dict[str, Any] = {
                        "signature_id": sig_hash,
                        "severity": sev_name,
                        "severity_rank": sev_rank,
                        "count": 1,
                        "first_line": line_no,
                        "last_line": line_no,
                        "sample_line": trimmed_line,
                        "context_before": [f"L{ln}: {txt}" for ln, txt in prev_buffer],
                        "context_after": after_ctx,
                    }
                    patterns[sig_hash] = entry
                    if safe_context > 0 and len(patterns) <= safe_max_patterns * 3:
                        pending_after.append({"after": after_ctx, "remaining": safe_context})
                else:
                    entry = patterns[sig_hash]
                    entry["count"] += 1
                    entry["last_line"] = line_no
                    if sev_rank < entry["severity_rank"]:
                        entry["severity_rank"] = sev_rank
                        entry["severity"] = sev_name

            if safe_context > 0:
                prev_buffer.append((line_no, trimmed_line))

    sorted_patterns = sorted(
        patterns.values(),
        key=lambda p: (p["severity_rank"], -p["count"], -p["last_line"]),
    )

    # Usuwamy pomocniczy severity_rank z JSON-a wyjściowego
    output_patterns = [
        {k: v for k, v in item.items() if k != "severity_rank"}
        for item in sorted_patterns[:safe_max_patterns]
    ]

    return {
        "file": filename,
        "file_size_mb": round(target_path.stat().st_size / (1024**2), 3),
        "filters": {
            "min_severity": severity_enum.value,
            "keywords": clean_keywords,
            "regex_pattern": regex_pattern,
        },
        "stats": {
            "lines_scanned": lines_scanned,
            "total_matches": total_matches,
            "unique_patterns_total": len(patterns),
            "unique_patterns_returned": len(output_patterns),
            "timed_out": timed_out,
            "scan_duration_ms": int((time.monotonic() - started_at) * 1000),
        },
        "patterns": output_patterns,
    }, warnings