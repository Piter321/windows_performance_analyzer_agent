from __future__ import annotations

import re

SECRET_PLACEHOLDER = "[SECRET_REDACTED]"

# Wzorce nieodwracalnych sekretów (klucze API, tokeny, hasła w linii poleceń i URL)
_KEY_PATTERNS: list[re.Pattern[str]] = [
    # Klucze OpenRouter / OpenAI / Anthropic / GitHub / AWS / JWT
    re.compile(r"\bsk-or-v1-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
]

# Nagłówki Authorization: Bearer / Basic
_AUTH_HEADER_RE = re.compile(
    r"(?i)\b(Authorization\s*[:=]\s*(?:Bearer|Basic|Token)\s+)([^\s\"';,]+)"
)

# Flagi i zmienne środowiskowe w cmdline: --password=xxx, -p xxx, api_key: xxx, token="xxx"
_CLI_SECRET_RE = re.compile(
    r"(?i)((?:--|-|/)?(?:pass(?:word|wd)?|pwd|secret|api[-_]?key|access[-_]?token|"
    r"auth[-_]?token|private[-_]?key|client[-_]?secret|bearer|token)\s*(?:=|:|\s+)\s*)"
    r"(\"[^\"]+\"|'[^']+'|[^\s\"',;]+)"
)

# Poświadczenia w URL: https://user:pass@host
_URL_CREDS_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")

# Detektory dynamicznych PII (przetwarzane przez PrivacyVault na deterministyczne tokeny)
SID_RE = re.compile(r"\bS-1-5-21(?:-\d+){3,}\b")
MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_CANDIDATE_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[A-Za-z0-9_.-]+)?(?![0-9A-Fa-f:])"
)

# Ścieżki profili Windows (zarówno C:\Users\Jan jak i JSON-owe C:\\Users\\Jan)
WINDOWS_USER_PATH_RE = re.compile(
    r"(?i)([A-Z]:(?:\\{1,2}|/)Users(?:\\{1,2}|/))([A-Za-z0-9._-]+)"
)

# Ścieżki sieciowe UNC (\\SERWER\udzial lub \\\\SERWER\\udzial)
UNC_HOST_RE = re.compile(r"(?<!:)(\\{2,4})([A-Za-z0-9_.-]{2,63})(\\{1,2}[A-Za-z0-9_.$ -]+)")

# Systemowe katalogi profili, których NIE trzeba anonimizować
SYSTEM_USER_DIRS = frozenset({"public", "default", "default user", "all users"})

# Wzorzec tokenów wygenerowanych przez PrivacyVault (chroni przed podwójną tokenizacją)
VAULT_TOKEN_RE = re.compile(
    r"^(?:HOST|FQDN|DOMAIN|USER|SID|IP_LAN|IP_EXT|IP6|MAC|SERIAL|MACHINE_GUID|EMAIL)_\d{2,}$"
)


def redact_secrets(text: str) -> str:
    """Nieodwracalnie usuwa sekrety, klucze API oraz hasła z tekstu i argumentów cmdline."""
    if not text:
        return text

    result = text
    for pattern in _KEY_PATTERNS:
        result = pattern.sub(SECRET_PLACEHOLDER, result)

    result = _AUTH_HEADER_RE.sub(rf"\1{SECRET_PLACEHOLDER}", result)
    result = _CLI_SECRET_RE.sub(rf"\1{SECRET_PLACEHOLDER}", result)
    result = _URL_CREDS_RE.sub(rf"\1{SECRET_PLACEHOLDER}:{SECRET_PLACEHOLDER}@", result)
    return result