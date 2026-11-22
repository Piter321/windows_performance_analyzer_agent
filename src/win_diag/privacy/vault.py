from __future__ import annotations

import getpass
import ipaddress
import os
import re
import socket
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import psutil

from win_diag.privacy.sanitizer import (
    EMAIL_RE,
    IPV4_CANDIDATE_RE,
    IPV6_CANDIDATE_RE,
    MAC_RE,
    SECRET_PLACEHOLDER,
    SID_RE,
    SYSTEM_USER_DIRS,
    UNC_HOST_RE,
    VAULT_TOKEN_RE,
    WINDOWS_USER_PATH_RE,
    redact_secrets,
)

# Adresy bezwartościowe identyfikacyjnie, ale krytyczne dla diagnostyki sieci
SAFE_WELL_KNOWN_IPS = frozenset(
    {
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::1",
        "::",
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
    }
)


class PrivacyVault:
    """Deterministyczny rejestr pseudonimizacji dla pojedynczej sesji diagnostycznej.

    Zapewnia spójne mapowanie (np. nazwa hosta -> HOST_01, lokalne IP -> IP_LAN_01),
    dzięki czemu LLM może korelować zdarzenia między narzędziami MCP bez poznawania
    jakichkolwiek danych identyfikujących komputer.
    """

    def __init__(self) -> None:
        self._raw_to_token: dict[str, str] = {}
        self._raw_lower_to_token: dict[str, str] = {}
        self._token_to_raw: dict[str, str] = {}
        self._category_counters: Counter[str] = Counter()
        self._irreversible_secrets: set[str] = set()
        self._literal_entries: list[tuple[str, str]] = []
        self._literals_dirty: bool = False

    def register_secret(self, value: str | None) -> None:
        """Rejestruje sekret nieodwracalny (np. klucz API) -> [SECRET_REDACTED]."""
        if value and len(value.strip()) >= 6:
            self._irreversible_secrets.add(value.strip())

    def register(self, category: str, raw_value: str | None) -> str | None:
        """Rejestruje wartość PII i zwraca przypisany jej deterministyczny token."""
        if not raw_value:
            return None

        cleaned = raw_value.strip()
        if not cleaned or len(cleaned) < 2:
            return None
        if VAULT_TOKEN_RE.match(cleaned):
            return cleaned

        key_lower = cleaned.lower()
        if key_lower in self._raw_lower_to_token:
            return self._raw_lower_to_token[key_lower]

        self._category_counters[category] += 1
        token = f"{category}_{self._category_counters[category]:02d}"

        self._raw_to_token[cleaned] = token
        self._raw_lower_to_token[key_lower] = token
        self._token_to_raw[token] = cleaned
        self._literals_dirty = True
        return token

    def _rebuild_sorted_literals(self) -> None:
        """Sortuje literalne wpisy od najdłuższych (FQDN przed krótką nazwą hosta)."""
        self._literal_entries = sorted(
            self._raw_to_token.items(),
            key=lambda item: len(item[0]),
            reverse=True,
        )
        self._literals_dirty = False

    @classmethod
    def from_local_system(cls, extra_secrets: list[str] | None = None) -> PrivacyVault:
        """Buduje PrivacyVault automatycznie wykrywając identyfikatory lokalnego Windowsa."""
        vault = cls()

        for secret in extra_secrets or []:
            vault.register_secret(secret)

        # 1. Nazwa hosta, FQDN i domena
        hostname = socket.gethostname()
        fqdn = socket.getfqdn()
        computername = os.environ.get("COMPUTERNAME")
        userdomain = os.environ.get("USERDOMAIN")

        if fqdn and fqdn.lower() != hostname.lower():
            vault.register("FQDN", fqdn)
        vault.register("HOST", hostname)
        if computername:
            vault.register("HOST", computername)
        if userdomain and userdomain.lower() not in {"nt authority", "builtin"}:
            vault.register("DOMAIN", userdomain)

        # 2. Bieżący użytkownik i katalogi profili w C:\Users
        for candidate in (getpass.getuser(), os.environ.get("USERNAME"), Path.home().name):
            if candidate and candidate.lower() not in SYSTEM_USER_DIRS:
                vault.register("USER", candidate)

        users_root = Path(os.environ.get("SystemDrive", "C:") + "\\Users")
        if sys.platform == "win32" and users_root.exists():
            try:
                for entry in users_root.iterdir():
                    if entry.is_dir() and entry.name.lower() not in SYSTEM_USER_DIRS:
                        vault.register("USER", entry.name)
            except OSError:
                pass

        # 3. Lokalny SID, MachineGuid i numery seryjne dysków (tylko Windows, tryb RO)
        if sys.platform == "win32":
            vault._discover_windows_identifiers()

        # 4. Lokalne adresy IP i MAC kart sieciowych
        try:
            for addrs in psutil.net_if_addrs().values():
                for addr in addrs:
                    address = addr.address
                    if not address:
                        continue
                    if MAC_RE.fullmatch(address):
                        vault.register("MAC", address)
                        # Rejestrujemy również wariant z dwukropkami/myślnikami
                        alt_mac = address.replace("-", ":") if "-" in address else address.replace(":", "-")
                        vault._register_alias(alt_mac, vault._raw_lower_to_token[address.lower()])
                    else:
                        vault._register_ip_if_valid(address)
        except Exception:
            pass

        return vault

    def _register_alias(self, alias: str, existing_token: str) -> None:
        """Mapuje alternatywny zapis tej samej wartości (np. MAC z ':' i '-') na ten sam token."""
        alias_lower = alias.lower()
        if alias_lower not in self._raw_lower_to_token:
            self._raw_to_token[alias] = existing_token
            self._raw_lower_to_token[alias_lower] = existing_token
            self._literals_dirty = True

    def _discover_windows_identifiers(self) -> None:
        """Odczytuje w trybie read-only SID bieżącego konta, MachineGuid oraz seriale dysków."""
        # SID bieżącego użytkownika
        try:
            import win32security  # type: ignore[import-untyped]

            sid, _, _ = win32security.LookupAccountName(None, getpass.getuser())
            sid_str = win32security.ConvertSidToStringSid(sid)
            vault_sid = self.register("SID", sid_str)
            if vault_sid and sid_str.count("-") >= 6:
                # Rejestrujemy też SID samej maszyny (bez RID użytkownika na końcu)
                machine_sid = sid_str.rsplit("-", 1)[0]
                self.register("SID", machine_sid)
        except Exception:
            pass

        # MachineGuid z rejestru (wyłącznie KEY_READ)
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                winreg.KEY_READ,
            ) as key:
                machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                if isinstance(machine_guid, str):
                    self.register("MACHINE_GUID", machine_guid)
        except Exception:
            pass

        # Numery seryjne dysków fizycznych (WMI, bezpiecznie z ignorowaniem błędów COM)
        try:
            import wmi  # type: ignore[import-untyped]

            conn = wmi.WMI()
            for disk in conn.Win32_DiskDrive():
                serial = (getattr(disk, "SerialNumber", None) or "").strip()
                if len(serial) >= 6:
                    self.register("SERIAL", serial)
        except Exception:
            pass

    def _register_ip_if_valid(self, raw_ip: str) -> str | None:
        """Waliduje adres IP i przypisuje token IP_LAN_XX / IP_EXT_XX / IP6_XX."""
        clean_ip = raw_ip.split("%", 1)[0].strip()
        if clean_ip in SAFE_WELL_KNOWN_IPS:
            return None

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            return None

        if ip_obj.is_loopback or ip_obj.is_unspecified:
            return None

        if isinstance(ip_obj, ipaddress.IPv4Address):
            category = "IP_LAN" if (ip_obj.is_private or ip_obj.is_link_local) else "IP_EXT"
            return self.register(category, clean_ip)

        return self.register("IP6", clean_ip)

    def anonymize(self, text: str) -> str:
        """Anonimizuje dowolny ciąg tekstowy przed wysłaniem go do OpenRoutera."""
        if not text:
            return text

        result = text

        # 1. Najpierw usuwamy jawnie zarejestrowane sekrety (np. OPENROUTER_API_KEY)
        for secret in sorted(self._irreversible_secrets, key=len, reverse=True):
            if secret in result:
                result = result.replace(secret, SECRET_PLACEHOLDER)

        # 2. Usuwamy wzorce sekretów (hasła cmdline, tokeny, klucze API)
        result = redact_secrets(result)

        # 3. Dynamiczne ścieżki C:\Users\<dowolny_profil> (łapie też inne konta z logów)
        def _replace_user_path(match: re.Match[str]) -> str:
            prefix, username = match.group(1), match.group(2)
            if username.lower() in SYSTEM_USER_DIRS or VAULT_TOKEN_RE.match(username):
                return match.group(0)
            token = self.register("USER", username)
            return f"{prefix}{token or username}"

        result = WINDOWS_USER_PATH_RE.sub(_replace_user_path, result)

        # 4. Ścieżki sieciowe UNC (\\SERWER\udzial)
        def _replace_unc_host(match: re.Match[str]) -> str:
            slashes, host, share = match.group(1), match.group(2), match.group(3)
            if VAULT_TOKEN_RE.match(host):
                return match.group(0)
            token = self.register("HOST", host)
            return f"{slashes}{token or host}{share}"

        result = UNC_HOST_RE.sub(_replace_unc_host, result)

        # 5. Podmiana wszystkich znanych literalnych identyfikatorów (case-insensitive, granice słów)
        if self._literals_dirty:
            self._rebuild_sorted_literals()

        for raw_val, token in self._literal_entries:
            pattern = re.compile(
                rf"(?<![A-Za-z0-9]){re.escape(raw_val)}(?![A-Za-z0-9])",
                re.IGNORECASE,
            )
            result = pattern.sub(lambda _, tok=token: tok, result)

        # 6. Dynamiczne wykrywanie pozostałych PII: SID, MAC, Email, IPv4, IPv6
        result = SID_RE.sub(lambda m: self.register("SID", m.group(0)) or m.group(0), result)
        result = MAC_RE.sub(lambda m: self.register("MAC", m.group(0)) or m.group(0), result)
        result = EMAIL_RE.sub(lambda m: self.register("EMAIL", m.group(0)) or m.group(0), result)

        def _replace_ipv4(match: re.Match[str]) -> str:
            candidate = match.group(0)
            token = self._register_ip_if_valid(candidate)
            return token if token else candidate

        result = IPV4_CANDIDATE_RE.sub(_replace_ipv4, result)

        def _replace_ipv6(match: re.Match[str]) -> str:
            candidate = match.group(0)
            if candidate.count(":") < 2:
                return candidate
            token = self._register_ip_if_valid(candidate)
            return token if token else candidate

        result = IPV6_CANDIDATE_RE.sub(_replace_ipv6, result)

        return result

    def anonymize_data(self, payload: Any) -> Any:
        """Rekurencyjnie anonimizuje słowniki, listy i stringi (np. wyniki narzędzi MCP)."""
        if isinstance(payload, str):
            return self.anonymize(payload)
        if isinstance(payload, list):
            return [self.anonymize_data(item) for item in payload]
        if isinstance(payload, tuple):
            return tuple(self.anonymize_data(item) for item in payload)
        if isinstance(payload, dict):
            return {
                (self.anonymize(k) if isinstance(k, str) else k): self.anonymize_data(v)
                for k, v in payload.items()
            }
        return payload

    def deanonymize(self, text: str) -> str:
        """Przywraca oryginalne nazwy wyłącznie lokalnie (np. przy generowaniu HTML).

        Sekrety oznaczone jako [SECRET_REDACTED] nigdy nie są przywracane.
        """
        if not text or not self._token_to_raw:
            return text

        result = text
        for token in sorted(self._token_to_raw.keys(), key=len, reverse=True):
            result = result.replace(token, self._token_to_raw[token])
        return result

    def stats(self) -> dict[str, int]:
        """Zwraca statystyki liczby zamaskowanych encji (bez ujawniania wartości)."""
        summary = dict(self._category_counters)
        if self._irreversible_secrets:
            summary["SECRETS_BLOCKED"] = len(self._irreversible_secrets)
        return summary
    
    def find_leaks(self, serialized_outbound_text: str) -> list[str]:
        """Sprawdza, czy w zserializowanym payloadzie wychodzącym pojawiła się jakakolwiek chroniona wartość.

        Zwraca listę wykrytych kategorii/tokenów (pusta lista oznacza 0 wycieków).
        """
        leaks: list[str] = []
        for idx, secret in enumerate(self._irreversible_secrets, start=1):
            if secret in serialized_outbound_text:
                leaks.append(f"IRREVERSIBLE_SECRET_{idx}")

        for raw_val, token in self._raw_to_token.items():
            if len(raw_val) < 3:
                continue
            pattern = re.compile(
                rf"(?<![A-Za-z0-9]){re.escape(raw_val)}(?![A-Za-z0-9])",
                re.IGNORECASE,
            )
            if pattern.search(serialized_outbound_text):
                leaks.append(token)
        return leaks