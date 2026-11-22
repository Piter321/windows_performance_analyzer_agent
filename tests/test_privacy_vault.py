from __future__ import annotations

import json

from win_diag.privacy.sanitizer import SECRET_PLACEHOLDER
from win_diag.privacy.vault import PrivacyVault


def test_zero_leakage_on_realistic_windows_telemetry() -> None:
    """Sprawdza, czy żaden wrażliwy identyfikator z telemetrii Windows nie wycieka."""
    api_key = "sk-or-v1-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d"
    vault = PrivacyVault()
    vault.register_secret(api_key)
    vault.register("FQDN", "WKST-JAN-2026.home.local")
    vault.register("HOST", "WKST-JAN-2026")
    vault.register("USER", "jkowalski")
    vault.register("SERIAL", "S4EMNX0N812345X")

    raw_payload = {
        "os_version": "Windows 11 Pro 10.0.22631.4317",
        "event_time": "2026-11-22T14:22:05Z",
        "host": "WKST-JAN-2026.home.local",
        "short_host": "WKST-JAN-2026",
        "user_path": r"C:\Users\jkowalski\AppData\Local\Temp\crash.dmp",
        "other_profile_json": r"C:\\Users\\anna_nowak\\Desktop\\app.log",
        "unc_share": r"\\NAS-DOMOWY\backup\logs.txt",
        "sid": "S-1-5-21-3623811015-3361044348-30300820-1001",
        "lan_ip": "192.168.1.45",
        "ext_ip": "83.14.221.19",
        "dns_public": "1.1.1.1",
        "loopback": "127.0.0.1",
        "ipv6": "fe80::1a2b:3c4d:5e6f:7a8b",
        "mac": "A4-BB-6D-11-22-33",
        "email": "jan.kowalski@example.com",
        "disk_serial": "S4EMNX0N812345X",
        "cmdline": (
            f'python.exe agent.py --password="SuperTajneHaslo123!" '
            f"--token {api_key} https://admin:sekret@192.168.1.45/api"
        ),
    }

    anonymized = vault.anonymize_data(raw_payload)
    serialized = json.dumps(anonymized)

    # Żadna z wrażliwych wartości nie może istnieć w zanonimizowanym JSON-ie
    forbidden_values = [
        "WKST-JAN-2026",
        "home.local",
        "jkowalski",
        "anna_nowak",
        "NAS-DOMOWY",
        "S-1-5-21-3623811015",
        "192.168.1.45",
        "83.14.221.19",
        "fe80::1a2b:3c4d:5e6f:7a8b",
        "A4-BB-6D-11-22-33",
        "jan.kowalski@example.com",
        "S4EMNX0N812345X",
        "SuperTajneHaslo123!",
        "sekret",
        api_key,
    ]
    for secret in forbidden_values:
        assert secret not in serialized, f"Wykryto wyciek danych: {secret}"

    # Metadane diagnostyczne (build Windows, timestamp, loopback, DNS 1.1.1.1) muszą ocaleć
    assert anonymized["os_version"] == "Windows 11 Pro 10.0.22631.4317"
    assert anonymized["event_time"] == "2026-11-22T14:22:05Z"
    assert anonymized["loopback"] == "127.0.0.1"
    assert anonymized["dns_public"] == "1.1.1.1"
    assert SECRET_PLACEHOLDER in anonymized["cmdline"]


def test_deterministic_mapping_and_safe_deanonymization() -> None:
    """Te same encje dostają identyczne tokeny, a de-anonimizacja nie przywraca sekretów."""
    vault = PrivacyVault()
    vault.register_secret("sk-or-v1-secretkeyvalue1234567890")
    vault.register("HOST", "MY-PC")
    vault.register("USER", "piotr")

    msg1 = vault.anonymize(r"Host MY-PC (192.168.50.10) user C:\Users\piotr")
    msg2 = vault.anonymize("Połączenie z MY-PC na 192.168.50.10 --password=tajne")

    # Deterministyczne korelacje
    assert "HOST_01" in msg1 and "HOST_01" in msg2
    assert "IP_LAN_01" in msg1 and "IP_LAN_01" in msg2
    assert "USER_01" in msg1
    assert "tajne" not in msg2

    # Lokalna de-anonimizacja przywraca nazwy dla raportu HTML, ale NIE przywraca hasła
    restored = vault.deanonymize(msg2)
    assert "MY-PC" in restored
    assert "192.168.50.10" in restored
    assert SECRET_PLACEHOLDER in restored
    assert "tajne" not in restored


def test_idempotency_and_word_boundaries() -> None:
    """Podwójna anonimizacja nie zmienia tokenów, a krótki login nie psuje zwykłych słów."""
    vault = PrivacyVault()
    vault.register("USER", "jan")

    sample = r"Date: January 2026, process owner: jan, path: C:\Users\jan\test.log"
    once = vault.anonymize(sample)
    twice = vault.anonymize(once)

    assert "January" in once
    assert "owner: USER_01" in once
    assert r"C:\Users\USER_01\test.log" in once
    assert once == twice