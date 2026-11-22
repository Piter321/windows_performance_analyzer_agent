from __future__ import annotations

import asyncio
import ctypes
import json
import platform
import sys
from datetime import datetime

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from win_diag import __version__
from win_diag.agent.orchestrator import DiagnosticOrchestrator
from win_diag.agent.schemas import AuditRunResult
from win_diag.config import load_settings
from win_diag.privacy.vault import PrivacyVault
from win_diag.reporting.renderer import render_html_report

app = typer.Typer(
    name="win-diag",
    help="Lokalny agent AI (Strict Read-Only) do diagnostyki systemu Windows.",
    no_args_is_help=True,
)
console = Console()


def is_admin() -> bool:
    """Sprawdza, czy proces CLI działa z podniesionymi uprawnieniami Administratora."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def require_admin(allow_non_admin: bool = False) -> None:
    """Blokuje uruchomienie diagnostyki bez uprawnień Administratora (chyba że wymuszono)."""
    if not is_admin() and not allow_non_admin:
        console.print(
            Panel(
                "[bold red]Brak uprawnień Administratora.[/bold red]\n\n"
                "Pełna diagnostyka (Event Log Security, cmdline usług SYSTEM, S.M.A.R.T., Minidump) "
                "wymaga uruchomienia z podniesionymi uprawnieniami.\n"
                "Otwórz [bold]Windows Terminal jako Administrator[/bold] i uruchom polecenie ponownie.",
                title="Wymagane uprawnienia (UAC)",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)


def _render_console_summary(result: AuditRunResult, vault: PrivacyVault, keep_anonymized: bool) -> None:
    """Wyświetla zwięzłe podsumowanie diagnozy w terminalu."""

    def _fmt(text: str) -> str:
        return text if keep_anonymized else vault.deanonymize(text)

    diag = result.final_diagnosis
    status_color = {
        "healthy": "green",
        "low": "cyan",
        "medium": "yellow",
        "high": "bright_red",
        "critical": "bold red",
    }.get(diag.overall_health.value, "white")

    console.print(
        Panel(
            f"[bold]Status diagnozy:[/bold] {diag.diagnosis_status.value}  |  "
            f"[bold]Stan systemu:[/bold] [{status_color}]{diag.overall_health.value.upper()}[/{status_color}]  |  "
            f"[bold]Pewność:[/bold] {diag.confidence_score:.0%}\n"
            f"[bold]Eskalacja Tier 2:[/bold] {'TAK (' + result.tier2_model + ')' if result.escalated else 'NIE (zakończono na ' + result.tier1_model + ')'}\n\n"
            f"{_fmt(diag.executive_summary)}",
            title="Podsumowanie diagnostyki",
            border_style="cyan",
        )
    )

    if diag.external_log_requests:
        blocks: list[str] = []
        for idx, req in enumerate(diag.external_log_requests, start=1):
            blocks.append(
                f"[bold yellow]{idx}. {_fmt(req.log_name)}[/bold yellow]\n"
                f"  • Dlaczego potrzebny: {_fmt(req.reason)}\n"
                f"  • Jak pozyskać: {_fmt(req.how_to_obtain)}\n"
                f"  • Format: {req.expected_format}\n"
                f"  • Gdzie zapisać: [bold]{req.target_directory}{req.example_filename}[/bold]"
            )
        console.print(
            Panel(
                "\n\n".join(blocks)
                + "\n\n[dim]Po zapisaniu pliku uruchom ponownie: uv run win-diag audit --problem \"...\"[/dim]",
                title="Wymagane dodatkowe logi zewnętrzne",
                border_style="yellow",
            )
        )

    usage_parts = [
        f"{tier}: {u.total_tokens} tok (in={u.prompt_tokens}, out={u.completion_tokens})"
        for tier, u in result.usage_by_tier.items()
    ]
    console.print(
        f"[dim]Wywołania MCP: {len(result.tool_calls)} | Tokeny: {' | '.join(usage_parts)}[/dim]"
    )


@app.command("check-env")
def check_env(
    allow_non_admin: bool = typer.Option(
        False,
        "--allow-non-admin",
        help="Pozwala uruchomić weryfikację środowiska bez uprawnień Administratora.",
    ),
) -> None:
    """Weryfikuje środowisko, uprawnienia Admina, plik .env oraz auto-detekcję PrivacyVault."""
    console.print(f"[bold cyan]win-diag v{__version__}[/bold cyan] — weryfikacja środowiska\n")

    admin_ok = is_admin()
    if not admin_ok and not allow_non_admin:
        require_admin(allow_non_admin=False)

    try:
        settings = load_settings()
    except ValidationError as exc:
        console.print(
            Panel(
                "[bold red]Błąd konfiguracji (.env):[/bold red]\n"
                f"{exc}\n\n"
                "Upewnij się, że skopiowałeś [bold].env.example[/bold] do [bold].env[/bold] "
                "i ustawiłeś poprawny [bold]OPENROUTER_API_KEY[/bold].",
                title="Brak lub błędny plik .env",
                border_style="red",
            )
        )
        raise typer.Exit(code=1) from exc

    settings.ensure_directories()

    api_key_raw = settings.openrouter_api_key.get_secret_value()
    api_key_looks_valid = bool(api_key_raw) and "tutaj-twoj-klucz" not in api_key_raw

    vault = PrivacyVault.from_local_system(extra_secrets=[api_key_raw])
    vault_stats = vault.stats()

    table = Table(title="Status środowiska", show_header=True, header_style="bold magenta")
    table.add_column("Komponent", style="cyan")
    table.add_column("Status")
    table.add_column("Szczegóły")

    table.add_row("System / Python", "[green]OK[/green]", f"{platform.platform()} / Python {sys.version.split()[0]}")
    table.add_row(
        "Uprawnienia Administratora",
        "[green]TAK[/green]" if admin_ok else "[yellow]NIE (tryb --allow-non-admin)[/yellow]",
        "Pełny odczyt Event Log / WMI / procesów" if admin_ok else "Ograniczony dostęp do telemetrii",
    )
    table.add_row(
        "OPENROUTER_API_KEY (.env)",
        "[green]ZAŁADOWANY[/green]" if api_key_looks_valid else "[yellow]PLACEHOLDER[/yellow]",
        "Zarejestrowany w PrivacyVault jako sekret nieodwracalny",
    )
    table.add_row("Model Tier 1 (Triage)", "[green]OK[/green]", settings.primary_model)
    table.add_row("Model Tier 2 (Eskalacja)", "[green]OK[/green]", settings.escalation_model)
    table.add_row(
        "Katalogi robocze",
        "[green]GOTOWE[/green]",
        f"{settings.external_logs_dir.resolve()} | {settings.reports_dir.resolve()}",
    )
    table.add_row(
        "PrivacyVault (wykryte PII)",
        "[green]AKTYWNY[/green]",
        ", ".join(f"{k}: {v}" for k, v in vault_stats.items()) or "brak wpisów",
    )

    console.print(table)


@app.command("audit")
def audit(
    problem: str = typer.Option(
        "Ogólny przegląd stanu systemu Windows i wykrywanie ukrytych anomalii",
        "--problem",
        "-p",
        help="Opis objawów lub problemu do zdiagnozowania.",
    ),
    force_escalate: bool = typer.Option(
        False,
        "--force-escalate",
        help="Wymusza uruchomienie Tier 2 (Claude Sonnet) niezależnie od pewności Tier 1.",
    ),
    keep_anonymized: bool = typer.Option(
        False,
        "--keep-anonymized",
        help="Zachowaj zanonimizowane tokeny w raporcie HTML (bezpieczne do udostępnienia).",
    ),
    open_report: bool = typer.Option(
        True,
        "--open/--no-open",
        help="Automatycznie otwiera wygenerowany raport HTML w domyślnej przeglądarce.",
    ),
    dump_outbound_log: bool = typer.Option(
        False,
        "--dump-outbound-log",
        help="Zapisuje dokładny JSON wysłany do OpenRoutera do reports/outbound_*.json i uruchamia test zero-leakage.",
    ),
) -> None:
    """Uruchamia pełną diagnostykę systemu przez lokalny serwer MCP, OpenRouter i generuje raport HTML."""
    require_admin()
    settings = load_settings()
    settings.ensure_directories()

    api_key_raw = settings.openrouter_api_key.get_secret_value()
    vault = PrivacyVault.from_local_system(extra_secrets=[api_key_raw])

    console.print(
        Panel(
            f"[bold]Cel audytu:[/bold] {problem}\n"
            f"[bold]Tier 1:[/bold] {settings.primary_model}  →  [bold]Tier 2:[/bold] {settings.escalation_model}\n"
            f"[bold]PrivacyVault:[/bold] aktywny ({sum(vault.stats().values())} chronionych encji)",
            title=f"win-diag v{__version__}",
            border_style="blue",
        )
    )

    orchestrator = DiagnosticOrchestrator(settings=settings, vault=vault, console=console)
    result = asyncio.run(
        orchestrator.run(
            problem_description=problem,
            force_escalate=force_escalate,
        )
    )

    _render_console_summary(result, vault=vault, keep_anonymized=keep_anonymized)

    # Generowanie raportu HTML (lokalny zapis poza zasięgiem LLM/MCP)
    report_path = render_html_report(
        result,
        vault=vault,
        reports_dir=settings.reports_dir,
        keep_anonymized=keep_anonymized,
        open_in_browser=open_report,
    )
    console.print(f"\n[bold green]Raport HTML zapisany:[/bold green] {report_path}")

    # Audyt prywatności ruchu wychodzącego
    outbound_serialized = json.dumps(result.outbound_payloads, indent=2, ensure_ascii=False)
    leaks = vault.find_leaks(outbound_serialized)
    if leaks:
        console.print(
            f"[bold red]OSTRZEŻENIE PRYWATNOŚCI:[/bold red] Wykryto nieoczekiwane tokeny w ruchu wychodzącym: {leaks}"
        )
    else:
        console.print("[green]Audyt prywatności (Zero-Leakage): OK — brak wrażliwych danych maszyny w zapytaniach do OpenRoutera.[/green]")

    if dump_outbound_log:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dump_path = settings.reports_dir / f"outbound_{ts}.json"
        dump_path.write_text(outbound_serialized, encoding="utf-8")
        console.print(f"[dim]Zapisano zrzut ruchu wychodzącego: {dump_path.resolve()}[/dim]")


if __name__ == "__main__":
    app()