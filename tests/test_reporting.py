from __future__ import annotations

from pathlib import Path

from win_diag.agent.schemas import (
    AgentDiagnosis,
    AuditRunResult,
    DiagnosisStatus,
    EvidenceItem,
    ExternalLogRequest,
    FindingItem,
    SeverityLevel,
    TokenUsage,
    ToolCallAudit,
)
from win_diag.privacy.vault import PrivacyVault
from win_diag.reporting.renderer import render_html_report


def _build_sample_result() -> AuditRunResult:
    diag = AgentDiagnosis(
        diagnosis_status=DiagnosisStatus.INSUFFICIENT_DATA,
        overall_health=SeverityLevel.MEDIUM,
        confidence_score=0.45,
        executive_summary="Na komputerze HOST_01 wykryto ostrzeżenie, ale brakuje logu aplikacji.",
        findings=[
            FindingItem(
                title="Timeout połączenia z IP_LAN_01 <script>alert(1)</script>",
                severity=SeverityLevel.MEDIUM,
                root_cause="Aplikacja w C:\\Users\\USER_01 nie otrzymała odpowiedzi.",
                evidence=[
                    EvidenceItem(
                        source_tool="query_event_logs",
                        reference="EventID 1000",
                        summary="Błąd procesu z [SECRET_REDACTED]",
                    )
                ],
                recommendations=["Sprawdź konfigurację zapory i zaktualizuj sterownik."],
            )
        ],
        open_hypotheses=["Możliwa kolizja portu z lokalną usługą."],
        external_log_requests=[
            ExternalLogRequest(
                log_name="Log aplikacji klienta",
                reason="Event Log nie zawiera śladu stosu wywołań.",
                how_to_obtain=r"Copy-Item C:\Users\USER_01\AppData\Local\App\app.log .\workspace\external_logs\app.log",
                expected_format=".log (UTF-8)",
                target_directory="workspace/external_logs/",
                example_filename="app.log",
            )
        ],
    )
    return AuditRunResult(
        problem_description="Losowe przycięcia na HOST_01",
        started_at_utc="2026-11-22T17:00:00+00:00",
        finished_at_utc="2026-11-22T17:00:25+00:00",
        tier1_model="anthropic/claude-haiku-5.5",
        tier2_model="anthropic/claude-sonnet-5.5",
        escalated=True,
        escalation_reasons=["Pewność diagnozy poniżej progu."],
        tier1_diagnosis=diag,
        final_diagnosis=diag,
        tool_calls=[
            ToolCallAudit(
                tier="tier2",
                model="anthropic/claude-sonnet-5.5",
                tool_name="get_network_diagnostics",
                arguments={"include_connections": True},
                duration_ms=420,
                status="ok",
                output_chars=1850,
            )
        ],
        usage_by_tier={"tier1": TokenUsage(prompt_tokens=1000, completion_tokens=200, total_tokens=1200)},
        outbound_payloads=[{"messages": [{"role": "user", "content": "Analiza HOST_01 i USER_01"}]}],
    )


def test_render_html_report_deanonymizes_locally_and_escapes_xss(tmp_path: Path) -> None:
    vault = PrivacyVault()
    vault.register("HOST", "MY-WORKSTATION")
    vault.register("USER", "janek")
    vault.register("IP_LAN", "192.168.10.20")

    result = _build_sample_result()
    report_path = render_html_report(
        result,
        vault=vault,
        reports_dir=tmp_path,
        keep_anonymized=False,
        open_in_browser=False,
    )

    assert report_path.exists()
    html = report_path.read_text(encoding="utf-8")

    # Lokalna de-anonimizacja zadziałała
    assert "MY-WORKSTATION" in html
    assert "janek" in html
    assert "192.168.10.20" in html
    # Sekcja brakujących logów jest wyrenderowana
    assert "Wymagane dodatkowe logi zewnętrzne" in html
    assert "workspace/external_logs/app.log" in html
    # XSS z nazwy znaleziska został poprawnie zescapowany
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    # Brak wycieków w ruchu wychodzącym
    assert vault.find_leaks("Analiza HOST_01 i USER_01") == []


def test_render_html_report_keep_anonymized_preserves_tokens(tmp_path: Path) -> None:
    vault = PrivacyVault()
    vault.register("HOST", "MY-WORKSTATION")
    vault.register("USER", "janek")

    result = _build_sample_result()
    report_path = render_html_report(
        result,
        vault=vault,
        reports_dir=tmp_path,
        keep_anonymized=True,
        open_in_browser=False,
    )

    html = report_path.read_text(encoding="utf-8")
    assert "HOST_01" in html
    assert "USER_01" in html
    assert "MY-WORKSTATION" not in html
    assert "janek" not in html  