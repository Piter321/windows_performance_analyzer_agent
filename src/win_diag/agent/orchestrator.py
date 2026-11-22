from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from rich.console import Console

from win_diag.agent.openrouter import OpenRouterAgentRunner
from win_diag.agent.prompts import TIER1_SYSTEM_PROMPT, TIER2_SYSTEM_PROMPT
from win_diag.agent.schemas import (
    AgentDiagnosis,
    AuditRunResult,
    DiagnosisStatus,
    EscalationDecision,
    SeverityLevel,
    TokenUsage,
    ToolCallAudit,
)
from win_diag.config import Settings
from win_diag.mcp_client.bridge import MCPBridge
from win_diag.privacy.vault import PrivacyVault

_CRITICAL_EVENT_IDS = frozenset({41, 1001, 161, 6008, 7, 11, 55, 129, 153})


def detect_critical_snapshot_signals(snapshot_bundle: dict[str, Any]) -> bool:
    """Sprawdza, czy wstępny snapshot zawiera zdarzenia o wysokim ryzyku (BSOD, Kernel-Power, błędy dysku)."""
    sys_logs = snapshot_bundle.get("query_event_logs_system", {})
    groups = sys_logs.get("data", {}).get("groups", []) if isinstance(sys_logs, dict) else []
    for grp in groups:
        if not isinstance(grp, dict):
            continue
        if int(grp.get("level") or 4) == 1:  # Critical
            return True
        if int(grp.get("event_id") or 0) in _CRITICAL_EVENT_IDS:
            return True
    return False


def evaluate_escalation_gate(
    diagnosis: AgentDiagnosis,
    *,
    confidence_threshold: float,
    snapshot_has_critical_signals: bool = False,
    force_escalate: bool = False,
) -> EscalationDecision:
    """Deterministyczna bramka decydująca o eskalacji z Tier 1 do Tier 2."""
    reasons: list[str] = []

    if force_escalate:
        reasons.append("Wymuszono eskalację flagą CLI (--force-escalate).")

    if diagnosis.diagnosis_status != DiagnosisStatus.CLEAR:
        reasons.append(f"Status diagnozy Tier 1 to '{diagnosis.diagnosis_status.value}' (wymagane 'clear').")

    if diagnosis.confidence_score < confidence_threshold:
        reasons.append(
            f"Pewność diagnozy ({diagnosis.confidence_score:.2f}) poniżej progu ({confidence_threshold:.2f})."
        )

    if diagnosis.overall_health == SeverityLevel.CRITICAL:
        reasons.append("Wykryto krytyczny stan zdrowia systemu (overall_health=critical).")

    if diagnosis.open_hypotheses:
        reasons.append(
            f"Model Tier 1 pozostawił otwarte hipotezy ({len(diagnosis.open_hypotheses)})."
        )

    unbacked = [f.title for f in diagnosis.findings if not f.evidence]
    if unbacked:
        reasons.append(
            f"Wykryto znaleziska bez twardych dowodów MCP: {', '.join(unbacked[:3])}."
        )

    if snapshot_has_critical_signals and diagnosis.confidence_score < 0.90:
        reasons.append(
            "Snapshot zawiera zdarzenia krytyczne (Critical/Kernel-Power/BSOD/I/O) przy pewności < 0.90."
        )

    return EscalationDecision(should_escalate=bool(reasons), reasons=reasons)


class DiagnosticOrchestrator:
    """Orkiestrator hybrydowy: Snapshot -> Tier 1 (Haiku) -> Bramka -> Tier 2 (Sonnet + MCP)."""

    def __init__(
        self,
        settings: Settings,
        vault: PrivacyVault,
        console: Console | None = None,
    ) -> None:
        self._settings = settings
        self._vault = vault
        self._console = console or Console()

    async def run(
        self,
        *,
        problem_description: str,
        force_escalate: bool = False,
    ) -> AuditRunResult:
        started_at = datetime.now(UTC).isoformat()
        all_tool_calls: list[ToolCallAudit] = []
        usage_by_tier: dict[str, TokenUsage] = {}
        outbound_payloads: list[dict[str, Any]] = []

        async with MCPBridge(self._settings, self._vault) as bridge:
            # Faza 1: Deterministyczny Triage Snapshot
            self._console.print("[bold cyan]1/3[/bold cyan] Zbieranie wstępnego snapshotu systemu przez serwer MCP...")
            snapshot_bundle, snap_metas = await bridge.collect_initial_snapshot()
            for meta in snap_metas:
                all_tool_calls.append(
                    ToolCallAudit(
                        tier="snapshot",
                        model="deterministic",
                        tool_name=meta["tool_name"],
                        arguments=meta["arguments"],
                        duration_ms=meta["duration_ms"],
                        status=meta["status"],
                        truncated=meta["truncated"],
                        output_chars=meta["output_chars"],
                    )
                )

            critical_signals = detect_critical_snapshot_signals(snapshot_bundle)
            runner = OpenRouterAgentRunner(
                settings=self._settings,
                bridge=bridge,
                vault=self._vault,
                console=self._console,
            )

            # Faza 2: Tier 1 (Triage)
            self._console.print(
                f"[bold cyan]2/3[/bold cyan] Analiza Tier 1 ({self._settings.primary_model})..."
            )
            tier1_user_payload = (
                f"ZGŁOSZONY PROBLEM / CEL AUDYTU:\n{problem_description}\n\n"
                f"WSTĘPNY SNAPSHOT SYSTEMU (zanonimizowany):\n"
                f"{json.dumps(snapshot_bundle, indent=2, ensure_ascii=False)}"
            )

            tier1_diag, tier1_tools, tier1_usage, tier1_outbound = await runner.run_tier(
                tier_label="tier1",
                model=self._settings.primary_model,
                system_prompt=TIER1_SYSTEM_PROMPT,
                user_payload=tier1_user_payload,
                max_tool_calls=self._settings.max_tool_calls_tier1,
            )
            all_tool_calls.extend(tier1_tools)
            usage_by_tier["tier1"] = tier1_usage
            outbound_payloads.extend(tier1_outbound)

            # Bramka Eskalacji
            gate = evaluate_escalation_gate(
                tier1_diag,
                confidence_threshold=self._settings.escalation_confidence_threshold,
                snapshot_has_critical_signals=critical_signals,
                force_escalate=force_escalate,
            )

            final_diag = tier1_diag

            # Faza 3: Opcjonalna eskalacja do Tier 2 (pełny dostęp do narzędzi MCP)
            if gate.should_escalate:
                self._console.print(
                    f"[bold yellow]3/3 Eskalacja do Tier 2 ({self._settings.escalation_model})![/bold yellow]\n"
                    + "\n".join(f"  • {r}" for r in gate.reasons)
                )
                prior_tools_summary = [
                    {
                        "tool": t.tool_name,
                        "args": t.arguments,
                        "status": t.status,
                    }
                    for t in all_tool_calls
                ]
                tier2_user_payload = (
                    f"ZGŁOSZONY PROBLEM / CEL AUDYTU:\n{problem_description}\n\n"
                    f"POWODY ESKALACJI Z TIER 1:\n"
                    + "\n".join(f"- {r}" for r in gate.reasons)
                    + "\n\n"
                    f"WSTĘPNA DIAGNOZA TIER 1 ({self._settings.primary_model}):\n"
                    f"{tier1_diag.model_dump_json(indent=2)}\n\n"
                    f"DOTYCHCZAS WYWOŁANE NARZĘDZIA MCP:\n"
                    f"{json.dumps(prior_tools_summary, indent=2, ensure_ascii=False)}\n\n"
                    f"WSTĘPNY SNAPSHOT SYSTEMU:\n"
                    f"{json.dumps(snapshot_bundle, indent=2, ensure_ascii=False)}\n\n"
                    "Wykorzystaj dostępne narzędzia MCP, aby dociągnąć brakujące dane, potwierdzić lub obalić "
                    "hipotezy Tier 1 i zwrócić ostateczny raport JSON zgodny ze schematem AgentDiagnosis."
                )

                tier2_diag, tier2_tools, tier2_usage, tier2_outbound = await runner.run_tier(
                    tier_label="tier2",
                    model=self._settings.escalation_model,
                    system_prompt=TIER2_SYSTEM_PROMPT,
                    user_payload=tier2_user_payload,
                    max_tool_calls=self._settings.max_tool_calls_tier2,
                )
                all_tool_calls.extend(tier2_tools)
                usage_by_tier["tier2"] = tier2_usage
                outbound_payloads.extend(tier2_outbound)
                final_diag = tier2_diag
            else:
                self._console.print(
                    f"[bold green]3/3[/bold green] Diagnoza rozstrzygnięta na Tier 1 "
                    f"(pewność: {tier1_diag.confidence_score:.2f}, brak potrzeby eskalacji)."
                )

        finished_at = datetime.now(UTC).isoformat()
        return AuditRunResult(
            problem_description=problem_description,
            started_at_utc=started_at,
            finished_at_utc=finished_at,
            tier1_model=self._settings.primary_model,
            tier2_model=self._settings.escalation_model,
            escalated=gate.should_escalate,
            escalation_reasons=gate.reasons,
            tier1_diagnosis=tier1_diag,
            final_diagnosis=final_diag,
            tool_calls=all_tool_calls,
            usage_by_tier=usage_by_tier,
            outbound_payloads=outbound_payloads,
        )