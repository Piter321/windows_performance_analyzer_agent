from __future__ import annotations

from win_diag.agent.orchestrator import evaluate_escalation_gate
from win_diag.agent.schemas import (
    AgentDiagnosis,
    DiagnosisStatus,
    EvidenceItem,
    FindingItem,
    SeverityLevel,
)


def _sample_clear_diagnosis(confidence: float = 0.92, with_evidence: bool = True) -> AgentDiagnosis:
    evidence = (
        [EvidenceItem(source_tool="query_event_logs", reference="EventID 1000", summary="Crash app.exe")]
        if with_evidence
        else []
    )
    return AgentDiagnosis(
        diagnosis_status=DiagnosisStatus.CLEAR,
        overall_health=SeverityLevel.MEDIUM,
        confidence_score=confidence,
        executive_summary="Zidentyfikowano przyczynę awarii aplikacji.",
        findings=[
            FindingItem(
                title="Powtarzający się crash app.exe",
                severity=SeverityLevel.MEDIUM,
                root_cause="Błąd modułu plugin.dll",
                evidence=evidence,
                recommendations=["Zaktualizuj aplikację."],
            )
        ],
    )


def test_clear_high_confidence_does_not_escalate() -> None:
    decision = evaluate_escalation_gate(
        _sample_clear_diagnosis(confidence=0.92),
        confidence_threshold=0.75,
    )
    assert decision.should_escalate is False
    assert decision.reasons == []


def test_low_confidence_triggers_escalation() -> None:
    decision = evaluate_escalation_gate(
        _sample_clear_diagnosis(confidence=0.60),
        confidence_threshold=0.75,
    )
    assert decision.should_escalate is True
    assert any("poniżej progu" in r for r in decision.reasons)


def test_ambiguous_or_insufficient_data_triggers_escalation() -> None:
    diag = _sample_clear_diagnosis(confidence=0.85)
    diag.diagnosis_status = DiagnosisStatus.INSUFFICIENT_DATA
    decision = evaluate_escalation_gate(diag, confidence_threshold=0.75)
    assert decision.should_escalate is True
    assert any("insufficient_data" in r for r in decision.reasons)


def test_unbacked_finding_without_evidence_triggers_escalation() -> None:
    diag = _sample_clear_diagnosis(confidence=0.95, with_evidence=False)
    decision = evaluate_escalation_gate(diag, confidence_threshold=0.75)
    assert decision.should_escalate is True
    assert any("bez twardych dowodów" in r for r in decision.reasons)


def test_critical_snapshot_signals_require_very_high_confidence() -> None:
    diag = _sample_clear_diagnosis(confidence=0.82)
    decision = evaluate_escalation_gate(
        diag,
        confidence_threshold=0.75,
        snapshot_has_critical_signals=True,
    )
    assert decision.should_escalate is True
    assert any("zdarzenia krytyczne" in r for r in decision.reasons)