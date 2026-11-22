from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DiagnosisStatus(str, Enum):
    CLEAR = "clear"
    AMBIGUOUS = "ambiguous"
    INSUFFICIENT_DATA = "insufficient_data"
    CRITICAL_UNKNOWN = "critical_unknown"


class SeverityLevel(str, Enum):
    HEALTHY = "healthy"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceItem(BaseModel):
    source_tool: str = Field(..., description="Nazwa narzędzia MCP, z którego pochodzi dowód")
    reference: str = Field(..., description="Konkretny identyfikator, np. EventID 41, PID 4320, sterownik")
    summary: str = Field(..., description="Zwięzły opis faktu z danych")


class FindingItem(BaseModel):
    title: str = Field(..., description="Krótki tytuł wykrytego problemu lub anomalii")
    severity: SeverityLevel = Field(..., description="Waga problemu")
    root_cause: str = Field(..., description="Wyjaśnienie przyczyny źródłowej")
    evidence: list[EvidenceItem] = Field(default_factory=list, description="Twarde dowody z MCP")
    recommendations: list[str] = Field(
        default_factory=list,
        description="Konkretne, bezpieczne kroki do ręcznego wykonania przez użytkownika",
    )


class ExternalLogRequest(BaseModel):
    log_name: str = Field(..., description="Nazwa brakującego logu (np. 'Logi sterownika Wi-Fi' lub 'Log aplikacji X')")
    reason: str = Field(..., description="Dlaczego ten log jest potrzebny do potwierdzenia przyczyny")
    how_to_obtain: str = Field(
        ...,
        description="Dokładna instrukcja krok po kroku (ścieżka w Windows lub komenda eksportu), jak pozyskać plik",
    )
    expected_format: str = Field(
        default=".log lub .txt (tekst UTF-8)",
        description="Wymagany format pliku (.log, .txt, .csv, .json)",
    )
    target_directory: str = Field(
        default="workspace/external_logs/",
        description="Katalog docelowy, do którego użytkownik ma skopiować plik",
    )
    example_filename: str = Field(
        default="diag_extra.log",
        description="Przykładowa nazwa pliku w katalogu dropzone",
    )


class AgentDiagnosis(BaseModel):
    diagnosis_status: DiagnosisStatus = Field(
        ...,
        description="clear | ambiguous | insufficient_data | critical_unknown",
    )
    overall_health: SeverityLevel = Field(
        ...,
        description="Ogólny stan systemu: healthy | low | medium | high | critical",
    )
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Pewność diagnozy w skali 0.0 - 1.0 poparta dowodami z narzędzi MCP",
    )
    executive_summary: str = Field(
        ...,
        description="Zwięzłe podsumowanie stanu systemu i głównej przyczyny problemu (2-4 zdania)",
    )
    findings: list[FindingItem] = Field(
        default_factory=list,
        description="Lista wykrytych problemów z dowodami i rekomendacjami",
    )
    open_hypotheses: list[str] = Field(
        default_factory=list,
        description="Niewyjaśnione anomalie lub hipotezy wymagające głębszej weryfikacji",
    )
    external_log_requests: list[ExternalLogRequest] = Field(
        default_factory=list,
        description="Wypełnij, jeśli w telemetrii Windows brakuje dowodów i użytkownik powinien dostarczyć zewnętrzne logi",
    )


class EscalationDecision(BaseModel):
    should_escalate: bool
    reasons: list[str] = Field(default_factory=list)


class ToolCallAudit(BaseModel):
    tier: str
    model: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = 0
    status: str = "ok"
    truncated: bool = False
    output_chars: int = 0


class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def add(self, prompt: int, completion: int, total: int) -> None:
        self.prompt_tokens += prompt
        self.completion_tokens += completion
        self.total_tokens += total


class AuditRunResult(BaseModel):
    problem_description: str
    started_at_utc: str
    finished_at_utc: str
    tier1_model: str
    tier2_model: str
    escalated: bool
    escalation_reasons: list[str] = Field(default_factory=list)
    tier1_diagnosis: AgentDiagnosis
    final_diagnosis: AgentDiagnosis
    tool_calls: list[ToolCallAudit] = Field(default_factory=list)
    usage_by_tier: dict[str, TokenUsage] = Field(default_factory=dict)
    outbound_payloads: list[dict[str, Any]] = Field(default_factory=list)