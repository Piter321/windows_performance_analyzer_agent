from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Konfiguracja aplikacji ładowana automatycznie z pliku .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # OpenRouter API
    openrouter_api_key: SecretStr = Field(..., description="Klucz API OpenRouter")
    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    # Routing modeli (Tier 1 -> Tier 2)
    primary_model: str = "anthropic/claude-haiku-5.5"
    escalation_model: str = "anthropic/claude-sonnet-5.5"

    # Bezpieczniki i bramka eskalacji
    escalation_confidence_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    max_tool_calls_tier1: int = Field(default=8, ge=1, le=30)
    max_tool_calls_tier2: int = Field(default=12, ge=1, le=40)
    tool_output_max_chars: int = Field(default=7000, ge=1000, le=50000)
    wmi_timeout_seconds: int = Field(default=15, ge=3, le=120)

    # Katalogi robocze
    workspace_dir: Path = Path("workspace")
    external_logs_dir: Path = Path("workspace/external_logs")
    reports_dir: Path = Path("reports")

    def ensure_directories(self) -> None:
        """Tworzy lokalne katalogi robocze (dropzone na logi i wyjściowe raporty HTML)."""
        self.external_logs_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    """Ładuje i waliduje ustawienia z pliku .env."""
    return Settings()  # type: ignore[call-arg]