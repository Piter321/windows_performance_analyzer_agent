from __future__ import annotations

import json
import re
from typing import Any

from openai import AsyncOpenAI
from pydantic import ValidationError
from rich.console import Console

from win_diag.agent.schemas import AgentDiagnosis, TokenUsage, ToolCallAudit
from win_diag.config import Settings
from win_diag.mcp_client.bridge import MCPBridge
from win_diag.privacy.vault import PrivacyVault

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)


def _extract_json_object(raw_text: str) -> dict[str, Any]:
    """Wyciąga obiekt JSON z odpowiedzi modelu (obsługuje czysty JSON i bloki ```json)."""
    cleaned = raw_text.strip()
    if not cleaned:
        raise ValueError("Model zwrócił pustą odpowiedź tekstową.")

    # 1. Bezpośredni JSON
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # 2. Blok ```json ... ```
    fence_match = _JSON_FENCE_RE.search(cleaned)
    if fence_match:
        parsed = json.loads(fence_match.group(1))
        if isinstance(parsed, dict):
            return parsed

    # 3. Pierwszy otwierający '{' do ostatniego zamykającego '}'
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        parsed = json.loads(cleaned[start : end + 1])
        if isinstance(parsed, dict):
            return parsed

    raise ValueError("Nie znaleziono poprawnego obiektu JSON w odpowiedzi modelu.")


class OpenRouterAgentRunner:
    """Klient OpenRouter z deterministyczną pętlą tool-callingu MCP i pełnym logowaniem API."""

    def __init__(
        self,
        settings: Settings,
        bridge: MCPBridge,
        vault: PrivacyVault,
        console: Console | None = None,
    ) -> None:
        self._settings = settings
        self._bridge = bridge
        self._vault = vault
        self._console = console or Console()
        self._client = AsyncOpenAI(
            api_key=settings.openrouter_api_key.get_secret_value(),
            base_url=settings.openrouter_base_url,
            default_headers={
                "HTTP-Referer": "https://localhost/win-diag-agent",
                "X-Title": "win-diag-agent",
            },
        )

    async def run_tier(
        self,
        *,
        tier_label: str,
        model: str,
        system_prompt: str,
        user_payload: str,
        max_tool_calls: int,
    ) -> tuple[AgentDiagnosis, list[ToolCallAudit], TokenUsage, list[dict[str, Any]]]:
        """Uruchamia pętlę wnioskowania dla danego poziomu (Tier 1 lub Tier 2)."""
        # Defense-in-depth: anonimizacja również na wejściu przed wysłaniem do OpenRoutera
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": self._vault.anonymize(user_payload)},
        ]

        tool_audits: list[ToolCallAudit] = []
        usage = TokenUsage()
        outbound_log: list[dict[str, Any]] = []
        tool_calls_used = 0
        final_text = ""

        # Maksymalna liczba rund = max_tool_calls + 2 (runda zamykająca + ewentualna naprawa JSON)
        for step_idx in range(1, max_tool_calls + 3):
            allow_tools = tool_calls_used < max_tool_calls
            request_kwargs: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "temperature": 0.1,
            }
            if allow_tools:
                request_kwargs["tools"] = self._bridge.openai_tools
                request_kwargs["tool_choice"] = "auto"

            # Rejestracja dokładnego payloadu wychodzącego do późniejszego audytu prywatności
            outbound_log.append(
                {
                    "tier": tier_label,
                    "step": step_idx,
                    "model": model,
                    "messages": json.loads(json.dumps(messages, ensure_ascii=False)),
                }
            )

            self._console.print(
                f"[dim]→ [{tier_label}] Wywołanie OpenRouter ({model}), krok {step_idx}, "
                f"narzędzia: {tool_calls_used}/{max_tool_calls}[/dim]"
            )

            response = await self._client.chat.completions.create(**request_kwargs)

            # Wymagany wydruk odpowiedzi API w konsoli przy każdym wywołaniu
            print(f"\n=== [API RESPONSE | {tier_label} | {model} | step {step_idx}] ===")
            print(response.model_dump_json(indent=2))
            print("=== [END API RESPONSE] ===\n")

            if response.usage:
                usage.add(
                    prompt=int(response.usage.prompt_tokens or 0),
                    completion=int(response.usage.completion_tokens or 0),
                    total=int(response.usage.total_tokens or 0),
                )

            choice = response.choices[0]
            msg = choice.message

            # Zapis odpowiedzi asystenta w historii konwersacji
            assistant_entry: dict[str, Any] = {
                "role": "assistant",
                "content": msg.content or "",
            }
            if msg.tool_calls:
                assistant_entry["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ]
            messages.append(assistant_entry)

            # Obsługa wywołań narzędzi MCP
            if msg.tool_calls and allow_tools:
                for tc in msg.tool_calls:
                    if tool_calls_used >= max_tool_calls:
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tc.id,
                                "content": json.dumps(
                                    {
                                        "status": "limit_reached",
                                        "data": {
                                            "error": "Osiągnięto limit wywołań narzędzi dla tego poziomu. Podsumuj diagnozę na podstawie zebranych danych."
                                        },
                                    },
                                    ensure_ascii=False,
                                ),
                            }
                        )
                        continue

                    tool_name = tc.function.name
                    try:
                        parsed_args = json.loads(tc.function.arguments or "{}")
                        if not isinstance(parsed_args, dict):
                            parsed_args = {}
                    except json.JSONDecodeError:
                        parsed_args = {}

                    self._console.print(
                        f"  [cyan]⚙ MCP [{tier_label}]:[/cyan] {tool_name}({json.dumps(parsed_args, ensure_ascii=False)})"
                    )
                    anon_result, meta = await self._bridge.call_tool(tool_name, parsed_args)
                    tool_calls_used += 1

                    tool_audits.append(
                        ToolCallAudit(
                            tier=tier_label,
                            model=model,
                            tool_name=meta["tool_name"],
                            arguments=meta["arguments"],
                            duration_ms=meta["duration_ms"],
                            status=meta["status"],
                            truncated=meta["truncated"],
                            output_chars=meta["output_chars"],
                        )
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": anon_result,
                        }
                    )

                if tool_calls_used >= max_tool_calls:
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Osiągnięto limit wywołań narzędzi MCP dla tego etapu. "
                                "Zwróć teraz wyłącznie końcowy obiekt JSON zgodny ze schematem AgentDiagnosis."
                            ),
                        }
                    )
                continue

            # Brak tool_calls → model zwrócił końcową diagnozę
            final_text = msg.content or ""
            break

        # Parsowanie i walidacja Pydantic (z 1 próbą automatycznej naprawy JSON-a)
        diagnosis = await self._parse_or_repair_diagnosis(
            raw_text=final_text,
            tier_label=tier_label,
            model=model,
            messages=messages,
            usage=usage,
            outbound_log=outbound_log,
        )
        return diagnosis, tool_audits, usage, outbound_log

    async def _parse_or_repair_diagnosis(
        self,
        *,
        raw_text: str,
        tier_label: str,
        model: str,
        messages: list[dict[str, Any]],
        usage: TokenUsage,
        outbound_log: list[dict[str, Any]],
    ) -> AgentDiagnosis:
        try:
            data = _extract_json_object(raw_text)
            return AgentDiagnosis.model_validate(data)
        except (ValueError, ValidationError, json.JSONDecodeError) as first_err:
            self._console.print(
                f"[yellow]⚠ [{tier_label}] Niepoprawny JSON diagnozy — uruchamiam próbę korekty schematu.[/yellow]"
            )
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"Twoja poprzednia odpowiedź nie przeszła walidacji schematu Pydantic: {first_err}\n"
                        "Zwróć teraz WYŁĄCZNIE poprawny obiekt JSON zgodny ze schematem AgentDiagnosis, "
                        "bez żadnego tekstu przed ani po obiekcie JSON."
                    ),
                }
            )
            outbound_log.append(
                {
                    "tier": tier_label,
                    "step": "schema_repair",
                    "model": model,
                    "messages": json.loads(json.dumps(messages, ensure_ascii=False)),
                }
            )

            repair_resp = await self._client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.0,
            )

            print(f"\n=== [API RESPONSE | {tier_label} | {model} | schema_repair] ===")
            print(repair_resp.model_dump_json(indent=2))
            print("=== [END API RESPONSE] ===\n")

            if repair_resp.usage:
                usage.add(
                    prompt=int(repair_resp.usage.prompt_tokens or 0),
                    completion=int(repair_resp.usage.completion_tokens or 0),
                    total=int(repair_resp.usage.total_tokens or 0),
                )

            repaired_text = repair_resp.choices[0].message.content or ""
            data = _extract_json_object(repaired_text)
            return AgentDiagnosis.model_validate(data)