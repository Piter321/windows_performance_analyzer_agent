from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from contextlib import AsyncExitStack
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console

from win_diag.config import Settings
from win_diag.privacy.vault import PrivacyVault


class MCPBridge:
    """Zarządza lokalnym procesem serwera MCP (stdio) i anonimizuje 100% jego odpowiedzi."""

    def __init__(
        self,
        settings: Settings,
        vault: PrivacyVault,
        console: Console | None = None,
    ) -> None:
        self._settings = settings
        self._vault = vault
        self._console = console or Console()
        self._exit_stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None
        self._openai_tools: list[dict[str, Any]] = []

    async def __aenter__(self) -> MCPBridge:
        server_env = os.environ.copy()
        server_env["TOOL_OUTPUT_MAX_CHARS"] = str(self._settings.tool_output_max_chars)
        server_env["WMI_TIMEOUT_SECONDS"] = str(self._settings.wmi_timeout_seconds)
        server_env["EXTERNAL_LOGS_DIR"] = str(self._settings.external_logs_dir.resolve())
        server_env["PYTHONUNBUFFERED"] = "1"
        server_env["PYTHONUTF8"] = "1"

        server_params = StdioServerParameters(
            command=sys.executable,
            args=["-u", "-m", "win_diag.mcp_server.server"],
            env=server_env,
        )

        self._exit_stack = AsyncExitStack()
        try:
            self._console.print(f"[dim]• Uruchamianie serwera MCP ({sys.executable})...[/dim]")
            read_stream, write_stream = await self._exit_stack.enter_async_context(
                stdio_client(server_params)
            )
            self._session = await self._exit_stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )

            self._console.print("[dim]• Handshake MCP (initialize)...[/dim]")
            await asyncio.wait_for(self._session.initialize(), timeout=20.0)

            self._console.print("[dim]• Pobieranie listy narzędzi MCP (list_tools)...[/dim]")
            tools_response = await asyncio.wait_for(self._session.list_tools(), timeout=15.0)

            self._openai_tools = []
            for tool in tools_response.tools:
                # Kompatybilność mcp 2.x (input_schema) oraz 1.x (inputSchema)
                raw_schema = getattr(tool, "input_schema", None) or getattr(
                    tool, "inputSchema", None
                )
                if not isinstance(raw_schema, dict) or "type" not in raw_schema:
                    raw_schema = {"type": "object", "properties": {}}

                self._openai_tools.append(
                    {
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description
                            or f"Narzędzie diagnostyczne MCP: {tool.name}",
                            "parameters": raw_schema,
                        },
                    }
                )

            self._console.print(
                f"[dim]• Serwer MCP gotowy ({len(self._openai_tools)} narzędzi).[/dim]"
            )
            return self
        except BaseException:
            # Wyjątek w __aenter__ nie wywołuje __aexit__ — musimy jawnie zamknąć podproces i potoki
            await self._exit_stack.aclose()
            self._exit_stack = None
            self._session = None
            raise

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._exit_stack is not None:
            await self._exit_stack.aclose()
            self._exit_stack = None
            self._session = None

    @property
    def openai_tools(self) -> list[dict[str, Any]]:
        """Zwraca definicje narzędzi MCP w formacie oczekiwanym przez OpenRouter/OpenAI."""
        return self._openai_tools

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Wywołuje narzędzie MCP i zwraca (zanonimizowany_tekst_json, metadane_wywołania)."""
        if self._session is None:
            raise RuntimeError("MCPBridge nie został zainicjalizowany (użyj 'async with').")

        safe_args = arguments or {}
        started = time.monotonic()
        call_timeout = max(30.0, float(self._settings.wmi_timeout_seconds) + 15.0)

        try:
            result = await asyncio.wait_for(
                self._session.call_tool(tool_name, arguments=safe_args),
                timeout=call_timeout,
            )
            parts: list[str] = []
            for block in result.content:
                text_val = getattr(block, "text", None)
                if text_val is not None:
                    parts.append(str(text_val))
            raw_text = "\n".join(parts) if parts else "{}"
        except TimeoutError:
            raw_text = json.dumps(
                {
                    "status": "error",
                    "data": {
                        "error": f"Timeout ({call_timeout:.0f}s) podczas wywołania MCP '{tool_name}'."
                    },
                },
                ensure_ascii=False,
            )
        except Exception as exc:
            raw_text = json.dumps(
                {
                    "status": "error",
                    "data": {"error": f"Błąd wywołania MCP '{tool_name}': {exc}"},
                },
                ensure_ascii=False,
            )

        duration_ms = int((time.monotonic() - started) * 1000)

        # KRYTYCZNE: 100% danych z MCP przechodzi przez PrivacyVault przed kontaktem z LLM
        anonymized_text = self._vault.anonymize(raw_text)

        status = "ok"
        truncated = False
        try:
            parsed = json.loads(anonymized_text)
            if isinstance(parsed, dict):
                status = str(parsed.get("status", "ok"))
                truncated = bool(parsed.get("truncated", False))
        except json.JSONDecodeError:
            status = "raw"

        meta = {
            "tool_name": tool_name,
            "arguments": self._vault.anonymize_data(safe_args),
            "duration_ms": duration_ms,
            "status": status,
            "truncated": truncated,
            "output_chars": len(anonymized_text),
        }
        return anonymized_text, meta

    async def collect_initial_snapshot(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Faza 1: Deterministyczny Triage Snapshot bez zużywania kroków LLM."""
        snapshot_calls: list[tuple[str, dict[str, Any]]] = [
            ("get_system_snapshot", {}),
            (
                "query_event_logs",
                {"channel": "System", "hours": 24, "min_level": "error", "max_groups": 15},
            ),
            (
                "query_event_logs",
                {"channel": "Application", "hours": 24, "min_level": "error", "max_groups": 15},
            ),
            ("get_top_processes", {"sort_by": "cpu", "limit": 8}),
            ("list_external_logs", {}),
        ]

        snapshot_bundle: dict[str, Any] = {}
        call_metas: list[dict[str, Any]] = []

        for idx, (tool_name, args) in enumerate(snapshot_calls):
            label = f"{tool_name}({args.get('channel', '')})" if "channel" in args else tool_name
            self._console.print(f"  [dim]⚙ Snapshot: {label}...[/dim]")
            anon_text, meta = await self.call_tool(tool_name, args)
            call_metas.append(meta)
            key = f"{tool_name}_{args['channel'].lower()}" if "channel" in args else tool_name
            try:
                snapshot_bundle[key] = json.loads(anon_text)
            except json.JSONDecodeError:
                snapshot_bundle[key] = {"raw": anon_text, "idx": idx}

        return snapshot_bundle, call_metas