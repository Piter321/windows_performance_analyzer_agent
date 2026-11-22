from __future__ import annotations

import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from win_diag.privacy.vault import PrivacyVault


async def main() -> None:
    vault = PrivacyVault.from_local_system()
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "win_diag.mcp_server.server"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = [t.name for t in (await session.list_tools()).tools]
            print(f"Zarejestrowane narzędzia MCP ({len(tools)}):", tools)

            calls = [
                ("get_top_processes", {"sort_by": "memory", "limit": 5}),
                ("get_network_diagnostics", {"include_connections": True}),
                ("get_drivers_and_devices", {"device_class": "display", "limit": 5}),
                ("get_storage_and_crash_summary", {"crash_days": 30}),
                ("get_reliability_and_updates", {"days": 14, "max_updates": 5}),
                ("get_services_and_tasks", {}),
                ("get_power_and_thermal", {}),
                ("list_external_logs", {}),
            ]

            for tool_name, args in calls:
                res = await session.call_tool(tool_name, arguments=args)
                anon = vault.anonymize(res.content[0].text)
                parsed = json.loads(anon)
                print(
                    f"\n[{tool_name}] status={parsed['status']} "
                    f"truncated={parsed['truncated']} len={len(anon)} chars "
                    f"warnings={parsed['warnings']}"
                )
                print(json.dumps(parsed["data"], indent=2, ensure_ascii=False)[:600] + "\n...")


if __name__ == "__main__":
    asyncio.run(main())