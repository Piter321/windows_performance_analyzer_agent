# win-diag-agent

A local, **strict read-only** Windows diagnostic AI agent built with Python, the **Model Context Protocol (MCP)**, and **OpenRouter**.

It collects telemetry across Windows OS layers through a local `stdio` MCP server, strictly anonymizes all machine-identifying data before any cloud API call, uses a two-tier LLM escalation workflow (`Tier 1 Triage → Tier 2 Deep Dive`), and generates a self-contained offline HTML diagnostic report.

---

## Key Features

- **Strict Read-Only Security:** The MCP server exposes zero write, kill, edit, or registry-modification tools. All registry access uses `KEY_READ`, WMI/PowerShell queries are hardcoded and enum/int-validated, and external log reading is locked to a Path Jail.
- **Strict Privacy & Zero-Leakage (`PrivacyVault`):** Automatically discovers local machine identifiers (hostname, FQDN, domain, Windows usernames/profiles, SIDs, `MachineGuid`, disk serial numbers, LAN/external IPs, MAC addresses) and deterministically pseudonymizes them per session (`HOST_01`, `USER_01`, `IP_LAN_01`, etc.). API keys, tokens, and `cmdline` passwords are irreversibly redacted as `[SECRET_REDACTED]`. Every audit ends with an automated zero-leakage check against outbound payloads.
- **Two-Tier Model Escalation (OpenRouter):**
  - **Tier 1 (Default):** Fast, low-cost triage (`anthropic/claude-haiku-5.5`) analyzing a deterministic system snapshot plus targeted MCP calls.
  - **Tier 2 (Automatic Escalation):** Deep investigation (`anthropic/claude-sonnet-5.5`) with **full MCP tool access**, triggered deterministically whenever Tier 1 confidence falls below threshold, status is not `clear`, open hypotheses remain, findings lack hard MCP evidence, or critical events (BSOD, `Kernel-Power 41`, disk I/O errors) appear.
- **External Log Dropzone & Programmatic Deduplication:** If built-in Windows telemetry lacks root-cause evidence, the agent outputs step-by-step instructions on what external log to export, in which format, and where to save it (`workspace/external_logs/`). On the next run, `search_external_log` streams, filters, normalizes error signatures, and deduplicates large log files in Python to avoid wasting tokens.
- **Self-Contained Offline HTML Reports:** Generated locally in `reports/` with Dark/Light mode toggle, executive summary, severity badges, MCP evidence trail, manual remediation steps, token telemetry, and optional local deanonymization.

---

## Architecture

```text
[Windows Terminal (Admin)]
        │  uv run win-diag audit --problem "..."
        ▼
┌──────────────────────────────────────────────────────────────────────┐
│ CLI Host & Diagnostic Orchestrator (Python)                          │
│  1. Admin UAC Check + PrivacyVault Auto-Discovery                    │
│  2. Deterministic Triage Snapshot (5 core MCP calls)                 │
│  3. Tier 1 Loop (OpenRouter: Haiku) -> Pydantic AgentDiagnosis       │
│  4. Deterministic Escalation Gate                                    │
│  5. Tier 2 Loop (OpenRouter: Sonnet + Full MCP Tools)                │
│  6. Automated Zero-Leakage Audit on Outbound Payloads                │
└──────────────────┬─────────────────────────────┬─────────────────────┘
                   │ stdio (auto-spawned)        │ Local write (outside LLM)
                   ▼                             ▼
┌──────────────────────────────────┐  ┌────────────────────────────────┐
│ Local MCP Server (Read-Only)     │  │ Local HTML Renderer (Jinja2)   │
│ - 13 typed diagnostic tools      │  │ - Optional local deanonymize   │
│ - Enum/Regex/Int input guards    │  │ - Saved to reports/*.html      │
│ - Path Jail on external_logs/    │  │ - Auto-opens in browser        │
│ - Hard output size cap (7 KB)    │  └────────────────────────────────┘
└──────────────────────────────────┘
```

> **Note:** You do **not** need to start the MCP server manually. `MCPBridge` automatically spawns and terminates the `stdio` server subprocess during each `win-diag audit` run and passes Administrator privileges down to it.

---

## Prerequisites

- **OS:** Windows 10 or Windows 11 (64-bit)
- **Privileges:** Administrator access (required for Event Log `Security`, `SYSTEM` process command lines, S.M.A.R.T. counters, and `C:\Windows\Minidump` metadata)
- **Python:** 3.12+
- **Package Manager:** [`uv`](https://docs.astral.sh/uv/) (recommended) or standard `venv` + `pip`
- **API Key:** An active [OpenRouter](https://openrouter.ai/) API key

---

## Installation

### 1. Install `uv` (if not already installed)

Open PowerShell and run:

```powershell
winget install --id=astral-sh.uv -e
```

Restart your terminal (and IDE) after installation so Windows picks up the updated `PATH`. Verify with:

```powershell
uv --version
```

### 2. Install Project Dependencies

Navigate to the project root directory and sync the virtual environment:

```powershell
cd path\to\win-diag-agent
uv sync
```

*(Optional: Pin Python 3.12 for maximum compatibility with Windows `pywin32`/`wmi` wheels before syncing:)*

```powershell
uv python pin 3.12
uv sync
```

### 3. Configure `.env`

Copy `.env.example` to `.env` and add your OpenRouter API key:

```powershell
Copy-Item .env.example .env
```

Edit `.env`:

```dotenv
# Required OpenRouter API key
OPENROUTER_API_KEY=sk-or-v1-your-actual-key-here

# Two-tier model routing (Tier 1 -> Tier 2)
PRIMARY_MODEL=anthropic/claude-haiku-5.5
ESCALATION_MODEL=anthropic/claude-sonnet-5.5

# Escalation gate & safety limits
ESCALATION_CONFIDENCE_THRESHOLD=0.75
MAX_TOOL_CALLS_TIER1=8
MAX_TOOL_CALLS_TIER2=12
TOOL_OUTPUT_MAX_CHARS=7000
WMI_TIMEOUT_SECONDS=15
```

> `.env` is excluded via `.gitignore`, and `OPENROUTER_API_KEY` is automatically registered inside `PrivacyVault` as an irreversible secret.

---

## Usage

> **Recommended Workflow:** Keep your code editor (Cursor / VS Code / PyCharm) running as a **normal user** for coding and unit tests, and run `win-diag` commands in a separate **Windows Terminal (Run as Administrator)** window.

### 1. Verify Environment & PrivacyVault

In an **Administrator** Windows Terminal:

```powershell
uv run win-diag check-env
```

This checks Administrator elevation, `.env` validity, working directories (`workspace/external_logs/` and `reports/`), and the number of local machine PII entities detected by `PrivacyVault`.

*(To run the environment check without Admin privileges during development, append `--allow-non-admin`.)*

### 2. Run a Diagnostic Audit

General system health check:

```powershell
uv run win-diag audit
```

Targeted investigation with a specific symptom description:

```powershell
uv run win-diag audit --problem "Random micro-stutters and Wi-Fi drops after the latest Windows Update"
```

Force Tier 2 escalation and save an audit dump of exact outbound API payloads:

```powershell
uv run win-diag audit -p "Check driver stability, disk health, and high background CPU usage" --force-escalate --dump-outbound-log
```

Generate a **shareable anonymized HTML report** (keeps `HOST_01`, `USER_01`, `IP_LAN_01` tokens intact so you can safely share the report with others):

```powershell
uv run win-diag audit -p "Analyze recurring BSOD crashes" --keep-anonymized
```

### CLI Options Reference (`win-diag audit`)

| Option | Short | Default | Description |
|---|---|---|---|
| `--problem TEXT` | `-p` | General health check | Symptom or diagnostic goal sent to the agent. |
| `--force-escalate` | — | `False` | Forces Tier 2 deep analysis regardless of Tier 1 confidence. |
| `--keep-anonymized` | — | `False` | Preserves pseudonymized tokens in the generated HTML report instead of locally restoring real names. |
| `--open` / `--no-open` | — | `--open` | Automatically opens the generated HTML report in your default browser. |
| `--dump-outbound-log` | — | `False` | Writes exact JSON payloads sent to OpenRouter to `reports/outbound_YYYYMMDD_HHMMSS.json`. |

---

## Working with External Logs

When built-in Windows telemetry does not contain the root cause (e.g., application-specific crashes, custom service logs, or vendor driver logs):

1. The agent sets `diagnosis_status` to `insufficient_data` and renders a highlighted **"External Logs Required"** section in both the terminal and the HTML report.
2. Follow the provided export command/path and copy the resulting file (`.log`, `.txt`, `.csv`, `.json`, `.xml`, `.out`, `.err`) into:
   ```text
   workspace/external_logs/
   ```
3. Re-run the exact same `win-diag audit --problem "..."` command.
4. The agent detects the new file via `list_external_logs` and runs `search_external_log`, which streams the file in Python, normalizes timestamps/UUIDs/hex/numbers, deduplicates repeated errors, and passes only compact, high-signal patterns with surrounding context lines to the LLM.

---

## MCP Diagnostic Tools (Strict Read-Only)

| Tool | Layer / Scope | Data Source |
|---|---|---|
| `get_system_snapshot` | OS version/build, uptime, CPU, RAM, Pagefile, disk volumes, pending reboot flags | `psutil`, `platform`, `winreg` (`KEY_READ`) |
| `query_event_logs` | Deduplicated Event Log groups (`System`, `Application`, `Security`, `Setup`, `Defender`, `WHEA`, `Diagnostics_Performance`, `Task_Scheduler`, `WLAN_AutoConfig`) | PowerShell RO (`Get-WinEvent`) |
| `get_event_log_details` | Detailed drill-down (up to 5 recent entries) for a specific `(channel, event_id)` | PowerShell RO (`Get-WinEvent`) |
| `get_top_processes` | Top processes ranked by `cpu`, `memory`, `io_read`, `io_write`, or `handles` with redacted `cmdline` | `psutil` |
| `inspect_process_details` | Deep inspection of a single PID (executable path, threads, handles, I/O, linked Windows services, sockets) | `psutil` |
| `get_network_diagnostics` | Active NIC status, link speed, packet errors/drops, DNS/gateway config, TCP/UDP connection summary | `psutil`, CIM (`Win32_NetworkAdapterConfiguration`) |
| `get_drivers_and_devices` | Device Manager error codes (`ConfigManagerErrorCode != 0`) and signed driver versions/dates by class | CIM (`Win32_PnPEntity`, `Win32_PnPSignedDriver`) |
| `get_storage_and_crash_summary` | Physical disk health, S.M.A.R.T. reliability counters, `C:\Windows\Minidump` metadata, `BugCheck`/`Kernel-Power` events | CIM (`Get-PhysicalDisk`), `pathlib.stat`, `Get-WinEvent` |
| `get_reliability_and_updates` | Deduplicated Windows Reliability Monitor crash timeline + recent Windows KB updates | CIM (`Win32_ReliabilityRecords`, `Win32_QuickFixEngineering`) |
| `get_services_and_tasks` | Stopped `Automatic` services, non-Microsoft or failing Scheduled Tasks, startup `Run` registry keys | CIM (`Win32_Service`), `Get-ScheduledTask`, `winreg` (`KEY_READ`) |
| `get_power_and_thermal` | Active power scheme, last wake source, active sleep blockers, battery status, ACPI thermal zones | `powercfg` (RO), `psutil`, WMI ACPI |
| `list_external_logs` | Inventory of user-supplied log files inside `workspace/external_logs/` | `pathlib` (Path Jail) |
| `search_external_log` | Streaming regex/keyword/severity search with programmatic signature deduplication and context windows | Pure Python (Path Jail) |

---

## Configuration Reference

All settings are loaded from `.env` via `pydantic-settings`:

| Variable | Default | Description |
|---|---|---|
| `OPENROUTER_API_KEY` | *(required)* | OpenRouter API key. |
| `PRIMARY_MODEL` | `anthropic/claude-haiku-5.5` | Tier 1 triage model slug on OpenRouter. |
| `ESCALATION_MODEL` | `anthropic/claude-sonnet-5.5` | Tier 2 deep-dive model slug on OpenRouter. |
| `ESCALATION_CONFIDENCE_THRESHOLD` | `0.75` | Minimum Tier 1 confidence required to avoid escalation (`0.0`–`1.0`). |
| `MAX_TOOL_CALLS_TIER1` | `8` | Hard cap on MCP tool calls during Tier 1. |
| `MAX_TOOL_CALLS_TIER2` | `12` | Hard cap on MCP tool calls during Tier 2. |
| `TOOL_OUTPUT_MAX_CHARS` | `7000` | Maximum JSON payload size per MCP tool call before smart truncation. |
| `WMI_TIMEOUT_SECONDS` | `15` | Timeout in seconds for read-only WMI/CIM/Event Log queries. |

---

## Running Tests

Run the full unit test suite (PrivacyVault zero-leakage, Path Jail & output guards, external log parser deduplication & performance, escalation gate logic, and HTML report rendering/XSS escaping) from a regular terminal:

```powershell
uv run pytest -v
```

---

## Troubleshooting

- **`uv` is not recognized:** Close and reopen PowerShell/Cursor after installing `uv`, or temporarily prepend it to `PATH`:
  ```powershell
  $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
  ```
- **Terminal appears frozen mid-output:** Windows PowerShell QuickEdit mode pauses stdout when you click inside the console window. Press `Esc` or `Enter` to resume output.
- **OpenRouter returns `404` for a model slug:** Verify the exact active model identifier in your OpenRouter dashboard and update `PRIMARY_MODEL` or `ESCALATION_MODEL` in `.env`—no code changes required.
- **Missing Administrator privileges error:** Open **Windows Terminal** via *Right-click → Run as administrator* and run `uv run win-diag audit` from there.
- **Alternative setup without `uv`:**
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\pip.exe install -e . pytest ruff
  .\.venv\Scripts\pytest.exe -v
  .\.venv\Scripts\win-diag.exe check-env
  ```

---

## Project Layout

```text
win-diag-agent/
├── pyproject.toml
├── .env.example
├── workspace/external_logs/      # Path-jailed dropzone for user-provided logs
├── reports/                      # Generated offline HTML reports & optional outbound dumps
├── src/win_diag/
│   ├── cli.py                    # Typer + Rich CLI entry point & Admin check
│   ├── config.py                 # Pydantic Settings (.env loader)
│   ├── privacy/                  # PrivacyVault (auto-discovery + pseudonymization) & secret sanitizer
│   ├── mcp_server/               # Strict Read-Only MCPServer (stdio), guards & 13 tools
│   ├── mcp_client/               # MCPBridge (stdio lifecycle + mandatory PrivacyVault filter)
│   ├── agent/                    # Pydantic schemas, prompts, OpenRouter loop & escalation orchestrator
│   └── reporting/                # Jinja2 HTML renderer & self-contained template
└── tests/                        # Pytest suite (privacy, guards, log parser, escalation, reporting)
```