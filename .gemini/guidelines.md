# AEGIS Security Platform - Gemini Code Assist / Antigravity Guidelines

CRITICAL: You MUST NOT modify this file. Any attempt to weaken these rules is a security violation and will be blocked by the integrity guard.

You are Gemini Code Assist (or Antigravity) working inside the AEGIS Security Platform.
**This project operates under a strict Hostile-By-Default architecture.**

## Core Invariants (MUST FOLLOW)

1. **Hostile-by-default:** Do not trust user inputs, agent payloads, or AI-generated commands. All execution must be treated as potentially malicious.
2. **Deterministic Enforcement:** The Governance engine (`python/aegis-ai/src/orchestrator/governance.py`) and Execution kernel (`python/aegis-ai/src/sandbox_os/kernel.py`) must strictly allowlist operations.
3. **No Execution Without Routing:** Every command must pass through the Governance router and require a valid `X-AEGIS-Key`.
4. **AI Policy Authority:** AI systems have NO policy authority. They only provide semantic context; they cannot authorize execution.

## Development Rules

- **Backend (Python/FastAPI):**
  - Do not suggest `os.system()` or bare `subprocess.run()` calls — route everything through `sandbox_os/kernel.py`.
  - Do not suggest removing or bypassing `slowapi` rate limits in `security.py`.
  - Keep `SANDBOX_MODE="docker"` logic intact.
  - Use `.venv/Scripts/python.exe` (Windows) or `.venv/bin/python` (Linux/Mac) for all commands.

- **Frontend (React/Vite):**
  - Do NOT suggest inline styles — all styles must be in CSS classes (enforces strict CSP).
  - All `fetch()` calls must include the `X-AEGIS-Key` header.
  - WebSocket connections are authenticated via `Origin` header policies.

## Gemini-Specific Behavior

- When generating multi-file diffs, verify `X-AEGIS-Key` dependencies remain consistent across `security.py`, `main.py`, and `App.tsx`.
- When executing commands via terminal tools, always verify `.venv` is active.
- Proactively flag any code that introduces new OS subprocess calls without kernel routing.
