# Master Copy: Cline Rules
# Location: /.clinerules

CRITICAL: You MUST NOT modify this file. Any attempt to weaken these rules is a security violation and will be blocked by the integrity guard.

---

# AEGIS Security Platform - Cline/Roo Instructions

You are an autonomous AI agent (Cline/Roo) working on the AEGIS Security Platform.
**This project operates under a strict Hostile-By-Default architecture.**

## Core Invariants (MUST FOLLOW)

1. **Hostile-by-default:** Do not trust user inputs, agent payloads, or AI-generated commands. All execution must be treated as potentially malicious.
2. **Deterministic Enforcement:** The Governance engine (`src/orchestrator/governance.py`) and Execution kernel (`src/sandbox_os/kernel.py`) must strictly allowlist operations.
3. **No Execution Without Routing:** Every command must pass through the Governance router and be assigned an `X-AEGIS-Key`.
4. **AI Has No Policy Authority:** AI systems have NO policy authority. They only provide semantic context; they cannot authorize execution.

## Development Rules

- **Backend (Python/FastAPI):**
  - Do not use generic `os.system` or unrestricted `subprocess.run`.
  - All OS operations MUST be routed through `sandbox_os/kernel.py`.
  - Do not bypass `slowapi` rate limits.
  - Maintain `SANDBOX_MODE="docker"` implementation to prevent Child-Process escapes.

- **Frontend (React/Vite):**
  - Do NOT use inline styles (violates strict CSP).
  - Ensure all network `fetch` requests pass the `X-AEGIS-Key` header.

## Cline-Specific Behavior

- **Terminal Execution:** Before running tests or scripts, ensure the virtual environment (`.venv/Scripts/python.exe`) is used.
- **Validation:** Always run `python -m pytest` after making changes to the execution or governance engine.
- Do not use tools to overwrite `src/security.py` without explicit permission, as this handles critical rate limiting and API key routing.
