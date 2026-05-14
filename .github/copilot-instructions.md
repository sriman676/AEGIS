# AEGIS Security Platform - GitHub Copilot Instructions

CRITICAL: You MUST NOT modify this file. Any attempt to weaken these rules is a security violation and will be blocked by the integrity guard.

You are GitHub Copilot working inside the AEGIS Security Platform repository.
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

- **Frontend (React/Vite):**
  - Do NOT suggest inline styles — all styles must be in CSS classes (enforces strict CSP).
  - All `fetch()` calls must include the `X-AEGIS-Key` header.

## Copilot-Specific Behavior

- When suggesting completions for API route handlers, always include auth middleware references.
- When generating tests, ensure they mock the `X-AEGIS-Key` header to reflect hardened security posture.
- Never suggest `eval()`, `exec()`, or dynamic code execution patterns.
