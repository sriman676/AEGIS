# Security Policy — AEGIS Security Platform

## Reporting a Vulnerability

If you discover a security vulnerability in AEGIS, **do not open a public GitHub Issue**.

Please report it via GitHub's private vulnerability reporting:
**Settings → Security → Advisories → Report a vulnerability**

We will acknowledge the report within **48 hours** and aim to patch critical issues within **7 days**.

---

## Known Attack Vectors & Mitigations

### 1. GitHub Trust Fall (AI IDE Prompt Injection via Rule Files)

**What it is:**
The "Trust Fall" is a supply chain attack where a malicious contributor modifies an AI IDE rule file (`.cursorrules`, `.clinerules`, `.claude/claude.md`, etc.) to inject hidden instructions into the AI assistant of anyone who subsequently opens the repository. The AI will silently follow these instructions — exfiltrating code, inserting backdoors, or bypassing security reviews.

**Attack vectors in this repo:**

| File | Risk if Tampered |
|---|---|
| `.cursorrules` | Cursor AI hijacked for all contributors |
| `.windsurfrules` | Windsurf AI hijacked |
| `.clinerules` | Cline/Roo agent hijacked |
| `.claude/claude.md` | Claude Code hijacked |
| `.gemini/guidelines.md` | Gemini Code Assist hijacked |
| `.github/copilot-instructions.md` | GitHub Copilot hijacked |
| `.antigravityrules` | Antigravity AI hijacked |

**AEGIS Mitigations:**

1. **`.ai-plugins.lock`** — SHA-256 integrity fingerprint of all rule files. Any change to a rule file without updating the lock file is **blocked at commit time** by `pre-commit`.
2. **CI Enforcement** — The `AI Plugin Integrity (Trust Fall Guard)` job runs first in every CI pipeline. All other jobs (`needs: ai-plugin-integrity`) are blocked if this check fails.
3. **Branch Protection Ruleset** — `main` requires this CI check to pass before any PR can merge (see `.github/rulesets/main-branch-protection.json`).
4. **Reviewer responsibility** — All PRs touching any AI plugin file MUST be scrutinized by a maintainer for hidden instructions or instruction override patterns.

**What AEGIS cannot protect against:**
- A developer opening a **different** malicious repository in their IDE. Rules from that repo will load regardless of AEGIS's posture.
- A developer running `git commit --no-verify` to bypass the pre-commit hook locally. The CI job is the backstop in this case.
- An attacker with **write access to `main`** who bypasses PR review. Enforce branch protection rules strictly.

**Reviewer checklist for AI plugin file changes:**
- [ ] Does the change add any instruction to ignore previous safety constraints?
- [ ] Does the change instruct the AI to send data to external URLs?
- [ ] Does the change lower restrictions on subprocess, eval, or exec usage?
- [ ] Does the change remove hostile-by-default invariants?
- [ ] Is `.ai-plugins.lock` updated in the same commit?

---

### 2. API Key Exposure (X-AEGIS-Key)

The `AEGIS_API_KEY` is auto-generated at startup if not set. In production:
- Store it in a secrets manager (GitHub Secrets, HashiCorp Vault, AWS Secrets Manager).
- Never commit it to `.env` files in the repository.
- Rotate it if you suspect it has been observed in logs or CI output.

---

### 3. Prompt Injection via Orchestration API

The `/orchestrate/route` endpoint accepts natural language context. Malicious payloads that attempt to override governance policies are blocked by:
- The `evaluate_request()` governance function (capability allowlist)
- The Semantic Analyzer's MITRE ATT&CK pattern matcher
- Rate limiting via `slowapi`

If you find a bypass for any of these layers, report it via the vulnerability disclosure process above.

---

### 4. Execution Kernel Escape

The `sandbox_os/kernel.py` enforces a strict command allowlist. Attempts to execute unlisted binaries or pass banned arguments (e.g., `-c`, `eval`, `curl`) are rejected before any subprocess is spawned.

In production, set `SANDBOX_MODE=docker` to enforce OS-level container isolation.

---

## Supported Versions

| Component | Supported |
|---|---|
| Python backend (`python/aegis-ai`) | ✅ Latest only |
| React dashboard (`dashboard/`) | ✅ Latest only |
| Rust crates (`crates/`) | ✅ Latest only |

---

## Activating Branch Protection (Maintainers)

After pushing to GitHub, activate the branch protection ruleset:

1. Go to **Settings → Rules → Rulesets**
2. Click **Import Ruleset**
3. Upload `.github/rulesets/main-branch-protection.json`
4. Click **Create**

This ensures the `AI Plugin Integrity (Trust Fall Guard)` CI check is a **required status check** — no PR can merge without it passing.
