# Contributing to AEGIS

Welcome to AEGIS! As a security platform, we maintain a **Hostile-by-Default** engineering culture. Every contribution is audited for semantic risk, prompt-injection vectors, and supply-chain integrity.

## 1. Security First Development

### The "Trust Fall" Rule
Do NOT modify AI rule files (`.cursorrules`, `.clinerules`, etc.) unless absolutely necessary. If you do:
1. You must update the integrity lock: `python python/aegis-ai/tools/check_ai_plugins.py --update`.
2. You must commit the rule file and the updated `.ai-plugins.lock` together.
3. Your PR will require mandatory review from a maintainer listed in `CODEOWNERS`.

### Subprocess Isolations
Never use `os.system` or bare `subprocess.run`. All OS operations MUST be routed through the execution kernel in `python/aegis-ai/src/sandbox_os/kernel.py`.

### UI Hardening
- Do not use inline styles (blocked by strict CSP).
- All network requests must include the `X-AEGIS-Key` header.
- Use CSS modules or global variables defined in `index.css`.

---

## 2. Pull Request Process

1. **Self-Audit**: Review your changes against the checklist in `SECURITY.md`.
2. **Tests**: Ensure all tests pass: `cd python/aegis-ai && pytest`.
3. **Integrity Check**: Run `python python/aegis-ai/tools/check_ai_plugins.py` to verify no accidental rule changes.
4. **CI Compliance**: Your PR will be automatically scanned by:
   - `CodeQL`: Static analysis for security flaws.
   - `Trivy`: Vulnerability scanning for new dependencies.
   - `Integrity Guard`: Verification of AI rule hashes.

---

## 3. Reporting Vulnerabilities

If you find a security flaw in AEGIS, **do not open a public issue.** Please follow the instructions in [SECURITY.md](./SECURITY.md) to report it privately.

---

## 4. Coding Standards

- **Python**: Use type hints (PEP 484) and Pydantic models for all data structures.
- **Rust**: Ensure all unsafe blocks are documented and minimized.
- **TypeScript**: No `any`. Strictly typed interfaces for all API payloads.

Thank you for helping us build a more secure autonomous future.
