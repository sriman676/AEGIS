# AEGIS AI Plugin Suite

This folder is the **canonical source of truth** for all AI IDE context rules in the AEGIS Security Platform. Every AI assistant that opens this repository will be automatically governed by these instructions.

> **Why a folder?** Each AI IDE enforces a specific filename and location (e.g., Cursor requires `.cursorrules` at root). The files in the repo root / subdirectories are the live stubs the IDEs read — this folder holds the human-readable master copies for documentation, review, and editing.

---

## Plugin Map

| AI IDE / Tool | Live File (auto-loaded by IDE) | Master Copy Here |
|---|---|---|
| **Cursor** | `/.cursorrules` | `cursor.md` |
| **Windsurf** | `/.windsurfrules` | `windsurf.md` |
| **Cline / Roo** | `/.clinerules` | `cline.md` |
| **Antigravity** | `/.antigravityrules` | `antigravity.md` |
| **Claude Code** | `/.claude/claude.md` | `claude.md` |
| **Gemini Code Assist** | `/.gemini/guidelines.md` | `gemini.md` |
| **GitHub Copilot** | `/.github/copilot-instructions.md` | `copilot.md` |

---

## Architecture: Hostile-By-Default

All rules enforce the following invariants. **No AI assistant may bypass these.**

1. **Hostile-by-default** — Every input is treated as potentially malicious.
2. **Deterministic Enforcement** — Governance engine + Execution Kernel strictly allowlist all operations.
3. **No Execution Without Routing** — Every command requires a valid `X-AEGIS-Key`.
4. **AI Has No Policy Authority** — AI provides semantic context only; it cannot authorize execution.

---

## AEGIS Guardian Daemon

The background threat monitor lives at `python/aegis-ai/aegis_guardian.py`.

- **What it does:** Connects to the AEGIS WebSocket telemetry stream and fires **native OS notifications** whenever an attack is blocked.
- **Auto-starts:** Registered via Windows Task Scheduler (`install.ps1`), systemd (Linux `install.sh`), or LaunchAgent (macOS `install.sh`) on first install.
- **Cross-platform:** Windows (win11toast), macOS (osascript), Linux (notify-send).

---

## Updating Rules

1. Edit the master copy in this folder (e.g., `cursor.md`).
2. Copy the changes to the corresponding live file at the root/subfolder path shown in the Plugin Map above.
3. Commit both files together.
