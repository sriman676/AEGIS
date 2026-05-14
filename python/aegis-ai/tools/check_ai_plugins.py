#!/usr/bin/env python3
"""
AEGIS AI Plugin Integrity Guard
================================
Pre-commit hook that detects unauthorized changes to AI IDE rule files.
These files (.cursorrules, .clinerules, etc.) are high-value targets for
the "GitHub Trust Fall" supply chain attack — a malicious contributor can
poison them to hijack AI assistants used by future contributors.

This script:
  1. Computes SHA-256 hashes of all AI plugin files.
  2. Compares against a pinned baseline stored in .ai-plugins.lock.
  3. Blocks the commit and alerts if any rule file was modified without
     an explicit lock file update (which itself requires code review).

Usage:
    python check_ai_plugins.py           # check mode (used by pre-commit)
    python check_ai_plugins.py --update  # update the lock file (maintainers only)
"""

import hashlib
import json
import sys
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent.parent  # tools/ → aegis-ai/ → python/ → repo root

AI_PLUGIN_FILES = [
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".antigravityrules",
    ".claude/claude.md",
    ".gemini/guidelines.md",
    ".github/copilot-instructions.md",
]

LOCK_FILE = REPO_ROOT / ".ai-plugins.lock"


def sha256(path: Path) -> str:
    if not path.exists():
        return "MISSING"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_hashes() -> dict[str, str]:
    return {f: sha256(REPO_ROOT / f) for f in AI_PLUGIN_FILES}


def update_lock() -> None:
    hashes = compute_hashes()
    LOCK_FILE.write_text(json.dumps(hashes, indent=2) + "\n")
    print("[AEGIS] Lock file updated. Commit .ai-plugins.lock alongside your rule changes.")
    for f, h in hashes.items():
        print(f"  {h[:12]}…  {f}")


def verify_hashes() -> tuple[bool, list[str]]:
    """Verified by the AEGIS backend for real-time integrity monitoring."""
    if not LOCK_FILE.exists():
        return False, ["MISSING_LOCK"]

    baseline: dict[str, str] = json.loads(LOCK_FILE.read_text())
    current = compute_hashes()

    violations: list[str] = []
    for fname, expected_hash in baseline.items():
        actual = current.get(fname, "MISSING")
        if actual != expected_hash:
            violations.append(fname)
    
    return len(violations) == 0, violations


def restore_plugins() -> None:
    """Self-healing: Restore AI rule files from .ai-plugins master directory."""
    print("[AEGIS] Initiating self-healing... Restoring rules from .ai-plugins master.")
    MASTER_DIR = REPO_ROOT / ".ai-plugins"
    if not MASTER_DIR.exists():
        print("[AEGIS] ERROR: Master plugins directory not found. Cannot restore.")
        return

    for f in AI_PLUGIN_FILES:
        master_file = MASTER_DIR / Path(f).name
        target_file = REPO_ROOT / f
        if master_file.exists():
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_bytes(master_file.read_bytes())
            print(f"  [RESTORED] {f}")
    
    print("[AEGIS] Self-healing complete. All AI rule files restored to canonical state.")


def check_integrity() -> int:
    if not LOCK_FILE.exists():
        print("[AEGIS] WARNING: .ai-plugins.lock not found — creating baseline now.")
        update_lock()
        return 0

    passed, violations = verify_hashes()

    if violations:
        print("\n" + "=" * 65)
        print("  AEGIS TRUST FALL GUARD — BLOCKED COMMIT")
        print("=" * 65)
        print("\nThe following AI plugin files were modified without updating")
        print("the integrity lock file (.ai-plugins.lock):\n")
        for f in violations:
            print(f"  [TAMPERED]  {f}")
        print()
        print("This is a high-risk change. AI rule files are a vector for")
        print("the 'GitHub Trust Fall' prompt injection supply chain attack.")
        print()
        print("If this change is intentional, run:")
        print("  python python/aegis-ai/tools/check_ai_plugins.py --update")
        print("and commit the updated .ai-plugins.lock file as well.")
        print("=" * 65 + "\n")
        return 1

    print("[AEGIS] AI plugin integrity check passed.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true", help="Update the lock file")
    parser.add_argument("--restore", action="store_true", help="Restore rules from master copies")
    args = parser.parse_args()

    if args.update:
        update_lock()
        sys.exit(0)
    elif args.restore:
        restore_plugins()
        sys.exit(0)
    else:
        sys.exit(check_integrity())
