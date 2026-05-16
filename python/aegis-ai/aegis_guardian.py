#!/usr/bin/env python3
"""
AEGIS Guardian — Background Security Daemon
============================================
Runs continuously in the background after repo clone/install.
Monitors the AEGIS API for blocked threats and fires OS desktop
notifications so developers are alerted in real-time.

Usage:
    python aegis_guardian.py          # foreground
    python aegis_guardian.py --daemon # detached background process

Supports:
  - Windows  → win11toast (native Action Center)
  - macOS    → osascript / pync
  - Linux    → notify-send / libnotify
"""

import asyncio
import json
import sys
import signal
import platform
import argparse
import os
import logging
import subprocess
import threading
from datetime import datetime

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AEGIS-GUARDIAN] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("aegis_guardian")

BACKEND_WS_URL = "ws://127.0.0.1:8000/ws/telemetry"
AEGIS_API_KEY = os.environ.get("AEGIS_API_KEY", "")
RECONNECT_DELAY = 5  # seconds

# ── OS-specific notifiers ─────────────────────────────────────────────────────

def _notify(title: str, message: str, critical: bool = False) -> None:
    """Cross-platform desktop notification, fire-and-forget."""
    os_name = platform.system()
    try:
        if os_name == "Windows":
            from win11toast import toast
            toast(title, message, app_id="AEGIS.CommandCenter")

        elif os_name == "Darwin":
            script = 'display notification (system attribute "AEGIS_MSG") with title (system attribute "AEGIS_TITLE") sound name "Basso"'
            env = os.environ.copy()
            env["AEGIS_TITLE"] = title
            env["AEGIS_MSG"] = message
            subprocess.run(["osascript", "-e", script], env=env, check=False, timeout=3)

        else:  # Linux / other POSIX
            urgency = "critical" if critical else "normal"
            subprocess.run(
                ["notify-send", "-u", urgency, "-a", "AEGIS Guardian", title, message],
                check=False,
                timeout=3,
            )
    except Exception as e:
        log.warning("Notification failed: %s", e)


# ── Event handler ─────────────────────────────────────────────────────────────

BLOCKED_EVENT_TYPES = {
    "OrchestrationRouted",
    "SandboxBlocked",
    "ThreatDetected",
    "RateLimitExceeded",
}

def _handle_event(raw: str) -> None:
    """Parse a telemetry WebSocket message and notify on threats."""
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        return

    event_type = msg.get("event", "")
    data = msg.get("data", {})

    if event_type not in BLOCKED_EVENT_TYPES:
        return

    # Only notify on actual blocks / rejections
    if event_type == "OrchestrationRouted" and data.get("approved", True):
        return

    timestamp = datetime.now().strftime("%H:%M:%S")
    title = f"AEGIS Security Alert [{timestamp}]"
    reasoning = data.get("reasoning", data.get("stderr", "Unknown threat vector."))
    message = f"{event_type}: {reasoning[:120]}"

    log.warning("BLOCKED ▶ %s | %s", event_type, reasoning)
    threading.Thread(
        target=_notify,
        args=(title, message, True),
        daemon=True,
    ).start()


# ── WebSocket listener ────────────────────────────────────────────────────────

async def _listen() -> None:
    """Persistent WebSocket listener with exponential back-off reconnect."""
    try:
        import websockets  # type: ignore
    except ImportError:
        log.error("Missing dependency: install 'websockets'  →  pip install websockets")
        sys.exit(1)

    backoff = RECONNECT_DELAY
    while True:
        try:
            ws_url = f"{BACKEND_WS_URL}?key={AEGIS_API_KEY}" if AEGIS_API_KEY else BACKEND_WS_URL
            log.info("Connecting to AEGIS backend at %s …", BACKEND_WS_URL)
            async with websockets.connect(ws_url) as ws:
                log.info("Connected. Monitoring for threats …")
                _notify(
                    "AEGIS Guardian Active",
                    "Real-time threat monitoring is now running.",
                    critical=False,
                )
                backoff = RECONNECT_DELAY  # reset on successful connect
                async for message in ws:
                    _handle_event(str(message))

        except (ConnectionRefusedError, OSError):
            log.warning(
                "Backend unavailable — retrying in %ds (is the AEGIS server running?)",
                backoff,
            )
        except Exception as e:
            log.error("WebSocket error: %s — retrying in %ds", e, backoff)

        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 60)  # cap at 60s


# ── Entry point ───────────────────────────────────────────────────────────────

def _graceful_exit(sig, frame):   # noqa: ANN001
    log.info("AEGIS Guardian shutting down (signal %s).", sig)
    sys.exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS Guardian — background threat monitor")
    parser.add_argument(
        "--daemon", action="store_true",
        help="Detach and run as a background daemon (Unix only)",
    )
    args = parser.parse_args()

    if args.daemon and platform.system() != "Windows":
        # Double-fork to detach from terminal on Unix
        if (pid := __import__("os").fork()) > 0:
            print(f"[AEGIS Guardian] Daemon started (PID {pid})")
            sys.exit(0)
        __import__("os").setsid()
        if (__import__("os").fork()) > 0:
            sys.exit(0)

    signal.signal(signal.SIGINT, _graceful_exit)
    signal.signal(signal.SIGTERM, _graceful_exit)

    log.info("AEGIS Guardian v1.0 starting — platform: %s", platform.system())
    asyncio.run(_listen())


if __name__ == "__main__":
    main()
