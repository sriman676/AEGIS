import logging
import logging.handlers
import json
import time
import os
from typing import Dict, Any, List
import asyncio
from pathlib import Path
from fastapi import WebSocket
import aiofiles

# ── Persistent audit log (survives process restarts) ──────────────────────────
_AUDIT_LOG_PATH = Path("aegis-audit.log")
_audit_logger = logging.getLogger("aegis_audit")
if not _audit_logger.handlers:
    _handler = logging.handlers.RotatingFileHandler(
        _AUDIT_LOG_PATH, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    _handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    _audit_logger.addHandler(_handler)
    _audit_logger.setLevel(logging.INFO)
    _audit_logger.propagate = False

class TelemetryPipeline:
    """
    Tier 3: Telemetry Pipeline for observability of autonomous orchestration.
    Maintains the 'runtime transparency' principle.
    Now broadcasts live over WebSockets to the UI Dashboard.
    """
    def __init__(self):
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] AEGIS-TELEMETRY: %(message)s")
        self.logger = logging.getLogger("aegis_telemetry")
        self.active_connections: List[WebSocket] = []
        self._last_log_time: float = 0
        self._log_count: int = 0
        self._MAX_LOGS_PER_SEC: int = 50
        self._background_tasks: set[asyncio.Task] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, event_type: str, data: Dict[str, Any]):
        message = json.dumps({"event": event_type, "data": data})
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass # Connection closed

    def log_event(self, event_type: str, payload: Dict[str, Any]):
        """Logs structured telemetry events and broadcasts via WebSockets."""
        # Volume throttling to prevent DoS
        now = time.time()
        if now - self._last_log_time > 1.0:
            self._last_log_time = now
            self._log_count = 0
        
        self._log_count += 1
        if self._log_count > self._MAX_LOGS_PER_SEC:
            if self._log_count == self._MAX_LOGS_PER_SEC + 1:
                self.logger.warning("TELEMETRY VOLUME EXCEEDED: Throttling audit logs.")
            return

        event_data = {
            "type": event_type,
            "data": payload
        }
        self.logger.info(json.dumps(event_data))
        _audit_logger.info(json.dumps(event_data))  # Persistent audit
        
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.broadcast(event_type, payload))
        except RuntimeError:
            pass # No loop running

    def log_decision(self, session_id: str, decision: Any):
        """Specifically logs governance decisions for auditability."""
        self.log_event("OrchestrationRouted", {
            "session": session_id,
            "approved": decision.approved,
            "escalation": decision.escalation_required,
            "reasoning": decision.reasoning,
            "capabilities": decision.applied_limits.model_dump()
        })

        if not decision.approved:
            # Capture forensic snapshot for blocked attacks
            self.capture_forensic_snapshot(session_id, decision)
            
            try:
                import threading
                from win11toast import toast
                # Fire the OS notification in the background so we don't block the API
                threading.Thread(
                    target=toast,
                    args=("AEGIS Security Alert", f"Attack Blocked: {decision.reasoning}"),
                    kwargs={"app_id": "AEGIS.CommandCenter"},
                    daemon=True
                ).start()
            except ImportError:
                pass

    async def _capture_forensic_snapshot_async(self, snapshot_path: Path, snapshot: Dict[str, Any]):
        try:
            async with aiofiles.open(snapshot_path, "w") as f:
                await f.write(json.dumps(snapshot, indent=2))
        except Exception as e:
            self.logger.error("Failed to async capture forensic snapshot: %s", str(e))

    def capture_forensic_snapshot(self, session_id: str, decision: Any):
        """Creates a detailed forensic artifact for security incidents."""
        # Sanitize session_id to prevent path traversal (CodeQL High Severity Alert)
        safe_session_id = os.path.basename(str(session_id))

        snapshot = {
            "session_id": safe_session_id,
            "timestamp": time.time(),
            "reasoning": decision.reasoning,
            "evidence": decision.model_dump(),
            "environment": {
                "os": os.name,
                "pid": os.getpid(),
                "cwd": os.getcwd(),
            }
        }

        snapshot_path = Path("forensics") / f"incident_{safe_session_id}.json"
        snapshot_path.parent.mkdir(exist_ok=True)

        self.logger.warning("FORENSIC SNAPSHOT CAPTURED: %s", snapshot_path)

        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(self._capture_forensic_snapshot_async(snapshot_path, snapshot))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
        except RuntimeError:
            # Fallback for environments without a running event loop (e.g., synchronous tests)
            with open(snapshot_path, "w") as f:
                json.dump(snapshot, f, indent=2)

telemetry = TelemetryPipeline()
