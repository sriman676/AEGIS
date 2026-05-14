"""
AEGIS Context Router — Hardened
==================================
Changes vs original:
  C-03  Session map capped at MAX_SESSIONS; oldest evicted when full
  C-03  Sessions carry a TTL — stale entries auto-expire
  M-02  Context size measured via json.dumps (accurate byte count)
"""

import json
import time
import logging
from typing import Dict, Any, List, Optional
from .governance import GovernanceEngine, OrchestrationRequest, OrchestrationDecision

logger = logging.getLogger("aegis_router")

MAX_SESSIONS: int = 10_000
SESSION_TTL_SEC: int = 3600  # 1 hour


class ContextRouter:
    def __init__(self, governance_engine: GovernanceEngine):
        self.governance = governance_engine
        # Each entry: {"status": ..., ..., "_created": float}
        self.active_sessions: Dict[str, Any] = {}

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _evict_expired(self) -> None:
        """Remove sessions older than SESSION_TTL_SEC."""
        now = time.time()
        expired = [
            sid for sid, data in self.active_sessions.items()
            if now - data.get("_created", 0) > SESSION_TTL_SEC
        ]
        for sid in expired:
            del self.active_sessions[sid]
            logger.debug("Evicted expired session %s", sid)

    def _enforce_cap(self) -> None:
        """C-03: if still over cap after TTL eviction, remove oldest entries."""
        if len(self.active_sessions) < MAX_SESSIONS:
            return
        # Sort by creation time ascending, drop the oldest
        sorted_sessions = sorted(
            self.active_sessions.items(),
            key=lambda kv: kv[1].get("_created", 0),
        )
        evict_count = len(self.active_sessions) - MAX_SESSIONS + 1
        for sid, _ in sorted_sessions[:evict_count]:
            del self.active_sessions[sid]
            logger.warning("Evicted session due to cap: %s", sid)

    # ── Public API ────────────────────────────────────────────────────────────

    def route_context(
        self,
        session_id: str,
        context_payload: Dict[str, Any],
        requested_caps: List[str],
        repo_path: Optional[str] = None,
    ) -> OrchestrationDecision:
        """Routes execution context through the GovernanceEngine."""
        # M-02: accurate byte count via json.dumps (not str())
        try:
            size_bytes = len(json.dumps(context_payload).encode("utf-8"))
        except (TypeError, ValueError):
            size_bytes = 0

        request = OrchestrationRequest(
            agent_id=session_id,
            target_capabilities=requested_caps,
            context_size_bytes=size_bytes,
        )

        decision = self.governance.evaluate_request(request, repo_path=repo_path)

        # C-03: evict stale/excess sessions before inserting new one
        self._evict_expired()
        self._enforce_cap()

        entry: Dict[str, Any] = {"_created": time.time()}
        if decision.approved:
            entry.update({"status": "routed", "limits": decision.applied_limits.model_dump()})
        else:
            entry.update({"status": "blocked", "reason": decision.reasoning})

        self.active_sessions[session_id] = entry
        return decision

    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        session = self.active_sessions.get(session_id)
        if session is None:
            return {"status": "not_found"}
        # Check TTL on read as well
        if time.time() - session.get("_created", 0) > SESSION_TTL_SEC:
            del self.active_sessions[session_id]
            return {"status": "expired"}
        # Return a copy without the internal _created key
        return {k: v for k, v in session.items() if k != "_created"}
