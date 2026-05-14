"""
AEGIS Hardened main.py
=======================
Changes vs original:
  C-01  API key authentication via SecurityMiddleware
  C-03  Session cap enforced in router (see router.py)
  C-05  Rate limiting via slowapi
  H-01  Explicit CORS allow_headers (no wildcard + credentials)
  H-03  WebSocket Origin validation in middleware
  H-06  Security headers middleware
  L-01  X-Process-Time only in debug mode
  L-02  /health returns minimal response
"""

import os
import time
import logging
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator, UUID4
from typing import List, Optional, Dict, Any

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

logger = logging.getLogger("aegis_main")

# ── Rate limiter ─────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

app = FastAPI(
    title="AEGIS Semantic Analyzer",
    description="Tier 1-5 AI-assisted semantic security & orchestration for AEGIS.",
    version="1.0.0",
    docs_url="/docs" if os.environ.get("AEGIS_DEBUG") == "true" else None,  # type: ignore
    redoc_url=None,
    openapi_url="/openapi.json" if os.environ.get("AEGIS_DEBUG") == "true" else None,  # type: ignore
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore

# ── CORS (H-01: no wildcard headers with credentials) ───────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "tauri://localhost",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-AEGIS-Key", "Authorization"],  # explicit, no wildcard
)

# ── Security middlewares (auth + headers + body size) ────────────────────────
from .security import APIKeyMiddleware, SecurityHeadersMiddleware, BodySizeLimitMiddleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(APIKeyMiddleware)
app.add_middleware(BodySizeLimitMiddleware)

# ── Process time (debug only — L-01) ─────────────────────────────────────────
_DEBUG = os.environ.get("AEGIS_DEBUG", "false").lower() == "true"  # type: ignore

@app.middleware("http")
async def _process_time(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    elapsed = time.time() - start
    if elapsed > 2.0:
        logger.warning("LATENCY: %s took %.2fs", request.url.path, elapsed)
    if _DEBUG:
        response.headers["X-Process-Time"] = f"{elapsed:.4f}"
    return response

# ── Models ───────────────────────────────────────────────────────────────────

class CapabilityNode(BaseModel):
    id: str
    type: str
    confidence: float

class SemanticAnalysisRequest(BaseModel):
    repository_url: Optional[str] = None
    execution_graph: Dict[str, Any]
    capabilities: List[CapabilityNode]

class SemanticAnalysisResponse(BaseModel):
    classifications: List[str]
    annotations: Dict[str, str]
    explanations: List[str]
    risk_enrichment: Dict[str, Any]

from .llm import evaluate_semantics

@app.post("/analyze", response_model=SemanticAnalysisResponse)
@limiter.limit("20/minute")
async def analyze_semantics(request: Request, body: SemanticAnalysisRequest):
    """
    Semantic analysis on execution graphs and capability sets.
    AI MAY classify, annotate, enrich, explain.
    AI MAY NOT bypass policy or enforce trust directly.
    """
    result = await evaluate_semantics(body.model_dump())
    return SemanticAnalysisResponse(**result)

# ── Repository Intake (Malware Defense) ───────────────────────────────────────

import subprocess
import json

class RepoIntakeRequest(BaseModel):
    path: str

@app.post("/repo/intake")
@limiter.limit("5/minute")
async def repo_intake(request: Request, body: RepoIntakeRequest):
    """
    Deterministic intake via Rust aegis-cli.
    Identifies 'Malware Repos' based on findings and risk scores.
    """
    # Path Traversal Protection
    from pathlib import Path
    base_dir = Path(os.environ.get("AEGIS_REPO_DIR", os.getcwd())).resolve()
    requested_path = Path(body.path).resolve()

    if not requested_path.is_relative_to(base_dir):
        raise HTTPException(status_code=403, detail="Access denied: Path is outside allowed repository directory.")

    if not requested_path.exists():
        raise HTTPException(status_code=404, detail="Path not found.")
    
    try:
        # 0. Fingerprint repository (Git remote)
        repo_id = body.path
        try:
            git_cmd = ["git", "-C", body.path, "remote", "get-url", "origin"]
            git_result = subprocess.run(git_cmd, capture_output=True, text=True, check=False)
            if git_result.returncode == 0:
                repo_id = git_result.stdout.strip()
        except Exception:
            pass

        # 1. Deterministic intake via Rust binary
        cmd = ["aegis", "intake", "--path", body.path, "--format", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        report = json.loads(result.stdout)
        
        # 2. Semantic documentation scan (README)
        readme_path = Path(body.path) / "README.md"
        if readme_path.exists():
            from .threat_intel import threat_intel
            doc_findings = threat_intel.scan_documentation(readme_path.read_text(errors="ignore"))
            for finding in doc_findings:
                report["findings"].append({
                    "title": "Documentation Risk",
                    "severity": "High",
                    "path": "README.md",
                    "evidence": finding,
                    "capabilities": ["SocialEngineering"]
                })
        
        # 3. VSCode Task Scan (Immediate Execution Vector)
        task_path = Path(body.path) / ".vscode" / "tasks.json"
        if task_path.exists():
            report["findings"].append({
                "title": "VSCode Auto-Task Detected",
                "severity": "Medium",
                "path": ".vscode/tasks.json",
                "evidence": "Repository contains VSCode tasks which may execute on open.",
                "capabilities": ["ProcessSpawn"]
            })

        # Track risk state in governance engine
        governance_engine.register_repo_risk(body.path, report)
        
        return report
    except subprocess.CalledProcessError as e:
        logger.error("Aegis CLI failed: %s", e.stderr)
        raise HTTPException(status_code=500, detail="Repository analysis failed.")
    except Exception as e:
        logger.error("Intake error: %s", str(e))
        raise HTTPException(status_code=500, detail="Intake processing error.")

# ── Orchestration ─────────────────────────────────────────────────────────────

from .orchestrator.governance import GovernanceEngine
from .orchestrator.router import ContextRouter

governance_engine = GovernanceEngine()
context_router = ContextRouter(governance_engine)

class OrchestrationPayload(BaseModel):
    session_id: str
    context_payload: Dict[str, Any]
    requested_capabilities: List[str]
    repo_path: Optional[str] = None

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, v: str) -> str:
        """M-03: enforce UUID4 format to prevent session collision attacks."""
        import uuid
        try:
            parsed = uuid.UUID(v, version=4)
            if str(parsed) != v:
                raise ValueError
        except (ValueError, AttributeError):
            raise ValueError("session_id must be a valid UUID4")
        return v

from .telemetry import telemetry

@app.post("/orchestrate/route")
@limiter.limit("30/minute")
async def route_orchestration_context(request: Request, payload: OrchestrationPayload):
    """Tier 3: Governed Autonomous Orchestration."""
    decision = context_router.route_context(
        session_id=payload.session_id,
        context_payload=payload.context_payload,
        requested_caps=payload.requested_capabilities,
        repo_path=payload.repo_path,
    )
    telemetry.log_decision(payload.session_id, decision)
    return decision

# ── OS Execution ─────────────────────────────────────────────────────────────

from .sandbox_os.kernel import kernel
from .sandbox_os.memory import memory_manager

class ExecutionPayload(BaseModel):
    session_id: str
    command: List[str]

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, v: str) -> str:
        import uuid
        try:
            parsed = uuid.UUID(v, version=4)
            if str(parsed) != v:
                raise ValueError
        except (ValueError, AttributeError):
            raise ValueError("session_id must be a valid UUID4")
        return v

@app.post("/os/execute")
@limiter.limit("10/minute")
async def execute_sandboxed_task(request: Request, payload: ExecutionPayload):
    """Tier 4: Sandbox execution — requires prior governance routing."""
    session_status = context_router.get_session_status(payload.session_id)
    if session_status.get("status") != "routed":
        raise HTTPException(status_code=403, detail="Session not routed or blocked by governance.")

    allowed_caps = session_status.get("limits", {}).get("allowed_capabilities", [])

    result = kernel.spawn_sandboxed_task(
        command=payload.command,
        execution_id=payload.session_id,
        allowed_capabilities=allowed_caps,
    )
    memory_manager.short_term.append(payload.session_id, {"event": "execution", "result": result.model_dump()})
    return result

# ── Health (L-02: minimal disclosure) ────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Liveness probe — returns minimal info in production."""
    if _DEBUG:
        return {"status": "healthy", "tier": "1_3_4", "component": "semantic-analyzer-orchestrator-os"}
    return {"status": "ok"}

@app.get("/system/status")
@limiter.limit("10/minute")
async def system_status(request: Request):
    """Tier 1: High-level security posture for the dashboard."""
    # Check integrity lock
    from .tools.check_ai_plugins import verify_hashes
    integrity_passed, violations = verify_hashes()
    
    return {
        "integrity": "verified" if integrity_passed else "tampered",
        "violations": violations,
        "sandbox_mode": SANDBOX_MODE,
        "threat_intel_version": "1.2.0",
        "governed_sessions": len(context_router.active_sessions),
        "audit_log_size": os.path.getsize(_AUDIT_LOG_PATH) if os.path.exists(_AUDIT_LOG_PATH) else 0
    }

@app.post("/system/restore")
@limiter.limit("2/minute")
async def system_restore(request: Request):
    """Tier 1: Self-healing: Restore AI rule files from master copies."""
    from .tools.check_ai_plugins import restore_plugins
    restore_plugins()
    return {"status": "restored", "message": "All AI rule files have been reset to canonical state."}

@app.post("/csp-report")
async def handle_csp_report(request: Request):
    """Tier 1: CSP Violation reporting. Logged for security audit."""
    report = await request.json()
    logger.warning("CSP VIOLATION: %s", json.dumps(report))
    telemetry.log_event("CSPViolation", report)
    return Response(status_code=204)

# ── WebSocket telemetry (H-03: origin validated in middleware) ────────────────

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    """Live telemetry stream — origin validated by APIKeyMiddleware."""
    await telemetry.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        telemetry.disconnect(websocket)
