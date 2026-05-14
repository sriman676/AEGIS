from typing import List
from pydantic import BaseModel
import uuid

class AutonomyLimit(BaseModel):
    max_steps: int
    allowed_capabilities: List[str]
    requires_human_review: bool

class GovernancePolicy(BaseModel):
    id: str
    scope: str
    limits: AutonomyLimit

class OrchestrationRequest(BaseModel):
    agent_id: str
    target_capabilities: List[str]
    context_size_bytes: int

class OrchestrationDecision(BaseModel):
    decision_id: str
    approved: bool
    escalation_required: bool
    reasoning: str
    applied_limits: AutonomyLimit
    malware_warning: bool = False

class GovernanceEngine:
    def __init__(self):
        # Default strict governance (Hostile-by-default)
        self.default_limits = AutonomyLimit(
            max_steps=5,
            allowed_capabilities=["FilesystemRead", "FilesystemWrite"],
            requires_human_review=True
        )
        # Track risk per repo path
        self.repo_risks: Dict[str, Dict[str, Any]] = {}

    def register_repo_risk(self, path: str, report: Dict[str, Any]):
        """Registers a deterministic risk report for a repository path."""
        self.repo_risks[path] = report

    def evaluate_request(self, request: OrchestrationRequest, repo_path: Optional[str] = None) -> OrchestrationDecision:
        """
        Evaluates an agent's orchestration request against strict governance policies.
        Enforces human review for dangerous capabilities.
        """
        escalation_required = False
        approved = True
        reasoning = "Capabilities within standard autonomous limits."

        # M-05: Malware Repo Defense — check deterministic risk score
        malware_warning = False
        if repo_path and repo_path in self.repo_risks:
            report = self.repo_risks[repo_path]
            risk_score = report.get("risk_score", 0)
            severity = report.get("overall_severity", "Low")
            
            if risk_score > 80 or severity == "Critical":
                approved = False
                escalation_required = True
                malware_warning = True
                reasoning = f"BLOCK: High-risk repository detected (Score: {risk_score}, Severity: {severity}). Potentially a malware repo."
                return OrchestrationDecision(
                    decision_id=str(uuid.uuid4()),
                    approved=False,
                    escalation_required=True,
                    reasoning=reasoning,
                    applied_limits=AutonomyLimit(max_steps=0, allowed_capabilities=[], requires_human_review=True),
                    malware_warning=True
                )
            elif risk_score > 50 or severity == "High":
                malware_warning = True
                reasoning = "WARNING: Suspicious repository patterns detected. Escalating for safety."
                escalation_required = True

        # M-06: Canary Monitor — check for access to 'aegis-canary.env'
        if any("aegis-canary" in cap for cap in request.target_capabilities):
            approved = False
            escalation_required = True
            reasoning = "BLOCK: Canary Honeypot triggered. Attempted access to dummy sensitive file."
            return OrchestrationDecision(
                decision_id=str(uuid.uuid4()),
                approved=False,
                escalation_required=True,
                reasoning=reasoning,
                applied_limits=AutonomyLimit(max_steps=0, allowed_capabilities=[], requires_human_review=True),
                malware_warning=True
            )

        dangerous_caps = {"ProcessSpawn", "NetworkAccess", "SecretAccess", "RuntimePrivilegeEscalation", "GitHookExecution"}
        
        requested_set = set(request.target_capabilities)
        
        # Check for dangerous capabilities that require immediate escalation
        if requested_set.intersection(dangerous_caps):
            escalation_required = True
            approved = False
            reasoning = f"Escalation required. Dangerous capabilities requested: {requested_set.intersection(dangerous_caps)}"

        # Enforce context bounds (to prevent token exhaustion / memory corruption)
        if request.context_size_bytes > 500000:
            approved = False
            reasoning = "Context size exceeds maximum autonomous routing bound (500KB)."

        decision = OrchestrationDecision(
            decision_id=str(uuid.uuid4()),
            approved=approved,
            escalation_required=escalation_required,
            reasoning=reasoning,
            applied_limits=self.default_limits if approved else AutonomyLimit(max_steps=0, allowed_capabilities=[], requires_human_review=True),
            malware_warning=malware_warning
        )
        return decision
