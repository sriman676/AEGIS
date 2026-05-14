use crate::model::{
    Capability, EnforcementMode, Finding, InvariantCheck, InvariantReport, PolicyDecision,
    RiskReport, Severity,
};

pub fn evaluate_findings(findings: &[Finding]) -> Vec<PolicyDecision> {
    findings.iter().map(evaluate_finding).collect()
}

fn evaluate_finding(finding: &Finding) -> PolicyDecision {
    let has = |capability: Capability| finding.capabilities.contains(&capability);

    let (mode, reason) = if has(Capability::RuntimePrivilegeEscalation)
        || has(Capability::SecretAccess)
        || matches!(finding.severity, Severity::Critical)
    {
        (
            EnforcementMode::Deny,
            "critical capability requires deterministic denial",
        )
    } else if has(Capability::ProcessSpawn)
        || has(Capability::NetworkAccess)
        || has(Capability::ContainerControl)
        || has(Capability::McpToolInvocation)
        || has(Capability::GitHookExecution)
        || has(Capability::IdeTaskExecution)
        || has(Capability::DependencyScriptExecution)
    {
        (
            EnforcementMode::Sandbox,
            "execution-capable behavior must be sandboxed before use",
        )
    } else {
        (
            EnforcementMode::Escalate,
            "hostile-by-default policy requires explicit human review",
        )
    };

    PolicyDecision {
        finding_id: finding.id,
        mode,
        reason: reason.to_string(),
        invariant_refs: vec![
            "hostile_by_default".to_string(),
            "deterministic_enforcement".to_string(),
            "no_ai_policy_authority".to_string(),
        ],
    }
}

pub fn validate_report_invariants(report: &RiskReport) -> InvariantReport {
    let checks = vec![
        InvariantCheck {
            id: "hostile_by_default".to_string(),
            passed: report.hostile_by_default,
            detail: "Repository intake must assume hostile-by-default trust.".to_string(),
        },
        InvariantCheck {
            id: "no_implicit_execution".to_string(),
            passed: !report.implicit_execution_allowed,
            detail: "Repository intake must not execute repository-defined code.".to_string(),
        },
        InvariantCheck {
            id: "deterministic_enforcement".to_string(),
            passed: report.policy_decisions.len() == report.findings.len(),
            detail: "Every finding must have one deterministic policy decision.".to_string(),
        },
        InvariantCheck {
            id: "no_ai_policy_authority".to_string(),
            passed: report
                .metadata
                .get("ai_policy_authority")
                .is_some_and(|value| value == "false"),
            detail: "AI systems may not directly grant policy authority.".to_string(),
        },
        InvariantCheck {
            id: "explainability".to_string(),
            passed: report
                .policy_decisions
                .iter()
                .all(|decision| !decision.reason.trim().is_empty()),
            detail: "Every policy decision must include an explanation.".to_string(),
        },
    ];

    InvariantReport { checks }
}
