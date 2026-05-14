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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FindingKind;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn mock_finding(severity: Severity, capabilities: Vec<Capability>) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            kind: FindingKind::AiInstruction,
            path: PathBuf::from("mock/path"),
            title: "Mock Finding".to_string(),
            evidence: "Mock evidence".to_string(),
            severity,
            capabilities,
        }
    }

    #[test]
    fn test_evaluate_finding_deny_critical_severity() {
        let finding = mock_finding(Severity::Critical, vec![]);
        let decision = evaluate_finding(&finding);
        assert_eq!(decision.mode, EnforcementMode::Deny);
        assert_eq!(decision.reason, "critical capability requires deterministic denial");
    }

    #[test]
    fn test_evaluate_finding_deny_runtime_privilege_escalation() {
        let finding = mock_finding(Severity::High, vec![Capability::RuntimePrivilegeEscalation]);
        let decision = evaluate_finding(&finding);
        assert_eq!(decision.mode, EnforcementMode::Deny);
        assert_eq!(decision.reason, "critical capability requires deterministic denial");
    }

    #[test]
    fn test_evaluate_finding_deny_secret_access() {
        let finding = mock_finding(Severity::High, vec![Capability::SecretAccess]);
        let decision = evaluate_finding(&finding);
        assert_eq!(decision.mode, EnforcementMode::Deny);
        assert_eq!(decision.reason, "critical capability requires deterministic denial");
    }

    #[test]
    fn test_evaluate_finding_sandbox_capabilities() {
        let sandbox_capabilities = vec![
            Capability::ProcessSpawn,
            Capability::NetworkAccess,
            Capability::ContainerControl,
            Capability::McpToolInvocation,
            Capability::GitHookExecution,
            Capability::IdeTaskExecution,
            Capability::DependencyScriptExecution,
        ];

        for capability in sandbox_capabilities {
            let finding = mock_finding(Severity::High, vec![capability]);
            let decision = evaluate_finding(&finding);
            assert_eq!(decision.mode, EnforcementMode::Sandbox);
            assert_eq!(
                decision.reason,
                "execution-capable behavior must be sandboxed before use"
            );
        }
    }

    #[test]
    fn test_evaluate_finding_escalate_default() {
        let finding = mock_finding(Severity::High, vec![Capability::FilesystemRead]);
        let decision = evaluate_finding(&finding);
        assert_eq!(decision.mode, EnforcementMode::Escalate);
        assert_eq!(
            decision.reason,
            "hostile-by-default policy requires explicit human review"
        );
    }

    #[test]
    fn test_evaluate_finding_escalate_empty_capabilities() {
        let finding = mock_finding(Severity::Info, vec![]);
        let decision = evaluate_finding(&finding);
        assert_eq!(decision.mode, EnforcementMode::Escalate);
    }

    #[test]
    fn test_evaluate_findings_maps_correctly() {
        let finding1 = mock_finding(Severity::Critical, vec![]);
        let finding2 = mock_finding(Severity::Medium, vec![Capability::ProcessSpawn]);
        let finding3 = mock_finding(Severity::Low, vec![Capability::FilesystemWrite]);

        let id1 = finding1.id;
        let id2 = finding2.id;
        let id3 = finding3.id;

        let findings = vec![finding1, finding2, finding3];
        let decisions = evaluate_findings(&findings);

        assert_eq!(decisions.len(), 3);

        let decision1 = decisions.iter().find(|d| d.finding_id == id1).unwrap();
        assert_eq!(decision1.mode, EnforcementMode::Deny);

        let decision2 = decisions.iter().find(|d| d.finding_id == id2).unwrap();
        assert_eq!(decision2.mode, EnforcementMode::Sandbox);

        let decision3 = decisions.iter().find(|d| d.finding_id == id3).unwrap();
        assert_eq!(decision3.mode, EnforcementMode::Escalate);
    }
}
