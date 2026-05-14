use crate::model::{Capability, Finding, Severity};

pub fn calculate_risk_score(findings: &[Finding]) -> u16 {
    let mut score: u16 = 0;
    for finding in findings {
        score = score.saturating_add(severity_weight(&finding.severity));
        for capability in &finding.capabilities {
            score = score.saturating_add(capability_weight(capability));
        }
    }
    score.min(100)
}

pub fn overall_severity(findings: &[Finding]) -> Severity {
    if findings.is_empty() {
        return Severity::Info;
    }

    let score = calculate_risk_score(findings);
    match score {
        0..=10 => Severity::Low,
        11..=35 => Severity::Medium,
        36..=70 => Severity::High,
        _ => Severity::Critical,
    }
}

fn severity_weight(severity: &Severity) -> u16 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 2,
        Severity::Medium => 6,
        Severity::High => 12,
        Severity::Critical => 25,
    }
}

fn capability_weight(capability: &Capability) -> u16 {
    match capability {
        Capability::FilesystemRead => 1,
        Capability::FilesystemWrite => 5,
        Capability::ProcessSpawn => 8,
        Capability::NetworkAccess => 7,
        Capability::SecretAccess => 15,
        Capability::ContainerControl => 9,
        Capability::GitHookExecution => 10,
        Capability::IdeTaskExecution => 9,
        Capability::McpToolInvocation => 12,
        Capability::PromptInfluence => 6,
        Capability::DependencyScriptExecution => 10,
        Capability::RuntimePrivilegeEscalation => 20,
    }
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
            kind: FindingKind::SuspiciousContent,
            path: PathBuf::from("test"),
            title: String::new(),
            evidence: String::new(),
            severity,
            capabilities,
        }
    }

    #[test]
    fn test_overall_severity_empty() {
        assert_eq!(overall_severity(&[]), Severity::Info);
    }

    #[test]
    fn test_overall_severity_low() {
        // Score 0: 1 Severity::Info (0), no capabilities.
        let f1 = mock_finding(Severity::Info, vec![]);
        assert_eq!(overall_severity(&[f1]), Severity::Low);

        // Score 10: 1 Severity::Low (2), 1 Capability::ProcessSpawn (8) = 10.
        let f2 = mock_finding(Severity::Low, vec![Capability::ProcessSpawn]);
        assert_eq!(overall_severity(&[f2]), Severity::Low);
    }

    #[test]
    fn test_overall_severity_medium() {
        // Score 11: 1 Severity::Low (2), 1 Capability::ContainerControl (9) = 11.
        let f1 = mock_finding(Severity::Low, vec![Capability::ContainerControl]);
        assert_eq!(overall_severity(&[f1]), Severity::Medium);

        // Score 35: 1 Severity::Critical (25), 1 Capability::DependencyScriptExecution (10) = 35.
        let f2 = mock_finding(Severity::Critical, vec![Capability::DependencyScriptExecution]);
        assert_eq!(overall_severity(&[f2]), Severity::Medium);
    }

    #[test]
    fn test_overall_severity_high() {
        // Score 36: 1 Severity::High (12), 2 Capability::McpToolInvocation (12+12=24) = 36.
        let f1 = mock_finding(
            Severity::High,
            vec![Capability::McpToolInvocation, Capability::McpToolInvocation],
        );
        assert_eq!(overall_severity(&[f1]), Severity::High);

        // Score 70: 1 Severity::Critical (25), 3 Capability::SecretAccess (15*3=45) = 70.
        let f2 = mock_finding(
            Severity::Critical,
            vec![
                Capability::SecretAccess,
                Capability::SecretAccess,
                Capability::SecretAccess,
            ],
        );
        assert_eq!(overall_severity(&[f2]), Severity::High);
    }

    #[test]
    fn test_overall_severity_critical() {
        // Score 71: 1 Severity::Critical (25), 3 Capability::SecretAccess (15*3=45), 1 Capability::FilesystemRead (1) = 71.
        let f1 = mock_finding(
            Severity::Critical,
            vec![
                Capability::SecretAccess,
                Capability::SecretAccess,
                Capability::SecretAccess,
                Capability::FilesystemRead,
            ],
        );
        assert_eq!(overall_severity(&[f1]), Severity::Critical);

        // Score > 100 (capped at 100): 4 Severity::Critical (25*4=100), 1 Capability::RuntimePrivilegeEscalation (20) = 120 (capped at 100).
        let f2 = mock_finding(Severity::Critical, vec![]);
        let f3 = mock_finding(Severity::Critical, vec![]);
        let f4 = mock_finding(Severity::Critical, vec![]);
        let f5 = mock_finding(
            Severity::Critical,
            vec![Capability::RuntimePrivilegeEscalation],
        );
        assert_eq!(overall_severity(&[f2, f3, f4, f5]), Severity::Critical);
    }
}
