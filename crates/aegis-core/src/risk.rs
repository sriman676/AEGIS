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
