use crate::model::{EnforcementMode, Finding, PolicyDecision, RiskReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Explanation {
    pub finding_id: String,
    pub summary: String,
    pub capability_reasoning: Vec<String>,
    pub enforcement_reasoning: String,
    pub human_review_required: bool,
}

pub fn explain_report(report: &RiskReport) -> Vec<Explanation> {
    report
        .findings
        .iter()
        .filter_map(|finding| {
            report
                .policy_decisions
                .iter()
                .find(|decision| decision.finding_id == finding.id)
                .map(|decision| explain_finding(finding, decision))
        })
        .collect()
}

fn explain_finding(finding: &Finding, decision: &PolicyDecision) -> Explanation {
    let capability_reasoning = finding
        .capabilities
        .iter()
        .map(|capability| format!("{capability:?} is requested by {}", finding.path.display()))
        .collect();

    Explanation {
        finding_id: finding.id.to_string(),
        summary: format!("{} in {}", finding.title, finding.path.display()),
        capability_reasoning,
        enforcement_reasoning: decision.reason.clone(),
        human_review_required: !matches!(decision.mode, EnforcementMode::Allow),
    }
}
