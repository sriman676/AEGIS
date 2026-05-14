use crate::model::{EnforcementMode, RiskReport};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    RepositoryIntakeStarted,
    FindingDetected,
    CapabilityEvaluated,
    PolicyDecisionIssued,
    RepositoryIntakeCompleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableEvent {
    pub event_id: Uuid,
    pub event_type: EventType,
    pub schema_version: String,
    pub occurred_at: String,
    pub lineage: Vec<Uuid>,
    pub payload: Value,
}

pub fn events_for_report(report: &RiskReport) -> Vec<ImmutableEvent> {
    let root_event = new_event(
        EventType::RepositoryIntakeStarted,
        Vec::new(),
        json!({
            "session_id": report.session_id,
            "repository_root": report.repository_root.clone(),
            "implicit_execution_allowed": report.implicit_execution_allowed
        }),
    );
    let root_id = root_event.event_id;

    let mut events = vec![root_event];

    for finding in &report.findings {
        events.push(new_event(
            EventType::FindingDetected,
            vec![root_id],
            json!({
                "session_id": report.session_id,
                "finding_id": finding.id,
                "kind": finding.kind.clone(),
                "path": finding.path.clone(),
                "severity": finding.severity.clone(),
                "capabilities": finding.capabilities.clone()
            }),
        ));
    }

    for decision in &report.policy_decisions {
        events.push(new_event(
            EventType::PolicyDecisionIssued,
            vec![root_id],
            json!({
                "session_id": report.session_id,
                "finding_id": decision.finding_id,
                "mode": mode_label(&decision.mode),
                "reason": decision.reason.clone(),
                "invariant_refs": decision.invariant_refs.clone()
            }),
        ));
    }

    events.push(new_event(
        EventType::RepositoryIntakeCompleted,
        vec![root_id],
        json!({
            "session_id": report.session_id,
            "finding_count": report.findings.len(),
            "policy_decision_count": report.policy_decisions.len(),
            "capability_count": report.capability_summary.len()
        }),
    ));

    events
}

fn new_event(event_type: EventType, lineage: Vec<Uuid>, payload: Value) -> ImmutableEvent {
    ImmutableEvent {
        event_id: Uuid::new_v4(),
        event_type,
        schema_version: "0.1.0".to_string(),
        occurred_at: "1970-01-01T00:00:00Z".to_string(),
        lineage,
        payload,
    }
}

fn mode_label(mode: &EnforcementMode) -> &'static str {
    match mode {
        EnforcementMode::Allow => "allow",
        EnforcementMode::Deny => "deny",
        EnforcementMode::Sandbox => "sandbox",
        EnforcementMode::Escalate => "escalate",
        EnforcementMode::Adaptive => "adaptive",
    }
}
