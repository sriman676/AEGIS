use aegis_core::{
    analyze_repository, validate_report_invariants, AnalysisConfig, EnforcementMode,
};
use std::path::PathBuf;

#[test]
fn hostile_by_default_never_allows_fixture_findings() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/malicious_repo");
    let report = analyze_repository(fixture, AnalysisConfig::default()).expect("analysis succeeds");

    assert!(report
        .policy_decisions
        .iter()
        .all(|decision| decision.mode != EnforcementMode::Allow));
}

#[test]
fn every_finding_has_policy_decision_and_explanation_basis() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/malicious_repo");
    let report = analyze_repository(fixture, AnalysisConfig::default()).expect("analysis succeeds");
    let invariants = validate_report_invariants(&report);

    assert!(invariants.passed());
    assert_eq!(report.findings.len(), report.policy_decisions.len());
    assert!(report
        .policy_decisions
        .iter()
        .all(|decision| !decision.invariant_refs.is_empty()));
}

