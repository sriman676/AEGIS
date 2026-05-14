use aegis_core::{
    analyze_repository, events_for_report, explain_report, validate_report_invariants,
    AnalysisConfig, Capability, EnforcementMode, FindingKind,
};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn ensure_git_hooks_exist(fixture: &PathBuf) {
    let hooks_dir = fixture.join(".git").join("hooks");
    let _ = std::fs::create_dir_all(&hooks_dir);
    let _ = std::fs::write(hooks_dir.join("pre-commit"), "#!/bin/sh\necho 'hacked'");
}

#[test]
fn malicious_fixture_produces_deterministic_denials_and_sandboxes() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/malicious_repo");
    ensure_git_hooks_exist(&fixture);
    let report = analyze_repository(fixture, AnalysisConfig::default()).expect("analysis succeeds");

    assert!(report.hostile_by_default);
    assert!(!report.implicit_execution_allowed);
    assert!(report.risk_score >= 70);
    assert!(report.findings.len() >= 5);
    assert!(report
        .capability_summary
        .iter()
        .any(|summary| summary.capability == Capability::ProcessSpawn));
    assert!(report
        .policy_decisions
        .iter()
        .any(|decision| decision.mode == EnforcementMode::Deny));
    assert!(report
        .policy_decisions
        .iter()
        .any(|decision| decision.mode == EnforcementMode::Sandbox));
    assert!(!report.execution_graph.nodes.is_empty());
    assert!(!report.execution_graph.edges.is_empty());
}

#[test]
fn malicious_fixture_detects_expected_execution_surfaces() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/malicious_repo");
    ensure_git_hooks_exist(&fixture);
    let report = analyze_repository(fixture, AnalysisConfig::default()).expect("analysis succeeds");
    let detected = report
        .findings
        .iter()
        .map(|finding| finding.kind.clone())
        .collect::<BTreeSet<_>>();

    for expected in [
        FindingKind::AiInstruction,
        FindingKind::DevContainer,
        FindingKind::DockerCompose,
        FindingKind::Dockerfile,
        FindingKind::GithubWorkflow,
        FindingKind::GitHook,
        FindingKind::Makefile,
        FindingKind::McpConfig,
        FindingKind::PackageScript,
        FindingKind::RustBuildScript,
        FindingKind::ShellScript,
        FindingKind::VscodeTask,
    ] {
        assert!(detected.contains(&expected), "missing {expected:?}");
    }
}

#[test]
fn reports_emit_events_explanations_and_invariant_checks() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/malicious_repo");
    ensure_git_hooks_exist(&fixture);
    let report = analyze_repository(fixture, AnalysisConfig::default()).expect("analysis succeeds");

    let events = events_for_report(&report);
    assert!(events.len() >= report.findings.len() + report.policy_decisions.len() + 2);

    let explanations = explain_report(&report);
    assert_eq!(explanations.len(), report.findings.len());
    assert!(explanations
        .iter()
        .all(|explanation| explanation.human_review_required));

    let invariants = validate_report_invariants(&report);
    assert!(invariants.passed());
}
