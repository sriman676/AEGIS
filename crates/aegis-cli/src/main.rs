use aegis_core::{
    analyze_repository, events_for_report, explain_report, validate_report_invariants,
    AnalysisConfig, EnforcementMode, RiskReport,
};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "aegis")]
#[command(about = "Hostile-by-default repository security intake")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Intake {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    Events {
        #[arg(long, default_value = ".")]
        path: PathBuf,
    },
    Explain {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        #[arg(long, env = "AEGIS_AI_URL")]
        ai_url: Option<String>,
    },
    Validate {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Intake { path, format } => run_intake(path, format),
        Command::Events { path } => run_events(path),
        Command::Explain { path, format, ai_url } => run_explain(path, format, ai_url),
        Command::Validate { path, format } => run_validate(path, format),
    };

    if let Err(error) = result {
        eprintln!("aegis error: {error}");
        std::process::exit(1);
    }
}

fn run_events(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let report = analyze_repository(path, AnalysisConfig::default())?;
    let events = events_for_report(&report);
    println!("{}", serde_json::to_string_pretty(&events)?);
    Ok(())
}

fn run_explain(path: PathBuf, format: OutputFormat, ai_url: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let report = analyze_repository(path, AnalysisConfig::default())?;
    let explanations = explain_report(&report);
    
    let ai_enrichment = if let Some(url) = ai_url {
        Some(aegis_core::ai::analyze_semantics(&url, &report.execution_graph, &report.capability_summary)?)
    } else {
        None
    };

    match format {
        OutputFormat::Json => {
            let mut output = serde_json::Map::new();
            output.insert("explanations".to_string(), serde_json::to_value(&explanations)?);
            if let Some(ai) = &ai_enrichment {
                output.insert("ai_enrichment".to_string(), serde_json::to_value(ai)?);
            }
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Text => {
            println!("Deterministic Explanations:");
            for explanation in explanations {
                println!("- {}", explanation.summary);
                println!("  enforcement: {}", explanation.enforcement_reasoning);
                println!("  human_review_required: {}", explanation.human_review_required);
                for reason in explanation.capability_reasoning {
                    println!("  capability: {reason}");
                }
            }
            if let Some(ai) = ai_enrichment {
                println!("\nAI Semantic Enrichment:");
                println!("- Classifications: {:?}", ai.classifications);
                for (node, annotation) in &ai.annotations {
                    println!("  Annotation [{}]: {}", node, annotation);
                }
                for exp in &ai.explanations {
                    println!("  Explanation: {}", exp);
                }
                println!("  Risk Context: {:?}", ai.risk_enrichment);
            }
        }
    }
    Ok(())
}

fn run_validate(path: PathBuf, format: OutputFormat) -> Result<(), Box<dyn std::error::Error>> {
    let report = analyze_repository(path, AnalysisConfig::default())?;
    let invariant_report = validate_report_invariants(&report);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&invariant_report)?),
        OutputFormat::Text => {
            for check in &invariant_report.checks {
                println!(
                    "{}: {} - {}",
                    check.id,
                    if check.passed { "pass" } else { "fail" },
                    check.detail
                );
            }
        }
    }
    if !invariant_report.passed() {
        std::process::exit(2);
    }
    Ok(())
}

fn run_intake(path: PathBuf, format: OutputFormat) -> Result<(), Box<dyn std::error::Error>> {
    let report = analyze_repository(path, AnalysisConfig::default())?;
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Text => print_text_report(&report),
    }
    Ok(())
}

fn print_text_report(report: &RiskReport) {
    println!("AEGIS repository intake");
    println!("session: {}", report.session_id);
    println!("root: {}", report.repository_root.display());
    println!("hostile_by_default: {}", report.hostile_by_default);
    println!("implicit_execution_allowed: {}", report.implicit_execution_allowed);
    println!("risk_score: {}", report.risk_score);
    println!("overall_severity: {:?}", report.overall_severity);
    println!("findings: {}", report.findings.len());
    println!();

    for finding in &report.findings {
        println!("- [{:?}] {}", finding.severity, finding.title);
        println!("  path: {}", finding.path.display());
        println!("  capabilities: {:?}", finding.capabilities);
        if !finding.evidence.is_empty() {
            println!("  evidence: {}", finding.evidence);
        }
    }

    println!();
    println!("policy decisions:");
    for decision in &report.policy_decisions {
        let label = match decision.mode {
            EnforcementMode::Allow => "allow",
            EnforcementMode::Deny => "deny",
            EnforcementMode::Sandbox => "sandbox",
            EnforcementMode::Escalate => "escalate",
            EnforcementMode::Adaptive => "adaptive",
        };
        println!("- {}: {}", label, decision.reason);
    }
}
