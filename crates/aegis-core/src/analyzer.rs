use crate::error::{AegisError, Result};
use crate::graph::build_execution_graph;
use crate::model::{
    Capability, CapabilitySummary, Finding, FindingKind, RiskReport, Severity,
};
use crate::policy::evaluate_findings;
use crate::risk::{calculate_risk_score, overall_severity as compute_overall_severity};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    pub max_file_bytes: u64,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: 512 * 1024,
        }
    }
}

pub fn analyze_repository(root: impl AsRef<Path>, config: AnalysisConfig) -> Result<RiskReport> {
    let root = root.as_ref().to_path_buf();
    if !root.exists() {
        return Err(AegisError::RepositoryNotFound(root));
    }
    if !root.is_dir() {
        return Err(AegisError::RepositoryNotDirectory(root));
    }

    let mut findings = Vec::new();
    analyze_known_files(&root, &mut findings)?;
    analyze_walked_files(&root, config.max_file_bytes, &mut findings)?;
    findings.sort_by(|left, right| left.path.cmp(&right.path).then(left.title.cmp(&right.title)));

    let capability_summary = summarize_capabilities(&findings);
    let execution_graph = build_execution_graph(&findings);
    let policy_decisions = evaluate_findings(&findings);
    let risk_score = calculate_risk_score(&findings);
    let overall_severity = compute_overall_severity(&findings);

    let mut metadata = BTreeMap::new();
    metadata.insert("engine".to_string(), "aegis-core".to_string());
    metadata.insert("tier".to_string(), "0".to_string());
    metadata.insert("ai_policy_authority".to_string(), "false".to_string());

    Ok(RiskReport {
        session_id: Uuid::new_v4(),
        repository_root: root,
        hostile_by_default: true,
        implicit_execution_allowed: false,
        risk_score,
        overall_severity,
        findings,
        capability_summary,
        execution_graph,
        policy_decisions,
        metadata,
    })
}

fn analyze_known_files(root: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    analyze_vscode_tasks(root, findings)?;
    analyze_package_scripts(root, findings)?;
    analyze_mcp_config(root, ".cursor/mcp.json", findings)?;
    analyze_mcp_config(root, ".mcp.json", findings)?;
    Ok(())
}

fn analyze_vscode_tasks(root: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    let path = root.join(".vscode").join("tasks.json");
    if !path.exists() {
        return Ok(());
    }
    let value = read_json(&path)?;
    let mut evidence = Vec::new();
    collect_json_strings(&value, &mut evidence);
    let evidence = evidence.join(" ");

    findings.push(Finding {
        id: Uuid::new_v4(),
        kind: FindingKind::VscodeTask,
        path: relative(root, &path),
        title: "VSCode task can trigger repository-defined commands".to_string(),
        evidence: trim_evidence(&evidence),
        severity: severity_for_text(&evidence, Severity::Medium),
        capabilities: capabilities_for_text(
            &evidence,
            &[Capability::IdeTaskExecution, Capability::ProcessSpawn],
        ),
    });
    Ok(())
}

fn analyze_package_scripts(root: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    let path = root.join("package.json");
    if !path.exists() {
        return Ok(());
    }
    let value = read_json(&path)?;
    let Some(scripts) = value.get("scripts").and_then(Value::as_object) else {
        return Ok(());
    };

    for (name, command) in scripts {
        let command = command.as_str().unwrap_or_default();
        findings.push(Finding {
            id: Uuid::new_v4(),
            kind: FindingKind::PackageScript,
            path: relative(root, &path),
            title: format!("package script `{name}` requests execution"),
            evidence: trim_evidence(command),
            severity: severity_for_text(command, Severity::Medium),
            capabilities: capabilities_for_text(
                command,
                &[
                    Capability::DependencyScriptExecution,
                    Capability::ProcessSpawn,
                    Capability::FilesystemRead,
                ],
            ),
        });
    }
    Ok(())
}

fn analyze_mcp_config(root: &Path, relative_path: &str, findings: &mut Vec<Finding>) -> Result<()> {
    let path = root.join(relative_path);
    if !path.exists() {
        return Ok(());
    }
    let content = read_text(&path)?;
    findings.push(Finding {
        id: Uuid::new_v4(),
        kind: FindingKind::McpConfig,
        path: PathBuf::from(relative_path),
        title: "MCP configuration can expose tool invocation".to_string(),
        evidence: trim_evidence(&content),
        severity: severity_for_text(&content, Severity::High),
        capabilities: capabilities_for_text(
            &content,
            &[Capability::McpToolInvocation, Capability::ProcessSpawn],
        ),
    });
    Ok(())
}

fn analyze_walked_files(
    root: &Path,
    max_file_bytes: u64,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    for entry in WalkDir::new(root)
        .max_depth(20) // H-10: Prevent zip-bomb/recursion DoS
        .follow_links(false)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();
        if !entry.file_type().is_file() || should_skip(path) {
            continue;
        }
        
        // H-11: Detect compiled binaries in source repositories (potential hijacking)
        if is_compiled_binary(path) {
            findings.push(Finding {
                id: Uuid::new_v4(),
                kind: FindingKind::SuspiciousContent,
                path: relative(root, path),
                title: "Compiled binary detected in source repository".to_string(),
                evidence: "Binary file potentially used for DLL hijacking or side-loading.".to_string(),
                severity: Severity::High,
                capabilities: vec![Capability::ProcessSpawn],
            });
            continue;
        }
        let metadata = fs::metadata(path).map_err(|source| AegisError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.len() > max_file_bytes {
            continue;
        }

        let relative_path = relative(root, path);
        let normalized = relative_path.to_string_lossy().replace('\\', "/");
        if is_known_structured_file(&normalized) {
            continue;
        }
        if normalized.ends_with("Dockerfile") || normalized == "Dockerfile" {
            let content = read_text(path)?;
            findings.push(finding_for_text(
                root,
                path,
                FindingKind::Dockerfile,
                "Dockerfile can define build-time execution",
                &content,
                Severity::Medium,
                &[
                    Capability::ProcessSpawn,
                    Capability::NetworkAccess,
                    Capability::ContainerControl,
                ],
            ));
        } else if normalized == "docker-compose.yml"
            || normalized == "docker-compose.yaml"
            || normalized.ends_with("/docker-compose.yml")
            || normalized.ends_with("/docker-compose.yaml")
            || normalized == "compose.yml"
            || normalized == "compose.yaml"
        {
            let content = read_text(path)?;
            findings.push(finding_for_text(
                root,
                path,
                FindingKind::DockerCompose,
                "Docker Compose can define multi-container runtime behavior",
                &content,
                Severity::Medium,
                &[
                    Capability::ContainerControl,
                    Capability::NetworkAccess,
                    Capability::FilesystemRead,
                ],
            ));
        } else if normalized.ends_with("/build.rs") || normalized == "build.rs" {
            let content = read_text(path).unwrap_or_default();
            findings.push(finding_for_text(
                root,
                path,
                FindingKind::RustBuildScript,
                "Rust build script executes during Cargo builds",
                &content,
                Severity::High,
                &[
                    Capability::DependencyScriptExecution,
                    Capability::ProcessSpawn,
                    Capability::FilesystemRead,
                ],
            ));
        } else if normalized == "Makefile" || normalized.ends_with("/Makefile") {
            let content = read_text(path).unwrap_or_default();
            findings.push(finding_for_text(
                root,
                path,
                FindingKind::Makefile,
                "Makefile can define repository-controlled command execution",
                &content,
                Severity::Medium,
                &[Capability::ProcessSpawn, Capability::FilesystemRead],
            ));
        } else if normalized.starts_with(".github/workflows/")
            && (normalized.ends_with(".yml") || normalized.ends_with(".yaml"))
        {
            let content = read_text(path).unwrap_or_default();
            findings.push(finding_for_text(
                root,
                path,
                FindingKind::GithubWorkflow,
                "GitHub Actions workflow can execute repository-defined automation",
                &content,
                Severity::Medium,
                &[
                    Capability::ProcessSpawn,
                    Capability::NetworkAccess,
                    Capability::SecretAccess,
                ],
            ));
        } else if normalized.starts_with(".devcontainer/")
            && (normalized.ends_with(".json")
                || normalized.ends_with(".jsonc")
                || normalized.ends_with(".yml")
                || normalized.ends_with(".yaml"))
        {
            let content = read_text(path).unwrap_or_default();
            findings.push(finding_for_text(
                root,
                path,
                FindingKind::DevContainer,
                "Devcontainer configuration can run lifecycle commands",
                &content,
                Severity::Medium,
                &[
                    Capability::ContainerControl,
                    Capability::ProcessSpawn,
                    Capability::NetworkAccess,
                ],
            ));
        } else if normalized.starts_with(".git/hooks/") {
            let content = read_text(path).unwrap_or_default();
            findings.push(finding_for_text(
                root,
                path,
                FindingKind::GitHook,
                "Git hook can execute implicitly during git workflows",
                &content,
                Severity::High,
                &[Capability::GitHookExecution, Capability::ProcessSpawn],
            ));
        } else if normalized.ends_with(".sh")
            || normalized.ends_with(".ps1")
            || normalized.ends_with(".bat")
        {
            let content = read_text(path).unwrap_or_default();
            if looks_executable(&content) {
                findings.push(finding_for_text(
                    root,
                    path,
                    FindingKind::ShellScript,
                    "Script contains execution-capable commands",
                    &content,
                    Severity::Low,
                    &[Capability::ProcessSpawn, Capability::FilesystemRead],
                ));
            }
        } else if is_ai_instruction_file(&normalized) {
            let content = read_text(path).unwrap_or_default();
            if contains_prompt_control_markers(&content) {
                findings.push(finding_for_text(
                    root,
                    path,
                    FindingKind::AiInstruction,
                    "AI instruction file can influence agent behavior",
                    &content,
                    Severity::Medium,
                    &[Capability::PromptInfluence],
                ));
            }
        } else {
            let content = read_text(path).unwrap_or_default();
            if contains_suspicious_prompt_or_secret_access(&content) {
                findings.push(finding_for_text(
                    root,
                    path,
                    FindingKind::SuspiciousContent,
                    "File contains prompt or secret-access risk markers",
                    &content,
                    Severity::Medium,
                    &[Capability::PromptInfluence, Capability::SecretAccess],
                ));
            }
        }
    }
    Ok(())
}

fn finding_for_text(
    root: &Path,
    path: &Path,
    kind: FindingKind,
    title: &str,
    text: &str,
    baseline: Severity,
    baseline_capabilities: &[Capability],
) -> Finding {
    Finding {
        id: Uuid::new_v4(),
        kind,
        path: relative(root, path),
        title: title.to_string(),
        evidence: trim_evidence(text),
        severity: severity_for_text(text, baseline),
        capabilities: capabilities_for_text(text, baseline_capabilities),
    }
}

fn read_json(path: &Path) -> Result<Value> {
    let text = read_text(path)?;
    serde_json::from_str(&text).map_err(|source| AegisError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn read_text(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|source| AegisError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn capabilities_for_text(text: &str, baseline: &[Capability]) -> Vec<Capability> {
    let lower = text.to_ascii_lowercase();
    let mut capabilities: BTreeSet<Capability> = baseline.iter().cloned().collect();

    for marker in ["curl", "wget", "http://", "https://", "npm install", "pip install"] {
        if lower.contains(marker) {
            capabilities.insert(Capability::NetworkAccess);
        }
    }
    for marker in ["rm -rf", "del /", "remove-item", "writefile", "chmod", "mv "] {
        if lower.contains(marker) {
            capabilities.insert(Capability::FilesystemWrite);
        }
    }
    for marker in ["process.env", "$env:", "secret", "token", "api_key", "apikey", ".env", ".aws", ".ssh", "id_rsa"] {
        if lower.contains(marker) {
            capabilities.insert(Capability::SecretAccess);
        }
    }
    for marker in ["sudo", "setuid", "--privileged", "cap_add", "runas"] {
        if lower.contains(marker) {
            capabilities.insert(Capability::RuntimePrivilegeEscalation);
        }
    }
    for marker in ["docker", "containerd", "firecracker", "gvisor"] {
        if lower.contains(marker) {
            capabilities.insert(Capability::ContainerControl);
        }
    }

    capabilities.into_iter().collect()
}

fn severity_for_text(text: &str, baseline: Severity) -> Severity {
    let lower = text.to_ascii_lowercase();
    if ["sudo", "--privileged", "rm -rf /", "token", "api_key", "secret"]
        .iter()
        .any(|marker| lower.contains(marker))
    {
        Severity::Critical
    } else if ["curl", "wget", "mcp", "preinstall", "postinstall", ".git/hooks"]
        .iter()
        .any(|marker| lower.contains(marker))
    {
        Severity::High
    } else {
        baseline
    }
}

fn summarize_capabilities(findings: &[Finding]) -> Vec<CapabilitySummary> {
    let mut counts: BTreeMap<Capability, usize> = BTreeMap::new();
    for finding in findings {
        for capability in &finding.capabilities {
            *counts.entry(capability.clone()).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .map(|(capability, count)| CapabilitySummary { capability, count })
        .collect()
}

fn collect_json_strings(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(text) => output.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| collect_json_strings(item, output)),
        Value::Object(map) => map.values().for_each(|item| collect_json_strings(item, output)),
        _ => {}
    }
}

fn trim_evidence(text: &str) -> String {
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    compact.chars().take(500).collect()
}

fn looks_executable(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["curl", "wget", "npm", "python", "powershell", "bash", "sh ", "docker", "chmod", "sudo"]
        .iter()
        .any(|marker| lower.contains(marker))
}

fn contains_suspicious_prompt_or_secret_access(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["ignore previous instructions", "system prompt", "process.env", "api_key", "secret", "token"]
        .iter()
        .any(|marker| lower.contains(marker))
}

fn contains_prompt_control_markers(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "ignore previous instructions",
        "system prompt",
        "developer message",
        "tool call",
        "run command",
        "execute",
        "autonomous",
        "agent",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn is_ai_instruction_file(normalized: &str) -> bool {
    normalized == "AGENTS.md"
        || normalized == "CLAUDE.md"
        || normalized == ".cursorrules"
        || normalized == ".windsurfrules"
        || normalized.ends_with("/AGENTS.md")
        || normalized.ends_with("/CLAUDE.md")
        || normalized.ends_with("/.cursorrules")
        || normalized.ends_with("/.windsurfrules")
}

fn is_known_structured_file(normalized: &str) -> bool {
    normalized == "package.json"
        || normalized == ".vscode/tasks.json"
        || normalized == ".cursor/mcp.json"
        || normalized == ".mcp.json"
}

fn should_skip(path: &Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    normalized.contains("/target/")
        || normalized.contains("/node_modules/")
        || normalized.contains("/.venv/")
        || normalized.contains("/dist/")
}

fn relative(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn is_compiled_binary(path: &Path) -> bool {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or_default().to_lowercase();
    matches!(ext.as_str(), "exe" | "dll" | "so" | "dylib" | "bin" | "node")
}
