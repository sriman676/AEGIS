use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    FilesystemRead,
    FilesystemWrite,
    ProcessSpawn,
    NetworkAccess,
    SecretAccess,
    ContainerControl,
    GitHookExecution,
    IdeTaskExecution,
    McpToolInvocation,
    PromptInfluence,
    DependencyScriptExecution,
    RuntimePrivilegeEscalation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Allow,
    Deny,
    Sandbox,
    Escalate,
    Adaptive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    VscodeTask,
    PackageScript,
    RustBuildScript,
    Makefile,
    GithubWorkflow,
    DevContainer,
    DockerCompose,
    GitHook,
    Dockerfile,
    ShellScript,
    AiInstruction,
    CursorConfig,
    McpConfig,
    SuspiciousContent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub kind: FindingKind,
    pub path: PathBuf,
    pub title: String,
    pub evidence: String,
    pub severity: Severity,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub relationship: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutionGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub finding_id: Uuid,
    pub mode: EnforcementMode,
    pub reason: String,
    pub invariant_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySummary {
    pub capability: Capability,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReport {
    pub session_id: Uuid,
    pub repository_root: PathBuf,
    pub hostile_by_default: bool,
    pub implicit_execution_allowed: bool,
    pub risk_score: u16,
    pub overall_severity: Severity,
    pub findings: Vec<Finding>,
    pub capability_summary: Vec<CapabilitySummary>,
    pub execution_graph: ExecutionGraph,
    pub policy_decisions: Vec<PolicyDecision>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantCheck {
    pub id: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantReport {
    pub checks: Vec<InvariantCheck>,
}

impl InvariantReport {
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|check| check.passed)
    }
}
