use crate::model::{CapabilitySummary, ExecutionGraph};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize)]
pub struct SemanticAnalysisRequest {
    pub repository_url: Option<String>,
    pub execution_graph: ExecutionGraph,
    pub capabilities: Vec<CapabilityNode>,
}

#[derive(Serialize)]
pub struct CapabilityNode {
    pub id: String,
    pub r#type: String,
    pub confidence: f32,
}

#[derive(Deserialize, Debug)]
pub struct SemanticAnalysisResponse {
    pub classifications: Vec<String>,
    pub annotations: HashMap<String, String>,
    pub explanations: Vec<String>,
    pub risk_enrichment: HashMap<String, serde_json::Value>,
}

pub fn analyze_semantics(
    endpoint_url: &str,
    graph: &ExecutionGraph,
    caps: &[CapabilitySummary],
) -> Result<SemanticAnalysisResponse, reqwest::Error> {
    let client = reqwest::blocking::Client::new();
    let capabilities = caps
        .iter()
        .map(|c| CapabilityNode {
            id: format!("cap_{:?}", c.capability).to_lowercase(),
            r#type: format!("{:?}", c.capability),
            confidence: 1.0, // Assuming static capabilities are found with 1.0 confidence for now
        })
        .collect();

    let req = SemanticAnalysisRequest {
        repository_url: None,
        execution_graph: graph.clone(),
        capabilities,
    };

    let resp = client
        .post(endpoint_url)
        .json(&req)
        .send()?
        .error_for_status()?
        .json::<SemanticAnalysisResponse>()?;

    Ok(resp)
}
