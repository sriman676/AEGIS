use crate::model::{ExecutionGraph, Finding, GraphEdge, GraphNode};

pub fn build_execution_graph(findings: &[Finding]) -> ExecutionGraph {
    let mut graph = ExecutionGraph::default();

    graph.nodes.push(GraphNode {
        id: "repository".to_string(),
        label: "repository".to_string(),
        node_type: "root".to_string(),
        path: None,
    });

    for finding in findings {
        let finding_node_id = finding.id.to_string();
        graph.nodes.push(GraphNode {
            id: finding_node_id.clone(),
            label: finding.title.clone(),
            node_type: format!("{:?}", finding.kind).to_lowercase(),
            path: Some(finding.path.clone()),
        });
        graph.edges.push(GraphEdge {
            from: "repository".to_string(),
            to: finding_node_id.clone(),
            relationship: "contains_execution_surface".to_string(),
        });

        for capability in &finding.capabilities {
            let capability_id = format!("capability::{capability:?}").to_lowercase();
            if !graph.nodes.iter().any(|node| node.id == capability_id) {
                graph.nodes.push(GraphNode {
                    id: capability_id.clone(),
                    label: format!("{capability:?}"),
                    node_type: "capability".to_string(),
                    path: None,
                });
            }
            graph.edges.push(GraphEdge {
                from: finding_node_id.clone(),
                to: capability_id,
                relationship: "requests_capability".to_string(),
            });
        }
    }

    graph
}

