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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Capability, FindingKind, Severity};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn create_finding(capabilities: Vec<Capability>) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            kind: FindingKind::VscodeTask,
            path: PathBuf::from(".vscode/tasks.json"),
            title: "Test Task".to_string(),
            evidence: "some evidence".to_string(),
            severity: Severity::Medium,
            capabilities,
        }
    }

    #[test]
    fn test_empty_findings() {
        let findings = vec![];
        let graph = build_execution_graph(&findings);

        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.nodes[0].id, "repository");
        assert_eq!(graph.nodes[0].node_type, "root");
        assert_eq!(graph.edges.len(), 0);
    }

    #[test]
    fn test_single_finding_no_capabilities() {
        let finding = create_finding(vec![]);
        let findings = vec![finding.clone()];

        let graph = build_execution_graph(&findings);

        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.nodes[0].id, "repository");
        assert_eq!(graph.nodes[1].id, finding.id.to_string());
        assert_eq!(graph.nodes[1].node_type, "vscodetask");

        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].from, "repository");
        assert_eq!(graph.edges[0].to, finding.id.to_string());
        assert_eq!(graph.edges[0].relationship, "contains_execution_surface");
    }

    #[test]
    fn test_single_finding_with_capabilities() {
        let finding = create_finding(vec![Capability::FilesystemRead, Capability::NetworkAccess]);
        let findings = vec![finding.clone()];

        let graph = build_execution_graph(&findings);

        assert_eq!(graph.nodes.len(), 4); // repository, finding, filesystem_read, network_access
        assert_eq!(graph.edges.len(), 3); // repo->finding, finding->filesystem_read, finding->network_access

        let fs_cap_id = "capability::filesystemread".to_string();
        let net_cap_id = "capability::networkaccess".to_string();

        assert!(graph.nodes.iter().any(|n| n.id == fs_cap_id && n.node_type == "capability"));
        assert!(graph.nodes.iter().any(|n| n.id == net_cap_id && n.node_type == "capability"));

        assert!(graph.edges.iter().any(|e| e.from == finding.id.to_string() && e.to == fs_cap_id && e.relationship == "requests_capability"));
        assert!(graph.edges.iter().any(|e| e.from == finding.id.to_string() && e.to == net_cap_id && e.relationship == "requests_capability"));
    }

    #[test]
    fn test_multiple_findings_shared_capability() {
        let finding1 = create_finding(vec![Capability::FilesystemRead]);
        let finding2 = create_finding(vec![Capability::FilesystemRead, Capability::ProcessSpawn]);
        let findings = vec![finding1.clone(), finding2.clone()];

        let graph = build_execution_graph(&findings);

        // Nodes: repository, finding1, finding2, capability::filesystemread, capability::processspawn
        assert_eq!(graph.nodes.len(), 5);

        // Edges: repo->finding1, repo->finding2, finding1->filesystemread, finding2->filesystemread, finding2->processspawn
        assert_eq!(graph.edges.len(), 5);

        let fs_cap_id = "capability::filesystemread".to_string();
        let ps_cap_id = "capability::processspawn".to_string();

        // Check node uniqueness for capability
        assert_eq!(graph.nodes.iter().filter(|n| n.id == fs_cap_id).count(), 1);

        // Check edges for finding1
        assert!(graph.edges.iter().any(|e| e.from == finding1.id.to_string() && e.to == fs_cap_id && e.relationship == "requests_capability"));

        // Check edges for finding2
        assert!(graph.edges.iter().any(|e| e.from == finding2.id.to_string() && e.to == fs_cap_id && e.relationship == "requests_capability"));
        assert!(graph.edges.iter().any(|e| e.from == finding2.id.to_string() && e.to == ps_cap_id && e.relationship == "requests_capability"));
    }
}
