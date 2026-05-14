from typing import Dict, Any

def parse_context_from_graph(execution_graph: Dict[str, Any], repository_url: str = None) -> str:
    """
    Parses an execution graph to generate a semantic string context suitable for an LLM prompt.
    This adheres to the 'hostile-by-default' invariant by ONLY parsing metadata and text,
    and NEVER executing any scripts or workflows found in the graph.
    """
    context_lines = []
    
    if repository_url:
        context_lines.append(f"Repository Origin: {repository_url}")
    else:
        context_lines.append("Repository Origin: Local Workspace (Unidentified)")

    nodes = execution_graph.get("nodes", [])
    edges = execution_graph.get("edges", [])

    context_lines.append(f"\nExecution Nodes Found ({len(nodes)} total):")
    for node in nodes:
        node_id = node.get("id", "unknown")
        node_type = node.get("node_type", "unknown")
        label = node.get("label", "")
        path = node.get("path", "N/A")
        
        context_lines.append(f"- Node [{node_id}]: Type='{node_type}', Label='{label}', Path='{path}'")

    context_lines.append("\nExecution Relationships (Edges):")
    for edge in edges:
        from_node = edge.get("from", "unknown")
        to_node = edge.get("to", "unknown")
        rel = edge.get("relationship", "unknown")
        
        context_lines.append(f"- {from_node} --[{rel}]--> {to_node}")

    return "\n".join(context_lines)
