import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.context_parser import parse_context_from_graph

def test_parse_context_with_repo_url():
    graph = {
        "nodes": [
            {"id": "node1", "node_type": "script", "label": "build.sh", "path": "/src/build.sh"}
        ],
        "edges": [
            {"from": "node1", "to": "node2", "relationship": "calls"}
        ]
    }
    result = parse_context_from_graph(graph, repository_url="https://github.com/example/repo")

    assert "Repository Origin: https://github.com/example/repo" in result
    assert "Execution Nodes Found (1 total):" in result
    assert "- Node [node1]: Type='script', Label='build.sh', Path='/src/build.sh'" in result
    assert "Execution Relationships (Edges):" in result
    assert "- node1 --[calls]--> node2" in result

def test_parse_context_without_repo_url():
    graph = {
        "nodes": [],
        "edges": []
    }
    result = parse_context_from_graph(graph)

    assert "Repository Origin: Local Workspace (Unidentified)" in result

def test_parse_context_empty_graph():
    graph = {}
    result = parse_context_from_graph(graph)

    assert "Execution Nodes Found (0 total):" in result
    assert "Execution Relationships (Edges):" in result

def test_parse_context_missing_keys():
    graph = {
        "nodes": [
            {}  # Missing all expected keys
        ],
        "edges": [
            {}  # Missing all expected keys
        ]
    }
    result = parse_context_from_graph(graph)

    assert "- Node [unknown]: Type='unknown', Label='', Path='N/A'" in result
    assert "- unknown --[unknown]--> unknown" in result
