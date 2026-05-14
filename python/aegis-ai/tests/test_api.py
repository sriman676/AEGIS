import sys
import os
import os.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fastapi.testclient import TestClient
from src.main import app
from src.security import AEGIS_API_KEY

client = TestClient(app)
client.headers.update({"X-AEGIS-Key": AEGIS_API_KEY})

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_os_execute_blocked():
    payload = {
        "session_id": "00000000-0000-4000-8000-000000000000",
        "command": ["echo", "test"]
    }
    response = client.post("/os/execute", json=payload)
    assert response.status_code == 403
    assert "Session not routed" in response.json()["detail"]

def test_os_execute_allowed():
    # Route session first
    route_payload = {
        "session_id": "11111111-1111-4000-8000-111111111111",
        "context_payload": {"test": "data"},
        "requested_capabilities": ["FilesystemRead"]
    }
    client.post("/orchestrate/route", json=route_payload)

    # Now execute
    exec_payload = {
        "session_id": "11111111-1111-4000-8000-111111111111",
        "command": ["python", "--version"]
    }
    response = client.post("/os/execute", json=exec_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert "Python" in data["stdout"]
    payload = {
        "session_id": "22222222-2222-4000-8000-222222222222",
        "context_payload": {"test": "data"},
        "requested_capabilities": ["FilesystemRead"]
    }
    response = client.post("/orchestrate/route", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["approved"] is True
    assert data["escalation_required"] is False

def test_orchestrator_route_dangerous():
    payload = {
        "session_id": "33333333-3333-4000-8000-333333333333",
        "context_payload": {"test": "data"},
        "requested_capabilities": ["ProcessSpawn"]
    }
    response = client.post("/orchestrate/route", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["approved"] is False
    assert data["escalation_required"] is True

def test_analyze_semantics_fallback():
    payload = {
        "repository_url": "https://github.com/example/repo",
        "execution_graph": {"nodes": []},
        "capabilities": [
            {"id": "cap_1", "type": "network", "confidence": 0.9}
        ]
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    # Asserting response schema compliance
    assert "classifications" in data
    assert "annotations" in data
    assert "explanations" in data
    assert "risk_enrichment" in data
    
    # High confidence capability should trigger 'semantic-chain-detected' in the mock logic
    assert "semantic-chain-detected" in data["classifications"]

def test_repo_intake_path_traversal():
    # Attempt to traverse outside the base directory using an absolute path to /etc/passwd
    payload_absolute = {
        "path": "/etc/passwd"
    }
    response_abs = client.post("/repo/intake", json=payload_absolute)
    assert response_abs.status_code == 403
    assert "outside allowed repository directory" in response_abs.json()["detail"]

    # Attempt to traverse outside the base directory using a relative path with '..'
    payload_relative = {
        "path": "../../../../../../etc/passwd"
    }
    response_rel = client.post("/repo/intake", json=payload_relative)
    assert response_rel.status_code == 403
    assert "outside allowed repository directory" in response_rel.json()["detail"]
