import httpx
from typing import List, Dict, Any

class Capabilities:
    FILESYSTEM_READ = "FilesystemRead"
    FILESYSTEM_WRITE = "FilesystemWrite"
    NETWORK_ACCESS = "NetworkAccess"
    PROCESS_SPAWN = "ProcessSpawn"

class AegisAgent:
    """
    AEGIS SDK (Tier 2/3 Developer Ecosystem).
    Allows developers to rapidly build governed agents in 3 lines of code.
    """
    def __init__(self, name: str, host: str = "http://localhost:8000"):
        self.name = name
        self.host = host
        self.session_id = f"{name}_session"

    def request_governance(self, capabilities: List[str], context: Dict[str, Any]) -> bool:
        """Requests route approval from the Governance Engine."""
        payload = {
            "session_id": self.session_id,
            "context_payload": context,
            "requested_capabilities": capabilities
        }
        response = httpx.post(f"{self.host}/orchestrate/route", json=payload)
        response.raise_for_status()
        data = response.json()
        if data.get("approved"):
            print(f"[AEGIS SDK] Governance approved for {self.name}.")
            return True
        else:
            print(f"[AEGIS SDK] Governance BLOCKED for {self.name}. Reason: {data.get('reasoning')}")
            return False

    def execute_in_sandbox(self, command: List[str]) -> Dict[str, Any]:
        """Executes a command within the approved Tier 4 sandbox."""
        payload = {
            "session_id": self.session_id,
            "command": command
        }
        response = httpx.post(f"{self.host}/os/execute", json=payload)
        if response.status_code == 403:
            raise Exception("Sandbox execution rejected by Governance.")
        return response.json()
