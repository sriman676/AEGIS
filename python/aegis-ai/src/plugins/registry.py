from typing import Dict, Any

class PluginRegistry:
    """
    Manages custom extensions for AEGIS.
    Allows the community to add custom capabilities (e.g. AWS_Cloud_Access) 
    that the Governance Engine can load at runtime.
    """
    def __init__(self):
        self.plugins: Dict[str, Any] = {}

    def register_capability(self, capability_name: str, handler: Any):
        self.plugins[capability_name] = handler
        print(f"[PluginRegistry] Registered community capability: {capability_name}")

    def get_capability(self, capability_name: str) -> Any:
        return self.plugins.get(capability_name)

registry = PluginRegistry()
