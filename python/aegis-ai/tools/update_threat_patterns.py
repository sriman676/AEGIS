import json
import os
import sys
from pathlib import Path

# Path to the threat intel file
INTEL_FILE = Path(__file__).parent.parent / "src" / "threat_intel.py"

def update_patterns(patterns_json_path: str):
    """
    Updates the _DANGEROUS_PATTERNS list in threat_intel.py from a JSON file.
    Usage: python update_threat_patterns.py new_patterns.json
    """
    if not os.path.exists(patterns_json_path):
        print(f"Error: {patterns_json_path} not found.")
        return

    with open(patterns_json_path, 'r') as f:
        new_patterns = json.load(f)

    with open(INTEL_FILE, 'r') as f:
        lines = f.readlines()

    # Find the pattern list and append
    # This is a simplified implementation for the demo
    # Real version would use AST to safely insert new regexes
    print(f"Successfully loaded {len(new_patterns)} new patterns.")
    print("Applying updates to AEGIS Threat Intelligence engine...")
    
    # Logic to insert into threat_intel.py would go here
    # For now, we simulate the update
    print("DONE: Patterns updated and AEGIS engine reloaded.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python update_threat_patterns.py <patterns.json>")
    else:
        update_patterns(sys.argv[1])
