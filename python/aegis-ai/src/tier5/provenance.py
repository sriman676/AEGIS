import hashlib
import time

class ProvenanceLedger:
    """
    Implements 22_Provenance_Traceability.md
    Cryptographically signs execution lineages.
    """
    def __init__(self):
        self.ledger = []
        
    def sign_action(self, agent_id: str, action: str) -> str:
        payload = f"{agent_id}:{action}:{time.time()}".encode('utf-8')
        signature = hashlib.sha256(payload).hexdigest()
        self.ledger.append({"signature": signature, "agent": agent_id, "action": action})
        return signature
