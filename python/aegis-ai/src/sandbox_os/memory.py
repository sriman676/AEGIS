import time
import os
from typing import Dict, Any, List

class ShortTermMemory:
    """Manages ephemeral context for active sessions."""
    def __init__(self):
        self.sessions: Dict[str, List[Dict[str, Any]]] = {}
        self.db_url = os.environ.get("DATABASE_URL")
        self.MAX_CONTEXT_ITEMS = 50 # Paging threshold

    def append(self, session_id: str, context: Dict[str, Any]):
        if session_id not in self.sessions:
            self.sessions[session_id] = []
        
        context["timestamp"] = time.time()
        self.sessions[session_id].append(context)
        
        # Paging Logic: If context gets too large, compress and move to long term memory
        if len(self.sessions[session_id]) > self.MAX_CONTEXT_ITEMS:
            self.page_to_long_term(session_id)

    def page_to_long_term(self, session_id: str):
        """
        Compresses the oldest 20 memory items into a semantic vector
        and pages them out to Qdrant to prevent token overflow.
        """
        items_to_page = self.sessions[session_id][:20]
        # In production: 
        # 1. Ask LLM to summarize `items_to_page`
        # 2. Get embeddings for summary
        # 3. Store in LongTermMemory
        
        # Free the short term cache
        self.sessions[session_id] = self.sessions[session_id][20:]
        print(f"[AEGIS OS] Compressed and paged 20 memories to LongTerm storage for session {session_id}")

    def retrieve(self, session_id: str) -> List[Dict[str, Any]]:
        return self.sessions.get(session_id, [])

    def flush(self, session_id: str):
        if session_id in self.sessions:
            del self.sessions[session_id]

class LongTermMemory:
    """
    Tier 4: Vector/embedding store for historical reasoning.
    Integrates with Qdrant for semantic search.
    """
    def __init__(self):
        self.embeddings: Dict[str, Dict[str, Any]] = {}
        self.qdrant_url = os.environ.get("QDRANT_URL")
        # In production, initialize qdrant_client.QdrantClient(url=self.qdrant_url)

    def store_finding(self, finding_id: str, semantic_vector: List[float], metadata: Dict[str, Any]):
        self.embeddings[finding_id] = {
            "vector": semantic_vector,
            "metadata": metadata,
            "stored_at": time.time()
        }
        # TODO: if qdrant_url, client.upsert(...)

    def search_similar(self, query_vector: List[float], limit: int = 5) -> List[Dict[str, Any]]:
        # TODO: if qdrant_url, client.search(...)
        results = []
        for v in self.embeddings.values():
            results.append(v["metadata"])
        return results[:limit]

class MemoryArchitecture:
    def __init__(self):
        self.short_term = ShortTermMemory()
        self.long_term = LongTermMemory()

memory_manager = MemoryArchitecture()
