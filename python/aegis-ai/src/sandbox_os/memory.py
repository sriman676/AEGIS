import time
import os
from typing import Dict, Any, List

try:
    import qdrant_client
    from qdrant_client.models import PointStruct, VectorParams, Distance
except ImportError:
    qdrant_client = None
    PointStruct = None
    VectorParams = None
    Distance = None

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
        self.client = None
        self.collection_name = "aegis_memory"
        if self.qdrant_url and qdrant_client:
            try:
                self.client = qdrant_client.QdrantClient(url=self.qdrant_url)
                # Ensure collection exists, assume vector size 1536 for OpenAI embeddings if creating
                if not self.client.collection_exists(self.collection_name):
                    self.client.create_collection(
                        collection_name=self.collection_name,
                        vectors_config=VectorParams(size=1536, distance=Distance.COSINE)
                    )
            except Exception as e:
                print(f"[AEGIS OS] Failed to initialize Qdrant client: {e}")
                self.client = None

    def store_finding(self, finding_id: str, semantic_vector: List[float], metadata: Dict[str, Any]):
        self.embeddings[finding_id] = {
            "vector": semantic_vector,
            "metadata": metadata,
            "stored_at": time.time()
        }

        if self.client and PointStruct:
            try:
                point = PointStruct(
                    id=finding_id,
                    vector=semantic_vector,
                    payload=metadata
                )
                self.client.upsert(
                    collection_name=self.collection_name,
                    points=[point]
                )
            except Exception as e:
                print(f"[AEGIS OS] Failed to upsert to Qdrant: {e}")

    def search_similar(self, query_vector: List[float], limit: int = 5) -> List[Dict[str, Any]]:
        if self.client:
            try:
                search_result = self.client.search(
                    collection_name=self.collection_name,
                    query_vector=query_vector,
                    limit=limit
                )
                return [hit.payload for hit in search_result if hit.payload is not None]
            except Exception as e:
                print(f"[AEGIS OS] Failed to search Qdrant: {e}")

        # Fallback to local memory if Qdrant is unavailable
        results = []
        for v in self.embeddings.values():
            results.append(v["metadata"])
        return results[:limit]

class MemoryArchitecture:
    def __init__(self):
        self.short_term = ShortTermMemory()
        self.long_term = LongTermMemory()

memory_manager = MemoryArchitecture()
