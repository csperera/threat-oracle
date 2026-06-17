"""
Hybrid Retrieval Layer
Dense (ChromaDB cosine) + Sparse (BM25) + RRF fusion.
Returns ranked ATT&CK technique matches for a given behaviour description.
"""

import json
import os
from pathlib import Path
from dotenv import load_dotenv
import chromadb
from chromadb import Documents, EmbeddingFunction, Embeddings
from rank_bm25 import BM25Okapi
import google.generativeai as genai

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)

DATA_DIR = Path(__file__).parent.parent / "data"
CHROMA_PATH = DATA_DIR / "chroma_db"
COLLECTION_NAME = "attck_techniques"
RRF_K = 60
TOP_K = 5


# --- Same Gemini embedding function as ingestion ---

class GeminiEmbeddingFunction(EmbeddingFunction):
    def __call__(self, input: Documents) -> Embeddings:
        embeddings = []
        for text in input:
            result = genai.embed_content(
                model="models/gemini-embedding-001",
                content=text,
                task_type="retrieval_query",
            )
            embeddings.append(result["embedding"])
        return embeddings


class HybridRetriever:
    def __init__(self):
        self._collection = None
        self._bm25 = None
        self._all_docs = None
        self._all_ids = None
        self._all_metadata = None
        self._technique_lookup = None

    def _load_collection(self):
        if self._collection is not None:
            return
        client = chromadb.PersistentClient(path=str(CHROMA_PATH))
        ef = GeminiEmbeddingFunction()
        self._collection = client.get_collection(
            name=COLLECTION_NAME,
            embedding_function=ef,
        )
        print(f"[Retrieval] Loaded collection: {self._collection.count()} techniques")

    def _build_bm25(self):
        if self._bm25 is not None:
            return
        self._load_collection()
        result = self._collection.get(include=["documents", "metadatas"])
        self._all_docs = result["documents"]
        self._all_ids = result["ids"]
        self._all_metadata = result["metadatas"]
        tokenized = [doc.lower().split() for doc in self._all_docs]
        self._bm25 = BM25Okapi(tokenized)
        print(f"[Retrieval] BM25 index built: {len(self._all_docs)} documents")

    def _load_technique_lookup(self):
        if self._technique_lookup is not None:
            return
        lookup_path = DATA_DIR / "attck" / "technique_lookup.json"
        if lookup_path.exists():
            self._technique_lookup = json.loads(lookup_path.read_text())
        else:
            self._technique_lookup = {}

    def _dense_search(self, query: str, n_results: int = 20) -> list:
        self._load_collection()
        results = self._collection.query(
            query_texts=[query],
            n_results=min(n_results, self._collection.count()),
            include=["documents", "metadatas", "distances"],
        )
        hits = []
        for i, doc_id in enumerate(results["ids"][0]):
            distance = results["distances"][0][i]
            similarity = 1.0 - distance
            hits.append({
                "id": doc_id,
                "score": similarity,
                "raw_similarity": similarity,
                "document": results["documents"][0][i],
                "metadata": results["metadatas"][0][i],
            })
        return hits

    def _sparse_search(self, query: str, n_results: int = 20) -> list:
        self._build_bm25()
        tokens = query.lower().split()
        scores = self._bm25.get_scores(tokens)
        ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:n_results]
        return [
            {
                "id": self._all_ids[idx],
                "score": float(scores[idx]),
                "raw_similarity": 0.0,  # BM25 has no similarity score
                "document": self._all_docs[idx],
                "metadata": self._all_metadata[idx],
            }
            for idx in ranked
        ]

    def _rrf_fusion(self, dense_hits: list, sparse_hits: list) -> list:
        rrf_scores = {}
        raw_sim_map = {}
        doc_map = {}

        for rank, hit in enumerate(dense_hits):
            doc_id = hit["id"]
            rrf_scores[doc_id] = rrf_scores.get(doc_id, 0) + 1 / (RRF_K + rank + 1)
            raw_sim_map[doc_id] = hit["raw_similarity"]
            doc_map[doc_id] = hit

        for rank, hit in enumerate(sparse_hits):
            doc_id = hit["id"]
            rrf_scores[doc_id] = rrf_scores.get(doc_id, 0) + 1 / (RRF_K + rank + 1)
            if doc_id not in doc_map:
                doc_map[doc_id] = hit

        # Blend raw cosine similarity + RRF position signal
        blended_scores = {}
        for doc_id, rrf_score in rrf_scores.items():
            raw_sim = raw_sim_map.get(doc_id, 0.5)
            rrf_normalized = min(rrf_score * 80, 0.95)
            # 60% raw cosine similarity + 40% RRF position
            blended = (raw_sim * 0.6) + (rrf_normalized * 0.4)
            blended_scores[doc_id] = round(min(blended, 0.97), 2)

        ranked = sorted(blended_scores.items(), key=lambda x: x[1], reverse=True)

        results = []
        for doc_id, confidence in ranked:
            hit = doc_map[doc_id]
            results.append({
                "technique_id": doc_id,
                "name": hit["metadata"].get("name", ""),
                "tactic_str": hit["metadata"].get("tactic_str", ""),
                "confidence": confidence,
                "url": hit["metadata"].get("url", ""),
                "metadata": hit["metadata"],
            })
        return results

    def search(self, query: str, top_k: int = TOP_K) -> list:
        """
        Hybrid search for a single query string.
        Returns top_k ATT&CK techniques ranked by confidence.
        """
        self._load_technique_lookup()
        dense = self._dense_search(query, n_results=20)
        sparse = self._sparse_search(query, n_results=20)
        fused = self._rrf_fusion(dense, sparse)

        enriched = []
        for hit in fused[:top_k]:
            tid = hit["technique_id"]
            full = self._technique_lookup.get(tid, {})
            hit["description"] = full.get("description", "")[:600]
            hit["detection"] = full.get("detection", "")[:400]
            hit["is_subtechnique"] = full.get("is_subtechnique", False)
            hit["parent_id"] = full.get("parent_id", "")
            enriched.append(hit)

        return enriched

    def search_behaviours(self, behaviours: list) -> list:
        """
        Search across multiple behaviour dicts from normalized JSON.
        Deduplicates techniques, keeps highest confidence per technique.
        Returns unified ranked list capped at 10.
        """
        all_results = {}

        for behaviour in behaviours:
            desc = behaviour.get("description", "")
            protocol = behaviour.get("protocol", "")
            pattern = behaviour.get("pattern", "")
            query = f"{desc} {protocol} {pattern}".strip()

            if not query:
                continue

            hits = self.search(query, top_k=TOP_K)
            for hit in hits:
                tid = hit["technique_id"]
                if tid not in all_results or hit["confidence"] > all_results[tid]["confidence"]:
                    hit["matched_behaviour"] = desc
                    all_results[tid] = hit

        return sorted(all_results.values(), key=lambda x: x["confidence"], reverse=True)[:10]


# Singleton for reuse across agents
_retriever = None

def get_retriever() -> HybridRetriever:
    global _retriever
    if _retriever is None:
        _retriever = HybridRetriever()
    return _retriever


if __name__ == "__main__":
    retriever = HybridRetriever()
    test_queries = [
        "SSH scanning multiple hosts failed authentication attempts",
        "large outbound data transfer Tor exit node",
        "cmd.exe whoami net user process spawned",
    ]
    for q in test_queries:
        print(f"\nQuery: {q}")
        results = retriever.search(q, top_k=3)
        for r in results:
            print(f"  {r['technique_id']} — {r['name']} | Confidence: {r['confidence']} | Tactic: {r['tactic_str']}")