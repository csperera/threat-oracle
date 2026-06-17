"""
MITRE ATT&CK Ingestion
Downloads enterprise-attack STIX bundle, parses techniques,
embeds via Gemini, stores in ChromaDB.
Run once to build the knowledge base.
"""

import json
import os
import time
import requests
import chromadb
from chromadb import Documents, EmbeddingFunction, Embeddings
from pathlib import Path
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)

DATA_DIR = Path(__file__).parent.parent / "data" / "attck"
CHROMA_PATH = Path(__file__).parent.parent / "data" / "chroma_db"
COLLECTION_NAME = "attck_techniques"
ATTCK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


# --- Custom Gemini Embedding Function for ChromaDB ---

class GeminiEmbeddingFunction(EmbeddingFunction):
    def __call__(self, input: Documents) -> Embeddings:
        embeddings = []
        for text in input:
            result = genai.embed_content(
                model="models/gemini-embedding-001",
                content=text,
                task_type="retrieval_document",
            )
            embeddings.append(result["embedding"])
        return embeddings


# --- Download ---

def download_attck(force=False):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    out_path = DATA_DIR / "enterprise-attack.json"
    if out_path.exists() and not force:
        print(f"[ATT&CK] Already downloaded: {out_path}")
        return out_path
    print("[ATT&CK] Downloading enterprise-attack STIX bundle (~12MB)...")
    r = requests.get(ATTCK_URL, timeout=120)
    r.raise_for_status()
    out_path.write_bytes(r.content)
    print(f"[ATT&CK] Saved ({len(r.content)//1024}KB)")
    return out_path


# --- Parse ---

def parse_attck(stix_path: Path):
    data = json.loads(stix_path.read_text())
    objects = data["objects"]

    # Tactic shortname -> display name
    tactic_lookup = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            tactic_lookup[obj["x_mitre_shortname"]] = obj["name"]

    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        # Technique ID
        technique_id = None
        url = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url = ref.get("url")
                break
        if not technique_id:
            continue

        # Tactics
        tactics = [
            tactic_lookup.get(p["phase_name"], p["phase_name"])
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]

        is_sub = obj.get("x_mitre_is_subtechnique", False)

        techniques.append({
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "tactics": tactics,
            "tactic_str": ", ".join(tactics),
            "description": obj.get("description", ""),
            "detection": obj.get("x_mitre_detection", ""),
            "platforms": obj.get("x_mitre_platforms", []),
            "is_subtechnique": is_sub,
            "parent_id": technique_id.split(".")[0] if is_sub else "",
            "url": url or "",
        })

    print(f"[ATT&CK] Parsed {len(techniques)} techniques")
    return techniques


# --- Chunk ---

def chunk_technique(t: dict) -> dict:
    parts = [
        f"Technique: {t['technique_id']} — {t['name']}",
        f"Tactics: {t['tactic_str']}",
    ]
    if t["description"]:
        parts.append(f"Description: {t['description'][:1500]}")
    if t["detection"]:
        parts.append(f"Detection: {t['detection'][:800]}")
    if t["platforms"]:
        parts.append(f"Platforms: {', '.join(t['platforms'])}")
    return {
        "text": "\n".join(parts),
        "metadata": {
            "technique_id": t["technique_id"],
            "name": t["name"],
            "tactic_str": t["tactic_str"],
            "is_subtechnique": str(t["is_subtechnique"]),
            "parent_id": t["parent_id"],
            "url": t["url"],
            "source": "attck",
        },
    }


# --- Embed + Store ---

def build_chroma_collection(techniques: list):
    CHROMA_PATH.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))

    try:
        client.delete_collection(COLLECTION_NAME)
        print(f"[ATT&CK] Cleared existing collection")
    except Exception:
        pass

    ef = GeminiEmbeddingFunction()
    collection = client.create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )

    chunks = [chunk_technique(t) for t in techniques]
    batch_size = 50
    total_batches = -(-len(chunks) // batch_size)  # ceiling division

    for i in range(0, len(chunks), batch_size):
        batch = chunks[i:i + batch_size]
        collection.add(
            documents=[c["text"] for c in batch],
            metadatas=[c["metadata"] for c in batch],
            ids=[c["metadata"]["technique_id"] for c in batch],
        )
        batch_num = i // batch_size + 1
        print(f"[ATT&CK] Embedded batch {batch_num}/{total_batches} ({len(batch)} chunks)")
        if batch_num < total_batches:
            print(f"[ATT&CK] Waiting 65s for rate limit...")
            time.sleep(65)

    print(f"[ATT&CK] Done — {collection.count()} techniques in ChromaDB")
    return collection


# --- Lookup Table ---

def save_technique_lookup(techniques: list):
    lookup = {t["technique_id"]: t for t in techniques}
    out_path = DATA_DIR / "technique_lookup.json"
    out_path.write_text(json.dumps(lookup, indent=2))
    print(f"[ATT&CK] Lookup saved: {len(lookup)} entries")
    return lookup


# --- Main ---

if __name__ == "__main__":
    stix_path = download_attck()
    techniques = parse_attck(stix_path)
    save_technique_lookup(techniques)
    build_chroma_collection(techniques)