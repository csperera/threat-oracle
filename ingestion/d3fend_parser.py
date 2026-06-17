"""
MITRE D3FEND Parser
Queries D3FEND API per ATT&CK technique ID and builds a local lookup table.
API endpoint: https://d3fend.mitre.org/api/offensive-technique/attack/{id}.json
"""

import json
import os
import time
import requests
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data" / "d3fend"
ATTCK_DIR = Path(__file__).parent.parent / "data" / "attck"
OUT_FILE = DATA_DIR / "d3fend_lookup.json"

BASE_URL = "https://d3fend.mitre.org/api/offensive-technique/attack/{technique_id}.json"


def infer_category(name: str) -> str:
    name_lower = name.lower()
    if any(w in name_lower for w in ["harden", "isolate", "filter", "block", "encrypt", "policy", "restrict", "allowlist", "credential"]):
        return "Prevent"
    if any(w in name_lower for w in ["detect", "analyze", "monitor", "log", "audit", "scan", "inspect", "analysis"]):
        return "Detect"
    if any(w in name_lower for w in ["respond", "contain", "restore", "recover", "remediat", "evict"]):
        return "Respond"
    return "Other"


def fetch_technique(technique_id: str) -> list:
    """Fetch D3FEND countermeasures for a single ATT&CK technique ID."""
    url = BASE_URL.format(technique_id=technique_id)
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 404:
            return []
        r.raise_for_status()
        data = r.json()
        bindings = data.get("off_to_def", {}).get("results", {}).get("bindings", [])
        countermeasures = []
        for b in bindings:
            name = b.get("def_tech_label", {}).get("value", "")
            d3fend_id = b.get("def_tech_id", {}).get("value", "")
            if not name:
                continue
            cm = {
                "d3fend_id": d3fend_id,
                "name": name,
                "category": infer_category(name),
                "url": f"https://d3fend.mitre.org/technique/d3f:{name.replace(' ', '')}",
            }
            if not any(x["name"] == name for x in countermeasures):
                countermeasures.append(cm)
        priority = {"Prevent": 1, "Detect": 2, "Respond": 3, "Other": 4}
        countermeasures.sort(key=lambda x: priority.get(x["category"], 4))
        return countermeasures
    except Exception as e:
        print(f"  [WARN] {technique_id}: {e}")
        return []


def run():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Load technique IDs from our ATT&CK lookup
    lookup_path = ATTCK_DIR / "technique_lookup.json"
    technique_ids = list(json.loads(lookup_path.read_text()).keys())
    print(f"[D3FEND] Querying {len(technique_ids)} techniques...")

    lookup = {}
    for i, tid in enumerate(technique_ids):
        cms = fetch_technique(tid)
        if cms:
            lookup[tid] = cms
        if (i + 1) % 25 == 0:
            print(f"[D3FEND] Progress: {i+1}/{len(technique_ids)} — {len(lookup)} techniques mapped so far")
            OUT_FILE.write_text(json.dumps(lookup, indent=2))  # Save progress
        time.sleep(0.3)  # Be polite to the API

    OUT_FILE.write_text(json.dumps(lookup, indent=2))
    print(f"[D3FEND] Done — {len(lookup)} technique mappings saved to {OUT_FILE}")

    # Sanity check
    for tid in ["T1110.003", "T1046", "T1090.003", "T1048"]:
        cms = lookup.get(tid, [])
        print(f"  {tid}: {len(cms)} countermeasures")


if __name__ == "__main__":
    run()