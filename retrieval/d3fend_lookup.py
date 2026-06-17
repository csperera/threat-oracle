"""
D3FEND Lookup
Loads the d3fend_lookup.json built by d3fend_parser.py
and provides countermeasure lookups by ATT&CK technique ID.
"""

import json
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data" / "d3fend"


class D3FENDLookup:
    def __init__(self):
        self._lookup = {}
        self._load()

    def _load(self):
        lookup_path = DATA_DIR / "d3fend_lookup.json"
        if lookup_path.exists():
            self._lookup = json.loads(lookup_path.read_text())
            print(f"[D3FEND] Loaded {len(self._lookup)} technique mappings")
        else:
            print("[D3FEND] WARNING: No lookup table found. Run d3fend_parser.py first.")

    def get(self, technique_id: str) -> list:
        """Get countermeasures for a technique ID. Falls back to parent technique."""
        cms = self._lookup.get(technique_id, [])
        if not cms and "." in technique_id:
            cms = self._lookup.get(technique_id.split(".")[0], [])
        return cms