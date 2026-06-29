# ThreatOracle AI — ARCHITECTURE_LAYERS.md

ThreatOracle AI is a RAG-powered cybersecurity threat diagnostic engine that accepts arbitrary input —
raw log snippets, plain English descriptions of suspicious behaviour, or structured JSON from upstream
detection systems like AegisAI — and returns a complete ATT&CK/D3FEND diagnosis in under 30 seconds.
It ingests the complete MITRE ATT&CK knowledge base (600+ techniques, 14 tactics) and the D3FEND
countermeasure ontology as its knowledge corpus. ThreatOracle is Component 2 of a loosely coupled
AI SOC pipeline — accepts input from AegisAI, any SIEM (Splunk, Sentinel, Chronicle), or plain
English analyst input. Designed to compress 45 minutes of manual MITRE navigation into 30 seconds.

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║              THREATORACLE AI — 4-STAGE RAG DIAGNOSTIC PIPELINE                       ║
║   Component 2 of AI SOC Pipeline  ·  Loosely Coupled  ·  Any Input → ATT&CK Output   ║
║   Data flow: Ingest → Normalize → Retrieve → Lookup → Synthesize → Report            ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────────────────────────────┐
│  KNOWLEDGE BASE INGESTION  (one-time setup — runs before any query is processed)     │
│                                                                                      │
│  IN:   Three MITRE open-source knowledge bases — all Apache 2.0 licensed             │
│  OUT:  ChromaDB vector index + D3FEND JSON lookup table + ATLAS corpus (V2)          │
│                                                                                      │
│  How it works:                                                                       │
│                                                                                      │
│  SOURCE 1 — MITRE ATT&CK (ingestion/attck_ingestion.py):                             │
│  → Downloads enterprise-attack STIX bundle from github.com/mitre/cti (~12MB)         │
│  → Parses ~600+ active techniques — skips deprecated and revoked entries             │
│  → Chunks one technique per document containing:                                     │
│       technique ID · name · tactic · description (1500 chars) · detection (800 chars)│
│       platforms · is_subtechnique flag · parent_id · source URL                      │
│  → Embeds via Google Gemini (models/gemini-embedding-001)                            │
│       task_type="retrieval_document" · batches of 50 · 65-second rate limit pause    │
│  → Stores in ChromaDB PersistentClient at data/chroma_db/                            │
│       collection name: attck_techniques · cosine similarity metric                   │
│       technique IDs used as ChromaDB document IDs for direct lookup                  │
│  → Full technique metadata saved as flat JSON at data/attck/technique_lookup.json    │
│                                                                                      │
│  SOURCE 2 — MITRE D3FEND (ingestion/d3fend_parser.py):                               │
│  → Queries live D3FEND API per ATT&CK technique ID:                                  │
│       https://d3fend.mitre.org/api/offensive-technique/attack/{id}.json              │
│  → Extracts countermeasure name and D3FEND ID from API bindings                      │
│  → Infers category from name keywords: Prevent · Detect · Respond · Other            │
│  → Sorts by priority: Prevent → Detect → Respond → Other                             │
│  → Saves as flat JSON lookup at data/d3fend/d3fend_lookup.json keyed by technique ID │
│  → Progress saved every 25 techniques — resilient to API interruptions               │
│  → NOT embedded — pure key lookup at query time                                      │
│  → 0.3 second polite delay between API calls                                         │
│                                                                                      │
│  SOURCE 3 — MITRE ATLAS (V2):                                                        │
│  → github.com/mitre-atlas/atlas-data · ML-specific attack techniques                 │
│  → Adversarial ML · prompt injection · model poisoning · training data corruption    │
│  → Same chunking strategy as ATT&CK · tagged source="ATLAS" for filtering            │
│  → Planned for V2 — not required for MVP                                             │
│                                                                                      │
│  Key design decision — ATT&CK embedded, D3FEND as lookup:                            │
│  → ATT&CK is a semantic search problem — technique descriptions need vector search   │
│  → D3FEND is a graph relationship problem — technique ID maps to countermeasures     │
│  → Two different data structures for two fundamentally different retrieval patterns  │
└──────────────────────────────────────────────────────────────────────────────────────┘
                                           │  knowledge base ready for runtime queries
                                           ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  INPUT LAYER                                                                         │
│                                                                                      │
│  IN:   Any of three input formats                                                    │
│  OUT:  Raw input string passed to Normalization Agent                                │
│                                                                                      │
│  How it works:                                                                       │
│  Three input formats accepted interchangeably:                                       │
│                                                                                      │
│  FORMAT 1 — Raw log snippets:                                                        │
│    Network traffic logs · authentication logs · system event logs                    │
│    Example: "02:14:33 - Host 192.168.1.45 attempting SSH connections to              │
│    47 internal hosts in 3 minutes · Multiple failed authentication attempts"         │
│                                                                                      │
│  FORMAT 2 — Plain English description:                                               │
│    Analyst describing suspicious behaviour in natural language                       │
│    Example: "We are seeing unusual outbound traffic to a known Tor exit node         │
│    with 2.3GB of data transferred in under 3 minutes"                                │
│                                                                                      │
│  FORMAT 3 — Structured JSON from AegisAI or SIEM:                                    │
│    { "attack_type": "BruteForce", "confidence": 0.97,                                │
│      "src_ip": "192.168.1.45", "dst_port": 22, "timestamp": "..." }                  │
│                                                                                      │
│  UI entry points:                                                                    │
│  → Streamlit frontend: demo scenario dropdown + log paste text area + Analyze button │
│  → FastAPI backend: POST /analyze endpoint accepts raw_input + input_format          │
└──────────────────────────────────────────────────────────────────────────────────────┘
                                           │  raw input string
                                           ▼
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  STAGE 1 — NORMALIZATION AGENT (LLM)                                                 ║
║  agents/normalization_agent.py                                                       ║
║                                                                                      ║
║  IN:   Raw input string — any of the three formats above                             ║
║  OUT:  Standardized security JSON regardless of input format                         ║
║                                                                                      ║
║  How it works:                                                                       ║
║  → LLM call with structured system prompt containing:                                ║
║       Role definition: "You are a cybersecurity analyst extracting structured        ║
║       security features from arbitrary input"                                        ║
║       Explicit examples of each input format and expected JSON output                ║
║       JSON-only instruction — no explanation, no markdown, raw JSON only             ║
║  → LLM extracts security-relevant features regardless of input format:               ║
║       source IP addresses · destination IPs and ports · protocol                     ║
║       behaviour patterns · timing information · data volume                          ║
║       attack indicators · affected hosts                                             ║
║  → Pydantic validation on output — Optional fields throughout                        ║
║       Partial extraction always better than failure                                  ║
║       If a field is not in the input → leave it null, do not hallucinate             ║
║                                                                                      ║
║  Example output (from SSH brute force log input):                                    ║
║  {                                                                                   ║
║    "behaviours": [                                                                   ║
║      { "description": "Rapid SSH connections to 47 internal hosts",                  ║
║        "source_ip": "192.168.1.45", "protocol": "SSH",                               ║
║        "pattern": "scanning", "volume": "47 hosts in 3 minutes" }                    ║
║    ],                                                                                ║
║    "external_connections": ["185.220.101.x"],                                        ║
║    "data_transfer": "2.3GB outbound",                                                ║
║    "affected_hosts": ["192.168.1.45", "192.168.1.103"]                               ║
║  }                                                                                   ║
║                                                                                      ║
║  Key design decision:                                                                ║
║  The normalization stage is the secret sauce — it handles the diversity of real-world║
║  log formats without requiring users to pre-format their input                       ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
                                           │  standardized security JSON
                                           ▼
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  STAGE 2 — HYBRID RAG RETRIEVAL + D3FEND LOOKUP                                      ║
║  retrieval/hybrid_search.py + retrieval/d3fend_lookup.py                             ║
║                                                                                      ║
║  IN:   Standardized security JSON from Normalization Agent                           ║
║  OUT:  Top ATT&CK technique matches with confidence scores + D3FEND countermeasures  ║
║                                                                                      ║
║  How it works — three sub-steps:                                                     ║
║                                                                                      ║
║  STEP 2a — HYBRID SEARCH (retrieval/hybrid_search.py):                               ║
║  → Each behaviour in the normalized JSON becomes a separate query                    ║
║  → Dense search: Gemini embeddings → ChromaDB vector similarity                      ║
║  → Sparse search: BM25 keyword matching on technique names and descriptions          ║
║  → RRF Fusion: merge dense and sparse ranked lists by position, not score            ║
║       Position-based merging prevents one method from dominating                     ║
║  → Confidence threshold filter: ≥ 0.70 to appear in results                          ║
║  → Output per behaviour: top ATT&CK technique matches with confidence scores         ║
║                                                                                      ║
║  Why hybrid and not pure vector search:                                              ║
║  → A query like "SSH brute force" needs both semantic understanding AND keyword match║
║  → Pure vector search misses exact technique names like "T1110" & "Password Spraying"║
║  → Pure BM25 misses semantic variants — "credential stuffing" vs "password attack"   ║
║  → Hybrid with RRF fusion gets both signals                                          ║
║                                                                                      ║
║  STEP 2b — D3FEND LOOKUP (retrieval/d3fend_lookup.py):                               ║
║  → Takes top ATT&CK technique IDs from hybrid search                                 ║
║  → Direct key lookup in data/d3fend/d3fend_lookup.json — NOT semantic search         ║
║  → Returns all countermeasures mapped to each technique                              ║
║  → Pre-sorted by implementation priority: Prevent → Detect → Respond → Other         ║
║  → Each countermeasure includes: D3FEND ID · name · category · URL                   ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
                                           │  techniques + confidence + D3FEND countermeasures
                                           ▼
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  STAGE 3 — SYNTHESIS AGENT (LLM)                                                     ║
║  agents/synthesis_agent.py                                                           ║
║                                                                                      ║
║  IN:   All retrieval results — ranked techniques + evidence + D3FEND countermeasures ║
║  OUT:  Complete structured analyst report                                            ║
║                                                                                      ║
║  How it works:                                                                       ║
║  → LLM call with all retrieval results injected as context                           ║
║  → System prompt enforces grounding constraints:                                     ║
║       Every claim must be traceable to retrieved ATT&CK or D3FEND content            ║
║       Always cite technique IDs (e.g. T1110, T1021.004)                              ║
║       No hallucination — if not in retrieved context, do not state it                ║
║  → Report structure — six sections:                                                  ║
║                                                                                      ║
║  1. EXECUTIVE SUMMARY (boardroom ready — 2-3 sentences):                             ║
║     "Our systems have detected a successful brute force attack against internal SSH  ║
║      services, leading to the compromise of an internal host..."                     ║
║                                                                                      ║
║  2. DETECTED TECHNIQUES (ranked by confidence):                                      ║
║     T1110.003 — Password Spraying (91%) · Tactic: Credential Access                  ║
║     Evidence: Multiple failed SSH authentication attempts observed                   ║
║                                                                                      ║
║  3. D3FEND COUNTERMEASURES per technique (Prevent → Detect → Respond):               ║
║     → D3-ALO Account Lockout [Prevent]                                               ║
║     → D3-MFA Multi-Factor Authentication [Prevent]                                   ║
║     → D3-SPP Strong Password Policy [Prevent]                                        ║
║                                                                                      ║
║  4. NETWORK INDICATORS:                                                              ║
║     Source IPs · Internal targets · External/C2 connections · Timeline · Data volume ║
║                                                                                      ║
║  5. RECOMMENDED IMMEDIATE ACTIONS (specific, with D3FEND codes):                     ║
║     "1. Isolate host 192.168.1.103 from network immediately"                         ║
║     "2. Block outbound connections to 185.220.101.x (D3-NTF Network Traffic Filter)" ║
║                                                                                      ║
║  6. ATTACK CHAIN ASSESSMENT (narrative connecting all techniques):                   ║
║     "The attack began with SSH brute force (T1110), achieving lateral movement       ║
║      via SSH (T1021.004), followed by C2 via Tor (T1090.003) and exfiltration..."    ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
                                           │  complete analyst report
                                           ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  OUTPUT LAYER                                                                        │
│                                                                                      │
│  IN:   Complete analyst report from Synthesis Agent                                  │
│  OUT:  Three-tab display in Streamlit + green confirmation bar                       │
│                                                                                      │
│  How it works:                                                                       │
│  Three tabs in the Streamlit right column:                                           │
│                                                                                      │
│  TAB 1 — ANALYST REPORT:                                                             │
│  → Full formatted diagnosis — all six sections                                       │
│  → Markdown-ready and copyable — paste directly into incident report                 │
│  → Executive summary at top — boardroom ready without further editing                │
│                                                                                      │
│  TAB 2 — TECHNIQUES:                                                                 │
│  → All detected techniques ranked by confidence                                      │
│  → Full ATT&CK detail per technique — tactic, description, evidence from input       │
│  → D3FEND countermeasures per technique with Prevent/Detect/Respond categorization   │
│                                                                                      │
│  TAB 3 — NORMALIZED JSON:                                                            │
│  → Shows exactly what the Normalization Agent extracted from the raw input           │
│  → Transparency into the normalization step — analyst can verify extraction accuracy │
│  → Useful for debugging and for understanding what the retrieval was based on        │
│                                                                                      │
│  GREEN CONFIRMATION BAR:                                                             │
│  → Displays below the Analyze button on completion                                   │
│  → "Done — N techniques identified" — confirmation the pipeline completed            │
│  → End-to-end time target: under 30 seconds                                          │
└──────────────────────────────────────────────────────────────────────────────────────┘

╔══════════════════════════════════════════════════════════════════════════════════════╗
║  FULL PIPELINE SUMMARY                                                               ║
║                                                                                      ║
║  KNOWLEDGE BASE BUILD (one-time):                                                    ║
║  ATT&CK STIX → chunk → Gemini embed → ChromaDB  |  D3FEND API → JSON lookup table    ║
║                                                                                      ║
║  QUERY FLOW (every request):                                                         ║
║  Input → Stage 1 (normalize) → Stage 2 (retrieve + lookup) → Stage 3 (synthesize)    ║
║        → Output (three-tab report + green bar)                                       ║
║                                                                                      ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║  TECH STACK                                                                          ║
║                                                                                      ║
║  Ingestion:     STIX JSON parser · D3FEND REST API · requests · time.sleep(0.3)      ║
║  Embeddings:    Google Gemini models/gemini-embedding-001 · batches of 50            ║
║  Vector DB:     ChromaDB PersistentClient · data/chroma_db/ · cosine similarity      ║
║  Retrieval:     Hybrid dense + BM25 sparse + RRF fusion · confidence ≥ 0.70          ║
║  D3FEND:        Direct JSON key lookup · data/d3fend/d3fend_lookup.json              ║
║  LLM:           Claude Sonnet (Anthropic API) · normalization + synthesis agents     ║
║  Validation:    Pydantic · Optional fields · partial extraction safe                 ║
║  Frontend:      Streamlit · two-column layout · three-tab diagnosis panel            ║
║  API:           FastAPI · POST /analyze · GET /health                                ║
║                                                                                      ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║  KEY ARCHITECTURAL DECISIONS                                                         ║
║                                                                                      ║
║  ATT&CK embedded, D3FEND as lookup  →  semantic vs graph retrieval patterns          ║
║  Gemini embeddings                  →  cost-effective, high quality                  ║
║  Hybrid dense + BM25 + RRF          →  semantic AND keyword precision                ║
║  Confidence threshold ≥ 0.70        →  only high-confidence techniques surface       ║
║  Pydantic with Optional fields      →  partial extraction always better than failure ║
║  Claude Sonnet for synthesis        →  grounded, structured, citation-enforced       ║
║  Loosely coupled input              →  AegisAI, SIEM, plain English — all accepted   ║
║  D3FEND queried via live API        →  always current, no OWL parsing complexity     ║
║                                                                                      ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║  PERFORMANCE TARGET                                                                  ║
║                                                                                      ║
║  End-to-end: under 30 seconds                                                        ║
║  Manual equivalent: 45 minutes of MITRE ATT&CK + D3FEND cross-referencing            ║
║  ATT&CK corpus: 600+ techniques · 14 tactics · threat actors · mitigations           ║
║  D3FEND corpus: countermeasures mapped to every ATT&CK technique ID                  ║
║                                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

LEGEND
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  ╔══╗  ║    Core processing stage or LLM agent                                       │
│  ┌──┐       Component, storage layer, or UI element                                  │
│  ──►  │  ▼  Data flow direction                                                      │
│  IN / OUT   What enters and exits each stage                                         │
│  RRF        Reciprocal Rank Fusion — merges dense + sparse ranked lists by position  │
│  BM25       Sparse lexical retrieval — keyword matching on technique names/descs     │
│  ChromaDB   Local vector DB storing ATT&CK technique embeddings                      │
│  Gemini     Google Gemini embedding model — models/gemini-embedding-001              │
│  D3FEND     Defensive countermeasure ontology — queried via live REST API            │
│  Pydantic   Python data validation — Optional fields, partial extraction safe        │
│  [V2]       Planned version 2 feature — MITRE ATLAS ML-specific attack techniques    │
└──────────────────────────────────────────────────────────────────────────────────────┘