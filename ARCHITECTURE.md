# ThreatOracle AI — System Architecture

ThreatOracle AI is a RAG-powered cybersecurity threat diagnostic engine that accepts arbitrary input — raw log snippets, plain English descriptions of suspicious behaviour, or structured JSON from upstream detection systems like AegisAI — and returns a complete ATT&CK/D3FEND diagnosis in under 30 seconds. It ingests the complete MITRE ATT&CK knowledge base (600+ techniques, 14 tactics), the D3FEND countermeasure ontology, and MITRE ATLAS (adversarial ML attacks) as its knowledge corpus. ThreatOracle is Component 2 of a loosely coupled AI SOC pipeline — it accepts structured JSON from AegisAI or any upstream SIEM (Splunk, Sentinel, Chronicle) and is not dependent on any specific upstream source. The system is designed to compress 45 minutes of manual MITRE navigation into under 30 seconds.

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│  COMPONENT 2 OF AI SOC PIPELINE — AegisAI | Splunk | Sentinel | Chronicle | plain English       │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘

╔═════════════════════════════════════════════════════════════════════════════════════════════════╗
║                    KNOWLEDGE BASE INGESTION  (one-time setup)                                   ║
╠═════════════════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                                 ║
║  SOURCE 1: MITRE ATT&CK          SOURCE 2: MITRE D3FEND         SOURCE 3: MITRE ATLAS  [V2]     ║
║  github.com/mitre/cti            d3fend.mitre.org               github.com/mitre-atlas/atlas-data║
║  STIX JSON                       OWL → JSON lookup table        JSON — ML attack techniques     ║
║  600+ techniques, 14 tactics     Countermeasures keyed to       (adversarial ML, prompt         ║
║  Threat actors, mitigations      ATT&CK technique IDs           injection, model poisoning)     ║
║       │                                   │                              │                      ║
║       │ Chunk: 1/technique                │ NOT embedded                 │ [V2 ingest]          ║
║       │ (ID, name, tactic, desc,          │ Direct JSON lookup           │                      ║
║       │  detection guidance)              ▼                              ▼                      ║
║       ▼                          ┌─────────────────────┐      ┌─────────────────────┐           ║
║  Embedding: OpenAI               │ D3FEND JSON Table   │      │ ATLAS corpus (V2)   │           ║
║  text-embedding-3-small          │ data/d3fend/        │      │ data/atlas/         │           ║
║       │                          └─────────────────────┘      └─────────────────────┘           ║
║       ▼                                                                                         ║
║  ┌─────────────────────────────────────────────────────────────────────────────────────────┐    ║
║  │  Vector Store: ChromaDB (local)  —  data/attck/  —  dense index of ATT&CK corpus        │    ║
║  └─────────────────────────────────────────────────────────────────────────────────────────┘    ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════╝
                                              │  (queries at runtime)
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│  INPUT LAYER                                                                                    │
├─────────────────────────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐  ┌─────────────────────────────┐  ┌───────────────────────────────┐    │
│  │ Raw Log Snippets    │  │ Plain English Description   │  │ Structured JSON (AegisAI/SIEM)│    │
│  │ Network, auth,      │  │ Suspicious behaviour in     │  │ attack_type, confidence,      │    │
│  │ system logs         │  │ natural language            │  │ features, timestamp           │    │
│  └──────────┬──────────┘  └──────────────┬──────────────┘  └───────────────┬───────────────┘    │
│             └────────────────────────────┴───────────────────────────────────┘                  │
└─────────────────────────────────────────────┬───────────────────────────────────────────────────┘
                                              │
              ┌───────────────────────────────┴───────────────────────────────┐
              ▼                                                               ▼
┌─────────────────────────────────────────┐     ┌─────────────────────────────────────────────────┐
│ FRONTEND  (Streamlit — app.py)          │     │ API  (FastAPI — api/main.py)                    │
│ Dark theme SOC aesthetic                │     │ POST /analyze  — raw_input + input_format       │
│ ┌───────────────┬─────────────────────┐ │     │ GET  /health   — status + knowledge base size   │
│ │ INPUT (left)  │ DIAGNOSIS (right)   │ │     └─────────────────────────┬───────────────────────┘
│ │ Demo dropdown │ Tab: Analyst Report │ │                               │
│ │ (Multi-Stage  │ Tab: Techniques     │ │                               │
│ │  Network      │ Tab: Normalized JSON│ │                               │
│ │  Intrusion…)  │                     │ │                               │
│ │ Log text area │                     │ │                               │
│ │ [Analyze]     │                     │ │                               │
│ │ ▓ green bar:  │                     │ │                               │
│ │ N techniques  │                     │ │                               │
│ └───────────────┴─────────────────────┘ │                               │
└─────────────────────┬───────────────────┘                               │
                      └─────────────────────┬─────────────────────────────┘
                                            ▼
╔═════════════════════════════════════════════════════════════════════════════════════════════════╗
║  STAGE 1 — NORMALIZATION AGENT (LLM)              agents/normalization_agent.py                 ║
╠═════════════════════════════════════════════════════════════════════════════════════════════════╣
║  Accepts any input format → extracts IPs, destinations, protocol, behaviour, timing, volume     ║
║  Outputs standardized security JSON  |  Pydantic validation (partial OK)                        ║
║  System prompt: explicit examples per format → expected JSON output                             ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════╝
                                            │  standardized security JSON
                                            │  (one query per behaviour)
                                            ▼
╔═════════════════════════════════════════════════════════════════════════════════════════════════╗
║  STAGE 2 — HYBRID RAG RETRIEVAL                   retrieval/hybrid_search.py                    ║
╠═════════════════════════════════════════════════════════════════════════════════════════════════╣
║  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────────────────────────────┐     ║
║  │ DENSE (ChromaDB) │ + │ SPARSE (BM25)    │ → │ RRF FUSION — merge by rank position      │     ║
║  │ vector similarity│   │ keyword match on │   │ Filter: confidence ≥ 0.70                │     ║
║  │                  │   │ names & descs    │   │ Out: top ATT&CK matches + scores/behaviour│    ║
║  └──────────────────┘   └──────────────────┘   └──────────────────────────────────────────┘     ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════╝
                                            │  top ATT&CK technique IDs + confidence
                                            ▼
╔═════════════════════════════════════════════════════════════════════════════════════════════════╗
║  STAGE 3 — D3FEND LOOKUP                          retrieval/d3fend_lookup.py                    ║
╠═════════════════════════════════════════════════════════════════════════════════════════════════╣
║  Direct JSON lookup by technique ID (NOT semantic search)                                       ║
║  Returns countermeasures per technique  |  Priority: Prevent → Detect → Respond                 ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════╝
                                            │  techniques + countermeasures + evidence
                                            ▼
╔═════════════════════════════════════════════════════════════════════════════════════════════════╗
║  STAGE 4 — SYNTHESIS AGENT (LLM)                   agents/synthesis_agent.py                    ║
╠═════════════════════════════════════════════════════════════════════════════════════════════════╣
║  REPORT STRUCTURE                          │  CONSTRAINTS                                       ║
║  1. Executive Summary (boardroom ready)    │  Every claim grounded in retrieved ATT&CK/D3FEND   ║
║  2. Detected Techniques + evidence         │  No hallucination — always cite technique IDs      ║
║  3. D3FEND countermeasures (P/D/R)         │  (e.g. T1078, T1021.001)                           ║
║  4. Network Indicators (IPs, timeline)     │                                                    ║
║  5. Recommended Immediate Actions + codes  │                                                    ║
║  6. Attack Chain Assessment (narrative)    │                                                    ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════╝
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│  OUTPUT LAYER                                                                                   │
├─────────────────────────────────────────────────────────────────────────────────────────────────┤
│  ┌────────────────────┐  ┌────────────────────┐  ┌──────────────────────────────────────────┐   │
│  │ Analyst Report     │  │ Techniques Tab     │  │ Normalized JSON Tab                      │   │
│  │ Markdown-ready     │  │ Ranked + ATT&CK    │  │ Normalization agent extraction           │   │
│  └────────────────────┘  └────────────────────┘  └──────────────────────────────────────────┘   │
│  ▓▓▓ GREEN CONFIRMATION BAR: "N techniques identified"  (< 30 s end-to-end)  ▓▓▓                │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│  V2 — MITRE ATLAS: ML-specific diagnosis (adversarial ML, prompt injection, model poisoning)    │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘


                                      LEGEND
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│  SYMBOL       │  MEANING                                                                        │
├───────────────┼─────────────────────────────────────────────────────────────────────────────────┤
│  ╔══╗  ║      │  Processing stage or major subsystem boundary                                   │
│  ┌──┐         │  Component, data source, or UI panel                                            │
│  ──►  │  ▼    │  Data flow direction (runtime pipeline)                                         │
│  [V2]         │  Planned version 2 — not required for MVP                                       │
│  ▓▓▓          │  Green confirmation bar in Streamlit UI                                         │
│  LLM          │  Large language model call (Anthropic / OpenAI)                                 │
│  RRF          │  Reciprocal Rank Fusion — merges dense + sparse ranked lists                    │
│  ≥ 0.70       │  Minimum confidence for a technique to appear in results                        │
│  P → D → R    │  D3FEND priority: Prevent, then Detect, then Respond                            │
│  NOT embedded │  D3FEND accessed via JSON key lookup, not vector search                         │
│  ChromaDB     │  Local vector DB storing ATT&CK technique embeddings                            │
│  BM25         │  Sparse lexical retrieval over technique names and descriptions                 │
└───────────────┴─────────────────────────────────────────────────────────────────────────────────┘
```
