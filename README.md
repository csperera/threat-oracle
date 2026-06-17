# ThreatOracle AI 🔍

> Paste suspicious behaviour. Get a complete ATT&CK diagnosis + D3FEND remediation in 15 seconds.

## The Problem

The MITRE ATT&CK framework contains 600+ techniques across 14 tactics. MITRE D3FEND maps hundreds of defensive countermeasures to those techniques. No analyst has all of that memorized. Manual ATT&CK/D3FEND cross-referencing takes an expert 15–45 minutes per incident. A typical enterprise SOC handles 1,000–10,000 alerts per day. The math is impossible.

ThreatOracle makes ATT&CK/D3FEND expertise democratically available to every analyst regardless of experience level — a junior analyst gets the same quality diagnosis as a 10-year veteran.

## The Solution

ThreatOracle accepts any suspicious behaviour input — raw log snippets, plain English descriptions, or structured JSON from upstream detection systems — and returns a complete threat diagnosis in 15 seconds:

- ATT&CK techniques ranked by confidence with cited technique IDs
- D3FEND countermeasures per technique, prioritized by action type (Prevent → Detect → Respond)
- Threat actor groups known to use the detected TTPs
- Recommended immediate actions for the SOC

## Architecture

Two-stage pipeline:
```
INPUT (any format)
│
▼
Normalization Agent (LLM)
│  extracts: behaviours, protocols, patterns, IPs, volume, timing
▼
Structured Security JSON
│
├──► ATT&CK RAG Query (hybrid dense + sparse search)
│    → Top technique matches ranked by confidence
│
├──► D3FEND Countermeasure Lookup
│    → Defensive recommendations per technique
│
└──► Synthesis Agent (LLM)
│
▼ 
OUTPUT (Analyst Report)
```
ANALYST REPORT
**Stage 1 — Normalization Agent:** Accepts arbitrary input format. Extracts structured security-relevant features regardless of source. Outputs standardized JSON. This handles the diversity of real-world log formats.

**Stage 2 — Diagnostic Agent:** Takes normalized JSON, queries the ATT&CK knowledge base via hybrid retrieval, retrieves D3FEND countermeasures, and synthesizes a ranked analyst report with full citations.

## Knowledge Base

All sources are open, Apache 2.0 licensed, and maintained by MITRE:


| Source                                                   | Contents                                                                | Size                 |
| -------------------------------------------------------- | ----------------------------------------------------------------------- | -------------------- |
| [MITRE ATT&CK v16](https://github.com/mitre/cti)         | Tactics, techniques, sub-techniques, threat actor profiles, mitigations | 600+ techniques      |
| [MITRE D3FEND](https://d3fend.mitre.org)                 | Defensive countermeasures mapped to ATT&CK techniques                   | 100+ countermeasures |
| [MITRE ATLAS](https://github.com/mitre-atlas/atlas-data) | ML-specific attacks: adversarial ML, model poisoning, prompt injection  | V2                   |


## Tech Stack


| Layer      | Technology                               |
| ---------- | ---------------------------------------- |
| Frontend   | Streamlit                                |
| Backend    | FastAPI                                  |
| LLM        | Claude claude-sonnet-4-6 (Anthropic API) |
| Embeddings | OpenAI text-embedding-3-small            |
| Vector DB  | ChromaDB (local persistent)              |
| Retrieval  | Hybrid dense + BM25 sparse + RRF fusion  |
| Validation | Pydantic                                 |


## Setup

```bash
# 1. Clone
git clone https://github.com/csperera/threat-oracle
cd threat-oracle

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set environment variables
cp .env.example .env
# Add your ANTHROPIC_API_KEY and OPENAI_API_KEY

# 4. Build the knowledge base (run once — downloads ~12MB ATT&CK bundle)
python ingestion/attck_ingestion.py
python ingestion/d3fend_parser.py

# 5. Run
streamlit run app.py
```

## Example Output

**Input:**
02:14:33 - Host 192.168.1.45 attempting SSH connections to 47 internal hosts in 3 minutes
02:14:41 - Multiple failed authentication attempts on each host
02:15:12 - Successful authentication on 192.168.1.103
02:15:45 - New process spawned on .103: cmd.exe /c whoami
02:16:34 - Outbound connection from .103 to 185.220.101.x (known Tor exit node)
02:17:01 - Large data transfer initiated: 2.3GB outbound

**Output (truncated):**
THREAT DIAGNOSIS REPORT
EXECUTIVE SUMMARY
This pattern is consistent with an automated credential attack followed by
lateral movement and data exfiltration via Tor. Confidence: HIGH.
DETECTED TECHNIQUES

T1048 — Exfiltration Over Alternative Protocol  (Confidence: 96%)
Tactic: Exfiltration
D3FEND: Outbound Traffic Filtering [PREVENT], Data Loss Prevention [PREVENT]
T1090.003 — Multi-hop Proxy via Tor  (Confidence: 94%)
Tactic: Command and Control
D3FEND: Outbound Traffic Filtering [PREVENT], DNS Allowlisting [PREVENT]
T1110.003 — Password Spraying  (Confidence: 91%)
Tactic: Credential Access
D3FEND: Account Lockout [PREVENT], Multi-Factor Authentication [PREVENT]

...
RECOMMENDED IMMEDIATE ACTIONS

Isolate 192.168.1.45 and 192.168.1.103
Block outbound to 185.220.101.x
Enable account lockout policy immediately
Preserve logs for forensic analysis

## Component Context

ThreatOracle is the **Intelligence Layer** of a loosely coupled AI-powered SOC pipeline:

- **Detection Layer:** [AegisAI](https://aegisai.online) — XGBoost + multi-agent anomaly detection (0.9886 AUC)
- **Intelligence Layer:** ThreatOracle (this repo) — RAG-based ATT&CK/D3FEND diagnosis

Loose coupling is a core design principle. ThreatOracle accepts input from any upstream detection source — AegisAI, Splunk, Microsoft Sentinel, CrowdStrike, or plain English. Neither component depends on the other.

## Status

## Status

✅ V1 Complete — fully operational local demo

- ✅ Scaffolding and architecture
- ✅ ATT&CK ingestion + ChromaDB embedding (697 techniques)
- ✅ D3FEND lookup table (423 technique mappings)
- ✅ Normalization agent (raw logs / plain English / AegisAI JSON)
- ✅ Hybrid retrieval (dense + sparse + RRF fusion)
- ✅ Synthesis agent (full analyst report with ATT&CK citations)
- ✅ Streamlit frontend with 3 demo scenarios preloaded
- ⬜ MITRE ATLAS ingestion (ML-specific attacks) — V2
- ⬜ ATT&CK Navigator heat map visualization — V2
- ⬜ AegisAI direct API integration — V2
- ⬜ Threat actor profiling — V2

## Target Vertical

Financial services. A compromised trading AI, deposit system, or fraud detection model represents systemic risk orders of magnitude beyond a compromised laptop. ThreatOracle is designed with financial services as the primary use case, with MITRE ATLAS (ML-specific attacks) in V2 to cover the AI/ML attack surface that classic ATT&CK doesn't address.
