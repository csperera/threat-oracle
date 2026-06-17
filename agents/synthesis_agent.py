"""
Synthesis Agent
Takes normalized security JSON + ATT&CK retrieval results + D3FEND countermeasures
and produces a formatted analyst report.
Uses Gemini 2.5 Flash.
"""

import json
import os
from datetime import datetime
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("models/gemini-2.5-flash")


SYSTEM_PROMPT = """You are an expert cybersecurity analyst writing a threat diagnosis report.

You will be given:
1. Normalized security data extracted from an analyst's input
2. ATT&CK techniques matched by a RAG retrieval system with confidence scores
3. D3FEND countermeasures mapped to each technique

Your job is to synthesize this into a structured analyst report.

Rules:
- Ground every claim in the provided ATT&CK/D3FEND data — do not invent techniques or countermeasures
- Always cite technique IDs (e.g. T1110.003)
- Rank techniques by confidence score descending
- Executive summary must be understandable by non-technical leadership (2-3 sentences)
- Immediate actions must be specific and actionable
- Threat actor groups must come from the ATT&CK data provided — do not invent them

Output the report in this exact format:

THREAT DIAGNOSIS REPORT
Generated: {timestamp}
Input Format: {input_format}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXECUTIVE SUMMARY
[2-3 sentences in plain English describing what is happening and the severity]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DETECTED TECHNIQUES (ranked by confidence)

[For each technique:]
{rank}. {technique_id} — {name}  (Confidence: {score}%)
   Tactic: {tactic}
   Evidence: {what behaviour triggered this match}
   
   D3FEND Countermeasures:
   → {d3fend_id} {name} [{category}]
   → ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

NETWORK INDICATORS
Source IPs: {list}
Internal Targets: {list}
External/C2: {list}
Timeline: {range}
Data Transfer: {volume}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RECOMMENDED IMMEDIATE ACTIONS
1. {action}
2. {action}
...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ATTACK CHAIN ASSESSMENT
[2-3 sentences describing the overall attack narrative, confidence level, and possible threat actor profile based on TTPs]
"""


def build_context(normalized: dict, techniques: list, d3fend_lookup: dict) -> str:
    """Build the context block fed to Gemini."""
    context_parts = []

    # Normalized data
    context_parts.append("=== NORMALIZED INPUT ===")
    context_parts.append(json.dumps(normalized, indent=2))

    # Techniques with D3FEND
    context_parts.append("\n=== ATT&CK TECHNIQUES MATCHED ===")
    for i, t in enumerate(techniques, 1):
        tid = t["technique_id"]
        confidence_pct = int(t["confidence"] * 100)
        context_parts.append(f"\n{i}. {tid} — {t['name']} (Confidence: {confidence_pct}%)")
        context_parts.append(f"   Tactic: {t.get('tactic_str', 'Unknown')}")
        context_parts.append(f"   Matched behaviour: {t.get('matched_behaviour', '')}")
        if t.get("description"):
            context_parts.append(f"   ATT&CK Description: {t['description'][:400]}")

        # D3FEND countermeasures
        cms = d3fend_lookup.get(tid, [])
        if not cms and t.get("parent_id"):
            cms = d3fend_lookup.get(t["parent_id"], [])
        if cms:
            context_parts.append(f"   D3FEND Countermeasures ({len(cms)}):")
            for cm in cms[:6]:  # Cap at 6 per technique
                context_parts.append(f"     → {cm.get('d3fend_id', '')} {cm['name']} [{cm['category']}]")
        else:
            context_parts.append("   D3FEND Countermeasures: None mapped")

    return "\n".join(context_parts)


def synthesize(normalized: dict, techniques: list, d3fend_lookup: dict) -> str:
    """
    Generate analyst report from retrieval results.
    Returns formatted report string.
    """
    if not techniques:
        return "No ATT&CK techniques matched with sufficient confidence. Input may be insufficient or non-malicious."

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    input_format = normalized.get("input_format_detected", "unknown")

    context = build_context(normalized, techniques, d3fend_lookup)

    prompt = f"""{SYSTEM_PROMPT}

Generated: {timestamp}
Input Format: {input_format}

{context}

Write the complete analyst report now:"""

    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"[Synthesis Error] {e}"


if __name__ == "__main__":
    import sys
    sys.path.append(str(__import__('pathlib').Path(__file__).parent.parent))

    from agents.normalization_agent import normalize
    from retrieval.hybrid_search import HybridRetriever
    from retrieval.d3fend_lookup import D3FENDLookup

    test_input = """
02:14:33 - Host 192.168.1.45 attempting SSH connections to 47 internal hosts in 3 minutes
02:14:41 - Multiple failed authentication attempts on each host
02:15:12 - Successful authentication on 192.168.1.103
02:15:45 - New process spawned on .103: cmd.exe /c whoami
02:16:02 - New process spawned on .103: cmd.exe /c net user
02:16:34 - Outbound connection from .103 to 185.220.101.x (known Tor exit node)
02:17:01 - Large data transfer initiated: 2.3GB outbound
"""

    print("[Synthesis] Step 1: Normalizing input...")
    normalized = normalize(test_input)

    print("[Synthesis] Step 2: Retrieving ATT&CK techniques...")
    retriever = HybridRetriever()
    techniques = retriever.search_behaviours(normalized["behaviours"])

    print("[Synthesis] Step 3: Loading D3FEND countermeasures...")
    d3fend = D3FENDLookup()

    print("[Synthesis] Step 4: Generating report...\n")
    report = synthesize(normalized, techniques, d3fend._lookup if hasattr(d3fend, '_lookup') else {})

    print(report)