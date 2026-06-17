"""
Normalization Agent
Accepts any input format (raw logs, plain English, AegisAI JSON, CSV)
and converts to standardized security JSON for the retrieval layer.
Uses Gemini Flash — fast and free.
"""

import json
import os
from pathlib import Path
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("models/gemini-2.5-flash")

SYSTEM_PROMPT = """You are a cybersecurity log normalization engine.

Your job is to analyze any security-related input and extract structured information into a JSON object.

Input may be:
- Raw log snippets (firewall, auth, system, network logs)
- Plain English descriptions of suspicious behaviour
- Structured JSON from detection systems like AegisAI
- CSV log exports

Output ONLY valid JSON matching this exact schema:
{
  "behaviours": [
    {
      "description": "one sentence describing the suspicious behaviour",
      "protocol": "SSH / HTTP / DNS / SMB / etc — or null",
      "pattern": "scanning / brute_force / exfiltration / lateral_movement / execution / persistence / discovery / other — or null",
      "severity": "high / medium / low"
    }
  ],
  "source_ips": ["list of source IPs observed — or empty list"],
  "destination_ips": ["list of internal destination IPs — or empty list"],
  "external_ips": ["list of external/suspicious IPs — or empty list"],
  "timeline": "time range observed — or null",
  "data_transfer": "any data volume mentioned — or null",
  "input_format_detected": "raw_log / plain_english / aegisai_json / csv"
}

Rules:
- Extract as many distinct behaviours as the input describes — each behaviour is a separate object in the array
- Never hallucinate fields not present in the input — use null or empty list
- Every behaviour needs at minimum a description and severity
- Output ONLY the JSON object — no preamble, no explanation, no markdown fences
"""


def normalize(raw_input: str) -> dict:
    """
    Convert any raw input string to standardized security JSON.
    Returns parsed dict. Falls back to minimal structure on failure.
    """
    prompt = f"{SYSTEM_PROMPT}\n\nInput to normalize:\n{raw_input}"

    try:
        response = model.generate_content(prompt)
        text = response.text.strip()

        # Strip markdown fences
        if "```" in text:
            blocks = text.split("```")
            for block in blocks:
                if block.startswith("json"):
                    text = block[4:].strip()
                    break
                elif block.strip().startswith("{"):
                    text = block.strip()
                    break

        # Take only the first complete JSON object
        brace_count = 0
        end_idx = 0
        for i, char in enumerate(text):
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break
        text = text[:end_idx]

        parsed = json.loads(text)
        parsed.setdefault("behaviours", [])
        parsed.setdefault("source_ips", [])
        parsed.setdefault("destination_ips", [])
        parsed.setdefault("external_ips", [])
        parsed.setdefault("timeline", None)
        parsed.setdefault("data_transfer", None)
        parsed.setdefault("input_format_detected", "unknown")

        return parsed

    except json.JSONDecodeError as e:
        print(f"[Normalization] JSON parse error: {e}")
        return _fallback(raw_input)
    except Exception as e:
        print(f"[Normalization] Error: {e}")
        return _fallback(raw_input)


def _fallback(raw_input: str) -> dict:
    """Minimal structure when normalization fails — never crash the pipeline."""
    return {
        "behaviours": [
            {
                "description": raw_input[:500],
                "protocol": None,
                "pattern": "other",
                "severity": "medium",
            }
        ],
        "source_ips": [],
        "destination_ips": [],
        "external_ips": [],
        "timeline": None,
        "data_transfer": None,
        "input_format_detected": "unknown",
    }


if __name__ == "__main__":
    test_input = """
02:14:33 - Host 192.168.1.45 attempting SSH connections to 47 internal hosts in 3 minutes
02:14:41 - Multiple failed authentication attempts on each host
02:15:12 - Successful authentication on 192.168.1.103
02:15:45 - New process spawned on .103: cmd.exe /c whoami
02:16:02 - New process spawned on .103: cmd.exe /c net user
02:16:34 - Outbound connection from .103 to 185.220.101.x (known Tor exit node)
02:17:01 - Large data transfer initiated: 2.3GB outbound
"""
    print("[Normalization] Testing with demo scenario...\n")
    result = normalize(test_input)
    print(json.dumps(result, indent=2))