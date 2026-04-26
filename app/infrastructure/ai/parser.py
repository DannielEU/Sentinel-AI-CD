"""
Shared JSON response parser used by all AI providers.
"""

import json
import re


def parse_ai_response(raw: str) -> dict:
    """Extract and validate the JSON gate decision from a raw AI text response."""
    clean = re.sub(r"```(?:json)?\s*", "", raw).strip()

    match = re.search(r"\{.*\}", clean, re.DOTALL)
    if match:
        clean = match.group(0)

    try:
        data = json.loads(clean)
    except json.JSONDecodeError:
        return {
            "decision": "WARNING",
            "reason": "AI model returned an unparseable response. Manual review required.",
            "recommendations": [
                "Review the raw scanner output manually.",
                f"Raw model output: {raw[:400]}",
            ],
        }

    data["decision"] = str(data.get("decision", "WARNING")).upper()
    if data["decision"] not in {"APPROVED", "WARNING", "REJECTED"}:
        data["decision"] = "WARNING"

    reason = data.get("reason") or "AI model returned no reason."
    data["reason"] = str(reason)[:500]

    recs = data.get("recommendations", [])
    if not isinstance(recs, list):
        recs = [str(recs)]
    data["recommendations"] = [str(r) for r in recs]

    return data
