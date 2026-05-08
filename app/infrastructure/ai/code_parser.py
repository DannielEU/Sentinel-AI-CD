"""
Response parser for the AI code analysis endpoint.
Extracts a JSON array of vulnerabilities from raw AI text.
"""

import json
import logging
import re

from domain.code_entities import CodeVulnerability

logger = logging.getLogger(__name__)

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def parse_code_analysis_response(raw: str, filename: str) -> list[CodeVulnerability]:
    clean = re.sub(r"```(?:json)?\s*", "", raw).strip()
    clean = re.sub(r"```\s*$", "", clean).strip()

    match = re.search(r"\[.*\]", clean, re.DOTALL)
    if not match:
        logger.warning("No JSON array found in code analysis response for %s", filename)
        return []

    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        logger.warning("JSON parse error in code analysis response for %s: %s", filename, exc)
        return []

    if not isinstance(data, list):
        return []

    results: list[CodeVulnerability] = []
    for item in data:
        if not isinstance(item, dict):
            continue

        severity = str(item.get("severity", "LOW")).upper().strip()
        if severity not in _VALID_SEVERITIES:
            severity = "LOW"

        line_number = item.get("line_number")
        if not isinstance(line_number, int) or line_number < 0:
            line_number = None

        try:
            vuln = CodeVulnerability(
                type=str(item.get("type", "Unknown"))[:200].strip() or "Unknown",
                severity=severity,
                line_number=line_number,
                description=str(item.get("description", "No description provided."))[:1000].strip(),
                code_snippet=str(item.get("code_snippet", ""))[:2000].strip() or None,
                suggestion=str(item.get("suggestion", ""))[:1000].strip() or None,
                cwe_id=str(item.get("cwe_id", ""))[:50].strip() or None,
                filename=filename,
            )
            results.append(vuln)
        except Exception as exc:
            logger.debug("Skipping malformed vulnerability entry: %s", exc)
            continue

    return results
