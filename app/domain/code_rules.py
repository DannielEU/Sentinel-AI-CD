"""
Deterministic threshold rules for source code vulnerability analysis.

Thresholds via environment variables:
  MAX_CODE_CRITICAL  (default 0 — any critical finding blocks)
  MAX_CODE_HIGH      (default 0 — any high finding blocks)
"""

import os

from domain.code_entities import CodeVulnerability, VulnerabilitySummary

MAX_CODE_CRITICAL = int(os.getenv("MAX_CODE_CRITICAL", "0"))
MAX_CODE_HIGH = int(os.getenv("MAX_CODE_HIGH", "0"))


def count_by_severity(vulns: list[CodeVulnerability]) -> VulnerabilitySummary:
    summary = VulnerabilitySummary()
    for v in vulns:
        match v.severity:
            case "CRITICAL":
                summary.CRITICAL += 1
            case "HIGH":
                summary.HIGH += 1
            case "MEDIUM":
                summary.MEDIUM += 1
            case "LOW":
                summary.LOW += 1
    return summary


def evaluate(summary: VulnerabilitySummary) -> tuple[str, str]:
    """Return (decision, reason). Decisions: BLOCKED | WARNING | PASSED."""
    if summary.CRITICAL > MAX_CODE_CRITICAL:
        return (
            "BLOCKED",
            f"{summary.CRITICAL} critical vulnerability/ies found in source code — push blocked.",
        )
    if summary.HIGH > MAX_CODE_HIGH:
        return (
            "BLOCKED",
            f"{summary.HIGH} high-severity vulnerability/ies found in source code — push blocked.",
        )
    if summary.HIGH > 0 or summary.MEDIUM > 0:
        return (
            "WARNING",
            f"Source code has {summary.HIGH} high and {summary.MEDIUM} medium "
            "vulnerability/ies — review before release.",
        )
    return "PASSED", "No critical or high-severity vulnerabilities found in source code."
