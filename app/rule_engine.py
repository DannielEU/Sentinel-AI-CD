"""
Rule Engine — deterministic security policies applied before consulting the AI model.

Rules are evaluated in order.  The first rule that fires returns a decision;
remaining rules are skipped.  If no rule fires, None is returned and the caller
should proceed to AI analysis.

Thresholds can be configured via environment variables:
  - MAX_IMAGE_SIZE_MB: Default 1200
  - MAX_HIGH_VULNS: Default 10
  - MAX_MEDIUM_VULNS: Default 30
"""

import os
from dataclasses import dataclass
from typing import Optional

from schemas import ImageReport

# Load thresholds from environment variables with defaults
MAX_IMAGE_SIZE_MB = int(os.getenv("MAX_IMAGE_SIZE_MB", "1200"))
MAX_HIGH_VULNS = int(os.getenv("MAX_HIGH_VULNS", "10"))
MAX_MEDIUM_VULNS = int(os.getenv("MAX_MEDIUM_VULNS", "30"))


@dataclass
class RuleResult:
    decision: str               # APPROVED | WARNING | REJECTED
    reason: str
    recommendations: list[str]


def _check_critical_vulnerabilities(report: ImageReport) -> Optional[RuleResult]:
    count = report.vulnerabilities.critical
    if count > 0:
        return RuleResult(
            decision="REJECTED",
            reason=f"Image has {count} critical vulnerability/ies. Deployment is blocked.",
            recommendations=[
                "Update base image to a patched version.",
                "Run `trivy image --severity CRITICAL <image>` to list affected packages.",
                "Pin vulnerable packages to fixed versions in the Dockerfile.",
            ],
        )
    return None


def _check_high_vulnerabilities(report: ImageReport) -> Optional[RuleResult]:
    count = report.vulnerabilities.high
    if count > MAX_HIGH_VULNS:
        return RuleResult(
            decision="REJECTED",
            reason=f"Image has {count} high-severity vulnerabilities (threshold: {MAX_HIGH_VULNS}).",
            recommendations=[
                f"Reduce high-severity vulnerabilities below {MAX_HIGH_VULNS} before deploying.",
                "Consider switching to a minimal base image (e.g. distroless or alpine).",
                "Apply security patches with `apt-get upgrade` or `apk upgrade`.",
            ],
        )
    if count > 0:
        return RuleResult(
            decision="WARNING",
            reason=f"Image has {count} high-severity vulnerability/ies.",
            recommendations=[
                "Review and patch high-severity vulnerabilities soon.",
                "Schedule a remediation sprint for the next release.",
            ],
        )
    return None


def _check_image_size(report: ImageReport) -> Optional[RuleResult]:
    size = report.image_size_mb
    if size > MAX_IMAGE_SIZE_MB:
        return RuleResult(
            decision="WARNING",
            reason=f"Image size {size:.0f} MB exceeds the recommended limit of {MAX_IMAGE_SIZE_MB} MB.",
            recommendations=[
                "Use a multi-stage Docker build to reduce the final image size.",
                "Switch to a minimal base image (alpine, distroless).",
                "Remove dev dependencies, build artifacts and cache layers.",
            ],
        )
    return None


def _check_medium_vulnerabilities(report: ImageReport) -> Optional[RuleResult]:
    count = report.vulnerabilities.medium
    if count > MAX_MEDIUM_VULNS:
        return RuleResult(
            decision="WARNING",
            reason=f"Image has {count} medium-severity vulnerabilities (threshold: {MAX_MEDIUM_VULNS}).",
            recommendations=[
                "Address medium-severity vulnerabilities in the next sprint.",
                "Enable automatic dependency updates (Dependabot, Renovate).",
            ],
        )
    return None


# Ordered list of rule functions — first match wins
_RULES = [
    _check_critical_vulnerabilities,
    _check_high_vulnerabilities,
    _check_image_size,
    _check_medium_vulnerabilities,
]


def evaluate(report: ImageReport) -> Optional[RuleResult]:
    """Run all rules against *report*.

    Returns the first :class:`RuleResult` whose rule fires, or ``None`` if no
    rule fires (meaning the AI model should perform the analysis).
    """
    for rule in _RULES:
        result = rule(report)
        if result is not None:
            return result
    return None
