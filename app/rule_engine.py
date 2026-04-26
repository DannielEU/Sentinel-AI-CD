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
    summary: str = ""           # General summary message for closure


def _build_summary_message(decision: str, report: ImageReport) -> str:
    """Generate a general summary message for closure."""
    total_vulns = (
        report.vulnerabilities.critical
        + report.vulnerabilities.high
        + report.vulnerabilities.medium
        + report.vulnerabilities.low
    )

    if decision == "APPROVED":
        return (
            f"Image '{report.image_name}' passed security validation. "
            f"No critical or high-severity vulnerabilities detected. Proceed with deployment."
        )

    if decision == "REJECTED":
        return (
            f"Image '{report.image_name}' has been rejected due to critical security issues "
            f"({report.vulnerabilities.critical} critical, {report.vulnerabilities.high} high). "
            f"Address vulnerabilities before attempting deployment."
        )

    # WARNING decision
    if total_vulns == 0:
        return (
            f"Image '{report.image_name}' has no vulnerabilities but triggered a warning "
            f"(likely due to size or policy). Review recommendations and proceed with caution."
        )

    return (
        f"Image '{report.image_name}' contains {total_vulns} vulnerability/ies "
        f"({report.vulnerabilities.critical} critical, {report.vulnerabilities.high} high, "
        f"{report.vulnerabilities.medium} medium). Follow action items before deployment."
    )


def _build_high_vulnerability_recommendations(report: ImageReport, is_rejected: bool) -> list[str]:
    """Generate specific recommendations based on high-severity vulnerability details."""
    recommendations = []

    # If we have detailed vulnerability info, extract specific packages and CVEs
    if report.high_vulnerabilities_details and len(report.high_vulnerabilities_details) > 0:
        # Group by package for targeted recommendations
        packages_affected = {}
        cves_found = []

        for vuln in report.high_vulnerabilities_details[:10]:  # Max 10 details
            pkg = vuln.package
            if pkg not in packages_affected:
                packages_affected[pkg] = []
            packages_affected[pkg].append(vuln.id)
            if vuln.id:
                cves_found.append(vuln.id)

        # Build specific recommendations
        if len(packages_affected) == 1:
            pkg_name = list(packages_affected.keys())[0]
            cves = packages_affected[pkg_name]
            recommendations.append(
                f"Update package '{pkg_name}' to a patched version (CVEs: {', '.join(cves[:3])})."
            )
        elif len(packages_affected) > 1:
            pkg_list = ", ".join(list(packages_affected.keys())[:3])
            recommendations.append(
                f"Update these packages to patched versions: {pkg_list}."
            )

        # Add CVE-specific action
        if cves_found:
            recommendations.append(
                f"Check {len(cves_found)} CVE(s) details with: trivy image --severity HIGH <image>"
            )

        # Add base image recommendation if available
        if report.base_image:
            recommendations.append(
                f"Consider updating base image '{report.base_image}' to latest patched version."
            )

    # Fallback to general recommendations if no details provided
    if len(recommendations) == 0:
        if is_rejected:
            recommendations = [
                f"Reduce high-severity vulnerabilities below {MAX_HIGH_VULNS} before deploying.",
                "Run `trivy image --severity HIGH <image>` to identify affected packages.",
                "Apply security patches and upgrade vulnerable dependencies.",
            ]
        else:
            recommendations = [
                "Review high-severity vulnerabilities in the next PR review.",
                "Run `trivy image --severity HIGH <image>` to identify affected packages and patches.",
                "Update vulnerable packages to their latest patched versions.",
            ]

    return recommendations[:5]  # Max 5 recommendations


def _check_critical_vulnerabilities(report: ImageReport) -> Optional[RuleResult]:
    count = report.vulnerabilities.critical
    if count > 0:
        decision = "REJECTED"
        return RuleResult(
            decision=decision,
            reason=f"Image has {count} critical vulnerability/ies. Deployment is blocked.",
            recommendations=[
                "Update base image to a patched version.",
                "Run `trivy image --severity CRITICAL <image>` to list affected packages.",
                "Pin vulnerable packages to fixed versions in the Dockerfile.",
            ],
            summary=_build_summary_message(decision, report),
        )
    return None


def _check_high_vulnerabilities(report: ImageReport) -> Optional[RuleResult]:
    count = report.vulnerabilities.high
    if count > MAX_HIGH_VULNS:
        decision = "REJECTED"
        recommendations = _build_high_vulnerability_recommendations(report, is_rejected=True)
        return RuleResult(
            decision=decision,
            reason=f"Image has {count} high-severity vulnerabilities (threshold: {MAX_HIGH_VULNS}).",
            recommendations=recommendations,
            summary=_build_summary_message(decision, report),
        )
    if count > 0:
        decision = "WARNING"
        recommendations = _build_high_vulnerability_recommendations(report, is_rejected=False)
        return RuleResult(
            decision=decision,
            reason=f"Image has {count} high-severity vulnerability/ies.",
            recommendations=recommendations,
            summary=_build_summary_message(decision, report),
        )
    return None


def _check_image_size(report: ImageReport) -> Optional[RuleResult]:
    size = report.image_size_mb
    if size > MAX_IMAGE_SIZE_MB:
        decision = "WARNING"
        return RuleResult(
            decision=decision,
            reason=f"Image size {size:.0f} MB exceeds the recommended limit of {MAX_IMAGE_SIZE_MB} MB.",
            recommendations=[
                "Use a multi-stage Docker build to reduce the final image size.",
                "Switch to a minimal base image (alpine, distroless).",
                "Remove dev dependencies, build artifacts and cache layers.",
            ],
            summary=_build_summary_message(decision, report),
        )
    return None


def _check_medium_vulnerabilities(report: ImageReport) -> Optional[RuleResult]:
    count = report.vulnerabilities.medium
    if count > MAX_MEDIUM_VULNS:
        decision = "WARNING"
        return RuleResult(
            decision=decision,
            reason=f"Image has {count} medium-severity vulnerabilities (threshold: {MAX_MEDIUM_VULNS}).",
            recommendations=[
                "Address medium-severity vulnerabilities in the next sprint.",
                "Enable automatic dependency updates (Dependabot, Renovate).",
            ],
            summary=_build_summary_message(decision, report),
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
