"""
Deterministic rule engine — OWASP-aligned security policies evaluated before
consulting the AI model.

Rules are evaluated in order. The first rule that fires returns a decision;
remaining rules are skipped. If no rule fires, None is returned and the caller
should proceed to AI analysis.

Thresholds can be configured via environment variables:
  MAX_IMAGE_SIZE_MB  (default 1200)
  MAX_HIGH_VULNS     (default 10)
  MAX_MEDIUM_VULNS   (default 30)
"""

import os
from dataclasses import dataclass, field
from typing import Optional

from domain.entities import CVEException, ImageReport

MAX_IMAGE_SIZE_MB = int(os.getenv("MAX_IMAGE_SIZE_MB", "1200"))
MAX_HIGH_VULNS = int(os.getenv("MAX_HIGH_VULNS", "10"))
MAX_MEDIUM_VULNS = int(os.getenv("MAX_MEDIUM_VULNS", "30"))


@dataclass
class RuleResult:
    decision: str
    reason: str
    recommendations: list[str] = field(default_factory=list)
    summary: str = ""


def _build_summary(decision: str, report: ImageReport) -> str:
    total = (
        report.vulnerabilities.critical
        + report.vulnerabilities.high
        + report.vulnerabilities.medium
        + report.vulnerabilities.low
    )
    if decision == "APPROVED":
        return (
            f"Image '{report.image_name}' passed security validation. "
            "No critical or high-severity vulnerabilities detected."
        )
    if decision == "REJECTED":
        return (
            f"Image '{report.image_name}' rejected: "
            f"{report.vulnerabilities.critical} critical, {report.vulnerabilities.high} high vulns. "
            "Address vulnerabilities before deploying."
        )
    if total == 0:
        return (
            f"Image '{report.image_name}' triggered a warning (size or policy). "
            "Review recommendations and proceed with caution."
        )
    return (
        f"Image '{report.image_name}' has {total} vulnerabilities "
        f"({report.vulnerabilities.critical} critical, {report.vulnerabilities.high} high, "
        f"{report.vulnerabilities.medium} medium). Follow action items before deploying."
    )


def _high_vuln_recommendations(report: ImageReport, is_rejected: bool) -> list[str]:
    recs: list[str] = []
    if report.high_vulnerabilities_details:
        packages: dict[str, list[str]] = {}
        cves: list[str] = []
        for vuln in report.high_vulnerabilities_details[:10]:
            pkg = vuln.package
            packages.setdefault(pkg, []).append(vuln.id)
            if vuln.id:
                cves.append(vuln.id)
        if len(packages) == 1:
            pkg_name = next(iter(packages))
            recs.append(
                f"Update '{pkg_name}' to a patched version (CVEs: {', '.join(packages[pkg_name][:3])})."
            )
        elif len(packages) > 1:
            recs.append(f"Update packages: {', '.join(list(packages)[:3])}.")
        if cves:
            recs.append(f"Check {len(cves)} CVE(s): trivy image --severity HIGH <image>")
        if report.base_image:
            recs.append(f"Update base image '{report.base_image}' to latest patched version.")
    if not recs:
        if is_rejected:
            recs = [
                f"Reduce HIGH vulnerabilities below {MAX_HIGH_VULNS} before deploying.",
                "Run `trivy image --severity HIGH <image>` to identify affected packages.",
                "Apply security patches and upgrade vulnerable dependencies.",
            ]
        else:
            recs = [
                "Review HIGH vulnerabilities in the next PR review.",
                "Run `trivy image --severity HIGH <image>` for details.",
                "Update vulnerable packages to their latest patched versions.",
            ]
    return recs[:5]


def _whitelisted_cves(report: ImageReport, exceptions: list[CVEException]) -> set[str]:
    """Return the set of CVE IDs in the report that are currently whitelisted."""
    if not exceptions or not report.high_vulnerabilities_details:
        return set()
    active_ids = {e.cve_id.upper() for e in exceptions if e.is_active}
    report_ids = {
        v.id.upper()
        for v in (report.high_vulnerabilities_details or [])
        if v.id
    }
    return report_ids & active_ids


def _check_critical(
    report: ImageReport, exceptions: list[CVEException]
) -> Optional[RuleResult]:
    count = report.vulnerabilities.critical
    if count == 0:
        return None

    # Critical vulns don't have a CVE detail list in the schema — never whitelisted
    return RuleResult(
        decision="REJECTED",
        reason=f"Image has {count} critical vulnerability/ies. Deployment is blocked.",
        recommendations=[
            "Update base image to a patched version.",
            "Run `trivy image --severity CRITICAL <image>` to list affected packages.",
            "Pin vulnerable packages to fixed versions in the Dockerfile.",
        ],
        summary=_build_summary("REJECTED", report),
    )


def _check_high(
    report: ImageReport, exceptions: list[CVEException]
) -> Optional[RuleResult]:
    count = report.vulnerabilities.high
    if count == 0:
        return None

    if count > MAX_HIGH_VULNS:
        whitelisted = _whitelisted_cves(report, exceptions)
        non_whitelisted = count - len(whitelisted)

        if non_whitelisted <= MAX_HIGH_VULNS and whitelisted:
            whitelist_note = (
                f"{len(whitelisted)} CVE(s) accepted via whitelist: "
                + ", ".join(sorted(whitelisted))
            )
            return RuleResult(
                decision="WARNING",
                reason=(
                    f"Image has {count} HIGH vulns but {len(whitelisted)} are whitelisted. "
                    f"Non-whitelisted: {non_whitelisted}."
                ),
                recommendations=[
                    whitelist_note,
                    "Review non-whitelisted HIGH vulnerabilities before next release.",
                ],
                summary=_build_summary("WARNING", report),
            )

        return RuleResult(
            decision="REJECTED",
            reason=f"Image has {count} HIGH vulnerabilities (threshold: {MAX_HIGH_VULNS}).",
            recommendations=_high_vuln_recommendations(report, is_rejected=True),
            summary=_build_summary("REJECTED", report),
        )

    return RuleResult(
        decision="WARNING",
        reason=f"Image has {count} HIGH vulnerability/ies.",
        recommendations=_high_vuln_recommendations(report, is_rejected=False),
        summary=_build_summary("WARNING", report),
    )


def _check_size(
    report: ImageReport, _exceptions: list[CVEException]
) -> Optional[RuleResult]:
    if report.image_size_mb <= MAX_IMAGE_SIZE_MB:
        return None
    return RuleResult(
        decision="WARNING",
        reason=f"Image size {report.image_size_mb:.0f} MB exceeds limit of {MAX_IMAGE_SIZE_MB} MB.",
        recommendations=[
            "Use a multi-stage Docker build to reduce the final image size.",
            "Switch to a minimal base image (alpine, distroless).",
            "Remove dev dependencies, build artifacts and cache layers.",
        ],
        summary=_build_summary("WARNING", report),
    )


def _check_medium(
    report: ImageReport, _exceptions: list[CVEException]
) -> Optional[RuleResult]:
    count = report.vulnerabilities.medium
    if count <= MAX_MEDIUM_VULNS:
        return None
    return RuleResult(
        decision="WARNING",
        reason=f"Image has {count} MEDIUM vulnerabilities (threshold: {MAX_MEDIUM_VULNS}).",
        recommendations=[
            "Address MEDIUM vulnerabilities in the next sprint.",
            "Enable automatic dependency updates (Dependabot, Renovate).",
        ],
        summary=_build_summary("WARNING", report),
    )


_RULES = [_check_critical, _check_high, _check_size, _check_medium]


def evaluate(
    report: ImageReport,
    active_exceptions: Optional[list[CVEException]] = None,
) -> Optional[RuleResult]:
    """Evaluate all rules against *report*.

    Returns the first RuleResult whose rule fires, or None if no rule fires
    (meaning the AI model should perform the analysis).
    """
    exceptions = active_exceptions or []
    for rule in _RULES:
        result = rule(report, exceptions)
        if result is not None:
            return result
    return None
