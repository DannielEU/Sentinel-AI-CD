"""
Shared prompt builder used by all AI providers.
"""

from domain.entities import ImageReport


def build_analysis_prompt(report: ImageReport) -> str:
    vulns = report.vulnerabilities
    extra_sections: list[str] = []

    if report.base_image:
        extra_sections.append(f"- Base image     : {report.base_image}")
    if report.os_family:
        extra_sections.append(f"- OS family      : {report.os_family}")

    if report.high_vulnerabilities_details:
        high_vulns_text = "\n## HIGH Vulnerability Details\n"
        for i, vuln in enumerate(report.high_vulnerabilities_details, 1):
            high_vulns_text += f"\n**{i}. {vuln.id} — {vuln.package}**\n"
            high_vulns_text += f"   Title: {vuln.title}\n"
            if vuln.description:
                high_vulns_text += f"   {vuln.description[:200]}\n"
        extra_sections.append(high_vulns_text)

    if report.dockerfile_content:
        extra_sections.append(
            f"\n### Dockerfile\n```\n{report.dockerfile_content[:3000]}\n```"
        )
    if report.scanner_output:
        extra_sections.append(
            f"\n### Scanner output (truncated)\n```\n{report.scanner_output[:3000]}\n```"
        )

    extra = "\n".join(extra_sections)

    return f"""You are HexaFlow, an automated container security gate integrated into a CI/CD pipeline.
You are ALREADY the automated scanning system — this analysis runs automatically on every pull request.
Your role is to approve or reject container image deployments based on security findings from Trivy.

## Context: what this pipeline already does
- Trivy scans every image on every PR automatically (that is how you received this report).
- This gate (you) runs on every PR to main/develop and blocks deployments when needed.
- Do NOT recommend implementing CI/CD scanning, automated pipelines, Dependabot, Snyk, or similar tools
  because those processes are ALREADY in place — recommending them is redundant and confusing.

## Decision Rules
1. Critical > 0           → REJECTED (no exceptions)
2. High > 10              → REJECTED (too many unpatched issues)
3. High 1–10              → WARNING  (acceptable but remediate soon)
4. Medium > 30            → WARNING  (schedule remediation)
5. Image size > 1200 MB   → WARNING  (optimize)
6. Otherwise              → APPROVED

## Image Report
- Image name     : {report.image_name}
- Image size     : {report.image_size_mb:.1f} MB
- Critical vulns : {vulns.critical} {"❌ REJECT" if vulns.critical > 0 else "✅"}
- High vulns     : {vulns.high} {"❌ REJECT" if vulns.high > 10 else "⚠️ WARNING" if vulns.high > 0 else "✅"}
- Medium vulns   : {vulns.medium} {"⚠️ WARNING" if vulns.medium > 30 else "✅"}
- Low vulns      : {vulns.low}
- Unknown vulns  : {vulns.unknown}
{extra}

## Response Format
Respond ONLY with valid JSON (no markdown, no extra text).
The "recommendations" list must contain AT MOST 5 items.
Each recommendation must be a concrete remediation action (e.g. upgrade a specific package,
pin a base image version, remove an unused dependency) — NOT process suggestions like
"implement scanning" or "add Dependabot" since those are already in place.
{{
  "decision": "APPROVED|WARNING|REJECTED",
  "reason": "Single sentence explaining the decision",
  "recommendations": ["concrete action 1", "concrete action 2"],
  "summary": "Detailed security assessment covering: (1) overall security posture, (2) most critical findings and their impact, (3) which packages or layers are affected, (4) exploitability context, (5) remediation priority and timeline, (6) positive security practices already in place"
}}
"""


def build_summary_prompt(
    image_name: str,
    decision: str,
    reason: str,
    critical: int,
    high: int,
    medium: int,
    base_image: str | None,
    size_mb: float,
) -> str:
    return (
        f"You are a DevSecOps assistant reviewing a container security gate decision.\n\n"
        f"Image: {image_name}\nDecision: {decision}\nReason: {reason}\n"
        f"Vulnerabilities: critical={critical}, high={high}, medium={medium}\n"
        f"Base image: {base_image or 'unknown'}\nImage size: {size_mb:.1f} MB\n\n"
        "Write a 2-3 sentence professional summary for the development team explaining "
        "the security implications and recommended next steps. "
        "Be specific, concise, and actionable. Plain text only — no JSON, no markdown."
    )
