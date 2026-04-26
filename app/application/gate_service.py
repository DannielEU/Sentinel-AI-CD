"""
GateService — application-layer orchestrator.

Coordinates the full analysis pipeline:
  1. Secrets detection (Dockerfile scan) — immediate REJECTED if found
  2. CVE whitelist loading from repository
  3. Deterministic rule engine (with whitelist awareness)
  4. AI provider (optional) for WARNING and no-rule-fired cases
  5. Persistence of each scan record
  6. Dashboard URL injection into the response
"""

import logging
import os
import urllib.parse
from datetime import datetime, timezone

from domain.entities import CVEException, GateDecision, ImageReport, ScanRecord
from domain.ports.ai_provider import AIProviderPort
from domain.ports.repository import RepositoryPort
from domain import rules
from infrastructure.security.secrets_detector import SecretFound, scan_dockerfile

logger = logging.getLogger(__name__)


def _secrets_rejected(
    secrets: list[SecretFound], image_name: str
) -> GateDecision:
    details = "; ".join(
        f"line {s.line_number} ({s.pattern_name})" for s in secrets[:5]
    )
    return GateDecision(
        decision="REJECTED",
        reason=f"Hardcoded secret(s) detected in Dockerfile: {details}.",
        recommendations=[
            "Remove all hardcoded credentials from the Dockerfile immediately.",
            "Use Docker build secrets (--secret), environment variables, or a secrets manager.",
            "Rotate any exposed credentials before next deployment.",
            "Add a pre-commit hook (e.g. detect-secrets) to prevent future leaks.",
        ],
        summary=(
            f"Image '{image_name}' rejected: {len(secrets)} hardcoded secret(s) found. "
            "Credentials must never be embedded in Dockerfiles or image layers."
        ),
        source="secrets_detector",
        image_name=image_name,
    )


def _rule_to_decision(
    result: rules.RuleResult, image_name: str, source: str
) -> GateDecision:
    return GateDecision(
        decision=result.decision,
        reason=result.reason,
        recommendations=result.recommendations,
        summary=result.summary,
        source=source,
        image_name=image_name,
    )


def _approved_decision(image_name: str) -> GateDecision:
    return GateDecision(
        decision="APPROVED",
        reason="No deterministic rule fired and AI fallback is disabled.",
        recommendations=[
            "Keep scheduled image scanning enabled in CI.",
            "Review warning thresholds periodically as the image evolves.",
        ],
        source="rule_engine",
        image_name=image_name,
    )


class GateService:
    def __init__(
        self,
        ai_provider: AIProviderPort | None,
        repository: RepositoryPort,
    ) -> None:
        self._ai = ai_provider
        self._repo = repository

    async def analyze(
        self, report: ImageReport, gate_base_url: str = ""
    ) -> GateDecision:
        # ── 1. Secrets detection ─────────────────────────────────────────────
        if report.dockerfile_content:
            secrets = scan_dockerfile(report.dockerfile_content)
            if secrets:
                logger.warning(
                    "Secrets detected in Dockerfile for %s: %d finding(s)",
                    report.image_name,
                    len(secrets),
                )
                decision = _secrets_rejected(secrets, report.image_name)
                await self._persist(report, decision, secrets_found=len(secrets))
                return self._inject_dashboard_url(decision, gate_base_url)

        # ── 2. Load whitelist ────────────────────────────────────────────────
        exceptions: list[CVEException] = await self._repo.get_active_exceptions()
        if exceptions:
            logger.info(
                "Whitelist loaded: %d active CVE exception(s)", len(exceptions)
            )

        # ── 3. Deterministic rule engine ─────────────────────────────────────
        rule_result = rules.evaluate(report, active_exceptions=exceptions)

        if rule_result is not None:
            logger.info(
                "Rule engine decision for %s: %s",
                report.image_name,
                rule_result.decision,
            )

            # Hard REJECTED — never override with AI
            if rule_result.decision == "REJECTED":
                decision = _rule_to_decision(rule_result, report.image_name, "rule_engine")
                await self._persist(report, decision)
                return self._inject_dashboard_url(decision, gate_base_url)

            # WARNING — delegate to AI for contextual enrichment
            if rule_result.decision == "WARNING" and self._ai is not None:
                logger.info(
                    "Rule engine flagged WARNING for %s — delegating to AI (%s).",
                    report.image_name,
                    self._ai.provider_name,
                )
                try:
                    decision = await self._ai.analyze(report)
                    logger.info(
                        "AI decision for %s: %s (via %s)",
                        report.image_name,
                        decision.decision,
                        self._ai.provider_name,
                    )
                    await self._persist(
                        report, decision, ai_provider=self._ai.provider_name
                    )
                    return self._inject_dashboard_url(decision, gate_base_url)
                except Exception as exc:
                    logger.warning(
                        "AI analysis failed for %s — falling back to rule engine WARNING: %s",
                        report.image_name,
                        exc,
                    )

            # AI disabled or failed — return rule engine decision
            decision = _rule_to_decision(rule_result, report.image_name, "rule_engine")
            await self._persist(report, decision)
            return self._inject_dashboard_url(decision, gate_base_url)

        # ── 4. No rule fired — pure AI analysis ──────────────────────────────
        if self._ai is None:
            logger.info(
                "No rule fired for %s and AI is disabled — APPROVED.",
                report.image_name,
            )
            decision = _approved_decision(report.image_name)
            await self._persist(report, decision)
            return self._inject_dashboard_url(decision, gate_base_url)

        logger.info(
            "No rule fired for %s — forwarding to AI (%s).",
            report.image_name,
            self._ai.provider_name,
        )
        decision = await self._ai.analyze(report)
        logger.info(
            "AI decision for %s: %s", report.image_name, decision.decision
        )
        await self._persist(report, decision, ai_provider=self._ai.provider_name)
        return self._inject_dashboard_url(decision, gate_base_url)

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _persist(
        self,
        report: ImageReport,
        decision: GateDecision,
        secrets_found: int = 0,
        ai_provider: str | None = None,
    ) -> None:
        record = ScanRecord(
            image_name=report.image_name,
            decision=decision.decision,
            reason=decision.reason,
            source=decision.source,
            critical_vulns=report.vulnerabilities.critical,
            high_vulns=report.vulnerabilities.high,
            medium_vulns=report.vulnerabilities.medium,
            low_vulns=report.vulnerabilities.low,
            image_size_mb=report.image_size_mb,
            secrets_found=secrets_found,
            ai_provider=ai_provider,
            scanned_at=datetime.now(tz=timezone.utc),
        )
        await self._repo.save_scan(record)

    def _inject_dashboard_url(
        self, decision: GateDecision, gate_base_url: str
    ) -> GateDecision:
        if not self._repo.is_available:
            return decision

        # Prefer an explicitly configured external URL (avoids localhost links in CI)
        external = os.getenv("GATE_EXTERNAL_URL", "").strip().rstrip("/")
        base = external or gate_base_url

        # Never emit a localhost/loopback dashboard URL — it won't be reachable
        # after the CI container is torn down
        if not base or any(
            h in base for h in ("localhost", "127.0.0.1", "0.0.0.0", "::1")
        ):
            return decision

        encoded = urllib.parse.quote(decision.image_name, safe="")
        url = f"{base}/dashboard/{encoded}"
        return decision.model_copy(update={"dashboard_url": url})
