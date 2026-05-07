"""
CodeGateService — application-layer orchestrator for source code analysis.

Pipeline:
  1. For each submitted file, call the AI code analyzer
  2. Aggregate all findings
  3. Apply deterministic severity thresholds
  4. Persist the scan record
  5. Return CodeScanDecision
"""

import logging
from datetime import datetime, timezone

from domain import code_rules
from domain.code_entities import (
    CodeScanDecision,
    CodeScanRecord,
    CodeScanReport,
    CodeVulnerability,
    VulnerabilitySummary,
)
from domain.ports.repository import RepositoryPort

logger = logging.getLogger(__name__)


class CodeGateService:
    def __init__(self, code_analyzer, repository: RepositoryPort) -> None:
        self._analyzer = code_analyzer
        self._repo = repository

    async def analyze(self, report: CodeScanReport) -> CodeScanDecision:
        all_vulns: list[CodeVulnerability] = []

        if self._analyzer is None:
            summary = VulnerabilitySummary()
            decision = "PASSED"
            reason = "AI code analysis is disabled — no scan performed."
            ai_provider = None
        else:
            for file in report.files:
                logger.info(
                    "Analyzing %s (%d chars)", file.filename, len(file.content)
                )
                vulns = await self._analyzer.analyze_file(file)
                all_vulns.extend(vulns)
                logger.info(
                    "Found %d vulnerabilities in %s", len(vulns), file.filename
                )

            summary = code_rules.count_by_severity(all_vulns)
            decision, reason = code_rules.evaluate(summary)
            ai_provider = self._analyzer.analyzer_name

        await self._persist(report, decision, reason, summary, len(report.files), ai_provider, all_vulns)

        logger.info(
            "Code scan decision for '%s': %s (%d vulns across %d files)",
            report.project_name,
            decision,
            len(all_vulns),
            len(report.files),
        )

        return CodeScanDecision(
            decision=decision,
            reason=reason,
            files_analyzed=len(report.files),
            total_vulnerabilities=len(all_vulns),
            summary=summary,
            vulnerabilities=all_vulns,
            blocked=decision == "BLOCKED",
            project_name=report.project_name,
            commit_sha=report.commit_sha,
            ai_provider=ai_provider,
        )

    async def _persist(
        self,
        report: CodeScanReport,
        decision: str,
        reason: str,
        summary: VulnerabilitySummary,
        files_analyzed: int,
        ai_provider: str | None,
        vulnerabilities: list[CodeVulnerability] | None = None,
    ) -> None:
        record = CodeScanRecord(
            project_name=report.project_name,
            commit_sha=report.commit_sha,
            branch=report.branch,
            decision=decision,
            critical_count=summary.CRITICAL,
            high_count=summary.HIGH,
            medium_count=summary.MEDIUM,
            low_count=summary.LOW,
            files_analyzed=files_analyzed,
            ai_provider=ai_provider,
            scanned_at=datetime.now(tz=timezone.utc),
            vulnerabilities=vulnerabilities or [],
        )
        await self._repo.save_code_scan(record)
