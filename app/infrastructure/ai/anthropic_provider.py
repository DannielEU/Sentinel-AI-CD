"""
Anthropic AI provider — calls the Anthropic Messages API via httpx.
No anthropic SDK required; uses the REST API directly.

Required env: ANTHROPIC_API_KEY
Optional env: ANTHROPIC_MODEL (default: claude-haiku-4-5-20251001)
"""

import logging

import httpx

from domain.entities import GateDecision, ImageReport
from infrastructure.ai.parser import parse_ai_response
from infrastructure.ai.prompt import build_analysis_prompt, build_summary_prompt

logger = logging.getLogger(__name__)

_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"
_REQUEST_TIMEOUT = 60.0


class AnthropicProvider:
    def __init__(self, api_key: str, model: str) -> None:
        self._api_key = api_key
        self._model = model

    @property
    def provider_name(self) -> str:
        return f"anthropic:{self._model}"

    def _headers(self) -> dict:
        return {
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "Content-Type": "application/json",
        }

    async def analyze(self, report: ImageReport) -> GateDecision:
        prompt = build_analysis_prompt(report)
        payload = {
            "model": self._model,
            "max_tokens": 512,
            "messages": [{"role": "user", "content": prompt}],
        }
        logger.info(
            "Sending prompt to Anthropic %s (%d chars)...", self._model, len(prompt)
        )
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            resp = await client.post(
                _ANTHROPIC_URL, json=payload, headers=self._headers()
            )
            resp.raise_for_status()

        raw = resp.json()["content"][0]["text"]
        logger.info("Anthropic raw response (%d chars): %s", len(raw), raw[:200])
        parsed = parse_ai_response(raw)
        return GateDecision(
            decision=parsed["decision"],
            reason=parsed.get("reason", ""),
            recommendations=parsed.get("recommendations", []),
            summary=parsed.get("summary"),
            source="ai_model",
            image_name=report.image_name,
        )

    async def generate_summary(
        self, report: ImageReport, decision: str, reason: str
    ) -> str | None:
        prompt = build_summary_prompt(
            image_name=report.image_name,
            decision=decision,
            reason=reason,
            critical=report.vulnerabilities.critical,
            high=report.vulnerabilities.high,
            medium=report.vulnerabilities.medium,
            base_image=report.base_image,
            size_mb=report.image_size_mb,
        )
        try:
            payload = {
                "model": self._model,
                "max_tokens": 150,
                "messages": [{"role": "user", "content": prompt}],
            }
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    _ANTHROPIC_URL, json=payload, headers=self._headers()
                )
                resp.raise_for_status()
            return resp.json()["content"][0]["text"].strip() or None
        except Exception as exc:
            logger.warning("Anthropic summary generation failed: %s", exc)
            return None
