"""
OpenAI AI provider — calls the OpenAI Chat Completions API via httpx.
No openai SDK required; uses the REST API directly to keep dependencies minimal.

Required env: OPENAI_API_KEY
Optional env: OPENAI_MODEL (default: gpt-4o-mini)
"""

import logging

import httpx

from domain.entities import GateDecision, ImageReport
from infrastructure.ai.parser import parse_ai_response
from infrastructure.ai.prompt import build_analysis_prompt, build_summary_prompt

logger = logging.getLogger(__name__)

_OPENAI_URL = "https://api.openai.com/v1/chat/completions"
_REQUEST_TIMEOUT = 60.0


class OpenAIProvider:
    def __init__(self, api_key: str, model: str) -> None:
        self._api_key = api_key
        self._model = model

    @property
    def provider_name(self) -> str:
        return f"openai:{self._model}"

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    async def analyze(self, report: ImageReport) -> GateDecision:
        prompt = build_analysis_prompt(report)
        payload = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 512,
            "response_format": {"type": "json_object"},
        }
        logger.info("Sending prompt to OpenAI %s (%d chars)...", self._model, len(prompt))
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            resp = await client.post(_OPENAI_URL, json=payload, headers=self._headers())
            resp.raise_for_status()

        raw = resp.json()["choices"][0]["message"]["content"]
        logger.info("OpenAI raw response (%d chars): %s", len(raw), raw[:200])
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
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 150,
            }
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    _OPENAI_URL, json=payload, headers=self._headers()
                )
                resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip() or None
        except Exception as exc:
            logger.warning("OpenAI summary generation failed: %s", exc)
            return None
