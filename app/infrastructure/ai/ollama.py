"""
Ollama AI provider — calls the local Ollama API (neural-chat / mistral).
"""

import logging

import httpx

from domain.entities import GateDecision, ImageReport
from infrastructure.ai.parser import parse_ai_response
from infrastructure.ai.prompt import build_analysis_prompt, build_summary_prompt

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT = 1800  # 30 min — first CPU inference can be slow


class OllamaProvider:
    def __init__(self, base_url: str, model: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model

    @property
    def provider_name(self) -> str:
        return f"ollama:{self._model}"

    async def analyze(self, report: ImageReport) -> GateDecision:
        prompt = build_analysis_prompt(report)
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 512},
        }
        logger.info("Sending prompt to Ollama (%d chars)...", len(prompt))
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            resp = await client.post(
                f"{self._base_url}/api/generate", json=payload
            )
            resp.raise_for_status()

        ollama_data = resp.json()
        raw_text: str = ollama_data.get("response", "")
        if not raw_text:
            raise ValueError("Ollama response missing 'response' field")

        logger.info(
            "Ollama raw response (%d chars): %s", len(raw_text), raw_text[:200]
        )
        parsed = parse_ai_response(raw_text)
        return GateDecision(
            decision=parsed["decision"],
            reason=parsed.get("reason", ""),
            recommendations=parsed.get("recommendations", []),
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
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.3, "num_predict": 150},
            }
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{self._base_url}/api/generate", json=payload
                )
                resp.raise_for_status()
            text = resp.json().get("response", "").strip()
            return text or None
        except Exception as exc:
            logger.warning("Ollama summary generation failed: %s", exc)
            return None
