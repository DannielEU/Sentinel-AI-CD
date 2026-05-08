"""
OpenAI AI provider — calls the OpenAI Chat Completions API via httpx.
Supports both standard OpenAI and Azure OpenAI endpoints.

Standard OpenAI:
  Required env: OPENAI_API_KEY
  Optional env: OPENAI_MODEL (default: gpt-4o-mini)

Azure OpenAI:
  Required env: OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT
  Optional env: AZURE_OPENAI_API_VERSION (default: 2024-02-01)
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
    def __init__(
        self,
        api_key: str,
        model: str,
        azure_endpoint: str | None = None,
        azure_deployment: str | None = None,
        azure_api_version: str = "2024-02-01",
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._azure_endpoint = azure_endpoint
        self._azure_deployment = azure_deployment or model
        self._azure_api_version = azure_api_version
        self._is_azure = bool(azure_endpoint)

    def _build_url(self) -> str:
        if self._is_azure:
            base = self._azure_endpoint.rstrip("/")
            return (
                f"{base}/openai/deployments/{self._azure_deployment}"
                f"/chat/completions?api-version={self._azure_api_version}"
            )
        return _OPENAI_URL

    def _headers(self) -> dict:
        if self._is_azure:
            return {"api-key": self._api_key, "Content-Type": "application/json"}
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    def _base_payload(self, messages: list, temperature: float, max_tokens: int) -> dict:
        payload: dict = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if not self._is_azure:
            payload["model"] = self._model
        return payload

    @property
    def provider_name(self) -> str:
        if self._is_azure:
            return f"azure_openai:{self._azure_deployment}"
        return f"openai:{self._model}"

    async def analyze(self, report: ImageReport) -> GateDecision:
        prompt = build_analysis_prompt(report)
        payload = self._base_payload(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=512,
        )
        payload["response_format"] = {"type": "json_object"}

        logger.info("Sending prompt to %s (%d chars)...", self.provider_name, len(prompt))
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            resp = await client.post(self._build_url(), json=payload, headers=self._headers())
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
            payload = self._base_payload(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=150,
            )
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    self._build_url(), json=payload, headers=self._headers()
                )
                resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip() or None
        except Exception as exc:
            logger.warning("OpenAI summary generation failed: %s", exc)
            return None
