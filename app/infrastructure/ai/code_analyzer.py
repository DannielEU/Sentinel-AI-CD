"""
AICodeAnalyzer — unified adapter implementing CodeAnalyzerPort for all backends.

Reuses the same provider configuration as the image gate (AI_PROVIDER env var)
but applies code-specific prompts and parses vulnerability arrays instead of
gate decisions.
"""

import logging

import httpx

from domain.code_entities import CodeFile, CodeVulnerability
from infrastructure.ai.code_parser import parse_code_analysis_response
from infrastructure.ai.code_prompt import build_code_analysis_prompt

logger = logging.getLogger(__name__)

_TIMEOUT = 300.0


def _snippet_exists(vuln: CodeVulnerability, content: str) -> bool:
    """Return False if the model hallucinated a code_snippet that doesn't exist in the file."""
    snippet = (vuln.code_snippet or "").strip()
    if not snippet:
        return True  # no snippet to validate — keep the finding
    # Normalise whitespace for comparison
    normalised_content = " ".join(content.split())
    normalised_snippet = " ".join(snippet.split())
    if normalised_snippet in normalised_content:
        return True
    # Allow a partial match: at least one full token of 8+ chars must appear
    tokens = [t for t in normalised_snippet.split() if len(t) >= 8]
    return any(t in normalised_content for t in tokens)


class AICodeAnalyzer:
    def __init__(self, provider: str, **config) -> None:
        self._provider = provider
        self._config = config

    @property
    def analyzer_name(self) -> str:
        model = self._config.get("model", "")
        return f"code:{self._provider}:{model}" if model else f"code:{self._provider}"

    async def analyze_file(self, file: CodeFile) -> list[CodeVulnerability]:
        prompt = build_code_analysis_prompt(file.filename, file.content)
        try:
            raw = await self._call(prompt)
            vulns = parse_code_analysis_response(raw, file.filename)
            return [v for v in vulns if _snippet_exists(v, file.content)]
        except Exception as exc:
            logger.warning("Code analysis failed for %s: %s", file.filename, exc)
            return []

    async def _call(self, prompt: str) -> str:
        match self._provider:
            case "ollama":
                return await self._call_ollama(prompt)
            case "openai":
                return await self._call_openai(prompt)
            case "anthropic":
                return await self._call_anthropic(prompt)
            case _:
                raise ValueError(f"Unknown provider for code analysis: {self._provider}")

    async def _call_ollama(self, prompt: str) -> str:
        base_url = self._config.get("base_url", "http://localhost:11434")
        model = self._config.get("model", "neural-chat")
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 2048},
        }
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(f"{base_url}/api/generate", json=payload)
            resp.raise_for_status()
        return resp.json().get("response", "")

    async def _call_openai(self, prompt: str) -> str:
        api_key = self._config["api_key"]
        model = self._config.get("model", "gpt-4o-mini")
        azure_endpoint = self._config.get("azure_endpoint")
        azure_deployment = self._config.get("azure_deployment")
        azure_api_version = self._config.get("azure_api_version", "2024-02-01")

        if azure_endpoint:
            deployment = azure_deployment or model
            url = f"{azure_endpoint}/openai/deployments/{deployment}/chat/completions?api-version={azure_api_version}"
            headers = {"api-key": api_key, "Content-Type": "application/json"}
        else:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 2048,
        }
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    async def _call_anthropic(self, prompt: str) -> str:
        api_key = self._config["api_key"]
        model = self._config.get("model", "claude-haiku-4-5-20251001")
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}],
        }
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
        return resp.json()["content"][0]["text"]
