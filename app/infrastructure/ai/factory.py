"""
AI provider factory — detects which provider to use at startup, before any
Ollama model interaction or external API call.

Reads AI_PROVIDER env var (default: ollama). Validates required credentials
immediately so misconfigurations surface at boot time rather than per-request.
"""

import logging
import os

logger = logging.getLogger(__name__)


def create_code_analyzer():
    """Return an AICodeAnalyzer using the same AI_PROVIDER config, or None if disabled."""
    provider = os.getenv("AI_PROVIDER", "ollama").lower().strip()

    if provider == "disabled":
        logger.info("Code analyzer: disabled — no AI code analysis will run")
        return None

    from infrastructure.ai.code_analyzer import AICodeAnalyzer

    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise EnvironmentError("AI_PROVIDER=openai requires OPENAI_API_KEY to be set")
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "").strip() or None
        azure_deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "").strip() or None
        azure_api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01")
        logger.info("Code analyzer: openai (model=%s)", model)
        return AICodeAnalyzer(
            "openai",
            api_key=api_key,
            model=model,
            azure_endpoint=azure_endpoint,
            azure_deployment=azure_deployment,
            azure_api_version=azure_api_version,
        )

    if provider == "anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            raise EnvironmentError("AI_PROVIDER=anthropic requires ANTHROPIC_API_KEY to be set")
        model = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
        logger.info("Code analyzer: anthropic (model=%s)", model)
        return AICodeAnalyzer("anthropic", api_key=api_key, model=model)

    if provider == "ollama":
        base_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        model = os.getenv("OLLAMA_MODEL", "neural-chat")
        logger.info("Code analyzer: ollama (%s, model=%s)", base_url, model)
        return AICodeAnalyzer("ollama", base_url=base_url, model=model)

    raise EnvironmentError(
        f"Unknown AI_PROVIDER='{provider}'. Valid values: ollama, openai, anthropic, disabled"
    )


def create_ai_provider():
    """Return the configured AI provider, or None if AI is disabled.

    Detection order (checked before any model pull or API call):
      1. AI_PROVIDER=disabled  → no AI, rules only
      2. AI_PROVIDER=openai    → OpenAI Chat Completions (requires OPENAI_API_KEY)
      3. AI_PROVIDER=anthropic → Anthropic Messages API (requires ANTHROPIC_API_KEY)
      4. AI_PROVIDER=ollama    → local Ollama (default)
    """
    provider = os.getenv("AI_PROVIDER", "ollama").lower().strip()

    if provider == "disabled":
        logger.info("AI provider: disabled — deterministic rules only")
        return None

    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise EnvironmentError(
                "AI_PROVIDER=openai requires OPENAI_API_KEY to be set"
            )
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "").strip() or None
        azure_deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "").strip() or None
        azure_api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01")
        if azure_endpoint:
            logger.info(
                "AI provider: azure_openai (endpoint=%s, deployment=%s)",
                azure_endpoint,
                azure_deployment or model,
            )
        else:
            logger.info("AI provider: openai (model=%s)", model)
        from infrastructure.ai.openai_provider import OpenAIProvider
        return OpenAIProvider(
            api_key=api_key,
            model=model,
            azure_endpoint=azure_endpoint,
            azure_deployment=azure_deployment,
            azure_api_version=azure_api_version,
        )

    if provider == "anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            raise EnvironmentError(
                "AI_PROVIDER=anthropic requires ANTHROPIC_API_KEY to be set"
            )
        model = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
        logger.info("AI provider: anthropic (model=%s)", model)
        from infrastructure.ai.anthropic_provider import AnthropicProvider
        return AnthropicProvider(api_key=api_key, model=model)

    if provider == "ollama":
        base_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        model = os.getenv("OLLAMA_MODEL", "neural-chat")
        logger.info("AI provider: ollama (%s, model=%s)", base_url, model)
        from infrastructure.ai.ollama import OllamaProvider
        return OllamaProvider(base_url=base_url, model=model)

    raise EnvironmentError(
        f"Unknown AI_PROVIDER='{provider}'. "
        "Valid values: ollama, openai, anthropic, disabled"
    )
