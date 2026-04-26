"""
Secrets detector — scans Dockerfile content for hardcoded credentials and secrets.

Patterns cover the most common secret types: cloud provider keys, OAuth tokens,
private keys, and generic credentials. Comments are excluded from scanning.

If any secret is found the gate returns REJECTED with source='secrets_detector'
before consulting the rule engine or AI model.
"""

import re
from dataclasses import dataclass

# (compiled_pattern, human-readable name)
_RAW_PATTERNS: list[tuple[str, str]] = [
    (r"\bAKIA[A-Z0-9]{16}\b", "AWS Access Key ID"),
    (r"(?i)(aws_secret_access_key)\s*[=:]\s*[A-Za-z0-9+/]{40}", "AWS Secret Access Key"),
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"ghs_[a-zA-Z0-9]{36}", "GitHub App Token"),
    (r"glpat-[a-zA-Z0-9\-_]{20,}", "GitLab Personal Access Token"),
    (r"-----BEGIN\s+(RSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----", "Private Key"),
    (
        r"(?i)(password|passwd|pwd)\s*[=:]\s*(?!\$\{)(?!\"\s*\$)(?!\"\"\s*)[^\s\n$\"{]{8,}",
        "Hardcoded Password",
    ),
    (
        r"(?i)(api_key|apikey|api-key|secret_key|secretkey)\s*[=:]\s*[a-zA-Z0-9_\-]{20,}",
        "Hardcoded API Key",
    ),
    # Generic token pattern — must appear in ENV/ARG lines to reduce false positives
    (
        r"(?i)(auth_token|access_token|bearer_token)\s*[=:]\s*[a-zA-Z0-9_\-\.]{20,}",
        "Hardcoded Auth Token",
    ),
    (r"(?i)PRIVATE_KEY\s*[=:]\s*[a-zA-Z0-9+/=]{40,}", "Hardcoded Private Key (base64)"),
]

_COMPILED: list[tuple[re.Pattern, str]] = [
    (re.compile(pat), name) for pat, name in _RAW_PATTERNS
]


@dataclass
class SecretFound:
    pattern_name: str
    line_number: int
    line_preview: str  # first 80 chars, value portion masked


def _mask_line(line: str) -> str:
    """Replace the value portion of a key=value pair with asterisks."""
    masked = re.sub(
        r"(=\s*)[^\s\n]{4,}",
        lambda m: m.group(1) + "****",
        line,
        count=1,
    )
    return masked[:80]


def scan_dockerfile(content: str) -> list[SecretFound]:
    """Scan *content* (Dockerfile text) for hardcoded secrets.

    Lines starting with '#' are skipped. Returns a list of SecretFound; an
    empty list means no secrets were detected.
    """
    if not content:
        return []

    found: list[SecretFound] = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for pattern, name in _COMPILED:
            if pattern.search(line):
                found.append(
                    SecretFound(
                        pattern_name=name,
                        line_number=lineno,
                        line_preview=_mask_line(line),
                    )
                )
                break  # one match per line is enough

    return found
