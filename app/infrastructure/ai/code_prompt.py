"""
Language-agnostic OWASP Top 10 prompt builder for source code analysis.
"""

import os

_LANG_MAP: dict[str, str] = {
    ".java": "Java",
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "JavaScript (React)",
    ".tsx": "TypeScript (React)",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".kt": "Kotlin",
    ".swift": "Swift",
    ".rs": "Rust",
    ".scala": "Scala",
    ".sh": "Shell",
    ".tf": "Terraform",
    ".yaml": "YAML",
    ".yml": "YAML",
}

_MAX_CONTENT_CHARS = 4000


def _detect_language(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    return _LANG_MAP.get(ext, "unknown")


def build_code_analysis_prompt(filename: str, content: str) -> str:
    language = _detect_language(filename)
    truncated = content[:_MAX_CONTENT_CHARS]

    return f"""You are a security code reviewer. Find security vulnerabilities in this {language} file.

FILE: {filename}

Look for: hardcoded passwords/secrets/credentials, SQL injection, command injection, \
broken authentication (plaintext passwords), sensitive data in logs, path traversal, XSS, \
insecure configurations, exposed API keys or connection strings.

CODE:
{truncated}

Output a JSON array of findings. Each finding must have these fields:
- "type": short vulnerability name
- "severity": CRITICAL, HIGH, MEDIUM, or LOW
- "line_number": integer (0 if unknown)
- "description": what is wrong and why it is dangerous
- "code_snippet": the vulnerable code (short)
- "suggestion": how to fix it
- "cwe_id": e.g. "CWE-798"

Severity guide: CRITICAL=remote exploit no auth, HIGH=serious risk easy to exploit, \
MEDIUM=requires conditions, LOW=best practice issue.

Important: hardcoded database URLs with username:password ARE critical vulnerabilities (CWE-798).
Plaintext password comparison without hashing IS a high vulnerability (CWE-256).
Logging user PII/tokens IS a medium vulnerability (CWE-532).

Output ONLY the JSON array, no other text. If nothing found, output: []"""
