#!/usr/bin/env python3
"""
Generate secure authentication tokens for Sentinel AI-CD Gate.

Usage:
    python3 generate_token.py                    # Generate 1 token
    python3 generate_token.py --count 5          # Generate 5 tokens
    python3 generate_token.py --save tokens.txt  # Save to file
"""

import secrets
import argparse
import hashlib
from datetime import datetime
from pathlib import Path


def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def hash_token(token: str) -> str:
    """Hash token using SHA-256 (for secure storage)"""
    return hashlib.sha256(token.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Generate secure authentication tokens for Sentinel AI-CD"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of tokens to generate (default: 1)"
    )
    parser.add_argument(
        "--save",
        type=str,
        default=None,
        help="Save tokens to file (e.g., tokens.txt)"
    )
    parser.add_argument(
        "--length",
        type=int,
        default=32,
        help="Token length in bytes (default: 32, produces ~43 char base64)"
    )
    parser.add_argument(
        "--show-hash",
        action="store_true",
        help="Also show hashed version of tokens"
    )

    args = parser.parse_args()

    print(f"\n{'='*80}")
    print(f"🔐 Sentinel AI-CD Token Generator")
    print(f"{'='*80}\n")

    tokens = []
    output_lines = [
        f"Generated at: {datetime.now().isoformat()}",
        f"Count: {args.count}",
        f"Token Length: {args.length} bytes (~{len(generate_token(args.length))} chars)",
        "",
        "⚠️  IMPORTANT SECURITY NOTES:",
        "   - Keep these tokens SECRET and SECURE",
        "   - Store in GitHub Secrets or Azure Key Vault, never in code",
        "   - Rotate tokens regularly (every 90 days recommended)",
        "   - Use different tokens for different environments (Dev/Staging/Prod)",
        "   - Do NOT share tokens in Slack, Email, or version control",
        "",
        f"{'─'*80}",
        "",
    ]

    for i in range(args.count):
        token = generate_token(args.length)
        tokens.append(token)

        token_num = f"[Token {i+1}/{args.count}]"
        print(f"{token_num}")
        print(f"  Raw:  {token}")

        if args.show_hash:
            token_hash = hash_token(token)
            print(f"  Hash: {token_hash}")
            output_lines.append(f"{token_num} Raw:  {token}")
            output_lines.append(f"{token_num} Hash: {token_hash}")
        else:
            output_lines.append(f"{token_num} {token}")

        print()

    print(f"{'='*80}\n")

    # Usage instructions
    print("📌 HOW TO USE:")
    print("\n1. GitHub Actions (.github/workflows/ci.yml):")
    print("   - Create secret: Settings → Secrets → GATE_AUTH_TOKEN")
    print("   - Paste token value")
    print("   - Reference in workflow: ${{ secrets.GATE_AUTH_TOKEN }}")

    print("\n2. Azure App Service:")
    print("   - Settings → Configuration → Application settings")
    print("   - Add: GATE_AUTH_TOKEN = <token>")

    print("\n3. Docker/Local:")
    print("   - export GATE_AUTH_TOKEN=<token>")
    print("   - Or in .env file (add to .gitignore)")

    print("\n4. API Request:")
    print("   curl -X POST http://localhost:8000/analyze-image \\")
    print("     -H \"Authorization: Bearer <token>\" \\")
    print("     -H \"Content-Type: application/json\" \\")
    print("     -d '{...}'")

    print(f"\n{'='*80}\n")

    # Save to file if requested
    if args.save:
        output_lines.append("")
        output_lines.append("DO NOT COMMIT THIS FILE TO VERSION CONTROL!")
        output_lines.append("Add to .gitignore immediately.")
        output_lines.append("")

        save_path = Path(args.save)
        save_path.write_text("\n".join(output_lines))

        print(f"✅ Tokens saved to: {save_path.absolute()}")
        print(f"   Make sure to add {args.save} to .gitignore\n")

    print("✅ Token(s) generated successfully!")
    print("\n⚠️  REMINDER:")
    print("   - Do NOT commit tokens to version control")
    print("   - Do NOT print tokens in logs or CI/CD output")
    print("   - Rotate tokens periodically")
    print("   - Use GitHub Secrets for sensitive data\n")


if __name__ == "__main__":
    main()
