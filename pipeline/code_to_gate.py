#!/usr/bin/env python3
"""
code_to_gate.py — Send source code files to the HexaFlow /analyze-code endpoint.

Usage:
  python pipeline/code_to_gate.py \\
      --gate   http://localhost:8000 \\
      --project my-project \\
      --files  src/AuthService.java src/UserController.java \\
      [--commit abc123] \\
      [--branch feature/login] \\
      [--token  $HEXAFLOW_TOKEN] \\
      [--extensions .java .py .ts]

Exit codes:
  0  PASSED   — no critical or high findings
  1  BLOCKED  — critical or high vulnerabilities detected
  2  WARNING  — medium/low findings, proceed with caution
  3  Error    — gate unreachable or unexpected response
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

_SUPPORTED_EXTENSIONS = {
    ".java", ".py", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".rb", ".php", ".cs", ".cpp", ".c",
    ".kt", ".swift", ".rs", ".scala", ".sh",
}

_MAX_FILE_BYTES = 50_000


def _collect_files(
    paths: list[str], extensions: set[str]
) -> list[tuple[str, str]]:
    collected: list[tuple[str, str]] = []
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            print(f"  [skip] {raw} — file not found", file=sys.stderr)
            continue
        if p.suffix.lower() not in extensions:
            print(f"  [skip] {raw} — extension not in scope", file=sys.stderr)
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            print(f"  [skip] {raw} — read error: {exc}", file=sys.stderr)
            continue
        if len(content.encode()) > _MAX_FILE_BYTES:
            content = content[:_MAX_FILE_BYTES]
        collected.append((raw, content))
    return collected


def main() -> None:
    parser = argparse.ArgumentParser(description="HexaFlow code gate client")
    parser.add_argument("--gate", default=os.getenv("HEXAFLOW_GATE_URL", "http://localhost:8000"))
    parser.add_argument("--project", required=True, help="Project name")
    parser.add_argument("--files", nargs="+", required=True, help="Source files to analyze")
    parser.add_argument("--commit", default=os.getenv("GITHUB_SHA", ""))
    parser.add_argument("--branch", default=os.getenv("GITHUB_REF_NAME", ""))
    parser.add_argument("--token", default=os.getenv("HEXAFLOW_TOKEN", ""))
    parser.add_argument(
        "--extensions",
        nargs="+",
        default=list(_SUPPORTED_EXTENSIONS),
        help="File extensions to analyze",
    )
    args = parser.parse_args()

    gate_url = args.gate.rstrip("/")
    extensions = {e if e.startswith(".") else f".{e}" for e in args.extensions}

    print(f"Gate URL  : {gate_url}")
    print(f"Project   : {args.project}")
    print(f"Commit    : {args.commit or '—'}")
    print(f"Branch    : {args.branch or '—'}")
    print()

    files = _collect_files(args.files, extensions)
    if not files:
        print("No eligible files to analyze — exiting with PASSED.", file=sys.stderr)
        sys.exit(0)

    print(f"Files to analyze: {len(files)}")
    for name, _ in files:
        print(f"  {name}")
    print()

    payload = {
        "project_name": args.project,
        "commit_sha": args.commit or None,
        "branch": args.branch or None,
        "files": [{"filename": name, "content": content} for name, content in files],
    }

    headers = {"Content-Type": "application/json"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    req = urllib.request.Request(
        f"{gate_url}/analyze-code",
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            response = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        print(f"Gate HTTP error {exc.code}: {body}", file=sys.stderr)
        sys.exit(3)
    except Exception as exc:
        print(f"Gate connection error: {exc}", file=sys.stderr)
        sys.exit(3)

    decision = response.get("decision", "ERROR")
    reason = response.get("reason", "")
    summary = response.get("summary", {})
    total = response.get("total_vulnerabilities", 0)
    files_analyzed = response.get("files_analyzed", 0)

    print(f"Decision         : {decision}")
    print(f"Reason           : {reason}")
    print(f"Files analyzed   : {files_analyzed}")
    print(f"Total findings   : {total}")
    print(f"  CRITICAL : {summary.get('CRITICAL', 0)}")
    print(f"  HIGH     : {summary.get('HIGH', 0)}")
    print(f"  MEDIUM   : {summary.get('MEDIUM', 0)}")
    print(f"  LOW      : {summary.get('LOW', 0)}")

    vulns = response.get("vulnerabilities", [])
    if vulns:
        print()
        print("Findings:")
        for v in vulns[:20]:
            print(
                f"  [{v.get('severity')}] {v.get('type')} — "
                f"{v.get('filename')}:{v.get('line_number') or '?'} — "
                f"{v.get('cwe_id') or ''}"
            )
        if len(vulns) > 20:
            print(f"  … and {len(vulns) - 20} more findings.")

    with open("code_gate_response.json", "w") as f:
        json.dump(response, f, indent=2)
    print()
    print("Full response saved to code_gate_response.json")

    exit_code = {"PASSED": 0, "BLOCKED": 1, "WARNING": 2}.get(decision, 3)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
