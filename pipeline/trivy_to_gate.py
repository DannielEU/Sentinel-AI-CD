#!/usr/bin/env python3
"""
trivy_to_gate.py — Trivy JSON → AI Deployment Gate adapter
===========================================================
Reads a Trivy JSON report, converts it to the ImageReport schema expected by
the gate API, sends it, and exits with a code the CI/CD pipeline can act on.

Exit codes
----------
  0  → APPROVED
  1  → REJECTED
  2  → WARNING  (pipeline may treat this as a soft failure)
  3  → Error communicating with the gate service

Usage
-----
  trivy image --format json -o trivy_report.json myapp:1.2.3
  python trivy_to_gate.py \\
      --report trivy_report.json \\
      --image  myapp:1.2.3 \\
      --gate   http://localhost:8000

Optional — include the Dockerfile so the AI model can reason about it:
  python trivy_to_gate.py --report trivy_report.json --image myapp:1.2.3 \\
      --dockerfile ./Dockerfile
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from collections import Counter
from pathlib import Path


EXIT_APPROVED = 0
EXIT_REJECTED = 1
EXIT_WARNING  = 2
EXIT_ERROR    = 3


# ── Trivy JSON parser ────────────────────────────────────────────────────────

def parse_trivy_report(path: Path) -> dict:
    """Return a dict with keys: critical, high, medium, low, unknown,
    os_family, scanner_output (truncated raw JSON), high_vulnerabilities_details."""
    data = json.loads(path.read_text())
    counts: Counter = Counter()
    os_family: str | None = None
    high_vulns_details = []

    for result in data.get("Results", []):
        # OS family is sometimes in the Type field
        rtype = result.get("Type", "")
        if rtype in ("alpine", "debian", "ubuntu", "redhat", "centos", "amazon"):
            os_family = rtype

        for vuln in result.get("Vulnerabilities") or []:
            sev = vuln.get("Severity", "UNKNOWN").upper()
            counts[sev] += 1

            # Extract details of HIGH severity vulnerabilities for AI enrichment
            if sev == "HIGH" and len(high_vulns_details) < 10:
                pkg_name = vuln.get("PkgName", "")
                if not pkg_name:
                    pkg_name = result.get("Target", "unknown")

                vuln_detail = {
                    "id": vuln.get("VulnerabilityID", ""),
                    "package": pkg_name,
                    "title": vuln.get("Title", ""),
                    "description": (vuln.get("Description", "")[:300] if vuln.get("Description") else None),
                }
                high_vulns_details.append(vuln_detail)

    return {
        "critical": counts.get("CRITICAL", 0),
        "high":     counts.get("HIGH", 0),
        "medium":   counts.get("MEDIUM", 0),
        "low":      counts.get("LOW", 0),
        "unknown":  counts.get("UNKNOWN", 0),
        "os_family": os_family,
        "scanner_output": json.dumps(data)[:4000],
        "high_vulnerabilities_details": high_vulns_details,
    }


def get_image_size_mb(image_name: str) -> float:
    """Try to get image size via docker inspect; fall back to 0 on error."""
    try:
        import subprocess
        out = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.Size}}", image_name],
            stderr=subprocess.DEVNULL,
        )
        size_bytes = int(out.strip())
        return round(size_bytes / (1024 * 1024), 2)
    except Exception:
        return 0.0


def extract_base_image(dockerfile_path: Path | None) -> str | None:
    if dockerfile_path is None or not dockerfile_path.exists():
        return None
    for line in dockerfile_path.read_text().splitlines():
        stripped = line.strip().upper()
        if stripped.startswith("FROM") and "SCRATCH" not in stripped:
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return None


# ── Gate API call ────────────────────────────────────────────────────────────

def call_gate(gate_url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{gate_url.rstrip('/')}/analyze-image",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    # Must exceed gate-side Ollama timeout (REQUEST_TIMEOUT=1800s in ollama_client.py)
    # so the client doesn't drop the connection while the model is still inferring.
    with urllib.request.urlopen(req, timeout=1830) as resp:
        return json.loads(resp.read())


# ── Pretty printer ───────────────────────────────────────────────────────────

def print_result(result: dict) -> None:
    decision = result.get("decision", "UNKNOWN")
    icons = {"APPROVED": "✅", "WARNING": "⚠️ ", "REJECTED": "❌"}
    icon = icons.get(decision, "❓")

    print("\n" + "=" * 70)
    print(f"  {icon}  GATE DECISION: {decision}")
    print("=" * 70)
    print(f"  Image  : {result.get('image_name', '-')}")
    print(f"  Source : {result.get('source', '-')}")
    print(f"  Reason : {result.get('reason', '-')}")

    recs = result.get("recommendations", [])
    if recs:
        print("\n  Action Items:")
        for i, r in enumerate(recs, 1):
            # Better formatting for specific vulnerability recommendations
            if "CVE" in r or "package" in r.lower() or "Update" in r:
                print(f"    [{i}] {r}")
            else:
                print(f"    • {r}")

    summary = result.get("summary")
    if summary:
        print("\n  Summary:")
        print(f"    {summary}")

    print("=" * 70 + "\n")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Send Trivy report to the AI Deployment Gate.")
    parser.add_argument("--report",     required=True,  help="Path to trivy JSON report")
    parser.add_argument("--image",      required=True,  help="Full image name (e.g. myapp:1.2.3)")
    parser.add_argument("--gate",       default="http://localhost:8000", help="Gate base URL")
    parser.add_argument("--dockerfile", default=None,   help="Path to Dockerfile (optional)")
    parser.add_argument("--size-mb",    type=float, default=None,
                        help="Image size in MB (auto-detected via docker inspect if omitted)")
    args = parser.parse_args()

    report_path     = Path(args.report)
    dockerfile_path = Path(args.dockerfile) if args.dockerfile else None

    if not report_path.exists():
        print(f"ERROR: report file not found: {report_path}", file=sys.stderr)
        return EXIT_ERROR

    print(f"Parsing Trivy report: {report_path}")
    trivy = parse_trivy_report(report_path)

    size_mb = args.size_mb
    if size_mb is None:
        size_mb = get_image_size_mb(args.image)
        if size_mb == 0.0:
            print("WARNING: could not determine image size via docker inspect, defaulting to 0 MB",
                  file=sys.stderr)

    payload: dict = {
        "image_name":    args.image,
        "image_size_mb": size_mb if size_mb > 0 else 1.0,
        "vulnerabilities": {
            "critical": trivy["critical"],
            "high":     trivy["high"],
            "medium":   trivy["medium"],
            "low":      trivy["low"],
            "unknown":  trivy["unknown"],
        },
        "scanner_output": trivy["scanner_output"],
    }

    if trivy["os_family"]:
        payload["os_family"] = trivy["os_family"]

    # Include HIGH vulnerability details for specific recommendations
    if trivy.get("high_vulnerabilities_details"):
        payload["high_vulnerabilities_details"] = trivy["high_vulnerabilities_details"]

    base_image = extract_base_image(dockerfile_path)
    if base_image:
        payload["base_image"] = base_image

    if dockerfile_path and dockerfile_path.exists():
        payload["dockerfile_content"] = dockerfile_path.read_text()[:4000]

    print(f"Sending report to gate: {args.gate}")
    print(f"  Vulns → critical={trivy['critical']} high={trivy['high']} "
          f"medium={trivy['medium']} low={trivy['low']}")

    try:
        result = call_gate(args.gate, payload)
    except urllib.error.URLError as exc:
        print(f"ERROR: could not reach gate service at {args.gate}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        print(f"ERROR: unexpected error calling gate: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print_result(result)

    decision = result.get("decision", "").upper()
    return {
        "APPROVED": EXIT_APPROVED,
        "WARNING":  EXIT_WARNING,
        "REJECTED": EXIT_REJECTED,
    }.get(decision, EXIT_ERROR)


if __name__ == "__main__":
    sys.exit(main())
