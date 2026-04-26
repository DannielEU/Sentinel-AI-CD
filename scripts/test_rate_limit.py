#!/usr/bin/env python3
"""
Test rate limiting and authentication on Sentinel AI-CD Gate.

Usage:
    python3 test_rate_limit.py --url http://localhost:8000
    python3 test_rate_limit.py --url http://localhost:8000 --token your-token
    python3 test_rate_limit.py --url http://localhost:8000 --test-auth
"""

import httpx
import time
import argparse
import json
from typing import Optional


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def print_header(text: str):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}")
    print(f"{text}")
    print(f"{'='*80}{Colors.RESET}\n")


def print_success(text: str):
    print(f"{Colors.GREEN}✅ {text}{Colors.RESET}")


def print_error(text: str):
    print(f"{Colors.RED}❌ {text}{Colors.RESET}")


def print_warning(text: str):
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.RESET}")


def print_info(text: str):
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.RESET}")


def test_rate_limit(base_url: str, token: Optional[str] = None, num_requests: int = 10):
    """Test rate limiting by sending multiple requests"""
    print_header("Testing Rate Limiting")

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    payload = {
        "image_name": "test:latest",
        "image_size_mb": 500,
        "vulnerabilities": {
            "critical": 0,
            "high": 5,
            "medium": 10,
            "low": 20,
            "unknown": 0
        }
    }

    url = f"{base_url}/analyze-image"
    results = {"success": 0, "rate_limited": 0, "errors": 0}

    print(f"Sending {num_requests} requests to {url}")
    print(f"Token: {'Yes' if token else 'No'}\n")

    for i in range(num_requests):
        try:
            response = httpx.post(url, json=payload, headers=headers, timeout=10)

            if response.status_code == 429:
                results["rate_limited"] += 1
                print_warning(f"Request {i+1}: Rate limited (429)")

            elif response.status_code == 200:
                results["success"] += 1
                print_success(f"Request {i+1}: Success (200)")

            else:
                results["errors"] += 1
                print_error(f"Request {i+1}: Error ({response.status_code})")
                print(f"  Response: {response.text[:100]}")

        except httpx.ConnectError:
            print_error(f"Request {i+1}: Cannot connect to {url}")
            break

        except Exception as e:
            results["errors"] += 1
            print_error(f"Request {i+1}: {str(e)}")

        time.sleep(0.1)

    print(f"\n{'─'*80}")
    print(f"Results:")
    print(f"  ✅ Successful: {results['success']}")
    print(f"  ⚠️  Rate Limited: {results['rate_limited']}")
    print(f"  ❌ Errors: {results['errors']}")

    return results


def test_authentication(base_url: str):
    """Test authentication with valid and invalid tokens"""
    print_header("Testing Authentication")

    payload = {
        "image_name": "test:latest",
        "image_size_mb": 500,
        "vulnerabilities": {
            "critical": 0,
            "high": 2,
            "medium": 5,
            "low": 10,
            "unknown": 0
        }
    }

    url = f"{base_url}/analyze-image"
    tests = [
        ("No token", None, [401, 400]),
        ("Invalid token", "Bearer invalid-token-xyz", [403]),
        ("Malformed header", "NotBearer validtoken", [401]),
    ]

    for test_name, auth_header, expected_status in tests:
        headers = {}
        if auth_header:
            headers["Authorization"] = auth_header

        try:
            response = httpx.post(url, json=payload, headers=headers, timeout=10)

            if response.status_code in expected_status:
                print_success(f"{test_name}: Got expected status {response.status_code}")
            else:
                print_warning(f"{test_name}: Got status {response.status_code}, expected {expected_status}")

        except Exception as e:
            print_error(f"{test_name}: {str(e)}")


def test_health(base_url: str):
    """Test health endpoint"""
    print_header("Testing Health Endpoint")

    try:
        response = httpx.get(f"{base_url}/health", timeout=10)
        if response.status_code == 200:
            print_success(f"Health check passed")
            data = response.json()
            print_info(f"Response: {json.dumps(data, indent=2)}")
        else:
            print_error(f"Health check failed: {response.status_code}")

    except httpx.ConnectError:
        print_error(f"Cannot connect to {base_url}")

    except Exception as e:
        print_error(f"Error: {str(e)}")


def test_valid_request(base_url: str, token: Optional[str] = None):
    """Test a valid request with proper data"""
    print_header("Testing Valid Request")

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        print_info(f"Using token: {token[:20]}...")
    else:
        print_warning("No token provided - authentication may fail")

    payload = {
        "image_name": "myapp:1.0.0",
        "image_size_mb": 320,
        "vulnerabilities": {
            "critical": 0,
            "high": 2,
            "medium": 8,
            "low": 15,
            "unknown": 1
        },
        "base_image": "python:3.11-slim",
        "os_family": "debian"
    }

    url = f"{base_url}/analyze-image"

    try:
        response = httpx.post(url, json=payload, headers=headers, timeout=10)

        if response.status_code == 200:
            print_success(f"Request successful (200)")
            data = response.json()
            print_info(f"Decision: {data.get('decision')}")
            print_info(f"Reason: {data.get('reason')}")
            if data.get('recommendations'):
                print_info(f"Recommendations: {len(data.get('recommendations'))} items")

        elif response.status_code == 401:
            print_error("Unauthorized - token missing or invalid")

        elif response.status_code == 429:
            print_warning("Rate limited - try again later")

        else:
            print_error(f"Error: {response.status_code}")
            print(f"Response: {response.text[:200]}")

    except Exception as e:
        print_error(f"Request failed: {str(e)}")


def main():
    parser = argparse.ArgumentParser(
        description="Test Sentinel AI-CD Gate rate limiting and authentication"
    )
    parser.add_argument(
        "--url",
        type=str,
        default="http://localhost:8000",
        help="Base URL of Sentinel Gate (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--token",
        type=str,
        default=None,
        help="Authentication token to test"
    )
    parser.add_argument(
        "--test-rate-limit",
        action="store_true",
        default=False,
        help="Test rate limiting (sends multiple requests)"
    )
    parser.add_argument(
        "--test-auth",
        action="store_true",
        default=False,
        help="Test authentication with invalid tokens"
    )
    parser.add_argument(
        "--test-all",
        action="store_true",
        default=False,
        help="Run all tests"
    )
    parser.add_argument(
        "--num-requests",
        type=int,
        default=10,
        help="Number of requests for rate limit test (default: 10)"
    )

    args = parser.parse_args()

    print(f"\n{Colors.BOLD}{Colors.BLUE}")
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║  Sentinel AI-CD Gate — Rate Limiting & Authentication Tester      ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")

    print_info(f"Target URL: {args.url}")

    # Run tests based on flags
    if args.test_all or not any([args.test_rate_limit, args.test_auth]):
        test_health(args.url)
        test_valid_request(args.url, args.token)
        if args.test_auth or args.test_all:
            test_authentication(args.url)
        if args.test_rate_limit or args.test_all:
            test_rate_limit(args.url, args.token, args.num_requests)

    else:
        if args.test_rate_limit:
            test_rate_limit(args.url, args.token, args.num_requests)
        if args.test_auth:
            test_authentication(args.url)

    print(f"\n{Colors.BLUE}{'='*80}{Colors.RESET}\n")


if __name__ == "__main__":
    main()
