"""
core/header_checker.py

A simple tool that fetches a URL and checks its HTTP response headers for:
  1. Missing security headers (headers that SHOULD be present but aren't)
  2. Information-leakage headers (headers that ARE present and reveal
     details about the server/technology stack)
"""

import requests
import urllib3
from typing import Dict, Any


# Security headers that a well-configured site should send.
# We flag any of these that are MISSING from the response.
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Headers that can leak details about the server/framework in use.
# We flag any of these that ARE present, along with their values.
INFO_LEAK_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Generator",
]


def check_headers(target_url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Fetch target_url and analyze its response headers.

    Returns a dictionary with the target URL, status code, missing
    security headers, any information-leaking headers found, and all
    raw headers from the response.
    """

    # --- Step 1: Normalize the URL ---
    # Beginners often type "example.com" without a scheme. If no scheme
    # is present, default to https:// so requests knows how to connect.
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    # --- Step 2: Suppress the "insecure request" warning ---
    # We use verify=False below (see explanation after this function),
    # which normally makes urllib3 print a warning to the console for
    # every request. This line just silences that specific warning so
    # the output stays clean for the user.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # --- Step 3: Make the actual HTTP request ---
    try:
        # requests.get() opens a connection to the target URL, sends an
        # HTTP GET request, waits for the server's response (up to
        # `timeout` seconds), and returns a Response object containing
        # the status code, headers, and body.
        #
        # verify=False tells requests to skip SSL certificate validation.
        # This is used here because this tool may be pointed at internal,
        # self-signed, or misconfigured hosts where a valid certificate
        # chain isn't guaranteed. In normal production code you would
        # leave verify=True to protect against man-in-the-middle attacks.
        response = requests.get(target_url, timeout=timeout, verify=False)
    except requests.exceptions.RequestException as exc:
        # This single except block catches timeouts, connection errors,
        # DNS failures, and malformed URLs, so the caller gets a clean,
        # readable error instead of a raw traceback.
        raise RuntimeError(f"Failed to reach '{target_url}': {exc}") from exc

    # --- Step 4: Check for missing security headers ---
    # response.headers is case-insensitive, so "header in response.headers"
    # correctly matches "content-security-policy", "Content-Security-Policy",
    # etc. We collect the names of any expected header that is absent.
    missing_headers = [
        header for header in SECURITY_HEADERS if header not in response.headers
    ]

    # --- Step 5: Check for information-leakage headers ---
    # Here we do the opposite: if the header IS present, we record its
    # key and value, since the value (e.g. "Server: nginx/1.18.0") is
    # what actually leaks information about the target's stack.
    info_headers = {
        header: response.headers[header]
        for header in INFO_LEAK_HEADERS
        if header in response.headers
    }

    # --- Step 6: Build and return the result dictionary ---
    return {
        "target": target_url,
        "status_code": response.status_code,
        "missing_headers": missing_headers,
        "info_headers": info_headers,
        "all_headers": dict(response.headers),
    }
           