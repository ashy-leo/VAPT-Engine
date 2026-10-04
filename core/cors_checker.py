"""Basic CORS security check."""

import requests
import urllib3


def check_cors(
    target_url: str,
    timeout: float = 5.0
) -> dict:
    """Run a basic CORS check on target_url and return a result dictionary."""

    # Add https:// if the user did not type a scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    normalized_url = target_url

    # Hide the warnings that appear when we skip HTTPS certificate checks
    urllib3.disable_warnings(
        urllib3.exceptions.InsecureRequestWarning
    )

    try:
        # Request 1: a normal request with no special headers
        response = requests.get(
            normalized_url,
            timeout=timeout,
            verify=False
        )

        # Request 2: pretend the request comes from a different website.
        # The browser sends an "Origin" header to say which site is asking.
        # A server that trusts every origin will echo it back to us.
        evil_response = requests.get(
            normalized_url,
            headers={"Origin": "https://evil.example"},
            timeout=timeout,
            verify=False
        )
    except requests.exceptions.RequestException as error:
        raise RuntimeError(
            f"CORS check failed: could not connect to {normalized_url} ({error})"
        )

    # Access-Control-Allow-Origin tells the browser which websites
    # are allowed to read this server's responses. None means it is missing.
    allow_origin = response.headers.get("Access-Control-Allow-Origin")
    missing = allow_origin is None

    # "*" means ANY website may read the response. That can be
    # security-sensitive if the page returns private or user-specific data.
    wildcard = allow_origin == "*"

    # Origin reflection: the server copies our fake Origin into its reply,
    # which means it may trust any website an attacker controls.
    reflected_value = evil_response.headers.get("Access-Control-Allow-Origin")
    origin_reflection = reflected_value == "https://evil.example"

    return {
        "target": normalized_url,
        "allow_origin": allow_origin,
        "origin_reflection": origin_reflection,
        "missing": missing,
        "potentially_vulnerable": missing or wildcard or origin_reflection,
    }
            