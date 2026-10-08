"""Basic CORS security check."""

import requests
import urllib3


def check_cors(
    target_url: str,
    timeout: float = 5.0
) -> dict:
    

    #Adding https:// if the user did not type a scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    normalized_url = target_url

    urllib3.disable_warnings(
        urllib3.exceptions.InsecureRequestWarning
    )

    try:
        #normal request with no special headers
        response = requests.get(
            normalized_url,
            timeout=timeout,
            verify=False
        )

        #pretending the request comes from a different website.
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

    allow_origin = response.headers.get("Access-Control-Allow-Origin")
    missing = allow_origin is None

    wildcard = allow_origin == "*"

 
    reflected_value = evil_response.headers.get("Access-Control-Allow-Origin")
    origin_reflection = reflected_value == "https://evil.example"

    return {
        "target": normalized_url,
        "allow_origin": allow_origin,
        "origin_reflection": origin_reflection,
        "missing": missing,
        "potentially_vulnerable": missing or wildcard or origin_reflection,
    }
            