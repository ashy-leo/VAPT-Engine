"""
core/header_checker.py

"""

import requests
import urllib3
from typing import Dict, Any

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

INFO_LEAK_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Generator",
]


def check_headers(target_url: str, timeout: float = 5.0) -> Dict[str, Any]:
    
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

   
    try:
        
        response = requests.get(target_url, timeout=timeout, verify=False)
    except requests.exceptions.RequestException as exc:
        
        raise RuntimeError(f"Failed to reach '{target_url}': {exc}") from exc

    missing_headers = [
        header for header in SECURITY_HEADERS if header not in response.headers
    ]

    info_headers = {
        header: response.headers[header]
        for header in INFO_LEAK_HEADERS
        if header in response.headers
    }

    return {
        "target": target_url,
        "status_code": response.status_code,
        "missing_headers": missing_headers,
        "info_headers": info_headers,
        "all_headers": dict(response.headers),
    }
           