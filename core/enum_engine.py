import requests
import urllib3
import urllib.parse
import concurrent.futures
import os
from typing import Optional


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INTERESTING_CODES = [200, 301, 302, 307, 401, 403]

HEADERS = {"User-Agent": "Mozilla/5.0"}


def _is_https_upgrade_redirect(url: str, response) -> bool:
    
    if response.status_code not in (301, 302, 307, 308):
        return False

    location = response.headers.get("Location", "")
    if not location:
        return False

    old = urllib.parse.urlparse(url)
    new = urllib.parse.urlparse(urllib.parse.urljoin(url, location))

    return (
        old.scheme == "http"
        and new.scheme == "https"
        and (old.hostname or "").lower() == (new.hostname or "").lower()
        and old.path == new.path
        and old.query == new.query
    )


def _check_endpoint(target_url: str, word: str, timeout: float) -> Optional[dict]:
    
    # "https://example.com//admin"(to avoid)
    url = f"{target_url.rstrip('/')}/{word.lstrip('/')}"

    try:
        
        response = requests.head(
            url, headers=HEADERS, timeout=timeout,
            verify=False, allow_redirects=False
        )

        
        if response.status_code == 405:
            response = requests.get(
                url, headers=HEADERS, timeout=timeout,
                verify=False, allow_redirects=False
            )

    except requests.exceptions.RequestException:
        return None

 
    if _is_https_upgrade_redirect(url, response):
        return None

    if response.status_code in INTERESTING_CODES:
        return {
            "endpoint": word,
            "status_code": response.status_code,
            "url": url,
        }

    return None


def enumerate_endpoints(
    target_url: str,
    wordlist_path: str,
    max_threads: int = 20,
    timeout: float = 3.0,
) -> list[dict]:
    
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    if not os.path.exists(wordlist_path):
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    
    with open(wordlist_path, "r", encoding="utf-8") as f:
        words = [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]

    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [
            executor.submit(_check_endpoint, target_url, word, timeout)
            for word in words
        ]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)

   
    results.sort(key=lambda item: item["url"])

    return results
