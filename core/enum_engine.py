import requests
import urllib3
import urllib.parse
import concurrent.futures
import os
from typing import Optional

# Hide warnings for self-signed / unverified HTTPS certs, like the other modules.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Only these status codes are considered "interesting" enough to report.
# This keeps noisy 404s (the vast majority of results) out of the output.
INTERESTING_CODES = [200, 301, 302, 307, 401, 403]

HEADERS = {"User-Agent": "Mozilla/5.0"}


def _is_https_upgrade_redirect(url: str, response) -> bool:
    """
    True if the response only redirects to the exact same URL over HTTPS
    (a blanket http -> https redirect, not a real endpoint).
    """
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
    """
    Check a single endpoint (target_url + word) and return a result dict
    if the response status code is one we care about, otherwise None.
    """
    # Build the full URL cleanly, avoiding duplicate slashes like
    # "https://example.com//admin"
    url = f"{target_url.rstrip('/')}/{word.lstrip('/')}"

    try:
        # We try HEAD first because it only fetches response headers,
        # not the full response body. This is much faster and uses
        # far less bandwidth when scanning hundreds/thousands of words.
        response = requests.head(
            url, headers=HEADERS, timeout=timeout,
            verify=False, allow_redirects=False
        )

        # Some servers don't support HEAD on certain routes and reply
        # with 405 Method Not Allowed. In that case, fall back to GET
        # so we don't miss a valid endpoint just because HEAD isn't supported.
        if response.status_code == 405:
            response = requests.get(
                url, headers=HEADERS, timeout=timeout,
                verify=False, allow_redirects=False
            )

    except requests.exceptions.RequestException:
        # Covers connection errors, timeouts, DNS failures, etc.
        # We swallow these silently so one bad/dead endpoint doesn't
        # crash or stop the whole scan.
        return None

    # Ignore a blanket http -> https redirect; it says nothing about
    # whether this particular path exists.
    if _is_https_upgrade_redirect(url, response):
        return None

    # Filter: only keep results with status codes we actually care about.
    # This cuts out the noise of hundreds of plain 404 "not found" responses.
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
    """
    Enumerate endpoints on target_url using words from wordlist_path.

    Returns a list of dicts for endpoints that responded with one of the
    "interesting" status codes, sorted by URL ascending.
    """
    # Normalize the target URL so the caller doesn't have to worry about
    # whether they included a scheme (http/https) or not.
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    # Fail early with a clear, readable error if the wordlist doesn't exist,
    # instead of letting a confusing low-level exception bubble up.
    if not os.path.exists(wordlist_path):
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    # Read and parse the wordlist:
    # - strip whitespace/newlines from each line
    # - skip empty lines
    # - skip comment lines starting with "#"
    with open(wordlist_path, "r", encoding="utf-8") as f:
        words = [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]

    results = []

    # ThreadPoolExecutor is used because this task is I/O bound -- most of
    # the time is spent waiting on network responses, not doing CPU work.
    # Threads let us have many requests "in flight" at once instead of
    # waiting for each one to finish before starting the next.
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [
            executor.submit(_check_endpoint, target_url, word, timeout)
            for word in words
        ]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)

    # Sort the final results by URL so output is predictable and readable.
    results.sort(key=lambda item: item["url"])

    return results
