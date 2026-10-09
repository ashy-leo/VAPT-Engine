"""
core/parameter_discovery.py

"""

import re
import urllib.parse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"User-Agent": "Mozilla/5.0"}

HREF_PATTERN = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


FORM_PATTERN = re.compile(r'<form\b[^>]*>.*?</form>', re.IGNORECASE | re.DOTALL)


FORM_ACTION_PATTERN = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)


FORM_METHOD_PATTERN = re.compile(r'method\s*=\s*["\']?(get|post)["\']?', re.IGNORECASE)


INPUT_TAG_PATTERN = re.compile(r'<input\b[^>]*>', re.IGNORECASE)


INPUT_NAME_PATTERN = re.compile(r'name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


INPUT_TYPE_PATTERN = re.compile(r'type\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


SKIP_INPUT_TYPES = {"submit", "button", "reset", "image", "file"}


FORM_PLACEHOLDER_VALUE = "test"


MAX_CRAWL_DEPTH = 2


def _same_host(url: str, base_netloc: str) -> bool:
    """Return True if url belongs to the same host:port as the target."""
    return urllib.parse.urlparse(url).netloc.lower() == base_netloc.lower()


def _urls_from_links(page_html: str, page_url: str, base_netloc: str) -> list:
    """Find <a href="..."> links that already carry a query string."""
    found = []

    for href in HREF_PATTERN.findall(page_html):
       
        absolute_url = urllib.parse.urljoin(page_url, href)
        parsed = urllib.parse.urlparse(absolute_url)

        if parsed.query and _same_host(absolute_url, base_netloc):
            found.append(absolute_url)

    return found


def _crawlable_links_from_page(page_html: str, page_url: str, base_netloc: str) -> list:
    """Find internal <a href="..."> links WITHOUT a query string.

    These are candidates to recursively crawl into (e.g.
    /dvwa/vulnerabilities/xss_r/) rather than parameterized URLs to test
    directly — those are already handled by _urls_from_links().
    """
    found = []

    for href in HREF_PATTERN.findall(page_html):
        absolute_url = urllib.parse.urljoin(page_url, href)
        parsed = urllib.parse.urlparse(absolute_url)

        # Skip non-http(s) links (mailto:, javascript:, tel:, #fragments-only, etc.)
        if parsed.scheme not in ("http", "https"):
            continue

        # Links that already carry a query string are handled as
        # parameterized candidates elsewhere, not crawled into.
        if parsed.query:
            continue

        if _same_host(absolute_url, base_netloc):
            found.append(absolute_url)

    return found


def _normalize_url(url: str) -> str:
    """Strip the fragment (#...) so '#'-only variants of the same page
    don't get treated as separate URLs in the visited set."""
    return urllib.parse.urldefrag(url)[0]


def _param_structure_key(url: str) -> tuple:
    
    parsed = urllib.parse.urlparse(url)
    param_names = frozenset(
        name for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    )
    return (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, param_names)


def _urls_from_forms(page_html: str, page_url: str, base_netloc: str) -> list:
    """Find simple GET forms and build one parameterized URL per form."""
    found = []

    for form_html in FORM_PATTERN.findall(page_html):
        method_match = FORM_METHOD_PATTERN.search(form_html)
        method = method_match.group(1).lower() if method_match else "get"

        # HTML forms default to GET when no method attribute is present,
        # so we only skip forms that explicitly say method="post".
        if method != "get":
            continue

        action_match = FORM_ACTION_PATTERN.search(form_html)
        action = action_match.group(1) if action_match else page_url

        form_action_url = urllib.parse.urljoin(page_url, action)

        if not _same_host(form_action_url, base_netloc):
            continue

        field_names = []
        for input_tag in INPUT_TAG_PATTERN.findall(form_html):
            type_match = INPUT_TYPE_PATTERN.search(input_tag)
            input_type = type_match.group(1).lower() if type_match else "text"
            if input_type in SKIP_INPUT_TYPES:
                continue

            name_match = INPUT_NAME_PATTERN.search(input_tag)
            if name_match:
                field_names.append(name_match.group(1))

        if not field_names:
            continue

        query_pairs = [(name, FORM_PLACEHOLDER_VALUE) for name in field_names]
        new_query = urllib.parse.urlencode(query_pairs)

        parsed_action = urllib.parse.urlparse(form_action_url)
        parameterized_url = urllib.parse.urlunparse(parsed_action._replace(query=new_query))

        found.append(parameterized_url)

    return found


def _fetch(url: str, timeout: float):
    """GET a URL, following redirects. Returns the response, or None on
    any request failure (dead host, timeout, etc.)."""
    try:
        return requests.get(
            url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=True
        )
    except requests.exceptions.RequestException:
        return None


def discover_parameters(base_url: str, discovered_endpoints: list, timeout: float = 5.0) -> list:
    
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = "https://" + base_url

    base_netloc = urllib.parse.urlparse(base_url).netloc

    parameterized_urls = []
    seen_params = set()  # holds _param_structure_key() values, not raw URLs

    # Tracks every page URL we've already requested, across all starting
    # endpoints, so overlapping crawls don't repeat the same request.
    visited = set()

    # BFS queue of (url, depth) pairs. Seed it with the endpoints
    # enum_engine already found, all at depth 0.
    queue = []
    for endpoint in discovered_endpoints:
        endpoint_url = endpoint.get("url")
        if endpoint_url:
            queue.append((endpoint_url, 0))

    if not queue:
        queue.append((base_url, 0))
    while queue:
        page_url, depth = queue.pop(0)

        normalized = _normalize_url(page_url)
        if normalized in visited:
            continue
        visited.add(normalized)

        response = _fetch(page_url, timeout)
        if response is None or not response.text:
            continue

        
        final_url = response.url or page_url

        candidate_params = _urls_from_links(response.text, final_url, base_netloc)
        candidate_params += _urls_from_forms(response.text, final_url, base_netloc)

        for url in candidate_params:
            key = _param_structure_key(url)
            if key not in seen_params:
                seen_params.add(key)
                parameterized_urls.append(url)

        
        if depth >= MAX_CRAWL_DEPTH:
            continue

        crawl_links = _crawlable_links_from_page(response.text, final_url, base_netloc)
        for link in crawl_links:
            if _normalize_url(link) not in visited:
                queue.append((link, depth + 1))

    return parameterized_urls
