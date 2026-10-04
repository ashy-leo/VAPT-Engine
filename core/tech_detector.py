import requests
import urllib3

# Headers that often reveal what software a website runs on
HEADERS_TO_CHECK = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

# Words that often appear in the HTML of sites built with these technologies
HTML_FINGERPRINTS = ["WordPress", "Joomla", "Drupal", "React", "Angular", "Vue"]


def detect_technologies(
    target_url: str,
    timeout: float = 5.0
) -> dict:
    """Detect basic web technologies from response headers and HTML."""

    # Add https:// if the user did not type a scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    # Hide the warning that appears when we skip HTTPS certificate checks
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.get(target_url, timeout=timeout, verify=False)
    except requests.exceptions.RequestException as error:
        raise RuntimeError(
            f"Could not connect to {target_url}. Check the URL and try again. ({error})"
        )

    technologies = []
    found_headers = {}

    # Servers often announce themselves in headers (for example
    # "Server: nginx"), so the header value itself is a fingerprint.
    for header_name in HEADERS_TO_CHECK:
        value = response.headers.get(header_name)
        if value:
            found_headers[header_name] = value
            # Only add it if we have not seen it yet (no duplicates)
            if value not in technologies:
                technologies.append(value)

    # The page source can reveal a CMS or JavaScript framework, because
    # these tools leave their names in scripts, meta tags and file paths.
    # We lowercase both sides so "WordPress", "wordpress" and "WORDPRESS"
    # all match.
    html = response.text.lower()
    for name in HTML_FINGERPRINTS:
        if name.lower() in html:
            # Skip names already found, so each technology appears once
            if name not in technologies:
                technologies.append(name)

    return {
        "target": target_url,
        "technologies": technologies,
        "headers": found_headers,
    }
         