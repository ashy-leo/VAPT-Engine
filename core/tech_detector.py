import requests
import urllib3

HEADERS_TO_CHECK = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

HTML_FINGERPRINTS = ["WordPress", "Joomla", "Drupal", "React", "Angular", "Vue"]

def detect_technologies(
    target_url: str,
    timeout: float = 5.0
) -> dict:
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        response = requests.get(target_url, timeout=timeout, verify=False)
    except requests.exceptions.RequestException as error:
        raise RuntimeError(
            f"Could not connect to {target_url}. Check the URL and try again. ({error})"
        )
    technologies = []
    found_headers = {}
    for header_name in HEADERS_TO_CHECK:
        value = response.headers.get(header_name)
        if value:
            found_headers[header_name] = value
            if value not in technologies:
                technologies.append(value)
    html = response.text.lower()
    for name in HTML_FINGERPRINTS:
        if name.lower() in html:
            if name not in technologies:
                technologies.append(name)
    return {
        "target": target_url,
        "technologies": technologies,
        "headers": found_headers,
    }
         