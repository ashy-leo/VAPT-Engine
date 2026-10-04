import requests
import urllib3
import urllib.parse

# Suppress warnings about self-signed / unverified HTTPS certs during testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# The one payload we test with. If this exact string comes back in the
# response body, we say the parameter "reflected" it.
XSS_PAYLOAD = "<script>alert(1)</script>"


def check_xss(target_url: str, timeout: float = 5.0) -> dict:
    # Make sure the URL has a scheme, since urllib.parse and requests
    # both expect "http://" or "https://" at the start.
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    # Break the URL into pieces: scheme, host, path, query string, etc.
    parsed = urllib.parse.urlparse(target_url)

    # A "query parameter" is a name/value pair found after the "?" in a URL,
    # e.g. in "https://example.com/search?q=test", "q" is the parameter
    # and "test" is its value. parse_qs turns "q=test&x=1" into a dict.
    query_params = urllib.parse.parse_qs(parsed.query)

    result = {
        "target": target_url,
        "tested_parameters": [],
        "vulnerable_parameters": [],
        "findings": [],
    }

    # Nothing to test if there's no query string at all.
    if not query_params:
        return result

    # URL-encode the payload so it can safely be placed inside a URL
    # (e.g. "<" becomes "%3C", ">" becomes "%3E", etc.)
    encoded_payload = urllib.parse.quote(XSS_PAYLOAD)

    for param_name in query_params:
        if param_name in result["tested_parameters"]:
            continue  # avoid testing/duplicating the same parameter twice

        result["tested_parameters"].append(param_name)

        # Copy the original parameters so we don't disturb them, then
        # replace just this one parameter's value with our payload.
        # We insert the payload INTO the parameter because that's how a
        # reflected XSS attack works: the attacker gets the app to place
        # attacker-controlled input directly into the page it sends back.
        test_params = {key: value[0] for key, value in query_params.items()}
        test_params[param_name] = encoded_payload

        # Rebuild the query string and then the full URL with our
        # modified parameter in place.
        new_query = urllib.parse.urlencode(test_params, safe="<>/'\"();:%")
        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

        try:
            response = requests.get(test_url, timeout=timeout, verify=False)
        except requests.exceptions.RequestException as exc:
            # Don't let a raw exception/traceback escape this function.
            raise RuntimeError(
                f"Request failed while testing parameter '{param_name}': {exc}"
            )

        # "Reflection" means the exact payload we sent shows up somewhere
        # in the page the server sent back. It does NOT mean the app is
        # definitely vulnerable — the browser might not actually run it
        # (e.g. it could be escaped, inside a comment, or in a non-executed
        # context). It's just a signal worth checking manually.
        reflected = XSS_PAYLOAD in response.text

        if reflected:
            result["vulnerable_parameters"].append(param_name)

        result["findings"].append({
            "parameter": param_name,
            "payload": XSS_PAYLOAD,
            "reflected": reflected,
        })

    return result
