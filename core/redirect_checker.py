import requests
import urllib3
import urllib.parse

# verify=False skips SSL certificate checks, which makes Python print a warning.
# We hide that warning to keep the output clean.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# The status codes that mean "go to another URL"
REDIRECT_CODES = [301, 302, 303, 307, 308]

# The external URL we try to inject into each parameter
TEST_URL = "https://example.com"


def check_redirect(
    target_url: str,
    timeout: float = 5.0
) -> dict:
    # Add https:// if the user did not type a scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    target = target_url

    result = {
        "target": target,
        "tested_parameters": [],
        "findings": []
    }

    # Split the URL into parts (scheme, host, path, query, ...)
    parsed_url = urllib.parse.urlparse(target)

    # Turn "next=/home&id=5" into [("next", "/home"), ("id", "5")]
    params = urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True)

    # Nothing to test if the URL has no query parameters
    if not params:
        return result

    for index, (name, value) in enumerate(params):
        # Copy the parameters and replace ONLY the value of the current one
        test_params = list(params)
        test_params[index] = (name, TEST_URL)

        # Rebuild the full URL with the changed query string
        new_query = urllib.parse.urlencode(test_params)
        test_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

        result["tested_parameters"].append(name)

        try:
            # A URL redirect is when a server answers "go to a different URL"
            # instead of showing a page. The browser then follows it automatically.
            #
            # allow_redirects=False is important: we want to STOP at the first
            # response and read the redirect ourselves. If requests followed it,
            # we would only see the final page and never see the Location header.
            response = requests.get(
                test_url,
                timeout=timeout,
                verify=False,
                allow_redirects=False
            )
        except requests.exceptions.RequestException as error:
            raise RuntimeError(
                f"Could not test parameter '{name}' on {target}: {error}"
            )

        if response.status_code in REDIRECT_CODES:
            # The Location header holds the URL the server wants us to go to
            location = response.headers.get("Location", "")

            # If the server sends us to the external URL we supplied, the site
            # trusts user input for redirects. An attacker could put their own
            # malicious site there and send the link to victims, who would
            # trust it because it starts with the real website's address.
            # This weakness is called an open redirect.
            if location == TEST_URL:
                result["findings"].append({
                    "parameter": name,
                    "redirect_location": location,
                    "potential_open_redirect": True
                })

    return result
