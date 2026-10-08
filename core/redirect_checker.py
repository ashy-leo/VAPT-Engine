import requests

import urllib3

import urllib.parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REDIRECT_CODES = [301, 302, 303, 307, 308]

TEST_URL = "https://example.com"



def check_redirect(

    target_url: str,

    timeout: float = 5.0

) -> dict:

    if not target_url.startswith(("http://", "https://")):

        target_url = "https://" + target_url

    target = target_url

    result = {

        "target": target,

        "tested_parameters": [],

        "findings": []

    }

    parsed_url = urllib.parse.urlparse(target)

    params = urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True)

    if not params:

        return result

    for index, (name, value) in enumerate(params):

        test_params = list(params)

        test_params[index] = (name, TEST_URL)

        new_query = urllib.parse.urlencode(test_params)

        test_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

        result["tested_parameters"].append(name)

        try:

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

            location = response.headers.get("Location", "")

            if location == TEST_URL:

                result["findings"].append({

                    "parameter": name,

                    "redirect_location": location,

                    "potential_open_redirect": True

                })

    return result