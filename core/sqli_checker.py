import requests
import urllib3
import urllib.parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common error snippets that different databases print when a query is malformed.
# If our injected quote/parenthesis breaks the SQL syntax, one of these may show up.
SQL_ERROR_INDICATORS = [
    "sql syntax",
    "mysql",
    "mysqli",
    "postgresql",
    "pg_query",
    "sqlite",
    "sqlstate",
    "oracle",
    "microsoft sql server",
]

# Basic SQL metacharacters. A single quote often breaks a query like:
#   SELECT * FROM items WHERE id = '1'
# turning it into invalid SQL, which can trigger a database error message.
TEST_PAYLOADS = ["'", '"', ")"]


def check_sqli(target_url: str, timeout: float = 5.0) -> dict:
    # Normalize the URL so requests always has a valid scheme to work with.
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    parsed = urllib.parse.urlparse(target_url)
    # parse_qsl keeps parameter order and gives us name/value tuples.
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

    if not query_pairs:
        return {
            "target": target_url,
            "tested_parameters": [],
            "findings": [],
        }

    param_names = [name for name, _ in query_pairs]
    findings = []

    # Test each parameter on its own, one payload at a time, leaving
    # every other parameter's value untouched.
    for target_index, (target_name, _original_value) in enumerate(query_pairs):
        for payload in TEST_PAYLOADS:
            # Rebuild the full parameter list, replacing only the current
            # parameter's value with the payload for this request.
            modified_pairs = list(query_pairs)
            modified_pairs[target_index] = (target_name, payload)

            new_query = urllib.parse.urlencode(modified_pairs)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            try:
                response = requests.get(test_url, timeout=timeout, verify=False)
            except requests.exceptions.RequestException as exc:
                raise RuntimeError(
                    f"Request failed while testing parameter '{target_name}' "
                    f"with payload {payload!r}: {exc}"
                )

            body_lower = response.text.lower()
            # A matching error string suggests our input reached a database
            # query and broke it. It does NOT prove the app is exploitable —
            # it just means a human should look closer.
            sql_error_detected = any(
                indicator in body_lower for indicator in SQL_ERROR_INDICATORS
            )

            if sql_error_detected:
                findings.append(
                    {
                        "parameter": target_name,
                        "payload": payload,
                        "sql_error_detected": True,
                    }
                )

    return {
        "target": target_url,
        "tested_parameters": param_names,
        "findings": findings,
    }
              