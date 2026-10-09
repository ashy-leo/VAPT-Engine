import requests
import urllib3
import urllib.parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

TEST_PAYLOADS = ["'", '"', ")"]

def check_sqli(target_url: str, timeout: float = 5.0) -> dict:
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url
    parsed = urllib.parse.urlparse(target_url)
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not query_pairs:
        return {
            "target": target_url,
            "tested_parameters": [],
            "findings": [],
        }
    param_names = [name for name, _ in query_pairs]
    findings = []
    for target_index, (target_name, _original_value) in enumerate(query_pairs):
        for payload in TEST_PAYLOADS:
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
              