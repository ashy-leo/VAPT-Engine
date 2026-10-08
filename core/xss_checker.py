import requests
import urllib3
import urllib.parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

XSS_PAYLOAD = "<script>alert(1)</script>"

def check_xss(target_url: str, timeout: float = 5.0) -> dict:
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url
    parsed = urllib.parse.urlparse(target_url)
    query_params = urllib.parse.parse_qs(parsed.query)
    result = {
        "target": target_url,
        "tested_parameters": [],
        "vulnerable_parameters": [],
        "findings": [],
    }
    if not query_params:
        return result
    encoded_payload = urllib.parse.quote(XSS_PAYLOAD)
    for param_name in query_params:
        if param_name in result["tested_parameters"]:
            continue
        result["tested_parameters"].append(param_name)
        test_params = {key: value[0] for key, value in query_params.items()}
        test_params[param_name] = encoded_payload
        new_query = urllib.parse.urlencode(test_params, safe="<>/'\"();:%")
        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        try:
            response = requests.get(test_url, timeout=timeout, verify=False)
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(
                f"Request failed while testing parameter '{param_name}': {exc}"
            )
        reflected = XSS_PAYLOAD in response.text
        if reflected:
            result["vulnerable_parameters"].append(param_name)
        result["findings"].append({
            "parameter": param_name,
            "payload": XSS_PAYLOAD,
            "reflected": reflected,
        })
    return result