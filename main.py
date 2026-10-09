#!/usr/bin/env python3
"""
main.py

VAPT-Engine command-line entry point.
Ties together port scanning, endpoint enumeration, HTTP header analysis,
web security checks, and PDF report generation.
"""

import argparse
import sys
import urllib.parse
from datetime import datetime

import requests
import urllib3

from config import (
    TOP_PORTS,
    DEFAULT_WORDLIST,
    DEFAULT_SOCKET_TIMEOUT,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_MAX_THREADS,
)
from core.port_scanner import scan_ports
from core.enum_engine import enumerate_endpoints
from core.parameter_discovery import discover_parameters
from core.header_checker import check_headers
from core.cors_checker import check_cors
from core.tech_detector import detect_technologies
from core.xss_checker import check_xss
from core.sqli_checker import check_sqli
from core.redirect_checker import check_redirect
from reporting.pdf_generator import generate_pdf
from utils.logger import log_info, log_success, log_warn, log_error, print_banner

# Same approach as the other modules: hide warnings for self-signed certs.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_arguments():
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="VAPT-Engine: A beginner-friendly vulnerability assessment CLI tool."
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target hostname or IP address (e.g., example.com or 192.168.1.10)"
    )
    parser.add_argument(
        "--ports",
        action="store_true",
        help="Run a TCP port scan against the target."
    )
    parser.add_argument(
        "--enum",
        action="store_true",
        help="Run endpoint/directory enumeration against the target."
    )
    parser.add_argument(
        "--headers",
        action="store_true",
        help="Run HTTP security header analysis against the target."
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all available scans (ports, enum, headers)."
    )
    parser.add_argument(
        "--wordlist",
        default=DEFAULT_WORDLIST,
        help=f"Path to wordlist for endpoint enumeration (default: {DEFAULT_WORDLIST})"
    )
    parser.add_argument(
        "-o", "--output",
        default="vapt_report.pdf",
        help="Output PDF report filename (default: vapt_report.pdf)"
    )

    args = parser.parse_args()

    if not (args.ports or args.enum or args.headers or args.all):
        args.all = True

    return args


def run_port_scan(target: str) -> list:
    """Run the port scan module and return its results."""
    log_info(f"Starting port scan on {target}...")
    try:
        results = scan_ports(
            target=target,
            ports=TOP_PORTS,
            timeout=DEFAULT_SOCKET_TIMEOUT,
            max_threads=DEFAULT_MAX_THREADS,
        )
        log_success(f"Port scan complete. {len(results)} open port(s) found.")
        return results
    except ValueError as exc:
        log_error(f"Port scan failed: {exc}")
        return []
    except Exception as exc:
        log_error(f"Unexpected error during port scan: {exc}")
        return []


def run_enum_scan(target_url: str, wordlist_path: str) -> list:
    """Run the endpoint enumeration module and return its results."""
    log_info(f"Starting endpoint enumeration on {target_url}...")
    try:
        results = enumerate_endpoints(
            target_url=target_url,
            wordlist_path=wordlist_path,
            max_threads=DEFAULT_MAX_THREADS,
            timeout=DEFAULT_HTTP_TIMEOUT,
        )
        log_success(f"Endpoint enumeration complete. {len(results)} endpoint(s) found.")
        return results
    except FileNotFoundError as exc:
        log_error(f"Endpoint enumeration failed: {exc}")
        return []
    except Exception as exc:
        log_error(f"Unexpected error during endpoint enumeration: {exc}")
        return []


def run_header_check(target_url: str) -> dict:
    """Run the header checker module and return its results."""
    log_info(f"Starting HTTP header analysis on {target_url}...")
    try:
        result = check_headers(
            target_url=target_url,
            timeout=DEFAULT_HTTP_TIMEOUT
        )
        log_success(
            f"Header analysis complete. "
            f"{len(result['missing_headers'])} missing, "
            f"{len(result['info_headers'])} leaking."
        )
        return result
    except RuntimeError as exc:
        log_error(f"Header analysis failed: {exc}")
        return {}
    except Exception as exc:
        log_error(f"Unexpected error during header analysis: {exc}")
        return {}


def run_cors_check(target_url: str) -> dict:
    """Run the CORS checker module and return its results."""
    log_info(f"Starting CORS check on {target_url}...")
    try:
        result = check_cors(
            target_url,
            timeout=DEFAULT_HTTP_TIMEOUT
        )

        if result["potentially_vulnerable"]:
            log_warn("CORS check complete. Potential CORS issue flagged.")
        else:
            log_success("CORS check complete. No CORS issue flagged.")

        return result
    except RuntimeError as exc:
        log_error(f"CORS check failed: {exc}")
        return {}
    except Exception as exc:
        log_error(f"Unexpected error during CORS check: {exc}")
        return {}


def run_technology_detection(target_url: str) -> dict:
    """Run the technology detector module and return its results."""
    log_info(f"Starting technology detection on {target_url}...")
    try:
        result = detect_technologies(
            target_url,
            timeout=DEFAULT_HTTP_TIMEOUT
        )

        log_success(
            f"Technology detection complete. "
            f"{len(result['technologies'])} technology(ies) detected."
        )
        return result
    except RuntimeError as exc:
        log_error(f"Technology detection failed: {exc}")
        return {}
    except Exception as exc:
        log_error(f"Unexpected error during technology detection: {exc}")
        return {}


def run_xss_check(target_url: str) -> dict:
    """Run the XSS checker module and return its results."""
    log_info(f"Starting XSS check on {target_url}...")
    try:
        result = check_xss(
            target_url,
            timeout=DEFAULT_HTTP_TIMEOUT
        )

        log_success(
            f"XSS check complete. "
            f"{len(result['tested_parameters'])} parameter(s) tested, "
            f"{len(result['vulnerable_parameters'])} reflected the payload."
        )
        return result
    except RuntimeError as exc:
        log_error(f"XSS check failed: {exc}")
        return {}
    except Exception as exc:
        log_error(f"Unexpected error during XSS check: {exc}")
        return {}


def run_sqli_check(target_url: str) -> dict:
    """Run the SQL injection checker module and return its results."""
    log_info(f"Starting SQL injection check on {target_url}...")
    try:
        result = check_sqli(
            target_url,
            timeout=DEFAULT_HTTP_TIMEOUT
        )

        log_success(
            f"SQL injection check complete. "
            f"{len(result['tested_parameters'])} parameter(s) tested, "
            f"{len(result['findings'])} possible SQL error(s) found."
        )
        return result
    except RuntimeError as exc:
        log_error(f"SQL injection check failed: {exc}")
        return {}
    except Exception as exc:
        log_error(f"Unexpected error during SQL injection check: {exc}")
        return {}


def run_redirect_check(target_url: str) -> dict:
    """Run the open-redirect checker module and return its results."""
    log_info(f"Starting open-redirect check on {target_url}...")
    try:
        result = check_redirect(
            target_url,
            timeout=DEFAULT_HTTP_TIMEOUT
        )

        log_success(
            f"Open-redirect check complete. "
            f"{len(result['tested_parameters'])} parameter(s) tested, "
            f"{len(result['findings'])} potential open redirect(s) found."
        )
        return result
    except RuntimeError as exc:
        log_error(f"Open-redirect check failed: {exc}")
        return {}
    except Exception as exc:
        log_error(f"Unexpected error during open-redirect check: {exc}")
        return {}


def run_xss_checks_on_urls(urls: list) -> dict:
    """
    Run the existing XSS checker against every parameterized URL and
    combine the results into one dict shaped like check_xss()'s normal
    return value, tagging each entry with the URL it came from so
    findings from different pages don't get mixed together silently.
    """
    aggregated = {
        "target": urls,
        "tested_parameters": [],
        "vulnerable_parameters": [],
        "findings": [],
    }

    for url in urls:
        result = run_xss_check(url)
        if not result:
            continue

        for param in result.get("tested_parameters", []):
            aggregated["tested_parameters"].append(f"{url} :: {param}")

        for param in result.get("vulnerable_parameters", []):
            aggregated["vulnerable_parameters"].append(f"{url} :: {param}")

        for finding in result.get("findings", []):
            finding_with_url = dict(finding)
            finding_with_url["url"] = url
            aggregated["findings"].append(finding_with_url)

    return aggregated


def run_sqli_checks_on_urls(urls: list) -> dict:
    """Run the existing SQLi checker against every parameterized URL and combine results."""
    aggregated = {
        "target": urls,
        "tested_parameters": [],
        "findings": [],
    }

    for url in urls:
        result = run_sqli_check(url)
        if not result:
            continue

        for param in result.get("tested_parameters", []):
            aggregated["tested_parameters"].append(f"{url} :: {param}")

        for finding in result.get("findings", []):
            finding_with_url = dict(finding)
            finding_with_url["url"] = url
            aggregated["findings"].append(finding_with_url)

    return aggregated


def run_redirect_checks_on_urls(urls: list) -> dict:
    """Run the existing open-redirect checker against every parameterized URL and combine results."""
    aggregated = {
        "target": urls,
        "tested_parameters": [],
        "findings": [],
    }

    for url in urls:
        result = run_redirect_check(url)
        if not result:
            continue

        for param in result.get("tested_parameters", []):
            aggregated["tested_parameters"].append(f"{url} :: {param}")

        for finding in result.get("findings", []):
            finding_with_url = dict(finding)
            finding_with_url["url"] = url
            aggregated["findings"].append(finding_with_url)

    return aggregated


def format_endpoints_for_report(raw_endpoints: list) -> list:
    """
    Convert enum_engine's endpoint dicts into the shape
    expected by pdf_generator.
    """
    formatted = []

    for entry in raw_endpoints:
        formatted.append({
            "path": entry.get("endpoint"),
            "status": entry.get("status_code"),
            "url": entry.get("url"),
        })

    return formatted


def format_headers_for_report(header_result: dict) -> dict:
    """
    Convert header_checker's result into the shape expected
    by pdf_generator.
    """
    if not header_result:
        return {"missing": [], "present": {}}

    return {
        "missing": header_result.get("missing_headers", []),
        "present": header_result.get("info_headers", {}),
    }


def get_web_url(target: str, open_ports: list) -> str:
    """
    Build the URL for the first detected web service.

    Uses HTTP for ports 80 and 8080 and HTTPS for ports 443 and 8443.
    """
    web_ports = {
        80: "http",
        443: "https",
        8080: "http",
        8443: "https",
    }

    for result in open_ports:
        port = result.get("port")

        if port in web_ports:
            scheme = web_ports[port]

            if port in (80, 443):
                return f"{scheme}://{target}"

            return f"{scheme}://{target}:{port}"

    return ""


def resolve_web_url(web_url: str) -> str:
    """
    If web_url is plain HTTP and the site redirects to HTTPS on the same
    host, return the HTTPS base URL instead. Otherwise return web_url as-is.

    Doing this once, up front, means every later module uses the same URL
    and enumeration never sees a blanket HTTP -> HTTPS redirect.
    """
    if not web_url.startswith("http://"):
        return web_url

    request_headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(
            web_url, headers=request_headers, timeout=DEFAULT_HTTP_TIMEOUT,
            verify=False, allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        return web_url

    if response.status_code not in (301, 302, 307, 308):
        return web_url

    # Location can be relative, so resolve it against the URL we requested.
    redirect_url = urllib.parse.urljoin(web_url, response.headers.get("Location", ""))
    old = urllib.parse.urlparse(web_url)
    new = urllib.parse.urlparse(redirect_url)

    # Only switch for an HTTP -> HTTPS upgrade on the SAME host.
    if new.scheme != "https" or (new.hostname or "").lower() != (old.hostname or "").lower():
        return web_url

    https_base = f"https://{new.netloc}"

    # Make sure HTTPS actually answers before committing to it.
    try:
        requests.get(
            https_base, headers=request_headers, timeout=DEFAULT_HTTP_TIMEOUT,
            verify=False, allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        return web_url

    return https_base


def main():
    print_banner()
    args = parse_arguments()

    target = args.target
    run_ports = args.ports or args.all
    run_enum = args.enum or args.all
    run_headers = args.headers or args.all

    scan_results = {
        "target": target,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": [],
        "endpoints": [],
        "http_headers": {"missing": [], "present": {}},
        "cors": {},
        "technologies": {},
        "xss": {},
        "sqli": {},
        "redirect": {},
        "parameterized_urls": [],
    }

    # --- Port scan ---
    if run_ports:
        scan_results["open_ports"] = run_port_scan(target)

    # Find a web service from the open ports.
    web_url = get_web_url(target, scan_results["open_ports"])

    # If the HTTP service just redirects to HTTPS, use the HTTPS URL for
    # everything so all modules share one consistent base URL.
    if web_url:
        https_url = resolve_web_url(web_url)
        if https_url != web_url:
            log_info(f"{web_url} redirects to HTTPS, switching to {https_url}")
            web_url = https_url

    has_web_service = bool(web_url)

    if has_web_service:
        log_info(f"Web service detected at {web_url}")

    # --- Endpoint enumeration ---
    if run_enum:
        if has_web_service:
            raw_endpoints = run_enum_scan(web_url, args.wordlist)
            scan_results["endpoints"] = format_endpoints_for_report(raw_endpoints)
        else:
            log_warn("No web service detected, skipping endpoint enumeration.")

    # --- Header analysis ---
    if run_headers:
        if has_web_service:
            header_result = run_header_check(web_url)
            scan_results["http_headers"] = format_headers_for_report(header_result)
        else:
            log_warn("No web service detected, skipping HTTP header analysis.")

    # --- Web security checks ---
    if args.all:
        if not has_web_service:
            log_warn("No web service detected, skipping web security checks.")
        else:
            scan_results["cors"] = run_cors_check(web_url)

            scan_results["technologies"] = run_technology_detection(web_url)

            # --- Parameter discovery ---
            # The XSS / SQLi / open-redirect checkers need URLs that already
            # carry query parameters (e.g. /search.php?q=test), but endpoint
            # enumeration only finds bare pages (e.g. /search.php). This step
            # bridges the two by visiting each discovered endpoint and
            # pulling parameterized URLs out of its links and GET forms.
            log_info("Starting parameter discovery...")
            parameterized_urls = discover_parameters(web_url, scan_results["endpoints"])
            scan_results["parameterized_urls"] = parameterized_urls
            log_success(
                f"Parameter discovery complete. "
                f"{len(parameterized_urls)} parameterized URL(s) found."
            )

            if parameterized_urls:
                scan_results["xss"] = run_xss_checks_on_urls(parameterized_urls)
                scan_results["sqli"] = run_sqli_checks_on_urls(parameterized_urls)
                scan_results["redirect"] = run_redirect_checks_on_urls(parameterized_urls)
            else:
                # Important: leave scan_results["xss"]/["sqli"]/["redirect"]
                # at their empty defaults rather than calling the checkers
                # against the bare web_url. An empty result here means
                # "nothing was tested", not "tested and found clean".
                log_warn(
                    "No parameterized URLs found. "
                    "Skipping XSS/SQLi/open-redirect parameter checks."
                )

    # --- Report generation ---
    log_info("Generating PDF report...")

    try:
        output_path = generate_pdf(
            scan_results,
            output_filename=args.output
        )
        log_success(f"Report saved to: {output_path}")
    except Exception as exc:
        log_error(f"Failed to generate PDF report: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_warn("Scan interrupted by user. Exiting.")
        sys.exit(1)

