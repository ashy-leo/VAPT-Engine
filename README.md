# VAPT-Engine

A Python command-line tool that automates basic reconnaissance and vulnerability checks, and saves the results as a PDF report.

## About

VAPT-Engine is a student project built to learn how common security checks work by implementing them from scratch. It scans a target for open ports, identifies a web service, enumerates endpoints, inspects HTTP headers, and runs a few simple web checks (CORS, XSS, SQL injection, and open redirect). Everything is collected into a single PDF report.

**Note:** The checks are intentionally simple, and their results are hints for manual follow-up, not confirmed vulnerabilities.

## Features

* **Port scanning:** Multithreaded TCP connect scan of a fixed list of common ports, with service names and basic banner grabbing.
* **Endpoint enumeration:** Wordlist-based discovery of paths, reporting HTTP status codes 200, 301, 302, 307, 401, and 403.
* **HTTP header analysis:** Reports missing security headers and headers that reveal server details.
* **CORS check:** Flags a missing `Access-Control-Allow-Origin` header, a wildcard value, or a reflected Origin.
* **Technology detection:** Identifies possible technologies from response headers and HTML keywords, including WordPress, Joomla, Drupal, React, Angular, and Vue.
* **Parameter discovery:** Crawls discovered pages for GET parameters in links and forms.
* **Basic XSS check:** Tests whether a script payload is reflected in the response.
* **Basic SQL injection check:** Sends quote and parenthesis characters and looks for database error messages.
* **Open redirect check:** Tests whether a parameter value is used as a redirect target.
* **PDF reporting:** Generates a PDF report and provides colored console logging.


## Project Structure

```text
VAPT-ENGINE/
├── main.py
├── config.py
├── core/
│   ├── cors_checker.py
│   ├── enum_engine.py
│   ├── header_checker.py
│   ├── parameter_discovery.py
│   ├── port_scanner.py
│   ├── redirect_checker.py
│   ├── sqli_checker.py
│   ├── tech_detector.py
│   └── xss_checker.py
├── reporting/
│   └── pdf_generator.py
└── utils/
    └── logger.py
```
* **`main.py`:** Parses arguments, calls the modules in order, and passes the combined results to the report generator.
* **`core/`:** Contains one module for each security check.
* **`reporting/`:** Converts the collected results into a PDF report.
* **`utils/`:** Contains logging helpers.
* **`config.py`:** Stores the default settings.


## Working Flow

`Target → main.py → Port scan → Web service detection → Discovery and checks → PDF report`

* The port scan checks the ports listed in `config.py`.
* The first open web port (80, 443, 8080, or 8443) is used to build the base URL. If HTTP redirects to HTTPS on the same host, the HTTPS URL is used for subsequent steps.
* Endpoint enumeration and header analysis run against that URL. In a full scan, CORS, technology detection, parameter discovery, XSS, SQL injection, and open redirect checks are also performed.
* All results are written to a PDF report.
* If no web service is found, the web-based steps are skipped with a warning.

## Technologies Used

* **Python 3**
* **`requests` and `urllib3`:** HTTP requests
* **`socket` and `concurrent.futures`:** Port scanning and multithreading
* **`argparse`, `re`, and `urllib.parse`:** CLI arguments, pattern matching, and URL handling
* **`reportlab`:** PDF generation
* **`rich`:** Console output

## Installation

Tested setup steps for Kali Linux and other Linux distributions:

1. Clone the repository:

   ```bash
   git clone <repository-url>
   ```

2. Navigate to the project directory:

   ```bash
   cd VAPT-ENGINE
   ```

3. Create a virtual environment:

   ```bash
   python3 -m venv venv
   ```

4. Activate the virtual environment:

   ```bash
   source venv/bin/activate
   ```

5. Install the dependencies:

   ```bash
   pip install requests reportlab rich
   ```

Endpoint enumeration reads a wordlist. The default is `/usr/share/wordlists/dirb/common.txt` on Kali. A different file can be provided using `--wordlist`.

## Usage

Run commands from the project root. Provide the target as a hostname or IP address without `http://` or `https://`.

**Full scan:**

```bash
python3 main.py -t example.com --all
```

**Full scan (default if no scan flag is given):**

```bash
python3 main.py -t example.com
```

**Port scan only:**

```bash
python3 main.py -t 192.168.1.10 --ports
```

**Ports, endpoint enumeration, and header analysis:**

```bash
python3 main.py -t example.com --ports --enum --headers
```

**Custom wordlist and report name:**

```bash
python3 main.py -t example.com --all --wordlist /path/to/wordlist.txt -o report.pdf
```

## Options

| Option           | Description                                                                                                             |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `-t`, `--target` | Target hostname or IP address (required)                                                                                |
| `--ports`        | Run the TCP port scan                                                                                                   |
| `--enum`         | Run endpoint enumeration                                                                                                |
| `--headers`      | Run HTTP header analysis                                                                                                |
| `--all`          | Run all checks, including CORS, technology detection, parameter discovery, XSS, SQL injection, and open redirect checks |
| `--wordlist`     | Wordlist path for enumeration                                                                                           |
| `-o`, `--output` | PDF filename (default: `vapt_report.pdf`)                                                                               |

The web service is detected from the port scan. There is no command-line option for choosing ports; the list can be changed in `config.py`.

## Output

The tool saves a PDF report containing:

* Open ports, services, and banners
* Missing and information-leaking HTTP headers
* Discovered endpoints with status codes
* CORS results
* Detected technologies
* XSS, SQL injection, and open redirect results

If parameter discovery finds no parameterized URLs, the XSS, SQL injection, and open redirect checks are skipped.

## Limitations

* Parameter discovery only follows GET links and forms. It does not perform authenticated crawling, send POST requests, or analyze JavaScript. Crawl depth is limited to 2.
* XSS detection only checks whether one payload is reflected. It does not confirm that the script would execute in a browser.
* SQL injection detection only looks for common database error text. It cannot detect blind or error-free injection.
* Open redirect detection only flags an exact match of the injected URL in the `Location` header.
* Technology detection uses keyword matching and may produce false positives or miss technologies.
* Only a fixed list of common ports is scanned, and IPv6 is not supported.
* HTTPS certificate verification is disabled so self-signed targets can be scanned.
* Results are indicators for manual review, not confirmed vulnerabilities.

## Legal and Ethical Disclaimer

This tool sends test requests and payloads to the target. Use it only on systems you own or have explicit written permission to test. Unauthorized scanning or testing may be illegal. The author accepts no responsibility for misuse or damage caused by this tool.
