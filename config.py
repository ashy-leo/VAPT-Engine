TOP_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    143,
    443,
    445,
    8080,
    8081,
    8443
]

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

DEFAULT_SOCKET_TIMEOUT = 1.0
DEFAULT_HTTP_TIMEOUT = 5.0
DEFAULT_MAX_THREADS = 50

CRITICAL_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Generator"
]

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

PRIMARY_COLOR = "#1A365D"
SECONDARY_COLOR = "#2B6CB0"

# --- Settings for the CORS, technology, XSS, SQLi and redirect modules ---

# Fake website used to test whether a server trusts any Origin (CORS)
CORS_TEST_ORIGIN = "https://evil.example"

# HTML keywords that hint at a CMS or JavaScript framework
TECH_HTML_FINGERPRINTS = [
    "WordPress",
    "Joomla",
    "Drupal",
    "React",
    "Angular",
    "Vue"
]

# Payload used to test for reflected XSS
XSS_PAYLOAD = "<script>alert(1)</script>"

# Characters that may break a SQL query and trigger a database error
SQLI_PAYLOADS = ["'", '"', ")"]

# Text in a response that suggests a database error happened
SQLI_ERROR_INDICATORS = [
    "sql syntax",
    "mysql",
    "mysqli",
    "postgresql",
    "pg_query",
    "sqlite",
    "sqlstate",
    "oracle",
    "microsoft sql server"
]

# External URL injected into parameters to test for open redirects
REDIRECT_TEST_URL = "https://example.com"
                                      