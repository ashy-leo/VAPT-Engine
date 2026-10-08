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


CORS_TEST_ORIGIN = "https://evil.example"

TECH_HTML_FINGERPRINTS = [
    "WordPress",
    "Joomla",
    "Drupal",
    "React",
    "Angular",
    "Vue"
]


XSS_PAYLOAD = "<script>alert(1)</script>"

SQLI_PAYLOADS = ["'", '"', ")"]

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

REDIRECT_TEST_URL = "https://example.com"
                                      