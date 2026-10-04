import socket
import concurrent.futures
from typing import List, Dict


def _grab_banner(ip_address: str, port: int, target: str) -> str:
    """
    Try to read a short banner from an open port by sending a
    basic HTTP request and reading whatever the service sends back.
    If anything goes wrong, just return an empty string -- a failed
    banner grab should never affect whether we report the port as open.
    """
    banner = ""
    try:
        # Open a brand new socket just for banner grabbing.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as banner_sock:
            banner_sock.settimeout(0.5)  # don't wait long for a reply
            banner_sock.connect((ip_address, port))

            request = f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()
            banner_sock.send(request)

            raw_data = banner_sock.recv(1024)
            text = raw_data.decode("utf-8", errors="ignore")

            # Keep only printable characters, then trim whitespace.
            printable_text = "".join(ch for ch in text if ch.isprintable() or ch in "\r\n")
            banner = printable_text.strip()
    except (socket.timeout, OSError):
        # Banner grabbing failed -- that's fine, we just leave it blank.
        banner = ""

    return banner


def _get_service_name(port: int) -> str:
    """
    Look up the common service name for a port (e.g. 80 -> 'http').
    If Python doesn't know it, just label it 'unknown'.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def _scan_single_port(ip_address: str, target: str, port: int, timeout: float) -> Dict:
    """
    Try to open a TCP connection to a single port.
    Returns a result dict if the port is open, or None if it's closed/unreachable.
    """
    # Create a fresh IPv4 TCP socket for this one port.
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.settimeout(timeout)

    try:
        # connect() will raise an exception if the port is closed,
        # filtered, or the connection times out.
        tcp_socket.connect((ip_address, port))

        # If we get here, the connection succeeded -- the port is open.
        service = _get_service_name(port)
        banner = _grab_banner(ip_address, port, target)

        return {
            "port": port,
            "state": "open",
            "service": service,
            "banner": banner,
        }
    except (socket.timeout, OSError):
        # Connection failed or timed out -- treat the port as closed
        # and simply skip it (return None).
        return None
    finally:
        # Always close the socket, whether we succeeded or failed.
        tcp_socket.close()


def scan_ports(
    target: str,
    ports: List[int],
    timeout: float = 1.0,
    max_threads: int = 50,
) -> List[Dict]:
    """
    Scan a list of TCP ports on `target` and return details about the open ones.

    Args:
        target: Hostname or IP address to scan.
        ports: List of port numbers to check.
        timeout: Seconds to wait per connection attempt.
        max_threads: How many ports to check at the same time.

    Returns:
        A list of dicts for each open port, sorted by port number.
    """
    # Turn the hostname into an IPv4 address first. If this fails,
    # there's no point trying to scan anything.
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Could not resolve target '{target}' to an IP address.")

    open_ports = []

    # A ThreadPoolExecutor lets us check many ports at once instead of
    # one at a time. Since each port check mostly just waits on the
    # network, running them in parallel threads makes the whole scan
    # much faster without needing complicated async code.
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit one scanning task per port and keep track of which
        # future belongs to which port.
        future_to_port = {
            executor.submit(_scan_single_port, ip_address, target, port, timeout): port
            for port in ports
        }

        # As each thread finishes, collect its result.
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    # Sort the results so ports come back in ascending numerical order.
    open_ports.sort(key=lambda item: item["port"])

    return open_ports
