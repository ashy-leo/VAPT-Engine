import socket

import concurrent.futures

from typing import List, Dict



def _grab_banner(ip_address: str, port: int, target: str) -> str:

    banner = ""

    try:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as banner_sock:
            banner_sock.settimeout(0.5)
            banner_sock.connect((ip_address, port))
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()
            banner_sock.send(request)
            raw_data = banner_sock.recv(1024)
            text = raw_data.decode("utf-8", errors="ignore")



            printable_text = "".join(ch for ch in text if ch.isprintable() or ch in "\r\n")
            banner = printable_text.strip()
    except (socket.timeout, OSError):
        banner = ""
    return banner



def _get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"



def _scan_single_port(ip_address: str, target: str, port: int, timeout: float) -> Dict:
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.settimeout(timeout)
    try:
        tcp_socket.connect((ip_address, port))
        service = _get_service_name(port)
        banner = _grab_banner(ip_address, port, target)
        return {
            "port": port,
            "state": "open",
            "service": service,
            "banner": banner,
        }
    except (socket.timeout, OSError):
        return None
    finally:
        tcp_socket.close()



def scan_ports(
    target: str,
    ports: List[int],
    timeout: float = 1.0,
    max_threads: int = 50,
) -> List[Dict]:

    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Could not resolve target '{target}' to an IP address.")
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:

        future_to_port = {
            executor.submit(_scan_single_port, ip_address, target, port, timeout): port
            for port in ports
        }

        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort(key=lambda item: item["port"])
    return open_ports