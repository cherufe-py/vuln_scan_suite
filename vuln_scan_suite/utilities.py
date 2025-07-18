"""
This module contains utilities for usage on this suite.
"""
import re
import socket
from typing import List


def handle_ports_argument(raw_ports) -> List[int]:
    """Converts string ports parameter into a list of integers."""
    if '-' in raw_ports:
        raw_ports = raw_ports.split('-')
        return list(range(int(raw_ports[0]), int(raw_ports[1]) + 1))
    if ',' in raw_ports:
        return [int(port) for port in raw_ports.split(',')]
    return [int(raw_ports)]


def handle_host_argument(raw_host) -> str:
    """Checks if the host is a valid IP,
    if not, it assumes the argument is a domain to convert into an IP."""
    return raw_host if is_a_valid_ipv4(raw_host) else socket.gethostbyname(raw_host)


def is_a_valid_ipv4(ip) -> bool:
    """Returns True if the ip passed as parameter is a valid IPv4."""
    return bool(re.fullmatch(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip))


def get_ttl_value_from_ping_response(value: str) -> int:
    """Returns the ttl value from a ping response passed as parameter."""
    pattern = r"(?i)ttl=\s*(\d+)"
    match = re.search(pattern, value)

    if match:
        return int(match.group(1))
    else:
        return -1
