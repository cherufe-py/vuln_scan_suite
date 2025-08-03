"""
This module contains the tools for attack surface recognition,
"""
import platform
import socket
import subprocess

from tqdm import tqdm

from vuln_scan_suite.utilities import handle_ports_argument, get_ttl_value_from_ping_response


def scan_ports(host: str, ports: str):
    """Scans ports of the host."""
    ports = handle_ports_argument(ports)
    for port in tqdm(ports, desc="Scanning ports..."):
        scan_port(host, port)


def scan_port(host: str, port: int):
    """Scans port of the host."""
    host_port = f"Host: {host} - Port: {port}"
    tqdm.write(f"Starting scanning for - {host_port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)

    result = s.connect_ex((host, port))

    if result == 0:
        tqdm.write(f"{host_port} - {port} is OPEN")
    else:
        tqdm.write(f"{host_port} - {port} is Closed/Filtered")

    s.close()


def get_os(host: str):
    """Gets OS from IP. It uses ping command to guess the OS."""
    if "win" in platform.system().lower():
        ping_command = ["ping", host]
    else:
        ping_command = ["ping", "-c", "1", host]

    response = subprocess.run(ping_command, capture_output=True, text=True, check=True)
    ttl = get_ttl_value_from_ping_response(response.stdout)

    if ttl == -1:
        print("Host is not available.")
        return
    if ttl <= 64:
        so = "Linux/Unix"
    elif ttl <= 128:
        so = "Windows"
    else:
        so = "Unknown"

    print(f"TTL: {ttl} - Successful against SO: {so}")
