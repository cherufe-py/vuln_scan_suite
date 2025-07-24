"""
This module contains the tools to scan ports for service info and vulnerabilities.
"""
import re
import socket
import ssl
from typing import List

from vuln_scan_suite.utilities import handle_ports_argument


def scan_ports_and_service_versions(host: str, ports: str):
    """Scans ports of the host."""
    ports = handle_ports_argument(ports)
    for port in ports:
        scan_port_and_service_version(host, port)


def scan_port_and_service_version(host: str, port: int):
    """Scans port of the host."""
    host_port = f"Host: {host} - Port: {port}"
    print(f"Starting scanning for - {host_port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)

    if port == 443:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ssock = context.wrap_socket(s, server_hostname=host)
        connection_socket = ssock
    else:
        connection_socket = s
    try:
        result = connection_socket.connect_ex((host, port))
    except ConnectionResetError:
        result = s.connect_ex((host, port))

    if result == 0:
        print(f"{host_port} - {port} is OPEN")
        get_banner_from_port(connection_socket, host, port)
    else:
        print(f"{host_port} - {port} is Closed/Filtered")

    s.close()


def get_banner_from_port(sock, host: str, port: int):
    """Gets the banner from port with service info."""
    match port:
        case 22:
            service_info = get_banner_from_port_22(sock)
        case 80 | 443:
            service_info = get_banner_from_port_http(sock, host)
        case 21:
            service_info = get_banner_from_port_21(sock)
        case _:
            service_info = get_banner_from_generic_port(sock, port)
    print(clean_service_version(service_info))


def get_banner_from_port_22(sock):
    """Gets banner from port 22."""
    try:
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        return banner
    except Exception as e:
        return "Undefined"


def get_banner_from_port_21(sock):
    """Gets banner from port 21."""
    try:
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        first_line = banner.split('\n')[0]
        return first_line
    except Exception as e:
        return "Undefined"


def get_banner_from_generic_port(sock, port: int):
    """Gets banner from general port."""
    try:
        banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
        return banner[:100] if len(banner) > 100 else banner
    except Exception as e:
        return "Undefined"


def get_banner_from_port_http(sock, host: str):
    """Gets banner from a http-like port.."""
    try:
        request = (f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
                   f"User-Agent: PythonBannerGrabber/1.0\r\n\r\n")
        sock.sendall(request.encode('utf-8'))
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
            if b"\r\n\r\n" in response:
                break

        response_str = response.decode('utf-8', errors='ignore')
        server_header = next((line for line in response_str.split('\n') if line.lower().startswith('server:')),
                             None)
        return server_header.strip() if server_header else "Undefined"
    except Exception as e:
        return "Undefined"


def clean_service_version(raw_service_version: str) -> List[str]:
    return re.sub(r"[ ()/\\_\-:]", ";", raw_service_version).split(";")
