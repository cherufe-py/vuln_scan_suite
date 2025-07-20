"""
This module contains the tools to scan ports for service info and vulnerabilities.
"""
import socket
import ssl

from tqdm import tqdm

from vuln_scan_suite.utilities import handle_ports_argument


def scan_ports_and_service_versions(host: str, ports: str):
    """Scans ports of the host."""
    ports = handle_ports_argument(ports)
    for port in tqdm(ports, desc="Scanning..."):
        scan_port_and_service_version(host, port)


def scan_port_and_service_version(host: str, port: int):
    """Scans port of the host."""
    host_port = f"Host: {host} - Port: {port}"
    tqdm.write(f"Starting scanning for - {host_port}")
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
        tqdm.write(f"{host_port} - {port} is OPEN")
        get_banner_from_port(connection_socket, host, port)
    else:
        tqdm.write(f"{host_port} - {port} is Closed/Filtered")

    s.close()


def get_banner_from_port(sock, host: str, port: int):
    """Gets the banner from port with service info."""
    match port:
        case 22:
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                service_info = f"SSH: {banner}"
            except Exception as e:
                service_info = f"SSH: Error - {e}"
        case 80:
            try:
                request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: PythonBannerGrabber/1.0\r\n\r\n"
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
                service_info = f"HTTP: {server_header.strip()}" if server_header else "HTTP: No 'Server' header found."
            except Exception as e:
                service_info = f"HTTP: Error - {e}"
        case 443:
            try:
                request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: PythonBannerGrabber/1.0\r\n\r\n"
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
                service_info = f"HTTPS: {server_header.strip()}" if server_header else "HTTPS: No 'Server' header found."
            except Exception as e:
                service_info = f"HTTPS: Error - {e}"
        case 21:
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                first_line = banner.split('\n')[0]
                service_info = f"FTP: {first_line}"
            except Exception as e:
                service_info = f"FTP: Error - {e}"
        case _:
            try:
                banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
                service_info = f"GENERIC ({port}): {banner[:100]}..." if len(
                    banner) > 100 else f"GENERIC ({port}): {banner}"
            except Exception as e:
                service_info = f"GENERIC ({port}): Error - {e}"
    print(service_info)
