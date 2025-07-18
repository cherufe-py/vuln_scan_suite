import socket

from tqdm import tqdm

from vuln_scan_suite.utilities import handle_ports_argument


def scan_ports(host, ports):
    """Scans ports of the host."""
    ports = handle_ports_argument(ports)
    for port in tqdm(ports, desc="Scanning..."):
        scan_port(host, port)


def scan_port(host, port):
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
