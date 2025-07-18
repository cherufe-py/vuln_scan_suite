import argparse

from vuln_scan_suite.attack_surface_recognition import scan_ports


def main():
    parser = argparse.ArgumentParser(
        description='args'
    )

    parser.add_argument(
        '--host',
        type=str,
        help='Host to scant',
        default='192.168.1.183'
    )

    parser.add_argument(
        '--ports',
        type=str,
        help='Ports to scan. It receives elements divided by comma ("80, 22") or hyphen for range ("20-9000").',
        default="80,22"
    )

    args = parser.parse_args()

    scan_ports(args.host, args.ports)


if __name__ == "__main__":
    main()
