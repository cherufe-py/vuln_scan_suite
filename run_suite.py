"""
Use this file to run the suite.
"""
import os

from vuln_scan_suite.attack_surface_recognition import get_os, scan_ports
from vuln_scan_suite.constants import COMMON_PORTS
from vuln_scan_suite.cve_searcher import CveSearcher
from vuln_scan_suite.services_and_vulnerabilities import scan_ports_and_service_versions
from vuln_scan_suite.sqli_scanner import scan_sqli
from vuln_scan_suite.xss_scanner_for_dynamic_page import scan_xss_for_dynamic_page
from vuln_scan_suite.xss_scanner_for_static_page import scan_xss_for_static_page


def main():
    """Main function."""
    while True:
        option = print_main_menu_and_get_option()
        clear_screen()
        match option:
            case "1":
                host_and_ports = print_get_host_and_ports_panel()
                clear_screen()
                get_os(host_and_ports.get('host'))
                scan_ports(*host_and_ports.values())
                input("Results on screen. Press any key to continue...")
                clear_screen()
            case "2":
                host_and_ports = print_get_host_and_ports_panel()
                scanned_ports = scan_ports_and_service_versions(*host_and_ports.values())
                cve_searcher = CveSearcher()
                for scanned_port in scanned_ports:
                    print("For Scanned Port: ", scanned_port.get("port"))
                    print(f"It got the following service version: {' '.join(scanned_port.get('service_version'))}")
                    cves = cve_searcher.perform_clean_search_by_keywords(scanned_port.get('service_version'))
                    for index, cve in enumerate(cves):
                        desc = cve.get("description", "")
                        short_desc = desc if len(desc) <= 100 else desc[:100] + "..."
                        print(f"{index} - CVE link: {cve.get('link')}\nDescription: {short_desc}")
                input("Results on screen. Press any key to continue...")
                clear_screen()
            case "3":
                clear_screen()
                ip = input("Provide an IP or Domain: ")
                print("Scanning for XSS vulnerabilities for static pages.")
                static_found_xss = scan_xss_for_static_page(ip)
                if static_found_xss:
                    print("Some XSS vulnerabilities were found.")
                    dynamic_found_xss = []
                    option = input("Do you want to scan for XSS vulnerabilities for dynamic pages? (y/n)")
                    if option == "y":
                        dynamic_found_xss = scan_xss_for_dynamic_page(ip)
                else:
                    print("Scanning for XSS vulnerabilities for dynamic pages.")
                    dynamic_found_xss = scan_xss_for_dynamic_page(ip)
                if static_found_xss:
                    print(f"XSS vulnerabilities for static pages were found."
                          f"\nVulnerabilities:\n{'\n'.join(static_found_xss)}")
                if dynamic_found_xss:
                    print(f"XSS vulnerabilities for dynamic pages were found."
                          f"\nVulnerabilities:\n{'\n'.join(dynamic_found_xss)}")
                input("Scan Done. Press any key to continue...")
                clear_screen()
            case "4":
                url = input("Provide the URL where the form displayed: ")
                username = input("Provide username field name: ")
                password = input("Provide password field name: ")
                found_sqli = scan_sqli(url, username, password)
                clear_screen()
                if found_sqli:
                    print(f"For URL {url} a SQLi vulnerability was found: {found_sqli}")
                else:
                    print(f"For URL {url} has no SQLi vulnerabilities.")
                input("Scan Done. Press any key to continue...")
            case "0":
                print("Bye")
                break
            case _:
                input("Provide a valid option.")
                pass


def print_main_menu_and_get_option():
    """Print main menu and returns the option selected."""
    print("=" * 20)
    print("=" * 20)
    print("Main menu")
    print("1- Perform attack surface recognition.")
    print("2- Get Services and Vulnerabilities.")
    print("3- Scan for XSS Vulnerabilities.")
    print("4- Scan for SQLi Vulnerabilities.")
    print("0- Exit Suite.")
    print("=" * 20)
    return input("Choose an option: ")


def print_get_host_and_ports_panel() -> dict:
    """Print panel to get host and ports from user."""
    ip = input("Provide an IP or Domain: ")
    ports = input("Provide ports to scan (keep blank to scan the commonest): ")
    ports = ports if ports else COMMON_PORTS
    return {"host": ip, "ports": ports}


def clear_screen():
    """Clears screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


if __name__ == "__main__":
    main()
