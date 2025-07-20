"""
Use this file to run the suite.
"""
import os

from vuln_scan_suite.attack_surface_recognition import get_os, scan_ports


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
            case "0":
                print("Bye")
                break
            case _:
                pass



def print_main_menu_and_get_option():
    """Print main menu and returns the option selected."""
    print("=" * 20)
    print("=" * 20)
    print("Main menu")
    print("1- Perform attack surface recognition.")
    print("0- Exit Suite.")
    print("=" * 20)
    return input("Choose an option: ")


def print_get_host_and_ports_panel() -> dict:
    """Print panel to get host and ports from user."""
    ip = input("Provide an IP or Domain: ")
    ports = input("Provide ports to scan (keep blank to scan the commonest): ")
    return {"host": ip, "ports": ports}


def clear_screen():
    """Clears screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


if __name__ == "__main__":
    main()
