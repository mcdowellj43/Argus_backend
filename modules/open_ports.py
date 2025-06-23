import os
import sys
import nmap
from rich.console import Console
from rich.table import Table
from colorama import Fore, init

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
              Argus - Open Ports Scanning
    =============================================
    """)

def scan_ports(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, '1-1024')  
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                open_ports.extend(nm[host][proto].keys())
        return open_ports
    except Exception as e:
        console.print(Fore.RED + f"[E] Error scanning ports: {e}")
        return None

def display_ports(open_ports):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Open Ports", style="cyan", justify="left")

    for port in open_ports:
        table.add_row(str(port))

    console.print(table)

def main(target):
    banner()
    console.print(Fore.WHITE + f"[I] Scanning open ports for: {target}")
    open_ports = scan_ports(target)
    if open_ports:
        display_ports(open_ports)
        num_open_ports = len(open_ports)
        console.print(Fore.GREEN + f"[I] Found {num_open_ports} open port(s) for {target}.")
    else:
        console.print(Fore.YELLOW + f"[I] No open ports found for {target}.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            main(target)
        except KeyboardInterrupt:
            console.print(Fore.RED + "\n[E] Process interrupted by user.")
            sys.exit(1)
    else:
        console.print(Fore.RED + "[E] No target provided. Please pass an IP address.")
        sys.exit(1)
