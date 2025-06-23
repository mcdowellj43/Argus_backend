import os
import sys
import dns.resolver
from rich.console import Console
from rich.table import Table
from colorama import Fore, init


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input, validate_domain  


init(autoreset=True)
console = Console()

def banner():
    print(Fore.GREEN + """
    =============================================
               Argus - DNS Records Check
    =============================================
    """)

def get_dns_records(domain):
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    try:
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                console.print(Fore.WHITE + f"[I] No {record_type} records found for {domain}.")
            except dns.resolver.NXDOMAIN:
                console.print(Fore.YELLOW + f"[I] Domain {domain} does not exist.")
                return None
            except dns.exception.DNSException as e:
                console.print(Fore.RED + f"[E] Error retrieving {record_type} records: {e}")
        return records
    except dns.exception.DNSException as e:
        console.print(Fore.RED + f"[E] Error retrieving DNS records for {domain}: {e}")
        return None

def display_dns_records(records):
    if records:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Record Type", style="cyan", justify="left")
        table.add_column("Record Value", style="green")

        for record_type, record_data in records.items():
            table.add_row(record_type, "\n".join(record_data))

        console.print(table)
    else:
        console.print(Fore.YELLOW + "[I] No DNS records to display.")

def main(target):
    banner()

    
    domain = clean_domain_input(target)

    if not validate_domain(domain):
        console.print(Fore.RED + "[E] Invalid domain format. Please check the domain and try again.")
        return

    console.print(Fore.WHITE + f"[I] Fetching DNS records for: {domain}")
    dns_records = get_dns_records(domain)

    if dns_records:
        display_dns_records(dns_records)
        num_record_types = len(dns_records)
        console.print(Fore.GREEN + f"[I] Found {num_record_types} types of DNS records for {domain}.")
    else:
        # This handles cases where dns_records is None (e.g., domain doesn't exist)
        # or dns_records is an empty dictionary (e.g. no records found after checking all types)
        console.print(Fore.YELLOW + f"[I] No DNS records found for {domain}.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        console.print(Fore.RED + "[E] No target provided. Please pass a domain.")
        sys.exit(1)
