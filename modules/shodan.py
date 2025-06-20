import sys
import os
import asyncio
import aiohttp
from aiohttp import ClientSession
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from colorama import Fore, init
import argparse
from urllib.parse import urlparse
import re
import ssl
import socket

sys.path.append(os.path.join(os.path.dirname(__file__), 'Util'))
init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 10
MAX_CONCURRENT_REQUESTS = 5

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import API_KEYS
from utils.util import resolve_to_ip  

SHODAN_API_KEY = API_KEYS.get("SHODAN_API_KEY")

def validate_api_key():
    if not SHODAN_API_KEY:
        console.print(Fore.RED + "[!] Shodan API key is not set. Please set it in config/settings.py.")
        return False
    return True

async def check_api_status():
    """Check API status and available credits"""
    try:
        async with ClientSession() as session:
            url = "https://api.shodan.io/api-info"
            params = {"key": SHODAN_API_KEY}
            
            async with session.get(url, params=params, timeout=DEFAULT_TIMEOUT) as response:
                if response.status == 200:
                    data = await response.json()
                    console.print(f"[cyan]Shodan Account Info:[/cyan]")
                    console.print(f"[cyan]├─ Plan: {data.get('plan', 'Unknown')}[/cyan]")
                    console.print(f"[cyan]├─ Query credits: {data.get('query_credits', 0)}[/cyan]")
                    console.print(f"[cyan]└─ Scan credits: {data.get('scan_credits', 0)}[/cyan]")
                    
                    if data.get('query_credits', 0) == 0:
                        console.print(f"[yellow][!] No query credits available. Using alternative methods...[/yellow]")
                    return data
                else:
                    console.print(f"[red][!] Failed to check API status: {response.status}[/red]")
                    return None
    except Exception as e:
        console.print(f"[red][!] Error checking API status: {e}[/red]")
        return None

async def get_basic_ip_info(session, ip):
    """Get basic IP information without using credits"""
    try:
        # Use ipinfo.io as fallback (free service)
        url = f"https://ipinfo.io/{ip}/json"
        async with session.get(url, timeout=DEFAULT_TIMEOUT) as response:
            if response.status == 200:
                data = await response.json()
                return {
                    "ip": ip,
                    "org": data.get('org', 'Unknown'),
                    "city": data.get('city', 'Unknown'),
                    "region": data.get('region', 'Unknown'),
                    "country": data.get('country', 'Unknown'),
                    "loc": data.get('loc', 'Unknown'),
                    "hostname": data.get('hostname', 'Unknown'),
                    "timezone": data.get('timezone', 'Unknown')
                }
    except Exception as e:
        console.print(f"[yellow][!] Could not get basic info for {ip}: {e}[/yellow]")
    
    return None

async def try_shodan_services_endpoint(session):
    """Try the services endpoint which might work with free accounts"""
    try:
        url = f"https://api.shodan.io/shodan/services"
        params = {"key": SHODAN_API_KEY}
        
        async with session.get(url, params=params, timeout=DEFAULT_TIMEOUT) as response:
            if response.status == 200:
                data = await response.json()
                console.print(f"[green][*] Available Shodan services retrieved[/green]")
                return data
            else:
                console.print(f"[yellow][!] Services endpoint returned: {response.status}[/yellow]")
    except Exception as e:
        console.print(f"[yellow][!] Services endpoint error: {e}[/yellow]")
    
    return None

async def enhanced_ip_scan(session, ip):
    """Enhanced IP scanning using multiple free sources"""
    console.print(f"[cyan][*] Scanning {ip} using multiple sources...[/cyan]")
    
    results = {
        "ip": ip,
        "basic_info": None,
        "ports": [],
        "services": [],
        "vulnerabilities": [],
        "error": None
    }
    
    # Get basic IP information
    basic_info = await get_basic_ip_info(session, ip)
    if basic_info:
        results["basic_info"] = basic_info
        console.print(f"[green][✓] Basic info retrieved for {ip}[/green]")
    
    # Try simple port scanning (common ports)
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
    open_ports = []
    
    for port in common_ports:
        try:
            # Quick connection test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # 1 second timeout
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                console.print(f"[green][✓] Port {port} is open on {ip}[/green]")
            sock.close()
        except Exception:
            pass
    
    results["ports"] = open_ports
    
    return results

def display_enhanced_results(results):
    """Display results from enhanced scanning"""
    if results.get("error"):
        console.print(Fore.RED + f"[!] {results['ip']}: {results['error']}")
        return
    
    ip = results["ip"]
    basic_info = results.get("basic_info", {})
    ports = results.get("ports", [])
    
    # Basic Info Table
    table = Table(title=f"IP Information for {ip}", box=box.ROUNDED)
    table.add_column("Field", style="cyan bold")
    table.add_column("Details", style="green bold")
    
    if basic_info:
        info_fields = {
            "IP Address": ip,
            "Organization": basic_info.get('org', 'Unknown'),
            "Location": f"{basic_info.get('city', 'Unknown')}, {basic_info.get('region', 'Unknown')}, {basic_info.get('country', 'Unknown')}",
            "Hostname": basic_info.get('hostname', 'Unknown'),
            "Timezone": basic_info.get('timezone', 'Unknown'),
            "Coordinates": basic_info.get('loc', 'Unknown')
        }
        
        for field, detail in info_fields.items():
            table.add_row(field, str(detail))
    else:
        table.add_row("IP Address", ip)
        table.add_row("Status", "Limited information available")
    
    console.print(table)
    
    # Ports Table
    if ports:
        ports_table = Table(title="Open Ports Detected", box=box.ROUNDED)
        ports_table.add_column("Port", style="cyan bold")
        ports_table.add_column("Common Service", style="green bold")
        
        port_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            993: "IMAPS", 995: "POP3S", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        
        for port in ports:
            service = port_services.get(port, "Unknown")
            ports_table.add_row(str(port), service)
        
        console.print(ports_table)
    else:
        console.print("[yellow][!] No common ports found open or accessible[/yellow]")

if not validate_api_key():
    sys.exit(1)

def banner():
    console.print(Fore.GREEN + """
=============================================
   Argus - Enhanced IP Reconnaissance
   (Free Account Compatible Version)
=============================================
""")

def clean_domain(domain):
    domain = domain.strip()
    parsed = urlparse(domain)
    return parsed.netloc if parsed.netloc else domain

def validate_ip(ip):
    pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    if not pattern.match(ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split('.'))

async def resolve_domain_async(domain):
    loop = asyncio.get_event_loop()
    ip = await loop.run_in_executor(None, resolve_to_ip, domain)
    if ip:
        return [ip]
    else:
        return []

async def main_async(inputs):
    banner()
    
    inputs_with_basic_info_count = 0
    inputs_with_ports_count = 0

    # Check API status
    api_info = await check_api_status()
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    recon_results = []

    async with ClientSession() as session:
        # Get Shodan services info (doesn't require credits)
        await try_shodan_services_endpoint(session)
        
        tasks = []
        for input_item in inputs:
            clean_input = clean_domain(input_item)
            if validate_ip(clean_input):
                tasks.append(enhanced_ip_scan(session, clean_input))
            else:
                resolved_ips = await resolve_domain_async(clean_input)
                if resolved_ips:
                    for ip in resolved_ips:
                        tasks.append(enhanced_ip_scan(session, ip))
                else:
                    console.print(Fore.RED + f"[!] Could not resolve domain: {clean_input}")
                    recon_results.append({"ip": clean_input, "error": "Resolution failed"})

        if tasks:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, console=console) as progress:
                task = progress.add_task("[cyan]Performing Enhanced IP Recon...", total=len(tasks))
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    recon_results.append(result)
                    display_enhanced_results(result)
                    progress.advance(task)

        actual_processed_inputs = len(recon_results) # Number of inputs for which scan was attempted
        successful_scans = 0
        for res in recon_results:
            if not res.get("error"): # Count scans that didn't have a top-level error.
                successful_scans +=1
                if res.get("basic_info"):
                    inputs_with_basic_info_count += 1
                if res.get("ports"):
                    inputs_with_ports_count += 1

        if actual_processed_inputs > 0:
            console.print(Fore.GREEN + f"[SUCCESS] IP reconnaissance completed for {actual_processed_inputs} target(s). Successfully scanned: {successful_scans}. Basic info found for {inputs_with_basic_info_count} target(s). Open ports detected for {inputs_with_ports_count} target(s).")
        else:
            # This case means no inputs were even attempted (e.g. all failed to resolve before creating tasks)
            console.print(Fore.YELLOW + f"[INFO] IP reconnaissance completed, but no targets were processed (e.g., all domains failed to resolve or no valid IPs provided).")
    
    if api_info and api_info.get('query_credits', 0) == 0:
        console.print(f"\n[yellow][💡] Tip: To get full Shodan data, you can:[/yellow]")
        console.print(f"[yellow]   • Tweet about Shodan to get 1 free credit[/yellow]")
        console.print(f"[yellow]   • Purchase credits at https://account.shodan.io/[/yellow]")
        console.print(f"[yellow]   • Apply for educational credits if you're a student[/yellow]")

def main(inputs):
    try:
        asyncio.run(main_async(inputs))
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
    except Exception as e:
        console.print(Fore.RED + f"[!] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Argus - Enhanced IP Reconnaissance (Free Account Compatible)")
    parser.add_argument('inputs', nargs='+', help='IP addresses or domains to analyze')
    args = parser.parse_args()
    main(args.inputs)