#!/usr/bin/env python3
"""
Argus - Advanced Data Leak Checker
Uses HaveIBeenPwned API to check for real data breaches
"""

import sys
import os
import requests
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from colorama import Fore, init
import argparse
import threading
import queue
import time
import json
from datetime import datetime
from collections import deque

# Set the API key in environment for the script
os.environ['HIBP_API_KEY'] = "46d0dd6674544e2286da27176198b5ea"

init(autoreset=True)
console = Console()
lock = threading.Lock()

# HaveIBeenPwned API Configuration
HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
HIBP_RATE_LIMIT = 6.0  # Seconds between requests (10 requests per minute = 6 seconds between requests)
HIBP_REQUESTS_PER_MINUTE = 10
HIBP_REQUEST_WINDOW = 60  # seconds

# Rate limiting tracker
request_times = deque()
rate_limit_lock = threading.Lock()

def get_api_key():
    """Get API key from environment or fallback"""
    api_key = os.getenv('HIBP_API_KEY') or os.getenv('HAVEIBEENPWNED_API_KEY')
    
    if not api_key:
        console.print(Fore.RED + "[!] No API key found. This shouldn't happen with hardcoded key.")
        return None
    
    return api_key

def validate_api_key(api_key):
    """Validate API key by making a test request"""
    if not api_key or len(api_key) < 20:  # HIBP API keys are typically longer
        return False, "API key appears to be too short or empty"
    
    # Test with a simple request
    test_url = f"{HIBP_BASE_URL}/breachedaccount/test@example.com"
    headers = {
        'hibp-api-key': api_key,
        'User-Agent': 'ArgusDataLeakChecker/2.0',
        'Accept': 'application/json'
    }
    
    try:
        response = requests.get(test_url, headers=headers, timeout=10)
        if response.status_code in [200, 404]:  # Both are valid responses
            return True, "API key validated successfully"
        elif response.status_code == 401:
            return False, "Invalid API key - authentication failed"
        elif response.status_code == 429:
            return True, "API key valid but rate limited (this is normal)"
        else:
            return False, f"Unexpected response: HTTP {response.status_code}"
    except requests.RequestException as e:
        return False, f"Network error during validation: {e}"

def banner():
    console.print(Fore.GREEN + """
    =============================================
           Argus - Advanced Data Leak Checker
    =============================================
    """, highlight=False)

def clean_domain_input(domain: str) -> str:
    """Clean and normalize domain input"""
    domain = domain.strip()
    parsed_url = urlparse(domain if domain.startswith(('http://', 'https://')) else f'http://{domain}')
    if parsed_url.netloc:
        return parsed_url.netloc
    else:
        return domain

def get_email_addresses(domain):
    """Generate common email patterns for the domain"""
    common_usernames = [
        'admin', 'administrator', 'contact', 'info', 'support', 'sales', 
        'webmaster', 'postmaster', 'security', 'noreply', 'no-reply',
        'help', 'service', 'abuse', 'privacy', 'legal', 'marketing'
    ]
    emails = [f"{username}@{domain}" for username in common_usernames]
    return emails

def wait_for_rate_limit():
    """Ensure we don't exceed 10 requests per minute"""
    with rate_limit_lock:
        current_time = time.time()
        
        # Remove requests older than 1 minute
        while request_times and current_time - request_times[0] > HIBP_REQUEST_WINDOW:
            request_times.popleft()
        
        # If we have 10 requests in the last minute, wait
        if len(request_times) >= HIBP_REQUESTS_PER_MINUTE:
            wait_time = HIBP_REQUEST_WINDOW - (current_time - request_times[0]) + 1
            with lock:
                console.print(Fore.YELLOW + f"[!] Rate limit reached. Waiting {wait_time:.1f} seconds...")
            time.sleep(wait_time)
            
            # Clean up old requests again after waiting
            current_time = time.time()
            while request_times and current_time - request_times[0] > HIBP_REQUEST_WINDOW:
                request_times.popleft()
        
        # Record this request
        request_times.append(current_time)

def check_email_breaches(email, session, api_key):
    """Check email against HaveIBeenPwned API with rate limiting"""
    
    # Wait for rate limit before making request
    wait_for_rate_limit()
    
    url = f"{HIBP_BASE_URL}/breachedaccount/{email}"
    headers = {
        'hibp-api-key': api_key,
        'User-Agent': 'ArgusDataLeakChecker/2.0',
        'Accept': 'application/json'
    }
    
    try:
        response = session.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            # Breaches found
            breaches_data = response.json()
            return parse_hibp_breaches(breaches_data)
        elif response.status_code == 404:
            # No breaches found (this is good!)
            return []
        elif response.status_code == 401:
            with lock:
                console.print(Fore.RED + f"[!] API authentication failed. Check API key.")
            return None
        elif response.status_code == 429:
            with lock:
                console.print(Fore.YELLOW + f"[!] Rate limited despite precautions. Waiting 60 seconds...")
            time.sleep(60)  # Wait a full minute and retry
            return check_email_breaches(email, session, api_key)
        else:
            with lock:
                console.print(Fore.RED + f"[!] Error checking {email}: HTTP {response.status_code}")
            return None
            
    except requests.RequestException as e:
        with lock:
            console.print(Fore.RED + f"[!] Network error checking {email}: {e}")
        return None
    except json.JSONDecodeError as e:
        with lock:
            console.print(Fore.RED + f"[!] Invalid JSON response for {email}: {e}")
        return None

def parse_hibp_breaches(breaches_data):
    """Parse HaveIBeenPwned breach data into standardized format"""
    if not breaches_data:
        return []
    
    parsed_breaches = []
    for breach in breaches_data:
        # Parse the breach date
        breach_date = breach.get('BreachDate', 'Unknown')
        if breach_date != 'Unknown':
            try:
                # Convert YYYY-MM-DD to more readable format
                date_obj = datetime.strptime(breach_date, '%Y-%m-%d')
                breach_date = date_obj.strftime('%B %d, %Y')
            except ValueError:
                pass  # Keep original if parsing fails
        
        # Extract data classes
        data_classes = breach.get('DataClasses', [])
        if isinstance(data_classes, list):
            data_classes_str = ', '.join(data_classes)
        else:
            data_classes_str = str(data_classes)
        
        # Determine severity based on data types
        severity = calculate_breach_severity(data_classes)
        
        parsed_breach = {
            'Name': breach.get('Name', 'Unknown Breach'),
            'Date': breach_date,
            'DataClasses': data_classes_str,
            'PwnCount': breach.get('PwnCount', 0),
            'Verified': breach.get('IsVerified', False),
            'Sensitive': breach.get('IsSensitive', False),
            'Retired': breach.get('IsRetired', False),
            'Description': breach.get('Description', ''),
            'Severity': severity
        }
        parsed_breaches.append(parsed_breach)
    
    # Sort by severity (high to low) then by date (recent first)
    parsed_breaches.sort(key=lambda x: (
        -x['Severity'], 
        -x['PwnCount']
    ))
    
    return parsed_breaches

def calculate_breach_severity(data_classes):
    """Calculate breach severity based on compromised data types"""
    if not data_classes:
        return 1
    
    severity_weights = {
        'passwords': 5,
        'password': 5,
        'credit cards': 5,
        'bank account': 5,
        'ssn': 5,
        'social security': 5,
        'financial': 4,
        'payment': 4,
        'personal health': 4,
        'private messages': 3,
        'security questions': 3,
        'phone numbers': 2,
        'addresses': 2,
        'dates of birth': 2,
        'names': 1,
        'email addresses': 1,
        'usernames': 1
    }
    
    max_severity = 0
    data_lower = [item.lower() for item in data_classes] if isinstance(data_classes, list) else [str(data_classes).lower()]
    
    for data_type in data_lower:
        for sensitive_type, weight in severity_weights.items():
            if sensitive_type in data_type:
                max_severity = max(max_severity, weight)
    
    return max_severity if max_severity > 0 else 1

def get_severity_color(severity):
    """Get color for severity level"""
    if severity >= 5:
        return "red"
    elif severity >= 3:
        return "yellow"
    elif severity >= 2:
        return "cyan"
    else:
        return "green"

def display_breaches(email, breaches):
    """Display breach information in a formatted table"""
    if not breaches:
        with lock:
            console.print(Fore.GREEN + f"[+] No breaches found for {email}")
        return
    
    # Create summary
    total_breaches = len(breaches)
    high_severity = len([b for b in breaches if b['Severity'] >= 4])
    verified_breaches = len([b for b in breaches if b['Verified']])
    total_accounts = sum(b['PwnCount'] for b in breaches)
    
    with lock:
        console.print(f"\n{Fore.RED}[!] BREACHES FOUND for {email}")
        console.print(f"{Fore.WHITE}    Total Breaches: {total_breaches}")
        console.print(f"{Fore.WHITE}    High Severity: {high_severity}")
        console.print(f"{Fore.WHITE}    Verified: {verified_breaches}")
        console.print(f"{Fore.WHITE}    Total Accounts Affected: {total_accounts:,}")
    
    # Create detailed table
    table = Table(
        title=f"Detailed Breach Information for {email}", 
        show_header=True, 
        header_style="bold magenta", 
        box=box.ROUNDED,
        title_style="bold red"
    )
    table.add_column("Breach Name", style="cyan", justify="left", min_width=15)
    table.add_column("Date", style="white", justify="center", min_width=12)
    table.add_column("Severity", style="yellow", justify="center", min_width=8)
    table.add_column("Affected", style="blue", justify="right", min_width=10)
    table.add_column("Data Compromised", style="yellow", justify="left", min_width=20)
    table.add_column("Verified", style="green", justify="center", min_width=8)
    
    for breach in breaches:
        name = breach.get('Name', 'N/A')
        breach_date = breach.get('Date', 'N/A')
        severity = breach.get('Severity', 1)
        severity_color = get_severity_color(severity)
        severity_text = f"[{severity_color}]{severity}/5[/{severity_color}]"
        
        pwn_count = breach.get('PwnCount', 0)
        pwn_count_str = f"{pwn_count:,}" if pwn_count > 0 else "Unknown"
        
        data_classes = breach.get('DataClasses', 'Unknown')
        # Truncate if too long
        if len(data_classes) > 30:
            data_classes = data_classes[:27] + "..."
        
        verified = "✓" if breach.get('Verified', False) else "✗"
        verified_color = "green" if breach.get('Verified', False) else "red"
        verified_text = f"[{verified_color}]{verified}[/{verified_color}]"
        
        table.add_row(
            name, 
            breach_date, 
            severity_text,
            pwn_count_str,
            data_classes, 
            verified_text
        )
    
    with lock:
        console.print(table)

def worker(email_queue, session, stats, api_key):
    """Worker thread for processing emails"""
    while True:
        email = email_queue.get()
        if email is None:
            break
        
        with lock:
            console.print(Fore.YELLOW + f"[*] Checking {email}...")
        
        breaches = check_email_breaches(email, session, api_key)
        
        if breaches is None:
            stats['errors'] += 1
            email_queue.task_done()
            continue
        
        if breaches:
            stats['breached'] += 1
            stats['total_breaches'] += len(breaches)
        else:
            stats['clean'] += 1
        
        display_breaches(email, breaches)
        email_queue.task_done()

def display_final_summary(stats, start_time):
    """Display final scan summary"""
    end_time = time.time()
    duration = end_time - start_time
    
    console.print(f"\n{Fore.CYAN}{'='*60}")
    console.print(f"{Fore.CYAN}                    SCAN SUMMARY")
    console.print(f"{Fore.CYAN}{'='*60}")
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Metric", style="cyan", justify="left")
    table.add_column("Value", style="white", justify="left")
    
    table.add_row("Total Emails Checked:", str(stats['total']))
    table.add_row("Clean (No Breaches):", f"[green]{stats['clean']}[/green]")
    table.add_row("Compromised Emails:", f"[red]{stats['breached']}[/red]")
    table.add_row("Total Breaches Found:", f"[yellow]{stats['total_breaches']}[/yellow]")
    table.add_row("Errors:", f"[red]{stats['errors']}[/red]")
    table.add_row("Scan Duration:", f"{duration:.1f} seconds")
    
    console.print(table)
    
    # Risk assessment
    if stats['breached'] > 0:
        risk_level = "HIGH" if stats['breached'] > 2 else "MEDIUM"
        console.print(f"\n{Fore.RED}[!] RISK LEVEL: {risk_level}")
        console.print(f"{Fore.WHITE}    Immediate action recommended for compromised accounts.")
    else:
        console.print(f"\n{Fore.GREEN}[+] RISK LEVEL: LOW")
        console.print(f"{Fore.WHITE}    No known breaches found for this domain.")

def main():
    banner()
    parser = argparse.ArgumentParser(description='Argus - Advanced Data Leak Checker using HaveIBeenPwned')
    parser.add_argument('domain', help='Domain to check for data leaks')
    parser.add_argument('--email', action='append', help='Specific email addresses to check (can be used multiple times)')
    parser.add_argument('--threads', type=int, default=1, help='Number of concurrent threads (default: 1, FORCED to 1 due to rate limits)')
    parser.add_argument('--api-key', help='HaveIBeenPwned API key (overrides environment variable)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--limit', type=int, help='Limit number of emails to check (useful for testing)')
    args = parser.parse_args()

    # Force single thread due to rate limiting
    if args.threads > 1:
        console.print(Fore.YELLOW + f"[!] Warning: API rate limit is 10/minute. Forcing single thread to prevent issues.")
        args.threads = 1

    # Get API key (priority: command line > environment)
    api_key = args.api_key or get_api_key()
    if not api_key:
        console.print(Fore.RED + "[!] No API key provided. Exiting.")
        sys.exit(1)

    # Validate API key
    console.print(Fore.WHITE + "[*] Validating API key...")
    is_valid, message = validate_api_key(api_key)
    if not is_valid:
        console.print(Fore.RED + f"[!] API key validation failed: {message}")
        sys.exit(1)
    else:
        console.print(Fore.GREEN + f"[+] {message}")

    domain = clean_domain_input(args.domain)
    start_time = time.time()

    if args.email:
        emails = args.email
    else:
        emails = get_email_addresses(domain)

    # Apply limit if specified
    if args.limit and args.limit < len(emails):
        emails = emails[:args.limit]
        console.print(Fore.YELLOW + f"[!] Limited to first {args.limit} emails for testing")

    # Calculate estimated time
    estimated_time = len(emails) * 6  # 6 seconds per email minimum
    estimated_minutes = estimated_time / 60

    console.print(Fore.WHITE + f"[*] Checking data leaks for domain: [bold cyan]{domain}[/bold cyan]")
    console.print(Fore.WHITE + f"[*] Emails to check: {len(emails)}")
    console.print(Fore.WHITE + f"[*] Rate limit: 10 requests per minute")
    console.print(Fore.WHITE + f"[*] Estimated time: {estimated_minutes:.1f} minutes")
    console.print(Fore.WHITE + f"[*] Using {args.threads} thread (forced due to rate limits)")
    
    if args.verbose:
        console.print(Fore.WHITE + f"[*] Email list: {', '.join(emails)}")

    if len(emails) > 10:
        console.print(Fore.YELLOW + f"[!] This will take approximately {estimated_minutes:.1f} minutes due to API rate limits.")
        console.print(Fore.YELLOW + f"[!] Consider using --limit to test with fewer emails first.")

    # Initialize statistics
    stats = {
        'total': len(emails),
        'clean': 0,
        'breached': 0,
        'total_breaches': 0,
        'errors': 0
    }

    email_queue = queue.Queue()
    session = requests.Session()

    # Start worker threads
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(email_queue, session, stats, api_key))
        t.start()
        threads.append(t)

    # Enqueue emails
    for email in emails:
        email_queue.put(email)

    # Wait for all emails to be processed
    email_queue.join()

    # Stop workers
    for _ in range(args.threads):
        email_queue.put(None)
    for t in threads:
        t.join()

    # Display final summary
    display_final_summary(stats, start_time)
    
    console.print(Fore.CYAN + "\n[*] Data leak check completed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
    except Exception as e:
        console.print(Fore.RED + f"\n[!] Unexpected error: {e}")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)