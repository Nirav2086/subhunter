#!/usr/bin/env python3

# =============================================================================
# SubHunter - Subdomain Finder Tool
# Built for learning: Bug Bounty & College Project
# =============================================================================
#
# WHAT THIS TOOL DOES:
#   Given a target domain like "example.com", this tool tries to discover
#   all its subdomains (like mail.example.com, api.example.com, etc.)
#   using multiple techniques simultaneously.
#
# TECHNIQUES USED:
#   1. DNS Brute-Force  - tries common names from a wordlist
#   2. crt.sh           - searches SSL certificate transparency logs
#   3. HackerTarget     - queries their free subdomain database
#   4. AlienVault OTX   - queries their passive DNS database
#   5. Web Archive      - searches historical internet archives
#
# HOW TO RUN:
#   python3 subhunter.py -d example.com
#   python3 subhunter.py -d example.com -w wordlist.txt
#   python3 subhunter.py -d example.com -o results.txt
#   python3 subhunter.py -d example.com -t 50 -o results.json
#
# =============================================================================

import argparse          # for reading command line arguments (-d, -w, -o, etc.)
import sys               # for exiting the program cleanly
import os                # for file path operations
import json              # for saving results in JSON format
import time              # for adding small delays between requests
import re                # for cleaning up subdomain strings with regex
from concurrent.futures import ThreadPoolExecutor, as_completed  # for running many DNS queries at once
from datetime import datetime  # for timestamps in output files

import requests          # for making HTTP requests to free APIs
import dns.resolver      # for making DNS queries (from dnspython library)
import dns.exception     # for catching DNS-specific errors

# colorama gives us colored terminal output so results are easy to read
from colorama import Fore, Style, init
init(autoreset=True)     # autoreset means color resets after each print automatically


# =============================================================================
# BANNER - shows when the tool starts
# =============================================================================

BANNER = f"""
{Fore.CYAN}
  ███████╗██╗   ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔════╝██║   ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████╗██║   ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ╚════██║██║   ██║██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ███████║╚██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}  Subdomain Finder Tool — For Learning & Bug Bounty
  Use only on domains you own or have permission to test.{Style.RESET_ALL}
"""


# =============================================================================
# HELPER: PRINT FUNCTIONS
# Makes output colorful and easy to read
# =============================================================================

def print_info(msg):
    """Blue [*] prefix — general information"""
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")

def print_success(msg):
    """Green [+] prefix — subdomain found"""
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def print_warning(msg):
    """Yellow [!] prefix — something worth noting"""
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def print_error(msg):
    """Red [-] prefix — an error occurred"""
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

def print_takeover(msg):
    """Magenta [TAKEOVER] prefix — possible subdomain takeover"""
    print(f"{Fore.MAGENTA}[TAKEOVER]{Style.RESET_ALL} {msg}")


# =============================================================================
# MODULE 1: WILDCARD DETECTION
#
# Problem: Some domains use wildcard DNS like *.example.com → 1.2.3.4
# This means EVERY subdomain resolves, even fake ones.
# If we don't detect this, our brute-force will report thousands of fake results.
#
# Solution: Query a random subdomain that definitely doesn't exist.
# If it resolves, the domain has a wildcard record.
# =============================================================================

def detect_wildcard(domain):
    """
    Check if the domain uses wildcard DNS.
    Returns the wildcard IP if found, None if not.
    
    Example: if *.example.com → 5.5.5.5
    Then querying thisisnotreal123456.example.com → 5.5.5.5
    We detect this and store 5.5.5.5 as the wildcard IP.
    Later, any result that resolves to 5.5.5.5 gets filtered out.
    """
    # Create a random subdomain that definitely won't exist
    import random
    import string
    random_sub = ''.join(random.choices(string.ascii_lowercase, k=15))
    test_domain = f"{random_sub}.{domain}"
    
    try:
        answers = dns.resolver.resolve(test_domain, 'A')
        # If we got here, the random subdomain resolved — wildcard exists!
        wildcard_ips = [str(r.address) for r in answers]
        return wildcard_ips
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        # NXDOMAIN means no wildcard — this is what we want
        return None


# =============================================================================
# MODULE 2: DNS RESOLVER
#
# This is the core function. Given a subdomain like "mail.example.com",
# it queries DNS and returns what it finds:
#   - A records (IPv4 addresses)
#   - CNAME records (aliases pointing elsewhere)
#   - Whether a CNAME points to a dead target (possible takeover)
# =============================================================================

def resolve_subdomain(subdomain, wildcard_ips=None):
    """
    Query DNS for a subdomain and return results.
    
    Returns a dict with:
        found    : True/False — did this subdomain resolve?
        ips      : list of IP addresses
        cname    : the CNAME target if there is one
        takeover : True if CNAME points to dead/unclaimed target
    
    Returns None if subdomain doesn't exist.
    """
    result = {
        'subdomain': subdomain,
        'ips': [],
        'cname': None,
        'takeover': False
    }
    
    try:
        # Step 1: Try to resolve the A record (IP address)
        # dnspython automatically follows CNAME chains
        answers = dns.resolver.resolve(subdomain, 'A')
        
        # Collect all IP addresses returned
        for rdata in answers:
            result['ips'].append(str(rdata.address))
        
        # Step 2: Check if there was a CNAME in the chain
        # canonical_name gives us the final name after following all CNAMEs
        canonical = str(answers.canonical_name).rstrip('.')
        if canonical != subdomain:
            # There was a CNAME redirect
            result['cname'] = canonical
        
        # Step 3: Wildcard filter
        # If the domain has a wildcard and this IP matches it, it's a fake result
        if wildcard_ips and result['ips']:
            if all(ip in wildcard_ips for ip in result['ips']):
                return None  # This is just the wildcard, not a real subdomain
        
        return result
    
    except dns.resolver.NXDOMAIN:
        # The subdomain genuinely doesn't exist
        # BUT — check if it has a CNAME pointing to a dead target
        # This is a potential subdomain takeover!
        try:
            cname_answers = dns.resolver.resolve(subdomain, 'CNAME')
            for rdata in cname_answers:
                result['cname'] = str(rdata.target).rstrip('.')
                result['takeover'] = True  # CNAME exists but target is dead
                result['ips'] = []
                return result  # Return it — this is interesting!
        except Exception:
            pass
        return None  # Normal NXDOMAIN, subdomain doesn't exist
    
    except dns.resolver.NoAnswer:
        # Subdomain exists in DNS but has no A record
        # Could have MX, NS, or other records but nothing to connect to via HTTP
        return None
    
    except dns.exception.DNSException:
        # Some other DNS error (timeout, server error, etc.)
        return None


# =============================================================================
# MODULE 3: DNS BRUTE-FORCE
#
# This is the most basic and reliable technique.
# We take a wordlist of common subdomain names and try each one.
# Uses threading to run many queries at the same time (much faster).
# =============================================================================

def bruteforce_subdomains(domain, wordlist_path, threads=50, wildcard_ips=None):
    """
    Try every word in the wordlist as a potential subdomain.
    
    Example wordlist entries: www, mail, api, dev, staging...
    For domain "example.com" we try: www.example.com, mail.example.com, etc.
    
    Uses ThreadPoolExecutor to run multiple DNS queries simultaneously.
    Without threading: 10,000 queries × 0.5s each = 83 minutes
    With 50 threads:   10,000 queries / 50 × 0.5s  = ~100 seconds
    """
    found = []
    
    # Read wordlist from file
    if not os.path.exists(wordlist_path):
        print_error(f"Wordlist not found: {wordlist_path}")
        return found
    
    with open(wordlist_path, 'r') as f:
        # Read each line, strip whitespace, skip empty lines and comments
        words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    print_info(f"Brute-force: loaded {len(words)} words from wordlist")
    print_info(f"Brute-force: running with {threads} parallel threads")
    
    # Build the full list of subdomains to try
    # e.g. ["www.example.com", "mail.example.com", "api.example.com", ...]
    subdomains_to_try = [f"{word}.{domain}" for word in words]
    
    # ThreadPoolExecutor runs multiple resolve_subdomain() calls at the same time
    with ThreadPoolExecutor(max_workers=threads) as executor:
        
        # Submit all jobs to the thread pool
        # Each job = resolve one subdomain
        future_to_sub = {
            executor.submit(resolve_subdomain, sub, wildcard_ips): sub
            for sub in subdomains_to_try
        }
        
        # as_completed() gives us results as they finish (not in order)
        for future in as_completed(future_to_sub):
            subdomain = future_to_sub[future]
            try:
                result = future.result()
                if result:
                    # We found something!
                    if result['takeover']:
                        print_takeover(f"{result['subdomain']}  →  CNAME  →  {result['cname']}  (TARGET IS DEAD!)")
                    elif result['cname']:
                        print_success(f"{result['subdomain']}  →  {', '.join(result['ips'])}  (CNAME: {result['cname']})")
                    else:
                        print_success(f"{result['subdomain']}  →  {', '.join(result['ips'])}")
                    found.append(result)
            except Exception:
                pass  # Ignore individual errors and keep going
    
    return found


# =============================================================================
# MODULE 4: crt.sh (Certificate Transparency Logs)
#
# Every time an SSL certificate is issued for a domain, it gets logged
# in public Certificate Transparency logs.
# crt.sh is a free website that lets us search these logs.
#
# Why this is powerful: It finds subdomains that were NEVER brute-forced
# because they existed in real SSL certificates.
# =============================================================================

def search_crtsh(domain):
    """
    Query crt.sh for SSL certificates issued for the domain.
    This reveals subdomains found in real SSL certificates.
    
    API endpoint: https://crt.sh/?q=%.example.com&output=json
    The % is a wildcard meaning "any subdomain of example.com"
    """
    found = set()  # Use a set to automatically remove duplicates
    
    print_info("crt.sh: searching certificate transparency logs...")
    
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    try:
        # Make the HTTP request with a 10 second timeout
        # We set a User-Agent header so the server knows who is calling
        response = requests.get(
            url,
            timeout=10,
            headers={'User-Agent': 'SubHunter/1.0 (Educational Tool)'}
        )
        
        if response.status_code != 200:
            print_error(f"crt.sh returned status {response.status_code}")
            return []
        
        # Parse the JSON response
        data = response.json()
        
        # Each entry in the JSON has a "name_value" field
        # which contains the domain name from the certificate
        for entry in data:
            name = entry.get('name_value', '')
            
            # A single cert can have multiple names separated by newlines
            for name_entry in name.split('\n'):
                name_entry = name_entry.strip().lower()
                
                # Remove wildcard prefix (*.example.com → example.com)
                if name_entry.startswith('*.'):
                    name_entry = name_entry[2:]
                
                # Only keep entries that are subdomains of our target
                if name_entry.endswith(f'.{domain}') or name_entry == domain:
                    found.add(name_entry)
        
        print_info(f"crt.sh: found {len(found)} unique entries")
        return list(found)
    
    except requests.exceptions.Timeout:
        print_error("crt.sh: request timed out")
        return []
    except requests.exceptions.ConnectionError:
        print_error("crt.sh: connection error (no internet?)")
        return []
    except json.JSONDecodeError:
        print_error("crt.sh: could not parse response")
        return []
    except Exception as e:
        print_error(f"crt.sh: unexpected error — {e}")
        return []


# =============================================================================
# MODULE 5: HackerTarget
#
# HackerTarget.com provides a free API that returns known subdomains
# from their database. Simple HTTP request, simple text response.
# Free tier is limited to a few queries per day — enough for our tool.
# =============================================================================

def search_hackertarget(domain):
    """
    Query HackerTarget's free subdomain lookup API.
    Returns a list of subdomains they have in their database.
    
    API endpoint: https://api.hackertarget.com/hostsearch/?q=example.com
    Response format: plain text, one "subdomain,ip" per line
    """
    found = []
    
    print_info("HackerTarget: querying subdomain database...")
    
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    
    try:
        response = requests.get(
            url,
            timeout=10,
            headers={'User-Agent': 'SubHunter/1.0 (Educational Tool)'}
        )
        
        if response.status_code != 200:
            print_error(f"HackerTarget returned status {response.status_code}")
            return []
        
        # Response is plain text: "subdomain.example.com,1.2.3.4"
        lines = response.text.strip().split('\n')
        
        for line in lines:
            # Check for API limit message
            if 'API count exceeded' in line or 'error' in line.lower():
                print_warning("HackerTarget: API limit reached for today")
                break
            
            # Each line is "subdomain,ip" — we only need the subdomain part
            if ',' in line:
                subdomain = line.split(',')[0].strip().lower()
                if subdomain.endswith(f'.{domain}') or subdomain == domain:
                    found.append(subdomain)
        
        print_info(f"HackerTarget: found {len(found)} entries")
        return found
    
    except Exception as e:
        print_error(f"HackerTarget: error — {e}")
        return []


# =============================================================================
# MODULE 6: AlienVault OTX (Open Threat Exchange)
#
# AlienVault is a cybersecurity platform that maintains a massive
# passive DNS database. Their API is completely free — no key needed.
# Great for finding subdomains from historical DNS data.
# =============================================================================

def search_alienvault(domain):
    """
    Query AlienVault OTX for passive DNS records of the domain.
    
    API endpoint: https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns
    """
    found = []
    
    print_info("AlienVault OTX: querying passive DNS database...")
    
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    
    try:
        response = requests.get(
            url,
            timeout=15,
            headers={'User-Agent': 'SubHunter/1.0 (Educational Tool)'}
        )
        
        if response.status_code != 200:
            print_error(f"AlienVault returned status {response.status_code}")
            return []
        
        data = response.json()
        
        # The response has a "passive_dns" list
        # Each entry has a "hostname" field with the subdomain
        for entry in data.get('passive_dns', []):
            hostname = entry.get('hostname', '').strip().lower()
            if hostname.endswith(f'.{domain}') or hostname == domain:
                found.append(hostname)
        
        print_info(f"AlienVault OTX: found {len(found)} entries")
        return found
    
    except Exception as e:
        print_error(f"AlienVault OTX: error — {e}")
        return []


# =============================================================================
# MODULE 7: Web Archive (Wayback Machine)
#
# The Wayback Machine at archive.org has crawled billions of web pages.
# We can query their CDX API to find URLs they've archived for a domain.
# These URLs often contain subdomains we'd never find by brute-force.
# =============================================================================

def search_webarchive(domain):
    """
    Query the Wayback Machine CDX API for archived URLs of the domain.
    Extract unique subdomains from those URLs.
    
    CDX API: http://web.archive.org/cdx/search/cdx?url=*.example.com&output=text&fl=original&collapse=urlkey
    """
    found = set()
    
    print_info("Web Archive: querying Wayback Machine...")
    
    url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*"
        f"&output=text"
        f"&fl=original"          # only return the original URL field
        f"&collapse=urlkey"      # deduplicate similar URLs
        f"&limit=5000"           # max 5000 results
    )
    
    try:
        response = requests.get(
            url,
            timeout=20,
            headers={'User-Agent': 'SubHunter/1.0 (Educational Tool)'}
        )
        
        if response.status_code != 200:
            print_error(f"Web Archive returned status {response.status_code}")
            return []
        
        # Each line is a URL like "https://api.example.com/endpoint?q=1"
        # We extract just the subdomain part from each URL
        lines = response.text.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Extract hostname from URL using regex
            # Pattern: matches the domain part of a URL
            match = re.search(r'https?://([a-zA-Z0-9.-]+)', line)
            if match:
                hostname = match.group(1).lower().rstrip('.')
                if hostname.endswith(f'.{domain}') or hostname == domain:
                    found.add(hostname)
        
        print_info(f"Web Archive: found {len(found)} unique subdomains")
        return list(found)
    
    except Exception as e:
        print_error(f"Web Archive: error — {e}")
        return []


# =============================================================================
# MODULE 8: DNS VERIFICATION
#
# After collecting subdomains from all sources (crt.sh, HackerTarget, etc.)
# we need to verify which ones are actually alive right now.
# A subdomain in a certificate from 3 years ago might not exist anymore.
#
# This module takes the full list and resolves each one via DNS.
# =============================================================================

def verify_subdomains(subdomains, wildcard_ips=None, threads=50):
    """
    Take a list of subdomains and verify which ones currently resolve in DNS.
    Returns only the ones that are alive with their IP addresses.
    """
    verified = []
    total = len(subdomains)
    
    print_info(f"DNS verification: checking {total} subdomains with {threads} threads...")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_sub = {
            executor.submit(resolve_subdomain, sub, wildcard_ips): sub
            for sub in subdomains
        }
        
        done = 0
        for future in as_completed(future_to_sub):
            done += 1
            subdomain = future_to_sub[future]
            
            # Show progress every 50 completions
            if done % 50 == 0:
                print_info(f"  Progress: {done}/{total}")
            
            try:
                result = future.result()
                if result:
                    if result['takeover']:
                        print_takeover(f"{result['subdomain']}  →  CNAME  →  {result['cname']}  (DEAD TARGET)")
                    elif result['cname']:
                        print_success(f"{result['subdomain']}  →  {', '.join(result['ips'])}  (CNAME: {result['cname']})")
                    else:
                        print_success(f"{result['subdomain']}  →  {', '.join(result['ips'])}")
                    verified.append(result)
            except Exception:
                pass
    
    return verified


# =============================================================================
# MODULE 9: SAVE RESULTS
#
# Save the found subdomains to a file.
# Supports two formats:
#   - TXT: simple list, one subdomain per line
#   - JSON: full details including IPs, CNAMEs, takeover flags
# =============================================================================

def save_results(results, output_file, domain):
    """
    Save results to a file. Format is determined by file extension.
    .txt → plain text list
    .json → full JSON with all details
    anything else → plain text
    """
    if not results:
        print_warning("No results to save.")
        return
    
    if output_file.endswith('.json'):
        # Save full details in JSON format
        output_data = {
            'target': domain,
            'timestamp': datetime.now().isoformat(),
            'total_found': len(results),
            'subdomains': results
        }
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
    else:
        # Save as plain text — just subdomain names, one per line
        with open(output_file, 'w') as f:
            f.write(f"# SubHunter results for {domain}\n")
            f.write(f"# Found: {len(results)} subdomains\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for r in results:
                line = r['subdomain']
                if r['ips']:
                    line += f"  [{', '.join(r['ips'])}]"
                if r['cname']:
                    line += f"  CNAME→{r['cname']}"
                if r['takeover']:
                    line += "  *** POSSIBLE TAKEOVER ***"
                f.write(line + '\n')
    
    print_success(f"Results saved to: {output_file}")


# =============================================================================
# MAIN FUNCTION
# This is where everything comes together.
# Reads arguments, runs all modules, combines results, saves output.
# =============================================================================

def main():
    print(BANNER)
    
    # -------------------------------------------------------------------------
    # ARGUMENT PARSING
    # argparse reads what you type after "python3 subhunter.py"
    # -------------------------------------------------------------------------
    parser = argparse.ArgumentParser(
        description='SubHunter — Subdomain Finder for Learning & Bug Bounty',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '-d', '--domain',
        required=True,
        help='Target domain (e.g. example.com)'
    )
    parser.add_argument(
        '-w', '--wordlist',
        default='wordlist.txt',
        help='Path to wordlist file (default: wordlist.txt)'
    )
    parser.add_argument(
        '-o', '--output',
        default=None,
        help='Save results to file (e.g. results.txt or results.json)'
    )
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=50,
        help='Number of parallel threads for DNS queries (default: 50)'
    )
    parser.add_argument(
        '--no-bruteforce',
        action='store_true',
        help='Skip DNS brute-force (only use passive sources)'
    )
    parser.add_argument(
        '--only-bruteforce',
        action='store_true',
        help='Only run DNS brute-force, skip passive sources'
    )
    
    args = parser.parse_args()
    
    # Clean the domain (remove http://, https://, trailing slashes, etc.)
    domain = args.domain.lower()
    domain = re.sub(r'^https?://', '', domain)  # remove http:// or https://
    domain = domain.rstrip('/')                  # remove trailing slash
    domain = domain.split('/')[0]                # remove any path
    
    print_info(f"Target domain : {Fore.CYAN}{domain}{Style.RESET_ALL}")
    print_info(f"Threads       : {args.threads}")
    print_info(f"Wordlist      : {args.wordlist}")
    print_info(f"Output file   : {args.output or 'none (print only)'}")
    print()
    
    # -------------------------------------------------------------------------
    # STEP 1: WILDCARD DETECTION
    # Must do this first before any brute-force
    # -------------------------------------------------------------------------
    print_info("Step 1/4 — Checking for wildcard DNS...")
    wildcard_ips = detect_wildcard(domain)
    
    if wildcard_ips:
        print_warning(f"Wildcard DNS detected! *.{domain} → {', '.join(wildcard_ips)}")
        print_warning("Brute-force results will be filtered to remove wildcard matches.")
    else:
        print_info("No wildcard DNS detected. Good — brute-force will be accurate.")
    print()
    
    # This set collects ALL unique subdomains found across all techniques
    all_subdomains = set()
    
    # -------------------------------------------------------------------------
    # STEP 2: PASSIVE SOURCES (APIs that don't touch the target directly)
    # -------------------------------------------------------------------------
    if not args.only_bruteforce:
        print_info("Step 2/4 — Querying passive sources (APIs)...")
        print()
        
        # crt.sh — Certificate Transparency logs
        crt_results = search_crtsh(domain)
        all_subdomains.update(crt_results)
        time.sleep(1)  # small delay to be polite to the API
        
        # HackerTarget
        ht_results = search_hackertarget(domain)
        all_subdomains.update(ht_results)
        time.sleep(1)
        
        # AlienVault OTX
        av_results = search_alienvault(domain)
        all_subdomains.update(av_results)
        time.sleep(1)
        
        # Web Archive
        wa_results = search_webarchive(domain)
        all_subdomains.update(wa_results)
        
        print()
        print_info(f"Passive sources total: {len(all_subdomains)} unique subdomains collected")
        print()
    
    # -------------------------------------------------------------------------
    # STEP 3: DNS BRUTE-FORCE
    # -------------------------------------------------------------------------
    brute_results = []
    
    if not args.no_bruteforce:
        print_info("Step 3/4 — Running DNS brute-force...")
        print()
        brute_results = bruteforce_subdomains(
            domain,
            args.wordlist,
            threads=args.threads,
            wildcard_ips=wildcard_ips
        )
        # Add brute-force found subdomains to the master set
        for r in brute_results:
            all_subdomains.add(r['subdomain'])
        print()
    else:
        print_info("Step 3/4 — DNS brute-force skipped (--no-bruteforce flag)")
    
    # -------------------------------------------------------------------------
    # STEP 4: VERIFY PASSIVE RESULTS VIA DNS
    # The subdomains from APIs might be outdated — verify them all
    # -------------------------------------------------------------------------
    print_info("Step 4/4 — DNS verification of all collected subdomains...")
    print()
    
    # Remove subdomains already verified by brute-force
    already_verified = {r['subdomain'] for r in brute_results}
    
    # Only verify the ones we haven't checked yet
    to_verify = [sub for sub in all_subdomains if sub not in already_verified]
    
    verified_results = []
    if to_verify:
        verified_results = verify_subdomains(to_verify, wildcard_ips, threads=args.threads)
    
    # Combine brute-force results + verified passive results
    final_results = brute_results + verified_results
    
    # Remove duplicates (same subdomain found by multiple methods)
    seen = set()
    unique_results = []
    for r in final_results:
        if r['subdomain'] not in seen:
            seen.add(r['subdomain'])
            unique_results.append(r)
    
    # Sort results alphabetically
    unique_results.sort(key=lambda x: x['subdomain'])
    
    # -------------------------------------------------------------------------
    # PRINT FINAL SUMMARY
    # -------------------------------------------------------------------------
    print()
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SCAN COMPLETE — RESULTS SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"  Target domain    : {domain}")
    print(f"  Total found      : {Fore.GREEN}{len(unique_results)}{Style.RESET_ALL} subdomains")
    
    # Count takeover candidates separately
    takeovers = [r for r in unique_results if r['takeover']]
    if takeovers:
        print(f"  Takeover risks   : {Fore.MAGENTA}{len(takeovers)}{Style.RESET_ALL} potential subdomain takeovers!")
    
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print()
    
    # Print all found subdomains in a clean table
    if unique_results:
        print(f"{'SUBDOMAIN':<45} {'IP ADDRESS':<20} {'NOTE'}")
        print('-' * 80)
        for r in unique_results:
            ip_str = ', '.join(r['ips']) if r['ips'] else 'N/A'
            note = ''
            if r['takeover']:
                note = f"{Fore.MAGENTA}POSSIBLE TAKEOVER → {r['cname']}{Style.RESET_ALL}"
            elif r['cname']:
                note = f"CNAME → {r['cname']}"
            print(f"{Fore.GREEN}{r['subdomain']:<45}{Style.RESET_ALL} {ip_str:<20} {note}")
    else:
        print_warning("No subdomains found. Try a larger wordlist or check the domain name.")
    
    print()
    
    # -------------------------------------------------------------------------
    # SAVE RESULTS IF OUTPUT FILE SPECIFIED
    # -------------------------------------------------------------------------
    if args.output:
        save_results(unique_results, args.output, domain)


# =============================================================================
# ENTRY POINT
# This runs when you execute: python3 subhunter.py
# =============================================================================

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        # User pressed Ctrl+C — exit cleanly
        print()
        print_warning("Scan interrupted by user (Ctrl+C). Exiting.")
        sys.exit(0)
