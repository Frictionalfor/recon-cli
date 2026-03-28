"""
dns_scan.py — Recon CLI v1.1
Queries A, AAAA, MX, NS, TXT, CNAME records using dnspython.
TXT records often expose SPF, DKIM, verification tokens, and internal info.
"""
import time
import dns.resolver
from colorama import Fore, Style

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

def run(domain, silent=False):
    if not silent:
        print(Fore.YELLOW + "[+] Querying DNS Records..." + Style.RESET_ALL, end=" ", flush=True)
    start = time.time()
    records = {}

    resolver = dns.resolver.Resolver(configure=False)
    # Termux has no /etc/resolv.conf — use public DNS directly
    resolver.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
    resolver.timeout = 3
    resolver.lifetime = 3

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [r.to_text() for r in answers]
        except Exception:
            pass

    elapsed = time.time() - start
    total = sum(len(v) for v in records.values())
    if not silent:
        print(Fore.GREEN + f"{total} records found " + Fore.WHITE + f"({elapsed:.1f}s)" + Style.RESET_ALL)
    return records, elapsed
