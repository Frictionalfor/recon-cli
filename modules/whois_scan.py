"""
whois_scan.py — Recon CLI v1.1
Queries WHOIS data for the target domain using python-whois.
Extracts registrar, creation date, expiry date, last updated, and nameservers.
"""
import time
from colorama import Fore, Style

def run(domain, silent=False):
    if not silent:
        print(Fore.YELLOW + "[+] Running WHOIS Lookup..." + Style.RESET_ALL, end=" ", flush=True)
    start = time.time()
    empty = {"registrar": "", "created": "", "expires": "", "updated": "", "nameservers": []}

    try:
        import whois
    except ImportError:
        print(Fore.RED + "python-whois not found. Install: pip install python-whois" + Style.RESET_ALL)
        return empty, 0

    try:
        w = whois.whois(domain)
        elapsed = time.time() - start

        def _first(val):
            """Handle fields that can be a list or a single value."""
            if isinstance(val, list):
                return str(val[0]) if val else ""
            return str(val) if val else ""

        def _fmt_date(val):
            raw = _first(val)
            # Trim to date only if datetime string
            return raw[:10] if raw else ""

        nameservers = w.name_servers or []
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        nameservers = sorted(set(ns.lower() for ns in nameservers if ns))

        result = {
            "registrar":   _first(w.registrar),
            "created":     _fmt_date(w.creation_date),
            "expires":     _fmt_date(w.expiration_date),
            "updated":     _fmt_date(w.updated_date),
            "nameservers": nameservers,
        }

        if not silent:
            print(Fore.GREEN + "done " + Fore.WHITE + f"({elapsed:.1f}s)" + Style.RESET_ALL)
        return result, elapsed

    except Exception as e:
        elapsed = time.time() - start
        if not silent:
            print(Fore.RED + f"failed ({elapsed:.1f}s)" + Style.RESET_ALL)
        return empty, elapsed
