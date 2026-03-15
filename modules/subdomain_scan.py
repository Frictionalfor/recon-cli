"""
subdomain_scan.py — Recon CLI v1.0
Runs a DNS bruteforce against ~40 common prefixes (www, api, mail, dev, etc.)
using dnspython directly. Fast because it's pure Python with 1s timeout per query.
If subfinder is installed on the system, its results are merged and deduplicated
on top of the DNS results.
"""
import subprocess
import re
import time
import dns.resolver
from utils.parser import parse_subdomains
from colorama import Fore, Style

COMMON_SUBS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
    "blog", "dev", "staging", "test", "api", "admin", "portal", "vpn",
    "ns1", "ns2", "mx", "shop", "store", "app", "mobile", "m", "cdn",
    "static", "assets", "media", "img", "images", "video", "docs",
    "support", "help", "status", "monitor", "dashboard", "login",
    "secure", "cloud", "git", "gitlab", "jenkins", "jira", "wiki",
]

def _strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

def _dns_bruteforce(domain):
    found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    for sub in COMMON_SUBS:
        try:
            resolver.resolve(f"{sub}.{domain}", "A")
            found.append(f"{sub}.{domain}")
        except Exception:
            pass
    return found

def _run_subfinder(domain):
    proc = subprocess.Popen(
        ["subfinder", "-d", domain, "-silent", "-timeout", "30"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        stdout, _ = proc.communicate(timeout=45)
        return [l.strip() for l in stdout.splitlines() if l.strip()]
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        proc.kill()
        proc.communicate()
        return []

def _run_sublist3r(domain):
    proc = subprocess.Popen(
        ["sublist3r", "-d", domain, "-t", "10"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        stdout, _ = proc.communicate(timeout=45)
        return parse_subdomains(_strip_ansi(stdout))
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        proc.kill()
        proc.communicate()
        return []

def run(domain):
    print(Fore.YELLOW + "[+] Running Subdomain Scan..." + Style.RESET_ALL, end=" ", flush=True)
    start = time.time()

    subdomains = _dns_bruteforce(domain)

    for tool, fn in [("subfinder", _run_subfinder), ("sublist3r", _run_sublist3r)]:
        try:
            extra = fn(domain)
            subdomains = list(set(subdomains + extra))
            break
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            break

    elapsed = time.time() - start
    print(Fore.GREEN + f"{len(subdomains)} subdomains found " + Fore.WHITE + f"({elapsed:.1f}s)" + Style.RESET_ALL)
    return sorted(subdomains), elapsed
