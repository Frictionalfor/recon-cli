"""
subdomain_scan.py — Recon CLI v1.2
DNS bruteforce against 200+ common prefixes using dnspython.
Merges results from subfinder/sublist3r if installed.
Supports custom wordlist via -w flag.
"""
import subprocess
import re
import time
import dns.resolver
from utils.parser import parse_subdomains
from colorama import Fore, Style

COMMON_SUBS = [
    # Core
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
    "blog", "dev", "staging", "test", "api", "admin", "portal", "vpn",
    "ns1", "ns2", "ns3", "ns4", "mx", "mx1", "mx2",
    # Commerce
    "shop", "store", "pay", "checkout", "cart", "billing", "invoice",
    # App
    "app", "apps", "mobile", "m", "wap", "pwa",
    # CDN / Static
    "cdn", "static", "assets", "media", "img", "images", "video", "files",
    "upload", "uploads", "download", "downloads", "s3", "storage",
    # Docs / Support
    "docs", "doc", "wiki", "kb", "help", "support", "faq", "forum",
    "community", "feedback", "ticket", "tickets",
    # Monitoring / Infra
    "status", "monitor", "monitoring", "health", "uptime", "metrics",
    "grafana", "kibana", "prometheus", "logs", "log",
    # Auth / Identity
    "login", "auth", "sso", "oauth", "id", "identity", "account",
    "accounts", "signup", "register", "password", "reset",
    # Dashboard / Admin
    "dashboard", "panel", "cp", "cpanel", "admin2", "administrator",
    "manage", "management", "console", "backend",
    # Dev / CI
    "git", "gitlab", "github", "bitbucket", "svn", "ci", "cd",
    "jenkins", "travis", "build", "deploy", "deployment",
    # Project tools
    "jira", "confluence", "notion", "trello", "slack", "chat",
    # Cloud / Infra
    "cloud", "aws", "azure", "gcp", "k8s", "kubernetes", "docker",
    "registry", "repo", "repository", "nexus", "artifactory",
    # Security
    "secure", "security", "vpn2", "remote2", "gateway", "firewall",
    "proxy", "waf",
    # DB / Cache
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "search", "solr",
    # Mail extras
    "smtp2", "mail2", "webmail2", "autodiscover", "autoconfig",
    # Misc
    "old", "new", "v1", "v2", "v3", "beta", "alpha", "demo", "sandbox",
    "uat", "qa", "preprod", "prod", "production", "internal", "intranet",
    "extranet", "partner", "partners", "client", "clients", "customer",
    "customers", "user", "users", "member", "members",
]

def _strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

def _dns_bruteforce(domain, wordlist):
    found = []
    resolver = dns.resolver.Resolver(configure=False)
    # Termux has no /etc/resolv.conf — use public DNS directly
    resolver.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
    resolver.timeout = 1
    resolver.lifetime = 1
    for sub in wordlist:
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

def run(domain, wordlist_file=None, silent=False):
    if not silent:
        print(Fore.YELLOW + "[+] Running Subdomain Scan..." + Style.RESET_ALL, end=" ", flush=True)
    start = time.time()

    # Load wordlist
    if wordlist_file:
        try:
            with open(wordlist_file) as f:
                wordlist = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            print(Fore.RED + f"wordlist not found: {wordlist_file}" + Style.RESET_ALL)
            wordlist = COMMON_SUBS
    else:
        wordlist = COMMON_SUBS

    subdomains = _dns_bruteforce(domain, wordlist)

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
    if not silent:
        print(Fore.GREEN + f"{len(subdomains)} subdomains found " + Fore.WHITE + f"({elapsed:.1f}s)" + Style.RESET_ALL)
    return sorted(subdomains), elapsed
