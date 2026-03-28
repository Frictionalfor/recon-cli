#!/usr/bin/env python3
"""
recon.py — Recon CLI v1.2
Entry point. Parses arguments, orchestrates module execution.
"""
import argparse
import sys
import os
import shutil
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import init, Fore, Style
from utils.banner import print_banner
from utils.validator import validate_domain
from modules import subdomain_scan, port_scan, tech_detect, header_check, vuln_check, dns_scan, ssl_scan, whois_scan
from reports.report_generator import generate

init(autoreset=True)

# Scan history directory — auto-saves every scan
HISTORY_DIR = os.path.expanduser("~/.recon/history")

def _check_for_update():
    """Silently check GitHub for a newer version and notify if found."""
    try:
        import urllib.request
        base = os.path.dirname(os.path.abspath(__file__))
        version_file = os.path.join(base, "version.txt")
        if not os.path.isfile(version_file):
            return
        with open(version_file) as f:
            current = f.read().strip()
        url = "https://raw.githubusercontent.com/Frictionalfor/recon-cli/main/version.txt"
        req = urllib.request.Request(url, headers={"User-Agent": "recon-cli"})
        with urllib.request.urlopen(req, timeout=3) as r:
            latest = r.read().decode().strip()
        if latest and latest != current:
            print(Fore.YELLOW + f"  [!] Update available: v{current} → v{latest}"
                  + f"  Run: bash update.sh" + Style.RESET_ALL)
    except Exception:
        pass  # never block the scan for an update check


def clean_pycache():
    """Remove __pycache__ dirs under project root, history dir, and any stray dirs."""
    targets = [
        os.path.dirname(os.path.abspath(__file__)),
        HISTORY_DIR,
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests"),
    ]
    for base in targets:
        if not os.path.isdir(base):
            continue
        for root, dirs, _ in os.walk(base):
            for d in dirs:
                if d == "__pycache__":
                    shutil.rmtree(os.path.join(root, d), ignore_errors=True)

def ensure_history_dir():
    os.makedirs(HISTORY_DIR, exist_ok=True)

def parse_args():
    formatter = lambda prog: argparse.RawTextHelpFormatter(prog, max_help_position=28)

    parser = argparse.ArgumentParser(
        prog="recon",
        description="Recon CLI v1.2 — Automated Reconnaissance Framework",
        formatter_class=formatter,
        epilog="""
examples:
  recon example.com
  recon example.com -f
  recon example.com -sd
  recon example.com -sd -w wordlist.txt
  recon example.com -p
  recon example.com -t
  recon example.com -head
  recon example.com -dns
  recon example.com -ssl
  recon example.com -whois
  recon example.com -f -o report
  recon example.com -f -o report -txt
  recon example.com -f -o report -json -txt
  recon example.com -f --silent
  recon -targets targets.txt -f --rate-limit 5
  recon --diff old.json new.json
  recon --history

repo: https://github.com/Frictionalfor/recon-cli
- by Frictionalfor
        """
    )

    parser.add_argument("domain",
        nargs="?",
        help="Target domain (e.g. example.com)")

    parser.add_argument("-targets", "--targets",
        metavar="FILE",
        help="File with list of domains, one per line")

    parser.add_argument("-f", "--full",
        action="store_true",
        help="Run all reconnaissance modules (default if no flag given)")

    parser.add_argument("-sd", "--subdomains",
        action="store_true",
        help="Subdomain enumeration via DNS bruteforce + subfinder")

    parser.add_argument("-w", "--wordlist",
        metavar="FILE",
        help="Custom wordlist for subdomain bruteforce")

    parser.add_argument("-p", "--ports",
        action="store_true",
        help="Port scanning via nmap")

    parser.add_argument("-t", "--tech",
        action="store_true",
        help="Technology detection via WhatWeb")

    parser.add_argument("-head", "--headers",
        action="store_true",
        help="HTTP security header analysis (checks quality too)")

    parser.add_argument("-dns", "--dns",
        action="store_true",
        help="DNS records lookup (A, AAAA, MX, NS, TXT, CNAME)")

    parser.add_argument("-ssl", "--ssl",
        action="store_true",
        help="SSL/TLS certificate info (expiry, issuer, SANs)")

    parser.add_argument("-whois", "--whois",
        action="store_true",
        help="WHOIS lookup (registrar, creation/expiry dates, nameservers)")

    parser.add_argument("-o", "--output",
        metavar="FILE",
        help="Save report to file (default: .json)")

    parser.add_argument("-json", "--json",
        action="store_true",
        help="Save output as JSON (default when -o is used)")

    parser.add_argument("-txt", "--txt",
        action="store_true",
        help="Save output as plain text")

    parser.add_argument("--silent",
        action="store_true",
        help="Suppress progress output — only print final report")

    parser.add_argument("--rate-limit",
        metavar="SECONDS",
        type=float,
        default=0,
        help="Delay in seconds between scans when using -targets")

    parser.add_argument("--diff",
        nargs=2,
        metavar=("OLD", "NEW"),
        help="Compare two JSON scan reports and show what changed")

    parser.add_argument("--history",
        action="store_true",
        help="List all saved scans from ~/.recon/history/")

    return parser.parse_args()


def _show_history():
    """List all saved scans from ~/.recon/history/ sorted by date."""
    if not os.path.isdir(HISTORY_DIR):
        print(Fore.YELLOW + "[!] No history found. Run a scan first." + Style.RESET_ALL)
        return

    files = sorted([
        f for f in os.listdir(HISTORY_DIR) if f.endswith(".json")
    ], reverse=True)

    if not files:
        print(Fore.YELLOW + "[!] History is empty." + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n{'─' * 50}")
    print(f"  Scan History  ({len(files)} scans)")
    print(f"{'─' * 50}" + Style.RESET_ALL)

    for f in files:
        path = os.path.join(HISTORY_DIR, f)
        size = os.path.getsize(path)
        try:
            with open(path) as fp:
                meta    = __import__("json").load(fp)
                tgt     = meta.get("target", "?")
                risk    = meta.get("risk", {}).get("level", "?")
                started = meta.get("scan", {}).get("start", "?")
                color   = {"High": Fore.RED, "Medium": Fore.YELLOW,
                           "Low": Fore.WHITE, "None": Fore.GREEN}.get(risk, Fore.WHITE)
                print(f"  {Fore.WHITE}{started}{Style.RESET_ALL}  "
                      f"{Fore.CYAN}{tgt:<30}{Style.RESET_ALL}  "
                      f"Risk: {color}{risk:<6}{Style.RESET_ALL}  "
                      f"{Fore.WHITE}{size//1024 or '<1'}KB{Style.RESET_ALL}")
                print(f"    {Fore.WHITE}{path}{Style.RESET_ALL}")
        except Exception:
            print(f"  {f}")

    print(Fore.CYAN + "─" * 50 + Style.RESET_ALL)
    print(f"  History dir: {HISTORY_DIR}\n")


def scan(domain, args):
    domain = validate_domain(domain)
    scan_start = datetime.now()
    timings = {}
    silent = args.silent

    if not silent:
        print(Fore.CYAN + f"\n{'='*50}" + Style.RESET_ALL)
        print(f"  Target  : {Fore.WHITE}{domain}{Style.RESET_ALL}")
        print(f"  Started : {scan_start.strftime('%H:%M:%S')}")
        print(Fore.CYAN + f"{'='*50}\n" + Style.RESET_ALL)

    run_all = args.full or not any([
        args.subdomains, args.ports, args.headers, args.tech,
        args.dns, args.ssl, args.whois
    ])

    subdomains = []
    ports      = []
    tech_data  = {"techs": [], "status": "", "country": "", "ip": "", "title": "", "server": ""}
    headers    = {"present": [], "missing": [], "weak": []}
    dns_data   = {}
    ssl_data   = {"subject": "", "issuer": "", "expires": "", "days_left": None, "expired": False, "sans": []}
    whois_data = {"registrar": "", "created": "", "expires": "", "updated": "", "nameservers": []}

    if run_all or args.subdomains:
        subdomains, t = subdomain_scan.run(domain, wordlist_file=args.wordlist, silent=silent)
        timings["subdomain_scan"] = t

    if run_all or args.ports:
        ports, t = port_scan.run(domain, silent=silent)
        timings["port_scan"] = t

    if run_all or args.tech:
        tech_data, t = tech_detect.run(domain, silent=silent)
        timings["tech_detection"] = t

    if run_all or args.headers:
        headers, t = header_check.run(domain, silent=silent)
        timings["header_check"] = t

    if run_all or args.dns:
        dns_data, t = dns_scan.run(domain, silent=silent)
        timings["dns_records"] = t

    if run_all or args.ssl:
        ssl_data, t = ssl_scan.run(domain, silent=silent)
        timings["ssl_certificate"] = t

    if run_all or args.whois:
        whois_data, t = whois_scan.run(domain, silent=silent)
        timings["whois_lookup"] = t

    issues, t = vuln_check.run(
        ports,
        headers.get("missing", []),
        tech_data.get("server", ""),
        weak_headers=headers.get("weak", []),
        silent=silent,
    )
    timings["vuln_analysis"] = t

    report = generate(domain, subdomains, ports, tech_data, headers, issues,
                      scan_start, timings, args.output, dns_data, ssl_data, whois_data,
                      save_json=args.json, save_txt=args.txt, silent=silent)

    if not silent:
        print("\n" + report)
    else:
        print(report)

    # ── Auto-save to history ─────────────────────────────
    ensure_history_dir()
    history_file = os.path.join(
        HISTORY_DIR,
        f"{domain}_{scan_start.strftime('%Y%m%d_%H%M%S')}.json"
    )
    generate(domain, subdomains, ports, tech_data, headers, issues,
             scan_start, timings, history_file, dns_data, ssl_data, whois_data,
             save_json=True, save_txt=False, silent=True)


def main():
    clean_pycache()
    print_banner()
    _check_for_update()
    args = parse_args()

    # ── History mode ─────────────────────────────────────
    if args.history:
        _show_history()
        return

    # ── Diff mode ────────────────────────────────────────
    if args.diff:
        from modules.diff import run as diff_run
        diff_run(args.diff[0], args.diff[1])
        return

    targets = []

    if args.targets:
        if not os.path.isfile(args.targets):
            print(Fore.RED + f"[!] File not found: {args.targets}" + Style.RESET_ALL)
            sys.exit(1)
        with open(args.targets) as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.domain:
        targets = [args.domain]
    else:
        print(Fore.RED + "[!] Provide a domain or use -targets targets.txt" + Style.RESET_ALL)
        print(Fore.WHITE + "    Run: recon --help" + Style.RESET_ALL)
        sys.exit(1)

    try:
        for i, domain in enumerate(targets):
            scan(domain, args)
            if args.rate_limit and i < len(targets) - 1:
                if not args.silent:
                    print(Fore.YELLOW + f"\n[*] Rate limit: waiting {args.rate_limit}s..." + Style.RESET_ALL)
                time.sleep(args.rate_limit)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n[!] Scan interrupted by user." + Style.RESET_ALL)
        sys.exit(0)
    finally:
        clean_pycache()

if __name__ == "__main__":
    main()
