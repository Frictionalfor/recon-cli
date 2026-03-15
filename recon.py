#!/usr/bin/env python3
"""
recon.py — Recon CLI v1.0
Entry point. Parses arguments, orchestrates module execution.
"""
import argparse
import sys
import os
import shutil
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import init, Fore, Style
from utils.banner import print_banner
from utils.validator import validate_domain
from modules import subdomain_scan, port_scan, tech_detect, header_check, vuln_check
from reports.report_generator import generate

init(autoreset=True)

def clean_pycache():
    """Remove __pycache__ dirs after every run to avoid storage buildup."""
    base = os.path.dirname(os.path.abspath(__file__))
    for root, dirs, _ in os.walk(base):
        for d in dirs:
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)

def parse_args():
    # Fixed column width so all flag descriptions align cleanly
    formatter = lambda prog: argparse.RawTextHelpFormatter(prog, max_help_position=28)

    parser = argparse.ArgumentParser(
        prog="recon",
        description="Recon CLI v1.0 — Automated Reconnaissance Framework",
        formatter_class=formatter,
        epilog="""
examples:
  recon example.com
  recon example.com -f
  recon example.com -sd
  recon example.com -p
  recon example.com -t
  recon example.com -head
  recon example.com -f -o report.txt
  recon example.com -f -o /home/user/reports/report.txt
  recon -targets targets.txt -f

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

    parser.add_argument("-p", "--ports",
        action="store_true",
        help="Port scanning via nmap -sV --open")

    parser.add_argument("-t", "--tech",
        action="store_true",
        help="Technology detection via WhatWeb")

    parser.add_argument("-head", "--headers",
        action="store_true",
        help="HTTP security header analysis")

    parser.add_argument("-o", "--output",
        metavar="FILE",
        help="Save report to a plain text file (ANSI codes stripped)")

    return parser.parse_args()

def scan(domain, args):
    domain = validate_domain(domain)
    scan_start = datetime.now()
    timings = {}

    print(Fore.CYAN + f"\n{'='*50}" + Style.RESET_ALL)
    print(f"  Target  : {Fore.WHITE}{domain}{Style.RESET_ALL}")
    print(f"  Started : {scan_start.strftime('%H:%M:%S')}")
    print(Fore.CYAN + f"{'='*50}\n" + Style.RESET_ALL)

    run_all = args.full or not any([args.subdomains, args.ports, args.headers, args.tech])

    subdomains = []
    ports      = []
    tech_data  = {"techs": [], "status": "", "country": "", "ip": "", "title": "", "server": ""}
    headers    = {"present": [], "missing": []}

    if run_all or args.subdomains:
        subdomains, t = subdomain_scan.run(domain)
        timings["Subdomain Scan"] = t

    if run_all or args.ports:
        ports, t = port_scan.run(domain)
        timings["Port Scan"] = t

    if run_all or args.tech:
        tech_data, t = tech_detect.run(domain)
        timings["Tech Detection"] = t

    if run_all or args.headers:
        headers, t = header_check.run(domain)
        timings["Header Check"] = t

    issues, t = vuln_check.run(ports, headers.get("missing", []), tech_data.get("server", ""))
    timings["Vuln Analysis"] = t

    report = generate(domain, subdomains, ports, tech_data, headers, issues,
                      scan_start, timings, args.output)
    print("\n" + report)

def main():
    args = parse_args()
    print_banner()

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
        for domain in targets:
            scan(domain, args)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n[!] Scan interrupted by user." + Style.RESET_ALL)
        sys.exit(0)
    finally:
        clean_pycache()

if __name__ == "__main__":
    main()
