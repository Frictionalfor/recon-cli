"""
port_scan.py — Recon CLI v1.0
Calls nmap -sV --open via subprocess. -sV detects service versions on each open
port. --open filters output to only show open ports. Raw nmap output is parsed
with a regex in utils/parser.py to extract port number and service name.
"""
import subprocess
import time
import sys
from utils.parser import parse_ports
from colorama import Fore, Style

def run(domain):
    print(Fore.YELLOW + "[+] Running Port Scan..." + Style.RESET_ALL, end=" ", flush=True)
    start = time.time()
    try:
        proc = subprocess.Popen(
            ["nmap", "-sV", "--open", domain],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        try:
            stdout, _ = proc.communicate(timeout=180)
        except KeyboardInterrupt:
            proc.kill()
            proc.communicate()
            print(Fore.YELLOW + "\n[!] Scan interrupted by user." + Style.RESET_ALL)
            sys.exit(0)
        ports = parse_ports(stdout)
        elapsed = time.time() - start
        print(Fore.GREEN + f"{len(ports)} open ports found " + Fore.WHITE + f"({elapsed:.1f}s)" + Style.RESET_ALL)
        return ports, elapsed
    except FileNotFoundError:
        print(Fore.RED + "nmap not found. Install: sudo apt install nmap" + Style.RESET_ALL)
        return [], 0
    except subprocess.TimeoutExpired:
        print(Fore.RED + "timed out." + Style.RESET_ALL)
        return [], 0
