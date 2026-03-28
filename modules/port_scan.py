"""
port_scan.py — Recon CLI v1.1
Calls nmap via subprocess. Uses -sV --open for root/Kali.
On Termux (non-root), falls back to -sT -sV --open (TCP connect scan).
"""
import subprocess
import time
import sys
import os
from utils.parser import parse_ports
from colorama import Fore, Style

def _is_root():
    return os.geteuid() == 0

def run(domain, silent=False):
    if not silent:
        print(Fore.YELLOW + "[+] Running Port Scan..." + Style.RESET_ALL, end=" ", flush=True)
    start = time.time()
    flags = ["-sV", "--open"] if _is_root() else ["-sT", "-sV", "--open"]
    try:
        proc = subprocess.Popen(
            ["nmap"] + flags + [domain],
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
        if not silent:
            print(Fore.GREEN + f"{len(ports)} open ports found " + Fore.WHITE + f"({elapsed:.1f}s)" + Style.RESET_ALL)
        return ports, elapsed
    except FileNotFoundError:
        if not silent:
            print(Fore.RED + "nmap not found. Run: pkg install nmap" + Style.RESET_ALL)
        return [], 0
    except subprocess.TimeoutExpired:
        if not silent:
            print(Fore.RED + "timed out." + Style.RESET_ALL)
        return [], 0
