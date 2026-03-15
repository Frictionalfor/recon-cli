"""
vuln_check.py — Recon CLI v1.0
Pure Python logic — no external tools. Matches open ports and missing headers
against a rules dictionary, assigning High/Medium/Low risk to each finding.
Also checks the detected server string against known outdated versions.
Calculates a weighted risk score: High=3, Medium=2, Low=1.
"""
import time
from colorama import Fore, Style

PORT_RULES = {
    "21":    ("High",   "FTP open — unencrypted file transfer"),
    "23":    ("High",   "Telnet open — unencrypted remote access"),
    "25":    ("Medium", "SMTP open — potential mail relay abuse"),
    "110":   ("Medium", "POP3 open — unencrypted mail retrieval"),
    "143":   ("Medium", "IMAP open — unencrypted mail access"),
    "3306":  ("High",   "MySQL exposed — database port publicly accessible"),
    "5432":  ("High",   "PostgreSQL exposed — database port publicly accessible"),
    "3389":  ("High",   "RDP open — remote desktop exposed"),
    "6379":  ("High",   "Redis exposed — often unauthenticated"),
    "27017": ("High",   "MongoDB exposed — often unauthenticated"),
    "8080":  ("Low",    "HTTP alternate port — may expose dev/admin interface"),
    "8443":  ("Low",    "HTTPS alternate port open"),
}

HEADER_RULES = {
    "Content-Security-Policy":   ("Medium", "Missing CSP — XSS risk"),
    "X-Frame-Options":           ("Medium", "Missing X-Frame-Options — Clickjacking risk"),
    "Strict-Transport-Security": ("Medium", "Missing HSTS — SSL stripping possible"),
    "X-Content-Type-Options":    ("Low",    "Missing X-Content-Type-Options — MIME sniffing risk"),
    "Referrer-Policy":           ("Low",    "Missing Referrer-Policy — info leakage risk"),
    "X-XSS-Protection":          ("Low",    "Missing X-XSS-Protection header"),
}

RISKY_SERVERS = ["apache/2.2", "apache/2.0", "nginx/1.0", "nginx/1.2",
                 "iis/6", "iis/7", "iis/8", "php/5", "php/7.0", "php/7.1"]

RISK_WEIGHT = {"High": 3, "Medium": 2, "Low": 1}

LEVEL_ICON  = {"High": "[!!]", "Medium": "[!] ", "Low": "[i] "}
LEVEL_COLOR = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.WHITE}

def risk_rating(issues):
    score = sum(RISK_WEIGHT.get(i["level"], 0) for i in issues)
    if score == 0:  return score, "None"
    if score <= 3:  return score, "Low"
    if score <= 8:  return score, "Medium"
    return score, "High"

def run(ports, missing_headers, server=""):
    print(Fore.YELLOW + "[+] Vulnerability Analysis..." + Style.RESET_ALL, end=" ", flush=True)
    start = time.time()
    issues = []

    for p in ports:
        port_num = str(p.get("port", ""))
        if port_num in PORT_RULES:
            level, desc = PORT_RULES[port_num]
            issues.append({"level": level, "issue": desc})

    for h in missing_headers:
        if h in HEADER_RULES:
            level, desc = HEADER_RULES[h]
            issues.append({"level": level, "issue": desc})

    if server:
        for risky in RISKY_SERVERS:
            if risky in server.lower():
                issues.append({"level": "High", "issue": f"Outdated server: {server} — known vulnerabilities likely"})
                break

    elapsed = time.time() - start
    score, rating = risk_rating(issues)
    print(Fore.GREEN + f"{len(issues)} issues found " + Fore.WHITE + f"({elapsed:.1f}s)" + Style.RESET_ALL)
    return issues, elapsed
