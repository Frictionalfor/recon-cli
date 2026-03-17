"""
vuln_check.py — Recon CLI v1.1
Pure Python logic — no external tools. Matches open ports and missing headers
against a rules dictionary, assigning High/Medium/Low risk to each finding.
Also checks the detected server string against known outdated versions.
Calculates a weighted risk score: High=3, Medium=2, Low=1.
"""
import time
from colorama import Fore, Style

PORT_RULES = {
    21:    ("High",   3.0,  "Open Port",       "FTP",        "FTP open — unencrypted file transfer, credentials sent in plaintext"),
    23:    ("High",   3.0,  "Open Port",       "Telnet",     "Telnet open — unencrypted remote access, credentials sent in plaintext"),
    25:    ("Medium", 2.0,  "Open Port",       "SMTP",       "SMTP open — potential mail relay abuse"),
    110:   ("Medium", 2.0,  "Open Port",       "POP3",       "POP3 open — unencrypted mail retrieval"),
    143:   ("Medium", 2.0,  "Open Port",       "IMAP",       "IMAP open — unencrypted mail access"),
    3306:  ("High",   3.0,  "Exposed Service", "MySQL",      "MySQL exposed — database port publicly accessible"),
    5432:  ("High",   3.0,  "Exposed Service", "PostgreSQL", "PostgreSQL exposed — database port publicly accessible"),
    3389:  ("High",   3.0,  "Exposed Service", "RDP",        "RDP open — remote desktop exposed to internet"),
    6379:  ("High",   3.0,  "Exposed Service", "Redis",      "Redis exposed — often unauthenticated by default"),
    27017: ("High",   3.0,  "Exposed Service", "MongoDB",    "MongoDB exposed — often unauthenticated by default"),
    8080:  ("Low",    1.0,  "Open Port",       "HTTP-Alt",   "HTTP alternate port open — may expose dev or admin interface"),
    8443:  ("Low",    1.0,  "Open Port",       "HTTPS-Alt",  "HTTPS alternate port open"),
}

HEADER_RULES = {
    "Content-Security-Policy":   ("Medium", 6.5, "Missing CSP — XSS and injection attacks may be possible"),
    "X-Frame-Options":           ("Medium", 6.5, "Missing X-Frame-Options — clickjacking attacks possible"),
    "Strict-Transport-Security": ("Medium", 6.5, "Missing HSTS — SSL stripping attacks possible"),
    "X-Content-Type-Options":    ("Low",    3.5, "Missing X-Content-Type-Options — MIME sniffing risk"),
    "Referrer-Policy":           ("Low",    3.5, "Missing Referrer-Policy — sensitive URL info may leak"),
    "X-XSS-Protection":          ("Low",    3.5, "Missing X-XSS-Protection — legacy XSS filter not enabled"),
}

RISKY_SERVERS = ["apache/2.2", "apache/2.0", "nginx/1.0", "nginx/1.2",
                 "iis/6", "iis/7", "iis/8", "php/5", "php/7.0", "php/7.1"]

RISK_WEIGHT = {"High": 3, "Medium": 2, "Low": 1}
LEVEL_ICON  = {"High": "[!!]", "Medium": "[!] ", "Low": "[i] "}
LEVEL_COLOR = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.WHITE}

def risk_rating(issues):
    score = sum(RISK_WEIGHT.get(i["risk"], 0) for i in issues)
    if score == 0:  return score, "None"
    if score <= 3:  return score, "Low"
    if score <= 8:  return score, "Medium"
    return score, "High"

def run(ports, missing_headers, server=""):
    print(Fore.YELLOW + "[+] Vulnerability Analysis..." + Style.RESET_ALL, end=" ", flush=True)
    start = time.time()
    issues = []

    for p in ports:
        port_num = int(p.get("port", 0))
        if port_num in PORT_RULES:
            risk, severity_score, itype, name, desc = PORT_RULES[port_num]
            issues.append({
                "type":           itype,
                "name":           name,
                "risk":           risk,
                "severity_score": severity_score,
                "description":    desc,
                "source":         "port_scan",
            })

    for h in missing_headers:
        if h in HEADER_RULES:
            risk, severity_score, desc = HEADER_RULES[h]
            issues.append({
                "type":           "Missing Header",
                "name":           h,
                "risk":           risk,
                "severity_score": severity_score,
                "description":    desc,
                "source":         "header_check",
            })

    if server:
        for risky in RISKY_SERVERS:
            if risky in server.lower():
                issues.append({
                    "type":           "Outdated Software",
                    "name":           server,
                    "risk":           "High",
                    "severity_score": 8.0,
                    "description":    f"Outdated server detected: {server} — known vulnerabilities likely",
                    "source":         "tech_detect",
                })
                break

    elapsed = time.time() - start
    score, rating = risk_rating(issues)
    print(Fore.GREEN + f"{len(issues)} issues found " + Fore.WHITE + f"({elapsed:.1f}s)" + Style.RESET_ALL)
    return issues, elapsed
