"""
report_generator.py — Recon CLI v1.1
Assembles all module results into a structured, color-coded terminal report.
Includes target info, subdomains, ports, technologies, headers, DNS records,
SSL certificate info, vulnerability issues, scan timings, and an at-a-glance
summary. When --output is used, ANSI color codes are stripped and the report
is saved as clean plain text.
"""
import re
import os
from datetime import datetime
from colorama import Fore, Style

RISK_WEIGHT = {"High": 3, "Medium": 2, "Low": 1}
LEVEL_COLOR = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.WHITE, "None": Fore.GREEN}
LEVEL_ICON  = {"High": "[!!]", "Medium": "[!] ", "Low": "[i] ", "None": "[ok]"}

# Ports that carry known risk — colored red in output
RISKY_PORTS = {"21", "23", "25", "110", "143", "3306", "5432", "3389", "6379", "27017"}
MEDIUM_PORTS = {"8080", "8443"}

def risk_rating(issues):
    score = sum(RISK_WEIGHT.get(i["level"], 0) for i in issues)
    if score == 0:  return score, "None"
    if score <= 3:  return score, "Low"
    if score <= 8:  return score, "Medium"
    return score, "High"

def _fmt_duration(seconds):
    if seconds < 60:
        return f"{seconds}s"
    return f"{seconds // 60}m {seconds % 60}s"

def _section(title):
    return f"\n{Fore.CYAN}{'─' * 50}\n  {title}\n{'─' * 50}{Style.RESET_ALL}"

def _strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

def generate(domain, subdomains, ports, tech_data, headers, issues,
             scan_start, timings, output_file=None, dns_data=None, ssl_data=None, whois_data=None):

    dns_data   = dns_data or {}
    ssl_data   = ssl_data or {"subject": "", "issuer": "", "expires": "", "days_left": None, "expired": False, "sans": []}
    whois_data = whois_data or {"registrar": "", "created": "", "expires": "", "updated": "", "nameservers": []}

    score, rating = risk_rating(issues)
    scan_end  = datetime.now()
    duration  = _fmt_duration((scan_end - scan_start).seconds)
    risk_color = LEVEL_COLOR.get(rating, Fore.WHITE)
    risk_icon  = LEVEL_ICON.get(rating, "")

    # Sort ports ascending by port number
    sorted_ports = sorted(ports, key=lambda p: int(p["port"]))

    # Deduplicate and sort subdomains
    sorted_subs = sorted(set(subdomains))

    lines = []

    # ── Header ──────────────────────────────────────────
    lines.append(Fore.CYAN + "═" * 50)
    lines.append("  RECON CLI v1.1 — Reconnaissance Report")
    lines.append("═" * 50 + Style.RESET_ALL)
    lines.append(f"  Target        : {Fore.WHITE}{domain}{Style.RESET_ALL}")
    lines.append(f"  Scan Started  : {scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Scan Finished : {scan_end.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Duration      : {duration}")
    lines.append(f"  Risk Level    : {risk_color}{risk_icon} {rating} (score: {score}){Style.RESET_ALL}")

    # ── At-a-Glance Summary ──────────────────────────────
    lines.append(_section("At-a-Glance Summary"))
    lines.append(f"  Subdomains Found  : {len(sorted_subs)}")
    lines.append(f"  Open Ports        : {len(sorted_ports)}")
    techs_all = ([tech_data["server"]] if tech_data.get("server") else []) + tech_data.get("techs", [])
    lines.append(f"  Technologies      : {len(techs_all)}")
    lines.append(f"  Headers Present   : {len(headers.get('present', []))}")
    lines.append(f"  Headers Missing   : {len(headers.get('missing', []))}")
    dns_total = sum(len(v) for v in dns_data.values())
    lines.append(f"  DNS Records       : {dns_total}")
    ssl_expiry = ssl_data.get("expires", "")
    lines.append(f"  SSL Expiry        : {ssl_expiry if ssl_expiry else 'N/A'}")
    lines.append(f"  Security Issues   : {len(issues)}")
    lines.append(f"  Overall Risk      : {risk_color}{rating}{Style.RESET_ALL}")

    # ── Target Info ──────────────────────────────────────
    if any(tech_data.get(k) for k in ["ip", "country", "title", "server"]):
        lines.append(_section("Target Info"))
        if tech_data.get("ip"):      lines.append(f"  IP Address  : {tech_data['ip']}")
        if tech_data.get("country"): lines.append(f"  Country     : {tech_data['country']}")
        if tech_data.get("title"):   lines.append(f"  Page Title  : {tech_data['title']}")
        if tech_data.get("server"):  lines.append(f"  Web Server  : {tech_data['server']}")

    # ── Subdomains — green = reachable (all DNS-confirmed) ───
    lines.append(_section(f"Subdomains  ({len(sorted_subs)} found)"))
    if sorted_subs:
        for s in sorted_subs:
            lines.append(Fore.GREEN + f"  • {s}" + Style.RESET_ALL)
    else:
        lines.append("  None found")

    # ── Open Ports — colored by risk ─────────────────────
    lines.append(_section(f"Open Ports  ({len(sorted_ports)} found)"))
    if sorted_ports:
        lines.append(f"  {'PORT':<12} {'STATE':<8} SERVICE")
        lines.append(f"  {'─'*10:<12} {'─'*5:<8} {'─'*10}")
        for p in sorted_ports:
            port_str = f"{p['port']}/tcp"
            pnum = str(p["port"])
            if pnum in RISKY_PORTS:
                color = Fore.RED
            elif pnum in MEDIUM_PORTS:
                color = Fore.YELLOW
            else:
                color = Fore.GREEN
            lines.append(color + f"  {port_str:<12} {'open':<8} {p['service']}" + Style.RESET_ALL)
    else:
        lines.append("  None found")

    # ── Technologies — grouped ────────────────────────────
    lines.append(_section(f"Technologies  ({len(techs_all)} detected)"))
    if tech_data.get("server"):
        lines.append(f"  {'Server':<14}: {tech_data['server']}")
    if tech_data.get("techs"):
        lines.append(f"  {'Detected':<14}:")
        for t in sorted(tech_data["techs"]):
            lines.append(f"    • {t}")
    if not techs_all:
        lines.append("  None detected")

    # ── Security Headers ─────────────────────────────────
    present = headers.get("present", [])
    missing = headers.get("missing", [])
    lines.append(_section(f"Security Headers  ({len(present)} present, {len(missing)} missing)"))
    for h in sorted(present):
        lines.append(Fore.GREEN  + f"  [ok] {h}" + Style.RESET_ALL)
    for h in sorted(missing):
        lines.append(Fore.YELLOW + f"  [!]  {h}" + Style.RESET_ALL)

    # ── DNS Records ──────────────────────────────────────
    if dns_data:
        dns_total = sum(len(v) for v in dns_data.values())
        lines.append(_section(f"DNS Records  ({dns_total} found)"))
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            for val in dns_data.get(rtype, []):
                lines.append(f"  {Fore.WHITE}{rtype:<8}{Style.RESET_ALL} {val}")

    # ── SSL Certificate ───────────────────────────────────
    if ssl_data.get("expires"):
        lines.append(_section("SSL Certificate"))
        lines.append(f"  {'Subject':<14}: {ssl_data['subject']}")
        lines.append(f"  {'Issuer':<14}: {ssl_data['issuer']}")

        days = ssl_data.get("days_left")
        if ssl_data.get("expired"):
            expiry_str = Fore.RED + f"{ssl_data['expires']} (EXPIRED)" + Style.RESET_ALL
        elif days is not None and days <= 30:
            expiry_str = Fore.YELLOW + f"{ssl_data['expires']} ({days} days left)" + Style.RESET_ALL
        else:
            expiry_str = Fore.GREEN + f"{ssl_data['expires']} ({days} days left)" + Style.RESET_ALL

        lines.append(f"  {'Expires':<14}: {expiry_str}")

        if ssl_data.get("sans"):
            lines.append(f"  {'SANs':<14}:")
            for san in sorted(ssl_data["sans"]):
                lines.append(f"    • {san}")

    # ── WHOIS ─────────────────────────────────────────────
    if any(whois_data.get(k) for k in ["registrar", "created", "expires"]):
        lines.append(_section("WHOIS"))
        if whois_data.get("registrar"): lines.append(f"  {'Registrar':<14}: {whois_data['registrar']}")
        if whois_data.get("created"):   lines.append(f"  {'Created':<14}: {whois_data['created']}")
        if whois_data.get("expires"):   lines.append(f"  {'Expires':<14}: {whois_data['expires']}")
        if whois_data.get("updated"):   lines.append(f"  {'Last Updated':<14}: {whois_data['updated']}")
        if whois_data.get("nameservers"):
            lines.append(f"  {'Nameservers':<14}:")
            for ns in whois_data["nameservers"]:
                lines.append(f"    • {ns}")

    # ── Vulnerability Issues ─────────────────────────────
    lines.append(_section(f"Vulnerability Issues  ({len(issues)} found)"))
    if issues:
        for i in sorted(issues, key=lambda x: RISK_WEIGHT.get(x["level"], 0), reverse=True):
            color = LEVEL_COLOR.get(i["level"], Fore.WHITE)
            icon  = LEVEL_ICON.get(i["level"], "")
            lines.append(color + f"  {icon} [{i['level']:6}]  {i['issue']}" + Style.RESET_ALL)
    else:
        lines.append(Fore.GREEN + "  [ok] No issues detected" + Style.RESET_ALL)

    # ── Scan Timings ─────────────────────────────────────
    if timings:
        lines.append(_section("Scan Timings"))
        for module, elapsed in timings.items():
            lines.append(f"  {module:<25} {elapsed:.1f}s")
        lines.append(f"  {'Total':<25} {duration}")

    lines.append(Fore.CYAN + "\n" + "═" * 50 + Style.RESET_ALL)

    report = "\n".join(lines)

    if output_file:
        abs_path = os.path.abspath(output_file)
        plain = _strip_ansi(report)
        with open(abs_path, "w") as f:
            f.write(plain)
        print(Fore.GREEN + f"\n[+] Report saved to: {abs_path}" + Style.RESET_ALL)

    return report
