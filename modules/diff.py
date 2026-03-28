"""
diff.py — Recon CLI v1.2
Compares two JSON scan reports and shows what changed.
New ports, resolved issues, new subdomains, SSL expiry changes, etc.
"""
import json
import os
from colorama import Fore, Style


def _load(path):
    if not os.path.isfile(path):
        print(Fore.RED + f"[!] File not found: {path}" + Style.RESET_ALL)
        return None
    with open(path) as f:
        return json.load(f)


def _section(title):
    return f"\n{Fore.CYAN}{'─' * 50}\n  {title}\n{'─' * 50}{Style.RESET_ALL}"


def run(old_path, new_path):
    old = _load(old_path)
    new = _load(new_path)
    if not old or not new:
        return

    lines = []
    lines.append(Fore.CYAN + "═" * 50)
    lines.append("  RECON CLI v1.2 — Diff Report")
    lines.append("═" * 50 + Style.RESET_ALL)
    lines.append(f"  Old scan : {old.get('scan', {}).get('start', old_path)}")
    lines.append(f"  New scan : {new.get('scan', {}).get('start', new_path)}")
    lines.append(f"  Target   : {new.get('target', '')}")

    changes = 0

    # ── Risk level ───────────────────────────────────────
    old_risk = old.get("risk", {}).get("level", "?")
    new_risk = new.get("risk", {}).get("level", "?")
    if old_risk != new_risk:
        color = Fore.RED if new_risk in ("High", "Medium") else Fore.GREEN
        lines.append(_section("Risk Level Changed"))
        lines.append(color + f"  {old_risk}  →  {new_risk}" + Style.RESET_ALL)
        changes += 1

    # ── Subdomains ───────────────────────────────────────
    old_subs = {s["host"] if isinstance(s, dict) else s for s in old.get("subdomains", [])}
    new_subs = {s["host"] if isinstance(s, dict) else s for s in new.get("subdomains", [])}
    added_subs   = new_subs - old_subs
    removed_subs = old_subs - new_subs
    if added_subs or removed_subs:
        lines.append(_section(f"Subdomains Changed (+{len(added_subs)} / -{len(removed_subs)})"))
        for s in sorted(added_subs):
            lines.append(Fore.GREEN + f"  [+] {s}" + Style.RESET_ALL)
        for s in sorted(removed_subs):
            lines.append(Fore.RED + f"  [-] {s}" + Style.RESET_ALL)
        changes += 1

    # ── Ports ────────────────────────────────────────────
    old_ports = {p["port"] for p in old.get("ports", [])}
    new_ports = {p["port"] for p in new.get("ports", [])}
    added_ports   = new_ports - old_ports
    removed_ports = old_ports - new_ports
    if added_ports or removed_ports:
        lines.append(_section(f"Ports Changed (+{len(added_ports)} / -{len(removed_ports)})"))
        new_port_map = {p["port"]: p for p in new.get("ports", [])}
        old_port_map = {p["port"]: p for p in old.get("ports", [])}
        for p in sorted(added_ports):
            svc = new_port_map.get(p, {}).get("service", "")
            lines.append(Fore.RED + f"  [+] {p}/tcp  {svc}" + Style.RESET_ALL)
        for p in sorted(removed_ports):
            svc = old_port_map.get(p, {}).get("service", "")
            lines.append(Fore.GREEN + f"  [-] {p}/tcp  {svc}" + Style.RESET_ALL)
        changes += 1

    # ── Issues ───────────────────────────────────────────
    old_issues = {i["name"] for i in old.get("issues", [])}
    new_issues = {i["name"] for i in new.get("issues", [])}
    added_issues   = new_issues - old_issues
    resolved_issues = old_issues - new_issues
    if added_issues or resolved_issues:
        lines.append(_section(f"Issues Changed (+{len(added_issues)} / -{len(resolved_issues)})"))
        new_issue_map = {i["name"]: i for i in new.get("issues", [])}
        for name in sorted(added_issues):
            risk = new_issue_map.get(name, {}).get("risk", "")
            lines.append(Fore.RED + f"  [+] [{risk}]  {name}" + Style.RESET_ALL)
        for name in sorted(resolved_issues):
            lines.append(Fore.GREEN + f"  [-] {name} (resolved)" + Style.RESET_ALL)
        changes += 1

    # ── SSL expiry ───────────────────────────────────────
    old_days = old.get("ssl", {}).get("days_left")
    new_days = new.get("ssl", {}).get("days_left")
    if old_days is not None and new_days is not None and old_days != new_days:
        lines.append(_section("SSL Certificate"))
        color = Fore.RED if new_days <= 30 else Fore.YELLOW if new_days <= 60 else Fore.GREEN
        lines.append(color + f"  Days left: {old_days}  →  {new_days}" + Style.RESET_ALL)
        if new_days <= 30:
            lines.append(Fore.RED + "  [!!] Certificate expiring soon!" + Style.RESET_ALL)
        changes += 1

    # ── Headers ──────────────────────────────────────────
    old_missing = set(old.get("security_headers", {}).get("missing", []))
    new_missing = set(new.get("security_headers", {}).get("missing", []))
    fixed_headers = old_missing - new_missing
    new_missing_headers = new_missing - old_missing
    if fixed_headers or new_missing_headers:
        lines.append(_section("Security Headers Changed"))
        for h in sorted(fixed_headers):
            lines.append(Fore.GREEN + f"  [+] {h} (now present)" + Style.RESET_ALL)
        for h in sorted(new_missing_headers):
            lines.append(Fore.RED + f"  [-] {h} (now missing)" + Style.RESET_ALL)
        changes += 1

    # ── Summary ──────────────────────────────────────────
    lines.append(Fore.CYAN + "\n" + "═" * 50 + Style.RESET_ALL)
    if changes == 0:
        lines.append(Fore.GREEN + "  No changes detected between scans." + Style.RESET_ALL)
    else:
        lines.append(f"  {changes} section(s) changed.")

    print("\n".join(lines))
