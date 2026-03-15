"""
tech_detect.py — Recon CLI v1.0
Calls whatweb --log-brief which gives one clean summary line per URL instead of
verbose plugin dumps. Parses out server, IP, country, title, and tech names.
Filters out WhatWeb meta-plugins that are not real technologies (RedirectLocation,
UncommonHeaders, Cookies, HttpOnly, etc.) so only meaningful names appear.
"""
import subprocess
import re
import time
import sys
from colorama import Fore, Style

# These are WhatWeb meta-plugins, not real technologies — skip them
SKIP_PLUGINS = {
    "redirectlocation", "uncommonheaders", "httpserver", "cookies",
    "httponly", "html5", "script", "country", "ip", "title", "email",
    "meta-refresh", "open-graph-protocol", "x-frame-options",
    "x-xss-protection", "strict-transport-security", "content-security-policy",
}

def _strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

def _clean_plugin_name(raw):
    """Strip version/value brackets and normalize name."""
    name = re.sub(r'\[.*?\]', '', raw).strip().rstrip(',').strip()
    return name

def _parse_summary_line(output):
    result = {
        "techs": [], "status": "", "country": "",
        "ip": "", "title": "", "server": ""
    }
    clean = _strip_ansi(output)

    # Collect all summary lines, prefer 200 OK
    candidates = []
    for line in clean.splitlines():
        line = line.strip()
        m = re.match(r'^https?://\S+\s+\[([^\]]+)\]\s+(.*)', line)
        if m:
            candidates.append((m.group(1), m.group(2)))

    # Pick 200 OK line first, fallback to last
    chosen = None
    for status, plugins_raw in candidates:
        if "200" in status:
            chosen = (status, plugins_raw)
            break
    if not chosen and candidates:
        chosen = candidates[-1]
    if not chosen:
        return result

    result["status"] = chosen[0]
    plugins_raw = chosen[1]

    seen = set()
    for plugin in re.split(r',\s*(?=[A-Z])', plugins_raw):
        plugin = plugin.strip()

        country = re.match(r'^Country\[([^\]]+)\]', plugin)
        ip      = re.match(r'^IP\[([^\]]+)\]', plugin)
        title   = re.match(r'^Title\[([^\]]+)\]', plugin)
        server  = re.match(r'^HTTPServer\[([^\]]+)\]', plugin)

        if country: result["country"] = country.group(1).split(",")[0].strip()
        elif ip:    result["ip"]      = ip.group(1)
        elif title: result["title"]   = title.group(1)
        elif server:result["server"]  = server.group(1)
        else:
            name = _clean_plugin_name(plugin)
            key  = name.lower()
            if name and key not in SKIP_PLUGINS and key not in seen:
                seen.add(key)
                result["techs"].append(name)

    return result

def run(domain):
    print(Fore.YELLOW + "[+] Detecting Technologies..." + Style.RESET_ALL, end=" ", flush=True)
    empty = {"techs": [], "status": "", "country": "", "ip": "", "title": "", "server": ""}
    start = time.time()
    try:
        proc = subprocess.Popen(
            ["whatweb", "--color=never", "--log-brief=/dev/stdout", f"https://{domain}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        try:
            stdout, stderr = proc.communicate(timeout=60)
        except KeyboardInterrupt:
            proc.kill()
            proc.communicate()
            print(Fore.YELLOW + "\n[!] Scan interrupted by user." + Style.RESET_ALL)
            sys.exit(0)
        data = _parse_summary_line(stdout + stderr)
        elapsed = time.time() - start
        count = len(data["techs"]) + (1 if data["server"] else 0)
        print(Fore.GREEN + f"{count} technologies detected "
              + Fore.WHITE + f"({elapsed:.1f}s)" + Style.RESET_ALL)
        return data, elapsed
    except FileNotFoundError:
        print(Fore.RED + "whatweb not found. Install: sudo apt install whatweb" + Style.RESET_ALL)
        return empty, 0
    except subprocess.TimeoutExpired:
        print(Fore.RED + "timed out." + Style.RESET_ALL)
        return empty, 0
