"""
tech_detect.py — Recon CLI v1.2
Primary: WhatWeb (Linux/Kali) — calls whatweb --log-brief
Fallback: Pure Python HTTP fingerprinting (works on Termux and anywhere)

The fallback detects technologies from:
- HTTP response headers (Server, X-Powered-By, Via, CF-Ray, etc.)
- HTML meta generator tags
- HTML content patterns (script/link paths, class names, comments)
- Cookie names (PHPSESSID, JSESSIONID, etc.)

No external tools required for fallback mode.
"""
import subprocess
import re
import time
import sys
import socket
from colorama import Fore, Style

# ── WhatWeb filter lists ──────────────────────────────────────────────────────
SKIP_PLUGINS = {
    "redirectlocation", "uncommonheaders", "httpserver", "cookies",
    "httponly", "html5", "script", "country", "ip", "title", "email",
    "meta-refresh", "open-graph-protocol", "x-frame-options",
    "x-xss-protection", "strict-transport-security", "content-security-policy",
    "meta-author", "meta-generator", "meta-viewport", "meta-description",
    "meta-keywords", "meta-robots", "meta-charset", "meta-language",
    "passwordfield", "formfield", "frame", "iframe", "object",
    "x-powered-by", "x-content-type-options", "referrer-policy",
    "permissions-policy", "cache-control", "via",
}
SKIP_PREFIXES = ("meta-", "x-", "http-")

# ── Pure Python fingerprint rules ─────────────────────────────────────────────
# Each rule: (name, confidence, check_fn)
# check_fn receives (headers_lower, html, cookies)

def _hdr(h):
    """Helper: return a check function that looks for value in a header."""
    def _check(headers, html, cookies):
        return h in headers
    return _check

def _hdr_val(h, val):
    def _check(headers, html, cookies):
        return val.lower() in headers.get(h, "").lower()
    return _check

def _html(pattern):
    def _check(headers, html, cookies):
        return bool(re.search(pattern, html, re.IGNORECASE))
    return _check

def _cookie(name):
    def _check(headers, html, cookies):
        return any(name.lower() in c.lower() for c in cookies)
    return _check

FINGERPRINTS = [
    # ── Servers / CDN ────────────────────────────────────
    ("Nginx",        0.95, _hdr_val("server", "nginx")),
    ("Apache",       0.95, _hdr_val("server", "apache")),
    ("IIS",          0.95, _hdr_val("server", "microsoft-iis")),
    ("LiteSpeed",    0.95, _hdr_val("server", "litespeed")),
    ("Caddy",        0.95, _hdr_val("server", "caddy")),
    ("OpenResty",    0.95, _hdr_val("server", "openresty")),
    ("Cloudflare",   0.95, _hdr("cf-ray")),
    ("Cloudflare",   0.90, _hdr_val("server", "cloudflare")),
    ("Vercel",       0.95, _hdr("x-vercel-id")),
    ("Vercel",       0.90, _hdr_val("server", "vercel")),
    ("Netlify",      0.95, _hdr("x-nf-request-id")),
    ("AWS CloudFront", 0.95, _hdr_val("via", "cloudfront")),
    ("AWS S3",       0.90, _hdr_val("server", "amazons3")),
    ("Fastly",       0.95, _hdr("x-fastly-request-id")),
    ("Akamai",       0.90, _hdr_val("x-check-cacheable", "")),
    ("GitHub Pages", 0.90, _hdr_val("server", "github.com")),
    # ── Languages / Frameworks ───────────────────────────
    ("PHP",          0.95, _hdr_val("x-powered-by", "php")),
    ("PHP",          0.90, _cookie("phpsessid")),
    ("ASP.NET",      0.95, _hdr_val("x-powered-by", "asp.net")),
    ("ASP.NET",      0.90, _cookie("asp.net_sessionid")),
    ("Java",         0.90, _cookie("jsessionid")),
    ("Node.js",      0.90, _hdr_val("x-powered-by", "express")),
    ("Express",      0.90, _hdr_val("x-powered-by", "express")),
    ("Ruby on Rails",0.90, _hdr_val("x-powered-by", "phusion passenger")),
    ("Python",       0.85, _hdr_val("x-powered-by", "python")),
    ("Django",       0.85, _hdr_val("x-frame-options", "sameorigin")),
    # ── CMS ──────────────────────────────────────────────
    ("WordPress",    0.95, _html(r'wp-content|wp-includes|wordpress')),
    ("WordPress",    0.90, _cookie("wordpress_")),
    ("Joomla",       0.95, _html(r'/components/com_|joomla')),
    ("Drupal",       0.95, _html(r'drupal|sites/default/files')),
    ("Magento",      0.95, _html(r'mage/|magento|varien')),
    ("Shopify",      0.95, _html(r'cdn\.shopify\.com|shopify')),
    ("Wix",          0.95, _html(r'wix\.com|wixsite')),
    ("Squarespace",  0.95, _html(r'squarespace\.com|static\.squarespace')),
    ("Ghost",        0.90, _html(r'ghost\.org|content/themes/casper')),
    ("Webflow",      0.90, _html(r'webflow\.com')),
    ("HubSpot",      0.90, _html(r'hubspot\.com|hs-scripts')),
    # ── JS Frameworks ────────────────────────────────────
    ("React",        0.85, _html(r'react\.js|react\.min\.js|__react|data-reactroot')),
    ("Vue.js",       0.85, _html(r'vue\.js|vue\.min\.js|__vue')),
    ("Angular",      0.85, _html(r'angular\.js|ng-version|angular\.min\.js')),
    ("Next.js",      0.90, _html(r'__next|_next/static')),
    ("Nuxt.js",      0.90, _html(r'__nuxt|_nuxt/')),
    ("jQuery",       0.85, _html(r'jquery\.js|jquery\.min\.js|jquery-\d')),
    ("Bootstrap",    0.85, _html(r'bootstrap\.css|bootstrap\.min\.css|bootstrap\.js')),
    ("Tailwind CSS", 0.85, _html(r'tailwind\.css|tailwindcss')),
    # ── Analytics / Marketing ────────────────────────────
    ("Google Analytics", 0.90, _html(r'google-analytics\.com|gtag\(|ga\(')),
    ("Google Tag Manager", 0.90, _html(r'googletagmanager\.com')),
    ("Hotjar",       0.85, _html(r'hotjar\.com')),
    ("Intercom",     0.85, _html(r'intercom\.io|intercomSettings')),
    ("Zendesk",      0.85, _html(r'zendesk\.com|zdassets\.com')),
    # ── Security / Infra ─────────────────────────────────
    ("reCAPTCHA",    0.90, _html(r'recaptcha\.net|google\.com/recaptcha')),
    ("Cloudflare Turnstile", 0.90, _html(r'challenges\.cloudflare\.com')),
    ("Stripe",       0.90, _html(r'js\.stripe\.com')),
    ("PayPal",       0.85, _html(r'paypal\.com/sdk')),
]


def _strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

def _clean_plugin_name(raw):
    name = re.sub(r'\[.*?\]', '', raw).strip().rstrip(',').strip()
    return name

def _parse_whatweb_line(output):
    result = {"techs": [], "status": "", "country": "", "ip": "", "title": "", "server": ""}
    clean = _strip_ansi(output)
    candidates = []
    for line in clean.splitlines():
        line = line.strip()
        m = re.match(r'^https?://\S+\s+\[([^\]]+)\]\s+(.*)', line)
        if m:
            candidates.append((m.group(1), m.group(2)))
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
        if country: result["country"] = country.group(1).split(",")[0].strip().title()
        elif ip:    result["ip"]      = ip.group(1)
        elif title: result["title"]   = title.group(1)
        elif server:result["server"]  = server.group(1)
        else:
            name = _clean_plugin_name(plugin)
            key  = name.lower()
            if (name and key not in SKIP_PLUGINS
                    and not any(key.startswith(p) for p in SKIP_PREFIXES)
                    and key not in seen):
                seen.add(key)
                result["techs"].append({"name": name, "confidence": 0.9})
    return result


def _python_fingerprint(domain):
    """Pure Python tech detection — works on Termux and anywhere."""
    import requests
    result = {"techs": [], "status": "", "country": "", "ip": "", "title": "", "server": ""}

    try:
        # Resolve IP
        try:
            result["ip"] = socket.gethostbyname(domain)
        except Exception:
            pass

        resp = None
        for scheme in ["https", "http"]:
            try:
                resp = requests.get(
                    f"{scheme}://{domain}",
                    timeout=10,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; ReconCLI/1.2)"},
                )
                break
            except Exception:
                continue

        if resp is None:
            return result

        result["status"] = str(resp.status_code)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        html = resp.text[:50000]  # cap at 50KB for speed

        # Server
        server_val = headers_lower.get("server", "")
        if server_val:
            result["server"] = server_val

        # Title
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if title_match:
            result["title"] = re.sub(r'\s+', ' ', title_match.group(1)).strip()[:100]

        # Cookies
        cookies = list(resp.cookies.keys())

        # Run fingerprints
        seen = set()
        for name, confidence, check_fn in FINGERPRINTS:
            key = name.lower()
            if key not in seen and check_fn(headers_lower, html, cookies):
                seen.add(key)
                # Don't double-add server as tech
                if name.lower() not in result["server"].lower():
                    result["techs"].append({"name": name, "confidence": confidence})

    except Exception:
        pass

    return result


def run(domain, silent=False):
    if not silent:
        print(Fore.YELLOW + "[+] Detecting Technologies..." + Style.RESET_ALL, end=" ", flush=True)
    empty = {"techs": [], "status": "", "country": "", "ip": "", "title": "", "server": ""}
    start = time.time()

    # Try WhatWeb first
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
        data = _parse_whatweb_line(stdout + stderr)
        elapsed = time.time() - start
        count = len(data["techs"]) + (1 if data["server"] else 0)
        if not silent:
            print(Fore.GREEN + f"{count} detected via WhatWeb "
                  + Fore.WHITE + f"({elapsed:.1f}s)" + Style.RESET_ALL)
        return data, elapsed

    except FileNotFoundError:
        # WhatWeb not available — use pure Python fallback
        if not silent:
            print(Fore.YELLOW + "WhatWeb not found — using built-in fingerprinting..." + Style.RESET_ALL, end=" ", flush=True)

    except subprocess.TimeoutExpired:
        if not silent:
            print(Fore.RED + "WhatWeb timed out — using built-in fingerprinting..." + Style.RESET_ALL, end=" ", flush=True)

    # Pure Python fallback
    try:
        data = _python_fingerprint(domain)
        elapsed = time.time() - start
        count = len(data["techs"]) + (1 if data["server"] else 0)
        if not silent:
            print(Fore.GREEN + f"{count} detected via HTTP fingerprinting "
                  + Fore.WHITE + f"({elapsed:.1f}s)" + Style.RESET_ALL)
        return data, elapsed
    except Exception:
        elapsed = time.time() - start
        if not silent:
            print(Fore.RED + f"failed ({elapsed:.1f}s)" + Style.RESET_ALL)
        return empty, elapsed
