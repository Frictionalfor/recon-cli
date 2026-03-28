"""
header_check.py — Recon CLI v1.2
Makes a requests.get() to the target (HTTPS first, HTTP fallback).
Checks presence AND quality of security headers.
A header with a weak/wildcard value is flagged as weak, not just present.
"""
import requests
import time
from colorama import Fore, Style

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

# Values that indicate a header is present but misconfigured/weak
WEAK_VALUES = {
    "content-security-policy": ["*", "unsafe-inline", "unsafe-eval"],
    "x-frame-options":         ["allow"],
    "strict-transport-security": [],   # any value is acceptable
    "x-content-type-options":  [],     # "nosniff" is the only value, always ok
    "referrer-policy":         ["unsafe-url"],
    "x-xss-protection":        ["0"],  # explicitly disabled
}

def _check_quality(header_name, value):
    """Returns 'ok', 'weak', based on header value."""
    key = header_name.lower()
    weak_triggers = WEAK_VALUES.get(key, [])
    val_lower = value.lower()
    for trigger in weak_triggers:
        if trigger in val_lower:
            return "weak"
    return "ok"

def run(domain, silent=False):
    if not silent:
        print(Fore.YELLOW + "[+] Checking Security Headers..." + Style.RESET_ALL, end=" ", flush=True)
    result = {"present": [], "missing": [], "weak": []}
    start = time.time()

    for scheme in ["https", "http"]:
        try:
            response = requests.get(f"{scheme}://{domain}", timeout=10, allow_redirects=True)
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            for h in SECURITY_HEADERS:
                val = headers_lower.get(h.lower())
                if val is None:
                    result["missing"].append(h)
                else:
                    quality = _check_quality(h, val)
                    if quality == "weak":
                        result["weak"].append({"header": h, "value": val})
                    else:
                        result["present"].append(h)
            elapsed = time.time() - start
            if not silent:
                weak_count = len(result["weak"])
                print(Fore.GREEN + f"{len(result['present'])} present, {len(result['missing'])} missing"
                      + (Fore.YELLOW + f", {weak_count} weak" if weak_count else "")
                      + Fore.WHITE + f" ({elapsed:.1f}s)" + Style.RESET_ALL)
            return result, elapsed
        except requests.exceptions.SSLError:
            continue
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            break

    elapsed = time.time() - start
    if not silent:
        print(Fore.RED + f"could not connect ({elapsed:.1f}s)" + Style.RESET_ALL)
    return result, elapsed
