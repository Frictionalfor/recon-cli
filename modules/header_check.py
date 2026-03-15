"""
header_check.py — Recon CLI v1.0
Makes a plain requests.get() to the target (tries HTTPS first, falls back to HTTP).
Checks the response headers against a list of 6 known security headers and splits
results into present and missing lists.
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

def run(domain):
    print(Fore.YELLOW + "[+] Checking Security Headers..." + Style.RESET_ALL, end=" ", flush=True)
    result = {"present": [], "missing": []}
    start = time.time()

    for scheme in ["https", "http"]:
        try:
            response = requests.get(f"{scheme}://{domain}", timeout=10, allow_redirects=True)
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            for h in SECURITY_HEADERS:
                if h.lower() in headers_lower:
                    result["present"].append(h)
                else:
                    result["missing"].append(h)
            elapsed = time.time() - start
            print(Fore.GREEN + f"{len(result['present'])} present, {len(result['missing'])} missing "
                  + Fore.WHITE + f"({elapsed:.1f}s)" + Style.RESET_ALL)
            return result, elapsed
        except requests.exceptions.SSLError:
            continue
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            break

    elapsed = time.time() - start
    print(Fore.RED + f"could not connect ({elapsed:.1f}s)" + Style.RESET_ALL)
    return result, elapsed
