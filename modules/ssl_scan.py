"""
ssl_scan.py — Recon CLI v1.1
Grabs the SSL/TLS certificate for the target using Python's built-in ssl module.
Extracts expiry date, issuer, subject, and SANs (Subject Alternative Names).
SANs often reveal subdomains that bruteforce misses entirely.
No external dependencies — stdlib only.
"""
import ssl
import socket
import time
from datetime import datetime
from colorama import Fore, Style


def _parse_cert(cert):
    result = {
        "subject":    "",
        "issuer":     "",
        "expires":    "",
        "days_left":  None,
        "expired":    False,
        "sans":       [],
    }

    # Subject CN
    for field in cert.get("subject", []):
        for k, v in field:
            if k == "commonName":
                result["subject"] = v

    # Issuer O
    for field in cert.get("issuer", []):
        for k, v in field:
            if k == "organizationName":
                result["issuer"] = v

    # Expiry
    raw_expiry = cert.get("notAfter", "")
    if raw_expiry:
        expiry_dt = datetime.strptime(raw_expiry, "%b %d %H:%M:%S %Y %Z")
        result["expires"]   = expiry_dt.strftime("%Y-%m-%d")
        result["days_left"] = (expiry_dt - datetime.utcnow()).days
        result["expired"]   = result["days_left"] < 0

    # SANs
    for san_type, san_value in cert.get("subjectAltName", []):
        if san_type == "DNS":
            result["sans"].append(san_value)

    return result


def run(domain):
    print(Fore.YELLOW + "[+] Checking SSL Certificate..." + Style.RESET_ALL, end=" ", flush=True)
    start = time.time()
    empty = {"subject": "", "issuer": "", "expires": "", "days_left": None,
             "expired": False, "sans": []}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        result  = _parse_cert(cert)
        elapsed = time.time() - start

        days = result["days_left"]
        if result["expired"]:
            status = Fore.RED + "EXPIRED"
        elif days is not None and days <= 30:
            status = Fore.YELLOW + f"expires in {days}d"
        else:
            status = Fore.GREEN + f"valid ({days}d left)"

        print(status + Style.RESET_ALL + Fore.WHITE + f" ({elapsed:.1f}s)" + Style.RESET_ALL)
        return result, elapsed

    except ssl.SSLCertVerificationError:
        elapsed = time.time() - start
        print(Fore.RED + f"certificate verification failed ({elapsed:.1f}s)" + Style.RESET_ALL)
        return empty, elapsed
    except (socket.timeout, ConnectionRefusedError, OSError):
        elapsed = time.time() - start
        print(Fore.RED + f"could not connect on port 443 ({elapsed:.1f}s)" + Style.RESET_ALL)
        return empty, elapsed
