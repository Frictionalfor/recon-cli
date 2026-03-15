import re
import sys

# Basic domain regex — no IPs, no paths, no special chars
DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}$'
)

def validate_domain(domain: str) -> str:
    """Validate and sanitize domain input. Exits on invalid input."""
    # Strip protocol if accidentally included
    domain = re.sub(r'^https?://', '', domain).strip().rstrip('/')

    if not DOMAIN_REGEX.match(domain):
        print(f"[!] Invalid domain: '{domain}'. Please provide a valid domain like example.com")
        sys.exit(1)

    return domain
