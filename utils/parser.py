import re

def parse_ports(nmap_output: str) -> list:
    """Extract open ports from nmap raw output."""
    ports = []
    for line in nmap_output.splitlines():
        match = re.match(r'^(\d+)/tcp\s+open\s+(\S+)', line)
        if match:
            ports.append({
                "port": match.group(1),
                "service": match.group(2)
            })
    return ports

def parse_subdomains(sublist3r_output: str) -> list:
    """Extract subdomains from sublist3r raw output."""
    subdomains = []
    for line in sublist3r_output.splitlines():
        line = line.strip()
        # Sublist3r prints subdomains as plain lines after the banner
        if line and '.' in line and not line.startswith('[') and not line.startswith('-'):
            subdomains.append(line)
    return list(set(subdomains))  # deduplicate

def parse_technologies(whatweb_output: str) -> list:
    """Extract technology names from whatweb raw output."""
    techs = []
    # WhatWeb format: URL [status] Tech1, Tech2[version], ...
    match = re.search(r'\[[\d]+\]\s+(.*)', whatweb_output)
    if match:
        raw = match.group(1)
        # Split by comma, clean up version info in brackets
        for item in raw.split(','):
            name = re.sub(r'\[.*?\]', '', item).strip()
            if name:
                techs.append(name)
    return techs
