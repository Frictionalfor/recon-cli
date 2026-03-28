# Recon CLI v1.1

Automated reconnaissance framework for security researchers and penetration testers.

Run a single command against a domain and get subdomains, open ports, detected technologies, HTTP security headers, DNS records, SSL certificate info, WHOIS data, and vulnerability indicators — all in one unified report.

---

## Requirements

- Python 3.7+
- Kali Linux / Debian-based system **or** Termux (Android)

---

## Installation

### Linux (Kali / Debian)

```bash
git clone https://github.com/Frictionalfor/recon-cli.git
cd recon-cli
sudo bash setup.sh
```

Installs Python dependencies, system tools (`nmap`, `whatweb`, `subfinder`), and registers `recon` as a global command at `/usr/local/bin/recon`.

### Termux (Android — no root required)

```bash
git clone https://github.com/Frictionalfor/recon-cli.git
cd recon-cli
bash termux-setup.sh
```

Installs Python dependencies, `nmap`, `subfinder` via `pkg`, and registers `recon` as a global command at `$PREFIX/bin/recon`.

> Note: `whatweb` is not available on Termux — tech detection (`-t`) is skipped. All other modules work fully without root.

### Verify environment (optional)

```bash
bash check.sh
```

Detects your environment (Linux or Termux) and checks all dependencies, auto-installing anything missing.

### Confirm install

```bash
recon --help
```

---

## Uninstall

### Linux

```bash
# Remove the global command
sudo rm /usr/local/bin/recon

# Remove the cloned folder
rm -rf /path/to/recon-cli

# Remove Python packages (optional)
pip uninstall requests colorama dnspython python-whois
```

### Termux

```bash
# Remove the global command
rm $PREFIX/bin/recon

# Remove the cloned folder
rm -rf /path/to/recon-cli

# Remove Python packages (optional)
pip uninstall requests colorama dnspython python-whois
```

---

## Usage

```bash
recon <domain> [flags]
```

If no scan flag is provided, full scan (`-f`) runs by default.

---

## Flags

| Flag              | Description                                        |
|-------------------|----------------------------------------------------|
| `-f` / `--full`   | Run all reconnaissance modules                     |
| `-sd`             | Subdomain enumeration (DNS bruteforce + subfinder) |
| `-p`              | Port scanning via nmap                             |
| `-t`              | Technology detection via WhatWeb (Linux only)      |
| `-head`           | HTTP security header analysis                      |
| `-dns`            | DNS records lookup (A, AAAA, MX, NS, TXT, CNAME)  |
| `-ssl`            | SSL/TLS certificate info (expiry, issuer, SANs)    |
| `-whois`          | WHOIS lookup (registrar, dates, nameservers)       |
| `-o FILE`         | Save report to file (default format: JSON)         |
| `-json`           | Save output as JSON (default when `-o` is used)    |
| `-txt`            | Save output as plain text                          |
| `-targets FILE`   | Scan multiple domains from a file (one per line)   |
| `-h` / `--help`   | Show help menu                                     |

---

## Examples

```bash
recon example.com
recon example.com -f
recon example.com -sd
recon example.com -p
recon example.com -t
recon example.com -head
recon example.com -dns
recon example.com -ssl
recon example.com -whois
recon example.com -f -o report
recon example.com -f -o report -txt
recon example.com -f -o report -json -txt
recon example.com -f -o /home/user/reports/report
recon -targets targets.txt -f
```

---

## Output Files

Use `-o` with a base filename — extension is added automatically.

| Command                            | Output                       |
|------------------------------------|------------------------------|
| `recon example.com -f -o report`   | `report.json`                |
| `... -o report -txt`               | `report.txt`                 |
| `... -o report -json`              | `report.json`                |
| `... -o report -json -txt`         | `report.json` + `report.txt` |

---

## JSON Report Structure

```json
{
  "tool":            { "name": "Recon CLI", "version": "1.1" },
  "scan_id":         "recon_20260317_204142",
  "target":          "example.com",
  "target_protocol": "https",
  "scan": {
    "start":            "2026-03-17 20:41:42",
    "end":              "2026-03-17 20:44:01",
    "duration":         "2m 19s",
    "duration_seconds": 139
  },
  "risk":    { "level": "Medium", "score": 7 },
  "summary": { "total_subdomains": 2, "total_ports": 2, "total_issues": 5 },
  "ip_info": { "ip": "76.76.21.21", "country": "United States" },
  "subdomains":   [{ "host": "www.example.com", "type": "www" }],
  "ports":        [{ "port": 443, "protocol": "tcp", "service": "https" }],
  "technologies": [{ "name": "Bootstrap", "confidence": 0.9 }],
  "security_headers": { "present": [...], "missing": [...] },
  "dns_records":  { "A": [...], "MX": [...], "TXT": [...] },
  "ssl":   { "subject": "...", "issuer": "...", "expires": "2027-01-01", "sans": [...] },
  "whois": { "registrar": "...", "created": "2020-01-01", "expires": "2027-01-01" },
  "issues": [
    {
      "type":           "Missing Header",
      "name":           "Content-Security-Policy",
      "risk":           "Medium",
      "severity_score": 6.5,
      "status":         "open",
      "description":    "Missing CSP — XSS and injection attacks may be possible",
      "source":         "header_check"
    }
  ],
  "timings": {
    "subdomain_scan":  27.4,
    "port_scan":       75.01,
    "tech_detection":  5.79,
    "header_check":    0.72,
    "dns_records":     1.02,
    "ssl_certificate": 0.33,
    "whois_lookup":    3.97,
    "vuln_analysis":   0.0
  }
}
```

---

## Project Structure

```
recon-cli/
├── recon.py                  # Entry point
├── setup.sh                  # Linux (Kali/Debian) install
├── termux-setup.sh           # Termux (Android) install — no root needed
├── check.sh                  # Verify + auto-install all dependencies
├── requirements.txt
├── modules/
│   ├── subdomain_scan.py     # DNS bruteforce + subfinder/sublist3r
│   ├── port_scan.py          # Nmap wrapper (auto -sT on non-root)
│   ├── tech_detect.py        # WhatWeb wrapper (Linux only)
│   ├── header_check.py       # HTTP security header analysis
│   ├── dns_scan.py           # DNS records lookup
│   ├── ssl_scan.py           # SSL/TLS certificate info (stdlib)
│   ├── whois_scan.py         # WHOIS lookup
│   └── vuln_check.py         # Rule-based vulnerability analysis
├── utils/
│   ├── banner.py             # Terminal banner
│   ├── parser.py             # Raw output parsers
│   └── validator.py          # Domain validation & sanitization
└── reports/
    └── report_generator.py   # Terminal report + JSON/TXT output
```

---

## Module Overview

| Module            | External Tool  | Works on Termux |
|-------------------|----------------|-----------------|
| subdomain_scan    | subfinder      | yes             |
| port_scan         | nmap           | yes (TCP mode)  |
| tech_detect       | whatweb        | no              |
| header_check      | none           | yes             |
| dns_scan          | none           | yes             |
| ssl_scan          | none           | yes             |
| whois_scan        | none           | yes             |
| vuln_check        | none           | yes             |

---

## Vulnerability Detection Rules

| Condition                 | Risk   | Severity Score |
|---------------------------|--------|----------------|
| Port 21 open (FTP)        | High   | 3.0            |
| Port 23 open (Telnet)     | High   | 3.0            |
| Port 3389 open (RDP)      | High   | 3.0            |
| Port 6379 open (Redis)    | High   | 3.0            |
| Port 3306 open (MySQL)    | High   | 3.0            |
| Port 27017 open (MongoDB) | High   | 3.0            |
| Outdated server version   | High   | 8.0            |
| Missing CSP               | Medium | 6.5            |
| Missing X-Frame-Options   | Medium | 6.5            |
| Missing HSTS              | Medium | 6.5            |
| Missing X-Content-Type    | Low    | 3.5            |
| Missing Referrer-Policy   | Low    | 3.5            |

---

## Security Notes

- Only use against systems you own or have explicit written permission to test.
- Input is validated and sanitized to prevent command injection.
- All subprocess calls use argument lists — `shell=True` is never used.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) or https://www.gnu.org/licenses/gpl-3.0.html

---

## Contributing

Pull requests are welcome. For major changes open an issue first.

GitHub: https://github.com/Frictionalfor/recon-cli
