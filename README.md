# Recon CLI v1.1

Automated reconnaissance framework for security researchers and penetration testers.

Run a single command against a domain and get subdomains, open ports, detected technologies, HTTP security headers, DNS records, SSL certificate info, WHOIS data, and vulnerability indicators — all in one unified report.

---

## Requirements

- Python 3.7+
- Kali Linux / Debian-based system recommended

---

## Installation

### Step 1 — Clone the repo

```bash
git clone https://github.com/Frictionalfor/recon-cli.git
cd recon-cli
```

### Step 2 — Run setup

```bash
chmod +x setup.sh && sudo bash setup.sh
```

This installs Python dependencies, system tools (`nmap`, `whatweb`, `subfinder`), and registers `recon` as a global command at `/usr/local/bin/recon`.

### Step 3 — Verify environment (optional)

```bash
bash check.sh
```

Checks all dependencies and auto-installs anything missing.

### Step 4 — Confirm

```bash
recon --help
```

---

## Usage

```bash
recon <domain> [flags]
```

If no scan flag is provided, full scan (`-f`) runs by default.

---

## Flags

| Flag               | Description                                          |
|--------------------|------------------------------------------------------|
| `-f` / `--full`    | Run all reconnaissance modules                       |
| `-sd`              | Subdomain enumeration (DNS bruteforce + subfinder)   |
| `-p`               | Port scanning via nmap -sV --open                    |
| `-t`               | Technology detection via WhatWeb                     |
| `-head`            | HTTP security header analysis                        |
| `-dns`             | DNS records lookup (A, AAAA, MX, NS, TXT, CNAME)    |
| `-ssl`             | SSL/TLS certificate info (expiry, issuer, SANs)      |
| `-whois`           | WHOIS lookup (registrar, dates, nameservers)         |
| `-o FILE`          | Save report to file (default format: JSON)           |
| `-json`            | Save output as JSON (default when `-o` is used)      |
| `-txt`             | Save output as plain text                            |
| `-targets FILE`    | Scan multiple domains from a file (one per line)     |
| `-h` / `--help`    | Show help menu                                       |

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

Use `-o` with a base filename (no extension needed — it's added automatically).

| Command                          | Output                        |
|----------------------------------|-------------------------------|
| `recon example.com -f -o report` | `report.json`                 |
| `... -o report -txt`             | `report.txt`                  |
| `... -o report -json`            | `report.json`                 |
| `... -o report -json -txt`       | `report.json` + `report.txt`  |

The full path is printed after saving:

```
[+] JSON report saved to: /home/user/Desktop/report.json
[+] TXT report saved to:  /home/user/Desktop/report.txt
```

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
  "ssl":          { "subject": "...", "issuer": "...", "expires": "2027-01-01", "sans": [...] },
  "whois":        { "registrar": "...", "created": "2020-01-01", "expires": "2027-01-01" },
  "issues": [
    {
      "type": "Missing Header",
      "name": "Content-Security-Policy",
      "risk": "Medium",
      "severity_score": 6.5,
      "status": "open",
      "description": "Missing CSP — XSS and injection attacks may be possible",
      "source": "header_check"
    }
  ],
  "timings": {
    "subdomain_scan": 27.4,
    "port_scan": 75.01,
    "tech_detection": 5.79,
    "header_check": 0.72,
    "dns_records": 1.02,
    "ssl_certificate": 0.33,
    "whois_lookup": 3.97,
    "vuln_analysis": 0.0
  }
}
```

---

## Project Structure

```
recon-cli/
├── recon.py                  # Entry point
├── setup.sh                  # Install dependencies + register global command
├── check.sh                  # Verify + auto-install all dependencies
├── requirements.txt
├── modules/
│   ├── subdomain_scan.py     # DNS bruteforce + subfinder/sublist3r integration
│   ├── port_scan.py          # Nmap wrapper
│   ├── tech_detect.py        # WhatWeb wrapper with output parsing
│   ├── header_check.py       # HTTP security header analysis
│   ├── dns_scan.py           # DNS records lookup (A, AAAA, MX, NS, TXT, CNAME)
│   ├── ssl_scan.py           # SSL/TLS certificate info via stdlib
│   ├── whois_scan.py         # WHOIS lookup via python-whois
│   └── vuln_check.py         # Rule-based vulnerability analysis
├── utils/
│   ├── banner.py             # Terminal banner
│   ├── parser.py             # Raw output parsers
│   └── validator.py          # Domain validation & sanitization
└── reports/
    └── report_generator.py   # Compiles terminal report + JSON/TXT output
```

---

## How It Works

### subdomain_scan.py
DNS bruteforce against ~40 common prefixes using `dnspython` (1s timeout per query). Merges results from `subfinder` or `sublist3r` if installed.

### port_scan.py
Calls `nmap -sV --open` via subprocess. Parses port number and service name into structured dicts with integer port values.

### tech_detect.py
Calls `whatweb --log-brief` and parses the compact summary line. Filters out WhatWeb meta-plugins (`Meta-*`, `X-*`, `UncommonHeaders`, etc.) so only real technology names appear. Each detected tech includes a `confidence` score.

### header_check.py
Makes a `requests.get()` to the target (HTTPS first, HTTP fallback). Checks against 6 security headers: `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-XSS-Protection`, `X-Content-Type-Options`, `Referrer-Policy`.

### dns_scan.py
Queries A, AAAA, MX, NS, TXT, CNAME records using `dnspython`. TXT records often expose SPF, DKIM, and verification tokens.

### ssl_scan.py
Grabs the SSL certificate via Python's stdlib `ssl` module. Extracts expiry date, issuer, subject, and SANs. Colors expiry red if expired, yellow if under 30 days.

### whois_scan.py
Queries WHOIS data via `python-whois`. Extracts registrar, creation date, expiry date, last updated, and nameservers.

### vuln_check.py
Pure Python — no external tools. Matches open ports and missing headers against a rules dictionary. Each issue includes `type`, `name`, `risk`, `severity_score`, `description`, and `source`. Weighted risk score: High=3, Medium=2, Low=1.

### report_generator.py
Assembles all results into a color-coded terminal report. Saves as JSON (default) or plain text via `-json` / `-txt` flags. JSON output is fully structured and machine-readable.

---

## Vulnerability Detection Rules

| Condition                    | Risk   | Severity Score |
|------------------------------|--------|----------------|
| Port 21 open (FTP)           | High   | 3.0            |
| Port 23 open (Telnet)        | High   | 3.0            |
| Port 3389 open (RDP)         | High   | 3.0            |
| Port 6379 open (Redis)       | High   | 3.0            |
| Port 3306 open (MySQL)       | High   | 3.0            |
| Port 27017 open (MongoDB)    | High   | 3.0            |
| Outdated server version      | High   | 8.0            |
| Missing CSP header           | Medium | 6.5            |
| Missing X-Frame-Options      | Medium | 6.5            |
| Missing HSTS                 | Medium | 6.5            |
| Missing X-Content-Type       | Low    | 3.5            |
| Missing Referrer-Policy      | Low    | 3.5            |

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
