# Recon CLI v1.2

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

### Termux (Android — no root required)

```bash
git clone https://github.com/Frictionalfor/recon-cli.git
cd recon-cli
bash termux-setup.sh
```

> Termux note: Port scan runs in TCP connect mode (`-sT`) automatically since root is not available. All modules including tech detection work fully — `whatweb` is not needed as the tool uses built-in HTTP fingerprinting as a fallback.

### Verify environment

```bash
bash check.sh
```

Detects Linux or Termux and checks all dependencies, auto-installing anything missing.

### Confirm

```bash
recon --help
```

> The tool will notify you on startup if a newer version is available on GitHub.

---

## Update

```bash
bash update.sh
```

Checks GitHub for the latest version, pulls changes, updates Python dependencies, and re-registers the `recon` command. Works on both Linux and Termux.

---

## Uninstall

### Linux

```bash
sudo rm /usr/local/bin/recon
rm -rf /path/to/recon-cli
rm -rf ~/.recon
pip uninstall requests colorama dnspython python-whois
```

### Termux

```bash
rm $PREFIX/bin/recon
rm -rf /path/to/recon-cli
rm -rf ~/.recon
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

| Flag                    | Description                                              |
|-------------------------|----------------------------------------------------------|
| `-f` / `--full`         | Run all reconnaissance modules                           |
| `-sd`                   | Subdomain enumeration (DNS bruteforce + subfinder)       |
| `-w FILE`               | Custom wordlist for subdomain bruteforce                 |
| `-p`                    | Port scanning via nmap (version detection included)      |
| `-t`                    | Technology detection via WhatWeb (Linux only)            |
| `-head`                 | HTTP security header analysis (checks quality too)       |
| `-dns`                  | DNS records lookup (A, AAAA, MX, NS, TXT, CNAME)        |
| `-ssl`                  | SSL/TLS certificate info (expiry, issuer, SANs)          |
| `-whois`                | WHOIS lookup (registrar, dates, nameservers)             |
| `-o FILE`               | Save report to file (default format: JSON)               |
| `-json`                 | Save output as JSON (default when `-o` is used)          |
| `-txt`                  | Save output as plain text                                |
| `--silent`              | Suppress progress lines — only print final report        |
| `--rate-limit SECONDS`  | Delay between scans when using `-targets`                |
| `--diff OLD NEW`        | Compare two JSON scan reports and show what changed      |
| `--history`             | List all saved scans from `~/.recon/history/`            |
| `-targets FILE`         | Scan multiple domains from a file (one per line)         |
| `-h` / `--help`         | Show help menu                                           |

---

## Examples

```bash
recon example.com
recon example.com -f
recon example.com -sd
recon example.com -sd -w wordlist.txt
recon example.com -p
recon example.com -t
recon example.com -head
recon example.com -dns
recon example.com -ssl
recon example.com -whois
recon example.com -f -o report
recon example.com -f -o report -txt
recon example.com -f -o report -json -txt
recon example.com -f --silent
recon -targets targets.txt -f --rate-limit 5
recon --diff old.json new.json
recon --history
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

## Scan History

Every scan is automatically saved to `~/.recon/history/` as a JSON file — no `-o` flag needed.

```
~/.recon/history/
  example.com_20260328_090332.json
  example.com_20260328_091500.json
```

List all saved scans:

```bash
recon --history
```

Use `--diff` to compare any two history files:

```bash
recon --diff ~/.recon/history/example.com_20260328_090332.json \
             ~/.recon/history/example.com_20260328_091500.json
```

---

## Diff Output

`--diff` compares two JSON reports and shows:

- Risk level changes
- New or removed subdomains
- New or closed ports
- New or resolved vulnerability issues
- SSL expiry changes (warns if under 30 days)
- Security header changes

---

## JSON Report Structure

```json
{
  "tool":            { "name": "Recon CLI", "version": "1.2" },
  "scan_id":         "recon_20260328_090332",
  "target":          "example.com",
  "target_protocol": "https",
  "scan": {
    "start":            "2026-03-28 09:03:32",
    "end":              "2026-03-28 09:03:37",
    "duration":         "5s",
    "duration_seconds": 5
  },
  "risk":    { "level": "Medium", "score": 7 },
  "summary": { "total_subdomains": 2, "total_ports": 2, "total_issues": 5 },
  "ip_info": { "ip": "76.76.21.21", "country": "United States" },
  "subdomains":   [{ "host": "www.example.com", "type": "www" }],
  "ports":        [{ "port": 443, "protocol": "tcp", "service": "https", "version": "nginx 1.24.0" }],
  "technologies": [{ "name": "Bootstrap", "confidence": 0.9 }],
  "security_headers": {
    "present": ["Strict-Transport-Security"],
    "missing": ["Content-Security-Policy"],
    "weak":    [{ "header": "X-XSS-Protection", "value": "0" }]
  },
  "dns_records":  { "A": ["76.76.21.21"], "MX": [...], "TXT": [...] },
  "ssl":   { "subject": "...", "issuer": "...", "expires": "2027-01-01", "days_left": 278, "sans": [...] },
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
├── update.sh                 # One-command updater (Linux + Termux)
├── check.sh                  # Verify + auto-install all dependencies
├── version.txt               # Current version number
├── requirements.txt
├── CHANGELOG.md              # Version history
├── modules/
│   ├── subdomain_scan.py     # DNS bruteforce (200+ words) + subfinder/sublist3r
│   ├── port_scan.py          # Nmap wrapper — version detection, auto -sT on non-root
│   ├── tech_detect.py        # WhatWeb wrapper (Linux only)
│   ├── header_check.py       # Header presence + quality fingerprinting
│   ├── dns_scan.py           # DNS records lookup
│   ├── ssl_scan.py           # SSL/TLS certificate info (stdlib)
│   ├── whois_scan.py         # WHOIS lookup
│   ├── vuln_check.py         # Rule-based vulnerability analysis
│   └── diff.py               # JSON report diff engine
├── utils/
│   ├── banner.py             # Terminal banner
│   ├── parser.py             # Raw output parsers (port + version)
│   └── validator.py          # Domain validation & sanitization
└── reports/
    └── report_generator.py   # Terminal report + JSON/TXT output
```

---

## Module Overview

| Module          | External Tool | Works on Termux |
|-----------------|---------------|-----------------|
| subdomain_scan  | subfinder     | yes             |
| port_scan       | nmap          | yes (TCP mode)  |
| tech_detect     | whatweb (optional) | yes (built-in fallback) |
| header_check    | none          | yes             |
| dns_scan        | none          | yes             |
| ssl_scan        | none          | yes             |
| whois_scan      | none          | yes             |
| vuln_check      | none          | yes             |
| diff            | none          | yes             |

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
| Weak header value         | Medium | 5.0            |
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
