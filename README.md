# Recon CLI v1.0

Automated reconnaissance framework for security researchers and penetration testers.

Run a single command against a domain and get subdomains, open ports, detected technologies, HTTP security header analysis, and vulnerability indicators — all in one unified report.

---

## Requirements

### System Tools (Kali Linux)

```bash
sudo apt install nmap whatweb
pip install sublist3r
```

### Python Dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

> Python 3.7+ required.

---

## Installation

### Step 1 — Clone the repo

```bash
git clone https://github.com/Frictionalfor/recon-cli.git
cd recon-cli
```

### Step 2 — Run setup

```bash
chmod +x setup.sh && sudo ./setup.sh
```

This will:
- Install Python dependencies (`requests`, `colorama`, `dnspython`)
- Install system tools via apt (`nmap`, `whatweb`, `subfinder`)
- Register `recon` as a global command at `/usr/local/bin/recon`

### Step 3 — Verify

```bash
recon --help
```

---

## Usage

```bash
recon <domain> [flags]
```

### Examples

```bash
recon example.com
recon example.com -f
recon example.com -sd
recon example.com -p
recon example.com -t
recon example.com -head
recon example.com -f -o report.txt
recon example.com -f -o /home/user/reports/example.txt
recon -targets targets.txt -f
```

> If no flag is provided, `-f` (full scan) is assumed by default.

---

## Flags

| Flag              | Shortcut    | Description                              |
|-------------------|-------------|------------------------------------------|
| `--full`          | `-f`        | Run all reconnaissance modules           |
| `--subdomains`    | `-sd`       | Subdomain enumeration                    |
| `--ports`         | `-p`        | Port scanning (Nmap)                     |
| `--tech`          | `-t`        | Technology detection (WhatWeb)           |
| `--headers`       | `-head`     | HTTP security header analysis            |
| `--output FILE`   | `-o FILE`   | Save report to plain text file           |
| `--targets FILE`  | `-targets`  | Scan multiple domains from a file        |
| `--help`          | `-h`        | Show help menu                           |

---

## Output Files

By default `-o report.txt` saves to your current working directory.
The tool always prints the full absolute path after saving so you know exactly where it is:

```
[+] Report saved to: /home/user/Desktop/report.txt
```

To save to a specific location, pass the full path:

```bash
recon example.com -f -o /home/user/reports/example.txt
recon example.com -f -o ~/Desktop/example-report.txt
```

---

## Project Structure

```
recon-cli/
├── recon.py                  # Entry point
├── requirements.txt
├── modules/
│   ├── subdomain_scan.py     # DNS bruteforce + subfinder integration
│   ├── port_scan.py          # Nmap wrapper
│   ├── tech_detect.py        # WhatWeb wrapper with output parsing
│   ├── header_check.py       # HTTP security header analysis
│   └── vuln_check.py         # Rule-based vulnerability analysis
├── utils/
│   ├── banner.py             # Terminal banner
│   ├── parser.py             # Raw output parsers
│   └── validator.py          # Domain validation & sanitization
└── reports/
    └── report_generator.py   # Compiles and formats the final report
```

---

## How It Works

### subdomain_scan.py
Runs a DNS bruteforce against ~40 common prefixes (`www`, `api`, `mail`, `dev`, `admin`, etc.) using `dnspython` directly — no external tool required. Each query has a 1s timeout so it completes fast. If `subfinder` is installed on the system, its results are merged in and deduplicated on top of the DNS results.

### port_scan.py
Calls `nmap -sV --open` via `subprocess`. The `-sV` flag detects service versions on each open port, and `--open` filters output to only show open ports. Raw nmap output is parsed with a regex in `utils/parser.py` to extract port number and service name into structured dicts.

### tech_detect.py
Calls `whatweb --log-brief` which outputs one compact summary line per URL instead of verbose plugin dumps. That line is parsed to extract the web server, IP address, country, page title, and technology names. WhatWeb meta-plugins that aren't real technologies (`RedirectLocation`, `UncommonHeaders`, `Cookies`, `HttpOnly`, etc.) are filtered out so only meaningful tech names appear.

### header_check.py
Makes a plain `requests.get()` to the target (tries HTTPS first, falls back to HTTP). Checks the response headers against a list of 6 known security headers: `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-XSS-Protection`, `X-Content-Type-Options`, and `Referrer-Policy`. Splits results into present and missing lists.

### vuln_check.py
Pure Python logic — no external tools. Matches open ports and missing headers against a rules dictionary, assigning a risk level (`High`, `Medium`, `Low`) to each finding. Also checks the detected web server string against a list of known outdated/vulnerable versions. Calculates a weighted risk score: High=3, Medium=2, Low=1.

### report_generator.py
Assembles all module results into a structured, color-coded terminal report with sections for target info, subdomains, ports, technologies, headers, and vulnerability issues. Includes scan start/finish timestamps, per-module timings, and an at-a-glance summary. When `--output` is used, ANSI color codes are stripped and the report is saved as clean plain text.

---

## Example Output

```
================================
  Recon CLI - Automated Recon
================================
Target: example.com

[+] Running Subdomain Scan...
    api.example.com
    dev.example.com

[+] Running Port Scan...
    22/tcp  open  ssh
    80/tcp  open  http
    443/tcp open  https

[+] Detecting Technologies...
    Apache
    PHP
    WordPress

[+] Checking Security Headers...
    [✓] Strict-Transport-Security
    [✗] Missing: Content-Security-Policy
    [✗] Missing: X-Frame-Options

[+] Vulnerability Analysis...
    [Medium] Missing CSP — XSS risk
    [Medium] Missing X-Frame-Options — Clickjacking risk
```

---

## Vulnerability Detection Rules

| Condition                    | Risk Level | Description                        |
|------------------------------|------------|------------------------------------|
| Port 21 open                 | High       | FTP — unencrypted file transfer    |
| Port 23 open                 | High       | Telnet — unencrypted remote access |
| Port 3389 open               | High       | RDP — remote desktop exposed       |
| Port 6379 open               | High       | Redis — often unauthenticated      |
| Port 3306 open               | Medium     | MySQL publicly accessible          |
| Missing CSP header           | Medium     | XSS risk                           |
| Missing X-Frame-Options      | Medium     | Clickjacking risk                  |
| Missing HSTS                 | Low        | SSL stripping possible             |

---

## Security Notes

- Only use this tool against systems you own or have explicit permission to test.
- Input is validated and sanitized to prevent command injection.
- External tool calls use `subprocess` with argument lists (no shell=True).

---

## Future Improvements

- WHOIS / DNS / IP geolocation (OSINT module)
- Website screenshot capture
- CVE database integration for outdated software
- Plugin system for custom modules

---

## License

This project is licensed under the GNU General Public License v3.0.

You are free to use, modify, and distribute this software under the terms of the GPL v3.
See the [LICENSE](LICENSE) file or visit https://www.gnu.org/licenses/gpl-3.0.html for details.

---

## Contributing

Pull requests are welcome. For major changes open an issue first.

GitHub: https://github.com/Frictionalfor/recon-cli
