# Recon CLI — Changelog

All notable changes to this project are documented here.

---

## v1.2 — Current

### New Features
- `--diff OLD NEW` — compare two JSON scan reports and show what changed (ports, subdomains, issues, SSL expiry, headers)
- `--history` — list all auto-saved scans from `~/.recon/history/` with target, risk, date, and file path
- `--silent` — suppress all progress lines, only print the final report
- `--rate-limit SECONDS` — delay between scans when using `-targets` for bulk scanning
- `-w FILE` — custom wordlist for subdomain bruteforce
- Auto-update system — `update.sh` checks GitHub for newer version and applies it with one command
- Update notification — tool notifies on startup if a newer version is available on GitHub
- Scan history — every scan auto-saved to `~/.recon/history/<domain>_<timestamp>.json`
- Built-in HTTP fingerprinting fallback for tech detection — detects 50+ technologies from HTTP headers, HTML content, cookies, and JS paths. Works on Termux and anywhere WhatWeb is unavailable

### Improvements
- Subdomain wordlist expanded from ~40 to 200+ entries
- Port scan now captures service version from nmap (e.g. `nginx 1.24.0`)
- Header check now detects weak header values (e.g. `CSP: unsafe-inline`, `X-XSS-Protection: 0`)
- Weak headers shown as separate `[~]` category in report and JSON
- DNS resolver uses public nameservers (`8.8.8.8`, `1.1.1.1`) — fixes crash on Termux where `/etc/resolv.conf` does not exist
- `clean_pycache()` now runs at startup and after every scan, covering project root + history dir
- `datetime.utcnow()` replaced with timezone-aware equivalent (Python 3.12+ compatibility)

### Bug Fixes
- Fixed `ssl_scan._parse_cert` to handle both flat and nested tuple formats from Python's ssl module
- Fixed `--history` crashing due to variable name collision with `domain`
- Fixed validator regex missing closing `$` anchor

---

## v1.1

### New Features
- `-dns` — DNS records lookup (A, AAAA, MX, NS, TXT, CNAME) via `dnspython`
- `-ssl` — SSL/TLS certificate info (expiry, issuer, SANs) via Python stdlib `ssl`
- `-whois` — WHOIS lookup (registrar, creation/expiry dates, nameservers) via `python-whois`
- `-json` / `-txt` output flags — save report as JSON (default) or plain text
- JSON output is now fully structured and machine-readable
- `check.sh` — dependency checker that auto-installs missing tools, works on Linux and Termux
- `termux-setup.sh` — dedicated setup script for Termux (Android), no root required
- Port scan auto-detects root — uses `-sT` (TCP connect) on non-root/Termux, `-sV` on root

### Improvements
- JSON structure redesigned: `tool`, `scan_id`, `scan`, `risk`, `summary`, `ip_info`, `security_headers`, `dns_records`, `timings` blocks
- Issues restructured with `type`, `name`, `risk`, `severity_score`, `description`, `source` fields
- Port numbers stored as integers (not strings)
- Service names normalized (e.g. `ssl/https` → `https`)
- Country names normalized with `.title()` (e.g. `UNITED STATES` → `United States`)
- Subdomains in JSON stored as `{ host, type }` objects
- Timing keys standardized to `snake_case` (`subdomain_scan`, `port_scan`, etc.)
- `scan_id` added (`recon_YYYYMMDD_HHMMSS`)
- `target_protocol`, `duration_seconds`, `ip_info` added to JSON
- `status: "open"` added to all issues
- Banner updated to v1.1

### Bug Fixes
- Fixed `Meta-Author`, `Meta-Generator`, `X-Powered-By` and similar WhatWeb noise appearing in tech detection
- Fixed help menu showing before banner — banner now prints before argparse output
- Fixed `setup.sh` crashing on subfinder apt failure due to `set -e`

---

## v1.0 — Initial Release

### Features
- `-sd` — subdomain enumeration via DNS bruteforce + subfinder/sublist3r
- `-p` — port scanning via nmap `-sV --open`
- `-t` — technology detection via WhatWeb
- `-head` — HTTP security header analysis (6 headers)
- `-f` — full scan (all modules)
- `-targets FILE` — bulk scan from file
- `-o FILE` — save report as plain text
- Color-coded terminal report with at-a-glance summary, target info, subdomains, ports, technologies, headers, vulnerability issues, and scan timings
- Rule-based vulnerability analysis (port rules + header rules + outdated server detection)
- Weighted risk scoring: High=3, Medium=2, Low=1
- Domain validation and sanitization
- `__pycache__` cleanup after every run
- `setup.sh` for one-command install on Kali/Debian

---

GitHub: https://github.com/Frictionalfor/recon-cli
