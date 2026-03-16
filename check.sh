#!/bin/bash

# check.sh — Recon CLI v1.1
# Checks all required tools and Python dependencies.
# Installs anything missing automatically.

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
PASS=0
FAIL=0

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}[ok]${RESET}  $1"; ((PASS++)); }
warn() { echo -e "  ${YELLOW}[!] ${RESET}  $1"; }
fail() { echo -e "  ${RED}[!!]${RESET}  $1"; ((FAIL++)); }
info() { echo -e "  ${CYAN}[*] ${RESET}  $1"; }

echo ""
echo "+======================================+"
echo "|  Recon CLI v1.1 — Dependency Check   |"
echo "+======================================+"
echo ""

# ── Python ───────────────────────────────────────────────
echo -e "${CYAN}Python${RESET}"

if command -v python3 &>/dev/null; then
    VER=$(python3 --version 2>&1)
    ok "python3 ($VER)"
else
    fail "python3 not found"
    info "Fix: sudo apt install python3"
fi

if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
    ok "pip"
else
    fail "pip not found"
    info "Fix: sudo apt install python3-pip"
    info "Attempting install..."
    sudo apt install -y python3-pip && ok "pip installed" || fail "pip install failed"
fi

echo ""

# ── Python packages ──────────────────────────────────────
echo -e "${CYAN}Python Packages${RESET}"

PIP=$(command -v pip3 || command -v pip)

check_py_pkg() {
    local import_name=$1
    local pkg_name=${2:-$1}
    if python3 -c "import $import_name" &>/dev/null; then
        ok "$pkg_name"
    else
        warn "$pkg_name not found — installing..."
        $PIP install "$pkg_name" --break-system-packages && ok "$pkg_name installed" || fail "$pkg_name install failed"
    fi
}

check_py_pkg requests
check_py_pkg colorama
check_py_pkg dns dnspython
check_py_pkg whois python-whois

echo ""

# ── System tools ─────────────────────────────────────────
echo -e "${CYAN}System Tools${RESET}"

check_tool() {
    local cmd=$1
    local pkg=${2:-$1}
    local optional=${3:-false}

    if command -v "$cmd" &>/dev/null; then
        ok "$cmd"
    else
        if [ "$optional" = "true" ]; then
            warn "$cmd not found (optional) — installing..."
        else
            warn "$cmd not found — installing..."
        fi
        sudo apt install -y "$pkg" && ok "$cmd installed" || {
            if [ "$optional" = "true" ]; then
                warn "$cmd install failed — some features may be limited"
            else
                fail "$cmd install failed"
            fi
        }
    fi
}

check_tool nmap
check_tool whatweb

# subfinder — try apt first, fallback to go
if command -v subfinder &>/dev/null; then
    ok "subfinder"
else
    warn "subfinder not found — attempting install..."
    if sudo apt install -y subfinder &>/dev/null; then
        ok "subfinder installed via apt"
    elif command -v go &>/dev/null; then
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
            && ok "subfinder installed via go" \
            || warn "subfinder install failed — subdomain scan will use DNS bruteforce only"
    else
        warn "subfinder install failed — subdomain scan will use DNS bruteforce only"
    fi
fi

echo ""

# ── Launcher check ───────────────────────────────────────
echo -e "${CYAN}Launcher${RESET}"

if command -v recon &>/dev/null; then
    ok "recon command found at $(command -v recon)"
else
    warn "recon command not found in PATH"
    info "Run bash setup.sh to install it"
fi

echo ""

# ── Summary ──────────────────────────────────────────────
echo -e "${CYAN}────────────────────────────────────────${RESET}"
if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}All checks passed ($PASS ok)${RESET}"
else
    echo -e "  ${RED}$FAIL issue(s) found${RESET} — $PASS passed"
fi
echo ""
