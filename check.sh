#!/bin/bash

# check.sh — Recon CLI v1.1
# Checks all required tools and Python dependencies.
# Works on both Kali/Debian and Termux (Android).

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

# ── Detect environment ───────────────────────────────────
IS_TERMUX=false
if [ -d "/data/data/com.termux" ]; then
    IS_TERMUX=true
    PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
fi

echo ""
echo "+======================================+"
echo "|  Recon CLI v1.1 — Dependency Check   |"
echo "+======================================+"
if $IS_TERMUX; then
    echo -e "  ${CYAN}Environment: Termux (Android)${RESET}"
else
    echo -e "  ${CYAN}Environment: Linux (Kali/Debian)${RESET}"
fi
echo ""

# ── Python ───────────────────────────────────────────────
echo -e "${CYAN}Python${RESET}"

PYTHON=$(command -v python3 || command -v python)
if [ -n "$PYTHON" ]; then
    VER=$($PYTHON --version 2>&1)
    ok "python ($VER)"
else
    fail "python not found"
    if $IS_TERMUX; then
        info "Fix: pkg install python"
    else
        info "Fix: sudo apt install python3"
    fi
fi

PIP=$(command -v pip3 || command -v pip)
if [ -n "$PIP" ]; then
    ok "pip"
else
    fail "pip not found"
    if $IS_TERMUX; then
        info "Fix: pkg install python-pip"
        pkg install -y python-pip && ok "pip installed" || fail "pip install failed"
    else
        info "Fix: sudo apt install python3-pip"
        sudo apt install -y python3-pip && ok "pip installed" || fail "pip install failed"
    fi
fi

echo ""

# ── Python packages ──────────────────────────────────────
echo -e "${CYAN}Python Packages${RESET}"

PYTHON_BIN=$(command -v python3 || command -v python)

check_py_pkg() {
    local import_name=$1
    local pkg_name=${2:-$1}
    if $PYTHON_BIN -c "import $import_name" &>/dev/null; then
        ok "$pkg_name"
    else
        warn "$pkg_name not found — installing..."
        if $IS_TERMUX; then
            $PIP install "$pkg_name" && ok "$pkg_name installed" || fail "$pkg_name install failed"
        else
            $PIP install "$pkg_name" --break-system-packages && ok "$pkg_name installed" || fail "$pkg_name install failed"
        fi
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
        return
    fi

    if [ "$optional" = "true" ]; then
        warn "$cmd not found (optional) — attempting install..."
    else
        warn "$cmd not found — attempting install..."
    fi

    if $IS_TERMUX; then
        pkg install -y "$pkg" && ok "$cmd installed" || warn "$cmd install failed — feature may be limited"
    else
        sudo apt install -y "$pkg" && ok "$cmd installed" || {
            [ "$optional" = "true" ] \
                && warn "$cmd install failed — feature may be limited" \
                || fail "$cmd install failed"
        }
    fi
}

check_tool nmap

# whatweb — Kali: apt, Termux: ruby gem
if command -v whatweb &>/dev/null; then
    ok "whatweb"
else
    if $IS_TERMUX; then
        warn "whatweb not found — attempting install via Ruby gem..."
        pkg install -y ruby && gem install whatweb \
            && ok "whatweb installed" \
            || warn "whatweb install failed — built-in HTTP fingerprinting will be used"
    else
        check_tool whatweb
    fi
fi

# subfinder
if command -v subfinder &>/dev/null; then
    ok "subfinder"
else
    warn "subfinder not found — attempting install..."
    if $IS_TERMUX; then
        pkg install -y subfinder && ok "subfinder installed" \
            || warn "subfinder install failed — subdomain scan uses DNS bruteforce only"
    else
        sudo apt install -y subfinder 2>/dev/null && ok "subfinder installed via apt" || {
            if command -v go &>/dev/null; then
                go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
                    && ok "subfinder installed via go" \
                    || warn "subfinder install failed — subdomain scan uses DNS bruteforce only"
            else
                warn "subfinder install failed — subdomain scan uses DNS bruteforce only"
            fi
        }
    fi
fi

echo ""

# ── Launcher check ───────────────────────────────────────
echo -e "${CYAN}Launcher${RESET}"

if command -v recon &>/dev/null; then
    ok "recon command found at $(command -v recon)"
else
    warn "recon command not found in PATH"
    if $IS_TERMUX; then
        info "Run: bash termux-setup.sh"
    else
        info "Run: sudo bash setup.sh"
    fi
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
