#!/data/data/com.termux/files/usr/bin/bash

# termux-setup.sh — Recon CLI v1.1
# Sets up Recon CLI on Termux (Android) without root.
# Usage: bash termux-setup.sh

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}[ok]${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}[!] ${RESET}  $1"; }
fail() { echo -e "  ${RED}[!!]${RESET}  $1"; }
info() { echo -e "  ${CYAN}[*] ${RESET}  $1"; }

echo ""
echo "+======================================+"
echo "|   Recon CLI v1.1 — Termux Setup      |"
echo "+======================================+"
echo ""

# ── Termux check ─────────────────────────────────────────
if [ ! -d "/data/data/com.termux" ]; then
    fail "This script is for Termux only."
    echo "    For Kali/Debian run: sudo bash setup.sh"
    exit 1
fi

# Ensure PREFIX is set (it always is in Termux but be safe)
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"

# ── Update packages ──────────────────────────────────────
info "Updating package lists..."
pkg update -y 2>/dev/null || warn "pkg update had errors — continuing anyway"

# ── Python ───────────────────────────────────────────────
info "Checking Python..."
if command -v python3 &>/dev/null || command -v python &>/dev/null; then
    ok "python already installed"
else
    info "Installing python..."
    pkg install -y python && ok "python installed" || { fail "python install failed"; exit 1; }
fi

# ── pip check ────────────────────────────────────────────
if ! command -v pip3 &>/dev/null && ! command -v pip &>/dev/null; then
    info "Installing pip..."
    pkg install -y python-pip && ok "pip installed" || { fail "pip install failed"; exit 1; }
fi

PIP=$(command -v pip3 || command -v pip)

# ── System tools ─────────────────────────────────────────
info "Installing system tools..."

install_pkg() {
    local bin=$1
    local pkg_name=${2:-$1}
    if command -v "$bin" &>/dev/null; then
        ok "$bin already installed"
    else
        info "Installing $pkg_name..."
        pkg install -y "$pkg_name" && ok "$pkg_name installed" \
            || warn "$pkg_name install failed — some features may be limited"
    fi
}

install_pkg nmap
install_pkg subfinder

# whatweb is not in Termux repos — built-in HTTP fingerprinting is used instead
info "Tech detection will use built-in HTTP fingerprinting (no whatweb needed)"

# ── Python dependencies ──────────────────────────────────
info "Installing Python dependencies..."
$PIP install -r "$INSTALL_DIR/requirements.txt" && ok "Python packages installed" \
    || { fail "pip install failed — check requirements.txt"; exit 1; }

# ── Launcher ─────────────────────────────────────────────
LAUNCHER="$PREFIX/bin/recon"
info "Creating global 'recon' command at $LAUNCHER..."

# Termux installs python3, may or may not have 'python' symlink
PYTHON_BIN=$(command -v python3 || command -v python)

cat > "$LAUNCHER" <<EOF
#!/data/data/com.termux/files/usr/bin/bash
$PYTHON_BIN "$INSTALL_DIR/recon.py" "\$@"
EOF

chmod +x "$LAUNCHER"

if command -v recon &>/dev/null; then
    ok "recon command registered successfully"
else
    warn "recon not found in PATH — you may need to restart Termux"
fi

echo ""
echo -e "${GREEN}[+] Setup complete. Run from anywhere:${RESET}"
echo "    recon example.com"
echo "    recon example.com -f"
echo "    recon example.com -dns -ssl -whois"
echo "    recon --help"
echo ""
echo -e "${YELLOW}Notes for Termux:${RESET}"
echo "  • Port scan uses TCP connect mode (-sT) — no root needed"
echo "  • Tech detection uses built-in HTTP fingerprinting — no whatweb needed"
echo "  • All modules work fully without root"
echo ""
