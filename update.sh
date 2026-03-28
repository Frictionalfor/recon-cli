#!/bin/bash

# update.sh — Recon CLI
# Checks for updates from GitHub and applies them with one command.
# Works on both Linux and Termux.
# Usage: bash update.sh

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="https://github.com/Frictionalfor/recon-cli"
RAW="https://raw.githubusercontent.com/Frictionalfor/recon-cli/main"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}[ok]${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}[!] ${RESET}  $1"; }
fail() { echo -e "  ${RED}[!!]${RESET}  $1"; }
info() { echo -e "  ${CYAN}[*] ${RESET}  $1"; }

# ── Detect environment ───────────────────────────────────
IS_TERMUX=false
[ -d "/data/data/com.termux" ] && IS_TERMUX=true

echo ""
echo "+======================================+"
echo "|      Recon CLI — Update Check        |"
echo "+======================================+"
echo ""

# ── Check git ────────────────────────────────────────────
if ! command -v git &>/dev/null; then
    fail "git not found."
    if $IS_TERMUX; then
        info "Installing git: pkg install git"
        pkg install -y git
    else
        info "Installing git: sudo apt install git"
        sudo apt install -y git
    fi
fi

# ── Get current version ──────────────────────────────────
CURRENT_VERSION="unknown"
if [ -f "$INSTALL_DIR/version.txt" ]; then
    CURRENT_VERSION=$(cat "$INSTALL_DIR/version.txt" | tr -d '[:space:]')
fi

# ── Get latest version from GitHub ───────────────────────
info "Checking latest version..."
LATEST_VERSION=$(curl -fsSL "$RAW/version.txt" 2>/dev/null | tr -d '[:space:]')

if [ -z "$LATEST_VERSION" ]; then
    # fallback: try wget
    LATEST_VERSION=$(wget -qO- "$RAW/version.txt" 2>/dev/null | tr -d '[:space:]')
fi

if [ -z "$LATEST_VERSION" ]; then
    fail "Could not reach GitHub. Check your internet connection."
    exit 1
fi

echo -e "  Current version : ${YELLOW}v$CURRENT_VERSION${RESET}"
echo -e "  Latest version  : ${GREEN}v$LATEST_VERSION${RESET}"
echo ""

# ── Compare versions ─────────────────────────────────────
if [ "$CURRENT_VERSION" = "$LATEST_VERSION" ]; then
    ok "Already up to date (v$CURRENT_VERSION)"
    echo ""
    exit 0
fi

echo -e "  ${CYAN}Update available: v$CURRENT_VERSION → v$LATEST_VERSION${RESET}"
echo ""

# ── Pull update ──────────────────────────────────────────
info "Pulling latest changes from GitHub..."

if [ -d "$INSTALL_DIR/.git" ]; then
    git -C "$INSTALL_DIR" pull origin main && ok "Code updated" || {
        fail "git pull failed. Try: git -C $INSTALL_DIR pull origin main"
        exit 1
    }
else
    fail "Not a git repo. Re-clone to enable auto-updates:"
    echo "    git clone $REPO"
    exit 1
fi

# ── Update Python dependencies ───────────────────────────
info "Updating Python dependencies..."
PIP=$(command -v pip3 || command -v pip)
if $IS_TERMUX; then
    $PIP install -r "$INSTALL_DIR/requirements.txt" --quiet \
        && ok "Python packages updated"
else
    $PIP install -r "$INSTALL_DIR/requirements.txt" --break-system-packages --quiet \
        && ok "Python packages updated"
fi

# ── Re-register launcher (path may have changed) ─────────
info "Re-registering recon command..."
if $IS_TERMUX; then
    PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
    LAUNCHER="$PREFIX/bin/recon"
    PYTHON_BIN=$(command -v python3 || command -v python)
    cat > "$LAUNCHER" <<EOF
#!/data/data/com.termux/files/usr/bin/bash
$PYTHON_BIN "$INSTALL_DIR/recon.py" "\$@"
EOF
    chmod +x "$LAUNCHER" && ok "Launcher updated at $LAUNCHER"
else
    sudo tee /usr/local/bin/recon > /dev/null <<EOF
#!/bin/bash
python3 "$INSTALL_DIR/recon.py" "\$@"
EOF
    sudo chmod +x /usr/local/bin/recon && ok "Launcher updated at /usr/local/bin/recon"
fi

echo ""
echo -e "${GREEN}[+] Updated to v$LATEST_VERSION successfully.${RESET}"
echo "    Run: recon --help"
echo ""
