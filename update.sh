#!/bin/bash

# update.sh — Recon CLI
# Pulls latest commits from GitHub, updates dependencies, re-registers launcher.
# Works on Linux and Termux. Run: bash update.sh

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_URL="https://github.com/Frictionalfor/recon-cli"
RAW_URL="https://raw.githubusercontent.com/Frictionalfor/recon-cli/main"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}[ok]${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}[!] ${RESET}  $1"; }
fail() { echo -e "  ${RED}[!!]${RESET}  $1"; }
info() { echo -e "  ${CYAN}[*] ${RESET}  $1"; }

IS_TERMUX=false
[ -d "/data/data/com.termux" ] && IS_TERMUX=true

echo ""
echo "+======================================+"
echo "|      Recon CLI — Updater             |"
echo "+======================================+"
echo ""

# ── Check git is installed ───────────────────────────────
if ! command -v git &>/dev/null; then
    warn "git not found — installing..."
    if $IS_TERMUX; then
        pkg install -y git && ok "git installed" || { fail "git install failed"; exit 1; }
    else
        sudo apt install -y git && ok "git installed" || { fail "git install failed"; exit 1; }
    fi
fi

# ── Must be a git repo ───────────────────────────────────
if [ ! -d "$INSTALL_DIR/.git" ]; then
    fail "This directory is not a git repository."
    echo ""
    echo "  To enable updates, re-clone the repo:"
    echo "    rm -rf $INSTALL_DIR"
    echo "    git clone $REPO_URL"
    if $IS_TERMUX; then
        echo "    cd recon-cli && bash termux-setup.sh"
    else
        echo "    cd recon-cli && sudo bash setup.sh"
    fi
    exit 1
fi

# ── Get current commit hash ──────────────────────────────
CURRENT_COMMIT=$(git -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null)
CURRENT_VERSION="unknown"
[ -f "$INSTALL_DIR/version.txt" ] && CURRENT_VERSION=$(cat "$INSTALL_DIR/version.txt" | tr -d '[:space:]')

info "Current version : v$CURRENT_VERSION"
info "Current commit  : ${CURRENT_COMMIT:0:7}"
info "Fetching latest from GitHub..."

# ── Fetch without merging first ──────────────────────────
git -C "$INSTALL_DIR" fetch origin main --quiet 2>&1
if [ $? -ne 0 ]; then
    fail "Could not reach GitHub. Check your internet connection."
    exit 1
fi

# ── Check if there are new commits ───────────────────────
LATEST_COMMIT=$(git -C "$INSTALL_DIR" rev-parse origin/main 2>/dev/null)
LATEST_VERSION="unknown"

# Try to get latest version.txt from remote
if command -v curl &>/dev/null; then
    LATEST_VERSION=$(curl -fsSL "$RAW_URL/version.txt" 2>/dev/null | tr -d '[:space:]')
elif command -v wget &>/dev/null; then
    LATEST_VERSION=$(wget -qO- "$RAW_URL/version.txt" 2>/dev/null | tr -d '[:space:]')
fi

echo ""
echo -e "  Latest version : ${GREEN}v$LATEST_VERSION${RESET}"
echo -e "  Latest commit  : ${GREEN}${LATEST_COMMIT:0:7}${RESET}"
echo ""

if [ "$CURRENT_COMMIT" = "$LATEST_COMMIT" ]; then
    ok "Already up to date. Nothing to update."
    echo ""
    exit 0
fi

# ── Show what changed ────────────────────────────────────
echo -e "  ${CYAN}Changes since your last update:${RESET}"
git -C "$INSTALL_DIR" log HEAD..origin/main --oneline --no-decorate 2>/dev/null | while read line; do
    echo -e "    ${YELLOW}•${RESET} $line"
done
echo ""

# ── Pull latest commits ──────────────────────────────────
info "Applying updates..."
git -C "$INSTALL_DIR" pull origin main 2>&1
if [ $? -ne 0 ]; then
    fail "git pull failed."
    echo ""
    echo "  If you have local changes, stash them first:"
    echo "    git -C $INSTALL_DIR stash"
    echo "    bash update.sh"
    exit 1
fi
ok "Code updated to latest commit"

# ── Update Python dependencies ───────────────────────────
info "Updating Python dependencies..."
PIP=$(command -v pip3 || command -v pip)
if [ -z "$PIP" ]; then
    warn "pip not found — skipping dependency update"
else
    if $IS_TERMUX; then
        $PIP install -r "$INSTALL_DIR/requirements.txt" --quiet \
            && ok "Python packages updated" \
            || warn "pip install had errors — run manually: pip install -r requirements.txt"
    else
        $PIP install -r "$INSTALL_DIR/requirements.txt" --break-system-packages --quiet \
            && ok "Python packages updated" \
            || warn "pip install had errors — run manually: pip install -r requirements.txt"
    fi
fi

# ── Re-register launcher ─────────────────────────────────
info "Re-registering recon command..."
if $IS_TERMUX; then
    PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
    LAUNCHER="$PREFIX/bin/recon"
    PYTHON_BIN=$(command -v python3 || command -v python)
    cat > "$LAUNCHER" <<EOF
#!/data/data/com.termux/files/usr/bin/bash
$PYTHON_BIN "$INSTALL_DIR/recon.py" "\$@"
EOF
    chmod +x "$LAUNCHER" && ok "Launcher updated"
else
    sudo tee /usr/local/bin/recon > /dev/null <<EOF
#!/bin/bash
python3 "$INSTALL_DIR/recon.py" "\$@"
EOF
    sudo chmod +x /usr/local/bin/recon && ok "Launcher updated"
fi

# ── Show new version ─────────────────────────────────────
NEW_VERSION="unknown"
[ -f "$INSTALL_DIR/version.txt" ] && NEW_VERSION=$(cat "$INSTALL_DIR/version.txt" | tr -d '[:space:]')
NEW_COMMIT=$(git -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null)

echo ""
echo -e "${GREEN}[+] Update complete!${RESET}"
echo -e "    Version : v$CURRENT_VERSION → v$NEW_VERSION"
echo -e "    Commit  : ${CURRENT_COMMIT:0:7} → ${NEW_COMMIT:0:7}"
echo ""
echo "    Run: recon --help"
echo ""
