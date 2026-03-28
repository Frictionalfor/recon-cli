#!/bin/bash

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "+======================================+"
echo "|       Recon CLI  v1.1 — Setup        |"
echo "+======================================+"
echo ""

# ── Must not be run on Termux ────────────────────────────
if [ -d "/data/data/com.termux" ]; then
    echo "[!] Termux detected. Run termux-setup.sh instead."
    exit 1
fi

# ── Python check ─────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "[!] python3 not found. Install it: sudo apt install python3"
    exit 1
fi

# ── pip check ────────────────────────────────────────────
if ! command -v pip3 &>/dev/null && ! command -v pip &>/dev/null; then
    echo "[*] pip not found — installing..."
    sudo apt install -y python3-pip
fi

PIP=$(command -v pip3 || command -v pip)

# ── Python dependencies ──────────────────────────────────
echo "[*] Installing Python dependencies..."
$PIP install -r "$INSTALL_DIR/requirements.txt" --break-system-packages
if [ $? -ne 0 ]; then
    echo "[!] pip install failed. Try: pip install -r requirements.txt"
    exit 1
fi

# ── System tools ─────────────────────────────────────────
echo "[*] Installing system tools..."

install_if_missing() {
    local cmd=$1
    local pkg=${2:-$1}
    if command -v "$cmd" &>/dev/null; then
        echo "    [ok] $cmd already installed"
    else
        echo "    [+] Installing $pkg..."
        sudo apt install -y "$pkg" || echo "    [!] Failed to install $pkg — skipping"
    fi
}

install_if_missing nmap
install_if_missing whatweb

# subfinder — apt first, go fallback
if command -v subfinder &>/dev/null; then
    echo "    [ok] subfinder already installed"
else
    echo "    [+] Installing subfinder..."
    sudo apt install -y subfinder 2>/dev/null || {
        if command -v go &>/dev/null; then
            echo "    [+] apt failed — trying go install..."
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
                && echo "    [ok] subfinder installed via go" \
                || echo "    [!] subfinder install failed — subdomain scan will use DNS bruteforce only"
        else
            echo "    [!] subfinder not available — subdomain scan will use DNS bruteforce only"
        fi
    }
fi

# ── Global launcher ──────────────────────────────────────
echo "[*] Creating global 'recon' command..."

sudo tee /usr/local/bin/recon > /dev/null <<EOF
#!/bin/bash
python3 "$INSTALL_DIR/recon.py" "\$@"
EOF

sudo chmod +x /usr/local/bin/recon

echo ""
echo "[+] Setup complete. Run from anywhere:"
echo "    recon example.com"
echo "    recon example.com -f"
echo "    recon example.com -dns -ssl -whois"
echo "    recon --help"
echo ""
