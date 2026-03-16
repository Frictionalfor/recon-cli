#!/bin/bash
set -e

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "+======================================+"
echo "|       Recon CLI  v1.1 — Setup        |"
echo "+======================================+"
echo ""

# ── Python check ────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "[!] python3 is not installed. Install it first: sudo apt install python3"
    exit 1
fi

if ! command -v pip &>/dev/null && ! command -v pip3 &>/dev/null; then
    echo "[*] pip not found — installing..."
    sudo apt install -y python3-pip
fi

PIP=$(command -v pip3 || command -v pip)

# ── Python dependencies ──────────────────────────────────
echo "[*] Installing Python dependencies..."
$PIP install -r "$INSTALL_DIR/requirements.txt" --break-system-packages

# ── System tools ─────────────────────────────────────────
echo "[*] Installing system tools..."

install_if_missing() {
    local cmd=$1
    local pkg=${2:-$1}
    if ! command -v "$cmd" &>/dev/null; then
        echo "    [+] Installing $pkg..."
        sudo apt install -y "$pkg"
    else
        echo "    [ok] $cmd already installed"
    fi
}

install_if_missing nmap
install_if_missing whatweb
install_if_missing subfinder

# subfinder may not be in apt on all systems — fallback to go install
if ! command -v subfinder &>/dev/null; then
    if command -v go &>/dev/null; then
        echo "    [+] Installing subfinder via go..."
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    else
        echo "    [!] subfinder not found and go is not installed."
        echo "        Subdomain scan will fall back to DNS bruteforce only."
    fi
fi

# ── Global launcher ──────────────────────────────────────
echo "[*] Creating global 'recon' command..."

sudo tee /usr/local/bin/recon > /dev/null <<EOF
#!/bin/bash
python3 "$INSTALL_DIR/recon.py" "\$@"
EOF

sudo chmod +x /usr/local/bin/recon

echo ""
echo "[+] Done. You can now run from anywhere:"
echo "    recon example.com"
echo "    recon example.com -f"
echo "    recon example.com -dns"
echo "    recon example.com -ssl"
echo "    recon example.com -whois"
echo "    recon --help"
echo ""
