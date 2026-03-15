#!/bin/bash
set -e

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Installing Python dependencies..."
pip install -r "$INSTALL_DIR/requirements.txt" --break-system-packages

echo "[*] Installing system tools..."
sudo apt install -y nmap whatweb subfinder

echo "[*] Creating global 'recon' command..."

# Write a launcher script to /usr/local/bin/recon
sudo tee /usr/local/bin/recon > /dev/null <<EOF
#!/bin/bash
python3 "$INSTALL_DIR/recon.py" "\$@"
EOF

sudo chmod +x /usr/local/bin/recon

echo ""
echo "[+] Done. You can now run from anywhere:"
echo "    recon example.com --full"
echo "    recon example.com -sd"
echo "    recon --help"
