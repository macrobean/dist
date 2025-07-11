#!/bin/bash
# Macrobean Server Installer (macOS/Linux)

set -euo pipefail
trap 'echo "[!] Installation aborted."; exit 1' INT

clear
echo "\n🌱 Welcome to the Macrobean Server Installer"
echo "----------------------------------------"
echo "This script will guide you through setting up Macrobean on your system.\n"

OS="$(uname)"
if [[ "$OS" == "Darwin" ]]; then
  PLATFORM="macos"
elif [[ "$OS" == "Linux" ]]; then
  PLATFORM="linux"
else
  echo "[!] Unsupported OS: $OS"
  exit 1
fi

read -p "Custom port [default 8080]: " PORT
PORT=${PORT:-8080}

echo "Enable optional features:"
read -p " → Enable Lua support? [y/N]: " LUA
read -p " → Enable SQLite database? [y/N]: " DB
read -p " → Enable TLS/HTTPS? [y/N]: " TLS
read -p " → Enable dev mode (--dev)? [y/N]: " DEV
read -p " → Enable file watching (--watch)? [y/N]: " WATCH

FLAGS=""
[[ "$LUA" =~ ^[Yy]$ ]] && FLAGS+=" --lua"
[[ "$DB" =~ ^[Yy]$ ]] && FLAGS+=" --db"
[[ "$DEV" =~ ^[Yy]$ ]] && FLAGS+=" --dev"
[[ "$WATCH" =~ ^[Yy]$ ]] && FLAGS+=" --watch"

if [[ "$TLS" =~ ^[Yy]$ ]]; then
  read -p " → Enter your domain (e.g. example.com): " DOMAIN
  echo "🔍 Checking domain resolution..."
  PUBLIC_IP=$(curl -s https://api.ipify.org)
  DOMAIN_IP=$(dig +short "$DOMAIN" | tail -n1)
  echo " → Your public IP: $PUBLIC_IP"
  echo " → Domain points to: $DOMAIN_IP"
  if [[ "$PUBLIC_IP" == "$DOMAIN_IP" ]]; then
    echo "✅ Domain verified. Issuing TLS cert via certbot..."
    sudo certbot certonly --standalone -d "$DOMAIN"
    TLS_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    TLS_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    FLAGS+=" --tls --cert $TLS_CERT --key $TLS_KEY"
  else
    echo "⚠️  Domain mismatch. Reverting to local HTTP mode."
  fi
fi

read -p " → Provide path to site.zip or leave blank to use embedded ZIP: " ZIP_PATH
if [[ -n "$ZIP_PATH" ]]; then
  if [[ ! -f "$ZIP_PATH" ]]; then
    echo "[!] ZIP file not found: $ZIP_PATH"
    exit 1
  fi
  FLAGS+=" --zip $ZIP_PATH"
fi

INSTALL_DIR="/usr/local/bin"
sudo cp ./macrobean.com "$INSTALL_DIR/macrobean"
sudo chmod +x "$INSTALL_DIR/macrobean"

echo "\n Launching Macrobean Server..."
echo " → Command: macrobean --port $PORT $FLAGS"
eval "macrobean --port $PORT $FLAGS"
