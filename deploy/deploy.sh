#!/usr/bin/env bash
# Deploy Recon Suite on Ubuntu: app build + systemd service + nginx + Let's Encrypt.
# Usage (from the repo on the server):  sudo EMAIL=you@example.com bash deploy/deploy.sh
# Prereqs: DNS A/AAAA for $DOMAIN points at this machine, ports 80/443 open, Node 20+ and npm installed.
# The app runs from this checkout as the user who owns it (override with APP_USER=...).
# Safe to re-run: it redeploys the app and reuses the existing certificate.
set -euo pipefail

DOMAIN="${DOMAIN:-recon.farvees.xyz}"
EMAIL="${EMAIL:?set EMAIL=you@example.com (used for certificate expiry notices)}"
PORT="${PORT:-3001}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
APP_DIR="$REPO"   # run from the current checkout, no copy
APP_USER="${APP_USER:-$(stat -c %U "$REPO")}"   # owner of the checkout runs build + service
CONF_SRC="$HERE/$DOMAIN.conf"

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo EMAIL=... bash deploy/deploy.sh"; exit 1; }
[ -f "$CONF_SRC" ] || { echo "missing $CONF_SRC"; exit 1; }
command -v node >/dev/null || { echo "Node.js not found. Install Node 20+ first."; exit 1; }

echo "[1/6] installing nginx + certbot"
apt-get update -y
apt-get install -y nginx certbot python3-certbot-nginx

echo "[2/6] building app in $APP_DIR as $APP_USER"
sudo -u "$APP_USER" bash -c "cd '$APP_DIR' && npm ci && npm run build"

echo "[3/6] installing systemd service (127.0.0.1:$PORT)"
cat > /etc/systemd/system/reconlite.service <<EOF
[Unit]
Description=Recon Suite (Next.js)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
WorkingDirectory=$APP_DIR
Environment=NODE_ENV=production
# Optional: put NVD_API_KEY=... in /etc/reconlite.env (chmod 600) for higher NVD rate limits.
EnvironmentFile=-/etc/reconlite.env
ExecStart=$(command -v npm) run start -- -H 127.0.0.1 -p $PORT
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable reconlite
systemctl restart reconlite

echo "[4/6] nginx: temporary HTTP-only site for certificate validation"
SITE="/etc/nginx/sites-available/$DOMAIN"
if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
  cat > "$SITE" <<EOF
server { listen 80; listen [::]:80; server_name $DOMAIN; root /var/www/html; }
EOF
  ln -sf "$SITE" "/etc/nginx/sites-enabled/$DOMAIN"
  rm -f /etc/nginx/sites-enabled/default
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx

  echo "[5/6] requesting certificate"
  certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL"
else
  echo "[5/6] certificate already present, skipping"
fi

echo "[6/6] installing real nginx config"
sed "s#127.0.0.1:[0-9]*#127.0.0.1:$PORT#g" "$CONF_SRC" > "$SITE"
ln -sf "$SITE" "/etc/nginx/sites-enabled/$DOMAIN"
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload nginx

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow 'Nginx Full'
fi

sleep 2
if curl -fsS -o /dev/null "http://127.0.0.1:$PORT"; then
  echo "app is up on 127.0.0.1:$PORT"
else
  echo "WARNING: app not responding yet. Check: journalctl -u reconlite -n 50"
fi
echo "done: https://$DOMAIN   logs: journalctl -u reconlite -f | tail -f /var/log/nginx/error.log"
