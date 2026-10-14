#!/usr/bin/env bash
# Deploy Recon Suite on Ubuntu: pm2 app process + nginx + Let's Encrypt certificate.
# Usage (from the repo on the server):  sudo bash deploy/deploy.sh
# Prereqs: DNS A/AAAA for $DOMAIN points at this machine, ports 80/443 open, Node 20+ and npm installed.
# The app runs from this checkout as the user who owns it (override with APP_USER=...).
# It first runs `git pull --ff-only` as the checkout owner (skip with SKIP_PULL=1).
# Safe to re-run: it stops the existing pm2 process, rebuilds, starts it again and reuses the certificate.
# Optional: put NVD_API_KEY=... in /etc/reconlite.env (chmod 600) for higher NVD rate limits.
set -euo pipefail

DOMAIN="${DOMAIN:-recon.farvees.xyz}"
PORT="${PORT:-3002}"
APP_NAME="${APP_NAME:-reconlite}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
APP_DIR="$REPO"   # run from the current checkout, no copy
APP_USER="${APP_USER:-$(stat -c %U "$REPO")}"   # owner of the checkout runs build + pm2
APP_HOME="$(getent passwd "$APP_USER" | cut -d: -f6)"
CONF_SRC="$HERE/$DOMAIN.conf"

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo bash deploy/deploy.sh"; exit 1; }
[ -f "$CONF_SRC" ] || { echo "missing $CONF_SRC"; exit 1; }
command -v node >/dev/null || { echo "Node.js not found. Install Node 20+ first."; exit 1; }
[ "$APP_USER" != "root" ] || echo "note: running the app as root; consider APP_USER=<unprivileged user>"

# Run a command as the app user with the current PATH (so node/npm/pm2 are found under sudo).
as_app() { sudo -u "$APP_USER" -H env "PATH=$PATH" "$@"; }

# Update the checkout first. Re-exec afterwards so bash runs the freshly pulled script, not a half-read old one.
if [ -z "${DEPLOY_PULLED:-}" ] && [ -z "${SKIP_PULL:-}" ] && [ -d "$REPO/.git" ]; then
  echo "[0/6] git pull in $REPO as $APP_USER"
  as_app git -C "$REPO" pull --ff-only
  export DEPLOY_PULLED=1
  exec bash "$HERE/deploy.sh" "$@"
fi

echo "[1/6] installing nginx, certbot and pm2"
apt-get update -y
apt-get install -y nginx certbot python3-certbot-nginx
command -v pm2 >/dev/null || npm install -g pm2

echo "[2/6] stopping existing pm2 process (if any)"
as_app pm2 delete "$APP_NAME" >/dev/null 2>&1 || true
# Retire the old systemd unit from earlier deployments so it cannot hold the port.
if systemctl list-unit-files | grep -q '^reconlite.service'; then
  systemctl disable --now reconlite || true
fi

echo "[3/6] building app in $APP_DIR as $APP_USER"
as_app bash -c "cd '$APP_DIR' && npm ci && npm run build"

echo "[4/6] starting app with pm2 on 127.0.0.1:$PORT"
NVD_API_KEY=""
if [ -f /etc/reconlite.env ]; then
  NVD_API_KEY="$(grep -E '^NVD_API_KEY=' /etc/reconlite.env | head -n1 | cut -d= -f2- || true)"
fi
as_app env "NODE_ENV=production" "NVD_API_KEY=$NVD_API_KEY" \
  pm2 start npm --name "$APP_NAME" --cwd "$APP_DIR" -- run start -- -H 127.0.0.1 -p "$PORT"
as_app pm2 save
# Restart pm2 and the saved process list on boot.
env "PATH=$PATH" pm2 startup systemd -u "$APP_USER" --hp "$APP_HOME" >/dev/null

echo "[5/6] nginx: certificate"
SITE="/etc/nginx/sites-available/$DOMAIN"
if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
  # Temporary HTTP-only site so certbot can validate before the real config needs the cert files.
  cat > "$SITE" <<EOF
server { listen 80; listen [::]:80; server_name $DOMAIN; root /var/www/html; }
EOF
  ln -sf "$SITE" "/etc/nginx/sites-enabled/$DOMAIN"
  rm -f /etc/nginx/sites-enabled/default
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
  certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email
else
  echo "certificate already present, skipping"
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

sleep 3
if curl -fsS -o /dev/null "http://127.0.0.1:$PORT"; then
  echo "app is up on 127.0.0.1:$PORT"
else
  echo "WARNING: app not responding yet. Check: sudo -u $APP_USER pm2 logs $APP_NAME"
fi
as_app pm2 status "$APP_NAME" || true
echo "done: https://$DOMAIN"
