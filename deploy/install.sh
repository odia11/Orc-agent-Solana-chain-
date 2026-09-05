#!/usr/bin/env bash
# ── OrcAgent — one-shot server setup (Ubuntu/Debian) ──
#
# Run this ONCE on a fresh server, as root, from the repo directory:
#     sudo bash deploy/install.sh
#
# It is safe to run again: every step checks before it acts, so a re-run
# repairs a half-finished setup instead of duplicating it.
#
# What it does NOT do, on purpose:
#   - It never writes your secrets. It creates /etc/orcagent.env from the
#     template with placeholder values and stops; you fill it in yourself.
#   - It never touches an existing database. Your live data is copied over
#     separately (see deploy/README.md) so a mistake here cannot erase it.
set -euo pipefail

APP_USER=orcagent
APP_DIR=/opt/orcagent
DATA_DIR=/data
ENV_FILE=/etc/orcagent.env
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say(){ printf '\n\033[1;33m▸ %s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "Run this with sudo."; exit 1; }

say "Installing system packages"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nginx sqlite3 curl ca-certificates

say "Creating the service user (no login shell — it only runs the app)"
id -u "$APP_USER" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "$APP_USER"

say "Installing the application into $APP_DIR"
mkdir -p "$APP_DIR"
# --delete keeps the deployed copy exactly matching the repo, but never
# reaches into $DATA_DIR, which lives outside $APP_DIR precisely so that
# redeploying can't touch the database.
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete --exclude '.git' --exclude '__pycache__' --exclude '*.db' "$REPO_DIR"/ "$APP_DIR"/
else
  cp -r "$REPO_DIR"/. "$APP_DIR"/
fi
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

say "Creating the data directory ($DATA_DIR)"
# The app writes its database, logs, backups and heartbeat here. It picks
# /data automatically when it exists (see _DATA_DIR in dashboard.py), which
# is what keeps your data outside the deployed code.
mkdir -p "$DATA_DIR/backups"
chown -R "$APP_USER:$APP_USER" "$DATA_DIR"

say "Building the Python environment"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
chown -R "$APP_USER:$APP_USER" "$APP_DIR/venv"

say "Preparing the environment file ($ENV_FILE)"
if [ -f "$ENV_FILE" ]; then
  echo "  already exists — left untouched so your secrets are not overwritten"
else
  cp "$REPO_DIR/deploy/env.example" "$ENV_FILE"
  echo "  created from the template — FILL IT IN before starting the service"
fi
# Readable only by root and the service user: this file holds the encryption
# key that every stored wallet key depends on.
chown root:"$APP_USER" "$ENV_FILE"
chmod 640 "$ENV_FILE"

say "Installing the systemd services"
cp "$REPO_DIR/deploy/orcagent.service"         /etc/systemd/system/orcagent.service
cp "$REPO_DIR/deploy/orcagent-monitor.service" /etc/systemd/system/orcagent-monitor.service
systemctl daemon-reload
systemctl enable orcagent orcagent-monitor >/dev/null

say "Installing the nginx site"
cp "$REPO_DIR/deploy/nginx-orcagent.conf" /etc/nginx/sites-available/orcagent
ln -sf /etc/nginx/sites-available/orcagent /etc/nginx/sites-enabled/orcagent
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

cat <<EOF

────────────────────────────────────────────────────────────
Setup complete. Three things left, in this order:

  1. Fill in your secrets:
         nano $ENV_FILE

     ENCRYPTION_KEY must be EXACTLY the value from Railway.
     A different key makes every stored wallet key unreadable.

  2. Copy your live database across (see deploy/README.md),
     otherwise the app starts empty — no users, no trades.

  3. Start it:
         systemctl start orcagent orcagent-monitor
         systemctl status orcagent
         journalctl -u orcagent -f

Then point your domain at this server and run:
         certbot --nginx -d orcagent.fun -d www.orcagent.fun
────────────────────────────────────────────────────────────
EOF
