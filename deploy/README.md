# Moving OrcAgent from Railway to your own server

Everything here is meant to be pasted into PuTTY. Work top to bottom.

## Before you start — the two things that can actually cost you

**1. `ENCRYPTION_KEY` must be copied exactly.**
Every user's trading key in the database is encrypted with it. A different
key does not reset anything — it makes every stored wallet permanently
unreadable, and the funds inside them unreachable through this app. Copy the
value from Railway character for character.

**2. Copy the database, or you start empty.**
Users, trades, open positions, calls, posts, fee history — all of it lives in
`orcagent.db`. A fresh install has none of it. Step 4 covers this, and does it
in an order where a mistake costs you nothing.

Also worth knowing: while both are running, **two copies of the bot are live
on the same wallets**. Do the cutover in one sitting and stop Railway as soon
as the new server answers (step 7).

---

## 1. Get the code onto the server

```bash
sudo apt-get update && sudo apt-get install -y git
sudo git clone https://github.com/odia11/social-multi-trading-chain-.git /root/orcagent-src
cd /root/orcagent-src
```

## 2. Run the installer

```bash
sudo bash deploy/install.sh
```

Installs Python, nginx and sqlite, creates a locked-down `orcagent` service
user, builds the virtualenv, and installs the systemd service and nginx site.
It does not write any secret and does not touch any database.

## 3. Fill in your secrets

```bash
sudo nano /etc/orcagent.env
```

Every value comes from Railway → your service → **Variables**. Click the eye
icon to reveal each one. `ENCRYPTION_KEY` first, and check it twice.

## 4. Bring your live database across

On Railway, open a shell to your service (Railway → your service → the `⋮`
menu → **Shell**) and check where the data actually is:

```bash
ls -la /data
```

Download `orcagent.db` from there. If Railway's UI has no download, print it
as base64 and copy the text out:

```bash
base64 /data/orcagent.db
```

Then on your server, paste it back:

```bash
sudo systemctl stop orcagent            # nothing should be writing during the copy
cat > /tmp/db.b64                       # paste, then press Ctrl-D
sudo base64 -d /tmp/db.b64 > /data/orcagent.db.new

# Only replace the live file once the copy proves to be a valid database.
sudo sqlite3 /data/orcagent.db.new "PRAGMA integrity_check;"    # must print: ok
sudo sqlite3 /data/orcagent.db.new "SELECT COUNT(*) FROM users;"  # must look right

sudo mv /data/orcagent.db.new /data/orcagent.db
sudo chown orcagent:orcagent /data/orcagent.db
rm /tmp/db.b64
```

The check before the `mv` is the point: a truncated paste is caught while the
old file is still untouched.

## 5. Start it

```bash
sudo systemctl start orcagent orcagent-monitor
sudo systemctl status orcagent
sudo journalctl -u orcagent -f
```

(`orcagent-monitor` is the Telegram uptime alerter. It stays silent unless
you filled in `TELEGRAM_BOT_TOKEN`.)

In the log you should see the startup lines this app prints about itself:

```
[startup] ENCRYPTION_KEY fingerprint: ab12cd34 (sha256 prefix — not the key itself)
[startup] owner wallets (full admin rights): Cdn8Wfta…
[startup] gas sponsor wallet (EVM): 0x9adAd542…
[startup] gas sponsor wallet (Solana): 9zdKtt8p…
```

**Compare that `ENCRYPTION_KEY fingerprint` with the one in your Railway
logs.** Same fingerprint means the key came across correctly and every stored
wallet still decrypts. Different means stop and fix it before anyone trades.

Check it answers:

```bash
curl -s localhost:8080/health
```

## 6. Point the domain here and switch on HTTPS

At your DNS provider, point `orcagent.fun` and `www` at this server's IP
(an `A` record each). Wait until `ping orcagent.fun` shows the new IP, then:

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d orcagent.fun -d www.orcagent.fun
```

Certbot edits the nginx site for you and sets up automatic renewal.

## 7. Stop Railway

Only once the new server serves the site over HTTPS: in Railway, remove the
domain and pause or delete the service. Until you do, both copies of the bot
are trading the same wallets.

Also update anything that points at the old host — the callback URL in the X
Developer Portal has to match your domain exactly.

---

## Running it day to day

```bash
sudo systemctl restart orcagent orcagent-monitor   # restart
sudo journalctl -u orcagent -f                     # follow the logs
sudo journalctl -u orcagent --since "1 hour ago" | grep -i error
```

Deploy a new version:

```bash
cd /root/orcagent-src && sudo git pull
sudo bash deploy/install.sh          # safe to re-run; leaves /etc/orcagent.env and /data alone
sudo systemctl restart orcagent orcagent-monitor
```

Back up the database (do this on a schedule):

```bash
sudo sqlite3 /data/orcagent.db ".backup /data/backups/orcagent-$(date +%F).db"
```

`.backup` is used rather than `cp` because it takes a consistent snapshot
while the app is still writing.

---

## Two notes on how this is set up

**One worker, deliberately.** The trading bot, the bridge poller, the gas
manager and the surge radar all run inside the web process. A second worker
is a second copy of all of it — two processes buying the same token, two gas
grants for one empty wallet. `deploy/orcagent.service` pins it to one worker
with four threads; please don't raise it.

**Data lives in `/data`, code in `/opt/orcagent`.** The app switches to
`/data` automatically when that directory exists. Keeping them apart is what
makes redeploying safe: `install.sh` replaces the code and never reaches into
your database.
