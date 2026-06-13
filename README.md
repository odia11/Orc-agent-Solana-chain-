# OrcAgent v4 — Solana Meme Coin Trading Bot

Autonomous Solana meme coin scalper with a live web dashboard. Multi-user, deployed on Railway with persistent storage. Connect your Phantom or Solflare wallet and let the bot trade for you.

---

## How It Works

1. **Connect wallet** — Phantom or Solflare. Your wallet address is your identity; no username or password.
2. **Add your trading private key** in Settings — double-encrypted before storage, never exposed in any API response or log.
3. **Start Trading** — the bot scans DexScreener every 30 seconds, scores tokens 0–10, and executes swaps via Jupiter when a signal qualifies.

Each wallet gets independent positions, P&L, trade history, and settings. The owner wallet gets a private admin dashboard.

---

## Trading Strategy

| Parameter | Value |
|---|---|
| Buy threshold | score ≥ 4.5 |
| Base position size | 40% of USDC balance |
| Momentum multiplier | score ≥ 7 → 60% of USDC balance |
| Min / max position | configurable per user in Settings |
| Take profit | +25% |
| Stop loss | −3% |
| Partial exit | +20% (sells 50%, resets entry) |
| Trailing stop | −7% from peak |
| Dynamic stop | moves to breakeven at +10%, locks +10% after +20% |
| Max concurrent positions | 5 |
| Scan interval | 30 seconds |

Scoring factors: 5-minute momentum, 1-hour trend, 5-minute volume, buy/sell ratio, liquidity floor, optional Claude Haiku AI bonus (+0–2 pts).

---

## Features

- Live token discovery via DexScreener (top-boosted, trending 6h, latest profiles)
- Market grid with signal badges, score breakdown, and OHLCV candlestick chart on click
- TradingView Lightweight Charts — 1m / 5m / 15m / 1h / 4h / D timeframes, GeckoTerminal data
- Token of the Day — auto-rotates every 15 minutes to the highest-scored token
- Open positions panel with live entry price, current price, cost, and unrealised P&L
- Per-user daily P&L tracking and trade history table
- SOL + USDC balances refreshed every 30 seconds from Solana RPC
- 20-minute inactivity session timeout with 18-minute warning and "Stay Connected" button
- Rate limiting on all endpoints (sliding window, IP banning, owner wallet whitelisted)
- Owner admin dashboard: user list, fee history, token performance, system health, IP ban manager

---

## Tech Stack

- **Python + Flask** — backend API, background trading loops, session management
- **SQLite + Fernet encryption** — user database with double-encrypted private keys
- **Jupiter DEX via Cloudflare Workers proxy** — swap execution on Solana
- **DexScreener API** — token discovery and market data
- **Claude AI Haiku** — optional AI signal scoring boost
- **Railway** — hosting + persistent volume at `/data` (DB and logs survive redeploys)

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ENCRYPTION_KEY` | **Yes** | Fernet key for encrypting private keys at rest |
| `SECRET_KEY` | **Yes** | Flask session secret — keep private |
| `OWNER_WALLET` | **Yes** | Your wallet address — receives 5% performance fees and unlocks admin panel |
| `ANTHROPIC_API_KEY` | No | Enables Claude Haiku AI signal boost (optional but recommended) |
| `JUPITER_PROXY_URL` | No | Cloudflare Workers proxy URL for Jupiter API (deploy `proxy/worker.js`) |
| `JUPITER_PROXY_SECRET` | No | Shared secret to authenticate requests to the Jupiter proxy |
| `PORT` | No | Server port — Railway sets this automatically |

```bash
# Generate ENCRYPTION_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## Main Files

| File | Purpose |
|---|---|
| `dashboard.py` | Flask server — API routes, trading loop, SQLite, encryption, admin endpoints |
| `dashboard.html` | Single-page frontend — wallet auth, live market, settings modal, admin dashboard |
| `orcagent_solana.py` | Standalone trading bot — Jupiter swaps, standalone CLI mode |
| `proxy/worker.js` | Cloudflare Workers proxy for Jupiter API |
| `proxy/wrangler.toml` | Wrangler deploy config |
| `Dockerfile` | Production container (Railway uses this automatically) |
| `requirements.txt` | Python dependencies |
| `.env.example` | Environment variable template |

---

## Deploy to Railway

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app)

1. Fork this repo
2. Create a new Railway project from your fork — Railway picks up the `Dockerfile` automatically
3. Set environment variables in Railway → Variables (see table above)
4. Add a persistent volume: Railway → Volumes → **Add Volume** → mount path `/data`
   - Without this the SQLite database resets on every redeploy
5. Deploy — the startup log will confirm `persistent storage: True  db=/data/orcagent.db`

---

## Run Locally

```bash
git clone https://github.com/odia11/Orc-agent-Solana-chain-.git
cd Orc-agent-Solana-chain-
pip install -r requirements.txt
cp .env.example .env   # fill in your values
python dashboard.py
```

Open `http://localhost:5000`, connect your wallet, add your trading private key in Settings, and start trading.

---

## Jupiter Proxy (Optional)

If Railway IPs are rate-limited by `api.jup.ag`, deploy the Cloudflare Workers proxy (free tier: 100 k requests/day):

```bash
npm install -g wrangler
wrangler login
cd proxy && wrangler deploy
```

Copy the deployed URL into Railway Variables as `JUPITER_PROXY_URL`.

---

## Security

- Use a **dedicated trading wallet** — never your main wallet
- Private keys are **double-encrypted** (Fernet + wallet-derived HMAC-SHA256 layer) before writing to SQLite
- Keys are **decrypted in memory only** at the moment of signing — cleared immediately after
- Keys are **never returned** in any API response or log line
- Sessions expire after **20 minutes of inactivity**
- All API endpoints are rate-limited; IPs that exceed limits are banned for 1 hour
- Owner wallet is whitelisted from all rate limiting

---

## Disclaimer

This bot trades real money on Solana. Meme coin trading is extremely high risk. You can lose your entire balance. Use only funds you can afford to lose. This is not financial advice.

---

Made with ♥ by [@odia11](https://github.com/odia11)
