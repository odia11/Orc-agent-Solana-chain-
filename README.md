# OrcAgent — Solana Meme Coin Trading Bot

Autonomous Solana meme coin scalper with a live web dashboard. Deployed on Railway. Connect your Phantom or Solflare wallet to start trading.

---

## How It Works

1. **Connect wallet** — Phantom or Solflare. Your wallet address is your user ID.
2. **Add your trading private key** in Settings (encrypted with Fernet before storage).
3. **Start Trading** — the bot scans live tokens from DexScreener every 90 seconds, scores them, and executes swaps via Jupiter.

Multi-user: each wallet address gets independent positions, P&L, settings, and balances.

---

## Features

- Live token discovery: DexScreener top-boosted, trending (6h score), and latest token profiles
- Trending filter: only tokens with h1 ≥ 50%, liquidity ≥ $10k, 24h volume ≥ $50k shown in market grid
- Momentum scoring 0–10: 5m/1h price change, 5m volume, buy/sell ratio, liquidity safety gate
- **Auto-buy at score ≥ 7 AND 5m change ≥ 10%** — max 3 concurrent positions, minimum $1 USDC
- **Auto-sell:** take profit at +15%, stop loss at −5%, or when 5m momentum dies
- Per-user daily P&L tracking with SVG chart and trade history table
- Open positions panel with live entry price, current price, cost, and unrealised P&L
- Token of the Day — auto-rotates every 15 minutes to the highest-scored token
- Live market grid with signal badges and candlestick chart on click
- SOL + USDC balances fetched per-user from Solana RPC, refreshed every 30 seconds
- **20-minute inactivity session timeout** with 18-minute warning popup and "Stay Connected" button
- Rate limiting on all API endpoints (sliding window)
- Private keys encrypted with Fernet, decrypted only in memory during swaps, never exposed in API responses
- Session cookie security: HttpOnly, SameSite=Lax, Secure on Railway

---

## Deploy to Railway

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app)

1. Fork this repo
2. Create a new Railway project from your fork
3. Set environment variables (see `.env.example`):
   - `ENCRYPTION_KEY` — generate with the command below
   - `SECRET_KEY` — any random string (keep secret)
4. Railway picks up `Procfile` automatically and runs gunicorn

```bash
# Generate ENCRYPTION_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## Run Locally

```bash
git clone https://github.com/odia11/Orc-agent-Solana-chain-.git
cd Orc-agent-Solana-chain-
pip install -r requirements.txt
cp .env.example .env   # fill in your values
python dashboard.py
```

Open `http://localhost:5000`, connect your wallet, configure settings, and start trading.

---

## Project Structure

```
dashboard.py          — Flask server: API routes, background loops, SQLite, Fernet encryption
dashboard.html        — Single-page frontend: wallet auth, live market, settings modal
orcagent_solana.py    — Jupiter swap execution (called as subprocess with env-var private key)
requirements.txt      — Python dependencies
Procfile              — Railway / gunicorn entry point
railway.json          — Railway config
.env.example          — Environment variable template
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ENCRYPTION_KEY` | Yes | Fernet key for encrypting private keys at rest |
| `SECRET_KEY` | Yes | Flask session secret |
| `ANTHROPIC_API_KEY` | No | Claude API key — only used if running `orcagent_solana.py` standalone |
| `WALLET_ADDRESS` | No | Default wallet for balance display (users connect their own via Phantom/Solflare) |
| `PORT` | No | Server port (Railway sets this automatically) |

---

## Security Notes

- Use a **dedicated trading wallet** with only the funds you are willing to risk — never your main wallet
- Private keys are **never stored raw** — Fernet-encrypted before writing to SQLite
- Keys are **decrypted in memory only** when a swap is being executed
- Keys are **wiped from memory** immediately after the trade thread exits
- Keys are **never returned** in any API response
- Sessions expire after **20 minutes of inactivity** (client-side) and 30 minutes server-side

---

## Disclaimer

This bot trades real money on Solana. Meme coin trading is extremely high risk. You can lose your entire balance. Use only funds you can afford to lose. This is not financial advice.

---

Made with ♥ by [@odia11](https://github.com/odia11)
