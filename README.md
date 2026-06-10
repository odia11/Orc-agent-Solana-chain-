# OrcAgent — Solana Meme Coin Trading Bot

Autonomous Solana meme coin scalper with a live web dashboard. Deployed on Railway. Connect your Phantom or Solflare wallet to start trading.

---

## How It Works

1. **Connect wallet** — Phantom or Solflare. Your wallet address is your user ID.
2. **Add your trading private key** in Settings (encrypted with Fernet before storage).
3. **Start Trading** — the bot scans live tokens from DexScreener every 2 minutes, scores them, and auto-buys/sells.

Multi-user: each wallet address gets independent positions, P&L, and settings.

---

## Features

- Live token discovery from DexScreener (top boosted + latest profiles)
- Momentum scoring: 5m/1h price change, volume, buy/sell ratio, liquidity
- Auto-buy at score ≥ 5, auto-sell at score ≤ −3
- Per-user daily P&L tracking with SVG chart and trade history
- Token of the Day — auto-rotates every 15 minutes to the top 24h performer
- Live market grid with signal badges (BUY / SELL / HOLD)
- Wallet balance (SOL + USDC) pulled directly from Solana RPC
- Private keys encrypted with Fernet, decrypted only in memory during swaps, never exposed in API responses

---

## Deploy to Railway

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app)

1. Fork this repo
2. Create a new Railway project from your fork
3. Set environment variables (see `.env.example`):
   - `ANTHROPIC_API_KEY` — from [console.anthropic.com](https://console.anthropic.com)
   - `ENCRYPTION_KEY` — generate with the command below
   - `SECRET_KEY` — any random string
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
assets/               — SVG logo assets
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Claude API key for AI trade decisions |
| `ENCRYPTION_KEY` | Yes | Fernet key for encrypting private keys at rest |
| `SECRET_KEY` | Yes | Flask session secret |
| `WALLET_ADDRESS` | No | Default wallet for balance display |
| `PORT` | No | Server port (Railway sets this automatically) |

---

## Security Notes

- Private keys are **never stored raw** — Fernet-encrypted before writing to SQLite
- Keys are **decrypted in memory only** when a swap is being executed
- Keys are **wiped from memory** immediately after the trade thread exits
- Keys are **never returned** in any API response
- Use a dedicated trading wallet with only the funds you're willing to risk

---

## Disclaimer

This bot trades real money on Solana. Meme coin trading is extremely high risk. You can lose your entire balance. Use only funds you can afford to lose. This is not financial advice.

---

Made with by [@odia11](https://github.com/odia11)
