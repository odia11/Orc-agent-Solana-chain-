# OrcAgent — Solana AI Trading Bot

Fully automated meme coin scalper on Solana. Scans tokens every 30 seconds, scores them with Claude AI, and executes trades via Jupiter DEX. Multi-user platform with encrypted key storage.

Live at: https://www.orcagent.fun

---

## What it does

- Scores 100+ tokens with Claude AI every 30 seconds
- Buys tokens showing 5–20% momentum in last 5 min with accelerating volume, exits at +12% take profit or −8% stop loss (100% position)
- 5% performance fee on profitable trades only
- Each user's private key is encrypted and stored — never exposed
- Admin dashboard for monitoring trades, fees, and users

---

## Deploy on Railway

1. Fork this repo
2. Create a new Railway project and connect your fork
3. Set the required environment variables (see below)
4. Railway will build and deploy automatically via the `Dockerfile`

---

## Required environment variables

| Variable | Description |
|---|---|
| `ENCRYPTION_KEY` | Fernet key for encrypting user private keys. Generate with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `SECRET_KEY` | Flask session secret. Use a long random string. |
| `OWNER_WALLET` | Your Solana wallet address — receives the 5% performance fees. |
| `SOLANA_RPC_URL` | RPC endpoint (e.g. Helius). Falls back to public RPC if not set. |

Optional:

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Claude API key for AI token scoring. |
| `HELIUS_API_KEY` | Helius RPC API key for reliable Solana RPC. |
| `BIRDEYE_API_KEY` | BirdEye API key for token data. |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token (from @BotFather) for uptime alerts. |
| `TELEGRAM_CHAT_ID` | Telegram chat or channel ID to receive uptime alerts. |

---

## How users connect

1. Go to the live URL
2. Enter their Solana wallet address and trading private key in Settings
3. The private key is encrypted with `ENCRYPTION_KEY` before storage — the server never logs or exposes it
4. The bot trades automatically on their behalf; they can monitor positions and claim rent from closed token accounts

---

## Stack

- Python / Flask backend
- Solana via `solders` + Jupiter DEX API
- Claude AI (Anthropic) for token scoring
- Deployed on Railway via Docker
