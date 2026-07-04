# OrcAgent — Social Solana Trading Platform

A social meme coin trading platform on Solana. Follow traders, copy their trades, share wins to X, and let an AI-scored automated bot trade on your behalf — all in one wallet-native app.

Live at: https://www.orcagent.fun

---

## What it does

**Social**
- Public feed: share posts, trades, and token calls; like, react, and reply
- Follow traders, see Followers/Following/Copiers on any profile
- Copy-trade tracking — copy a trader's positions with one click
- Trader profiles: SOL balance, trade history, win rate, PnL, badges
- Notifications for replies, reactions, likes, and follows
- Direct messages between users
- Connect X (Twitter) — auto-share big trades and new badges, or manually share any post

**Trading**
- Automated bot scores tokens every 30 seconds and enters on momentum + volume acceleration
- Configurable take-profit / stop-loss, min/max trade size (USDC), and daily loss limit per user
- Manual trading via the Live Market page (Trending / New Pairs / Gainers)
- Performance fee on profitable trades only (no fee on losses)

**Security**
- Each user's private key is encrypted (Fernet + wallet-derived HMAC) and never exposed
- CSRF protection, rate limiting, and IP banning on all mutating endpoints
- Role-based admin console (owner / moderator / analyst) for platform management

---

## Deploy on Railway

1. Fork this repo
2. Create a new Railway project and connect your fork
3. Set the required environment variables (see below)
4. Railway will build and deploy automatically via the Dockerfile

---

## Required environment variables

| Variable | Description |
|---|---|
| `ENCRYPTION_KEY` | Fernet key for encrypting user private keys. Generate with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `SECRET_KEY` | Flask session secret. Use a long random string — set this explicitly in production so sessions survive redeploys. |
| `OWNER_WALLET` | Your Solana wallet address — receives performance fees and has full admin access. |
| `SOLANA_RPC_URL` | RPC endpoint (e.g. Helius). Falls back to public RPC if not set. |

Optional:

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Claude API key for AI token scoring. |
| `HELIUS_API_KEY` | Helius RPC API key for reliable Solana RPC. |
| `BIRDEYE_API_KEY` | BirdEye API key for token data. |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token (from @BotFather) for uptime alerts. |
| `TELEGRAM_CHAT_ID` | Telegram chat or channel ID to receive uptime alerts. |
| `X_CLIENT_ID` / `X_CLIENT_SECRET` | X (Twitter) OAuth 2.0 app credentials, for the Connect X / auto-share feature. |
| `X_CALLBACK_URL` | OAuth callback URL, must match exactly what's registered in the X Developer Portal. |

---

## How users connect

1. Go to the live URL and connect a wallet (or browse in guest mode)
2. Add a trading private key in Settings — it's encrypted with ENCRYPTION_KEY before storage and never logged or exposed
3. Configure bot settings (trade size, daily loss limit) or trade manually via Live Market
4. Follow other traders, share posts, and connect X to auto-share wins

---

## Stack

- Python / Flask backend, SQLite storage
- Solana via solders + Jupiter DEX API
- Claude AI (Anthropic) for token scoring
- X (Twitter) API v2 for social sharing
- Deployed on Railway via Docker
