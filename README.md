# 🐋 OrcAgent — Solana Smart Scalper + Sniper

> Autonomous Solana meme coin trading bot with AI-powered decision making, new token sniping, and a live dashboard.

![OrcAgent Dashboard](assets/preview.png)

---

## ⚡ Quick Start (Windows)

### Option 1 — Download the App (Easiest)
1. Go to [Releases](../../releases) and download `OrcAgent.exe`
2. Double-click to run
3. If Windows shows a SmartScreen warning → click **"More info"** → **"Run anyway"** (normal for unsigned apps)
4. Browser opens automatically at `http://localhost:5000`
5. Fill in the setup wizard and click **Launch OrcAgent**

### Option 2 — Run from Source (Advanced)
```bash
git clone https://github.com/odia11/Orc-agent-Solana-chain-.git
cd Orc-agent-Solana-chain-
pip install -r requirements.txt
python app.py
```
Then open `http://localhost:5000` in your browser.

---

## 🔧 Setup

You'll need:

| Field | Where to get it |
|---|---|
| **Anthropic API Key** | [console.anthropic.com](https://console.anthropic.com) → API Keys |
| **Wallet Address** | Your Solana wallet public key (e.g. from Phantom) |
| **Private Key** | Phantom → Settings → Export Private Key |

> ⚠️ Your private key is stored **only on your local PC** in a `.env` file. It is never sent anywhere except to sign transactions on the Solana blockchain.

---

## 🤖 Features

### Trade Mode
- Scans **7 Solana meme coins** every 5 minutes
- Uses **Claude AI (Haiku)** to score each token on momentum, volume, buy/sell ratio, and liquidity
- Auto-buys when score exceeds threshold
- Auto-exits at:
  - ✅ **15% Take Profit**
  - 🛑 **5% Stop Loss**
  - 📉 **3% Trailing Stop**

### Snipe Mode
- Watches **DexScreener** every 15 seconds for brand new token launches
- Queues tokens for a configurable delay (default 10 min)
- Runs safety checks before buying:
  - ❌ Skips tokens with freeze authority set (rug risk)
  - ❌ Skips tokens with liquidity too low or too high
  - ✅ Buys tokens that pass all checks
- Auto-sells sniped tokens at same TP/SL/trailing levels

### Dashboard
- 🐋 Live ORC logo and dancing animation on every trade
- Connect **Phantom wallet** for live balance updates
- Real-time log of all bot activity
- Token signal scores updated every minute
- Sniper queue with countdown timers

---

## ⚙️ Configuration

All settings configurable from the dashboard or via `.env`:

```env
ANTHROPIC_API_KEY=sk-ant-...
WALLET_ADDRESS=57ENjXjh...
WALLET_PRIVATE_KEY=your_base58_key

# Trading
STOP_LOSS=0.05          # 5% stop loss
TAKE_PROFIT=0.15        # 15% take profit
TRAILING_STOP=0.03      # 3% trailing stop
MAX_TRADE_PCT=0.20      # max 20% of balance per trade
MAX_OPEN_POSITIONS=3    # max simultaneous positions
MIN_USDC_RESERVE=3.0    # always keep $3 in reserve
INTERVAL=300            # scan every 300 seconds

# Sniper
SNIPER_AMOUNT=1.0       # USDC per snipe
SNIPER_MIN_LIQ=1000     # min liquidity to snipe ($)
SNIPER_MAX_LIQ=50000    # max liquidity to snipe ($)
SNIPER_DELAY=600        # seconds to wait before buying
```

---

## 📦 Requirements (Source)

```
anthropic
solders
requests
python-dotenv
flask
```

Install with:
```bash
pip install anthropic solders requests python-dotenv flask
```

---

## ⚠️ Disclaimer

This bot trades real money on the Solana blockchain. Meme coin trading is extremely high risk. You can lose your entire balance. Use only money you can afford to lose. This is not financial advice.

- Start with small amounts ($1–5 per trade)
- Monitor the bot regularly
- Keep most of your funds off the trading wallet

---

## 🔗 Links

- [Solscan](https://solscan.io) — verify your transactions
- [Jupiter](https://jup.ag) — swap tokens manually
- [DexScreener](https://dexscreener.com) — token charts
- [Phantom](https://phantom.app) — Solana wallet

---

Made with 🐋 by [@degentrader1990](https://github.com/odia11)
