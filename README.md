# 👹 OrcAgent Solana

> Brutal. Fast. Profitable.

Autonomous Solana meme coin trading bot powered by Claude AI. OrcAgent monitors multiple tokens, analyzes price data and automatically executes swaps via Jupiter.

---

## Features

- AI-driven BUY/SELL/HOLD decisions via Claude
- Trades any Solana token (pump.fun, meme coins, SPL tokens)
- Auto-executes swaps via Jupiter aggregator
- Stop-loss and take-profit on every position
- Price data via DexScreener (free, no API key needed)
- Easy setup wizard — no coding required

---

## Quick start

### 1. Install Python dependencies

```bash
pip install anthropic python-dotenv requests solders solana
```

### 2. Clone the repo

```bash
git clone https://github.com/odia11/Orc-agent-Solana-chain-
cd Orc-agent-Solana-chain-
```

### 3. Configure your .env

Open `orcagent_setup.html` in your browser to generate your config automatically, or copy `.env.example` to `.env` and fill in your details:

```
ANTHROPIC_API_KEY=sk-ant-api03-...
WALLET_ADDRESS=your_solana_public_key
WALLET_PRIVATE_KEY=your_private_key
MAX_USDC=50
STOP_LOSS=0.03
TAKE_PROFIT=0.05
INTERVAL=900
```

### 4. Run the bot

```bash
python orcagent_solana.py
```

---

## Setup wizard

Open `orcagent_setup.html` in any browser — fill in your API keys, wallet, and token contracts to generate your `.env` file automatically.

---

## Getting API keys

| Key | Where to get it |
|-----|----------------|
| Anthropic API key | [console.anthropic.com](https://console.anthropic.com) → API keys |
| Solana wallet | [phantom.app](https://phantom.app) — create a new wallet |

---

## How it works

1. Every 15 minutes the bot fetches token prices from DexScreener
2. Claude AI analyzes the data and returns a BUY/SELL/HOLD decision
3. If BUY — the bot gets a quote from Jupiter and executes the swap
4. Stop-loss (3%) and take-profit (5%) are checked every cycle

---

## Warning

- Meme coins are extremely risky — only trade what you can afford to lose
- Never share your private key with anyone
- This bot is for educational purposes — trade at your own risk

---

## License

MIT
