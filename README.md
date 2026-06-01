# 👹 OrcAgent

> *Brutal. Fast. Profitable.*

Autonomous crypto trading bot powered by Claude AI. OrcAgent analyzes market data in real-time and automatically places orders via your exchange API.

## Features

- AI-driven decisions via Claude (RSI, SMA, price trend)
- Supports Kraken, Binance, Coinbase Advanced, Bybit
- Automatic stop-loss and take-profit
- Live dashboard with price chart and AI reasoning
- Fully configurable system prompt

## Installation

```bash
pip install anthropic ccxt python-dotenv
```

## Usage

```bash
python orcagent.py
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `EXCHANGE_ID` | `kraken` | Exchange name |
| `PAIR` | `BTC/USD` | Trading pair |
| `MAX_USD` | `50` | Max position size |
| `STOP_LOSS` | `0.03` | 3% stop-loss |
| `TAKE_PROFIT` | `0.05` | 5% take-profit |
| `INTERVAL` | `900` | Analysis interval (sec) |

## Environment Variables

Never store API keys in your code. Create a `.env` file:
