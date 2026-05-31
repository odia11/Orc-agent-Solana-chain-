import anthropic, ccxt, time, json
from dotenv import load_dotenv
import os

load_dotenv()

EXCHANGE_ID = "binance"
API_KEY     = os.getenv("EXCHANGE_API_KEY")
API_SECRET  = os.getenv("EXCHANGE_API_SECRET")
PAIR        = "BTC/USDT"
MAX_USDT    = 50
STOP_LOSS   = 0.03
TAKE_PROFIT = 0.05
INTERVAL    = 900

client   = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
exchange = getattr(ccxt, EXCHANGE_ID)({"apiKey": API_KEY, "secret": API_SECRET})

def get_indicators():
    ohlcv  = exchange.fetch_ohlcv(PAIR, "5m", limit=30)
    closes = [c[4] for c in ohlcv]
    sma7   = sum(closes[-7:]) / 7
    sma20  = sum(closes[-20:]) / 20
    g = l  = 0
    for i in range(1, 15):
        d = closes[-i] - closes[-i-1]
        if d > 0: g += d
        else: l += abs(d)
    rsi = 100 - (100 / (1 + g / max(l, 0.001)))
    return {"price": closes[-1], "sma7": sma7,
            "sma20": sma20, "rsi": rsi,
            "change": (closes[-1]-closes[-2])/closes[-2]*100}

def ai_decision(ind, cash, position):
    prompt = f"""Pair: {PAIR} | Price: {ind['price']:.2f}
RSI: {ind['rsi']:.1f} | SMA7: {ind['sma7']:.2f} | SMA20: {ind['sma20']:.2f}
Change: {ind['change']:.2f}% | Cash: {cash:.2f} USDT | Position: {position}
Respond ONLY in JSON: {{"decision":"BUY|SELL|HOLD","reasoning":"...","confidence":0.0-1.0,"amount_pct":0.1-1.0}}"""
    msg = client.messages.create(
        model="claude-sonnet-4-20250514", max_tokens=300,
        system="You are a cautious crypto trading agent for OrcAgent. Analyze market data and return a JSON decision.",
        messages=[{"role": "user", "content": prompt}])
    return json.loads(msg.content[0].text)

def run():
    position = avg_price = 0.0
    cash = exchange.fetch_balance()["USDT"]["free"]
    print(f"👹 OrcAgent started | Cash: {cash:.2f} USDT")
    while True:
        try:
            ind    = get_indicators()
            result = ai_decision(ind, cash, position)
            print(f"[{result['decision']}] {result['reasoning'][:80]}")
            if result["decision"] == "BUY" and cash > 10:
                amt = min(cash * result["amount_pct"], MAX_USDT) / ind["price"]
                exchange.create_market_buy_order(PAIR, amt)
                position = amt; avg_price = ind["price"]
                cash -= amt * ind["price"]
                print(f"BUY {amt:.6f} {PAIR.split('/')[0]} @ ${ind['price']:.2f}")
            elif result["decision"] == "SELL" and position > 0:
                exchange.create_market_sell_order(PAIR, position)
                cash += position * ind["price"]
                print(f"SELL {position:.6f} {PAIR.split('/')[0]} @ ${ind['price']:.2f}")
                position = 0
            if position > 0:
                chg = (ind["price"] - avg_price) / avg_price
                if chg <= -STOP_LOSS or chg >= TAKE_PROFIT:
                    exchange.create_market_sell_order(PAIR, position)
                    cash += position * ind["price"]; position = 0
                    print(f"SL/TP triggered: {chg*100:.1f}%")
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    run()
