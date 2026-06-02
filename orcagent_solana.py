import anthropic, time, json, os, requests
from dotenv import load_dotenv
load_dotenv()

ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
WALLET_ADDRESS = os.getenv('WALLET_ADDRESS')
MAX_USDC = float(os.getenv('MAX_USDC', 50))
STOP_LOSS = float(os.getenv('STOP_LOSS', 0.03))
TAKE_PROFIT = float(os.getenv('TAKE_PROFIT', 0.05))
INTERVAL = int(os.getenv('INTERVAL', 900))
SOLANA_RPC = 'https://api.mainnet-beta.solana.com'
JUPITER_BASE = 'https://quote-api.jup.ag/v6'
TOKEN_MINT = 'So11111111111111111111111111111111111111112'
USEC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

def get_prices():
    r = requests.get('https://api.coingecko.com/api/v3/coins/solana/market_chart', params={'vs_currency': 'usd', 'days': 1, 'interval': 'hourly'}, timeout=10)
    r.raise_for_status()
    return [float(p[1]) for p in r.json()['prices']]

def get_balance():
    r = requests.post(SOLANA_RPC, json={'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [WALLET_ADDRESS]}, timeout=10)
    return r.json()['result']['value'] / 1e9

def get_indicators():
    c = get_prices()
    if len(c) < 21: raise ValueError('Not enough data')
    sma7 = sum(c[-7:]) / 7
    sma20 = sum(c[-20:]) / 20
    g = l = 0.0
    for i in range(1, 15):
        d = c[-i] - c[-i-1]
        if d > 0: g += d
        else: l += abs(d)
    rsi = 100 - (100 / (1 + g / max(l, 0.0001)))
    chg = ((c[-1] - c[-2]) / c[-2] * 100) if c[-2] != 0 else 0.0
    return {'price': c[-1], 'sma7': sma7, 'sma20': sma20, 'rsi': rsi, 'change': chg}

def ai_decision(ind, sol, usdc):
    prompt = 'SOL price:' + str(round(ind['price'],2)) + ' RSI:' + str(round(ind['rsi'],1)) + ' SMA7:' + str(round(ind['sma7'],2)) + ' SMA20:' + str(round(ind['sma20'],2)) + ' SOL:' + str(round(sol,4)) + ' USDC:' + str(round(usdc,2)) + ' Reply ONLY JSON: {"decision":"BUY|SELL|HOLD","reasoning":"str","confidence":0.5,"amount_pct":0.3}'
    msg = client.messages.create(model='claude-haiku-4-5-20251001', max_tokens=200, system='Cautious Solana trading agent. JSON only.', messages=[{'role': 'user', 'content': prompt}])
    raw = msg.content[0].text.strip()
    if raw.startswith('```'): raw = raw.split('```')[1].lstrip('json')
    return json.loads(raw.strip())

def run():
    print('OrcAgent Solana started')
    print('Wallet: ' + str(WALLET_ADDRESS))
    sol = usdc = tp = abp = 0.0
    try:
        sol = get_balance()
        print('SOL: ' + str(round(sol, 4)))
    except Exception as e:
        print('Balance error: ' + str(e))
    while True:
        try:
            ind = get_indicators()
            res = ai_decision(ind, sol, usdc)
            print('Price:' + str(round(ind['price'],2)) + ' [' + res['decision'] + '] ' + res['reasoning'][:60])
            if res['decision'] == 'BUY' and usdc > 10:
                spend = min(usdc * res['amount_pct'], MAX_USDC)
                try:
                    q = requests.get(JUPITER_BASE + '/quote', params={'inputMint': USEC_MINT, 'outputMint': TOKEN_MINT, 'amount': int(spend*1e6), 'slippageBps': 50}, timeout=10).json()
                    out = int(q['outAmount']) / 1e9
                    print('BUY: ' + str(round(spend,2)) + ' USDC -> ' + str(round(out,6)) + ' SOL')
                    tp += out; abp = ind['price']; usdc -= spend
                except Exception as e: print('BUY err: ' + str(e))
            elif res['decision'] == 'SELL' and tp > 0:
                try:
                    q = requests.get(JUPITER_BASE + '/quote', params={'inputMint': TOKEN_MINT, 'outputMint': USEC_MINT, 'amount': int(tp*1e9), 'slippageBps': 50}, timeout=10).json()
                    out = int(q['outAmount']) / 1e6
                    print('SELL: ' + str(round(tp,6)) + ' SOL -> ' + str(round(out,2)) + ' USDC')
                    usdc += out; tp = abp = 0.0
                except Exception as e: print('SELL err: ' + str(e))
            if tp > 0 and abp > 0:
                chg = (ind['price'] - abp) / abp
                if chg <= -STOP_LOSS or chg >= TAKE_PROFIT:
                    print('SL/TP: ' + str(round(chg*100,1)) + '%')
                    tp = abp = 0.0
            print('SOL:' + str(round(sol,4)) + ' USDC:' + str(round(usdc,2)) + ' Sleeping...')
        except Exception as e: print('Error: ' + str(e))
        time.sleep(INTERVAL)

if __name__ == '__main__': run()
