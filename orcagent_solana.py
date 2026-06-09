import anthropic, time, json, os, requests, base64
from dotenv import load_dotenv
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction
from solders.message import to_bytes_versioned
load_dotenv()
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
WALLET_ADDRESS = os.getenv('WALLET_ADDRESS')
PRIVATE_KEY = os.getenv('WALLET_PRIVATE_KEY')
MAX_USDC = float(os.getenv('MAX_USDC', 50))
STOP_LOSS = float(os.getenv('STOP_LOSS', 0.05))
TAKE_PROFIT = float(os.getenv('TAKE_PROFIT', 0.15))
TRAILING_STOP = float(os.getenv('TRAILING_STOP', 0.03))
INTERVAL = int(os.getenv('INTERVAL', 300))
SOLANA_RPC = 'https://api.mainnet-beta.solana.com'
JUPITER_QUOTE = 'https://api.jup.ag/swap/v1/quote'
JUPITER_SWAP = 'https://api.jup.ag/swap/v1/swap'
USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'

def discover_tokens(limit=20):
    mints = []
    seen = {USDC_MINT}
    try:
        r = requests.get('https://api.dexscreener.com/token-boosts/top/v1', timeout=10)
        if r.status_code == 200:
            for item in r.json():
                if item.get('chainId') == 'solana':
                    m = item.get('tokenAddress', '')
                    if m and m not in seen:
                        seen.add(m); mints.append(m)
    except: pass
    try:
        r = requests.get('https://api.dexscreener.com/token-profiles/latest/v1', timeout=10)
        if r.status_code == 200:
            items = r.json() if isinstance(r.json(), list) else []
            for item in items:
                if item.get('chainId') == 'solana':
                    m = item.get('tokenAddress', '')
                    if m and m not in seen:
                        seen.add(m); mints.append(m)
    except: pass
    return [{'mint': m, 'label': m[:8]} for m in mints[:limit]]
client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
keypair = Keypair.from_base58_string(PRIVATE_KEY)

def get_token_data(mint):
    try:
        r = requests.get('https://api.dexscreener.com/latest/dex/tokens/' + mint, timeout=10)
        r.raise_for_status()
        pairs = r.json().get('pairs', [])
        if not pairs: return None
        p = pairs[0]
        return {
            'price': float(p.get('priceUsd', 0)),
            'volume1h': float(p.get('volume', {}).get('h1', 0)),
            'change5m': float(p.get('priceChange', {}).get('m5', 0)),
            'change1h': float(p.get('priceChange', {}).get('h1', 0)),
            'liquidity': float(p.get('liquidity', {}).get('usd', 0)),
            'txns_buys': int(p.get('txns', {}).get('h1', {}).get('buys', 0)),
            'txns_sells': int(p.get('txns', {}).get('h1', {}).get('sells', 0)),
        }
    except: return None

def get_balance():
    r = requests.post(SOLANA_RPC, json={'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [WALLET_ADDRESS]}, timeout=10)
    return r.json()['result']['value'] / 1e9

def get_usdc_balance():
    r = requests.post(SOLANA_RPC, json={'jsonrpc': '2.0', 'id': 1, 'method': 'getTokenAccountsByOwner', 'params': [WALLET_ADDRESS, {'mint': USDC_MINT}, {'encoding': 'jsonParsed'}]}, timeout=10)
    accounts = r.json().get('result', {}).get('value', [])
    if accounts:
        return float(accounts[0]['account']['data']['parsed']['info']['tokenAmount']['uiAmount'] or 0)
    return 0.0

def score_token(data):
    score = 0
    if data['change5m'] > 2: score += 3
    elif data['change5m'] > 0: score += 1
    else: score -= 2
    if data['change1h'] > 5: score += 3
    elif data['change1h'] > 0: score += 1
    else: score -= 2
    if data['volume1h'] > 10000: score += 2
    elif data['volume1h'] > 1000: score += 1
    buy_ratio = data['txns_buys'] / max(data['txns_sells'], 1)
    if buy_ratio > 2: score += 3
    elif buy_ratio > 1.2: score += 1
    else: score -= 1
    if data['liquidity'] < 1000: score -= 3
    elif data['liquidity'] > 10000: score += 1
    return score

def ai_decision(label, data, usdc):
    score = score_token(data)
    prompt = ('Token:' + label + ' Price:$' + str(data['price']) + ' 5m:' + str(data['change5m']) + '% 1h:' + str(data['change1h']) + '% Vol1h:$' + str(data['volume1h']) + ' Buys:' + str(data['txns_buys']) + ' Sells:' + str(data['txns_sells']) + ' Liq:$' + str(data['liquidity']) + ' Score:' + str(score) + ' USDC:' + str(round(usdc,2)) + ' Reply ONLY JSON: {"decision":"BUY|SELL|HOLD","reasoning":"str","confidence":0.5,"amount_pct":0.3}')
    msg = client.messages.create(model='claude-haiku-4-5-20251001', max_tokens=200, system='Aggressive Solana meme coin scalper. BUY when score>4 and momentum rising. SELL when dropping. JSON only.', messages=[{'role': 'user', 'content': prompt}])
    raw = msg.content[0].text.strip()
    if raw.startswith('```'): raw = raw.split('```')[1].lstrip('json')
    result = json.loads(raw.strip())
    if score >= 5 and result['decision'] == 'HOLD': result['decision'] = 'BUY'
    if score <= -2 and result['decision'] == 'HOLD': result['decision'] = 'SELL'
    return result

def execute_swap(input_mint, output_mint, amount):
    quote = requests.get(JUPITER_QUOTE, params={'inputMint': input_mint, 'outputMint': output_mint, 'amount': int(amount), 'slippageBps': 150}, timeout=10).json()
    swap_resp = requests.post(JUPITER_SWAP, json={'quoteResponse': quote, 'userPublicKey': WALLET_ADDRESS, 'wrapAndUnwrapSol': True}, timeout=10).json()
    tx_key = 'swapTransaction' if 'swapTransaction' in swap_resp else 'transaction'
    raw_tx = base64.b64decode(swap_resp[tx_key])
    tx = VersionedTransaction.from_bytes(raw_tx)
    msg_bytes = to_bytes_versioned(tx.message)
    sig = keypair.sign_message(msg_bytes)
    tx.signatures[0] = sig
    encoded = base64.b64encode(bytes(tx)).decode()
    result = requests.post(SOLANA_RPC, json={'jsonrpc': '2.0', 'id': 1, 'method': 'sendTransaction', 'params': [encoded, {'encoding': 'base64', 'skipPreflight': True}]}, timeout=30).json()
    return result.get('result', str(result))

def run():
    print('OrcAgent Solana SMART SCALPER v4 started')
    print('Wallet: ' + str(WALLET_ADDRESS))
    print('Live token discovery enabled | Interval: ' + str(INTERVAL) + 's')
    print('SL: ' + str(STOP_LOSS*100) + '% | TP: ' + str(TAKE_PROFIT*100) + '% | Trailing: ' + str(TRAILING_STOP*100) + '%')
    positions = {}
    tokens = []
    last_discovery = 0
    while True:
        try:
            now = time.time()
            if now - last_discovery > 300:
                fresh = discover_tokens()
                if fresh:
                    tokens = fresh
                    for t in tokens:
                        if t['mint'] not in positions:
                            positions[t['mint']] = {'amount': 0.0, 'buy_price': 0.0, 'peak_price': 0.0}
                    print('Discovered ' + str(len(tokens)) + ' tokens from DexScreener')
                last_discovery = now
            sol = get_balance()
            usdc = get_usdc_balance()
            print('--- SOL:' + str(round(sol,4)) + ' USDC:' + str(round(usdc,2)) + ' Tokens:' + str(len(tokens)) + ' ---')
            scored = []
            for token in tokens:
                try:
                    data = get_token_data(token['mint'])
                    if data: scored.append((score_token(data), token, data))
                except: pass
            scored.sort(key=lambda x: x[0], reverse=True)
            for score, token, data in scored:
                try:
                    if data.get('liquidity', 0) < 10000: continue
                    pos = positions[token['mint']]
                    res = ai_decision(token['label'], data, usdc)
                    print(token['label'] + ' $' + str(data['price']) + ' 5m:' + str(data['change5m']) + '% score:' + str(score) + ' [' + res['decision'] + '] ' + res['reasoning'][:40])
                    if res['decision'] == 'BUY' and usdc > 5:
                        spend = min(usdc * res['amount_pct'], MAX_USDC / 4)
                        tx = execute_swap(USDC_MINT, token['mint'], int(spend * 1e6))
                        print('BUY ' + token['label'] + ' $' + str(round(spend,2)) + ' TX: ' + str(tx))
                        pos['amount'] += spend / data['price']
                        pos['buy_price'] = data['price']
                        pos['peak_price'] = data['price']
                        usdc -= spend
                    elif res['decision'] == 'SELL' and pos['amount'] > 0:
                        tx = execute_swap(token['mint'], USDC_MINT, int(pos['amount'] * 1e6))
                        pnl = (data['price'] - pos['buy_price']) / pos['buy_price'] * 100
                        print('SELL ' + token['label'] + ' PnL:' + str(round(pnl,1)) + '% TX: ' + str(tx))
                        usdc += pos['amount'] * data['price']
                        pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                    if pos['amount'] > 0 and pos['buy_price'] > 0:
                        if data['price'] > pos['peak_price']: pos['peak_price'] = data['price']
                        chg = (data['price'] - pos['buy_price']) / pos['buy_price']
                        trail = (data['price'] - pos['peak_price']) / pos['peak_price']
                        if chg <= -STOP_LOSS:
                            tx = execute_swap(token['mint'], USDC_MINT, int(pos['amount'] * 1e6))
                            print('STOP LOSS ' + token['label'] + ' ' + str(round(chg*100,1)) + '%')
                            usdc += pos['amount'] * data['price']
                            pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                        elif chg >= TAKE_PROFIT:
                            tx = execute_swap(token['mint'], USDC_MINT, int(pos['amount'] * 1e6))
                            print('TAKE PROFIT ' + token['label'] + ' +' + str(round(chg*100,1)) + '%')
                            usdc += pos['amount'] * data['price']
                            pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                        elif trail <= -TRAILING_STOP and chg > 0:
                            tx = execute_swap(token['mint'], USDC_MINT, int(pos['amount'] * 1e6))
                            print('TRAILING STOP ' + token['label'] + ' locked:' + str(round(chg*100,1)) + '%')
                            usdc += pos['amount'] * data['price']
                            pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                except Exception as e:
                    print(token['label'] + ' error: ' + str(e))
            print('Sleeping ' + str(INTERVAL) + 's...')
        except Exception as e:
            print('Error: ' + str(e))
        time.sleep(INTERVAL)

if __name__ == '__main__': run()
