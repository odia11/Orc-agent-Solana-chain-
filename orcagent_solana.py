import anthropic, sys, time, json, os, requests, base64
from dotenv import load_dotenv
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction
from solders.message import to_bytes_versioned
load_dotenv()

ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
WALLET_ADDRESS    = os.getenv('WALLET_ADDRESS')
PRIVATE_KEY       = os.getenv('WALLET_PRIVATE_KEY')
MAX_USDC          = float(os.getenv('MAX_USDC', 50))
STOP_LOSS         = float(os.getenv('STOP_LOSS', 0.05))    # 5%
TAKE_PROFIT       = float(os.getenv('TAKE_PROFIT', 0.15))  # 15%
TRAILING_STOP     = float(os.getenv('TRAILING_STOP', 0.03))
INTERVAL          = int(os.getenv('INTERVAL', 60))
SOLANA_RPC        = 'https://api.mainnet-beta.solana.com'
JUPITER_QUOTE     = 'https://api.jup.ag/swap/v1/quote'
JUPITER_SWAP      = 'https://api.jup.ag/swap/v1/swap'
USDC_MINT         = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'

def discover_tokens(limit=30):
    mints    = []
    trending = set()
    seen     = {USDC_MINT}
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
        r = requests.get(
            'https://api.dexscreener.com/latest/dex/search?q=solana&rankBy=trendingScoreH6',
            timeout=10)
        if r.status_code == 200:
            data  = r.json()
            pairs = data.get('pairs', []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            for p in pairs:
                if p.get('chainId') == 'solana':
                    m = (p.get('baseToken') or {}).get('address', '')
                    if m:
                        trending.add(m)
                        if m not in seen:
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
    return [{'mint': m, 'label': m[:8]} for m in mints[:limit]], trending

def get_token_data(mint):
    try:
        r = requests.get('https://api.dexscreener.com/latest/dex/tokens/' + mint, timeout=10)
        r.raise_for_status()
        pairs = r.json().get('pairs', [])
        if not pairs: return None
        p    = pairs[0]
        txns = p.get('txns', {})
        m5b  = int(txns.get('m5', {}).get('buys',  0) or 0)
        m5s  = int(txns.get('m5', {}).get('sells', 0) or 0)
        h1b  = int(txns.get('h1', {}).get('buys',  0) or 0)
        h1s  = int(txns.get('h1', {}).get('sells', 0) or 0)
        return {
            'price':      float(p.get('priceUsd', 0) or 0),
            'change5m':   float(p.get('priceChange', {}).get('m5',  0) or 0),
            'change15m':  float(p.get('priceChange', {}).get('m15', 0) or 0),
            'change1h':   float(p.get('priceChange', {}).get('h1',  0) or 0),
            'liquidity':  float(p.get('liquidity', {}).get('usd', 0) or 0),
            'volume5m':   float(p.get('volume', {}).get('m5', 0) or 0),
            'volume1h':   float(p.get('volume', {}).get('h1', 0) or 0),
            'txns_buys':  m5b or h1b,
            'txns_sells': m5s or h1s,
        }
    except: return None

def score_token(data):
    """Score 0–10. Momentum-focused: ≥4 = BUY signal."""
    if data.get('price', 0) <= 0: return 0
    score = 0.0
    m5    = data.get('change5m', 0)
    h1    = data.get('change1h', 0)
    vol5m = data.get('volume5m', 0)
    liq   = data.get('liquidity', 0)
    buys  = data.get('txns_buys', 0)
    sells = max(data.get('txns_sells', 1), 1)

    if   m5 >= 50: score += 4.0
    elif m5 >= 30: score += 3.0
    elif m5 >= 20: score += 2.5
    elif m5 >= 10: score += 1.5
    elif m5 >=  5: score += 0.5

    if   h1 >= 60: score += 2.0
    elif h1 >= 30: score += 1.5
    elif h1 >= 15: score += 1.0
    elif h1 >=  5: score += 0.5

    if   vol5m >= 50000: score += 2.0
    elif vol5m >= 20000: score += 1.5
    elif vol5m >=  5000: score += 1.0
    elif vol5m >=  1000: score += 0.5

    ratio = buys / sells
    if   ratio >= 4.0: score += 2.0
    elif ratio >= 2.5: score += 1.5
    elif ratio >= 1.5: score += 1.0
    elif ratio >= 1.0: score += 0.5

    if   liq < 5000:  score = max(0, score - 4.0)
    elif liq < 10000: score = max(0, score - 2.0)

    return min(10.0, max(0.0, round(score, 1)))

def get_balance():
    r = requests.post(SOLANA_RPC, json={'jsonrpc':'2.0','id':1,'method':'getBalance','params':[WALLET_ADDRESS]}, timeout=10)
    return r.json()['result']['value'] / 1e9

def get_usdc_balance():
    r = requests.post(SOLANA_RPC, json={'jsonrpc':'2.0','id':1,'method':'getTokenAccountsByOwner','params':[WALLET_ADDRESS,{'mint':USDC_MINT},{'encoding':'jsonParsed'}]}, timeout=10)
    accounts = r.json().get('result',{}).get('value',[])
    if accounts:
        return float(accounts[0]['account']['data']['parsed']['info']['tokenAmount']['uiAmount'] or 0)
    return 0.0

def execute_swap(input_mint, output_mint, amount_lamports):
    """Execute a Jupiter swap. amount_lamports is in base units (e.g. micro-USDC for USDC)."""
    keypair    = Keypair.from_base58_string(PRIVATE_KEY)
    quote      = requests.get(JUPITER_QUOTE, params={'inputMint': input_mint, 'outputMint': output_mint,
                               'amount': int(amount_lamports), 'slippageBps': 300, 'maxAccounts': 20}, timeout=10).json()
    if 'error' in quote: raise Exception('Quote: ' + str(quote['error']))
    swap_resp  = requests.post(JUPITER_SWAP, json={'quoteResponse': quote, 'userPublicKey': WALLET_ADDRESS,
                                'wrapAndUnwrapSol': True}, timeout=10).json()
    if 'error' in swap_resp: raise Exception('Swap: ' + str(swap_resp['error']))
    tx_key     = 'swapTransaction' if 'swapTransaction' in swap_resp else 'transaction'
    if tx_key not in swap_resp: raise Exception('No tx in response')
    raw_tx     = base64.b64decode(swap_resp[tx_key])
    tx         = VersionedTransaction.from_bytes(raw_tx)
    msg_bytes  = to_bytes_versioned(tx.message)
    sig        = keypair.sign_message(msg_bytes)
    tx.signatures[0] = sig
    encoded    = base64.b64encode(bytes(tx)).decode()
    result     = requests.post(SOLANA_RPC, json={'jsonrpc':'2.0','id':1,'method':'sendTransaction',
                                'params':[encoded,{'encoding':'base64','skipPreflight': False}]}, timeout=30).json()
    if 'error' in result: raise Exception('RPC: ' + str(result['error']))
    return result.get('result', str(result))

def execute_single_swap(action, mint, amount_str):
    """Called when invoked as: python orcagent_solana.py buy|sell MINT AMOUNT"""
    amount = float(amount_str)
    if action == 'buy':
        # amount is USDC dollars; convert to micro-USDC (6 decimals)
        tx = execute_swap(USDC_MINT, mint, int(amount * 1e6))
        print('BUY ' + mint[:16] + ' $' + str(round(amount, 2)) + ' TX:' + str(tx))
    elif action == 'sell':
        # amount is token units; convert to micro-token (assume 6 decimals)
        tx = execute_swap(mint, USDC_MINT, int(amount * 1e6))
        print('SELL ' + mint[:16] + ' amt:' + str(round(amount, 4)) + ' TX:' + str(tx))
    else:
        print('Unknown action: ' + action)
        sys.exit(1)

def run():
    """Standalone trading loop (not used by dashboard.py but available for direct CLI use)."""
    print('OrcAgent Solana — momentum scalper v5')
    print('Wallet: ' + str(WALLET_ADDRESS))
    print('TP:' + str(TAKE_PROFIT * 100) + '% | SL:' + str(STOP_LOSS * 100) + '% | Interval:' + str(INTERVAL) + 's')
    client    = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    positions = {}
    while True:
        try:
            tokens, trending_mints = discover_tokens()
            sol    = get_balance()
            usdc   = get_usdc_balance()
            print('SOL:' + str(round(sol, 4)) + ' USDC:' + str(round(usdc, 2)))

            # Score and filter for momentum
            candidates = []
            for t in tokens:
                mint = t['mint']
                data = get_token_data(mint)
                if not data or data['price'] <= 0 or data['liquidity'] < 15000: continue
                m5  = data['change5m']
                m15 = data.get('change15m', 0)
                is_tr = mint in trending_mints
                if (m5 >= 5 or m15 >= 10 or is_tr) and data['volume5m'] >= 5000:
                    sc = score_token(data)
                    candidates.append((sc, t, data, is_tr))
            candidates.sort(key=lambda x: x[0], reverse=True)

            for sc, token, data, is_tr in candidates:
                try:
                    mint  = token['mint']
                    label = token['label']
                    m5    = data['change5m']
                    if mint not in positions:
                        positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'peak_price': 0.0}
                    pos = positions[mint]

                    # Exit checks
                    if pos['amount'] > 0 and pos['buy_price'] > 0:
                        if data['price'] > pos['peak_price']: pos['peak_price'] = data['price']
                        chg = (data['price'] - pos['buy_price']) / pos['buy_price']
                        if chg >= TAKE_PROFIT:
                            tx = execute_swap(mint, USDC_MINT, int(pos['amount'] * 1e6))
                            print('TAKE PROFIT ' + label + ' +' + str(round(chg * 100, 1)) + '% TX:' + str(tx))
                            pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                        elif chg <= -STOP_LOSS:
                            tx = execute_swap(mint, USDC_MINT, int(pos['amount'] * 1e6))
                            print('STOP LOSS ' + label + ' ' + str(round(chg * 100, 1)) + '% TX:' + str(tx))
                            pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                        elif m5 < 5:
                            tx = execute_swap(mint, USDC_MINT, int(pos['amount'] * 1e6))
                            print('MOMENTUM DIED ' + label + ' m5=' + str(round(m5, 1)) + '% TX:' + str(tx))
                            pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                        continue

                    # Entry: score ≥ 4, momentum (m5≥5 / m15≥10 / trending)
                    if sc >= 4 and (m5 >= 5 or data.get('change15m', 0) >= 10 or is_tr) and usdc > 5:
                        spend = min(usdc * 0.20, MAX_USDC / 4)
                        tx    = execute_swap(USDC_MINT, mint, int(spend * 1e6))
                        print('BUY ' + label + ' $' + str(round(spend, 2)) + ' score:' + str(sc) + ' m5:+' + str(round(m5, 1)) + '% TX:' + str(tx))
                        pos['amount']     = spend / data['price']
                        pos['buy_price']  = data['price']
                        pos['peak_price'] = data['price']
                        usdc -= spend
                except Exception as e:
                    print(token['label'] + ' error: ' + str(e))
        except Exception as e:
            print('Error: ' + str(e))
        time.sleep(INTERVAL)

if __name__ == '__main__':
    if len(sys.argv) >= 4:
        # Single swap mode: python orcagent_solana.py buy|sell MINT AMOUNT
        execute_single_swap(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        run()
