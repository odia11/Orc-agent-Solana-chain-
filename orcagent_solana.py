import anthropic, time, json, os, requests, base64, logging
from dotenv import load_dotenv
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction
load_dotenv()
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trades.log")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S", handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()])
log = logging.info
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
WALLET_ADDRESS = os.getenv('WALLET_ADDRESS')
PRIVATE_KEY = os.getenv('WALLET_PRIVATE_KEY')
MAX_USDC = float(os.getenv('MAX_USDC', 50))
STOP_LOSS = float(os.getenv('STOP_LOSS', 0.05))
TAKE_PROFIT = float(os.getenv('TAKE_PROFIT', 0.15))
TRAILING_STOP = float(os.getenv('TRAILING_STOP', 0.03))
INTERVAL = int(os.getenv('INTERVAL', 300))
# --- NEW: per-trade cap and position limit ---
MAX_TRADE_PCT = float(os.getenv('MAX_TRADE_PCT', 0.20))   # max 20% of USDC balance per trade
MAX_OPEN_POSITIONS = int(os.getenv('MAX_OPEN_POSITIONS', 3))  # max 3 open trades at once
MIN_USDC_RESERVE = float(os.getenv('MIN_USDC_RESERVE', 3.0))  # always keep $3 USDC in reserve
# --------------------------------------------
SOLANA_RPC = 'https://api.mainnet-beta.solana.com'
JUPITER_QUOTE = 'https://api.jup.ag/swap/v1/quote'
JUPITER_SWAP = 'https://api.jup.ag/swap/v1/swap'
USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
TOKENS = [
    {'mint': 'HMfERpVKozrefwou3dvZEegMdmyiKzeWBBDcsijDpump', 'label': 'TOKEN1'},
    {'mint': 'AqQtvEvV6wTGYjxSmzzWB11K2kmWBwbdfKCNkkW3pump', 'label': 'TOKEN2'},
    {'mint': '6xUoG8JtjYxKfBD3nsLGp8n9pGzKUigF5WTwWyy1pump', 'label': 'TOKEN3'},
    {'mint': 'uuxWwFL6G9UjiYRZvWxJrSB18V1oKBgYrmueamREK57', 'label': 'TOKEN4'},
    {'mint': '6KHeDqkeGc5JKAM9u5UKXZ1uqTeV4o45PAjAruHNpump', 'label': 'TOKEN5'},
    {'mint': 'Ac8EScJ4ufRo8PiFkun7diUrcCCktg4JvArb3mPmpump', 'label': 'TOKEN6'},
    {'mint': 'aLqb3HVkpHardDE992xHf1NBnw55C2f88hkEZ3mpump', 'label': 'TOKEN7'},
    {'mint': '7sgtaBCjEyo1LsPWfsfZXhj7H8q4SX1TJgyBZ7c5pump', 'label': 'TOKEN8'},
    {'mint': 'FeMbDoX7R1Psc4GEcvJdsbNbZA3bfztcyDCatJVJpump', 'label': 'TOKEN9'},
    {'mint': 'ACtfUWtgvaXrQGNMiohTusi5jcx5RJf5zwu9aAxkpump', 'label': 'TOKEN10'},
    {'mint': '78B31QV1rtyoe2EYvVNjBVjeowyrtcH5FPTE4tCypump', 'label': 'TOKEN11'},
    {'mint': 'FzMe8rQ54FRg31KH1sHUbrdPEMMMJbLjNJ8miV8Tpump', 'label': 'TOKEN12'},
]
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
    if 'error' in quote:
        raise Exception('Jupiter quote error: ' + str(quote['error']))
    swap_resp = requests.post(JUPITER_SWAP, json={'quoteResponse': quote, 'userPublicKey': WALLET_ADDRESS, 'wrapAndUnwrapSol': True}, timeout=10).json()
    if 'error' in swap_resp:
        raise Exception('Jupiter swap error: ' + str(swap_resp['error']))
    tx_key = 'swapTransaction' if 'swapTransaction' in swap_resp else 'transaction'
    if tx_key not in swap_resp:
        raise Exception('No transaction in swap response: ' + str(list(swap_resp.keys())))
    raw_tx = base64.b64decode(swap_resp[tx_key])
    # Sign using VersionedTransaction.populate — the correct way to sign versioned txs
    tx = VersionedTransaction.from_bytes(raw_tx)
    signed_tx = VersionedTransaction(tx.message, [keypair])
    encoded = base64.b64encode(bytes(signed_tx)).decode()
    result = requests.post(SOLANA_RPC, json={'jsonrpc': '2.0', 'id': 1, 'method': 'sendTransaction', 'params': [encoded, {'encoding': 'base64', 'skipPreflight': False}]}, timeout=30).json()
    if 'error' in result:
        raise Exception('RPC error: ' + str(result['error']))
    return result.get('result', str(result))

def count_open_positions(positions):
    return sum(1 for p in positions.values() if p['amount'] > 0)

def run():
    log('OrcAgent Solana SMART SCALPER v4 started')
    log('Wallet: ' + str(WALLET_ADDRESS))
    log('Monitoring ' + str(len(TOKENS)) + ' tokens | Interval: ' + str(INTERVAL) + 's')
    log('SL: ' + str(STOP_LOSS*100) + '% | TP: ' + str(TAKE_PROFIT*100) + '% | Trailing: ' + str(TRAILING_STOP*100) + '%')
    log('Max trade: ' + str(MAX_TRADE_PCT*100) + '% of balance | Max positions: ' + str(MAX_OPEN_POSITIONS) + ' | Reserve: $' + str(MIN_USDC_RESERVE))
    positions = {t['mint']: {'amount': 0.0, 'buy_price': 0.0, 'peak_price': 0.0} for t in TOKENS}
    while True:
        try:
            sol = get_balance()
            usdc = get_usdc_balance()
            open_positions = count_open_positions(positions)
            log('--- SOL:' + str(round(sol,4)) + ' USDC:' + str(round(usdc,2)) + ' Positions:' + str(open_positions) + '/' + str(MAX_OPEN_POSITIONS) + ' ---')
            scored = []
            for token in TOKENS:
                try:
                    data = get_token_data(token['mint'])
                    if data: scored.append((score_token(data), token, data))
                except: pass
            scored.sort(key=lambda x: x[0], reverse=True)
            for score, token, data in scored:
                try:
                    pos = positions[token['mint']]
                    res = ai_decision(token['label'], data, usdc)
                    log(token['label'] + ' $' + str(data['price']) + ' 5m:' + str(data['change5m']) + '% score:' + str(score) + ' [' + res['decision'] + '] ' + res['reasoning'][:40])

                    if res['decision'] == 'BUY':
                        open_positions = count_open_positions(positions)
                        spendable = usdc - MIN_USDC_RESERVE  # never touch the reserve
                        if open_positions >= MAX_OPEN_POSITIONS:
                            log('SKIP ' + token['label'] + ' — max positions reached (' + str(MAX_OPEN_POSITIONS) + ')')
                        elif spendable < 1.0:
                            log('SKIP ' + token['label'] + ' — not enough USDC after reserve ($' + str(round(usdc,2)) + ')')
                        else:
                            # cap: lowest of (AI suggestion) vs (MAX_TRADE_PCT of balance) vs (MAX_USDC/4)
                            ai_amount = spendable * res['amount_pct']
                            pct_cap = usdc * MAX_TRADE_PCT
                            hard_cap = MAX_USDC / 4
                            spend = min(ai_amount, pct_cap, hard_cap, spendable)
                            spend = round(spend, 2)
                            log('BUY SIZE: AI=$' + str(round(ai_amount,2)) + ' PctCap=$' + str(round(pct_cap,2)) + ' HardCap=$' + str(round(hard_cap,2)) + ' -> Spending=$' + str(spend))
                            tx = execute_swap(USDC_MINT, token['mint'], int(spend * 1e6))
                            log('BUY ' + token['label'] + ' $' + str(spend) + ' TX: ' + str(tx))
                            pos['amount'] += spend / data['price']
                            pos['buy_price'] = data['price']
                            pos['peak_price'] = data['price']
                            usdc -= spend

                    elif res['decision'] == 'SELL' and pos['amount'] > 0:
                        tx = execute_swap(token['mint'], USDC_MINT, int(pos['amount'] * 1e6))
                        pnl = (data['price'] - pos['buy_price']) / pos['buy_price'] * 100
                        log('SELL ' + token['label'] + ' PnL:' + str(round(pnl,1)) + '% TX: ' + str(tx))
                        usdc += pos['amount'] * data['price']
                        pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0

                    if pos['amount'] > 0 and pos['buy_price'] > 0:
                        if data['price'] > pos['peak_price']: pos['peak_price'] = data['price']
                        chg = (data['price'] - pos['buy_price']) / pos['buy_price']
                        trail = (data['price'] - pos['peak_price']) / pos['peak_price']
                        if chg <= -STOP_LOSS:
                            tx = execute_swap(token['mint'], USDC_MINT, int(pos['amount'] * 1e6))
                            log('STOP LOSS ' + token['label'] + ' ' + str(round(chg*100,1)) + '%')
                            usdc += pos['amount'] * data['price']
                            pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                        elif chg >= TAKE_PROFIT:
                            tx = execute_swap(token['mint'], USDC_MINT, int(pos['amount'] * 1e6))
                            log('TAKE PROFIT ' + token['label'] + ' +' + str(round(chg*100,1)) + '%')
                            usdc += pos['amount'] * data['price']
                            pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                        elif trail <= -TRAILING_STOP and chg > 0:
                            tx = execute_swap(token['mint'], USDC_MINT, int(pos['amount'] * 1e6))
                            log('TRAILING STOP ' + token['label'] + ' locked:' + str(round(chg*100,1)) + '%')
                            usdc += pos['amount'] * data['price']
                            pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                except Exception as e:
                    log(token['label'] + ' error: ' + str(e))
            log('Sleeping ' + str(INTERVAL) + 's...')
        except Exception as e:
            log('Error: ' + str(e))
        time.sleep(INTERVAL)

if __name__ == '__main__': run()
