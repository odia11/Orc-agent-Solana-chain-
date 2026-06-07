import threading, time, json, os, sys, requests, logging, webbrowser
from flask import Flask, jsonify, request, send_from_directory, render_template_string
from dotenv import load_dotenv, set_key

if getattr(sys, 'frozen', False):
    BASE = os.path.dirname(sys.executable)
else:
    BASE = os.path.dirname(os.path.abspath(__file__))

ENV_FILE = os.path.join(BASE, '.env')
LOG_FILE = os.path.join(BASE, 'trades.log')
load_dotenv(ENV_FILE)

logging.basicConfig(level=logging.WARNING)
app = Flask(__name__, static_folder=os.path.join(BASE, 'static'))

state = {
    'trader_running': False,
    'sniper_running': False,
    'usdc': 0.0,
    'sol': 0.0,
    'positions': 0,
    'queue_count': 0,
    'log_lines': [],
    'tokens': [],
    'queue_items': [],
    'configured': False,
}

trader_stop = threading.Event()
sniper_stop = threading.Event()
trader_thread = None
sniper_thread = None
sniped = set()
pending = {}

USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
SOLANA_RPC = 'https://api.mainnet-beta.solana.com'
JUPITER_QUOTE = 'https://api.jup.ag/swap/v1/quote'
JUPITER_SWAP = 'https://api.jup.ag/swap/v1/swap'

TOKENS = [
    {'mint': 'AqQtvEvV6wTGYjxSmzzWB11K2kmWBwbdfKCNkkW3pump', 'label': 'TOKEN2'},
    {'mint': '6xUoG8JtjYxKfBD3nsLGp8n9pGzKUigF5WTwWyy1pump', 'label': 'TOKEN3'},
    {'mint': '6KHeDqkeGc5JKAM9u5UKXZ1uqTeV4o45PAjAruHNpump', 'label': 'TOKEN5'},
    {'mint': 'Ac8EScJ4ufRo8PiFkun7diUrcCCktg4JvArb3mPmpump', 'label': 'TOKEN6'},
    {'mint': '7sgtaBCjEyo1LsPWfsfZXhj7H8q4SX1TJgyBZ7c5pump', 'label': 'TOKEN8'},
    {'mint': 'FeMbDoX7R1Psc4GEcvJdsbNbZA3bfztcyDCatJVJpump', 'label': 'TOKEN9'},
    {'mint': 'FzMe8rQ54FRg31KH1sHUbrdPEMMMJbLjNJ8miV8Tpump', 'label': 'TOKEN12'},
]

def add_log(msg):
    t = time.strftime('%H:%M:%S')
    entry = {'t': t, 'msg': msg}
    state['log_lines'].insert(0, entry)
    if len(state['log_lines']) > 200:
        state['log_lines'].pop()
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(time.strftime('%Y-%m-%d %H:%M:%S') + ' ' + msg + '\n')
    except: pass

def is_configured():
    return bool(os.getenv('WALLET_ADDRESS') and os.getenv('ANTHROPIC_API_KEY') and os.getenv('WALLET_PRIVATE_KEY'))

def get_sol():
    try:
        r = requests.post(SOLANA_RPC, json={'jsonrpc':'2.0','id':1,'method':'getBalance','params':[os.getenv('WALLET_ADDRESS','')]}, timeout=8)
        return round(r.json()['result']['value'] / 1e9, 4)
    except: return state['sol']

def get_usdc():
    try:
        r = requests.post(SOLANA_RPC, json={'jsonrpc':'2.0','id':1,'method':'getTokenAccountsByOwner','params':[os.getenv('WALLET_ADDRESS',''),{'mint':USDC_MINT},{'encoding':'jsonParsed'}]}, timeout=8)
        accounts = r.json().get('result',{}).get('value',[])
        if accounts:
            return round(float(accounts[0]['account']['data']['parsed']['info']['tokenAmount']['uiAmount'] or 0), 2)
        return 0.0
    except: return state['usdc']

def get_token_data(mint):
    try:
        r = requests.get('https://api.dexscreener.com/latest/dex/tokens/' + mint, timeout=8)
        pairs = r.json().get('pairs', [])
        if not pairs: return None
        p = pairs[0]
        return {
            'price': float(p.get('priceUsd', 0) or 0),
            'change5m': float(p.get('priceChange', {}).get('m5', 0) or 0),
            'change1h': float(p.get('priceChange', {}).get('h1', 0) or 0),
            'liquidity': float(p.get('liquidity', {}).get('usd', 0) or 0),
            'volume1h': float(p.get('volume', {}).get('h1', 0) or 0),
            'txns_buys': int(p.get('txns', {}).get('h1', {}).get('buys', 0) or 0),
            'txns_sells': int(p.get('txns', {}).get('h1', {}).get('sells', 0) or 0),
        }
    except: return None

def score_token(data):
    score = 0
    if data.get('price', 0) <= 0: return -99
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

def execute_swap(input_mint, output_mint, amount_usdc):
    import base64
    try:
        from solders.keypair import Keypair
        from solders.transaction import VersionedTransaction
    except ImportError:
        add_log('ERROR: solders not installed')
        return None
    pk = os.getenv('WALLET_PRIVATE_KEY', '')
    wallet = os.getenv('WALLET_ADDRESS', '')
    keypair = Keypair.from_base58_string(pk)
    amount = int(amount_usdc * 1e6)
    quote = requests.get(JUPITER_QUOTE, params={'inputMint': input_mint, 'outputMint': output_mint, 'amount': amount, 'slippageBps': 300, 'maxAccounts': 20}, timeout=10).json()
    if 'error' in quote: raise Exception('Quote error: ' + str(quote['error']))
    swap_resp = requests.post(JUPITER_SWAP, json={'quoteResponse': quote, 'userPublicKey': wallet, 'wrapAndUnwrapSol': True}, timeout=10).json()
    if 'error' in swap_resp: raise Exception('Swap error: ' + str(swap_resp['error']))
    tx_key = 'swapTransaction' if 'swapTransaction' in swap_resp else 'transaction'
    if tx_key not in swap_resp: raise Exception('No tx in response')
    raw_tx = base64.b64decode(swap_resp[tx_key])
    tx = VersionedTransaction.from_bytes(raw_tx)
    signed = VersionedTransaction(tx.message, [keypair])
    encoded = base64.b64encode(bytes(signed)).decode()
    result = requests.post(SOLANA_RPC, json={'jsonrpc':'2.0','id':1,'method':'sendTransaction','params':[encoded,{'encoding':'base64','skipPreflight':False}]}, timeout=30).json()
    if 'error' in result: raise Exception('RPC error: ' + str(result['error']))
    return result.get('result')

def balance_loop():
    while True:
        if is_configured():
            state['sol'] = get_sol()
            state['usdc'] = get_usdc()
            state['configured'] = True
        time.sleep(30)

def token_loop():
    while True:
        try:
            out = []
            for t in TOKENS:
                data = get_token_data(t['mint'])
                if data:
                    sc = score_token(data)
                    out.append({'label': t['label'], 'price': data['price'], 'change5m': data['change5m'], 'score': sc})
            state['tokens'] = out
        except: pass
        time.sleep(60)

def trader_loop(stop_event, cfg):
    add_log('Trader started — scanning every ' + str(cfg.get('interval', 300)) + 's')
    positions = {t['mint']: {'amount': 0.0, 'buy_price': 0.0, 'peak_price': 0.0} for t in TOKENS}
    SL = float(os.getenv('STOP_LOSS', 0.05))
    TP = float(os.getenv('TAKE_PROFIT', 0.15))
    TR = float(os.getenv('TRAILING_STOP', 0.03))
    while not stop_event.is_set():
        try:
            usdc = state['usdc']
            open_pos = sum(1 for p in positions.values() if p['amount'] > 0)
            state['positions'] = open_pos
            add_log('--- SOL:' + str(state['sol']) + ' USDC:' + str(usdc) + ' Positions:' + str(open_pos) + '/3 ---')
            for t in TOKENS:
                if stop_event.is_set(): break
                data = get_token_data(t['mint'])
                if not data or data['price'] <= 0: continue
                sc = score_token(data)
                pos = positions[t['mint']]
                decision = 'BUY' if sc >= 5 else ('SELL' if sc <= -3 else 'HOLD')
                add_log(t['label'] + ' $' + str(round(data['price'], 8)) + ' score:' + str(sc) + ' [' + decision + ']')
                if decision == 'BUY' and usdc > 3 and open_pos < 3 and pos['amount'] == 0:
                    spend = round(min(usdc * cfg.get('trade_pct', 0.20), cfg.get('max_usdc', 12.5)), 2)
                    try:
                        tx = execute_swap(USDC_MINT, t['mint'], spend)
                        add_log('BUY ' + t['label'] + ' $' + str(spend) + ' TX: ' + str(tx))
                        pos['amount'] = spend / data['price']
                        pos['buy_price'] = data['price']
                        pos['peak_price'] = data['price']
                        usdc -= spend
                        open_pos += 1
                    except Exception as e:
                        add_log(t['label'] + ' BUY error: ' + str(e))
                elif decision == 'SELL' and pos['amount'] > 0:
                    try:
                        tx = execute_swap(t['mint'], USDC_MINT, pos['amount'])
                        pnl = round((data['price'] - pos['buy_price']) / pos['buy_price'] * 100, 1)
                        add_log('SELL ' + t['label'] + ' PnL:' + str(pnl) + '% TX: ' + str(tx))
                        pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                        open_pos -= 1
                    except Exception as e:
                        add_log(t['label'] + ' SELL error: ' + str(e))
                if pos['amount'] > 0 and pos['buy_price'] > 0:
                    if data['price'] > pos['peak_price']: pos['peak_price'] = data['price']
                    chg = (data['price'] - pos['buy_price']) / pos['buy_price']
                    trail = (data['price'] - pos['peak_price']) / pos['peak_price']
                    if chg <= -SL or chg >= TP or (trail <= -TR and chg > 0):
                        reason = 'STOP LOSS' if chg <= -SL else ('TAKE PROFIT' if chg >= TP else 'TRAILING STOP')
                        try:
                            tx = execute_swap(t['mint'], USDC_MINT, pos['amount'])
                            add_log(reason + ' ' + t['label'] + ' ' + str(round(chg*100,1)) + '% TX: ' + str(tx))
                            pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                        except Exception as e:
                            add_log(t['label'] + ' exit error: ' + str(e))
        except Exception as e:
            add_log('Trader error: ' + str(e))
        stop_event.wait(cfg.get('interval', 300))
    add_log('Trader stopped')
    state['trader_running'] = False

def sniper_loop(stop_event, cfg):
    add_log('Sniper started — $' + str(cfg.get('snipe_amount', 1)) + ' per snipe | min liq $' + str(cfg.get('min_liq', 1000)) + ' | delay ' + str(cfg.get('delay', 600)) + 's')
    while not stop_event.is_set():
        try:
            r = requests.get('https://api.dexscreener.com/token-profiles/latest/v1', timeout=8)
            if r.status_code == 200:
                tokens = r.json() if isinstance(r.json(), list) else []
                for t in tokens[:5]:
                    mint = t.get('tokenAddress', '')
                    if not mint or mint in sniped or mint in pending: continue
                    if t.get('chainId') != 'solana': continue
                    pending[mint] = time.time()
                    state['queue_items'].append({'mint': mint[:16]+'...', 'queued': time.time(), 'delay': cfg.get('delay', 600)})
                    state['queue_count'] = len(pending)
                    add_log('SNIPER: Queued ' + mint[:16] + '...')
            now = time.time()
            for mint in list(pending.keys()):
                if mint in sniped: del pending[mint]; continue
                if now - pending[mint] < cfg.get('delay', 600): continue
                del pending[mint]
                if state['usdc'] - 3.0 < cfg.get('snipe_amount', 1.0):
                    add_log('SNIPER: SKIP ' + mint[:16] + '... not enough USDC'); sniped.add(mint); continue
                data = get_token_data(mint)
                if not data: sniped.add(mint); continue
                liq = data.get('liquidity', 0)
                if liq < cfg.get('min_liq', 1000):
                    add_log('SNIPER: SKIP ' + mint[:16] + '... liq $' + str(round(liq))); sniped.add(mint); continue
                if liq > cfg.get('max_liq', 50000):
                    add_log('SNIPER: SKIP ' + mint[:16] + '... too high $' + str(round(liq))); sniped.add(mint); continue
                add_log('SNIPER: PASS liq=$' + str(round(liq)) + ' buying $' + str(cfg.get('snipe_amount', 1.0)))
                try:
                    tx = execute_swap(USDC_MINT, mint, cfg.get('snipe_amount', 1.0))
                    add_log('SNIPER: BUY ' + mint[:16] + '... TX: ' + str(tx))
                except Exception as e:
                    add_log('SNIPER: BUY FAILED ' + mint[:16] + '... ' + str(e))
                sniped.add(mint)
                state['queue_items'] = [q for q in state['queue_items'] if mint[:16] not in q['mint']]
        except Exception as e:
            add_log('Sniper error: ' + str(e))
        stop_event.wait(15)
    add_log('Sniper stopped')
    state['sniper_running'] = False

@app.route('/')
def index():
    with open(os.path.join(BASE, 'dashboard.html'), encoding='utf-8') as f:
        return f.read()

@app.route('/api/state')
def api_state():
    return jsonify({
        'trader_running': state['trader_running'],
        'sniper_running': state['sniper_running'],
        'usdc': state['usdc'],
        'sol': state['sol'],
        'positions': state['positions'],
        'queue_count': len(pending),
        'log_lines': state['log_lines'][:50],
        'tokens': state['tokens'],
        'configured': is_configured(),
        'wallet': os.getenv('WALLET_ADDRESS', ''),
        'queue_items': [{'mint': q['mint'], 'pct': min(100, round((time.time()-q['queued'])/q['delay']*100)), 'remaining': max(0, int(q['delay']-(time.time()-q['queued'])))} for q in state['queue_items']],
    })

@app.route('/api/setup', methods=['POST'])
def api_setup():
    data = request.json
    for key, val in data.items():
        os.environ[key] = val
        set_key(ENV_FILE, key, val)
    return jsonify({'ok': True})

@app.route('/api/trader/start', methods=['POST'])
def start_trader():
    global trader_thread, trader_stop
    if state['trader_running']: return jsonify({'ok': False})
    cfg = request.json or {}
    trader_stop = threading.Event()
    trader_thread = threading.Thread(target=trader_loop, args=(trader_stop, cfg), daemon=True)
    trader_thread.start()
    state['trader_running'] = True
    return jsonify({'ok': True})

@app.route('/api/trader/stop', methods=['POST'])
def stop_trader():
    trader_stop.set()
    state['trader_running'] = False
    return jsonify({'ok': True})

@app.route('/api/sniper/start', methods=['POST'])
def start_sniper():
    global sniper_thread, sniper_stop
    if state['sniper_running']: return jsonify({'ok': False})
    cfg = request.json or {}
    sniper_stop = threading.Event()
    sniper_thread = threading.Thread(target=sniper_loop, args=(sniper_stop, cfg), daemon=True)
    sniper_thread.start()
    state['sniper_running'] = True
    return jsonify({'ok': True})

@app.route('/api/sniper/stop', methods=['POST'])
def stop_sniper():
    sniper_stop.set()
    state['sniper_running'] = False
    state['queue_items'] = []
    return jsonify({'ok': True})

@app.route('/api/log')
def api_log():
    try:
        with open(LOG_FILE, encoding='utf-8') as f:
            lines = f.readlines()[-100:]
        return jsonify({'lines': [l.strip() for l in reversed(lines)]})
    except: return jsonify({'lines': []})

def open_browser():
    time.sleep(1.5)
    webbrowser.open('http://localhost:5000')

if __name__ == '__main__':
    threading.Thread(target=balance_loop, daemon=True).start()
    threading.Thread(target=token_loop, daemon=True).start()
    threading.Thread(target=open_browser, daemon=True).start()
    add_log('OrcAgent App started')
    print('OrcAgent running at http://localhost:5000')
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)
