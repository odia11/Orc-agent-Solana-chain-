import threading, time, json, os, sys, subprocess, requests, logging
from flask import Flask, jsonify, request, send_from_directory, redirect
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

BASE = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE, 'trades.log')
STATE_FILE = os.path.join(BASE, 'bot_state.json')

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
}

trader_thread = None
sniper_thread = None
trader_stop = threading.Event()
sniper_stop = threading.Event()

WALLET_ADDRESS = os.getenv('WALLET_ADDRESS', '')
USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
SOLANA_RPC = 'https://api.mainnet-beta.solana.com'

X_CLIENT_ID     = os.getenv('X_CLIENT_ID', '')
X_CLIENT_SECRET = os.getenv('X_CLIENT_SECRET', '')
X_CALLBACK_URL  = os.getenv('X_CALLBACK_URL', '')

x_state = {
    'verifier':      None,
    'access_token':  None,
    'refresh_token': None,
    'username':      None,
    'connected':     False,
}

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
    state['log_lines'].insert(0, {'t': t, 'msg': msg})
    if len(state['log_lines']) > 100:
        state['log_lines'].pop()

def get_sol_balance():
    try:
        r = requests.post(SOLANA_RPC, json={'jsonrpc':'2.0','id':1,'method':'getBalance','params':[WALLET_ADDRESS]}, timeout=8)
        return r.json()['result']['value'] / 1e9
    except: return state['sol']

def get_usdc_balance():
    try:
        r = requests.post(SOLANA_RPC, json={'jsonrpc':'2.0','id':1,'method':'getTokenAccountsByOwner','params':[WALLET_ADDRESS,{'mint':USDC_MINT},{'encoding':'jsonParsed'}]}, timeout=8)
        accounts = r.json().get('result',{}).get('value',[])
        if accounts:
            return float(accounts[0]['account']['data']['parsed']['info']['tokenAmount']['uiAmount'] or 0)
        return 0.0
    except: return state['usdc']

def get_token_data(mint):
    try:
        r = requests.get('https://api.dexscreener.com/latest/dex/tokens/' + mint, timeout=8)
        pairs = r.json().get('pairs', [])
        if not pairs: return None
        p = pairs[0]
        base = p.get('baseToken', {})
        return {
            'symbol': base.get('symbol', '') or '',
            'name': base.get('name', '') or '',
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

def balance_loop():
    while True:
        try:
            state['sol'] = round(get_sol_balance(), 4)
            state['usdc'] = round(get_usdc_balance(), 2)
        except: pass
        time.sleep(30)

def token_loop():
    while True:
        try:
            tokens_data = []
            for t in TOKENS:
                data = get_token_data(t['mint'])
                if data:
                    sc = score_token(data)
                    tokens_data.append({
                        'mint': t['mint'],
                        'symbol': data['symbol'] or t['label'],
                        'name': data['name'] or data['symbol'] or t['label'],
                        'price': data['price'],
                        'change5m': data['change5m'],
                        'change1h': data['change1h'],
                        'volume1h': data['volume1h'],
                        'liquidity': data['liquidity'],
                        'score': sc,
                    })
            state['tokens'] = tokens_data
        except: pass
        time.sleep(60)

def trader_loop(stop_event, config):
    add_log('Trader started — scanning every ' + str(config.get('interval', 300)) + 's')
    positions = {t['mint']: {'amount': 0.0, 'buy_price': 0.0} for t in TOKENS}
    while not stop_event.is_set():
        try:
            usdc = state['usdc']
            open_pos = sum(1 for p in positions.values() if p['amount'] > 0)
            state['positions'] = open_pos
            add_log('--- SOL:' + str(state['sol']) + ' USDC:' + str(usdc) + ' Positions:' + str(open_pos) + '/3 ---')
            for t in TOKENS:
                if stop_event.is_set(): break
                data = get_token_data(t['mint'])
                if not data: continue
                sc = score_token(data)
                label = data['symbol'] or data['name'] or t['label']
                decision = 'BUY' if sc >= 5 else ('SELL' if sc <= -3 else 'HOLD')
                add_log(label + ' $' + str(round(data['price'], 8)) + ' score:' + str(sc) + ' [' + decision + ']')
                if decision == 'BUY' and usdc > 3 and open_pos < 3 and positions[t['mint']]['amount'] == 0:
                    spend = round(min(usdc * config.get('trade_pct', 0.20), config.get('snipe_amount', 1.0) * 3), 2)
                    add_log('BUY ' + label + ' $' + str(spend) + ' (executing via orcagent_solana.py)')
                    os.system('cd "' + BASE + '" && python orcagent_solana.py buy ' + t['mint'] + ' ' + str(spend) + ' &')
        except Exception as e:
            add_log('Trader error: ' + str(e))
        stop_event.wait(config.get('interval', 300))
    add_log('Trader stopped')

sniped = set()
pending = {}

def sniper_loop(stop_event, config):
    add_log('Sniper started — watching for new launches every 15s')
    add_log('Min liq: $' + str(config.get('min_liq', 1000)) + ' | Delay: ' + str(config.get('delay', 600)) + 's | Amount: $' + str(config.get('snipe_amount', 1.0)))
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
                    state['queue_items'].append({'mint': mint[:16]+'...', 'queued': time.time(), 'delay': config.get('delay', 600)})
                    state['queue_count'] = len([q for q in state['queue_items'] if time.time()-q['queued'] < config.get('delay',600)])
                    add_log('SNIPER: Queued ' + mint[:16] + '... (buy in ' + str(config.get('delay',600)) + 's)')

            now = time.time()
            for mint in list(pending.keys()):
                if mint in sniped: del pending[mint]; continue
                if now - pending[mint] < config.get('delay', 600): continue
                del pending[mint]
                if state['usdc'] - 3.0 < config.get('snipe_amount', 1.0):
                    add_log('SNIPER: SKIP ' + mint[:16] + '... not enough USDC')
                    sniped.add(mint)
                    continue
                data = get_token_data(mint)
                if not data:
                    add_log('SNIPER: SKIP ' + mint[:16] + '... no data')
                    sniped.add(mint)
                    continue
                liq = data.get('liquidity', 0)
                if liq < config.get('min_liq', 1000):
                    add_log('SNIPER: SKIP ' + mint[:16] + '... liq too low $' + str(round(liq)))
                    sniped.add(mint)
                    continue
                if liq > config.get('max_liq', 50000):
                    add_log('SNIPER: SKIP ' + mint[:16] + '... liq too high $' + str(round(liq)))
                    sniped.add(mint)
                    continue
                add_log('SNIPER: PASS liq=$' + str(round(liq)) + ' — buying $' + str(config.get('snipe_amount', 1.0)))
                os.system('cd "' + BASE + '" && python orcagent_solana.py buy ' + mint + ' ' + str(config.get('snipe_amount', 1.0)) + ' &')
                sniped.add(mint)
                state['queue_items'] = [q for q in state['queue_items'] if mint[:16] not in q['mint']]
        except Exception as e:
            add_log('Sniper error: ' + str(e))
        stop_event.wait(15)
    add_log('Sniper stopped')

@app.route('/')
def index():
    return send_from_directory(BASE, 'dashboard.html')

@app.route('/api/state')
def api_state():
    return jsonify({
        'trader_running': state['trader_running'],
        'sniper_running': state['sniper_running'],
        'usdc': state['usdc'],
        'sol': state['sol'],
        'positions': state['positions'],
        'queue_count': len([q for q in state['queue_items'] if time.time()-q['queued'] < 600]),
        'log_lines': state['log_lines'][:40],
        'tokens': state['tokens'],
        'queue_items': [{'mint': q['mint'], 'pct': min(100, round((time.time()-q['queued'])/q['delay']*100)), 'remaining': max(0, int(q['delay']-(time.time()-q['queued'])))} for q in state['queue_items']],
    })

@app.route('/api/trader/start', methods=['POST'])
def start_trader():
    global trader_thread, trader_stop
    if state['trader_running']:
        return jsonify({'ok': False, 'msg': 'Already running'})
    config = request.json or {}
    trader_stop = threading.Event()
    trader_thread = threading.Thread(target=trader_loop, args=(trader_stop, config), daemon=True)
    trader_thread.start()
    state['trader_running'] = True
    return jsonify({'ok': True})

@app.route('/api/trader/stop', methods=['POST'])
def stop_trader():
    global trader_stop
    trader_stop.set()
    state['trader_running'] = False
    return jsonify({'ok': True})

@app.route('/api/sniper/start', methods=['POST'])
def start_sniper():
    global sniper_thread, sniper_stop
    if state['sniper_running']:
        return jsonify({'ok': False, 'msg': 'Already running'})
    config = request.json or {}
    sniper_stop = threading.Event()
    sniper_thread = threading.Thread(target=sniper_loop, args=(sniper_stop, config), daemon=True)
    sniper_thread.start()
    state['sniper_running'] = True
    return jsonify({'ok': True})

@app.route('/api/sniper/stop', methods=['POST'])
def stop_sniper():
    global sniper_stop
    sniper_stop.set()
    state['sniper_running'] = False
    state['queue_items'] = []
    return jsonify({'ok': True})

@app.route('/api/market')
def api_market():
    return jsonify({'tokens': state['tokens']})

@app.route('/api/log')
def api_log():
    try:
        with open(LOG_FILE, encoding='utf-8') as f:
            lines = f.readlines()[-50:]
        return jsonify({'lines': [l.strip() for l in reversed(lines)]})
    except:
        return jsonify({'lines': []})

# ── X OAUTH 2.0 WITH PKCE ──

@app.route('/api/x/verifier', methods=['POST'])
def x_store_verifier():
    data = request.json or {}
    x_state['verifier'] = data.get('verifier')
    return jsonify({'ok': True})

@app.route('/x-callback')
def x_callback():
    code  = request.args.get('code')
    error = request.args.get('error')
    if error or not code or not x_state.get('verifier'):
        return '<script>window.close()</script>'
    try:
        r = requests.post(
            'https://api.twitter.com/2/oauth2/token',
            auth=(X_CLIENT_ID, X_CLIENT_SECRET),
            data={
                'code':          code,
                'grant_type':    'authorization_code',
                'redirect_uri':  X_CALLBACK_URL,
                'code_verifier': x_state['verifier'],
            },
            timeout=10,
        )
        tokens = r.json()
        access_token = tokens.get('access_token')
        if not access_token:
            return '<script>window.close()</script>'
        me = requests.get(
            'https://api.twitter.com/2/users/me',
            headers={'Authorization': 'Bearer ' + access_token},
            timeout=8,
        ).json()
        x_state['access_token']  = access_token
        x_state['refresh_token'] = tokens.get('refresh_token')
        x_state['username']      = me.get('data', {}).get('username', 'user')
        x_state['connected']     = True
        x_state['verifier']      = None
    except Exception as e:
        add_log('X OAuth error: ' + str(e))
    return '<script>window.close()</script>'

@app.route('/api/x/status')
def x_status():
    return jsonify({
        'connected': x_state['connected'],
        'username':  x_state.get('username', ''),
    })

def _x_refresh():
    if not x_state.get('refresh_token'):
        return False
    try:
        r = requests.post(
            'https://api.twitter.com/2/oauth2/token',
            auth=(X_CLIENT_ID, X_CLIENT_SECRET),
            data={'grant_type': 'refresh_token', 'refresh_token': x_state['refresh_token']},
            timeout=10,
        )
        t = r.json()
        if t.get('access_token'):
            x_state['access_token']  = t['access_token']
            x_state['refresh_token'] = t.get('refresh_token', x_state['refresh_token'])
            return True
    except:
        pass
    return False

@app.route('/api/x/tweet', methods=['POST'])
def x_post_tweet():
    if not x_state['connected'] or not x_state.get('access_token'):
        return jsonify({'ok': False, 'msg': 'Not connected to X'})
    text = (request.json or {}).get('text', '').strip()
    if not text:
        return jsonify({'ok': False, 'msg': 'Empty text'})
    if len(text) > 280:
        text = text[:277] + '...'
    def _post(token):
        return requests.post(
            'https://api.twitter.com/2/tweets',
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
            json={'text': text},
            timeout=10,
        )
    r = _post(x_state['access_token'])
    if r.status_code == 401 and _x_refresh():
        r = _post(x_state['access_token'])
    if r.status_code in (200, 201):
        add_log('X: posted — ' + text[:60])
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'msg': r.text[:200]})

@app.route('/api/x/logout', methods=['POST'])
def x_logout():
    x_state.update({'access_token': None, 'refresh_token': None,
                    'username': None, 'connected': False, 'verifier': None})
    return jsonify({'ok': True})

# Start background threads on import so gunicorn picks them up
threading.Thread(target=balance_loop, daemon=True).start()
threading.Thread(target=token_loop, daemon=True).start()
add_log('OrcAgent started')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print('OrcAgent Dashboard running on port', port)
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
