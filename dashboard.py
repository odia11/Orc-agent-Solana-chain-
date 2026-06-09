import threading, time, json, os, sys, subprocess, requests, logging, hashlib, base64, traceback, datetime, sqlite3
from urllib.parse import urlencode
from flask import Flask, jsonify, request, send_from_directory, redirect, session
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.fernet import Fernet
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'orcagent-dev-secret-change-in-prod')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

BASE       = os.path.dirname(os.path.abspath(__file__))
LOG_FILE   = os.path.join(BASE, 'trades.log')
STATE_FILE = os.path.join(BASE, 'bot_state.json')
DB_FILE    = os.path.join(BASE, 'orcagent.db')

WALLET_ADDRESS = os.environ.get('WALLET_ADDRESS', '')
USDC_MINT      = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
SOLANA_RPC     = 'https://api.mainnet-beta.solana.com'

# ── FERNET ENCRYPTION ──
_enc_key_str = os.environ.get('ENCRYPTION_KEY', '')
if _enc_key_str:
    try:
        _fernet = Fernet(_enc_key_str.encode())
    except Exception:
        _k = Fernet.generate_key()
        _fernet = Fernet(_k)
        print('WARNING: Invalid ENCRYPTION_KEY format. Ephemeral key used: ' + _k.decode(), flush=True)
else:
    _k = Fernet.generate_key()
    _fernet = Fernet(_k)
    print('WARNING: ENCRYPTION_KEY not set. Private keys will NOT survive restart.', flush=True)
    print('Set ENCRYPTION_KEY=' + _k.decode() + ' in your environment.', flush=True)

def encrypt_key(raw: str) -> str:
    return _fernet.encrypt(raw.encode()).decode()

def decrypt_key(enc: str) -> str:
    return _fernet.decrypt(enc.encode()).decode()

# ── SQLITE DATABASE ──
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id                   INTEGER PRIMARY KEY AUTOINCREMENT,
        x_username           TEXT UNIQUE NOT NULL,
        wallet_address       TEXT DEFAULT '',
        encrypted_private_key TEXT DEFAULT '',
        trading_active       INTEGER DEFAULT 0,
        max_trade_size       REAL DEFAULT 12.5,
        daily_loss_limit     REAL DEFAULT 50.0,
        created_at           TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS trades (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id      INTEGER NOT NULL,
        token        TEXT,
        entry_price  REAL,
        exit_price   REAL,
        amount       REAL,
        pnl          REAL,
        timestamp    TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

def get_or_create_user(username: str) -> int:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO users (x_username) VALUES (?)', (username,))
    conn.commit()
    c.execute('SELECT id FROM users WHERE x_username=?', (username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

# ── GLOBAL STATE ──
trader_thread = None
trader_stop   = threading.Event()

def _fresh_daily():
    return {
        'date': datetime.datetime.utcnow().strftime('%Y-%m-%d'),
        'total_pnl': 0.0, 'total_pnl_pct': 0.0,
        'trades': 0, 'wins': 0, 'best': None, 'worst': None, 'curve': [],
    }

state = {
    'trader_running': False,
    'usdc': 0.0, 'sol': 0.0,
    'positions': 0,
    'log_lines': [],
    'tokens': [],
    'wallet': WALLET_ADDRESS,
    'trades_history': [],
    'daily_stats': _fresh_daily(),
    'token_of_the_day': None,
    'totd_updated_at': 0.0,
}

# ── PER-USER STATE ──
user_states: dict = {}

def get_user_state(username: str) -> dict:
    if username not in user_states:
        user_states[username] = {
            'positions': {},
            'daily_stats': _fresh_daily(),
            'trades_history': [],
            'trader_running': False,
            'trader_stop': None,
            'trader_thread': None,
        }
    return user_states[username]

# ── X OAUTH ──
X_CLIENT_ID     = os.getenv('X_CLIENT_ID', '')
X_CLIENT_SECRET = os.getenv('X_CLIENT_SECRET', '')
CALLBACK_URL    = 'https://orc-agent-solana-chain-production.up.railway.app/x-callback'

def _https(url):
    """Force https:// — Railway proxy can produce http:// URLs."""
    return url.replace('http://', 'https://', 1) if url.startswith('http://') else url

x_state = {
    'verifier': None, 'access_token': None,
    'refresh_token': None, 'username': None, 'connected': False,
}

# ── TOKEN DISCOVERY ──
DISCOVERY_LIMIT = 20
TOTD_INTERVAL   = 900  # 15 minutes

def discover_tokens():
    mints = []
    seen  = {USDC_MINT}
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
    return mints[:DISCOVERY_LIMIT]

def add_log(msg):
    t = time.strftime('%H:%M:%S')
    state['log_lines'].insert(0, {'t': t, 'msg': msg})
    if len(state['log_lines']) > 100:
        state['log_lines'].pop()

def get_sol_balance():
    addr = state.get('wallet') or WALLET_ADDRESS
    if not addr: return state['sol']
    try:
        r = requests.post(SOLANA_RPC, json={'jsonrpc':'2.0','id':1,'method':'getBalance','params':[addr]}, timeout=8)
        return r.json()['result']['value'] / 1e9
    except: return state['sol']

def get_usdc_balance():
    addr = state.get('wallet') or WALLET_ADDRESS
    if not addr: return state['usdc']
    try:
        r = requests.post(SOLANA_RPC, json={'jsonrpc':'2.0','id':1,'method':'getTokenAccountsByOwner','params':[addr,{'mint':USDC_MINT},{'encoding':'jsonParsed'}]}, timeout=8)
        accounts = r.json().get('result',{}).get('value',[])
        if accounts:
            return float(accounts[0]['account']['data']['parsed']['info']['tokenAmount']['uiAmount'] or 0)
        return 0.0
    except: return state['usdc']

def _get_user_usdc(wallet_address: str) -> float:
    try:
        r = requests.post(SOLANA_RPC, json={'jsonrpc':'2.0','id':1,'method':'getTokenAccountsByOwner','params':[wallet_address,{'mint':USDC_MINT},{'encoding':'jsonParsed'}]}, timeout=8)
        accounts = r.json().get('result',{}).get('value',[])
        if accounts:
            return float(accounts[0]['account']['data']['parsed']['info']['tokenAmount']['uiAmount'] or 0)
    except: pass
    return 0.0

def get_token_data(mint):
    try:
        r = requests.get('https://api.dexscreener.com/latest/dex/tokens/' + mint, timeout=8)
        pairs = r.json().get('pairs', [])
        if not pairs: return None
        p    = pairs[0]
        base = p.get('baseToken', {})
        return {
            'symbol':    base.get('symbol', '') or '',
            'name':      base.get('name', '') or '',
            'price':     float(p.get('priceUsd', 0) or 0),
            'change5m':  float(p.get('priceChange', {}).get('m5', 0) or 0),
            'change1h':  float(p.get('priceChange', {}).get('h1', 0) or 0),
            'change24h': float(p.get('priceChange', {}).get('h24', 0) or 0),
            'liquidity': float(p.get('liquidity', {}).get('usd', 0) or 0),
            'volume1h':  float(p.get('volume', {}).get('h1', 0) or 0),
            'volume24h': float(p.get('volume', {}).get('h24', 0) or 0),
            'fdv':       float(p.get('fdv', 0) or p.get('marketCap', 0) or 0),
            'txns_buys':  int(p.get('txns', {}).get('h1', {}).get('buys', 0) or 0),
            'txns_sells': int(p.get('txns', {}).get('h1', {}).get('sells', 0) or 0),
        }
    except: return None

def score_token(data):
    score = 0
    if data.get('price', 0) <= 0: return -99
    if data['change5m'] > 2:    score += 3
    elif data['change5m'] > 0:  score += 1
    else:                        score -= 2
    if data['change1h'] > 5:    score += 3
    elif data['change1h'] > 0:  score += 1
    else:                        score -= 2
    if data['volume1h'] > 10000: score += 2
    elif data['volume1h'] > 1000: score += 1
    buy_ratio = data['txns_buys'] / max(data['txns_sells'], 1)
    if buy_ratio > 2:    score += 3
    elif buy_ratio > 1.2: score += 1
    else:                 score -= 1
    if data['liquidity'] < 1000:   score -= 3
    elif data['liquidity'] > 10000: score += 1
    return score

# ── BACKGROUND LOOPS ──
def totd_loop():
    for _ in range(20):
        if state['tokens']: break
        time.sleep(30)
    while True:
        try:
            tokens = state['tokens']
            if tokens:
                best = max(tokens, key=lambda t: t.get('change24h', 0))
                state['token_of_the_day'] = best
                state['totd_updated_at']  = time.time()
                add_log('Token of the Day: ' + best.get('symbol', '?') + ' (' +
                        ('+' if best.get('change24h', 0) >= 0 else '') +
                        str(round(best.get('change24h', 0), 1)) + '% 24h)')
        except: pass
        time.sleep(TOTD_INTERVAL)

def balance_loop():
    while True:
        try:
            state['sol']  = round(get_sol_balance(), 4)
            state['usdc'] = round(get_usdc_balance(), 2)
        except: pass
        time.sleep(30)

def token_loop():
    while True:
        try:
            mints       = discover_tokens()
            tokens_data = []
            for mint in mints:
                data = get_token_data(mint)
                if data and data['price'] > 0 and data['liquidity'] > 10000:
                    sc = score_token(data)
                    tokens_data.append({
                        'mint': mint,
                        'symbol':   data['symbol'] or mint[:8],
                        'name':     data['name'] or data['symbol'] or mint[:8],
                        'price':    data['price'],
                        'change5m': data['change5m'],
                        'change1h': data['change1h'],
                        'change24h':data['change24h'],
                        'volume1h': data['volume1h'],
                        'volume24h':data['volume24h'],
                        'liquidity':data['liquidity'],
                        'fdv':      data['fdv'],
                        'score':    sc,
                    })
            if tokens_data:
                state['tokens'] = tokens_data
                add_log('Market refresh: ' + str(len(tokens_data)) + ' live tokens discovered')
        except: pass
        time.sleep(120)

# ── TRADE RECORDING ──
def check_daily_reset():
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    if state['daily_stats']['date'] != today:
        state['daily_stats'] = _fresh_daily()

def check_daily_reset_user(us: dict):
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    if us.get('daily_stats', {}).get('date') != today:
        us['daily_stats'] = _fresh_daily()

def record_trade(symbol, entry, exit_price, amount, spend):
    check_daily_reset()
    now   = datetime.datetime.utcnow()
    today = now.strftime('%Y-%m-%d')
    pnl     = round(amount * (exit_price - entry), 4) if entry > 0 else 0.0
    pnl_pct = round((exit_price - entry) / entry * 100, 2) if entry > 0 else 0.0
    trade   = {
        'symbol': symbol, 'entry': entry, 'exit': exit_price,
        'amount': amount, 'spend': spend,
        'pnl': pnl, 'pnl_pct': pnl_pct,
        'time': now.strftime('%H:%M'), 'date': today, 'ts': now.timestamp(),
    }
    state['trades_history'].append(trade)
    if len(state['trades_history']) > 500:
        state['trades_history'] = state['trades_history'][-500:]
    ds = state['daily_stats']
    ds['total_pnl'] = round(ds['total_pnl'] + pnl, 4)
    ds['trades']   += 1
    if pnl > 0: ds['wins'] += 1
    today_spend   = sum(t['spend'] for t in state['trades_history'] if t['date'] == today)
    ds['total_pnl_pct'] = round(ds['total_pnl'] / today_spend * 100, 2) if today_spend else 0.0
    if ds['best']  is None or pnl_pct > ds['best']:  ds['best']  = pnl_pct
    if ds['worst'] is None or pnl_pct < ds['worst']: ds['worst'] = pnl_pct
    ds['curve'].append({'t': now.strftime('%H:%M'), 'v': ds['total_pnl']})

def _record_user_trade(user_id: int, us: dict, symbol: str, entry: float, exit_price: float, amount: float, spend: float):
    check_daily_reset_user(us)
    now   = datetime.datetime.utcnow()
    today = now.strftime('%Y-%m-%d')
    pnl     = round(amount * (exit_price - entry), 4) if entry > 0 else 0.0
    pnl_pct = round((exit_price - entry) / entry * 100, 2) if entry > 0 else 0.0
    trade   = {
        'symbol': symbol, 'entry': entry, 'exit': exit_price,
        'amount': amount, 'spend': spend, 'pnl': pnl, 'pnl_pct': pnl_pct,
        'time': now.strftime('%H:%M'), 'date': today, 'ts': now.timestamp(),
    }
    us['trades_history'].append(trade)
    if len(us['trades_history']) > 500:
        us['trades_history'] = us['trades_history'][-500:]
    ds = us['daily_stats']
    ds['total_pnl'] = round(ds.get('total_pnl', 0) + pnl, 4)
    ds['trades']    = ds.get('trades', 0) + 1
    if pnl > 0: ds['wins'] = ds.get('wins', 0) + 1
    today_spend   = sum(t['spend'] for t in us['trades_history'] if t.get('date') == today)
    ds['total_pnl_pct'] = round(ds['total_pnl'] / today_spend * 100, 2) if today_spend else 0.0
    if ds.get('best')  is None or pnl_pct > ds['best']:  ds['best']  = pnl_pct
    if ds.get('worst') is None or pnl_pct < ds['worst']: ds['worst'] = pnl_pct
    ds['curve'].append({'t': now.strftime('%H:%M'), 'v': ds['total_pnl']})
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute('INSERT INTO trades (user_id, token, entry_price, exit_price, amount, pnl) VALUES (?,?,?,?,?,?)',
                     (user_id, symbol, entry, exit_price, amount, pnl))
        conn.commit()
        conn.close()
    except: pass

# ── SWAP EXECUTION ──
def _execute_user_swap(wallet_address: str, private_key: str, action: str, mint: str, amount_str: str):
    """Execute a Jupiter swap with the user's private key passed via env (never command-line args)."""
    try:
        env = os.environ.copy()
        env['WALLET_ADDRESS']    = wallet_address
        env['WALLET_PRIVATE_KEY'] = private_key
        result = subprocess.run(
            [sys.executable, os.path.join(BASE, 'orcagent_solana.py'), action, mint, amount_str],
            env=env, capture_output=True, text=True, timeout=60
        )
        if result.stdout:
            add_log('Swap: ' + result.stdout.strip()[-80:])
    except Exception as e:
        add_log('Swap error: ' + str(e)[:80])

# ── GLOBAL TRADER ──
def trader_loop(stop_event, config):
    add_log('Trader started — scanning every ' + str(config.get('interval', 300)) + 's')
    positions = {}
    while not stop_event.is_set():
        try:
            check_daily_reset()
            usdc     = state['usdc']
            open_pos = sum(1 for p in positions.values() if p['amount'] > 0)
            state['positions'] = open_pos
            live = state['tokens']
            add_log('--- SOL:' + str(state['sol']) + ' USDC:' + str(usdc) + ' Pos:' + str(open_pos) + '/3 Tokens:' + str(len(live)) + ' ---')
            for t in live:
                if stop_event.is_set(): break
                mint = t['mint']
                if mint not in positions:
                    positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
                pos      = positions[mint]
                sc       = t['score']
                label    = t['symbol'] or t['name'] or mint[:8]
                decision = 'BUY' if sc >= 5 else ('SELL' if sc <= -3 else 'HOLD')
                add_log(label + ' $' + str(round(t['price'], 8)) + ' score:' + str(sc) + ' [' + decision + ']')
                if decision == 'BUY' and usdc > 3 and open_pos < 3 and pos['amount'] == 0:
                    spend = round(min(usdc * config.get('trade_pct', 0.20), config.get('max_usdc', 12.5)), 2)
                    add_log('BUY ' + label + ' $' + str(spend))
                    os.system('cd "' + BASE + '" && python orcagent_solana.py buy ' + mint + ' ' + str(spend) + ' &')
                    pos['amount'] = spend / t['price']
                    pos['buy_price'] = t['price']
                    pos['spend']  = spend
                    usdc -= spend; open_pos += 1
                elif decision == 'SELL' and pos['amount'] > 0:
                    record_trade(label, pos['buy_price'], t['price'], pos['amount'], pos['spend'])
                    pnl = round(pos['amount'] * (t['price'] - pos['buy_price']), 4)
                    add_log('SELL ' + label + ' PnL:' + ('+' if pnl >= 0 else '') + str(pnl))
                    os.system('cd "' + BASE + '" && python orcagent_solana.py sell ' + mint + ' ' + str(pos['amount']) + ' &')
                    pos['amount'] = pos['buy_price'] = pos['spend'] = 0.0
                    open_pos -= 1
        except Exception as e:
            add_log('Trader error: ' + str(e))
        stop_event.wait(config.get('interval', 300))
    add_log('Trader stopped')

# ── PER-USER TRADER ──
def user_trader_loop(stop_event, config, username):
    us = get_user_state(username)
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('SELECT id, wallet_address, encrypted_private_key, max_trade_size, daily_loss_limit FROM users WHERE x_username=?', (username,))
        row  = c.fetchone()
        conn.close()
    except Exception as e:
        add_log('[' + username + '] DB error: ' + str(e))
        us['trader_running'] = False
        return

    if not row or not row[2]:
        add_log('[' + username + '] No private key — configure in Settings first')
        us['trader_running'] = False
        return

    user_id           = row[0]
    wallet_address    = row[1] or ''
    max_usdc          = float(row[3] or config.get('max_usdc', 12.5))
    daily_loss_limit  = abs(float(row[4] or config.get('daily_loss_limit', 50.0)))

    if not wallet_address:
        add_log('[' + username + '] No wallet address — configure in Settings first')
        us['trader_running'] = False
        return

    try:
        private_key = decrypt_key(row[2])
    except Exception as e:
        add_log('[' + username + '] Key decryption failed: ' + str(e))
        us['trader_running'] = False
        return

    add_log('[' + username + '] Trader started — ' + wallet_address[:6] + '...' + wallet_address[-4:])
    positions = us['positions']

    try:
        while not stop_event.is_set():
            try:
                check_daily_reset_user(us)
                daily_loss = us['daily_stats'].get('total_pnl', 0)
                if daily_loss < -daily_loss_limit:
                    add_log('[' + username + '] Daily loss limit hit ($' + str(round(daily_loss, 2)) + ') — pausing 5 min')
                    stop_event.wait(300)
                    continue
                live     = state['tokens']
                open_pos = sum(1 for p in positions.values() if p.get('amount', 0) > 0)
                us_usdc  = _get_user_usdc(wallet_address)
                add_log('[' + username + '] USDC:' + str(round(us_usdc, 2)) + ' Pos:' + str(open_pos) + '/3')
                for t in live:
                    if stop_event.is_set(): break
                    mint  = t['mint']
                    if mint not in positions:
                        positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
                    pos      = positions[mint]
                    sc       = t['score']
                    label    = t['symbol'] or mint[:8]
                    decision = 'BUY' if sc >= 5 else ('SELL' if sc <= -3 else 'HOLD')
                    if decision == 'BUY' and us_usdc > 3 and open_pos < 3 and pos['amount'] == 0:
                        spend = round(min(us_usdc * config.get('trade_pct', 0.20), max_usdc), 2)
                        add_log('[' + username + '] BUY ' + label + ' $' + str(spend))
                        _execute_user_swap(wallet_address, private_key, 'buy', mint, str(spend))
                        pos['amount']    = spend / t['price']
                        pos['buy_price'] = t['price']
                        pos['spend']     = spend
                        us_usdc -= spend; open_pos += 1
                    elif decision == 'SELL' and pos.get('amount', 0) > 0:
                        add_log('[' + username + '] SELL ' + label)
                        _execute_user_swap(wallet_address, private_key, 'sell', mint, str(pos['amount']))
                        _record_user_trade(user_id, us, label, pos['buy_price'], t['price'], pos['amount'], pos['spend'])
                        pos['amount'] = pos['buy_price'] = pos['spend'] = 0.0
                        open_pos -= 1
            except Exception as e:
                add_log('[' + username + '] Trader error: ' + str(e))
            stop_event.wait(config.get('interval', 300))
    finally:
        private_key = None  # wipe from memory
        add_log('[' + username + '] Trader stopped, key wiped from memory')
        us['trader_running'] = False


# ══════════════════════════════════════════════════════
#  FLASK ROUTES
# ══════════════════════════════════════════════════════

@app.route('/')
def index():
    return send_from_directory(BASE, 'dashboard.html')

# ── WALLET ──
@app.route('/api/wallet/set', methods=['POST'])
def set_wallet():
    address = (request.json or {}).get('address', '').strip()
    if address:
        state['wallet'] = address
        add_log('Wallet connected: ' + address[:6] + '...' + address[-4:])
    else:
        state['wallet'] = WALLET_ADDRESS
        add_log('Wallet disconnected')
    return jsonify({'ok': True, 'wallet': state['wallet']})

# ── SETTINGS ──
@app.route('/api/settings', methods=['GET'])
def get_settings():
    username = x_state.get('username') or session.get('x_username', '')
    if not username:
        return jsonify({'ok': False, 'msg': 'Not authenticated with X'})
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute('SELECT wallet_address, encrypted_private_key, max_trade_size, daily_loss_limit FROM users WHERE x_username=?', (username,))
    row  = c.fetchone()
    conn.close()
    if row:
        return jsonify({
            'ok': True,
            'wallet_address':  row[0] or '',
            'has_key':         bool(row[1]),
            'max_trade_size':  row[2] or 12.5,
            'daily_loss_limit':row[3] or 50.0,
        })
    return jsonify({'ok': True, 'wallet_address': '', 'has_key': False, 'max_trade_size': 12.5, 'daily_loss_limit': 50.0})

@app.route('/api/settings', methods=['POST'])
def save_settings():
    username = x_state.get('username') or session.get('x_username', '')
    if not username:
        return jsonify({'ok': False, 'msg': 'Not authenticated with X'})
    data             = request.json or {}
    wallet_address   = data.get('wallet_address', '').strip()
    private_key_raw  = data.get('private_key', '').strip()
    max_trade_size   = float(data.get('max_trade_size', 12.5))
    daily_loss_limit = float(data.get('daily_loss_limit', 50.0))

    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute('SELECT id, encrypted_private_key FROM users WHERE x_username=?', (username,))
    row  = c.fetchone()

    if private_key_raw:
        try:
            encrypted = encrypt_key(private_key_raw)
        except Exception as e:
            conn.close()
            return jsonify({'ok': False, 'msg': 'Encryption failed: ' + str(e)})
    else:
        encrypted = row[1] if row else ''

    if row:
        c.execute('UPDATE users SET wallet_address=?, encrypted_private_key=?, max_trade_size=?, daily_loss_limit=? WHERE x_username=?',
                  (wallet_address, encrypted, max_trade_size, daily_loss_limit, username))
    else:
        c.execute('INSERT INTO users (x_username, wallet_address, encrypted_private_key, max_trade_size, daily_loss_limit) VALUES (?,?,?,?,?)',
                  (username, wallet_address, encrypted, max_trade_size, daily_loss_limit))
    conn.commit()
    conn.close()

    if wallet_address:
        state['wallet'] = wallet_address
    add_log('Settings saved for @' + username)
    return jsonify({'ok': True})

# ── STATE ──
@app.route('/api/state')
def api_state():
    username = x_state.get('username') or session.get('x_username', '')
    if username:
        us       = get_user_state(username)
        open_pos = sum(1 for p in us.get('positions', {}).values() if p.get('amount', 0) > 0)
        return jsonify({
            'trader_running': us.get('trader_running', False),
            'usdc': state['usdc'], 'sol': state['sol'],
            'positions': open_pos,
            'log_lines': state['log_lines'][:40],
            'tokens':    state['tokens'],
            'wallet':    state.get('wallet', ''),
        })
    return jsonify({
        'trader_running': state['trader_running'],
        'usdc': state['usdc'], 'sol': state['sol'],
        'positions': int(state.get('positions', 0)),
        'log_lines': state['log_lines'][:40],
        'tokens':    state['tokens'],
        'wallet':    state.get('wallet', ''),
    })

# ── TRADER START/STOP ──
@app.route('/api/trader/start', methods=['POST'])
def start_trader():
    global trader_thread, trader_stop
    username = x_state.get('username') or session.get('x_username', '')
    config   = request.json or {}

    if username:
        us = get_user_state(username)
        if us['trader_running']:
            return jsonify({'ok': False, 'msg': 'Already running'})
        us['trader_stop']   = threading.Event()
        us['trader_thread'] = threading.Thread(target=user_trader_loop, args=(us['trader_stop'], config, username), daemon=True)
        us['trader_thread'].start()
        us['trader_running'] = True
        return jsonify({'ok': True, 'user': username})

    if state['trader_running']:
        return jsonify({'ok': False, 'msg': 'Already running'})
    trader_stop    = threading.Event()
    trader_thread  = threading.Thread(target=trader_loop, args=(trader_stop, config), daemon=True)
    trader_thread.start()
    state['trader_running'] = True
    return jsonify({'ok': True})

@app.route('/api/trader/stop', methods=['POST'])
def stop_trader():
    global trader_stop
    username = x_state.get('username') or session.get('x_username', '')

    if username:
        us = get_user_state(username)
        if us.get('trader_stop'):
            us['trader_stop'].set()
        us['trader_running'] = False
        return jsonify({'ok': True})

    trader_stop.set()
    state['trader_running'] = False
    return jsonify({'ok': True})

# ── MARKET ──
@app.route('/api/market')
def api_market():
    return jsonify({'tokens': state['tokens']})

# ── TOTD ──
@app.route('/api/totd')
def api_totd():
    updated = state.get('totd_updated_at', 0)
    next_in = max(0.0, TOTD_INTERVAL - (time.time() - updated)) if updated else 0.0
    return jsonify({'token': state.get('token_of_the_day'), 'updated_at': updated, 'next_update_in': round(next_in)})

# ── TRADES ──
@app.route('/api/trades')
def api_trades():
    username = x_state.get('username') or session.get('x_username', '')
    if username:
        us = get_user_state(username)
        check_daily_reset_user(us)
        today        = us['daily_stats']['date']
        today_trades = [t for t in us.get('trades_history', []) if t.get('date') == today]
        return jsonify({'daily': us['daily_stats'], 'history': today_trades[-10:]})
    check_daily_reset()
    today        = state['daily_stats']['date']
    today_trades = [t for t in state['trades_history'] if t.get('date') == today]
    return jsonify({'daily': state['daily_stats'], 'history': today_trades[-10:]})

@app.route('/api/log')
def api_log():
    try:
        with open(LOG_FILE, encoding='utf-8') as f:
            lines = f.readlines()[-50:]
        return jsonify({'lines': [l.strip() for l in reversed(lines)]})
    except:
        return jsonify({'lines': []})

# ══════════════════════════════════════════════════════
#  X OAUTH 2.0 WITH PKCE
# ══════════════════════════════════════════════════════

@app.route('/api/x/auth')
def x_auth_start():
    if not X_CLIENT_ID:
        print('[X OAuth] ERROR: X_CLIENT_ID not set', flush=True)
        return 'X_CLIENT_ID not configured on server', 500
    verifier  = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    session['x_verifier'] = verifier
    x_state['verifier']   = verifier
    callback  = _https(CALLBACK_URL)
    auth_url  = 'https://twitter.com/i/oauth2/authorize?' + urlencode({
        'response_type': 'code', 'client_id': X_CLIENT_ID,
        'redirect_uri': callback,
        'scope': 'tweet.read tweet.write users.read offline.access',
        'state': 'orcagent',
        'code_challenge': challenge, 'code_challenge_method': 'S256',
    })
    print(f'[X OAuth] redirect_uri={callback}', flush=True)
    add_log('X OAuth: redirecting to Twitter')
    return redirect(auth_url)

_ERROR_PAGE = '''<!DOCTYPE html><html><body style="background:#0f0f0f;color:#ff5555;
font-family:monospace;text-align:center;padding:3rem">
<h2>❌ {title}</h2><p style="color:#aaa;font-size:13px">{msg}</p>
<button onclick="window.close()" style="margin-top:1.5rem;padding:10px 24px;background:#222;
color:#aaa;border:1px solid #444;border-radius:8px;font-family:monospace;cursor:pointer;
font-size:13px">Close &amp; try again</button>
</body></html>'''

@app.route('/x-callback')
def x_callback():
    print('[X callback] ── STEP 1: request received ──────────────────────', flush=True)
    print(f'[X callback] full URL     : {request.url}', flush=True)
    print(f'[X callback] args         : {dict(request.args)}', flush=True)

    code        = request.args.get('code')
    error       = request.args.get('error')
    state_param = request.args.get('state')

    print(f'[X callback] code         : {"YES (" + code[:12] + "...)" if code else "MISSING"}', flush=True)
    print(f'[X callback] error        : {error!r}', flush=True)

    session_verifier = session.get('x_verifier')
    memory_verifier  = x_state.get('verifier')
    verifier         = session_verifier or memory_verifier
    verifier_ok      = bool(verifier)
    add_log('X callback hit: code=' + ('YES' if code else 'NO') + ' verifier=' + ('OK' if verifier_ok else 'MISSING'))

    if error:
        add_log('X OAuth error: ' + error)
        return _ERROR_PAGE.format(title='X Auth Failed', msg='Twitter returned: ' + error)
    if not code:
        return _ERROR_PAGE.format(title='X Auth Failed', msg='No code returned by Twitter.')
    if not verifier_ok:
        add_log('X OAuth: verifier missing')
        return _ERROR_PAGE.format(title='X Auth Failed', msg='Session lost — please go back and try again.')

    try:
        credentials = base64.b64encode(f'{X_CLIENT_ID}:{X_CLIENT_SECRET}'.encode()).decode()
        r = requests.post(
            'https://api.twitter.com/2/oauth2/token',
            headers={'Authorization': f'Basic {credentials}', 'Content-Type': 'application/x-www-form-urlencoded'},
            data={'code': code, 'grant_type': 'authorization_code',
                  'redirect_uri': _https(CALLBACK_URL), 'code_verifier': verifier},
            timeout=10,
        )
        print(f'[X callback] token exchange status : {r.status_code}', flush=True)
        tokens       = r.json()
        access_token = tokens.get('access_token')
        if not access_token:
            err = tokens.get('error_description') or tokens.get('error') or str(tokens)
            add_log('X OAuth token exchange failed: ' + err)
            return _ERROR_PAGE.format(title='X Auth Failed', msg='Token exchange failed: ' + err)

        me_resp  = requests.get('https://api.twitter.com/2/users/me',
                                headers={'Authorization': 'Bearer ' + access_token}, timeout=8)
        username = me_resp.json().get('data', {}).get('username', 'user')
        print(f'[X callback] username : @{username}', flush=True)

        x_state['access_token']  = access_token
        x_state['refresh_token'] = tokens.get('refresh_token')
        x_state['username']      = username
        x_state['connected']     = True
        x_state['verifier']      = None
        session['x_connected']   = True
        session['x_username']    = username
        session.pop('x_verifier', None)

        # Create/update user record in DB
        try:
            get_or_create_user(username)
            add_log('X connected: @' + username + ' — user record ready')
        except Exception as e:
            add_log('DB user create error: ' + str(e))

    except Exception as e:
        print(f'[X callback] EXCEPTION: {e}', flush=True)
        print(traceback.format_exc(), flush=True)
        add_log('X OAuth exception: ' + str(e))
        return _ERROR_PAGE.format(title='X Auth Failed', msg=str(e))

    return redirect('/?x=1')

@app.route('/api/x/status')
def x_status():
    connected = x_state['connected'] or session.get('x_connected', False)
    username  = x_state.get('username') or session.get('x_username', '')
    return jsonify({'connected': connected, 'username': username})

def _x_refresh():
    if not x_state.get('refresh_token'): return False
    try:
        r = requests.post('https://api.twitter.com/2/oauth2/token',
                          auth=(X_CLIENT_ID, X_CLIENT_SECRET),
                          data={'grant_type': 'refresh_token', 'refresh_token': x_state['refresh_token']},
                          timeout=10)
        t = r.json()
        if t.get('access_token'):
            x_state['access_token']  = t['access_token']
            x_state['refresh_token'] = t.get('refresh_token', x_state['refresh_token'])
            return True
    except: pass
    return False

@app.route('/api/x/tweet', methods=['POST'])
def x_post_tweet():
    if not x_state['connected'] or not x_state.get('access_token'):
        return jsonify({'ok': False, 'msg': 'Not connected to X'})
    text = (request.json or {}).get('text', '').strip()
    if not text: return jsonify({'ok': False, 'msg': 'Empty text'})
    if len(text) > 280: text = text[:277] + '...'
    def _post(token):
        return requests.post('https://api.twitter.com/2/tweets',
                             headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
                             json={'text': text}, timeout=10)
    r = _post(x_state['access_token'])
    if r.status_code == 401 and _x_refresh(): r = _post(x_state['access_token'])
    if r.status_code in (200, 201):
        add_log('X: posted — ' + text[:60])
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'msg': r.text[:200]})

@app.route('/api/x/logout', methods=['POST'])
def x_logout():
    x_state.update({'access_token': None, 'refresh_token': None,
                    'username': None, 'connected': False, 'verifier': None})
    session.pop('x_connected', None)
    session.pop('x_username', None)
    return jsonify({'ok': True})

# ── STARTUP ──
init_db()
threading.Thread(target=balance_loop, daemon=True).start()
threading.Thread(target=token_loop,   daemon=True).start()
threading.Thread(target=totd_loop,    daemon=True).start()
add_log('OrcAgent started')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print('OrcAgent Dashboard running on port', port)
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
