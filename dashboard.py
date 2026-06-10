import threading, time, json, os, sys, subprocess, requests, logging, datetime, sqlite3, re, functools
from flask import Flask, jsonify, request, send_from_directory, session
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.fernet import Fernet
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'orcagent-dev-secret-change-in-prod')
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=24)
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'
app.config['SESSION_COOKIE_SECURE']     = bool(os.getenv('RAILWAY_ENVIRONMENT'))
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

BASE       = os.path.dirname(os.path.abspath(__file__))
LOG_FILE   = os.path.join(BASE, 'trades.log')
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
        print('WARNING: Invalid ENCRYPTION_KEY format — ephemeral key in use. Private keys will NOT survive restart.', flush=True)
else:
    _k = Fernet.generate_key()
    _fernet = Fernet(_k)
    print('WARNING: ENCRYPTION_KEY not set — private keys will NOT survive restart. '
          'Generate one: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" '
          'and set it as ENCRYPTION_KEY env var.', flush=True)

def encrypt_key(raw: str) -> str:
    return _fernet.encrypt(raw.encode()).decode()

def decrypt_key(enc: str) -> str:
    return _fernet.decrypt(enc.encode()).decode()

# ── INPUT VALIDATION ──
_SOLANA_ADDR_RE = re.compile(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$')
_SOLANA_KEY_RE  = re.compile(r'^[1-9A-HJ-NP-Za-km-z]{44,88}$')

def is_valid_solana_address(addr: str) -> bool:
    return bool(_SOLANA_ADDR_RE.match(addr or ''))

def is_valid_solana_private_key(key: str) -> bool:
    key = (key or '').strip()
    if _SOLANA_KEY_RE.match(key):
        return True
    if key.startswith('[') and key.endswith(']'):
        try:
            arr = json.loads(key)
            return (isinstance(arr, list) and len(arr) in (32, 64)
                    and all(isinstance(b, int) and 0 <= b <= 255 for b in arr))
        except Exception:
            pass
    return False

# ── RATE LIMITING ──
_rl_lock: threading.Lock = threading.Lock()
_rl_hits: dict           = {}

def _rate_ok(key: str, limit: int, window: int) -> bool:
    now = time.time()
    with _rl_lock:
        hits = [t for t in _rl_hits.get(key, []) if now - t < window]
        if len(hits) >= limit:
            _rl_hits[key] = hits
            return False
        hits.append(now)
        _rl_hits[key] = hits
        return True

def rate_limit(limit: int, window: int = 60):
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            key = f.__name__ + ':' + (request.remote_addr or '0.0.0.0')
            if not _rate_ok(key, limit, window):
                return jsonify({'ok': False, 'msg': 'Too many requests — slow down'}), 429
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ── TRADER LOCK (prevents double-start race condition) ──
_trader_lock = threading.Lock()

# ── SQLITE DATABASE ──
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Migrate old X-based schema if it exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if c.fetchone():
        c.execute('PRAGMA table_info(users)')
        cols = [row[1] for row in c.fetchall()]
        if 'x_username' in cols:
            c.execute('DROP TABLE users')
            conn.commit()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_address        TEXT UNIQUE NOT NULL,
        encrypted_private_key TEXT DEFAULT '',
        trading_active        INTEGER DEFAULT 0,
        max_trade_size        REAL DEFAULT 12.5,
        daily_loss_limit      REAL DEFAULT 50.0,
        created_at            TEXT DEFAULT CURRENT_TIMESTAMP
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

def get_or_create_user(wallet: str) -> int:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO users (wallet_address) VALUES (?)', (wallet,))
    conn.commit()
    c.execute('SELECT id FROM users WHERE wallet_address=?', (wallet,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def _current_wallet() -> str:
    """Returns the wallet address for the current session only.
    Never falls back to shared state — that would leak one user's identity to another."""
    return session.get('wallet', '')

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

def get_user_state(wallet: str) -> dict:
    if wallet not in user_states:
        user_states[wallet] = {
            'positions': {},
            'daily_stats': _fresh_daily(),
            'trades_history': [],
            'trader_running': False,
            'trader_stop': None,
            'trader_thread': None,
            'sol': 0.0,
            'usdc': 0.0,
            'balance_fetched_at': 0.0,
        }
    return user_states[wallet]

def fetch_user_balances(wallet: str):
    """Fetch SOL and USDC balances from Solana RPC and cache in per-user state."""
    us = get_user_state(wallet)
    try:
        r = requests.post(SOLANA_RPC, json={
            'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [wallet]
        }, timeout=8)
        us['sol'] = round(r.json()['result']['value'] / 1e9, 4)
    except Exception:
        pass
    try:
        r = requests.post(SOLANA_RPC, json={
            'jsonrpc': '2.0', 'id': 1, 'method': 'getTokenAccountsByOwner',
            'params': [wallet, {'mint': USDC_MINT}, {'encoding': 'jsonParsed'}]
        }, timeout=8)
        accounts = r.json().get('result', {}).get('value', [])
        us['usdc'] = round(float(
            accounts[0]['account']['data']['parsed']['info']['tokenAmount']['uiAmount'] or 0
        ), 2) if accounts else 0.0
    except Exception:
        pass
    us['balance_fetched_at'] = time.time()

# ── TOKEN DISCOVERY ──
TOTD_INTERVAL = 900  # 15 minutes

def discover_tokens():
    seen  = {USDC_MINT}
    mints = []

    # 1. Top boosted Solana tokens
    try:
        r = requests.get('https://api.dexscreener.com/token-boosts/top/v1', timeout=10)
        if r.status_code == 200:
            for item in r.json():
                if item.get('chainId') == 'solana':
                    m = item.get('tokenAddress', '')
                    if m and m not in seen:
                        seen.add(m); mints.append(m)
    except: pass

    # 2. Trending Solana tokens — mirrors DexScreener trending page (6h score)
    try:
        r = requests.get(
            'https://api.dexscreener.com/latest/dex/search?q=solana&rankBy=trendingScoreH6',
            timeout=10
        )
        if r.status_code == 200:
            data  = r.json()
            pairs = data.get('pairs', []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            for p in pairs:
                if p.get('chainId') == 'solana':
                    m = (p.get('baseToken') or {}).get('address', '')
                    if m and m not in seen:
                        seen.add(m); mints.append(m)
    except: pass

    # 3. Latest Solana token profiles
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

    return mints[:80]  # cap discovery to avoid excessive per-token API calls

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

def _get_user_usdc(wallet: str) -> float:
    try:
        r = requests.post(SOLANA_RPC, json={'jsonrpc':'2.0','id':1,'method':'getTokenAccountsByOwner','params':[wallet,{'mint':USDC_MINT},{'encoding':'jsonParsed'}]}, timeout=8)
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
        txns = p.get('txns', {})
        m5_buys   = int(txns.get('m5',  {}).get('buys',  0) or 0)
        m5_sells  = int(txns.get('m5',  {}).get('sells', 0) or 0)
        h1_buys   = int(txns.get('h1',  {}).get('buys',  0) or 0)
        h1_sells  = int(txns.get('h1',  {}).get('sells', 0) or 0)
        h24_buys  = int(txns.get('h24', {}).get('buys',  0) or 0)
        h24_sells = int(txns.get('h24', {}).get('sells', 0) or 0)
        return {
            'symbol':        base.get('symbol', '') or '',
            'name':          base.get('name', '') or '',
            'price':         float(p.get('priceUsd', 0) or 0),
            'change5m':      float(p.get('priceChange', {}).get('m5',  0) or 0),
            'change1h':      float(p.get('priceChange', {}).get('h1',  0) or 0),
            'change6h':      float(p.get('priceChange', {}).get('h6',  0) or 0),
            'change24h':     float(p.get('priceChange', {}).get('h24', 0) or 0),
            'liquidity':     float(p.get('liquidity', {}).get('usd', 0) or 0),
            'volume5m':      float(p.get('volume', {}).get('m5',  0) or 0),
            'volume1h':      float(p.get('volume', {}).get('h1',  0) or 0),
            'volume6h':      float(p.get('volume', {}).get('h6',  0) or 0),
            'volume24h':     float(p.get('volume', {}).get('h24', 0) or 0),
            'fdv':           float(p.get('fdv', 0) or p.get('marketCap', 0) or 0),
            'txns_buys':     m5_buys  or h1_buys,
            'txns_sells':    m5_sells or h1_sells,
            'txns24h_buys':  h24_buys,
            'txns24h_sells': h24_sells,
            'txns24h':       h24_buys + h24_sells,
            'makers24h':     int(p.get('makers', 0) or 0),
        }
    except: return None

def score_token(data):
    """Score 0–10. Momentum-focused: ≥7 = strong BUY signal."""
    if data.get('price', 0) <= 0: return 0
    score = 0.0
    m5    = data.get('change5m', 0)
    h1    = data.get('change1h', 0)
    vol5m = data.get('volume5m', 0)
    liq   = data.get('liquidity', 0)
    buys  = data.get('txns_buys', 0)
    sells = max(data.get('txns_sells', 1), 1)

    # M5 momentum (0–4 pts) — primary pump signal
    if   m5 >= 50: score += 4.0
    elif m5 >= 30: score += 3.0
    elif m5 >= 20: score += 2.5
    elif m5 >= 10: score += 1.5
    elif m5 >=  5: score += 0.5

    # H1 trend confirmation (0–2 pts)
    if   h1 >= 60: score += 2.0
    elif h1 >= 30: score += 1.5
    elif h1 >= 15: score += 1.0
    elif h1 >=  5: score += 0.5

    # 5-min volume — real buying activity (0–2 pts)
    if   vol5m >= 50000: score += 2.0
    elif vol5m >= 20000: score += 1.5
    elif vol5m >=  5000: score += 1.0
    elif vol5m >=  1000: score += 0.5

    # Buy pressure (0–2 pts)
    ratio = buys / sells
    if   ratio >= 4.0: score += 2.0
    elif ratio >= 2.5: score += 1.5
    elif ratio >= 1.5: score += 1.0
    elif ratio >= 1.0: score += 0.5

    # Liquidity safety gate
    if   liq < 5000:   score = max(0, score - 4.0)  # likely rug
    elif liq < 10000:  score = max(0, score - 2.0)

    return min(10.0, max(0.0, round(score, 1)))

# ── BACKGROUND LOOPS ──
def totd_loop():
    for _ in range(60):
        if state['tokens']: break
        time.sleep(5)
    while True:
        try:
            tokens = state['tokens']
            if tokens:
                best = max(tokens, key=lambda t: t.get('score', 0))
                state['token_of_the_day'] = best
                state['totd_updated_at']  = time.time()
                m5 = best.get('change5m', 0)
                add_log('Token of the Day: ' + best.get('symbol', '?') +
                        ' (score:' + str(best.get('score', 0)) +
                        ' m5:' + ('+' if m5 >= 0 else '') + str(round(m5, 1)) + '%)')
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
            mints      = discover_tokens()
            all_tokens = []
            for mint in mints:
                data = get_token_data(mint)
                if not data or data['price'] <= 0:
                    continue
                # Trending filter — mirrors DexScreener pumpswap trending
                if data['change1h'] < 50:
                    continue
                if data['liquidity'] < 10000:
                    continue
                if data['volume24h'] < 50000:
                    continue
                # txns24h==0 means data unavailable (new token); allow it through
                if data['txns24h'] > 0 and data['txns24h'] < 500:
                    continue
                sc    = score_token(data)
                entry = {
                    'mint':          mint,
                    'symbol':        data['symbol'] or mint[:8],
                    'name':          data['name'] or data['symbol'] or mint[:8],
                    'price':         data['price'],
                    'change5m':      data['change5m'],
                    'change1h':      data['change1h'],
                    'change6h':      data['change6h'],
                    'change24h':     data['change24h'],
                    'volume5m':      data['volume5m'],
                    'volume1h':      data['volume1h'],
                    'volume24h':     data['volume24h'],
                    'liquidity':     data['liquidity'],
                    'fdv':           data['fdv'],
                    'score':         sc,
                    'txns24h':       data['txns24h'],
                    'txns24h_buys':  data['txns24h_buys'],
                    'txns24h_sells': data['txns24h_sells'],
                    'makers24h':     data['makers24h'],
                }
                all_tokens.append(entry)
            # Sort by 1h % descending — biggest 1h gainers first
            display = sorted(all_tokens, key=lambda t: t['change1h'], reverse=True)
            state['tokens'] = display
            if display:
                add_log('Market refresh: ' + str(len(display)) + ' trending tokens (h1≥50%)')
            else:
                add_log('Market refresh: no qualifying tokens yet (h1≥50% filter active)')
        except: pass
        time.sleep(90)

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
    today_spend = sum(t['spend'] for t in state['trades_history'] if t['date'] == today)
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
    today_spend = sum(t['spend'] for t in us['trades_history'] if t.get('date') == today)
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
def _execute_user_swap(wallet: str, private_key: str, action: str, mint: str, amount_str: str):
    """Execute a Jupiter swap with the private key passed via env (never via CLI args)."""
    try:
        env = os.environ.copy()
        env['WALLET_ADDRESS']     = wallet
        env['WALLET_PRIVATE_KEY'] = private_key
        result = subprocess.run(
            [sys.executable, os.path.join(BASE, 'orcagent_solana.py'), action, mint, amount_str],
            env=env, capture_output=True, text=True, timeout=60
        )
        if result.stdout:
            add_log('Swap: ' + result.stdout.strip()[-80:])
    except Exception as e:
        add_log('Swap error: ' + str(e)[:80])

# ── GLOBAL TRADER (no wallet connected) ──
def trader_loop(stop_event, config):
    add_log('Trader started — momentum strategy | TP:15% SL:5% | score≥7')
    positions = {}
    while not stop_event.is_set():
        try:
            check_daily_reset()
            usdc     = state['usdc']
            open_pos = sum(1 for p in positions.values() if p.get('amount', 0) > 0)
            state['positions'] = open_pos
            live = state['tokens']
            add_log('SOL:' + str(state['sol']) + ' USDC:' + str(usdc) + ' Pos:' + str(open_pos) + '/3 Tokens:' + str(len(live)))
            for t in live:
                if stop_event.is_set(): break
                mint  = t['mint']
                if mint not in positions:
                    positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'peak_price': 0.0, 'spend': 0.0}
                pos   = positions[mint]
                sc    = t['score']
                m5    = t.get('change5m', 0)
                label = t['symbol'] or t['name'] or mint[:8]

                # ── Exit checks for open positions ──
                if pos['amount'] > 0 and pos['buy_price'] > 0:
                    price = t['price']
                    if price > pos['peak_price']: pos['peak_price'] = price
                    chg = (price - pos['buy_price']) / pos['buy_price']
                    exit_reason = None
                    if   chg >= 0.15:  exit_reason = 'TAKE PROFIT +' + str(round(chg * 100, 1)) + '%'
                    elif chg <= -0.05: exit_reason = 'STOP LOSS '    + str(round(chg * 100, 1)) + '%'
                    elif m5 < 5:       exit_reason = 'MOMENTUM DIED (m5=' + str(round(m5, 1)) + '%)'
                    if exit_reason:
                        add_log(exit_reason + ' ' + label)
                        subprocess.Popen(
                            [sys.executable, os.path.join(BASE, 'orcagent_solana.py'), 'sell', mint, str(pos['amount'])],
                            env=os.environ.copy()
                        )
                        record_trade(label, pos['buy_price'], price, pos['amount'], pos['spend'])
                        positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'peak_price': 0.0, 'spend': 0.0}
                        open_pos -= 1
                        continue

                # ── Entry: score ≥ 7, still pumping ──
                if sc >= 7 and m5 >= 10 and usdc > 3 and open_pos < 3 and pos['amount'] == 0:
                    spend = round(min(usdc * config.get('trade_pct', 0.20), config.get('max_usdc', 12.5)), 2)
                    add_log('BUY ' + label + ' $' + str(spend) + ' score:' + str(sc) + ' m5:+' + str(round(m5, 1)) + '%')
                    subprocess.Popen(
                        [sys.executable, os.path.join(BASE, 'orcagent_solana.py'), 'buy', mint, str(spend)],
                        env=os.environ.copy()
                    )
                    pos['amount']     = spend / t['price']
                    pos['buy_price']  = t['price']
                    pos['peak_price'] = t['price']
                    pos['spend']      = spend
                    usdc -= spend; open_pos += 1
                else:
                    add_log(label + ' score:' + str(sc) + ' m5:' + str(round(m5, 1)) + '% HOLD')
        except Exception as e:
            add_log('Trader error: ' + str(e))
        stop_event.wait(config.get('interval', 60))
    add_log('Trader stopped')

# ── PER-USER TRADER ──
def user_trader_loop(stop_event, config, wallet: str):
    us    = get_user_state(wallet)
    short = wallet[:6] + '...' + wallet[-4:]
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('SELECT id, encrypted_private_key, max_trade_size, daily_loss_limit FROM users WHERE wallet_address=?', (wallet,))
        row  = c.fetchone()
        conn.close()
    except Exception as e:
        add_log('[' + short + '] DB error: ' + str(e))
        us['trader_running'] = False
        return

    if not row or not row[1]:
        add_log('[' + short + '] No private key — configure in Settings first')
        us['trader_running'] = False
        return

    user_id          = row[0]
    max_usdc         = float(row[2] if row[2] is not None else 12.5)
    daily_loss_limit = abs(float(row[3] if row[3] is not None else 50.0))

    try:
        private_key = decrypt_key(row[1])
    except Exception as e:
        add_log('[' + short + '] Key decryption failed: ' + str(e))
        us['trader_running'] = False
        return

    add_log('[' + short + '] Trader started — momentum strategy | TP:15% SL:5% | score≥7')
    positions = us['positions']

    try:
        while not stop_event.is_set():
            try:
                check_daily_reset_user(us)
                daily_loss = us['daily_stats'].get('total_pnl', 0)
                if daily_loss < -daily_loss_limit:
                    add_log('[' + short + '] Daily loss limit hit ($' + str(round(daily_loss, 2)) + ') — pausing')
                    stop_event.wait(300)
                    continue
                live     = state['tokens']
                open_pos = sum(1 for p in positions.values() if p.get('amount', 0) > 0)
                us_usdc  = _get_user_usdc(wallet)
                add_log('[' + short + '] USDC:' + str(round(us_usdc, 2)) + ' Pos:' + str(open_pos) + '/3')
                for t in live:
                    if stop_event.is_set(): break
                    mint  = t['mint']
                    if mint not in positions:
                        positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'peak_price': 0.0, 'spend': 0.0}
                    pos   = positions[mint]
                    sc    = t['score']
                    m5    = t.get('change5m', 0)
                    label = t['symbol'] or mint[:8]

                    # ── Exit checks for open positions ──
                    if pos['amount'] > 0 and pos['buy_price'] > 0:
                        price = t['price']
                        if price > pos.get('peak_price', price): pos['peak_price'] = price
                        chg = (price - pos['buy_price']) / pos['buy_price']
                        exit_reason = None
                        if   chg >= 0.15:  exit_reason = 'TAKE PROFIT +' + str(round(chg * 100, 1)) + '%'
                        elif chg <= -0.05: exit_reason = 'STOP LOSS '    + str(round(chg * 100, 1)) + '%'
                        elif m5 < 5:       exit_reason = 'MOMENTUM DIED (m5=' + str(round(m5, 1)) + '%)'
                        if exit_reason:
                            add_log('[' + short + '] ' + exit_reason + ' ' + label)
                            _execute_user_swap(wallet, private_key, 'sell', mint, str(pos['amount']))
                            _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'])
                            positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'peak_price': 0.0, 'spend': 0.0}
                            open_pos -= 1
                            continue

                    # ── Entry: score ≥ 7, still pumping (m5 ≥ 10) ──
                    if sc >= 7 and m5 >= 10 and us_usdc > 3 and open_pos < 3 and pos['amount'] == 0:
                        spend = round(min(us_usdc * config.get('trade_pct', 0.20), max_usdc), 2)
                        add_log('[' + short + '] BUY ' + label + ' $' + str(spend) + ' score:' + str(sc) + ' m5:+' + str(round(m5, 1)) + '%')
                        _execute_user_swap(wallet, private_key, 'buy', mint, str(spend))
                        pos['amount']     = spend / t['price']
                        pos['buy_price']  = t['price']
                        pos['peak_price'] = t['price']
                        pos['spend']      = spend
                        us_usdc -= spend; open_pos += 1
            except Exception as e:
                add_log('[' + short + '] Trader error: ' + str(e))
            stop_event.wait(config.get('interval', 60))
    finally:
        private_key = None  # wipe from memory
        add_log('[' + short + '] Trader stopped, key wiped from memory')
        us['trader_running'] = False


# ══════════════════════════════════════════════════════
#  FLASK ROUTES
# ══════════════════════════════════════════════════════

@app.after_request
def _security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options',        'DENY')
    resp.headers.setdefault('X-XSS-Protection',       '1; mode=block')
    resp.headers.setdefault('Referrer-Policy',        'strict-origin-when-cross-origin')
    return resp

@app.route('/')
def index():
    return send_from_directory(BASE, 'dashboard.html')

# ── WALLET ──
@app.route('/api/wallet/set', methods=['POST'])
@rate_limit(10, 60)
def set_wallet():
    address = (request.json or {}).get('address', '').strip()
    if address:
        if not is_valid_solana_address(address):
            return jsonify({'ok': False, 'msg': 'Invalid Solana wallet address'}), 400
        session.permanent = True
        session['wallet'] = address
        state['wallet']   = address
        try:
            get_or_create_user(address)
        except: pass
        threading.Thread(target=fetch_user_balances, args=(address,), daemon=True).start()
        add_log('Wallet connected: ' + address[:6] + '...' + address[-4:])
    else:
        session.pop('wallet', None)
        state['wallet'] = WALLET_ADDRESS
        add_log('Wallet disconnected')
    return jsonify({'ok': True, 'wallet': session.get('wallet', state['wallet'])})

# ── SETTINGS ──
@app.route('/api/settings', methods=['GET'])
def get_settings():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'})
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute('SELECT encrypted_private_key, max_trade_size, daily_loss_limit FROM users WHERE wallet_address=?', (wallet,))
    row  = c.fetchone()
    conn.close()
    if row:
        return jsonify({'ok': True, 'has_key': bool(row[0]), 'max_trade_size': row[1] or 12.5, 'daily_loss_limit': row[2] or 50.0})
    return jsonify({'ok': True, 'has_key': False, 'max_trade_size': 12.5, 'daily_loss_limit': 50.0})

@app.route('/api/settings', methods=['POST'])
@rate_limit(10, 60)
def save_settings():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'})
    data            = request.json or {}
    private_key_raw = data.get('private_key', '').strip()
    try:
        max_trade_size = float(data.get('max_trade_size', 12.5))
    except (ValueError, TypeError):
        max_trade_size = 12.5
    try:
        daily_loss_limit = float(data.get('daily_loss_limit', 50.0))
    except (ValueError, TypeError):
        daily_loss_limit = 50.0
    max_trade_size   = max(0.5,  min(max_trade_size,   10000.0))
    daily_loss_limit = max(1.0,  min(daily_loss_limit, 50000.0))

    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute('SELECT id, encrypted_private_key FROM users WHERE wallet_address=?', (wallet,))
    row  = c.fetchone()

    if private_key_raw:
        if not is_valid_solana_private_key(private_key_raw):
            conn.close()
            return jsonify({'ok': False, 'msg': 'Invalid private key format — paste the base58 or JSON array key from your wallet'})
        try:
            encrypted = encrypt_key(private_key_raw)
        except Exception:
            conn.close()
            return jsonify({'ok': False, 'msg': 'Failed to save private key'})
    else:
        encrypted = row[1] if row else ''

    if row:
        c.execute('UPDATE users SET encrypted_private_key=?, max_trade_size=?, daily_loss_limit=? WHERE wallet_address=?',
                  (encrypted, max_trade_size, daily_loss_limit, wallet))
    else:
        c.execute('INSERT INTO users (wallet_address, encrypted_private_key, max_trade_size, daily_loss_limit) VALUES (?,?,?,?)',
                  (wallet, encrypted, max_trade_size, daily_loss_limit))
    conn.commit()
    conn.close()
    add_log('Settings saved for ' + wallet[:6] + '...' + wallet[-4:])
    return jsonify({'ok': True})

# ── STATE ──
@app.route('/api/state')
def api_state():
    wallet = _current_wallet()
    if wallet:
        us       = get_user_state(wallet)
        open_pos = sum(1 for p in us.get('positions', {}).values() if p.get('amount', 0) > 0)
        live_map = {t['mint']: t for t in state.get('tokens', [])}
        positions_detail = []
        for mint, pos in us.get('positions', {}).items():
            if pos.get('amount', 0) > 0:
                live        = live_map.get(mint, {})
                cur_price   = live.get('price', pos['buy_price'])
                symbol      = live.get('symbol', mint[:8])
                entry       = pos['buy_price']
                pnl         = round(pos['amount'] * (cur_price - entry), 4) if entry > 0 else 0.0
                pnl_pct     = round((cur_price - entry) / entry * 100, 2)   if entry > 0 else 0.0
                positions_detail.append({
                    'mint': mint, 'symbol': symbol,
                    'entry': entry, 'current': cur_price,
                    'spend': round(pos.get('spend', 0), 2),
                    'pnl': pnl, 'pnl_pct': pnl_pct,
                })
        return jsonify({
            'trader_running':   us.get('trader_running', False),
            'usdc':             us.get('usdc', 0.0),
            'sol':              us.get('sol',  0.0),
            'positions':        open_pos,
            'positions_detail': positions_detail,
            'log_lines':        state['log_lines'][:40],
            'tokens':           state['tokens'],
            'wallet':           wallet,
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
@rate_limit(5, 60)
def start_trader():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    with _trader_lock:
        us = get_user_state(wallet)
        if us['trader_running']:
            return jsonify({'ok': False, 'msg': 'Already running'})
        config = request.json or {}
        us['trader_stop']   = threading.Event()
        us['trader_thread'] = threading.Thread(target=user_trader_loop, args=(us['trader_stop'], config, wallet), daemon=True)
        us['trader_thread'].start()
        us['trader_running'] = True
    return jsonify({'ok': True})

@app.route('/api/trader/stop', methods=['POST'])
def stop_trader():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    us = get_user_state(wallet)
    if us.get('trader_stop'):
        us['trader_stop'].set()
    us['trader_running'] = False
    return jsonify({'ok': True})

# ── BALANCE ──
@app.route('/api/balance')
@rate_limit(10, 60)
def api_balance():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'sol': 0.0, 'usdc': 0.0})
    fetch_user_balances(wallet)
    us = get_user_state(wallet)
    return jsonify({'ok': True, 'sol': us.get('sol', 0.0), 'usdc': us.get('usdc', 0.0)})

# ── MARKET / TOTD / TRADES ──
@app.route('/api/market')
def api_market():
    return jsonify({'tokens': state['tokens']})

@app.route('/api/totd')
def api_totd():
    updated = state.get('totd_updated_at', 0)
    next_in = max(0.0, TOTD_INTERVAL - (time.time() - updated)) if updated else 0.0
    return jsonify({'token': state.get('token_of_the_day'), 'updated_at': updated, 'next_update_in': round(next_in)})

@app.route('/api/chart/<mint>')
@rate_limit(30, 60)
def api_chart(mint):
    if not _SOLANA_ADDR_RE.match(mint or ''):
        return jsonify({'candles': [], 'error': 'invalid mint'})
    try:
        r = requests.get('https://api.dexscreener.com/latest/dex/tokens/' + mint, timeout=8)
        pairs = r.json().get('pairs', []) if r.status_code == 200 else []
        if not pairs:
            return jsonify({'candles': [], 'error': 'no pairs'})
        pair         = pairs[0]
        pair_address = pair.get('pairAddress', '')
        chain_id     = pair.get('chainId', 'solana')
        if not pair_address:
            return jsonify({'candles': [], 'error': 'no pair address'})

        now     = int(time.time())
        from_ts = now - 1800  # 30 minutes
        chart_url = (
            f'https://io.dexscreener.com/dex/chart/amm/v3/{chain_id}/{pair_address}'
            f'?res=1&cb=0&from={from_ts}&to={now}'
        )
        rc = requests.get(chart_url, timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Referer': 'https://dexscreener.com/',
        })

        def _norm_ts(t):
            return int(t) // 1000 if t > 1e10 else int(t)

        candles = []
        if rc.status_code == 200:
            data = rc.json()
            # TradingView UDF format: {t:[...], o:[...], h:[...], l:[...], c:[...], v:[...]}
            if isinstance(data, dict) and isinstance(data.get('t'), list):
                ts_arr = data['t']
                opens  = data.get('o', [])
                highs  = data.get('h', [])
                lows   = data.get('l', [])
                closes = data.get('c', [])
                vols   = data.get('v', [])
                for i, raw_ts in enumerate(ts_arr):
                    t_ts = _norm_ts(raw_ts)
                    if t_ts >= from_ts:
                        candles.append({
                            't': t_ts,
                            'o': float(opens[i])  if i < len(opens)  else 0,
                            'h': float(highs[i])  if i < len(highs)  else 0,
                            'l': float(lows[i])   if i < len(lows)   else 0,
                            'c': float(closes[i]) if i < len(closes) else 0,
                            'v': float(vols[i])   if i < len(vols)   else 0,
                        })
            elif isinstance(data, list):
                for c in data:
                    if not isinstance(c, dict): continue
                    t_ts = _norm_ts(c.get('time', c.get('t', 0)))
                    if t_ts >= from_ts:
                        candles.append({
                            't': t_ts,
                            'o': float(c.get('open',   c.get('o', 0)) or 0),
                            'h': float(c.get('high',   c.get('h', 0)) or 0),
                            'l': float(c.get('low',    c.get('l', 0)) or 0),
                            'c': float(c.get('close',  c.get('c', 0)) or 0),
                            'v': float(c.get('volume', c.get('v', 0)) or 0),
                        })
            candles.sort(key=lambda x: x['t'])
            candles = candles[-30:]

        # Fallback: synthesize 2 data points from current price + m5 change when
        # the chart API returns nothing (rate-limited, new token, API down, etc.)
        if not candles:
            current_price = float(pair.get('priceUsd', 0) or 0)
            change5m = float((pair.get('priceChange') or {}).get('m5', 0) or 0)
            if current_price > 0:
                factor = max(1 + change5m / 100, 0.0001)
                p_ago  = current_price / factor
                candles = [
                    {'t': now - 300, 'o': 0, 'h': 0, 'l': 0, 'c': p_ago,          'v': 0},
                    {'t': now,       'o': 0, 'h': 0, 'l': 0, 'c': current_price,   'v': 0},
                ]

        return jsonify({'candles': candles, 'pair_address': pair_address})
    except Exception:
        return jsonify({'candles': [], 'error': 'Chart data unavailable'})

@app.route('/api/trades')
def api_trades():
    wallet = _current_wallet()
    if wallet:
        us = get_user_state(wallet)
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
