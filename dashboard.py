import threading, time, json, os, sys, subprocess, requests, logging, datetime, sqlite3, re, functools, struct, base64, math
from flask import Flask, jsonify, request, send_from_directory, session
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.fernet import Fernet
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or os.urandom(32)
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'
app.config['SESSION_COOKIE_SECURE']     = bool(os.getenv('RAILWAY_ENVIRONMENT'))
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

@app.before_request
def _refresh_session():
    if session.get('wallet'):
        session.modified = True  # extend cookie lifetime on every API call
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

BASE       = os.path.dirname(os.path.abspath(__file__))
LOG_FILE   = os.path.join(BASE, 'trades.log')
DB_FILE    = os.path.join(BASE, 'orcagent.db')

WALLET_ADDRESS = os.environ.get('WALLET_ADDRESS', '')
USDC_MINT      = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
SOLANA_RPC     = 'https://api.mainnet-beta.solana.com'
OWNER_WALLET   = os.environ.get('OWNER_WALLET', '57enjXJH7Ro1aVTT97NuSvf3noYEsBwp4GUjet22vGW6')
BIRDEYE_KEY    = os.environ.get('BIRDEYE_API_KEY', '')
FEE_RATE       = 0.05  # 5% performance fee on profitable trades only

# ── FERNET ENCRYPTION ──
# Priority: ENCRYPTION_KEY env var → key persisted in DB → generate and persist in DB.
# Storing the key in the DB means private keys survive server restarts even without an env var.
_enc_key_str = os.environ.get('ENCRYPTION_KEY', '')
_fernet: 'Fernet | None' = None

if _enc_key_str:
    try:
        _fernet = Fernet(_enc_key_str.encode())
    except Exception:
        print('WARNING: Invalid ENCRYPTION_KEY env var — falling back to DB-persisted key.', flush=True)

if _fernet is None:
    _cfg_db  = sqlite3.connect(DB_FILE)
    _cfg_cur = _cfg_db.cursor()
    _cfg_cur.execute('CREATE TABLE IF NOT EXISTS server_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    _cfg_cur.execute('SELECT value FROM server_config WHERE key="encryption_key"')
    _cfg_row = _cfg_cur.fetchone()
    if _cfg_row:
        try:
            _fernet = Fernet(_cfg_row[0].encode())
        except Exception:
            _cfg_row = None  # corrupt stored key — regenerate below
    if not _cfg_row:
        _gen_key = Fernet.generate_key()
        _fernet  = Fernet(_gen_key)
        _cfg_cur.execute('INSERT OR REPLACE INTO server_config (key, value) VALUES ("encryption_key", ?)',
                         (_gen_key.decode(),))
        print('OrcAgent: new encryption key generated and persisted to DB.', flush=True)
    _cfg_db.commit()
    _cfg_db.close()

def encrypt_key(raw: str) -> str:
    return _fernet.encrypt(raw.encode()).decode()

def decrypt_key(enc: str) -> str:
    return _fernet.decrypt(enc.encode()).decode()

# ── PERFORMANCE FEE COLLECTION ──
def send_usdc_fee(from_privkey: str, to_wallet_str: str, amount_usdc: float) -> str:
    """SPL USDC transfer: send amount_usdc from from_privkey's wallet to to_wallet_str.
    Uses a direct Token-program Transfer instruction (discriminant 3).
    Creates the recipient's ATA if it doesn't exist yet."""
    from solders.keypair import Keypair as _KP
    from solders.pubkey import Pubkey
    from solders.instruction import Instruction, AccountMeta
    from solders.transaction import Transaction
    from solders.hash import Hash as SolHash

    TOKEN_PROG   = Pubkey.from_string('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')
    ASSOC_PROG   = Pubkey.from_string('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bRC')
    SYS_PROG     = Pubkey.from_string('11111111111111111111111111111111')
    SYSVAR_RENT  = Pubkey.from_string('SysvarRent111111111111111111111111111111111')
    USDC_PK      = Pubkey.from_string(USDC_MINT)

    keypair  = _KP.from_base58_string(from_privkey)
    sender   = keypair.pubkey()
    receiver = Pubkey.from_string(to_wallet_str)

    src_ata = Pubkey.find_program_address([bytes(sender),   bytes(TOKEN_PROG), bytes(USDC_PK)], ASSOC_PROG)[0]
    dst_ata = Pubkey.find_program_address([bytes(receiver), bytes(TOKEN_PROG), bytes(USDC_PK)], ASSOC_PROG)[0]

    amount_micro = int(amount_usdc * 1_000_000)

    # Check if recipient's USDC account exists; create it if not
    acc_resp = requests.post(SOLANA_RPC, json={
        'jsonrpc': '2.0', 'id': 1, 'method': 'getAccountInfo',
        'params': [str(dst_ata), {'encoding': 'base64'}],
    }, timeout=10).json()
    dst_exists = acc_resp.get('result', {}).get('value') is not None

    ixs = []
    if not dst_exists:
        ixs.append(Instruction(
            program_id=ASSOC_PROG,
            accounts=[
                AccountMeta(sender,      is_signer=True,  is_writable=True),
                AccountMeta(dst_ata,     is_signer=False, is_writable=True),
                AccountMeta(receiver,    is_signer=False, is_writable=False),
                AccountMeta(USDC_PK,     is_signer=False, is_writable=False),
                AccountMeta(SYS_PROG,    is_signer=False, is_writable=False),
                AccountMeta(TOKEN_PROG,  is_signer=False, is_writable=False),
                AccountMeta(SYSVAR_RENT, is_signer=False, is_writable=False),
            ],
            data=bytes([]),
        ))

    ixs.append(Instruction(
        program_id=TOKEN_PROG,
        accounts=[
            AccountMeta(src_ata, is_signer=False, is_writable=True),
            AccountMeta(dst_ata, is_signer=False, is_writable=True),
            AccountMeta(sender,  is_signer=True,  is_writable=False),
        ],
        data=bytes([3]) + struct.pack('<Q', amount_micro),  # SPL Transfer instruction
    ))

    bh = requests.post(SOLANA_RPC, json={
        'jsonrpc': '2.0', 'id': 1, 'method': 'getLatestBlockhash', 'params': [],
    }, timeout=10).json()['result']['value']['blockhash']

    tx = Transaction.new_signed_with_payer(ixs, sender, [keypair], SolHash.from_string(bh))

    encoded = base64.b64encode(bytes(tx)).decode()
    res = requests.post(SOLANA_RPC, json={
        'jsonrpc': '2.0', 'id': 1, 'method': 'sendTransaction',
        'params': [encoded, {'encoding': 'base64', 'skipPreflight': False}],
    }, timeout=30).json()
    if 'error' in res:
        raise Exception('Fee TX: ' + str(res['error']))
    return res.get('result', str(res))

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

# ── MEMORY CLEANUP ──
_USER_STATES_MAX = 200   # evict LRU entries beyond this cap

def _cleanup_loop():
    """Periodically evict stale rate-limit buckets, idle user states, and dead position slots."""
    while True:
        time.sleep(300)
        now = time.time()
        # Evict expired rate-limit buckets
        with _rl_lock:
            stale = [k for k, hits in _rl_hits.items() if not any(now - t < 120 for t in hits)]
            for k in stale:
                del _rl_hits[k]
        # Prune zero-amount position slots that accumulate in active traders
        for us in list(user_states.values()):
            pos = us.get('positions')
            if pos and len(pos) > 200:
                dead = [m for m, p in list(pos.items()) if not p.get('amount')]
                for m in dead[:len(pos) - 100]:
                    pos.pop(m, None)
        # Evict idle user states beyond cap
        if len(user_states) > _USER_STATES_MAX:
            by_age = sorted(
                user_states.items(),
                key=lambda kv: kv[1].get('balance_fetched_at', 0),
            )
            for wallet, _ in by_age[:len(user_states) - _USER_STATES_MAX]:
                try:
                    if not user_states[wallet].get('trader_running'):
                        del user_states[wallet]
                except KeyError:
                    pass  # already removed by another thread

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
    c.execute('CREATE TABLE IF NOT EXISTS server_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_address        TEXT UNIQUE NOT NULL,
        encrypted_private_key TEXT DEFAULT '',
        trading_active        INTEGER DEFAULT 0,
        max_trade_size        REAL DEFAULT 1.0,
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
        fee_amount   REAL DEFAULT 0,
        timestamp    TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS fees (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        user_wallet  TEXT NOT NULL,
        token        TEXT,
        gross_profit REAL,
        fee_amount   REAL,
        fee_tx       TEXT DEFAULT '',
        timestamp    TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    # Migrate: add fee_amount column to trades if it doesn't exist yet
    try:
        c.execute('ALTER TABLE trades ADD COLUMN fee_amount REAL DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    c.execute('CREATE INDEX IF NOT EXISTS idx_trades_user_id ON trades(user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_fees_wallet    ON fees(user_wallet)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_fees_timestamp ON fees(timestamp)')
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
def _fresh_daily():
    return {
        'date': datetime.datetime.utcnow().strftime('%Y-%m-%d'),
        'total_pnl': 0.0, 'total_pnl_pct': 0.0,
        'total_fees': 0.0, 'net_pnl': 0.0,
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
            'log_lines': list(state['log_lines']),  # seed with recent system events
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

def add_log(msg: str):
    """System-wide event (market refresh, TOTD, startup).
    Written to the small system buffer AND broadcast to every active user's log."""
    t     = time.strftime('%H:%M:%S')
    entry = {'t': t, 'msg': msg}
    state['log_lines'].insert(0, entry)
    if len(state['log_lines']) > 20:   # small buffer — only used to seed new sessions
        state['log_lines'].pop()
    for _us in user_states.values():   # broadcast to all currently active per-user logs
        _us['log_lines'].insert(0, entry)
        if len(_us['log_lines']) > 100:
            _us['log_lines'].pop()

def add_user_log(wallet: str, msg: str):
    """User-specific event — stored only in this wallet's log, never visible to others."""
    t  = time.strftime('%H:%M:%S')
    us = get_user_state(wallet)
    us['log_lines'].insert(0, {'t': t, 'msg': msg})
    if len(us['log_lines']) > 100:
        us['log_lines'].pop()

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
    """Score 0–10. Momentum-focused: ≥4 = strong BUY signal."""
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

def _record_user_trade(user_id: int, us: dict, symbol: str, entry: float, exit_price: float,
                       amount: float, spend: float, wallet: str = '', private_key: str = ''):
    check_daily_reset_user(us)
    now   = datetime.datetime.utcnow()
    today = now.strftime('%Y-%m-%d')
    pnl     = round(amount * (exit_price - entry), 4) if entry > 0 else 0.0
    pnl_pct = round((exit_price - entry) / entry * 100, 2) if entry > 0 else 0.0

    # 5% performance fee on profitable trades only
    fee_amount = 0.0
    if pnl > 0.0 and wallet and private_key and OWNER_WALLET and wallet != OWNER_WALLET:
        fee_amount = round(pnl * FEE_RATE, 6)
        if fee_amount >= 0.0001:  # skip dust fees below 0.0001 USDC
            _pk   = private_key   # captured by value — survives outer key wipe
            _sym  = symbol
            _gros = pnl
            _fee  = fee_amount
            _wlt  = wallet
            def _do_fee(pk, sym, gross, fee, wlt):
                try:
                    tx_sig = send_usdc_fee(pk, OWNER_WALLET, fee)
                    conn = sqlite3.connect(DB_FILE)
                    conn.execute(
                        'INSERT INTO fees (user_wallet, token, gross_profit, fee_amount, fee_tx) VALUES (?,?,?,?,?)',
                        (wlt, sym, gross, fee, tx_sig))
                    conn.commit()
                    conn.close()
                    add_user_log(wlt, f'✓ Perf fee ${fee:.4f} USDC (5% of +${gross:.4f}) TX:{tx_sig[:12]}...')
                except Exception as e:
                    add_user_log(wlt, f'Fee transfer failed: {str(e)[:80]}')
                finally:
                    pk = None
            threading.Thread(target=_do_fee, args=(_pk, _sym, _gros, _fee, _wlt), daemon=True).start()

    trade = {
        'symbol': symbol, 'entry': entry, 'exit': exit_price,
        'amount': amount, 'spend': spend, 'pnl': pnl, 'pnl_pct': pnl_pct,
        'fee': fee_amount,
        'net_pnl': round(pnl - fee_amount, 4),
        'time': now.strftime('%H:%M'), 'date': today, 'ts': now.timestamp(),
    }
    us['trades_history'].append(trade)
    if len(us['trades_history']) > 500:
        us['trades_history'] = us['trades_history'][-500:]
    ds = us['daily_stats']
    ds['total_pnl']  = round(ds.get('total_pnl', 0) + pnl, 4)
    ds['total_fees'] = round(ds.get('total_fees', 0) + fee_amount, 6)
    ds['net_pnl']    = round(ds['total_pnl'] - ds['total_fees'], 4)
    ds['trades']     = ds.get('trades', 0) + 1
    if pnl > 0: ds['wins'] = ds.get('wins', 0) + 1
    today_spend = sum(t['spend'] for t in us['trades_history'] if t.get('date') == today)
    ds['total_pnl_pct'] = round(ds['total_pnl'] / today_spend * 100, 2) if today_spend else 0.0
    if ds.get('best')  is None or pnl_pct > ds['best']:  ds['best']  = pnl_pct
    if ds.get('worst') is None or pnl_pct < ds['worst']: ds['worst'] = pnl_pct
    ds['curve'].append({'t': now.strftime('%H:%M'), 'v': ds['net_pnl']})
    try:
        conn = sqlite3.connect(DB_FILE)
        try:
            conn.execute(
                'INSERT INTO trades (user_id, token, entry_price, exit_price, amount, pnl, fee_amount) VALUES (?,?,?,?,?,?,?)',
                (user_id, symbol, entry, exit_price, amount, pnl, fee_amount))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass

# ── SWAP EXECUTION ──
def _execute_user_swap(wallet: str, private_key: str, action: str, mint: str, amount_str: str) -> bool:
    """Execute a Jupiter swap. Returns True only if the subprocess exited 0 with output."""
    try:
        env = os.environ.copy()
        env['WALLET_ADDRESS']     = wallet
        env['WALLET_PRIVATE_KEY'] = private_key
        result = subprocess.run(
            [sys.executable, os.path.join(BASE, 'orcagent_solana.py'), action, mint, amount_str],
            env=env, capture_output=True, text=True, timeout=60
        )
        if result.stdout:
            add_user_log(wallet, 'Swap: ' + result.stdout.strip()[-80:])
        if result.stderr:
            add_user_log(wallet, 'Swap err: ' + result.stderr.strip()[-80:])
        return result.returncode == 0 and bool(result.stdout.strip())
    except Exception as e:
        add_user_log(wallet, 'Swap error: ' + str(e)[:80])
        return False

# ── PER-USER TRADER ──
def user_trader_loop(stop_event, config, wallet: str):
    us    = get_user_state(wallet)
    short = wallet[:6] + '...' + wallet[-4:]
    try:
        conn = sqlite3.connect(DB_FILE)
        try:
            c   = conn.cursor()
            c.execute('SELECT id, encrypted_private_key, max_trade_size, daily_loss_limit FROM users WHERE wallet_address=?', (wallet,))
            row = c.fetchone()
        finally:
            conn.close()
    except Exception as e:
        add_user_log(wallet, '[' + short + '] DB error: ' + str(e))
        us['trader_running'] = False
        return

    if not row or not row[1]:
        add_user_log(wallet, '[' + short + '] No private key — configure in Settings first')
        us['trader_running'] = False
        return

    user_id          = row[0]
    max_usdc         = float(row[2] if row[2] is not None else 1.0)
    daily_loss_limit = abs(float(row[3] if row[3] is not None else 50.0))

    try:
        private_key = decrypt_key(row[1])
    except Exception:
        add_user_log(wallet, '[' + short + '] ✗ Cannot decrypt private key — please re-save it in Settings')
        us['trader_running'] = False
        return

    add_user_log(wallet, '[' + short + '] Trader started — momentum strategy | TP:15% SL:5% | score≥4')
    positions = us['positions']

    try:
        while not stop_event.is_set():
            try:
                check_daily_reset_user(us)
                daily_loss = us['daily_stats'].get('total_pnl', 0)
                if daily_loss < -daily_loss_limit:
                    add_user_log(wallet, '[' + short + '] Daily loss limit hit ($' + str(round(daily_loss, 2)) + ') — pausing')
                    stop_event.wait(300)
                    continue
                live     = state['tokens']
                open_pos = sum(1 for p in positions.values() if p.get('amount', 0) > 0)
                us_usdc  = _get_user_usdc(wallet)
                add_user_log(wallet, '[' + short + '] USDC:' + str(round(us_usdc, 2)) + ' Pos:' + str(open_pos) + '/3')
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
                            add_user_log(wallet, '[' + short + '] ' + exit_reason + ' ' + label)
                            sell_ok = _execute_user_swap(wallet, private_key, 'sell', mint, str(pos['amount']))
                            if sell_ok:
                                _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'],
                                                   wallet=wallet, private_key=private_key)
                            else:
                                add_user_log(wallet, '[' + short + '] ✗ Sell failed — position cleared to avoid retry loop')
                            positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'peak_price': 0.0, 'spend': 0.0}
                            open_pos -= 1
                            continue

                    # ── Entry: score ≥ 4, still pumping (m5 ≥ 10) ──
                    if sc >= 4 and m5 >= 10 and us_usdc > 1 and open_pos < 3 and pos['amount'] == 0:
                        spend = round(min(us_usdc * config.get('trade_pct', 0.20), max_usdc), 2)
                        if spend < 1.0: continue
                        add_user_log(wallet, '[' + short + '] BUY ' + label + ' $' + str(spend) + ' score:' + str(sc) + ' m5:+' + str(round(m5, 1)) + '%')
                        _execute_user_swap(wallet, private_key, 'buy', mint, str(spend))
                        pos['amount']     = spend / t['price']
                        pos['buy_price']  = t['price']
                        pos['peak_price'] = t['price']
                        pos['spend']      = spend
                        us_usdc -= spend; open_pos += 1
            except Exception as e:
                add_user_log(wallet, '[' + short + '] Trader error: ' + str(e))
            stop_event.wait(config.get('interval', 60))
    finally:
        private_key = None  # wipe from memory
        add_user_log(wallet, '[' + short + '] Trader stopped, key wiped from memory')
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
        try:
            get_or_create_user(address)
        except: pass
        threading.Thread(target=fetch_user_balances, args=(address,), daemon=True).start()
        add_user_log(address, 'Wallet connected: ' + address[:6] + '...' + address[-4:])
        has_key = False
        try:
            conn2 = sqlite3.connect(DB_FILE)
            c2    = conn2.cursor()
            c2.execute('SELECT encrypted_private_key FROM users WHERE wallet_address=?', (address,))
            kr = c2.fetchone()
            conn2.close()
            has_key = bool(kr and kr[0])
        except Exception:
            pass
        return jsonify({'ok': True, 'wallet': address, 'has_key': has_key})
    else:
        prev = _current_wallet()
        session.pop('wallet', None)
        if prev:
            add_user_log(prev, 'Wallet disconnected')
    return jsonify({'ok': True, 'wallet': session.get('wallet', '')})

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
        return jsonify({'ok': True, 'has_key': bool(row[0]), 'max_trade_size': row[1] or 1.0, 'daily_loss_limit': row[2] or 50.0})
    return jsonify({'ok': True, 'has_key': False, 'max_trade_size': 1.0, 'daily_loss_limit': 50.0})

@app.route('/api/settings', methods=['POST'])
@rate_limit(10, 60)
def save_settings():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'})
    data            = request.json or {}
    private_key_raw = data.get('private_key', '').strip()
    try:
        max_trade_size = float(data.get('max_trade_size', 1.0))
    except (ValueError, TypeError):
        max_trade_size = 1.0
    try:
        daily_loss_limit = float(data.get('daily_loss_limit', 50.0))
    except (ValueError, TypeError):
        daily_loss_limit = 50.0
    max_trade_size   = max(1.0,  min(max_trade_size,   10000.0))
    daily_loss_limit = max(1.0,  min(daily_loss_limit, 50000.0))

    # Validate key before touching the DB
    if private_key_raw:
        if not is_valid_solana_private_key(private_key_raw):
            return jsonify({'ok': False, 'msg': 'Invalid private key format — paste the base58 or JSON array key from your wallet'})
        try:
            encrypted = encrypt_key(private_key_raw)
        except Exception:
            return jsonify({'ok': False, 'msg': 'Failed to save private key'})
    else:
        encrypted = None  # resolved below after DB read

    conn = sqlite3.connect(DB_FILE)
    try:
        c   = conn.cursor()
        c.execute('SELECT id, encrypted_private_key FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
        if encrypted is None:
            encrypted = row[1] if row else ''
        if row:
            c.execute('UPDATE users SET encrypted_private_key=?, max_trade_size=?, daily_loss_limit=? WHERE wallet_address=?',
                      (encrypted, max_trade_size, daily_loss_limit, wallet))
        else:
            c.execute('INSERT INTO users (wallet_address, encrypted_private_key, max_trade_size, daily_loss_limit) VALUES (?,?,?,?)',
                      (wallet, encrypted, max_trade_size, daily_loss_limit))
        conn.commit()
    finally:
        conn.close()
    add_user_log(wallet, 'Settings saved for ' + wallet[:6] + '...' + wallet[-4:])
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
            'log_lines':        us.get('log_lines', [])[:40],
            'tokens':           state['tokens'],
            'wallet':           wallet,
        })
    return jsonify({
        'trader_running': state['trader_running'],
        'usdc': state['usdc'], 'sol': state['sol'],
        'positions': int(state.get('positions', 0)),
        'log_lines': state['log_lines'][:20],
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
    us  = get_user_state(wallet)
    age = time.time() - us.get('balance_fetched_at', 0)
    if age > 25:
        # Return cached value immediately; refresh in background so this never blocks
        threading.Thread(target=fetch_user_balances, args=(wallet,), daemon=True).start()
    return jsonify({'ok': True, 'sol': us.get('sol', 0.0), 'usdc': us.get('usdc', 0.0)})

# ── MARKET / TOTD / TRADES ──
@app.route('/api/market')
@rate_limit(30, 60)
def api_market():
    return jsonify({'tokens': state['tokens']})

@app.route('/api/totd')
@rate_limit(30, 60)
def api_totd():
    updated = state.get('totd_updated_at', 0)
    next_in = max(0.0, TOTD_INTERVAL - (time.time() - updated)) if updated else 0.0
    return jsonify({'token': state.get('token_of_the_day'), 'updated_at': updated, 'next_update_in': round(next_in)})

@app.route('/api/carousel')
@rate_limit(30, 60)
def api_carousel():
    return jsonify({'tokens': state['tokens'][:10]})

def _synthetic_candles(pair: dict, now: int, tcfg: dict) -> list:
    """Generate N synthetic OHLCV candles from DexScreener price-change percentages.
    Used when both Birdeye and DexScreener chart APIs are unavailable.
    Uses sine-based deterministic noise — no random module needed."""
    cur = float(pair.get('priceUsd', 0) or 0)
    if cur <= 0:
        return []
    ch     = pair.get('priceChange', {}) or {}
    ch5m   = float(ch.get('m5',  0) or 0) / 100
    ch1h   = float(ch.get('h1',  0) or 0) / 100
    ch6h   = float(ch.get('h6',  0) or 0) / 100
    ch24h  = float(ch.get('h24', 0) or 0) / 100
    vol5m  = float((pair.get('volume', {}) or {}).get('m5', 0) or 0)
    n      = tcfg['n']
    win    = tcfg['window']
    step_s = win // n
    if   win <= 600:   total_chg = ch5m
    elif win <= 7200:  total_chg = ch1h
    elif win <= 86400: total_chg = ch6h
    else:              total_chg = ch24h
    p_start = cur / max(1.0 + total_chg, 0.001)
    candles = []
    for i in range(n):
        frac  = i / max(n - 1, 1)
        base  = p_start + (cur - p_start) * frac
        noise = base * 0.003
        o = base + math.sin(i * 2.3)         * noise
        c = base + math.sin(i * 2.3 + 1.1)  * noise
        h = max(o, c) + abs(math.sin(i * 2.3 + 2.2)) * noise * 1.6
        l = min(o, c) - abs(math.sin(i * 2.3 + 3.3)) * noise * 1.6
        v = vol5m * max(0.0, math.sin(i * 1.7 + 0.5) * 0.3 + 0.5)
        candles.append({'t': now - win + i * step_s,
                        'o': o, 'h': h, 'l': l, 'c': c, 'v': round(v, 2)})
    return candles


@app.route('/api/chart/<mint>')
@rate_limit(60, 60)
def api_chart(mint):
    if not _SOLANA_ADDR_RE.match(mint or ''):
        return jsonify({'candles': [], 'error': 'invalid mint'})
    tf   = request.args.get('tf', '5m')
    _TF  = {
        '1m':  {'res': '1',    'window': 1800,    'n': 60, 'brd': '1m'},
        '5m':  {'res': '5',    'window': 9000,    'n': 60, 'brd': '5m'},
        '15m': {'res': '15',   'window': 21600,   'n': 60, 'brd': '15m'},
        '1h':  {'res': '60',   'window': 86400,   'n': 48, 'brd': '1H'},
        '4h':  {'res': '240',  'window': 345600,  'n': 42, 'brd': '4H'},
        'D':   {'res': '1440', 'window': 2592000, 'n': 30, 'brd': '1D'},
    }
    tcfg = _TF.get(tf, _TF['5m'])
    try:
        # ── Step 1: resolve pair address from DexScreener public API ──
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
        from_ts = now - tcfg['window']
        candles = []

        # ── Step 2: Birdeye OHLCV (primary) ──
        # DexScreener's internal chart API (io.dexscreener.com) is protected by
        # Cloudflare and returns 404/bot-challenge HTML for server-side requests.
        # Birdeye is the reliable server-to-server OHLCV source.
        if BIRDEYE_KEY:
            try:
                brd_url = (
                    f'https://public-api.birdeye.so/defi/ohlcv'
                    f'?address={mint}&type={tcfg["brd"]}'
                    f'&time_from={from_ts}&time_to={now}'
                )
                rb = requests.get(brd_url, timeout=10, headers={
                    'X-API-KEY': BIRDEYE_KEY,
                    'x-chain':   'solana',
                    'Accept':    'application/json',
                })
                if rb.status_code == 200:
                    for item in (rb.json().get('data') or {}).get('items', []):
                        c_val = float(item.get('c', 0) or 0)
                        if c_val <= 0:
                            continue
                        candles.append({
                            't': int(item.get('unixTime', 0)),
                            'o': float(item.get('o', c_val) or c_val),
                            'h': float(item.get('h', c_val) or c_val),
                            'l': float(item.get('l', c_val) or c_val),
                            'c': c_val,
                            'v': float(item.get('v', 0) or 0),
                        })
                else:
                    print(f'[chart] Birdeye {rb.status_code} for {mint[:8]}', flush=True)
            except Exception as e:
                print(f'[chart] Birdeye error: {e}', flush=True)

        # ── Step 3: DexScreener internal chart API (secondary) ──
        if not candles:
            try:
                chart_url = (
                    f'https://io.dexscreener.com/dex/chart/amm/v3/{chain_id}/{pair_address}'
                    f'?res={tcfg["res"]}&cb=0&from={from_ts}&to={now}'
                )
                rc = requests.get(chart_url, timeout=10, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept':    'application/json',
                    'Referer':   'https://dexscreener.com/',
                    'Origin':    'https://dexscreener.com',
                })
                if rc.status_code == 200:
                    data = rc.json()
                    def _norm(t): return int(t) // 1000 if t > 1e10 else int(t)
                    if isinstance(data, dict) and isinstance(data.get('t'), list):
                        ts_arr = data['t']
                        o_arr  = data.get('o', [])
                        h_arr  = data.get('h', [])
                        l_arr  = data.get('l', [])
                        c_arr  = data.get('c', [])
                        v_arr  = data.get('v', [])
                        for i, raw_ts in enumerate(ts_arr):
                            t_ts = _norm(raw_ts)
                            if t_ts < from_ts: continue
                            c_val = float(c_arr[i]) if i < len(c_arr) else 0
                            if c_val <= 0: continue
                            candles.append({
                                't': t_ts,
                                'o': float(o_arr[i]) if i < len(o_arr) else c_val,
                                'h': float(h_arr[i]) if i < len(h_arr) else c_val,
                                'l': float(l_arr[i]) if i < len(l_arr) else c_val,
                                'c': c_val,
                                'v': float(v_arr[i]) if i < len(v_arr) else 0,
                            })
                    elif isinstance(data, list):
                        for c in data:
                            if not isinstance(c, dict): continue
                            raw_ts = c.get('time', c.get('t', 0))
                            t_ts   = _norm(raw_ts)
                            c_val  = float(c.get('close', c.get('c', 0)) or 0)
                            if t_ts < from_ts or c_val <= 0: continue
                            candles.append({
                                't': t_ts,
                                'o': float(c.get('open',   c.get('o', c_val)) or c_val),
                                'h': float(c.get('high',   c.get('h', c_val)) or c_val),
                                'l': float(c.get('low',    c.get('l', c_val)) or c_val),
                                'c': c_val,
                                'v': float(c.get('volume', c.get('v', 0))    or 0),
                            })
                else:
                    print(f'[chart] DexScreener {rc.status_code} for {pair_address[:8]}', flush=True)
            except Exception as e:
                print(f'[chart] DexScreener error: {e}', flush=True)

        if candles:
            candles.sort(key=lambda x: x['t'])
            candles = candles[-tcfg['n']:]

        # ── Step 4: synthetic OHLCV fallback ──
        if not candles:
            print(f'[chart] using synthetic fallback for {mint[:8]}', flush=True)
            candles = _synthetic_candles(pair, now, tcfg)

        return jsonify({'candles': candles, 'pair_address': pair_address})
    except Exception as e:
        print(f'[chart] unhandled error: {e}', flush=True)
        return jsonify({'candles': [], 'error': 'Chart data unavailable'})

@app.route('/api/trades')
@rate_limit(30, 60)
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

@app.route('/api/admin')
def api_admin():
    wallet = _current_wallet()
    if not wallet or wallet != OWNER_WALLET:
        return jsonify({'error': 'Unauthorized'}), 403
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('SELECT COALESCE(SUM(fee_amount),0) FROM fees WHERE timestamp LIKE ?', (today + '%',))
        fees_today = round(float(c.fetchone()[0] or 0), 4)
        c.execute('SELECT COALESCE(SUM(fee_amount),0) FROM fees')
        fees_total = round(float(c.fetchone()[0] or 0), 4)
        c.execute('SELECT user_wallet, token, gross_profit, fee_amount, fee_tx, timestamp FROM fees ORDER BY timestamp DESC LIMIT 200')
        fee_txs = [{'wallet': r[0], 'token': r[1], 'gross': r[2], 'fee': r[3], 'tx': r[4], 'ts': r[5]}
                   for r in c.fetchall()]
        c.execute('SELECT COUNT(*) FROM users')
        total_users  = int(c.fetchone()[0] or 0)
        c.execute('SELECT COUNT(*) FROM trades')
        total_trades = int(c.fetchone()[0] or 0)
        conn.close()
        return jsonify({
            'fees_today':   fees_today,
            'fees_total':   fees_total,
            'fee_txs':      fee_txs,
            'total_users':  total_users,
            'total_trades': total_trades,
            'owner':        OWNER_WALLET,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── STARTUP ──
init_db()
threading.Thread(target=token_loop,    daemon=True).start()
threading.Thread(target=totd_loop,     daemon=True).start()
threading.Thread(target=_cleanup_loop, daemon=True).start()
add_log('OrcAgent started')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print('OrcAgent Dashboard running on port', port)
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
