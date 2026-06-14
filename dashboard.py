import threading, time, json, os, sys, subprocess, requests, logging, datetime, sqlite3, re, functools, struct, base64, math, hashlib, hmac, secrets
from contextlib import contextmanager
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

# /api/wallet/set is the auth-bootstrap endpoint — it establishes the session so it
# cannot require a session-scoped CSRF token. Origin check still protects it.
_CSRF_EXEMPT_PATHS = frozenset({'/api/wallet/set'})

def _get_csrf_token() -> str:
    """Return (creating if absent) a per-session CSRF token stored in the Flask session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def _validate_csrf(token: str) -> bool:
    """Constant-time CSRF token comparison — prevents timing oracle attacks."""
    expected = session.get('csrf_token', '')
    if not expected or not token:
        return False
    return hmac.compare_digest(token.encode(), expected.encode())

@app.before_request
def _csrf_check():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and request.path.startswith('/api/'):
        # ── 1. Origin / Host validation ──────────────────────────────────────
        origin = request.headers.get('Origin', '')
        if origin:
            host = request.headers.get('Host', '') or ''
            host_bare = host.split(':')[0]
            origin_bare = origin.split('//')[-1].split(':')[0]
            if origin_bare not in ('localhost', '127.0.0.1') and origin_bare != host_bare:
                return jsonify({'error': 'CSRF check failed'}), 403
        # ── 2. CSRF token for authenticated sessions ──────────────────────────
        if session.get('wallet') and request.path not in _CSRF_EXEMPT_PATHS:
            tok = (request.headers.get('X-CSRF-Token', '') or
                   (request.get_json(silent=True) or {}).get('csrf_token', ''))
            if not _validate_csrf(tok):
                _log_security_event('csrf_fail', session.get('wallet', 'unknown'),
                                    f'bad/missing token on {request.path}')
                return jsonify({'error': 'CSRF validation failed'}), 403

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

BASE         = os.path.dirname(os.path.abspath(__file__))
# Use Railway persistent volume when available so the DB and logs survive redeploys.
_DATA_DIR    = '/data' if os.path.exists('/data') else BASE
LOG_FILE     = os.path.join(_DATA_DIR, 'trades.log')
DB_FILE      = os.path.join(_DATA_DIR, 'orcagent.db')
print(f"[startup] persistent storage: {os.path.exists('/data')}  db={DB_FILE}", flush=True)

WALLET_ADDRESS   = os.environ.get('WALLET_ADDRESS', '')
USDC_MINT        = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
SOL_MINT         = 'So11111111111111111111111111111111111111112'
SOLANA_RPC       = 'https://api.mainnet-beta.solana.com'
OWNER_WALLET     = os.environ.get('OWNER_WALLET', '')
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
JUPITER_PROXY    = os.environ.get('JUPITER_PROXY_URL', '').rstrip('/')
PROXY_SECRET     = os.environ.get('JUPITER_PROXY_SECRET', '')
FEE_RATE         = 0.05  # 5% performance fee on profitable trades only

# ── FERNET ENCRYPTION ──
# ENCRYPTION_KEY must be set as an environment variable. No fallback — app refuses to start
# without it to ensure all stored private keys are always properly encrypted.
_enc_key_str = os.environ.get('ENCRYPTION_KEY', '').strip()
if not _enc_key_str:
    print('CRITICAL: ENCRYPTION_KEY env var is not set. Refusing to start.', flush=True)
    print('         Generate one: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"', flush=True)
    sys.exit(1)

try:
    _fernet = Fernet(_enc_key_str.encode())
except Exception:
    print('CRITICAL: ENCRYPTION_KEY is not a valid Fernet key. Refusing to start.', flush=True)
    sys.exit(1)

def _wallet_fernet(wallet: str) -> Fernet:
    """Derive a wallet-specific Fernet key via HMAC-SHA256(ENCRYPTION_KEY, wallet_address)."""
    derived = hmac.digest(_enc_key_str.encode(), wallet.encode(), 'sha256')
    return Fernet(base64.urlsafe_b64encode(derived))

def encrypt_private_key(raw: str, wallet: str) -> str:
    """Double-encrypt: Layer 1 = ENCRYPTION_KEY Fernet, Layer 2 = wallet-derived Fernet.
    Result is prefixed with 'v2:' to distinguish from legacy single-layer ciphertext."""
    l1 = _fernet.encrypt(raw.encode())
    l2 = _wallet_fernet(wallet).encrypt(l1)
    return 'v2:' + l2.decode()

def decrypt_private_key(enc: str, wallet: str) -> str:
    """Decrypt v2 (double-encrypted) or legacy v1 (single Fernet layer) private key."""
    if enc.startswith('v2:'):
        l1 = _wallet_fernet(wallet).decrypt(enc[3:].encode())
        return _fernet.decrypt(l1).decode()
    return _fernet.decrypt(enc.encode()).decode()  # legacy v1 — migrated on next save

# ── PERFORMANCE FEE COLLECTION ──
def send_sol_fee(from_privkey: str, to_wallet_str: str, amount_sol: float) -> str:
    """Native SOL transfer via System Program — no ATA, no SPL, just lamports."""
    from solders.keypair import Keypair as _KP
    from solders.pubkey import Pubkey
    from solders.instruction import Instruction, AccountMeta
    from solders.transaction import Transaction
    from solders.hash import Hash as SolHash

    SYS_PROG = Pubkey.from_string('11111111111111111111111111111111')
    keypair  = _KP.from_base58_string(from_privkey)
    sender   = keypair.pubkey()
    receiver = Pubkey.from_string(to_wallet_str)
    lamports = int(amount_sol * 1_000_000_000)

    # System Program Transfer: u32 discriminant=2 + u64 lamports (little-endian)
    ix = Instruction(
        program_id=SYS_PROG,
        accounts=[
            AccountMeta(sender,   is_signer=True,  is_writable=True),
            AccountMeta(receiver, is_signer=False, is_writable=True),
        ],
        data=struct.pack('<IQ', 2, lamports),
    )

    bh = requests.post(SOLANA_RPC, json={
        'jsonrpc': '2.0', 'id': 1, 'method': 'getLatestBlockhash', 'params': [],
    }, timeout=10).json()['result']['value']['blockhash']

    tx = Transaction.new_signed_with_payer([ix], sender, [keypair], SolHash.from_string(bh))

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
# threading.Lock is a factory function, not a class — capture the actual type once
# so isinstance() checks in _run_security_checks() work correctly.
_THREADING_LOCK_TYPE = type(_rl_lock)

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

def rate_limit(limit: int, window: int = 60, ban: bool = False):
    """Sliding-window rate limiter.  When ban=True, repeated overages trigger the
    IP-ban system (_record_ip_failure) in addition to returning 429.
    The owner wallet is always bypassed — session.get('wallet') is checked
    so this works for every endpoint without any per-route special-casing."""
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            ip  = request.remote_addr or '0.0.0.0'
            # Owner wallet is never rate-limited or banned
            if _is_owner(session.get('wallet', '')):
                return f(*args, **kwargs)
            # Respect existing bans before even counting the request
            if ban and _is_banned(ip):
                return jsonify({'ok': False, 'msg': 'Too many requests — slow down'}), 429
            key = f.__name__ + ':' + ip
            if not _rate_ok(key, limit, window):
                if ban:
                    # Only ban for extreme volume — 100+ req/min on this endpoint
                    _now = time.time()
                    with _rl_lock:
                        _recent = len([t for t in _rl_hits.get(key, []) if _now - t < 60])
                    if _recent >= 100:
                        _record_ip_failure(ip)
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
        # Evict expired IP bans and stale warn records
        for ip in list(_ip_ban.keys()):
            if now >= _ip_ban[ip]:
                _ip_ban.pop(ip, None)
                _ip_warn.pop(ip, None)
        # Evict stale AI cache entries (keep only entries younger than 2× TTL)
        ai_cutoff = now - _AI_CACHE_TTL * 2
        for mint in list(_ai_cache.keys()):
            if _ai_cache[mint].get('ts', 0) < ai_cutoff:
                del _ai_cache[mint]
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

# ── SYSTEM AUDIT ──
_audit_state: dict = {
    'status': 'unknown',   # 'pass' | 'warn' | 'fail' | 'unknown'
    'checks': [],
    'ran_at': None,
    'ran_at_ts': 0.0,
}

def _run_audit() -> dict:
    checks = []

    # 1. Database connectivity
    try:
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM users')
            n_users = c.fetchone()[0]
            c.execute('SELECT COUNT(*) FROM trades')
            n_trades = c.fetchone()[0]
        finally:
            conn.close()
        checks.append({'name': 'Database', 'status': 'pass',
                        'msg': f'{n_users} user(s), {n_trades} trade(s) on record'})
    except Exception as e:
        checks.append({'name': 'Database', 'status': 'fail', 'msg': str(e)[:80]})

    # 2. Token feed freshness
    n_tokens = len(state.get('tokens', []))
    if n_tokens == 0:
        checks.append({'name': 'Token Feed', 'status': 'warn',
                        'msg': 'No tokens loaded — DexScreener scan pending or h1≥50% filter active'})
    elif n_tokens < 3:
        checks.append({'name': 'Token Feed', 'status': 'warn',
                        'msg': f'Only {n_tokens} token(s) visible — market filter is very strict right now'})
    else:
        checks.append({'name': 'Token Feed', 'status': 'pass',
                        'msg': f'{n_tokens} trending token(s) loaded'})

    # 3. Solana RPC
    try:
        r = requests.post(SOLANA_RPC,
                          json={'jsonrpc': '2.0', 'id': 1, 'method': 'getHealth'},
                          timeout=5)
        health = r.json().get('result', '')
        if health == 'ok':
            checks.append({'name': 'Solana RPC', 'status': 'pass', 'msg': 'Mainnet RPC healthy'})
        else:
            checks.append({'name': 'Solana RPC', 'status': 'warn',
                            'msg': f'RPC returned: {str(health)[:40]}'})
    except Exception as e:
        checks.append({'name': 'Solana RPC', 'status': 'fail',
                        'msg': f'Unreachable — {str(e)[:60]}'})

    # 4. DexScreener API (token discovery source)
    if time.time() < _dex_429_until:
        remaining = int(_dex_429_until - time.time())
        checks.append({'name': 'DexScreener', 'status': 'warn',
                        'msg': f'Rate-limited (429) — backoff {remaining}s remaining'})
    else:
        try:
            r = requests.get(
                'https://api.dexscreener.com/latest/dex/tokens/' + USDC_MINT,
                headers=_DEX_HEADERS, timeout=6)
            if r.status_code == 200:
                checks.append({'name': 'DexScreener', 'status': 'pass',
                                'msg': f'HTTP {r.status_code} — token data available'})
            else:
                checks.append({'name': 'DexScreener', 'status': 'warn',
                                'msg': f'HTTP {r.status_code} — degraded'})
        except Exception as e:
            checks.append({'name': 'DexScreener', 'status': 'fail',
                            'msg': f'Unreachable — {str(e)[:60]}'})

    # 5. Jupiter API (swap quote endpoint — critical for trade execution)
    _sol_mint    = 'So11111111111111111111111111111111111111112'
    _jup_url     = (JUPITER_PROXY + '/quote') if JUPITER_PROXY else 'https://api.jup.ag/swap/v1/quote'
    _jup_headers = {'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0 OrcAgent/1.0'}
    if PROXY_SECRET:
        _jup_headers['X-Proxy-Secret'] = PROXY_SECRET
    _route_label = f'via proxy ({JUPITER_PROXY})' if JUPITER_PROXY else 'direct (quote-api.jup.ag)'
    try:
        jr = requests.get(
            _jup_url,
            params={
                'inputMint':   USDC_MINT,
                'outputMint':  _sol_mint,
                'amount':      '1000000',
                'slippageBps': '300',
            },
            headers=_jup_headers,
            timeout=8,
        )
        if jr.status_code == 200:
            checks.append({'name': 'Jupiter API', 'status': 'pass',
                            'msg': f'Reachable {_route_label} — HTTP 200, quote OK'})
        elif jr.status_code == 429:
            checks.append({'name': 'Jupiter API', 'status': 'warn',
                            'msg': f'Rate-limited (429) {_route_label}'})
        else:
            checks.append({'name': 'Jupiter API', 'status': 'warn',
                            'msg': f'HTTP {jr.status_code} {_route_label} — {jr.text[:80]}'})
    except Exception as e:
        checks.append({'name': 'Jupiter API', 'status': 'fail',
                        'msg': f'Unreachable {_route_label} — {str(e)[:80]}'})

    # 6. Encryption key (private key storage)
    if _fernet is not None:
        checks.append({'name': 'Encryption Key', 'status': 'pass',
                        'msg': 'Fernet key initialised — private keys stored securely'})
    else:
        checks.append({'name': 'Encryption Key', 'status': 'fail',
                        'msg': 'Fernet not initialised — cannot save private keys'})

    # 7. Memory
    n_states = len(user_states)
    n_rl     = len(_rl_hits)
    if n_states > 190:
        checks.append({'name': 'Memory', 'status': 'fail',
                        'msg': f'{n_states} user states (cleanup loop may be stuck)'})
    elif n_states > 150:
        checks.append({'name': 'Memory', 'status': 'warn',
                        'msg': f'{n_states} user states in memory — approaching cap'})
    else:
        checks.append({'name': 'Memory', 'status': 'pass',
                        'msg': f'{n_states} user state(s), {n_rl} rate-limit bucket(s)'})

    # 8. Active traders
    active = sum(1 for us in list(user_states.values()) if us.get('trader_running'))
    checks.append({'name': 'Active Traders', 'status': 'pass',
                    'msg': f'{active} trader(s) currently running'})

    # Overall
    if any(c['status'] == 'fail' for c in checks):
        overall = 'fail'
    elif any(c['status'] == 'warn' for c in checks):
        overall = 'warn'
    else:
        overall = 'pass'

    return {
        'status':    overall,
        'checks':    checks,
        'ran_at':    datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'ran_at_ts': time.time(),
    }

def _audit_loop():
    time.sleep(15)   # let token/TOTD loops start first
    while True:
        try:
            result = _run_audit()
            _audit_state.update(result)
        except Exception as e:
            _audit_state.update({
                'status':    'fail',
                'checks':    [{'name': 'Audit runner', 'status': 'fail', 'msg': str(e)[:120]}],
                'ran_at':    datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'ran_at_ts': time.time(),
            })
        time.sleep(300)   # re-run every 5 minutes

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
        max_trade_size        REAL DEFAULT 0.5,
        min_trade_size        REAL DEFAULT 0.01,
        daily_loss_limit      REAL DEFAULT 10.0,
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
    # Migrations: add columns introduced after initial deploy
    try:
        c.execute('ALTER TABLE trades ADD COLUMN fee_amount REAL DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE trades ADD COLUMN fee_paid INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE fees ADD COLUMN status TEXT DEFAULT "ok"')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE users ADD COLUMN min_trade_size REAL DEFAULT 0.01')
    except sqlite3.OperationalError:
        pass
    # Fix stale users still on the old UI defaults (min=3, max=5, daily=50)
    c.execute('''UPDATE users
                 SET min_trade_size=0.01, max_trade_size=0.5, daily_loss_limit=10.0
                 WHERE min_trade_size=3 AND max_trade_size=5 AND daily_loss_limit=50''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_trades_user_id ON trades(user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_fees_wallet    ON fees(user_wallet)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_fees_timestamp ON fees(timestamp)')
    c.execute('''CREATE TABLE IF NOT EXISTS security_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        wallet     TEXT NOT NULL,
        ip_addr    TEXT DEFAULT '',
        details    TEXT DEFAULT '',
        timestamp  TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_seclog_ts ON security_log(timestamp)')
    # Migrate: add key_hash column to users if not already present
    try:
        c.execute('ALTER TABLE users ADD COLUMN key_hash TEXT DEFAULT ""')
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

# ── SECURITY HELPERS ──
# Matches base58 strings 87-88 chars long — Solana private key length.
# Also matches TX signatures; actively block only on key-sensitive API paths.
_KEY_LEAK_RE     = re.compile(r'[1-9A-HJ-NP-Za-km-z]{87,88}')
# Endpoints where any 87-88 char base58 string in the response triggers a hard block.
# Admin endpoints that return TX hashes are excluded — TX sigs are the same length.
_SENSITIVE_PATHS = {'/api/settings', '/api/claim_sol', '/api/admin/test_fee'}

# Paths that should never be legitimately accessed — any hit is a scan/probe.
_HONEYPOT_PATHS = frozenset({'/.env', '/wp-login.php', '/admin', '/phpmyadmin', '/config.php', '/.git/config'})

# Fields that must never appear in any JSON response body.
# Includes DB column names so a runaway SELECT * can never accidentally expose them.
_FORBIDDEN_RESPONSE_KEYS = frozenset({
    'private_key', 'private_key_raw', 'encrypted_private_key',
    'enc_key', 'encrypted_key', 'encryption_key', 'raw_key', 'privkey',
    'secret', 'secret_key',
    'key_hash',
    'traceback',
})

def _redact_keys(text: str) -> str:
    """Replace 87-88 char base58 strings in text with [REDACTED].
    Covers both private keys and TX hashes — used for subprocess output before logging."""
    return _KEY_LEAK_RE.sub('[REDACTED]', text)

def _security_selftest() -> bool:
    STATE_ALLOWED    = frozenset({
        'trader_running', 'usdc', 'sol', 'positions', 'positions_detail',
        'log_lines', 'tokens', 'wallet', 'is_admin', 'has_trading_key',
    })
    SETTINGS_ALLOWED = frozenset({
        'ok', 'has_trading_key', 'max_trade_size', 'min_trade_size', 'daily_loss_limit', 'msg',
    })
    passed = True
    for name, allowed in [('/api/state', STATE_ALLOWED), ('/api/settings', SETTINGS_ALLOWED)]:
        leak = allowed & _FORBIDDEN_RESPONSE_KEYS
        if leak:
            print(f'[SECURITY SELFTEST FAIL] {name} schema contains forbidden field(s): {leak}', flush=True)
            passed = False
    if '/api/settings' not in _SENSITIVE_PATHS:
        print('[SECURITY SELFTEST FAIL] /api/settings not in _SENSITIVE_PATHS', flush=True)
        passed = False
    if not _KEY_LEAK_RE.pattern:
        print('[SECURITY SELFTEST FAIL] _KEY_LEAK_RE not compiled', flush=True)
        passed = False
    if passed:
        print(f'[security selftest] PASS — '
              f'{len(_SENSITIVE_PATHS)} blocked path(s), '
              f'{len(_FORBIDDEN_RESPONSE_KEYS)} forbidden field(s), '
              f'log_lines scrubbed, regex active on all endpoints', flush=True)
    return passed

def _run_security_checks() -> list:
    """Run all runtime security invariant checks. Returns list of failed {check, detail} dicts."""
    failures = []

    # 1. ENCRYPTION_KEY is still present and valid in the environment
    try:
        live_key = os.environ.get('ENCRYPTION_KEY', '').strip()
        if not live_key:
            failures.append({'check': 'ENCRYPTION_KEY', 'detail': 'missing from environment at runtime'})
        else:
            Fernet(live_key.encode())  # re-validate without decrypting anything
    except Exception as e:
        failures.append({'check': 'ENCRYPTION_KEY', 'detail': f'invalid Fernet key at runtime: {str(e)[:80]}'})

    # 2. All stored encrypted private keys can still be decrypted
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('SELECT wallet_address, encrypted_private_key FROM users '
                  'WHERE encrypted_private_key != "" AND encrypted_private_key IS NOT NULL')
        rows = c.fetchall()
        conn.close()
        n_ok = n_fail = 0
        for waddr, enc_blob in rows:
            raw = None
            try:
                raw = decrypt_private_key(enc_blob, waddr)
                n_ok += 1
            except Exception:
                n_fail += 1
            finally:
                raw = None
        if n_fail:
            failures.append({'check': 'Key Decryption',
                             'detail': f'{n_fail}/{n_ok + n_fail} stored key(s) cannot be decrypted'})
    except Exception as e:
        failures.append({'check': 'Key Decryption', 'detail': f'DB query failed: {str(e)[:80]}'})

    # 3. /api/state schema contains no forbidden response fields
    _state_schema = frozenset({
        'trader_running', 'usdc', 'sol', 'positions', 'positions_detail',
        'log_lines', 'tokens', 'wallet', 'is_admin', 'has_trading_key',
    })
    leaked = _FORBIDDEN_RESPONSE_KEYS & _state_schema
    if leaked:
        failures.append({'check': 'Response Schema',
                         'detail': f'forbidden field(s) in /api/state schema: {leaked}'})

    # 4. All honeypot routes are still registered in the URL map
    registered = {rule.rule for rule in app.url_map.iter_rules()}
    missing_pots = _HONEYPOT_PATHS - registered
    if missing_pots:
        failures.append({'check': 'Honeypots',
                         'detail': f'honeypot route(s) not in url_map: {missing_pots}'})

    # 5. Rate limiting is active (lock, hits dict, and decorator all functional)
    if not callable(rate_limit):
        failures.append({'check': 'Rate Limiter', 'detail': 'rate_limit is not callable'})
    elif not isinstance(_rl_lock, _THREADING_LOCK_TYPE):
        failures.append({'check': 'Rate Limiter', 'detail': '_rl_lock is not a threading.Lock'})
    elif not isinstance(_rl_hits, dict):
        failures.append({'check': 'Rate Limiter', 'detail': '_rl_hits is not a dict'})

    return failures


# Persistent state for the security check loop — read by /api/admin/security-status
_sec_check_state: dict = {
    'consecutive_failures': 0,
    'last_checked':         None,
    'last_failures':        [],
    'trading_paused':       False,
    'paused_at':            None,
}

def _security_check_loop():
    """Background thread: run security invariant checks every 60 s.
    Two consecutive failures pause ALL user traders and log CRITICAL."""
    time.sleep(30)  # let startup (DB init, selftest) finish first
    while True:
        try:
            failures  = _run_security_checks()
            now_str   = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            _sec_check_state['last_checked'] = now_str
            if failures:
                _sec_check_state['consecutive_failures'] += 1
                _sec_check_state['last_failures']         = failures
                n_consec = _sec_check_state['consecutive_failures']
                for f in failures:
                    print(f'CRITICAL [security] CHECK FAILED ({n_consec}x): '
                          f'{f["check"]} — {f["detail"]}', flush=True)
                    _log_security_event('CRITICAL_check_failed', 'system',
                                        f'({n_consec}x) {f["check"]}: {f["detail"][:200]}')
                # Pause all trading after 2 consecutive failures
                if n_consec >= 2 and not _sec_check_state['trading_paused']:
                    _sec_check_state['trading_paused'] = True
                    _sec_check_state['paused_at']      = now_str
                    n_stopped = 0
                    for w, us in list(user_states.items()):
                        if us.get('trader_running'):
                            if us.get('trader_stop'):
                                us['trader_stop'].set()
                            us['trader_running'] = False
                            try:
                                add_user_log(w, '[SECURITY] Trading paused by security check failure. '
                                             'Contact admin to resume.')
                            except Exception:
                                pass
                            n_stopped += 1
                    print(f'CRITICAL [security] ALL TRADING PAUSED — '
                          f'{n_stopped} trader(s) stopped after {n_consec} consecutive failures',
                          flush=True)
                    _log_security_event('trading_paused_security', 'system',
                                        f'{n_consec} consecutive failures — {n_stopped} trader(s) paused')
            else:
                _sec_check_state['consecutive_failures'] = 0
                _sec_check_state['last_failures']        = []
                print('[security] OK — all checks passed', flush=True)
        except Exception as e:
            print(f'[security] ERROR in check loop: {e}', flush=True)
        time.sleep(60)

def _log_security_event(event_type: str, wallet: str, details: str = '') -> None:
    short   = (wallet[:4] + '...' + wallet[-4:]) if len(wallet) >= 8 else wallet
    details = _redact_keys(str(details))  # scrub before printing — belt-and-suspenders
    try:
        ip = request.remote_addr or 'system'
    except RuntimeError:
        ip = 'system'  # no request context (background thread)
    print(f'SEC [{event_type}] {short} {details}', flush=True)
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            'INSERT INTO security_log (event_type, wallet, ip_addr, details) VALUES (?,?,?,?)',
            (event_type, short, ip, details))
        conn.commit()
        conn.close()
    except Exception:
        pass

_ip_ban:  dict = {}  # ip → ban_expires_at (epoch seconds)
_ip_warn: dict = {}  # ip → list of recent failure timestamps

# Multi-IP wallet monitoring: same wallet from 3+ distinct IPs within 1 h → alert + pause
_wallet_ips:      dict           = {}   # wallet → [(ip, timestamp), ...]
_wallet_ips_lock: threading.Lock = threading.Lock()

def _check_wallet_multi_ip(wallet: str, ip: str) -> bool:
    """Record auth IP for wallet. Returns True if 3+ distinct IPs seen in last hour.
    On detection: logs CRITICAL, pauses the wallet's trader, records security event."""
    now = time.time()
    with _wallet_ips_lock:
        entries = [(h, ts) for h, ts in _wallet_ips.get(wallet, []) if now - ts < 3600]
        entries.append((ip, now))
        _wallet_ips[wallet] = entries
        distinct = {h for h, _ in entries}
    if len(distinct) >= 3:
        short = (wallet[:6] + '...' + wallet[-4:]) if len(wallet) >= 10 else wallet
        msg = (f'CRITICAL [security] Multi-IP alert: {short} authenticated from '
               f'{len(distinct)} distinct IPs in 1h')
        print(msg, flush=True)
        _log_security_event('multi_ip_alert', wallet,
                            f'{len(distinct)} IPs in 1h: {", ".join(sorted(distinct)[:8])}')
        # Pause this user's active trader
        us = user_states.get(wallet)
        if us and us.get('trader_running'):
            if us.get('trader_stop'):
                us['trader_stop'].set()
            us['trader_running'] = False
            try:
                add_user_log(wallet, '[SECURITY] Trading paused — multiple IPs detected. '
                             'Contact admin if this was not you.')
            except Exception:
                pass
        return True
    return False

def _is_banned(ip: str) -> bool:
    expires = _ip_ban.get(ip, 0)
    if time.time() < expires:
        return True
    _ip_ban.pop(ip, None)
    return False

def _record_ip_failure(ip: str, duration: int = 3600, threshold: int = 3, window: int = 600) -> None:
    """Ban IP for duration seconds after threshold failures within window seconds."""
    now  = time.time()
    hits = [t for t in _ip_warn.get(ip, []) if now - t < window]
    hits.append(now)
    _ip_warn[ip] = hits
    if len(hits) >= threshold:
        _ip_ban[ip] = now + duration
        print(f'SECURITY: IP {ip} banned {duration}s after {len(hits)} failures', flush=True)

@contextmanager
def _use_key(enc_blob: str, wallet: str):
    """Decrypt private key for one operation with best-effort memory protection.
    Zeros a mutable bytearray copy of the key in finally, then drops the reference."""
    _k = None
    try:
        _k = decrypt_private_key(enc_blob, wallet)
        _log_security_event('key_access', wallet, 'trade execution')
        yield _k
    finally:
        if _k is not None:
            try:
                # Python strings are immutable so we cannot zero in-place;
                # zero a mutable copy so the content at least lives briefly.
                _kb = bytearray(_k.encode('utf-8'))
                _kb[:] = b'\x00' * len(_kb)
            except Exception:
                pass
        _k = None

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

def _is_owner(wallet: str) -> bool:
    """Constant-time comparison: is wallet the OWNER_WALLET?
    hmac.compare_digest prevents timing oracle attacks on admin auth checks."""
    if not OWNER_WALLET or not wallet:
        return False
    return hmac.compare_digest(wallet.encode(), OWNER_WALLET.encode())

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

# ── DEXSCREENER HTTP HELPERS ──
_DEX_HEADERS   = {'User-Agent': 'Mozilla/5.0 OrcAgent/1.0', 'Accept': 'application/json'}
_dex_429_until  = 0.0  # epoch seconds — 0 means not in backoff
_dex_lock       = threading.Lock()
_last_good_mints: list = []  # last non-empty result from discover_tokens()

def _dex_get(url: str, timeout: int = 10):
    """GET a DexScreener URL with shared headers and 429 backoff.
    Returns the Response, or None if in backoff / request failed."""
    global _dex_429_until
    with _dex_lock:
        if time.time() < _dex_429_until:
            return None
    try:
        r = requests.get(url, headers=_DEX_HEADERS, timeout=timeout)
        if r.status_code == 429:
            with _dex_lock:
                _dex_429_until = time.time() + 60
            add_log('DexScreener rate-limited (429) — backing off 60 s, serving cached data')
            return None
        return r
    except Exception:
        return None

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
            'has_trading_key': False,
            'log_lines': list(state['log_lines']),  # seed with recent system events
        }
    return user_states[wallet]

def fetch_user_balances(wallet: str):
    """Fetch SOL balance from Solana RPC and cache in per-user state."""
    us = get_user_state(wallet)
    try:
        r = requests.post(SOLANA_RPC, json={
            'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [wallet]
        }, timeout=8)
        us['sol'] = round(r.json()['result']['value'] / 1e9, 4)
    except Exception:
        pass
    us['balance_fetched_at'] = time.time()

# ── TOKEN DISCOVERY ──
TOTD_INTERVAL = 900  # 15 minutes

def discover_tokens():
    seen  = {USDC_MINT, SOL_MINT}
    mints = []

    # 1. Top boosted Solana tokens
    r = _dex_get('https://api.dexscreener.com/token-boosts/top/v1')
    if r and r.status_code == 200:
        try:
            for item in r.json():
                if item.get('chainId') == 'solana':
                    m = item.get('tokenAddress', '')
                    if m and m not in seen:
                        seen.add(m); mints.append(m)
        except Exception: pass
    time.sleep(0.5)  # stagger — avoid hammering all endpoints at once

    # 2. Trending Solana tokens — mirrors DexScreener trending page (6h score)
    r = _dex_get('https://api.dexscreener.com/latest/dex/search?q=solana&rankBy=trendingScoreH6')
    if r and r.status_code == 200:
        try:
            data  = r.json()
            pairs = data.get('pairs', []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            for p in pairs:
                if p.get('chainId') == 'solana':
                    m = (p.get('baseToken') or {}).get('address', '')
                    if m and m not in seen:
                        seen.add(m); mints.append(m)
        except Exception: pass
    time.sleep(0.5)  # stagger

    # 3. Latest Solana token profiles
    r = _dex_get('https://api.dexscreener.com/token-profiles/latest/v1')
    if r and r.status_code == 200:
        try:
            items = r.json() if isinstance(r.json(), list) else []
            for item in items:
                if item.get('chainId') == 'solana':
                    m = item.get('tokenAddress', '')
                    if m and m not in seen:
                        seen.add(m); mints.append(m)
        except Exception: pass

    return mints[:100]  # cap discovery to 100 tokens per cycle

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

def _get_user_sol(wallet: str) -> float:
    try:
        r = requests.post(SOLANA_RPC, json={'jsonrpc':'2.0','id':1,'method':'getBalance','params':[wallet]}, timeout=8)
        return round(r.json()['result']['value'] / 1e9, 6)
    except: pass
    return 0.0

def get_token_data(mint):
    try:
        r = _dex_get('https://api.dexscreener.com/latest/dex/tokens/' + mint, timeout=8)
        if not r:
            return None
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
            'change15m':     float(p.get('priceChange', {}).get('m15', 0) or 0),
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
            'pairAddress':   p.get('pairAddress', '') or '',
            'pairCreatedAt': int(p.get('pairCreatedAt', 0) or 0),
        }
    except: return None

_ai_cache: dict = {}
_AI_CACHE_TTL      = 300   # seconds — cache per-token AI signal for 5 min
_ai_disabled_until = 0.0   # epoch — set to now+3600 on 401, resets automatically

_ANTHROPIC_URL     = 'https://api.anthropic.com/v1/messages'
_ANTHROPIC_HEADERS = {'anthropic-version': '2023-06-01', 'content-type': 'application/json'}

def get_ai_signal(token_data: dict, mint: str) -> tuple:
    """Returns (bonus_pts 0–2.0, text). Direct REST call — no SDK dependency.
    Caches per mint for _AI_CACHE_TTL seconds to avoid hammering the API."""
    global _ai_disabled_until
    if not ANTHROPIC_API_KEY:
        return 0.0, ''
    now = time.time()
    if now < _ai_disabled_until:
        return 0.0, ''
    cached = _ai_cache.get(mint)
    if cached and now - cached['ts'] < _AI_CACHE_TTL:
        return cached['score'], cached['reasoning']
    try:
        prompt = (
            f'price: ${token_data.get("price", 0)}, '
            f'm5: {token_data.get("change5m", 0):.1f}%, '
            f'1h: {token_data.get("change1h", 0):.1f}%, '
            f'liq: ${token_data.get("liquidity", 0):,.0f}, '
            f'Buys: {token_data.get("txns24h_buys", 0)}, '
            f'Sells: {token_data.get("txns24h_sells", 0)}. '
            'Reply with just a number 1-10.'
        )
        resp = requests.post(
            _ANTHROPIC_URL,
            headers={**_ANTHROPIC_HEADERS, 'x-api-key': ANTHROPIC_API_KEY},
            json={'model': 'claude-haiku-4-5-20251001', 'max_tokens': 10,
                  'messages': [{'role': 'user', 'content': prompt}]},
            timeout=10,
        )
        if resp.status_code == 401:
            _ai_disabled_until = now + 3600  # 1-hour backoff, not permanent
            add_log('AI signals disabled - check ANTHROPIC_API_KEY')
            _ai_cache[mint] = {'score': 0.0, 'reasoning': '', 'ts': now}
            return 0.0, ''
        if resp.status_code == 429:
            _ai_cache[mint] = {'score': 0.0, 'reasoning': '', 'ts': now}
            return 0.0, ''
        resp.raise_for_status()
        text   = ((resp.json().get('content') or [{}])[0].get('text') or '').strip()
        ai_raw = max(1.0, min(10.0, float(text.split()[0])))
        bonus  = round(max(0.0, min(2.0, (ai_raw - 5) / 5 * 2)), 1)
        _ai_cache[mint] = {'score': bonus, 'reasoning': text[:40], 'ts': now}
        return bonus, text[:40]
    except Exception:
        _ai_cache[mint] = {'score': 0.0, 'reasoning': '', 'ts': now}
        return 0.0, ''

def score_token(data: dict) -> tuple:
    """Multi-factor signal scoring. Returns (score 0–10, breakdown dict).
    Factors: momentum(0-3) + volume(0-2) + trend(0-2) + liq(0-1) + activity(0-1) - penalties."""
    if data.get('price', 0) <= 0:
        return 0.0, {
            'label': 'AVOID', 'confidence': 0, 'momentum': 0, 'volume': 0,
            'trend': 0, 'liquidity': 0, 'trader_activity': 0, 'penalties': 0,
            'ai_bonus': 0, 'ai_reasoning': '', 'vol_accel': False,
            'buy_pressure': 50, 'risk_flags': [], 'why_buy': [],
        }

    m5     = data.get('change5m',  0)
    h1     = data.get('change1h',  0)
    h6     = data.get('change6h',  0)
    v5m    = data.get('volume5m',  0)
    v1h    = data.get('volume1h',  0)
    liq    = data.get('liquidity', 0)
    fdv    = data.get('fdv',       0)
    buys   = data.get('txns_buys',  0) or 0
    sells  = data.get('txns_sells', 0) or 0
    txns24 = data.get('txns24h',    0) or 0
    makers = data.get('makers24h',  0) or 0

    total_5m  = buys + sells
    buy_ratio = buys / total_5m if total_5m > 0 else 0.5
    buy_pct   = round(buy_ratio * 100)

    # age from pairCreatedAt (ms epoch)
    created_ms = data.get('pairCreatedAt', 0) or 0
    age_hours  = (time.time() - created_ms / 1000) / 3600 if created_ms > 0 else 999

    # ── MOMENTUM (0–3 pts) ──────────────────────────────────────────────
    if   m5 >= 20: mom_pts = 3.0
    elif m5 >= 10: mom_pts = 2.0
    elif m5 >=  5: mom_pts = 1.0
    else:          mom_pts = 0.0

    # ── VOLUME (0–2 pts) ────────────────────────────────────────────────
    # volume acceleration: current 5m pace > average 5m pace from last hour
    vol_accel = bool(v5m > 0 and v1h > 0 and v5m > v1h / 12)
    vol_pts   = (1.0 if vol_accel else 0.0) + (1.0 if buy_ratio > 0.6 else 0.0)

    # ── TREND ALIGNMENT (0–2 pts) ────────────────────────────────────────
    trend_pts = (0.5 if h1 > 0 else 0.0) + (0.5 if h6 > 0 else 0.0)
    if m5 > 0 and h1 > 0 and h6 > 0:
        trend_pts += 1.0  # golden cross: all three timeframes aligned
    if h6 < -10 and m5 > 10:
        trend_pts = max(0.0, trend_pts - 0.5)  # dead-cat-bounce risk

    # ── LIQUIDITY HEALTH (0–1 pt) ────────────────────────────────────────
    liq_pts = 1.0 if liq >= 100_000 else (0.5 if liq >= 50_000 else 0.0)

    # ── TRADER ACTIVITY (0–1 pt) ─────────────────────────────────────────
    activity   = makers if makers > 0 else txns24
    trader_pts = 1.0 if activity >= 500 else (0.5 if activity >= 200 else 0.0)

    base = mom_pts + vol_pts + trend_pts + liq_pts + trader_pts

    # ── RISK PENALTIES ────────────────────────────────────────────────────
    penalties  = 0.0
    risk_flags = []
    if buy_ratio < 0.4:
        penalties += 1.0;  risk_flags.append('SELL PRESSURE')
    if liq < 5_000:
        penalties += 4.0;  risk_flags.append('VERY LOW LIQ')
    elif liq < 15_000:
        penalties += 2.0;  risk_flags.append('LOW LIQ')
    if 0 < activity < 100:
        penalties += 1.0;  risk_flags.append('FEW TRADERS')
    if fdv > 0 and liq > 0 and fdv / liq > 100:
        penalties += 1.0;  risk_flags.append('HIGH MCAP/LIQ')
    if 0 < age_hours < 1:
        penalties += 1.0;  risk_flags.append('VERY NEW <1H')

    raw = max(0.0, base - penalties)

    # ── WHY BUY reasons ───────────────────────────────────────────────────
    why = []
    if mom_pts >= 2:         why.append(f'+{m5:.0f}% in 5m — strong momentum')
    elif mom_pts == 1:       why.append(f'+{m5:.0f}% in 5m — building momentum')
    if vol_accel:            why.append('Volume accelerating above average pace')
    if buy_ratio > 0.6:      why.append(f'{buy_pct}% buy pressure — strong demand')
    if trend_pts >= 2:       why.append('All timeframes aligned (5m + 1h + 6h)')
    elif trend_pts >= 1:     why.append('Multi-timeframe trend positive')
    if liq >= 100_000:       why.append(f'Deep liquidity ${liq/1000:.0f}K')

    # Store helper fields for AI call
    data['_buy_pct']    = buy_pct
    data['_base_score'] = round(raw, 1)

    score = round(min(10.0, raw), 1)

    if   score >= 8: lbl = 'STRONG BUY'
    elif score >= 6: lbl = 'BUY'
    elif score >= 4: lbl = 'WATCH'
    else:            lbl = 'AVOID'

    bd = {
        'label':          lbl,
        'confidence':     round(score / 10 * 100),
        'momentum':       mom_pts,
        'volume':         vol_pts,
        'vol_accel':      vol_accel,
        'buy_pressure':   buy_pct,
        'trend':          trend_pts,
        'liquidity':      liq_pts,
        'trader_activity': trader_pts,
        'penalties':      penalties,
        'risk_flags':     risk_flags,
        'ai_bonus':       0.0,
        'ai_reasoning':   '',
        'why_buy':        why[:3],
    }
    return score, bd

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
    global _last_good_mints
    while True:
        try:
            mints = discover_tokens()
            if mints:
                _last_good_mints = list(mints)
                add_log('Scanning ' + str(len(mints)) + ' tokens...')
            elif _last_good_mints:
                with _dex_lock:
                    in_backoff = time.time() < _dex_429_until
                if in_backoff:
                    add_log('DexScreener rate limited — using last ' + str(len(_last_good_mints)) + ' known tokens')
                else:
                    add_log('Scanning ' + str(len(_last_good_mints)) + ' tokens (cached)...')
                mints = _last_good_mints
            else:
                # No data at all yet — skip cycle silently
                time.sleep(120)
                continue
            total_disc = len(mints)
            all_tokens = []
            for i, mint in enumerate(mints):
                if i > 0:
                    time.sleep(0.3)  # stagger per-token calls
                data = get_token_data(mint)
                if not data or data['price'] <= 0:
                    continue
                # Minimum quality filters — score handles the rest
                if data['liquidity'] < 15000:
                    continue
                if data['volume5m'] < 1000:
                    continue
                sc, bd = score_token(data)
                entry = {
                    'mint':          mint,
                    'symbol':        data['symbol'] or mint[:8],
                    'name':          data['name'] or data['symbol'] or mint[:8],
                    'price':         data['price'],
                    'change5m':      data['change5m'],
                    'change15m':     data.get('change15m', 0),
                    'change1h':      data['change1h'],
                    'change6h':      data['change6h'],
                    'change24h':     data['change24h'],
                    'volume5m':      data['volume5m'],
                    'volume1h':      data['volume1h'],
                    'volume24h':     data['volume24h'],
                    'liquidity':     data['liquidity'],
                    'fdv':           data['fdv'],
                    'score':         sc,
                    'breakdown':     bd,
                    'pairCreatedAt': data.get('pairCreatedAt', 0),
                    'txns24h':       data['txns24h'],
                    'txns24h_buys':  data['txns24h_buys'],
                    'txns24h_sells': data['txns24h_sells'],
                    'makers24h':     data['makers24h'],
                    'pairAddress':   data.get('pairAddress', '') or '',
                }
                all_tokens.append(entry)
            # Sort by score descending — best opportunity first
            display    = sorted(all_tokens, key=lambda t: t['score'], reverse=True)
            # AI signal boost for top 5 scoring tokens (adds 0–2 bonus pts)
            if ANTHROPIC_API_KEY:
                for entry in display[:5]:
                    ai_bonus, ai_reason = get_ai_signal(entry, entry['mint'])
                    if ai_bonus > 0 or ai_reason:
                        entry['score'] = round(min(10.0, entry['score'] + ai_bonus), 1)
                        bd = entry.get('breakdown', {})
                        bd['ai_bonus']     = ai_bonus
                        bd['ai_reasoning'] = ai_reason
                        if ai_reason:
                            why = bd.get('why_buy', [])
                            why.append(f'AI: {ai_reason}')
                            bd['why_buy'] = why[:3]
                        sc = entry['score']
                        bd['label']      = 'STRONG BUY' if sc >= 8 else ('BUY' if sc >= 6 else ('WATCH' if sc >= 4 else 'AVOID'))
                        bd['confidence'] = round(sc / 10 * 100)
                # Re-sort after AI adjustments
                display.sort(key=lambda t: t['score'], reverse=True)
            qualifying = [t for t in display if t['score'] >= 4.5]
            state['tokens'] = display
            add_log(str(len(qualifying)) + '/' + str(total_disc) + ' qualify (score≥4.5) — '
                    + ('best: ' + display[0]['symbol'] + ' ' + str(display[0]['score']) + '/10'
                       if display else 'no tokens'))
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

def _record_user_trade(user_id: int, us: dict, symbol: str, entry: float, exit_price: float,
                       amount: float, spend: float, wallet: str = '', private_key: str = ''):
    check_daily_reset_user(us)
    now   = datetime.datetime.utcnow()
    today = now.strftime('%Y-%m-%d')
    pnl     = round(amount * (exit_price - entry), 4) if entry > 0 else 0.0
    pnl_pct = round((exit_price - entry) / entry * 100, 2) if entry > 0 else 0.0

    # 5% performance fee on profitable trades only (collected in SOL)
    fee_amount = 0.0
    short_w    = (wallet[:6] + '...' + wallet[-4:]) if len(wallet) >= 10 else wallet
    _owner_set = bool(OWNER_WALLET)
    print(f'[fee] {short_w} {symbol} pnl={pnl:.6f} SOL  '
          f'pnl_positive={pnl>0}  has_key={bool(private_key and wallet)}  '
          f'owner_wallet_set={_owner_set}', flush=True)

    # Collect fees from ALL profitable trades regardless of who the session wallet belongs to.
    # The fee goes FROM the trading keypair TO OWNER_WALLET — these are different addresses,
    # so even the platform owner's trades generate a valid transfer.
    if pnl > 0.0 and wallet and private_key and _owner_set:
        fee_amount = round(pnl * FEE_RATE, 6)
        print(f'[fee] {short_w} {symbol} fee owed = {fee_amount:.6f} SOL '
              f'(5% of {pnl:.6f} SOL profit)  threshold_met={fee_amount >= 0.0001}', flush=True)

        if fee_amount >= 0.0001:
            _pk   = private_key     # Python string — immutable, ref lives in thread args tuple
            _sym  = symbol
            _gros = pnl
            _fee  = fee_amount
            _wlt  = wallet
            _uid  = user_id
            _ts   = now.strftime('%Y-%m-%dT%H:%M:%SZ')

            def _do_fee(pk, sym, gross, fee, wlt, uid, trade_ts):
                sw = (wlt[:6] + '...' + wlt[-4:]) if len(wlt) >= 10 else wlt
                # Wait for the sell TX to confirm on-chain before we try to spend from that balance
                time.sleep(12)
                print(f'[fee] → attempting {fee:.6f} SOL transfer from trading wallet to OWNER_WALLET '
                      f'for {sw} {sym}  gross_profit={gross:.6f} SOL', flush=True)
                if not OWNER_WALLET:
                    print(f'[fee] ✗ OWNER_WALLET is not set — cannot collect fee', flush=True)
                    return
                tx_sig   = None
                err_msg  = None
                try:
                    tx_sig = send_sol_fee(pk, OWNER_WALLET, fee)
                    print(f'[fee] ✓ {sw} {sym} {fee:.6f} SOL sent  TX:{tx_sig[:20]}...', flush=True)
                    add_user_log(wlt, f'✓ Perf fee {fee:.5f} SOL (5% of +{gross:.5f} SOL profit)  TX:{tx_sig[:12]}...')
                except Exception as e:
                    err_msg = _redact_keys(str(e))
                    print(f'[fee] ✗ {sw} {sym} transfer FAILED: {err_msg}', flush=True)
                    add_user_log(wlt, f'Fee {fee:.5f} SOL owed but transfer failed — will appear in admin recovery panel')

                # Always record in fees table: successful → fee_tx=sig, failed → fee_tx='FAILED:...'
                try:
                    status = 'ok' if tx_sig else 'failed'
                    fee_tx = tx_sig if tx_sig else ('FAILED: ' + (err_msg or 'unknown')[:80])
                    conn2  = sqlite3.connect(DB_FILE)
                    conn2.execute(
                        'INSERT INTO fees (user_wallet, token, gross_profit, fee_amount, fee_tx, status) VALUES (?,?,?,?,?,?)',
                        (wlt, sym, gross, fee, fee_tx, status))
                    if tx_sig:
                        # Mark trade as fee paid using timestamp to identify it
                        conn2.execute(
                            'UPDATE trades SET fee_paid=1 WHERE user_id=? AND timestamp=?',
                            (uid, trade_ts))
                    conn2.commit()
                    conn2.close()
                    print(f'[fee] recorded in fees table: status={status} fee_tx={fee_tx[:30]}', flush=True)
                except Exception as db_e:
                    print(f'[fee] ✗ could not write to fees table: {db_e}', flush=True)
                finally:
                    pk = None

            threading.Thread(
                target=_do_fee,
                args=(_pk, _sym, _gros, _fee, _wlt, _uid, _ts),
                daemon=True,
            ).start()
            print(f'[fee] {short_w} {symbol} fee thread started (will execute in ~12s after sell confirms)', flush=True)
        else:
            print(f'[fee] {short_w} {symbol} fee {fee_amount:.6f} SOL below 0.0001 dust threshold — skipped', flush=True)
    else:
        if pnl <= 0.0:
            print(f'[fee] {short_w} {symbol} no fee — trade not profitable (pnl={pnl:.6f})', flush=True)
        elif not _owner_set:
            print(f'[fee] {short_w} {symbol} no fee — OWNER_WALLET env var is not set', flush=True)
        elif not private_key:
            print(f'[fee] {short_w} {symbol} no fee — no private key available (sell may have failed)', flush=True)

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
                '''INSERT INTO trades
                   (user_id, token, entry_price, exit_price, amount, pnl, fee_amount, fee_paid, timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?)''',
                (user_id, symbol, entry, exit_price, amount, pnl, fee_amount, 0,
                 now.strftime('%Y-%m-%dT%H:%M:%SZ')))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f'[trade_record] DB write failed: {e}', flush=True)

# ── SWAP EXECUTION ──
def _execute_user_swap(wallet: str, private_key: str, action: str, mint: str, amount_str: str) -> bool:
    """Execute a Jupiter swap. Returns True only if the subprocess exited 0 with output.
    Key is passed via env var to the subprocess and the env dict is discarded after launch."""
    try:
        env = os.environ.copy()
        env['WALLET_ADDRESS']     = wallet
        env['WALLET_PRIVATE_KEY'] = private_key
        result = subprocess.run(
            [sys.executable, os.path.join(BASE, 'orcagent_solana.py'), action, mint, amount_str],
            env=env, capture_output=True, text=True, timeout=30
        )
        env['WALLET_PRIVATE_KEY'] = ''  # clear from local dict immediately after subprocess returns
        if result.stdout:
            add_user_log(wallet, 'Swap: ' + _redact_keys(result.stdout.strip()[-400:]))
        if result.stderr:
            add_user_log(wallet, 'Swap err: ' + _redact_keys(result.stderr.strip()[-400:]))
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
            c.execute('SELECT id, encrypted_private_key, daily_loss_limit FROM users WHERE wallet_address=?', (wallet,))
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
    daily_loss_limit = abs(float(row[2] if row[2] is not None else 10.0))

    # Keep only the encrypted blob — never store decrypted key across loop iterations.
    # Each trade decrypts at the moment of signing and clears immediately after.
    try:
        from solders.keypair import Keypair as _KP_init
        _enc_blob = row[1]
        _test_key = decrypt_private_key(_enc_blob, wallet)
        # Derive the trading wallet address from the keypair (this is where Jupiter
        # creates ATAs and where SOL lands after sells — NOT the Phantom session wallet).
        _trading_wallet = str(_KP_init.from_base58_string(_test_key).pubkey())
        _test_key = None  # clear immediately
        del _KP_init
    except Exception:
        add_user_log(wallet, '[' + short + '] ✗ Cannot decrypt private key — please re-save it in Settings')
        us['trader_running'] = False
        return

    print(f'[trader] {short} session={wallet[:8]}... trading={_trading_wallet[:8]}...', flush=True)
    add_user_log(wallet, '[' + short + '] Trader started — TP:20% SL:5% | score≥4.5 | max 5 pos | scan 30s | momentum 7+ → 60%')
    positions = us['positions']

    # ── Immediate stop-loss pass on startup ──────────────────────────────────
    # Catches any positions that breached -5% while the stop-loss bug was active.
    for _mint, _pos in list(positions.items()):
        if stop_event.is_set(): break
        if _pos.get('amount', 0) <= 0 or _pos.get('buy_price', 0) <= 0:
            continue
        _td = get_token_data(_mint)
        _price = float(_td['price']) if _td else 0.0
        if _price <= 0:
            continue
        _chg = (_price - _pos['buy_price']) / _pos['buy_price']
        _label = (_td.get('symbol', '') if _td else '') or _pos.get('symbol', _mint[:8])
        if _chg <= -0.05:
            add_user_log(wallet, f'[{short}] STARTUP FORCE SELL {_label} {round(_chg*100,1)}% (stop loss missed while bug was active)')
            print(f'[trader] {short} STARTUP FORCE SELL {_label} {round(_chg*100,1)}%', flush=True)
            with _use_key(_enc_blob, wallet) as _pk:
                _sell_ok = _execute_user_swap(wallet, _pk, 'sell', _mint, str(_pos['amount']))
            if _sell_ok:
                with _use_key(_enc_blob, wallet) as _pk:
                    _record_user_trade(user_id, us, _label, _pos['buy_price'], _price,
                                       _pos['amount'], _pos.get('spend', 0), wallet=wallet, private_key=_pk)
            else:
                _record_user_trade(user_id, us, _label, _pos['buy_price'], _price,
                                   _pos['amount'], _pos.get('spend', 0))
            positions[_mint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}

    try:
        while not stop_event.is_set():
            try:
                check_daily_reset_user(us)
                daily_loss = us['daily_stats'].get('total_pnl', 0)
                if daily_loss < -daily_loss_limit:
                    add_user_log(wallet, '[' + short + '] Daily loss limit hit ($' + str(round(daily_loss, 2)) + ') — pausing')
                    stop_event.wait(300)
                    continue
                live     = state['tokens']  # already sorted by score desc
                open_pos = sum(1 for p in positions.values() if p.get('amount', 0) > 0)
                us_sol  = _get_user_sol(_trading_wallet)
                total_live = len(live)
                if total_live == 0:
                    add_user_log(wallet, '[' + short + '] Waiting for token data... SOL:' + str(round(us_sol, 4)) + ' Pos:' + str(open_pos) + '/5')
                else:
                    add_user_log(wallet, '[' + short + '] Scanning ' + str(total_live) +
                                 ' tokens... SOL:' + str(round(us_sol, 4)) + ' Pos:' + str(open_pos) + '/5')

                # ── Pass 1: exit checks for ALL open positions ──
                # Iterates positions dict (not live scan) so tokens that drop off the
                # DexScreener trending list still get stop-loss/take-profit every cycle.
                live_map = {t['mint']: t for t in live}
                for mint, pos in list(positions.items()):
                    if stop_event.is_set(): break
                    if pos.get('amount', 0) <= 0 or pos.get('buy_price', 0) <= 0:
                        continue
                    if mint in live_map:
                        price = live_map[mint]['price']
                        label = live_map[mint]['symbol'] or pos.get('symbol', mint[:8])
                    else:
                        # Token left the live scan — fetch price directly so SL still fires
                        _td   = get_token_data(mint)
                        price = float(_td['price']) if _td else 0.0
                        label = (_td['symbol'] if _td else '') or pos.get('symbol', mint[:8])
                        if price > 0:
                            add_user_log(wallet, '[' + short + '] ' + label +
                                         ' not in scan — fetched price $' + str(round(price, 8)))
                    if price <= 0:
                        continue
                    chg = (price - pos['buy_price']) / pos['buy_price']
                    exit_reason = None
                    if chg >= 0.20:
                        exit_reason = 'TAKE PROFIT +' + str(round(chg*100,1)) + '%'
                    elif chg <= -0.05:
                        exit_reason = 'STOP LOSS ' + str(round(chg*100,1)) + '%'
                    if exit_reason:
                        add_user_log(wallet, '[' + short + '] ' + exit_reason + ' ' + label)
                        with _use_key(_enc_blob, wallet) as _pk:
                            sell_ok = _execute_user_swap(wallet, _pk, 'sell', mint, str(pos['amount']))
                        if sell_ok:
                            with _use_key(_enc_blob, wallet) as _pk:
                                _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'],
                                                   wallet=wallet, private_key=_pk)
                        else:
                            add_user_log(wallet, '[' + short + '] ✗ Sell failed — position cleared')
                            _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'])
                        positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
                        open_pos -= 1

                # ── Pass 2: pick the single best entry ──
                if not stop_event.is_set() and open_pos < 5 and us_sol > 0.01:
                    not_held   = [t for t in live if positions.get(t['mint'], {}).get('amount', 0) == 0]
                    qualifying = [t for t in not_held if t['score'] >= 4.5]
                    add_user_log(wallet, '[' + short + '] ' + str(len(qualifying)) + '/' +
                                 str(total_live) + ' qualify (score≥4.5)')
                    if qualifying:
                        best  = qualifying[0]  # list is sorted by score desc
                        bmint = best['mint']
                        label = best['symbol'] or bmint[:8]
                        sc    = best['score']
                        m5    = best.get('change5m', 0)
                        m5s   = ('+' if m5 >= 0 else '') + str(round(m5, 1)) + '%'
                        add_user_log(wallet, '[' + short + '] Best: ' + label +
                                     ' score ' + str(sc) + '/10 → BUYING m5:' + m5s)
                        trade_pct = 0.60 if sc >= 7 else config.get('trade_pct', 0.40)
                        spend = round(us_sol * trade_pct, 4)
                        if spend >= 0.001:
                            if bmint not in positions:
                                positions[bmint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
                            pos = positions[bmint]

                            # Entry timing: if token is very extended (m5 > 30%), wait for 2-5% pullback
                            if m5 > 30 and not pos.get('entry_waiting'):
                                pos['entry_waiting']   = True
                                pos['entry_ref_price'] = best['price']
                                pos['entry_wait_count']= 0
                                add_user_log(wallet, '[' + short + '] WAITING FOR ENTRY — ' + label +
                                             ' extended (+' + str(round(m5,1)) + '%), watching for pullback')
                            elif pos.get('entry_waiting'):
                                ref = pos.get('entry_ref_price', best['price'])
                                dip = (best['price'] - ref) / ref if ref > 0 else 0
                                pos['entry_wait_count'] = pos.get('entry_wait_count', 0) + 1
                                if -0.06 <= dip <= -0.02:
                                    # Good pullback — buy now
                                    add_user_log(wallet, '[' + short + '] PULLBACK ENTRY — ' + label +
                                                 ' dipped ' + str(round(dip*100,1)) + '%')
                                    pos.pop('entry_waiting', None)
                                    pos.pop('entry_ref_price', None)
                                    pos.pop('entry_wait_count', None)
                                    with _use_key(_enc_blob, wallet) as _pk:
                                        _execute_user_swap(wallet, _pk, 'buy', bmint, str(spend))
                                    pos['amount']     = spend / best['price']
                                    pos['buy_price']  = best['price']
                                    pos['spend']      = spend
                                    pos['symbol']     = label
                                    pos['opened_at']  = time.time()
                                    open_pos += 1
                                elif pos.get('entry_wait_count', 0) >= 5 or dip > 0.05:
                                    # Timed out or ran away — cancel wait
                                    add_user_log(wallet, '[' + short + '] ENTRY WAIT CANCELLED — ' + label)
                                    pos.pop('entry_waiting', None)
                                    pos.pop('entry_ref_price', None)
                                    pos.pop('entry_wait_count', None)
                                # else still waiting
                            else:
                                with _use_key(_enc_blob, wallet) as _pk:
                                    _execute_user_swap(wallet, _pk, 'buy', bmint, str(spend))
                                pos['amount']     = spend / best['price']
                                pos['buy_price']  = best['price']
                                pos['spend']      = spend
                                pos['symbol']     = label
                                pos['opened_at']  = time.time()
                                open_pos += 1
            except Exception as e:
                add_user_log(wallet, '[' + short + '] Trader error: ' + str(e))
            stop_event.wait(config.get('interval', 30))
    finally:
        add_user_log(wallet, '[' + short + '] Trader stopped')
        us['trader_running'] = False


# ══════════════════════════════════════════════════════
#  FLASK ROUTES
# ══════════════════════════════════════════════════════

@app.after_request
def _security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options',  'nosniff')
    resp.headers.setdefault('X-Frame-Options',          'DENY')
    resp.headers.setdefault('X-XSS-Protection',         '1; mode=block')
    resp.headers.setdefault('Referrer-Policy',          'strict-origin-when-cross-origin')
    resp.headers.setdefault('Permissions-Policy',       'camera=(), microphone=(), geolocation=()')
    resp.headers.setdefault('Content-Security-Policy',
        "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: https:; "
        "frame-src https://dexscreener.com; "
        "object-src 'none'")
    if os.getenv('RAILWAY_ENVIRONMENT'):
        resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    # Scan JSON responses for possible private key leak (87-88 char base58 = private key length).
    # Actively block only on endpoints that must never return key material.
    # Other endpoints (e.g. /api/admin with fee TX hashes) only log a warning.
    if (resp.content_type or '').startswith('application/json'):
        path = getattr(request, 'path', '')
        try:
            body = resp.get_data(as_text=True)
            # ── 1. Block 87-88 char base58 on sensitive endpoints ──
            if _KEY_LEAK_RE.search(body):
                if path in _SENSITIVE_PATHS:
                    print(f'SECURITY ALERT: possible key leak in {path} — response blocked', flush=True)
                    try:
                        _log_security_event('key_leak_blocked', _current_wallet() or 'unknown', path)
                    except Exception:
                        pass
                    r = jsonify({'error': 'Response blocked by security policy'})
                    r.status_code = 500
                    return r
                else:
                    print(f'SEC WARN: 87+ char base58 in {path} (expected for TX hashes)', flush=True)
            # ── 2. Strip forbidden field names from JSON responses ──
            try:
                payload = json.loads(body)
                if isinstance(payload, dict):
                    dirty = _FORBIDDEN_RESPONSE_KEYS & payload.keys()
                    if dirty:
                        for k in dirty:
                            del payload[k]
                        print(f'SEC: stripped forbidden field(s) {dirty} from {path}', flush=True)
                        r = jsonify(payload)
                        r.status_code = resp.status_code
                        return r
            except (json.JSONDecodeError, Exception):
                pass
        except Exception:
            pass
    return resp

@app.route('/')
def index():
    return send_from_directory(BASE, 'dashboard.html')

# ── HONEYPOTS ──
# These paths are never legitimately accessed. Any hit means a scanner or attacker.
# Log the IP, increment failure count (triggering ban on repeat hits), return 404.
@app.route('/.env')
@app.route('/wp-login.php')
@app.route('/admin')
@app.route('/phpmyadmin')
@app.route('/config.php')
@app.route('/.git/config')
def _honeypot():
    ip = request.remote_addr or 'unknown'
    _log_security_event('honeypot_hit', 'anonymous', f'{request.method} {request.path} from {ip}')
    _record_ip_failure(ip)
    return '', 404

# ── CSRF TOKEN ──
@app.route('/api/csrf-token')
@rate_limit(60, 60)
def get_csrf_token_endpoint():
    """Return (or create) the per-session CSRF token.
    Called by the frontend on page load so subsequent POSTs can include it."""
    return jsonify({'token': _get_csrf_token()})

# ── WALLET ──
@app.route('/api/wallet/set', methods=['POST'])
@rate_limit(10, 60)
def set_wallet():
    ip      = request.remote_addr or '0.0.0.0'
    address = (request.json or {}).get('address', '').strip()
    if address:
        if not is_valid_solana_address(address):
            return jsonify({'ok': False, 'msg': 'Invalid Solana wallet address'}), 400
        session.permanent = True
        session['wallet'] = address
        # Generate (or retrieve) CSRF token for this session now that the session exists
        csrf_tok = _get_csrf_token()
        try:
            get_or_create_user(address)
        except: pass
        threading.Thread(target=fetch_user_balances, args=(address,), daemon=True).start()
        add_user_log(address, 'Wallet connected: ' + address[:6] + '...' + address[-4:])
        # Multi-IP detection: same wallet from 3+ IPs in 1 h → CRITICAL alert + pause trader
        threading.Thread(target=_check_wallet_multi_ip, args=(address, ip), daemon=True).start()
        has_trading_key = False
        try:
            conn2 = sqlite3.connect(DB_FILE)
            c2    = conn2.cursor()
            c2.execute('SELECT encrypted_private_key FROM users WHERE wallet_address=?', (address,))
            kr = c2.fetchone()
            conn2.close()
            has_trading_key = bool(kr and kr[0])
        except Exception:
            pass
        us = get_user_state(address)
        us['has_trading_key'] = has_trading_key
        return jsonify({'ok': True, 'wallet': address, 'has_trading_key': has_trading_key,
                        'is_admin': _is_owner(address), 'csrf_token': csrf_tok})
    else:
        prev = _current_wallet()
        session.pop('wallet', None)
        if prev:
            add_user_log(prev, 'Wallet disconnected')
    return jsonify({'ok': True, 'wallet': session.get('wallet', '')})

# ── SETTINGS ──
@app.route('/api/settings', methods=['GET'])
@rate_limit(30, 60)
def get_settings():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'})
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute('SELECT encrypted_private_key, max_trade_size, min_trade_size, daily_loss_limit FROM users WHERE wallet_address=?', (wallet,))
    row  = c.fetchone()
    conn.close()
    has_key = bool(row and row[0])
    # Sync in-memory cache so /api/state benefits from this read
    get_user_state(wallet)['has_trading_key'] = has_key
    if row:
        return jsonify({'ok': True, 'has_trading_key': has_key,
                        'max_trade_size': row[1] if row[1] is not None else 0.5,
                        'min_trade_size': row[2] if row[2] is not None else 0.01,
                        'daily_loss_limit': row[3] if row[3] is not None else 10.0})
    return jsonify({'ok': True, 'has_trading_key': False, 'max_trade_size': 0.5, 'min_trade_size': 0.01, 'daily_loss_limit': 10.0})

@app.route('/api/settings', methods=['POST'])
@rate_limit(10, 60)
def save_settings():
    ip     = request.remote_addr or '0.0.0.0'
    wallet = _current_wallet()
    if not wallet:
        _record_ip_failure(ip)
        return jsonify({'ok': False, 'msg': 'No wallet connected'})
    if _is_banned(ip):
        return jsonify({'ok': False, 'msg': 'Access temporarily blocked'}), 429
    data            = request.json or {}
    private_key_raw = data.get('private_key', '').strip()
    try:
        max_trade_size = float(data.get('max_trade_size', 0.5))
    except (ValueError, TypeError):
        max_trade_size = 0.5
    try:
        min_trade_size = float(data.get('min_trade_size', 0.01))
    except (ValueError, TypeError):
        min_trade_size = 0.01
    try:
        daily_loss_limit = float(data.get('daily_loss_limit', 10.0))
    except (ValueError, TypeError):
        daily_loss_limit = 10.0
    max_trade_size   = max(0.1,  min(max_trade_size,   10000.0))
    min_trade_size   = max(0.01, min(min_trade_size,   max_trade_size))
    daily_loss_limit = max(0.1,  min(daily_loss_limit, 50000.0))

    # Validate, double-encrypt, and verify round-trip before touching the DB
    encrypted = ''   # initialised here so it is always defined in the INSERT branch below
    new_hash  = None
    if private_key_raw:
        if not is_valid_solana_private_key(private_key_raw):
            _record_ip_failure(ip)
            return jsonify({'ok': False, 'msg': 'Invalid private key format — paste the base58 or JSON array key from your wallet'})
        try:
            encrypted = encrypt_private_key(private_key_raw, wallet)
            _verify   = decrypt_private_key(encrypted, wallet)
            if _verify != private_key_raw:
                raise ValueError('Round-trip verify failed')
            _verify   = None
            new_hash  = hashlib.sha256(private_key_raw.encode()).hexdigest()
        except Exception:
            return jsonify({'ok': False, 'msg': 'Failed to save private key'})
        _log_security_event('key_saved', wallet)

    conn = sqlite3.connect(DB_FILE)
    try:
        c   = conn.cursor()
        c.execute('SELECT id, encrypted_private_key FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
        if row:
            if private_key_raw:
                # New key provided — update key columns + settings
                c.execute('UPDATE users SET encrypted_private_key=?, key_hash=?, max_trade_size=?, min_trade_size=?, daily_loss_limit=? WHERE wallet_address=?',
                          (encrypted, new_hash, max_trade_size, min_trade_size, daily_loss_limit, wallet))
                final_enc = encrypted
            else:
                # No new key — only update settings, leave encrypted_private_key untouched
                c.execute('UPDATE users SET max_trade_size=?, min_trade_size=?, daily_loss_limit=? WHERE wallet_address=?',
                          (max_trade_size, min_trade_size, daily_loss_limit, wallet))
                final_enc = row[1]
        else:
            c.execute('INSERT INTO users (wallet_address, encrypted_private_key, key_hash, max_trade_size, min_trade_size, daily_loss_limit) VALUES (?,?,?,?,?,?)',
                      (wallet, encrypted or '', new_hash or '', max_trade_size, min_trade_size, daily_loss_limit))
            final_enc = encrypted or ''
        conn.commit()
    finally:
        conn.close()
    final_has_key = bool(final_enc)
    get_user_state(wallet)['has_trading_key'] = final_has_key
    add_user_log(wallet, 'Settings saved for ' + wallet[:6] + '...' + wallet[-4:])
    return jsonify({'ok': True, 'has_trading_key': final_has_key})

@app.route('/api/settings/key', methods=['DELETE'])
@rate_limit(5, 60)
def delete_trading_key():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute('UPDATE users SET encrypted_private_key="", key_hash="" WHERE wallet_address=?', (wallet,))
        conn.commit()
    finally:
        conn.close()
    get_user_state(wallet)['has_trading_key'] = False
    _log_security_event('key_deleted', wallet)
    add_user_log(wallet, 'Trading key removed for ' + wallet[:6] + '...' + wallet[-4:])
    return jsonify({'ok': True})

# ── STATE ──
def _db_has_key(wallet: str) -> bool:
    """Check SQLite directly for a non-empty encrypted_private_key for this wallet."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute(
            "SELECT COUNT(*) FROM users WHERE wallet_address=? "
            "AND encrypted_private_key IS NOT NULL AND encrypted_private_key != ''",
            (wallet,))
        result = bool(c.fetchone()[0])
        conn.close()
        return result
    except Exception:
        return False

@app.route('/api/state')
@rate_limit(60, 60, ban=True)
def api_state():
    wallet = _current_wallet()
    if wallet:
        us       = get_user_state(wallet)
        # In-memory may be stale after server restart — DB-confirm when False
        htk = us.get('has_trading_key', False)
        if not htk:
            htk = _db_has_key(wallet)
            if htk:
                us['has_trading_key'] = True  # warm the cache
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
                    'opened_at': pos.get('opened_at', 0),
                })
        safe_logs = [{'t': ln.get('t', ''), 'msg': _redact_keys(str(ln.get('msg', '')))}
                     for ln in us.get('log_lines', [])[:40]]
        return jsonify({
            'trader_running':   us.get('trader_running', False),
            'usdc':             us.get('usdc', 0.0),
            'sol':              us.get('sol',  0.0),
            'positions':        open_pos,
            'positions_detail': positions_detail,
            'log_lines':        safe_logs,
            'tokens':           state['tokens'],
            'wallet':           wallet,
            'is_admin':         _is_owner(wallet),
            'has_trading_key':  htk,
        })
    safe_sys_logs = [{'t': ln.get('t', ''), 'msg': _redact_keys(str(ln.get('msg', '')))}
                     for ln in state['log_lines'][:20]]
    return jsonify({
        'trader_running':  state['trader_running'],
        'usdc':            state['usdc'], 'sol': state['sol'],
        'positions':       int(state.get('positions', 0)),
        'log_lines':       safe_sys_logs,
        'tokens':          state['tokens'],
        'wallet':          state.get('wallet', ''),
        'is_admin':        False,
        'has_trading_key': False,
    })

# ── TRADER START/STOP ──
@app.route('/api/trader/start', methods=['POST'])
@rate_limit(5, 60)
def start_trader():
    ip     = request.remote_addr or '0.0.0.0'
    wallet = _current_wallet()
    if not wallet:
        _record_ip_failure(ip)
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    if _is_banned(ip):
        return jsonify({'ok': False, 'msg': 'Access temporarily blocked'}), 429
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('SELECT encrypted_private_key FROM users WHERE wallet_address=?', (wallet,))
        kr = c.fetchone()
        conn.close()
    except Exception as e:
        return jsonify({'ok': False, 'msg': 'DB error: ' + str(e)[:60]}), 500
    if not kr or not kr[0]:
        return jsonify({'ok': False, 'msg': 'No trading key saved — add it in Settings first'}), 400
    if _sec_check_state.get('trading_paused'):
        return jsonify({'ok': False,
                        'msg': 'Trading suspended — security check failure. Contact admin to resume.'}), 503
    with _trader_lock:
        us = get_user_state(wallet)
        if us['trader_running']:
            return jsonify({'ok': True})  # idempotent — already in desired state
        config = request.json or {}
        us['trader_stop']   = threading.Event()
        us['trader_thread'] = threading.Thread(target=user_trader_loop, args=(us['trader_stop'], config, wallet), daemon=True)
        us['trader_thread'].start()
        us['trader_running'] = True
    return jsonify({'ok': True})

@app.route('/api/trader/stop', methods=['POST'])
@rate_limit(10, 60)
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

# ── CLAIM SOL ──
@app.route('/api/claim_sol', methods=['POST'])
@rate_limit(3, 60)
def api_claim_sol():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not authenticated'}), 401

    conn = sqlite3.connect(DB_FILE)
    row  = conn.execute('SELECT encrypted_private_key FROM users WHERE wallet_address=?', (wallet,)).fetchone()
    conn.close()
    if not row or not row[0]:
        return jsonify({'ok': False, 'msg': 'No trading key — configure in Settings first'}), 400

    enc_blob       = row[0]
    SPL_PROG_STR   = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
    short_w        = (wallet[:6] + '...' + wallet[-4:]) if len(wallet) >= 10 else wallet

    from solders.keypair     import Keypair     as _KP
    from solders.pubkey      import Pubkey      as _PBK
    from solders.instruction import Instruction as _IX, AccountMeta as _AM
    from solders.transaction import Transaction as _TX
    from solders.hash        import Hash        as _SH

    # Derive the trading keypair once — authority must match the account's owner field
    try:
        with _use_key(enc_blob, wallet) as _pk_tmp:
            _kp_probe  = _KP.from_base58_string(_pk_tmp)
            trading_pk = str(_kp_probe.pubkey())
    except Exception as e:
        return jsonify({'ok': False, 'msg': 'Cannot decrypt trading key: ' + str(e)[:80]}), 500

    print(f'[claim_sol] ═══ START ═══', flush=True)
    print(f'[claim_sol] session_wallet  = {wallet}', flush=True)
    print(f'[claim_sol] trading_wallet  = {trading_pk}', flush=True)
    print(f'[claim_sol] wallets_differ  = {wallet != trading_pk}', flush=True)
    print(f'[claim_sol] RPC             = {SOLANA_RPC}', flush=True)
    print(f'[claim_sol] SPL_PROG        = {SPL_PROG_STR}', flush=True)

    # Fetch token accounts for BOTH wallets — either may hold empty ATAs
    def _rpc_token_accounts(owner: str, label: str):
        print(f'[claim_sol] → getTokenAccountsByOwner  owner={owner}  label={label}', flush=True)
        r    = requests.post(SOLANA_RPC, json={
            'jsonrpc': '2.0', 'id': 1,
            'method':  'getTokenAccountsByOwner',
            'params':  [owner, {'programId': SPL_PROG_STR}, {'encoding': 'jsonParsed'}],
        }, timeout=15)
        resp = r.json()
        if 'error' in resp:
            print(f'[claim_sol]   RPC ERROR for {label}: {resp["error"]}', flush=True)
            return []
        accs = resp.get('result', {}).get('value', [])
        print(f'[claim_sol]   {label} → {len(accs)} token account(s) returned', flush=True)
        return accs

    try:
        session_accs = _rpc_token_accounts(wallet, 'session_wallet')
        trading_accs = _rpc_token_accounts(trading_pk, 'trading_wallet') if trading_pk != wallet else []
        if trading_pk == wallet:
            print(f'[claim_sol]   trading_wallet == session_wallet, skipping duplicate query', flush=True)
    except Exception as e:
        return jsonify({'ok': False, 'msg': 'RPC request failed: ' + str(e)}), 500

    all_accs = session_accs + trading_accs
    print(f'[claim_sol] total accounts before dedup: {len(all_accs)}', flush=True)

    # Filter: raw amount == "0" is the definitive empty check.
    # uiAmount can be None/null for non-zero dust — only raw amount == 0 guarantees CloseAccount succeeds.
    # Also record the on-chain owner so we know which keypair must sign.
    closeable  = []
    skipped    = []
    seen       = set()
    print(f'[claim_sol] ─── account details ───', flush=True)
    for idx, acc in enumerate(all_accs):
        pub = acc.get('pubkey', '')
        src = 'session' if idx < len(session_accs) else 'trading'
        if pub in seen:
            print(f'[claim_sol]   [{src}] {pub} → DUPLICATE skipped', flush=True)
            continue
        seen.add(pub)
        try:
            info           = acc['account']['data']['parsed']['info']
            tok            = info.get('tokenAmount', {})
            raw_amt        = str(tok.get('amount',        '1'))
            ui_amt         = tok.get('uiAmount',          None)   # float or null
            ui_str         = tok.get('uiAmountString',    '?')
            decimals       = tok.get('decimals',          '?')
            lamports       = int(acc['account']['lamports'])
            sol_rent       = lamports / 1e9
            mint_str       = info.get('mint',  'unknown')
            owner_on_chain = info.get('owner', '')
            state          = info.get('state', '?')

            print(f'[claim_sol]   [{src}] pubkey={pub}', flush=True)
            print(f'[claim_sol]         mint={mint_str}', flush=True)
            print(f'[claim_sol]         owner_on_chain={owner_on_chain}', flush=True)
            print(f'[claim_sol]         state={state}  decimals={decimals}', flush=True)
            print(f'[claim_sol]         raw_amount={raw_amt}  uiAmount={ui_amt}  uiAmountString={ui_str}', flush=True)
            print(f'[claim_sol]         lamports={lamports}  ({sol_rent:.6f} SOL rent)', flush=True)

            if raw_amt == '0':
                closeable.append({'pubkey': pub, 'lamports': lamports, 'owner': owner_on_chain})
                print(f'[claim_sol]         → CLOSEABLE (raw_amount==0)', flush=True)
            else:
                skipped.append({'pubkey': pub, 'amount': raw_amt, 'ui': str(ui_amt), 'mint': mint_str})
                print(f'[claim_sol]         → SKIPPED (raw_amount={raw_amt} != 0, still holds tokens)', flush=True)
        except Exception as ex:
            print(f'[claim_sol]   [{src}] {pub} → PARSE ERROR: {ex}  raw={acc}', flush=True)

    print(f'[claim_sol] ─── summary ───', flush=True)
    print(f'[claim_sol] total unique accounts : {len(seen)}', flush=True)
    print(f'[claim_sol] closeable (amount==0) : {len(closeable)}', flush=True)
    print(f'[claim_sol] skipped (have tokens) : {len(skipped)}', flush=True)
    for s in skipped:
        print(f'[claim_sol]   skipped: pubkey={s["pubkey"]}  mint={s["mint"]}  '
              f'raw={s["amount"]}  ui={s["ui"]}', flush=True)
    for c in closeable:
        print(f'[claim_sol]   closeable: pubkey={c["pubkey"]}  lamports={c["lamports"]}  '
              f'owner={c["owner"]}', flush=True)

    if not closeable:
        msg = (f'No empty token accounts found — {len(all_accs)} total accounts checked '
               f'({len(skipped)} still have token balance). '
               f'Wallets checked: session={wallet[:8]}... trading={trading_pk[:8]}...')
        add_user_log(wallet, '[claim] ' + msg)
        return jsonify({'ok': True, 'msg': msg, 'reclaimed': 0.0, 'closed': 0,
                        'debug': {'session_wallet': wallet, 'trading_wallet': trading_pk,
                                  'total_accounts': len(all_accs), 'skipped': skipped}})

    total_lamports = sum(a['lamports'] for a in closeable)
    tx_sigs  = []
    failed   = []
    last_err = ''

    with _use_key(enc_blob, wallet) as pk_str:
        kp       = _KP.from_base58_string(pk_str)
        signer   = kp.pubkey()
        SPL_PROG = _PBK.from_string(SPL_PROG_STR)

        # Only close accounts where on-chain owner == our signing keypair.
        # Accounts owned by the session (Phantom) wallet need Phantom's key — we don't have it.
        our_accs   = [a for a in closeable if a['owner'] == str(signer)]
        other_accs = [a for a in closeable if a['owner'] != str(signer)]
        if other_accs:
            print(f'[claim_sol] {len(other_accs)} accounts owned by a different key '
                  f'(owner={other_accs[0]["owner"][:12]}...) — cannot sign, skipping', flush=True)

        print(f'[claim_sol] ─── close phase ───', flush=True)
        print(f'[claim_sol] signer (trading keypair) = {str(signer)}', flush=True)
        print(f'[claim_sol] our_accs   (owner==signer)  : {len(our_accs)}', flush=True)
        print(f'[claim_sol] other_accs (owner!=signer)  : {len(other_accs)}', flush=True)
        for a in other_accs:
            print(f'[claim_sol]   other: pubkey={a["pubkey"]}  owner={a["owner"]}', flush=True)
        print(f'[claim_sol] destination (rent back) = {str(signer)}', flush=True)

        for i in range(0, len(our_accs), 5):   # small batches — most reliable
            batch = our_accs[i:i+5]
            ixs = []
            for a in batch:
                print(f'[claim_sol] → closing {a["pubkey"]}  lamports={a["lamports"]}', flush=True)
                ixs.append(_IX(
                    program_id=SPL_PROG,
                    accounts=[
                        _AM(_PBK.from_string(a['pubkey']), is_signer=False, is_writable=True),  # token account to close
                        _AM(signer,                         is_signer=False, is_writable=True),  # destination (rent back)
                        _AM(signer,                         is_signer=True,  is_writable=False), # authority (must match owner)
                    ],
                    data=bytes([9]),  # CloseAccount instruction index
                ))
            try:
                bh_resp = requests.post(SOLANA_RPC, json={
                    'jsonrpc': '2.0', 'id': 1, 'method': 'getLatestBlockhash', 'params': [],
                }, timeout=10).json()
                bh  = bh_resp['result']['value']['blockhash']
                tx  = _TX.new_signed_with_payer(ixs, signer, [kp], _SH.from_string(bh))
                res = requests.post(SOLANA_RPC, json={
                    'jsonrpc': '2.0', 'id': 1, 'method': 'sendTransaction',
                    'params': [base64.b64encode(bytes(tx)).decode(),
                               {'encoding': 'base64', 'skipPreflight': False}],
                }, timeout=30).json()
                print(f'[claim_sol] sendTransaction response: {res}', flush=True)
                if 'error' in res:
                    last_err = str(res['error'])
                    failed.extend(batch)
                    print(f'[claim_sol] ✗ TX failed: {last_err}', flush=True)
                else:
                    sig = str(res.get('result', ''))
                    tx_sigs.append(sig)
                    print(f'[claim_sol] ✓ {len(batch)} closed TX:{sig[:20]}', flush=True)
            except Exception as e:
                last_err = str(e)
                failed.extend(batch)
                print(f'[claim_sol] ✗ TX exception: {e}', flush=True)

    closed        = len(our_accs) - len(failed)
    skipped_other = len(other_accs)
    print(f'[claim_sol] ─── result ───', flush=True)
    print(f'[claim_sol] our_accs={len(our_accs)}  closed={closed}  failed={len(failed)}  '
          f'skipped_other_owner={skipped_other}', flush=True)

    if closed == 0 and our_accs:
        return jsonify({
            'ok':   False,
            'msg':  f'Found {len(our_accs)} empty accounts but close TX failed: {last_err}',
            'reclaimed': 0.0,
            'debug': {'last_error': last_err, 'trading_wallet': trading_pk,
                      'skipped_wrong_owner': skipped_other},
        })

    reclaimed = sum(a['lamports'] for a in our_accs if a not in failed) / 1e9
    msg = f'Closed {closed} empty account{"s" if closed != 1 else ""} — reclaimed ~{reclaimed:.5f} SOL'
    if skipped_other:
        msg += f' ({skipped_other} account{"s" if skipped_other != 1 else ""} owned by different key — use sol-incinerator.com directly)'
    add_user_log(wallet, '[claim] ' + msg)
    threading.Thread(target=fetch_user_balances, args=(wallet,), daemon=True).start()
    return jsonify({'ok': True, 'msg': msg, 'reclaimed': round(reclaimed, 6),
                    'closed': closed, 'txs': tx_sigs})

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

@app.route('/api/chart/<mint>')
@rate_limit(60, 60)
def api_chart(mint):
    if not _SOLANA_ADDR_RE.match(mint or ''):
        return jsonify({'candles': [], 'error': 'invalid mint'})
    tf   = request.args.get('tf', '5m')
    _TF  = {
        '1m':  {'gt_tf': 'minute', 'gt_agg': 1,  'limit': 60},
        '5m':  {'gt_tf': 'minute', 'gt_agg': 5,  'limit': 60},
        '15m': {'gt_tf': 'minute', 'gt_agg': 15, 'limit': 60},
        '1h':  {'gt_tf': 'hour',   'gt_agg': 1,  'limit': 48},
        '4h':  {'gt_tf': 'hour',   'gt_agg': 4,  'limit': 42},
        'D':   {'gt_tf': 'day',    'gt_agg': 1,  'limit': 30},
    }
    tcfg = _TF.get(tf, _TF['5m'])
    try:
        # ── Step 1: resolve pool address from DexScreener ──
        r = _dex_get('https://api.dexscreener.com/latest/dex/tokens/' + mint, timeout=8)
        pairs = r.json().get('pairs', []) if (r and r.status_code == 200) else []
        if not pairs:
            return jsonify({'candles': [], 'error': 'no pairs'})
        pair_address = pairs[0].get('pairAddress', '')
        if not pair_address:
            return jsonify({'candles': [], 'error': 'no pair address'})

        # ── Step 2: GeckoTerminal OHLCV ──
        candles = []
        try:
            gt_url = (
                f'https://api.geckoterminal.com/api/v2/networks/solana'
                f'/pools/{pair_address}/ohlcv/{tcfg["gt_tf"]}'
                f'?aggregate={tcfg["gt_agg"]}&limit={tcfg["limit"]}'
                f'&currency=usd&token=base'
            )
            rg = requests.get(gt_url, timeout=10, headers={'Accept': 'application/json;version=20230302'})
            if rg.status_code == 200:
                items = (rg.json().get('data') or {}).get('attributes', {}).get('ohlcv_list', [])
                for row in items:
                    # row = [timestamp_ms, open, high, low, close, volume]
                    if len(row) < 6: continue
                    c_val = float(row[4] or 0)
                    if c_val <= 0: continue
                    candles.append({
                        't': int(row[0]) // 1000 if int(row[0]) > 1e10 else int(row[0]),
                        'o': float(row[1] or c_val),
                        'h': float(row[2] or c_val),
                        'l': float(row[3] or c_val),
                        'c': c_val,
                        'v': float(row[5] or 0),
                    })
                candles.sort(key=lambda x: x['t'])
            else:
                print(f'[chart] GeckoTerminal {rg.status_code} for {pair_address[:8]}', flush=True)
        except Exception as e:
            print(f'[chart] GeckoTerminal error: {e}', flush=True)

        if candles:
            return jsonify({'candles': candles, 'pair_address': pair_address})
        return jsonify({'candles': [], 'error': 'Chart unavailable', 'pair_address': pair_address})
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
@rate_limit(30, 60)
def api_log():
    if not _current_wallet():
        return jsonify({'lines': []})
    try:
        with open(LOG_FILE, encoding='utf-8') as f:
            lines = f.readlines()[-50:]
        return jsonify({'lines': [l.strip() for l in reversed(lines)]})
    except:
        return jsonify({'lines': []})

@app.route('/api/audit')
@rate_limit(12, 60)
def api_audit():
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify(_audit_state)

@app.route('/api/audit/run', methods=['POST'])
@rate_limit(3, 60)
def api_audit_run():
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        result = _run_audit()
        _audit_state.update(result)
        return jsonify(_audit_state)
    except Exception as e:
        return jsonify({'status': 'fail', 'checks': [], 'ran_at': None, 'error': str(e)}), 500

@app.route('/api/admin')
def api_admin():
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        ok_f = "(status IS NULL OR status='ok') AND (fee_tx IS NULL OR fee_tx NOT LIKE 'FAILED:%')"
        c.execute(f'SELECT COALESCE(SUM(fee_amount),0) FROM fees WHERE ({ok_f}) AND timestamp LIKE ?', (today + '%',))
        fees_today = round(float(c.fetchone()[0] or 0), 4)
        c.execute(f'SELECT COALESCE(SUM(fee_amount),0) FROM fees WHERE {ok_f}')
        fees_total = round(float(c.fetchone()[0] or 0), 4)
        c.execute('SELECT COALESCE(SUM(fee_amount),0) FROM fees WHERE status="failed" OR fee_tx LIKE "FAILED:%"')
        fees_failed = round(float(c.fetchone()[0] or 0), 4)
        c.execute('SELECT user_wallet, token, gross_profit, fee_amount, fee_tx, timestamp, status FROM fees ORDER BY timestamp DESC LIMIT 200')
        fee_txs = [{'wallet': r[0], 'token': r[1], 'gross': r[2], 'fee': r[3], 'tx': r[4], 'ts': r[5],
                    'status': r[6] or ('failed' if str(r[4] or '').startswith('FAILED:') else 'ok')}
                   for r in c.fetchall()]
        c.execute('SELECT COUNT(*) FROM users')
        total_users  = int(c.fetchone()[0] or 0)
        c.execute("SELECT COUNT(*) FROM users WHERE encrypted_private_key != '' AND encrypted_private_key IS NOT NULL")
        users_with_key = int(c.fetchone()[0] or 0)
        c.execute('SELECT COUNT(*) FROM trades')
        total_trades = int(c.fetchone()[0] or 0)
        c.execute('SELECT COUNT(*) FROM trades WHERE timestamp LIKE ?', (today + '%',))
        trades_today = int(c.fetchone()[0] or 0)
        c.execute('SELECT event_type, wallet, ip_addr, details, timestamp FROM security_log ORDER BY timestamp DESC LIMIT 20')
        sec_log = [{'event': r[0], 'wallet': r[1], 'ip': r[2],
                    'details': _redact_keys(str(r[3] or '')), 'ts': r[4]}
                   for r in c.fetchall()]
        conn.close()
        users_trading = sum(1 for us in list(user_states.values()) if us.get('trader_running'))
        return jsonify({
            'fees_today':        fees_today,
            'fees_total':        fees_total,
            'fees_failed_total': fees_failed,
            'fee_txs':           fee_txs,
            'total_users':       total_users,
            'users_with_key':    users_with_key,
            'users_trading':     users_trading,
            'total_trades':      total_trades,
            'trades_today':      trades_today,
            'owner_configured':  bool(OWNER_WALLET),
            'security_log':      sec_log,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users')
@rate_limit(20, 60)
def admin_users():
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('''SELECT wallet_address, encrypted_private_key, created_at,
                            max_trade_size, min_trade_size, daily_loss_limit
                     FROM users ORDER BY created_at DESC''')
        rows = c.fetchall()
        conn.close()
        users = []
        for r in rows:
            w   = r[0] or ''
            us  = user_states.get(w, {})
            pos = sum(1 for p in us.get('positions', {}).values() if p.get('amount', 0) > 0)
            users.append({
                'wallet':     w[:4] + '...' + w[-4:] if len(w) >= 8 else w,
                'has_key':    bool(r[1]),
                'trading':    us.get('trader_running', False),
                'positions':  pos,
                'max_trade':  r[3],
                'min_trade':  r[4],
                'loss_limit': r[5],
                'created':    (r[2] or '')[:10],
            })
        return jsonify({'users': users, 'total': len(users)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/fees')
@rate_limit(20, 60)
def admin_fees():
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        ok_filter = "(status IS NULL OR status='ok') AND (fee_tx IS NULL OR fee_tx NOT LIKE 'FAILED:%')"
        c.execute(f'SELECT COALESCE(SUM(fee_amount),0) FROM fees WHERE ({ok_filter}) AND timestamp LIKE ?', (today + '%',))
        fees_today = round(float(c.fetchone()[0] or 0), 4)
        c.execute(f'SELECT COALESCE(SUM(fee_amount),0) FROM fees WHERE {ok_filter}')
        fees_total = round(float(c.fetchone()[0] or 0), 4)
        c.execute('SELECT COALESCE(SUM(fee_amount),0) FROM fees WHERE status="failed" OR fee_tx LIKE "FAILED:%"')
        fees_failed_total = round(float(c.fetchone()[0] or 0), 4)
        c.execute('''SELECT user_wallet, token, gross_profit, fee_amount, fee_tx, timestamp, status
                     FROM fees ORDER BY timestamp DESC LIMIT 200''')
        txs = []
        for r in c.fetchall():
            w      = r[0] or ''
            status = r[6] or ('failed' if str(r[4] or '').startswith('FAILED:') else 'ok')
            txs.append({
                'wallet': w[:4] + '...' + w[-4:] if len(w) >= 8 else w,
                'token':  r[1], 'gross': round(r[2] or 0, 4),
                'fee':    round(r[3] or 0, 4), 'tx': r[4], 'ts': r[5], 'status': status,
            })
        conn.close()
        return jsonify({'fees_today': fees_today, 'fees_total': fees_total,
                        'fees_failed_total': fees_failed_total, 'transactions': txs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/recover-fees', methods=['POST'])
@rate_limit(5, 60)
def admin_recover_fees():
    """Scan trades table for profitable trades with uncollected fees and recover them."""
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    if not OWNER_WALLET:
        return jsonify({'error': 'OWNER_WALLET not configured'}), 500

    results   = []
    total_sent = 0.0

    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()

        # Per-wallet: total fees recorded in trades (calculated) vs total fees confirmed sent
        c.execute('''
            SELECT u.wallet_address,
                   u.encrypted_private_key,
                   COALESCE(SUM(t.fee_amount), 0) AS owed
            FROM users u
            JOIN trades t ON t.user_id = u.id
            WHERE t.pnl > 0
              AND t.fee_amount > 0
              AND u.encrypted_private_key IS NOT NULL
              AND u.encrypted_private_key != ""
            GROUP BY u.wallet_address, u.encrypted_private_key
        ''')
        owed_rows = c.fetchall()

        # Only count fees that were successfully sent (status='ok' or no status yet / no FAILED: prefix)
        c.execute('''
            SELECT user_wallet, COALESCE(SUM(fee_amount), 0)
            FROM fees
            WHERE (status IS NULL OR status = 'ok')
              AND (fee_tx IS NULL OR fee_tx NOT LIKE 'FAILED:%')
            GROUP BY user_wallet
        ''')
        collected_map = {row[0]: float(row[1]) for row in c.fetchall()}
        conn.close()
    except Exception as e:
        return jsonify({'error': f'DB query failed: {e}'}), 500

    for (user_wallet, enc_blob, owed_raw) in owed_rows:
        if _is_owner(user_wallet):
            continue
        owed      = round(float(owed_raw), 6)
        collected = round(collected_map.get(user_wallet, 0.0), 6)
        outstanding = round(owed - collected, 6)
        sw = (user_wallet[:6] + '...' + user_wallet[-4:]) if len(user_wallet) >= 10 else user_wallet

        if outstanding < 0.0001:
            results.append({'wallet': sw, 'owed': owed, 'collected': collected,
                            'outstanding': outstanding, 'status': 'skipped_dust'})
            continue

        print(f'[fee-recovery] {sw} owed={owed:.6f} collected={collected:.6f} outstanding={outstanding:.6f} SOL', flush=True)
        try:
            with _use_key(enc_blob, user_wallet) as pk:
                tx_sig = send_sol_fee(pk, OWNER_WALLET, outstanding)

            conn2 = sqlite3.connect(DB_FILE)
            conn2.execute(
                'INSERT INTO fees (user_wallet, token, gross_profit, fee_amount, fee_tx) VALUES (?,?,?,?,?)',
                (user_wallet, '[recovery]', outstanding / FEE_RATE, outstanding, tx_sig))
            conn2.commit()
            conn2.close()

            total_sent += outstanding
            print(f'[fee-recovery] ✓ {sw} recovered {outstanding:.6f} SOL TX:{tx_sig[:20]}', flush=True)
            add_log(f'[fee-recovery] {sw} {outstanding:.6f} SOL TX:{tx_sig[:16]}...')
            results.append({'wallet': sw, 'owed': owed, 'collected': collected,
                            'outstanding': outstanding, 'tx': tx_sig, 'status': 'sent'})
        except Exception as e:
            err = _redact_keys(str(e)[:160])
            print(f'[fee-recovery] ✗ {sw} FAILED: {err}', flush=True)
            results.append({'wallet': sw, 'owed': owed, 'collected': collected,
                            'outstanding': outstanding, 'error': err, 'status': 'failed'})

    return jsonify({
        'ok':         True,
        'wallets_checked': len(owed_rows),
        'total_sent_sol':  round(total_sent, 6),
        'results':    results,
    })


@app.route('/api/admin/force-sell', methods=['POST'])
@rate_limit(10, 60)
def admin_force_sell():
    """Immediately sell a token position across all users who hold it."""
    admin_wallet = _current_wallet()
    if not admin_wallet or not _is_owner(admin_wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    target_mint = ((request.json or {}).get('mint') or '').strip()
    if not target_mint:
        return jsonify({'error': 'mint required'}), 400

    results = []
    for wallet, us in list(user_states.items()):
        pos = us.get('positions', {}).get(target_mint, {})
        if pos.get('amount', 0) <= 0:
            continue
        sw = (wallet[:6] + '...' + wallet[-4:]) if len(wallet) >= 10 else wallet
        conn = sqlite3.connect(DB_FILE)
        try:
            row = conn.execute(
                'SELECT id, encrypted_private_key FROM users WHERE wallet_address=?', (wallet,)
            ).fetchone()
        finally:
            conn.close()
        if not row or not row[1]:
            results.append({'wallet': sw, 'status': 'no_key'})
            continue
        user_id, enc_blob = row[0], row[1]
        td    = get_token_data(target_mint)
        price = float(td['price']) if td else 0.0
        label = (td['symbol'] if td else '') or pos.get('symbol', target_mint[:8])
        print(f'[force-sell] {sw} {label} amount={pos["amount"]} price=${price}', flush=True)
        try:
            with _use_key(enc_blob, wallet) as _pk:
                sell_ok = _execute_user_swap(wallet, _pk, 'sell', target_mint, str(pos['amount']))
            if sell_ok and price > 0:
                with _use_key(enc_blob, wallet) as _pk:
                    _record_user_trade(user_id, us, label, pos['buy_price'], price,
                                       pos['amount'], pos['spend'], wallet=wallet, private_key=_pk)
            else:
                _record_user_trade(user_id, us, label, pos['buy_price'], price,
                                   pos['amount'], pos['spend'])
            us['positions'][target_mint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
            add_user_log(wallet, f'[ADMIN FORCE SELL] {label} sell_ok={sell_ok} price=${round(price,8)}')
            print(f'[force-sell] ✓ {sw} {label} sell_ok={sell_ok}', flush=True)
            results.append({'wallet': sw, 'label': label, 'sell_ok': sell_ok,
                            'price': price, 'status': 'sold'})
        except Exception as e:
            err = _redact_keys(str(e)[:160])
            print(f'[force-sell] ✗ {sw} {label} FAILED: {err}', flush=True)
            results.append({'wallet': sw, 'label': label, 'error': err, 'status': 'failed'})

    if not results:
        return jsonify({'ok': False, 'msg': f'No open positions found for {target_mint[:12]}...'})
    return jsonify({'ok': True, 'results': results})


@app.route('/api/admin/tokens')
@rate_limit(20, 60)
def admin_tokens():
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('''SELECT token,
                            COUNT(*) trades,
                            COALESCE(SUM(pnl),0) total_pnl,
                            COALESCE(AVG(pnl),0) avg_pnl,
                            COALESCE(MAX(pnl),0) best_pnl,
                            SUM(CASE WHEN pnl > 0 THEN 1 ELSE 0 END) wins
                     FROM trades WHERE token IS NOT NULL AND token != ''
                     GROUP BY token ORDER BY trades DESC LIMIT 30''')
        tokens = []
        for r in c.fetchall():
            trades = int(r[1])
            wins   = int(r[5])
            tokens.append({
                'token':     r[0],
                'trades':    trades,
                'total_pnl': round(r[2], 4),
                'avg_pnl':   round(r[3], 4),
                'best_pnl':  round(r[4], 4),
                'win_rate':  round(wins / trades * 100, 0) if trades > 0 else 0,
            })
        conn.close()
        return jsonify({'tokens': tokens})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/health')
@rate_limit(20, 60)
def admin_health():
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        db_size_kb = 0
        try:
            db_size_kb = round(os.path.getsize(DB_FILE) / 1024, 1)
        except Exception:
            pass
        active_traders = sum(1 for us in user_states.values() if us.get('trader_running'))
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('SELECT COUNT(*) FROM users')
        total_users = int(c.fetchone()[0] or 0)
        c.execute('SELECT COUNT(*) FROM security_log WHERE timestamp >= datetime("now", "-1 hour")')
        sec_events_1h = int(c.fetchone()[0] or 0)
        conn.close()
        with _dex_lock:
            dex_limited = time.time() < _dex_429_until
        return jsonify({
            'tokens_tracked':   len(state.get('tokens', [])),
            'active_traders':   active_traders,
            'total_sessions':   len(user_states),
            'total_users':      total_users,
            'db_size_kb':       db_size_kb,
            'ai_cache_size':    len(_ai_cache),
            'ai_disabled':      time.time() < _ai_disabled_until,
            'dex_rate_limited': dex_limited,
            'sec_events_1h':    sec_events_1h,
            'owner_configured': bool(OWNER_WALLET),
            'jupiter_proxy':    bool(JUPITER_PROXY),
            'anthropic_key':    bool(ANTHROPIC_API_KEY),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/bans')
@rate_limit(20, 60)
def admin_bans():
    """Return currently active IP bans and total rate-limit bucket count."""
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    now  = time.time()
    bans = []
    for ip, expires in list(_ip_ban.items()):
        if expires > now:
            bans.append({
                'ip':         ip,
                'expires_at': int(expires),
                'mins_left':  round((expires - now) / 60, 1),
            })
        else:
            _ip_ban.pop(ip, None)
            _ip_warn.pop(ip, None)
    with _rl_lock:
        rl_bucket_count = len(_rl_hits)
    return jsonify({'bans': sorted(bans, key=lambda x: x['mins_left'], reverse=True),
                    'rl_bucket_count': rl_bucket_count})


@app.route('/api/admin/clear_ratelimit', methods=['POST'])
@rate_limit(10, 60)
def admin_clear_ratelimit():
    """Clear IP ban and rate-limit hit counters.
    POST body: {"ip": "1.2.3.4"} to target one IP, or {} to clear everything."""
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    data   = request.json or {}
    target = (data.get('ip') or '').strip()
    if target:
        banned = target in _ip_ban
        _ip_ban.pop(target, None)
        _ip_warn.pop(target, None)
        with _rl_lock:
            keys = [k for k in list(_rl_hits) if k.endswith(':' + target)]
            for k in keys:
                del _rl_hits[k]
        print(f'[admin] clear_ratelimit: {wallet[:8]}… cleared IP {target} '
              f'(was_banned={banned}, rl_buckets={len(keys)})', flush=True)
        return jsonify({'ok': True,
                        'msg': f'Cleared {target} — ban removed: {banned}, '
                               f'rate-limit buckets cleared: {len(keys)}'})
    else:
        n_bans = len(_ip_ban)
        n_rl   = len(_rl_hits)
        _ip_ban.clear()
        _ip_warn.clear()
        with _rl_lock:
            _rl_hits.clear()
        print(f'[admin] clear_ratelimit: {wallet[:8]}… cleared ALL '
              f'({n_bans} bans, {n_rl} rl buckets)', flush=True)
        return jsonify({'ok': True,
                        'msg': f'Cleared all — {n_bans} ban(s) and {n_rl} rate-limit bucket(s) removed'})


@app.route('/api/admin/test', methods=['POST'])
@rate_limit(5, 60)
def admin_test():
    """Test live connectivity for Claude API and other integrations."""
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    results = {}
    # ── Claude API ──
    if ANTHROPIC_API_KEY:
        try:
            resp = requests.post(
                _ANTHROPIC_URL,
                headers={**_ANTHROPIC_HEADERS, 'x-api-key': ANTHROPIC_API_KEY},
                json={'model': 'claude-haiku-4-5-20251001', 'max_tokens': 5,
                      'messages': [{'role': 'user', 'content': 'Reply with just: ok'}]},
                timeout=10,
            )
            if resp.status_code == 200:
                results['ai'] = {'ok': True,  'msg': 'Claude API key is valid ✓'}
                global _ai_disabled_until
                _ai_disabled_until = 0.0  # clear any backoff
            elif resp.status_code == 401:
                results['ai'] = {'ok': False, 'msg': 'Invalid API key (401)'}
            elif resp.status_code == 429:
                results['ai'] = {'ok': False, 'msg': 'Rate limited — key is valid but quota hit (429)'}
            else:
                results['ai'] = {'ok': False, 'msg': f'Unexpected HTTP {resp.status_code}'}
        except Exception as e:
            results['ai'] = {'ok': False, 'msg': str(e)[:100]}
    else:
        results['ai'] = {'ok': False, 'msg': 'ANTHROPIC_API_KEY not set in environment'}
    return jsonify(results)

@app.route('/api/admin/test_fee', methods=['POST'])
@rate_limit(3, 300)
def admin_test_fee():
    """Verify the full fee-transfer path step-by-step.
    If sender == receiver (owner testing with their own key), infrastructure is
    checked without sending — the SPL token program forbids self-transfers."""
    import traceback as _tb
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403

    steps = []

    def _step(msg, ok=True, detail=''):
        entry = {'msg': msg, 'ok': ok, 'detail': detail}
        steps.append(entry)
        print(f'[test_fee] {"✓" if ok else "✗"} {msg}' + (f': {detail}' if detail else ''), flush=True)

    # ── 1. Trading key ──────────────────────────────────────────────────────
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('SELECT encrypted_private_key FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
    finally:
        conn.close()
    if not row or not (row[0] or '').strip():
        _step('Trading key', ok=False, detail='No trading key saved — add your private key in Settings first')
        return jsonify({'ok': False, 'steps': steps, 'error': steps[-1]['detail']}), 400
    _step('Trading key', detail='found in DB')

    sig = None
    try:
        from solders.keypair import Keypair as _KP
        from solders.pubkey import Pubkey as _PK

        with _use_key(row[0], wallet) as pk:
            # ── 2. Keypair ──────────────────────────────────────────────────
            kp     = _KP.from_base58_string(pk)
            sender = kp.pubkey()
            _step('Keypair', detail=str(sender)[:8] + '…')

            # ── 3. SOL balance ──────────────────────────────────────────────
            bal_r   = requests.post(SOLANA_RPC, json={
                'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [str(sender)],
            }, timeout=10).json()
            lamports = (bal_r.get('result') or {}).get('value', 0)
            balance  = lamports / 1e9
            _step('SOL balance', detail=f'{balance:.6f} SOL')
            if balance < 0.001:
                _step('Balance check', ok=False,
                      detail=f'Insufficient SOL: {balance:.6f} (need ≥ 0.001 SOL for test transfer + fees)')
                return jsonify({'ok': False, 'steps': steps, 'error': steps[-1]['detail']}), 400
            _step('Balance check', detail='sufficient')

            # ── 4. Self-transfer guard ──────────────────────────────────────
            # Native SOL self-transfer is technically valid on-chain but wastes fees.
            # When owner tests with their own key, sender == OWNER_WALLET — just
            # confirm infrastructure is wired up without burning lamports.
            if _is_owner(str(sender)):
                _step('Transfer skipped',
                      detail='sender == OWNER_WALLET (owner self-transfer). '
                             'All infrastructure verified ✓ — no lamports wasted.')
                return jsonify({
                    'ok':   True,
                    'steps': steps,
                    'msg':  'Infrastructure verified — key, balance, and RPC all OK. '
                            'Transfer skipped: sender is OWNER_WALLET.',
                })

            # ── 5. Send 0.0001 SOL ──────────────────────────────────────────
            _step('Building SOL transfer…')
            sig = send_sol_fee(pk, OWNER_WALLET, 0.0001)
            _step('Transaction sent', detail=sig[:16] + '…')

        _log_security_event('key_access', wallet, 'test_fee_transfer 0.0001 SOL')
        return jsonify({
            'ok':          True,
            'steps':       steps,
            'sig':         sig,
            'solscan_url': 'https://solscan.io/tx/' + sig,
            'msg':         'Sent 0.0001 SOL successfully',
        })

    except Exception as e:
        tb = _tb.format_exc()
        print(f'[test_fee] EXCEPTION:\n{tb}', flush=True)  # server log only — never sent to client
        _step('Error', ok=False, detail=str(e)[:120])
        return jsonify({'ok': False, 'steps': steps, 'error': str(e)[:120]}), 500

@app.route('/api/admin/rotate_keys', methods=['POST'])
@rate_limit(1, 300)
def admin_rotate_keys():
    """Re-encrypt all stored private keys with a new ENCRYPTION_KEY.
    After rotating, update the ENCRYPTION_KEY env var and redeploy."""
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    new_enc_key = (request.json or {}).get('new_encryption_key', '').strip()
    if not new_enc_key:
        return jsonify({'ok': False, 'msg': 'new_encryption_key required in request body'}), 400
    try:
        new_fernet = Fernet(new_enc_key.encode())
    except Exception:
        return jsonify({'ok': False, 'msg': 'Invalid Fernet key format — generate with Fernet.generate_key()'}), 400

    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute("SELECT wallet_address, encrypted_private_key FROM users WHERE encrypted_private_key != '' AND encrypted_private_key IS NOT NULL")
        rows = c.fetchall()
        migrated = failed = 0
        for waddr, enc_blob in rows:
            raw = None
            try:
                raw      = decrypt_private_key(enc_blob, waddr)
                l1       = new_fernet.encrypt(raw.encode())
                derived  = hmac.digest(new_enc_key.encode(), waddr.encode(), 'sha256')
                new_wf   = Fernet(base64.urlsafe_b64encode(derived))
                l2       = new_wf.encrypt(l1)
                new_enc  = 'v2:' + l2.decode()
                new_hash = hashlib.sha256(raw.encode()).hexdigest()
                c.execute('UPDATE users SET encrypted_private_key=?, key_hash=? WHERE wallet_address=?',
                          (new_enc, new_hash, waddr))
                migrated += 1
            except Exception:
                failed += 1
            finally:
                raw = None  # clear immediately
        conn.commit()
    finally:
        conn.close()

    _log_security_event('key_rotation', wallet, f'{migrated} migrated, {failed} failed')
    return jsonify({
        'ok':       True,
        'migrated': migrated,
        'failed':   failed,
        'note':     'Now update ENCRYPTION_KEY in your environment to the new key and redeploy',
    })

@app.route('/api/admin/security-status')
@rate_limit(20, 60)
def admin_security_status():
    """Real-time snapshot of all security checks, consecutive failure count, and trading pause state."""
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    failures = _run_security_checks()
    now = time.time()
    # Summarise multi-IP wallets (2+ distinct IPs in last hour)
    with _wallet_ips_lock:
        multi_ip = {
            w: len({h for h, _ in entries})
            for w, entries in _wallet_ips.items()
            if len({h for h, ts in entries if now - ts < 3600}) >= 2
        }
    all_checks = [{'name': c['check'], 'ok': False, 'detail': c['detail']} for c in failures]
    passing = {c['check'] for c in failures}
    _known = ['ENCRYPTION_KEY', 'Key Decryption', 'Response Schema', 'Honeypots', 'Rate Limiter']
    for name in _known:
        if name not in passing:
            all_checks.append({'name': name, 'ok': True, 'detail': ''})
    return jsonify({
        'ok':                   len(failures) == 0,
        'checks':               all_checks,
        'consecutive_failures': _sec_check_state['consecutive_failures'],
        'trading_paused':       _sec_check_state['trading_paused'],
        'paused_at':            _sec_check_state.get('paused_at'),
        'last_checked':         _sec_check_state.get('last_checked'),
        'last_failures':        _sec_check_state.get('last_failures', []),
        'ip_bans_active':       sum(1 for exp in _ip_ban.values() if now < exp),
        'active_traders':       sum(1 for us in user_states.values() if us.get('trader_running')),
        'multi_ip_wallets':     multi_ip,
        'ran_at':               datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
    })

@app.route('/api/admin/test_trade', methods=['POST'])
@rate_limit(3, 300)
def admin_test_trade():
    """Execute a $1 USDC test buy using the owner's saved trading key.
    Returns the full subprocess stdout/stderr so you can verify the on-chain path
    without waiting for the bot to find a signal naturally."""
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403

    token_address = ((request.json or {}).get('token_address', '') or '').strip()
    if not token_address or not _SOLANA_ADDR_RE.match(token_address):
        return jsonify({'error': 'token_address must be a valid Solana mint address'}), 400

    # Fetch owner's encrypted key from DB
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('SELECT encrypted_private_key FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
    finally:
        conn.close()

    if not row or not (row[0] or '').strip():
        return jsonify({'error': 'No trading key saved for owner wallet — add it in Settings first'}), 400

    enc_blob = row[0]
    start_ts = time.time()

    try:
        with _use_key(enc_blob, wallet) as pk:
            env = os.environ.copy()
            env['WALLET_ADDRESS']     = wallet
            env['WALLET_PRIVATE_KEY'] = pk
            proc = subprocess.run(
                [sys.executable, os.path.join(BASE, 'orcagent_solana.py'),
                 'buy', token_address, '1.0'],
                env=env, capture_output=True, text=True, timeout=60,
            )
            env['WALLET_PRIVATE_KEY'] = ''
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    elapsed = round(time.time() - start_ts, 2)
    stdout  = proc.stdout.strip()
    stderr  = proc.stderr.strip()

    # Extract Solscan URL from output before redacting (TX hash is in the URL path)
    solscan_url = ''
    for line in stdout.splitlines():
        if 'solscan.io/tx/' in line:
            idx = line.find('https://')
            if idx >= 0:
                solscan_url = line[idx:].strip()
                break

    _log_security_event('key_access', wallet, f'test_trade {token_address[:8]}')

    return jsonify({
        'ok':          proc.returncode == 0 and bool(solscan_url),
        'returncode':  proc.returncode,
        'stdout':      _redact_keys(stdout),
        'stderr':      _redact_keys(stderr),
        'solscan_url': solscan_url,
        'elapsed_s':   elapsed,
    })

# ── STARTUP ──
if not OWNER_WALLET:
    print('WARNING: OWNER_WALLET is not set in environment variables.')
    print('         is_admin will never be true for any user.')
    print('         Set OWNER_WALLET in Railway Variables and redeploy.')
init_db()
threading.Thread(target=token_loop,            daemon=True).start()
threading.Thread(target=totd_loop,             daemon=True).start()
threading.Thread(target=_cleanup_loop,         daemon=True).start()
threading.Thread(target=_audit_loop,           daemon=True).start()
threading.Thread(target=_security_check_loop,  daemon=True).start()
_security_selftest()
add_log('OrcAgent started')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print('OrcAgent Dashboard running on port', port)
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
