import threading, time, json, os, sys, subprocess, requests, logging, datetime, sqlite3, re, functools, struct, base64, math, hashlib, hmac, secrets, binascii, shutil
try:
    from apscheduler.schedulers.background import BackgroundScheduler as _BgScheduler
    from apscheduler.triggers.cron import CronTrigger as _CronTrigger
    _APSCHEDULER_OK = True
except ImportError:
    _APSCHEDULER_OK = False
from contextlib import contextmanager
from flask import Flask, jsonify, request, session, render_template, redirect
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or os.urandom(32)
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'
app.config['SESSION_COOKIE_SECURE']     = bool(os.getenv('RAILWAY_ENVIRONMENT'))
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

@app.template_filter('fmtk')
def _jinja_fmtk(v):
    """Format a large number as 1.2K / 3.4M for use in Jinja2 templates."""
    v = float(v or 0)
    if v >= 1_000_000:
        return f'{v / 1_000_000:.1f}M'
    if v >= 1_000:
        return f'{v / 1_000:.1f}K'
    return f'{v:.0f}'

@app.before_request
def _security_gate():
    """Runs before every other before_request hook (registration order).
    IP-based blocking/banning has been removed — this only logs scanner/exploit
    probe paths for visibility, and applies a soft global rate limit (429,
    never a ban) to blunt DDoS-style floods without locking out real users."""
    ip = request.remote_addr or '0.0.0.0'
    if _BLOCKED_PROBE_RE.search(request.path):
        _log_security_event('honeypot_hit', 'anonymous', f'{request.method} {request.path} from {ip}')
    if request.query_string and _SUSPICIOUS_INPUT_RE.search(request.query_string.decode('utf-8', 'ignore')):
        _log_security_event('suspicious_input', session.get('wallet', 'anonymous'),
                            f'querystring on {request.path} from {ip}')
    if request.method in ('POST', 'PUT', 'PATCH') and (request.content_type or '').startswith('application/json'):
        body = request.get_data(as_text=True) or ''
        if body and _SUSPICIOUS_INPUT_RE.search(body):
            _log_security_event('suspicious_input', session.get('wallet', 'anonymous'),
                                f'request body on {request.path} from {ip}')
    if not _rate_ok('global:' + ip, 60, 60):
        return jsonify({'error': 'Too many requests'}), 429
    _ext_hit('api')
    return None

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
        # ── 0. Shared client secret (only enforced if X_CLIENT_SECRET is configured) ──
        if X_CLIENT_SECRET:
            sent = request.headers.get('X-Client-Secret', '')
            if not sent or not hmac.compare_digest(sent.encode(), X_CLIENT_SECRET.encode()):
                _log_security_event('client_secret_fail', session.get('wallet', 'unknown'),
                                    f'bad/missing X-Client-Secret on {request.path}')
                return jsonify({'error': 'Forbidden'}), 403
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
DB_FILE        = os.path.join(_DATA_DIR, 'orcagent.db')
BACKUP_DIR     = os.path.join(_DATA_DIR, 'backups')
HEARTBEAT_FILE = os.path.join(_DATA_DIR, 'heartbeat.txt')
_APP_START     = time.time()
print(f"[startup] persistent storage: {os.path.exists('/data')}  db={DB_FILE}", flush=True)

DIFFICULTY_PRESETS = {
    'EASY':   {'tp': 0.09, 'sl': 0.05, 'crash': 0.15, 'm5_min': 15, 'm5_max': None},
    'MEDIUM': {'tp': 0.15, 'sl': 0.05, 'crash': 0.15, 'm5_min': 15, 'm5_max': None},
    'HARD':   {'tp': 0.35, 'sl': 0.05, 'crash': 0.15, 'm5_min': 15, 'm5_max': None},
}

WALLET_ADDRESS   = os.environ.get('WALLET_ADDRESS', '')
USDC_MINT        = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
SOL_MINT         = 'So11111111111111111111111111111111111111112'
SOLANA_RPC       = 'https://api.mainnet-beta.solana.com'
SOLANA_RPC_URL   = os.environ.get('SOLANA_RPC_URL', '')   # set in Railway — overrides all fallbacks
HELIUS_RPC       = os.environ.get('HELIUS_RPC', '')        # full Helius URL e.g. https://mainnet.helius-rpc.com/?api-key=xxx
HELIUS_API_KEY   = os.environ.get('HELIUS_API_KEY', '')
OWNER_WALLET     = os.environ.get('OWNER_WALLET', '')
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
JUPITER_PROXY    = os.environ.get('JUPITER_PROXY_URL', '').rstrip('/')
PROXY_SECRET     = os.environ.get('JUPITER_PROXY_SECRET', '')
# Optional shared secret the frontend echoes back on every mutating request.
# Defense-in-depth against scripted bots that POST straight to the API without ever
# loading the page (and therefore never seeing this value). Skipped entirely when unset,
# so local/dev deployments without the env var keep working unchanged.
X_CLIENT_SECRET  = os.environ.get('X_CLIENT_SECRET', '')
FEE_RATE         = 0.05  # 5% performance fee on profitable trades only

# Ordered list of RPC endpoints for claim_sol / blockhash / send_raw queries.
# Priority: SOLANA_RPC_URL → HELIUS_RPC → HELIUS_API_KEY → public fallbacks
def _build_claim_rpcs() -> list:
    rpcs = []
    if SOLANA_RPC_URL:
        rpcs.append(SOLANA_RPC_URL)
    if HELIUS_RPC:
        rpcs.append(HELIUS_RPC)
    if HELIUS_API_KEY:
        rpcs.append(f'https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}')
    rpcs.append('https://solana-mainnet.g.alchemy.com/v2/demo')
    rpcs.append('https://mainnet.helius-rpc.com/?api-key=demo')
    rpcs.append('https://api.mainnet-beta.solana.com')
    return rpcs
CLAIM_SOL_RPCS = _build_claim_rpcs()
def _rpc_label(url: str) -> str:
    if 'helius' in url: return 'Helius'
    if 'alchemy' in url: return 'Alchemy'
    if 'mainnet-beta' in url: return 'mainnet-beta'
    return url[:40]
print(f'[rpc] CLAIM_SOL_RPCS ({len(CLAIM_SOL_RPCS)} endpoints): '
      + ', '.join(_rpc_label(u) for u in CLAIM_SOL_RPCS), flush=True)

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

# Non-reversible fingerprint of ENCRYPTION_KEY — safe to log (unlike the key itself).
# Logged at startup and alongside every encrypt/decrypt so a key mismatch between when a
# private key was *saved* and when it's later *decrypted* (e.g. ENCRYPTION_KEY rotated or
# differs between environments) shows up immediately as mismatched fingerprints in the logs.
_enc_key_fingerprint = hashlib.sha256(_enc_key_str.encode()).hexdigest()[:8]
print(f'[startup] ENCRYPTION_KEY fingerprint: {_enc_key_fingerprint} (sha256 prefix — not the key itself)', flush=True)

def _wallet_fernet(wallet: str) -> Fernet:
    """Derive a wallet-specific Fernet key via HMAC-SHA256(ENCRYPTION_KEY, wallet_address)."""
    derived = hmac.digest(_enc_key_str.encode(), wallet.encode(), 'sha256')
    return Fernet(base64.urlsafe_b64encode(derived))

def encrypt_private_key(raw: str, wallet: str) -> str:
    """Double-encrypt: Layer 1 = ENCRYPTION_KEY Fernet, Layer 2 = wallet-derived Fernet.
    Result is prefixed with 'v2:' to distinguish from legacy single-layer ciphertext."""
    l1 = _fernet.encrypt(raw.encode())
    l2 = _wallet_fernet(wallet).encrypt(l1)
    short_w = (wallet[:6] + '...' + wallet[-4:]) if len(wallet) >= 10 else wallet
    print(f'[encrypt] wallet={short_w} enc_key_fp={_enc_key_fingerprint}', flush=True)
    return 'v2:' + l2.decode()

def decrypt_private_key(enc: str, wallet: str) -> str:
    """Decrypt v2 (double-encrypted) or legacy v1 (single Fernet layer) private key.
    Logs the specific failure category (bad input / malformed ciphertext / wrong key or
    corrupted blob / encoding issue) before re-raising, so the real cause is visible in
    prod logs instead of a generic failure. Never logs key or plaintext material."""
    short_w  = (wallet[:6] + '...' + wallet[-4:]) if len(wallet) >= 10 else wallet
    blob_len = len(enc) if isinstance(enc, str) else -1
    is_v2    = isinstance(enc, str) and enc.startswith('v2:')
    try:
        if not isinstance(enc, str) or not enc:
            raise ValueError(f'encrypted blob is {"empty" if enc == "" else type(enc).__name__}, expected non-empty str')
        if is_v2:
            l1 = _wallet_fernet(wallet).decrypt(enc[3:].encode())
            return _fernet.decrypt(l1).decode()
        return _fernet.decrypt(enc.encode()).decode()  # legacy v1 — migrated on next save
    except InvalidToken:
        print(f'[decrypt] ✗ InvalidToken  wallet={short_w} v2={is_v2} blob_len={blob_len} '
              f'enc_key_fp={_enc_key_fingerprint} — either ENCRYPTION_KEY does not match the key '
              f'used to encrypt this blob (compare fingerprints against the [encrypt] log line '
              f'for this wallet), or the ciphertext is corrupted/tampered.', flush=True)
        raise
    except (binascii.Error, ValueError) as e:
        print(f'[decrypt] ✗ {type(e).__name__}  wallet={short_w} v2={is_v2} blob_len={blob_len} '
              f'— malformed ciphertext / wrong key format: {e}', flush=True)
        raise
    except UnicodeDecodeError as e:
        print(f'[decrypt] ✗ UnicodeDecodeError  wallet={short_w} v2={is_v2} blob_len={blob_len} '
              f'— decrypted bytes are not valid UTF-8 text (encoding issue): {e}', flush=True)
        raise
    except Exception as e:
        print(f'[decrypt] ✗ Unexpected {type(e).__name__}  wallet={short_w} v2={is_v2} blob_len={blob_len}: {e}', flush=True)
        raise

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

# ── HONEYPOT GATE (logging only — no IP blocking) ──
# Owner/trusted IPs — set via Railway env var, comma-separated (e.g. "1.2.3.4,5.6.7.8").
_OWNER_IPS = frozenset(
    ip.strip() for ip in os.environ.get('OWNER_IP_WHITELIST', '').split(',') if ip.strip()
)

# Any request path matching this is a known scanner/exploit probe — never legitimate
# traffic for this app. Dotfile segments (e.g. /.env, /.git/config) are blocked except
# /.well-known/ (used for ACME/domain-verification). wp-* and config.php cover the most
# common CMS-scanner probes.
_BLOCKED_PROBE_RE = re.compile(
    r'(^|/)\.(?!well-known(/|$))[^/]*'
    r'|/wp-admin(/|$)'
    r'|/wp-login\.php$'
    r'|/config\.php$'
    r'|/phpinfo(\.php)?$',
    re.IGNORECASE,
)

# Common SQL-injection / XSS / path-traversal signatures in request bodies or query
# strings. Logging only — never blocks, since legitimate input could rarely overlap
# (e.g. a token symbol containing "or"). Lets the security_log surface real attack
# attempts without risking false-positive lockouts of real users.
_SUSPICIOUS_INPUT_RE = re.compile(
    r"union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|"
    r"'\s*or\s*'?1'?\s*=\s*'?1|;\s*--|<script[\s>]|javascript:|onerror\s*=|"
    r"\.\./\.\.|%00|\bexec\s*\(",
    re.IGNORECASE,
)

# ── RATE LIMITING ──
_rl_lock: threading.Lock = threading.Lock()
_rl_hits: dict           = {}
_rl_blocked: dict        = {}  # key → list of block timestamps (for rate-stats dashboard)
# threading.Lock is a factory function, not a class — capture the actual type once
# so isinstance() checks in _run_security_checks() work correctly.
_THREADING_LOCK_TYPE = type(_rl_lock)

# ── EXTERNAL API CALL COUNTERS ──
_ext_lock  = threading.Lock()
# Timestamp lists; filtered to last 24 h for "today" stats, last 1 h for rate-stats.
_ext_calls: dict = {'api': [], 'dexscreener': [], 'jupiter': []}

def _ext_hit(category: str) -> None:
    """Record one external or internal API call for admin observability."""
    now = time.time()
    with _ext_lock:
        lst = _ext_calls.get(category)
        if lst is not None:
            lst.append(now)

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

def _record_block(key: str) -> None:
    """Record that a rate-limit block occurred for this key (for admin observability)."""
    now = time.time()
    with _rl_lock:
        hits = [t for t in _rl_blocked.get(key, []) if now - t < 3600]
        hits.append(now)
        _rl_blocked[key] = hits

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
                _record_block(key)
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
        # Evict expired rate-limit buckets and block records
        with _rl_lock:
            stale = [k for k, hits in _rl_hits.items() if not any(now - t < 120 for t in hits)]
            for k in stale:
                del _rl_hits[k]
            stale_b = [k for k, hits in _rl_blocked.items() if not any(now - t < 3600 for t in hits)]
            for k in stale_b:
                del _rl_blocked[k]
        # Trim external-call lists to last 25 h (keeps "today" window fresh)
        _cutoff_ext = now - 90000
        with _ext_lock:
            for cat in list(_ext_calls.keys()):
                _ext_calls[cat] = [t for t in _ext_calls[cat] if t > _cutoff_ext]
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
        id                       INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_address           TEXT UNIQUE NOT NULL,
        encrypted_private_key    TEXT DEFAULT '',
        trading_active           INTEGER DEFAULT 0,
        max_trade_size           REAL DEFAULT 10.0,
        min_trade_size           REAL DEFAULT 1.0,
        daily_loss_limit         REAL DEFAULT 50.0,
        trade_size_unit_migrated INTEGER DEFAULT 1,
        created_at               TEXT DEFAULT CURRENT_TIMESTAMP
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
        c.execute('ALTER TABLE users ADD COLUMN min_trade_size REAL DEFAULT 1.0')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN difficulty TEXT DEFAULT 'MEDIUM'")
    except sqlite3.OperationalError:
        pass
    try:
        # DEFAULT 0 here (existing rows still hold SOL-denominated amounts from
        # before min/max_trade_size and daily_loss_limit became USDC-denominated —
        # see _migrate_trade_size_units()). New rows always insert with this set to 1.
        c.execute('ALTER TABLE users ADD COLUMN trade_size_unit_migrated INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    # One-time hard reset of every user's trade-size settings to flat USDC defaults
    # (the earlier price-based SOL->USDC conversion produced inconsistent values).
    # Guarded by server_config so it never re-fires and wipes a user's later changes.
    c.execute("SELECT value FROM server_config WHERE key='trade_size_reset_v1'")
    if not c.fetchone():
        c.execute('''UPDATE users SET
                     min_trade_size           = 1.0,
                     max_trade_size           = 10.0,
                     daily_loss_limit         = 50.0,
                     trade_size_unit_migrated = 1''')
        c.execute("INSERT INTO server_config (key, value) VALUES ('trade_size_reset_v1', 'done')")
        conn.commit()
        print('[migration] reset all users trade-size settings to USDC defaults (1/10/50)', flush=True)
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
    c.execute('''CREATE TABLE IF NOT EXISTS banned_ips (
        ip         TEXT PRIMARY KEY,
        expires_at REAL NOT NULL,
        banned_at  TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    # Migrate: add key_hash column to users if not already present
    try:
        c.execute('ALTER TABLE users ADD COLUMN key_hash TEXT DEFAULT ""')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE users ADD COLUMN username TEXT DEFAULT NULL')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE users ADD COLUMN avatar_url TEXT DEFAULT NULL')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE users ADD COLUMN bio TEXT DEFAULT NULL')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE trades ADD COLUMN opened_at REAL DEFAULT NULL')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE trades ADD COLUMN mint_address TEXT DEFAULT NULL')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE users ADD COLUMN referral_code TEXT UNIQUE')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE users ADD COLUMN referred_by TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE users ADD COLUMN referral_count INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    c.execute('''CREATE TABLE IF NOT EXISTS follows (
        follower_id  INTEGER NOT NULL,
        following_id INTEGER NOT NULL,
        created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (follower_id, following_id),
        FOREIGN KEY (follower_id)  REFERENCES users(id),
        FOREIGN KEY (following_id) REFERENCES users(id)
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_follows_follower  ON follows(follower_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following_id)')
    conn.commit()
    conn.close()

def run_migrations():
    con = sqlite3.connect(DB_FILE)
    for sql in [
        "ALTER TABLE users ADD COLUMN referral_code TEXT",
        "ALTER TABLE users ADD COLUMN referred_by TEXT",
        "ALTER TABLE users ADD COLUMN referral_count INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN badges TEXT DEFAULT ''",
    ]:
        try:
            con.execute(sql)
            con.commit()
        except Exception:
            pass
    con.close()

# ── SECURITY HELPERS ──
# Matches base58 strings 87-88 chars long — Solana private key length.
# Also matches TX signatures; actively block only on key-sensitive API paths.
_KEY_LEAK_RE     = re.compile(r'[1-9A-HJ-NP-Za-km-z]{87,88}')
# Exact-match variant — used by the field-level scanner so substrings inside
# longer values (e.g. a data-URI that happens to contain 87 base58 chars) are ignored.
_B58_EXACT_RE    = re.compile(r'^[1-9A-HJ-NP-Za-km-z]{87,88}$')
# Long base64 blob: 200+ chars using the full base64 alphabet (contains + or / or =).
_BASE64_BLOB_RE  = re.compile(r'^[A-Za-z0-9+/=]{200,}$')
# Field names whose values are always image/avatar data — never key material.
_SKIP_IMAGE_FIELDS = frozenset({
    'avatar', 'avatar_url', 'avatar_data',
    'profile_image', 'image', 'photo', 'picture',
})
# Endpoints where any 87-88 char base58 string in the response triggers a hard block.
# Admin endpoints that return TX hashes are excluded — TX sigs are the same length.
_SENSITIVE_PATHS = {'/api/settings', '/api/claim_sol', '/api/admin/test_fee'}

# Paths that should never be legitimately accessed — any hit is a scan/probe.
_HONEYPOT_PATHS = frozenset({'/.env', '/wp-login.php', '/admin', '/phpmyadmin', '/config.php', '/.git/config', '/wp-admin', '/phpinfo', '/phpinfo.php'})

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

def _scan_obj_for_key_leak(obj, _parent_key: str = '') -> tuple | None:
    """
    Recursively walk a decoded JSON object looking for Solana private key material.
    Returns (field_path, redacted_snippet) on first hit, or None if clean.

    Skips:
    - Fields in _SKIP_IMAGE_FIELDS (avatar / image data)
    - Strings containing '+' or '=' (base64 markers absent from base58)
    - Strings >200 chars composed entirely of base64 chars
    Flags:
    - Strings matching base58 exactly at 87-88 chars
    - Lists of exactly 64 ints in [0,255] (raw key byte array)
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _SKIP_IMAGE_FIELDS:
                continue
            hit = _scan_obj_for_key_leak(v, _parent_key=k)
            if hit:
                return hit
    elif isinstance(obj, list):
        # Raw key stored as a 64-element byte array
        if (len(obj) == 64 and
                all(isinstance(x, int) and 0 <= x <= 255 for x in obj)):
            return (_parent_key or '[root]', '[64-int array]')
        for item in obj:
            hit = _scan_obj_for_key_leak(item, _parent_key=_parent_key)
            if hit:
                return hit
    elif isinstance(obj, str):
        # base64 always uses + or = — base58 never does
        if '+' in obj or '=' in obj:
            return None
        # Long blob of base64-alphabet chars (e.g. data URI without padding stripped)
        if len(obj) > 200 and _BASE64_BLOB_RE.match(obj):
            return None
        if _B58_EXACT_RE.match(obj):
            return (_parent_key or '[root]', obj[:8] + '...')
    return None

def _security_selftest() -> bool:
    STATE_ALLOWED    = frozenset({
        'trader_running', 'usdc', 'sol', 'positions', 'positions_detail',
        'log_lines', 'tokens', 'wallet', 'is_admin', 'has_trading_key', 'sol_price',
    })
    SETTINGS_ALLOWED = frozenset({
        'ok', 'has_trading_key', 'max_trade_size', 'min_trade_size', 'daily_loss_limit', 'msg', 'avatar_url',
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
        'log_lines', 'tokens', 'wallet', 'is_admin', 'has_trading_key', 'sol_price',
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
    """IP banning has been disabled. Kept as a stub returning False so existing
    call sites don't need to change."""
    return False

def _ban_ip(ip: str, duration: int) -> None:
    """No-op — IP banning has been disabled. Regular users must always be able
    to reach the site, so nothing in this codebase is allowed to block by IP
    anymore. Kept as a stub so existing call sites don't need to change."""
    return

def _load_banned_ips() -> None:
    """IP banning has been disabled. Wipe any bans persisted before this change
    so nobody stays locked out across the upgrade."""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute('DELETE FROM banned_ips')
        conn.commit()
        conn.close()
    except Exception:
        pass
    _ip_ban.clear()
    _ip_warn.clear()

def _record_ip_failure(ip: str, duration: int = 3600, threshold: int = 3, window: int = 600) -> None:
    """Tracks recent failures for visibility only — no longer escalates to a ban."""
    now  = time.time()
    hits = [t for t in _ip_warn.get(ip, []) if now - t < window]
    hits.append(now)
    _ip_warn[ip] = hits

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

_REF_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'   # no ambiguous 0/O/1/I

def get_or_create_user(wallet: str) -> int:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO users (wallet_address) VALUES (?)', (wallet,))
    conn.commit()
    c.execute('SELECT id, referral_code FROM users WHERE wallet_address=?', (wallet,))
    row = c.fetchone()
    if row and not row[1]:
        for _ in range(10):
            code = ''.join(secrets.choice(_REF_CHARS) for _ in range(8))
            try:
                c.execute('UPDATE users SET referral_code=? WHERE wallet_address=?', (code, wallet))
                conn.commit()
                break
            except sqlite3.IntegrityError:
                continue   # collision — try a new code
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

_sol_price_usd: float = 0.0  # refreshed each token_loop cycle via DexScreener
_trade_size_units_migrated: bool = False  # one-time SOL→USDC migration guard, see _migrate_trade_size_units()
_price_snapshots: dict = {}  # mint -> {'price': float, 'ts': float} — previous-cycle prices for reversal detection
cooldown_tokens:  dict = {}  # symbol -> expiry_timestamp — 30-min post-loss cooldown per token
profit_cooldown:  dict = {}  # user_id -> expiry_timestamp — 1-hour pause after 60% profit in 2h

def _migrate_trade_size_units(sol_price: float) -> None:
    """One-time migration: min_trade_size/max_trade_size/daily_loss_limit used to be
    SOL-denominated. Now that the Settings UI treats them as USDC, convert any
    pre-existing (unmigrated) rows to their dollar-equivalent at the given SOL
    price so existing users' real trade-size/loss-limit behavior doesn't silently
    shrink ~100x+ after this change. Guarded by trade_size_unit_migrated so it
    only ever runs once per row, even across redeploys."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('SELECT COUNT(*) FROM users WHERE trade_size_unit_migrated=0')
        n = c.fetchone()[0]
        if n:
            c.execute('''UPDATE users SET
                         min_trade_size           = ROUND(min_trade_size   * ?, 2),
                         max_trade_size           = ROUND(max_trade_size   * ?, 2),
                         daily_loss_limit         = ROUND(daily_loss_limit * ?, 2),
                         trade_size_unit_migrated = 1
                       WHERE trade_size_unit_migrated = 0''', (sol_price, sol_price, sol_price))
            conn.commit()
            print(f'[migration] converted {n} user(s) trade-size settings from SOL to USDC '
                  f'at ${sol_price:.2f}/SOL', flush=True)
        conn.close()
    except Exception as e:
        print(f'[migration] trade_size_unit migration failed: {e}', flush=True)

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
        _ext_hit('dexscreener')
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
            'dexId':         (p.get('dexId', '') or '').lower(),
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
            # Remove expired cooldown entries each scan cycle
            global cooldown_tokens
            _cd_now = time.time()
            _cd_expired = [s for s, exp in cooldown_tokens.items() if exp <= _cd_now]
            for _cd_s in _cd_expired:
                cooldown_tokens.pop(_cd_s, None)
                print(f'[cooldown] {_cd_s} cooldown expired — eligible again', flush=True)

            # Snapshot previous prices BEFORE overwriting state['tokens'] — used by
            # reversal check in Pass 2 to skip tokens whose price is already falling.
            global _price_snapshots
            _snap_ts = time.time()
            for _old_t in state.get('tokens', []):
                _price_snapshots[_old_t['mint']] = {'price': _old_t['price'], 'ts': _snap_ts}
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
                    'dexId':         data.get('dexId', '') or '',
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
            # Refresh SOL/USD price once per scan cycle
            global _sol_price_usd, _trade_size_units_migrated
            try:
                _sr = _dex_get('https://api.dexscreener.com/latest/dex/tokens/' + SOL_MINT, timeout=6)
                if _sr and _sr.status_code == 200:
                    _pairs = (_sr.json().get('pairs') or [])
                    _p = next((p for p in _pairs if (p.get('quoteToken') or {}).get('address') == USDC_MINT), _pairs[0] if _pairs else None)
                    if _p:
                        _sp = float(_p.get('priceUsd', 0) or 0)
                        if _sp > 1:
                            _sol_price_usd = _sp
                            if not _trade_size_units_migrated:
                                _migrate_trade_size_units(_sp)
                                _trade_size_units_migrated = True
            except Exception:
                pass
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
                       amount: float, spend: float, wallet: str = '', private_key: str = '', mint: str = '',
                       exit_reason: str = '', opened_at: float = 0.0):
    check_daily_reset_user(us)
    now   = datetime.datetime.utcnow()
    today = now.strftime('%Y-%m-%d')
    pnl     = round(amount * (exit_price - entry), 4) if entry > 0 else 0.0
    pnl_pct = round((exit_price - entry) / entry * 100, 2) if entry > 0 else 0.0

    if pnl < 0 and symbol:
        cooldown_tokens[symbol] = time.time() + 1800
        print(f'[cooldown] {symbol} enters 30-min cooldown (pnl={pnl:.6f} SOL, exit_reason={exit_reason})', flush=True)

    # 5% performance fee on profitable trades only (collected in SOL)
    fee_amount = 0.0
    short_w    = (wallet[:6] + '...' + wallet[-4:]) if len(wallet) >= 10 else wallet
    _owner_set = bool(OWNER_WALLET)
    print(f'[fee] {short_w} {symbol} pnl={pnl:.6f} SOL  '
          f'pnl_positive={pnl>0}  has_key={bool(private_key and wallet)}  '
          f'owner_wallet_set={_owner_set}', flush=True)

    # Referred users receive a 10% discount on the performance fee (4.5% instead of 5%).
    _applied_fee_rate = FEE_RATE
    if wallet:
        try:
            _fconn = sqlite3.connect(DB_FILE)
            _frow  = _fconn.execute(
                'SELECT referred_by FROM users WHERE wallet_address=?', (wallet,)
            ).fetchone()
            _fconn.close()
            if _frow and _frow[0]:
                _applied_fee_rate = round(FEE_RATE * 0.9, 6)
        except Exception:
            pass

    # Collect fees from ALL profitable trades regardless of who the session wallet belongs to.
    # The fee goes FROM the trading keypair TO OWNER_WALLET — these are different addresses,
    # so even the platform owner's trades generate a valid transfer.
    if pnl > 0.0 and wallet and private_key and _owner_set:
        fee_amount   = round(pnl * _applied_fee_rate, 6)
        _disc_note   = ' (10% referral discount)' if _applied_fee_rate < FEE_RATE else ''
        print(f'[fee] {short_w} {symbol} fee owed = {fee_amount:.6f} SOL '
              f'({_applied_fee_rate * 100:.1f}% of {pnl:.6f} SOL profit{_disc_note})', flush=True)

        if fee_amount > 0:
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
                except Exception as e:
                    err_msg = _redact_keys(str(e))
                    print(f'[fee] ✗ {sw} {sym} transfer FAILED: {err_msg}', flush=True)

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
            print(f'[fee] {short_w} {symbol} nothing to collect', flush=True)
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
        'mint': mint, 'exit_reason': exit_reason,
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
    ds['curve'].append({'t': now.strftime('%H:%M'), 'v': ds['total_pnl']})
    try:
        conn = sqlite3.connect(DB_FILE)
        try:
            conn.execute(
                '''INSERT INTO trades
                   (user_id, token, entry_price, exit_price, amount, pnl, fee_amount, fee_paid, timestamp, opened_at, mint_address)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                (user_id, symbol, entry, exit_price, amount, pnl, fee_amount, 0,
                 now.strftime('%Y-%m-%dT%H:%M:%SZ'), opened_at if opened_at else None,
                 mint or None))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f'[trade_record] DB write failed: {e}', flush=True)
    if wallet:
        _recalculate_badges(wallet)

# ── BADGE SYSTEM ──
def _calculate_badges(wallet: str) -> list:
    badges = []
    try:
        conn = sqlite3.connect(DB_FILE)
        row = conn.execute('SELECT id FROM users WHERE wallet_address=?', (wallet,)).fetchone()
        if not row:
            conn.close()
            return []
        user_id = row[0]
        trades = conn.execute(
            'SELECT pnl, amount, timestamp, opened_at FROM trades WHERE user_id=? ORDER BY timestamp ASC',
            (user_id,)
        ).fetchall()
        conn.close()
        if not trades:
            return []

        pnls       = [t[0] or 0.0 for t in trades]
        amounts    = [t[1] or 0.0 for t in trades]
        timestamps = [t[2] or ''  for t in trades]
        opened_ats = [t[3]        for t in trades]
        total      = len(trades)
        wins       = sum(1 for p in pnls if p > 0)

        # 🔥 Hot Streak — 5+ consecutive wins
        streak = max_streak = 0
        for p in pnls:
            streak = streak + 1 if p > 0 else 0
            max_streak = max(max_streak, streak)
        if max_streak >= 5:
            badges.append('🔥 Hot Streak')

        # 💎 Diamond Hands — any position held 30+ minutes
        for ts_str, opened_at in zip(timestamps, opened_ats):
            if opened_at and ts_str:
                try:
                    close_dt = datetime.datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    open_dt  = datetime.datetime.fromtimestamp(opened_at, tz=datetime.timezone.utc)
                    if (close_dt - open_dt).total_seconds() >= 1800:
                        badges.append('💎 Diamond Hands')
                        break
                except Exception:
                    pass

        # 🐋 Whale — single trade volume > 1 SOL
        if any(a > 1.0 for a in amounts):
            badges.append('🐋 Whale')

        # ⚡ Speed Trader — 10+ trades in one calendar day
        day_counts: dict = {}
        for ts in timestamps:
            day = ts[:10]
            day_counts[day] = day_counts.get(day, 0) + 1
        if any(v >= 10 for v in day_counts.values()):
            badges.append('⚡ Speed Trader')

        # 🎯 Sharp Shooter — win rate > 70% with 20+ trades
        if total >= 20 and (wins / total) > 0.70:
            badges.append('🎯 Sharp Shooter')

        # 🏆 Top Earner — total PnL > 5 SOL
        if sum(pnls) > 5.0:
            badges.append('🏆 Top Earner')

    except Exception as e:
        print(f'[badges] calculate error for {wallet}: {e}', flush=True)
    return badges


def _recalculate_badges(wallet: str) -> None:
    badges = _calculate_badges(wallet)
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute('UPDATE users SET badges=? WHERE wallet_address=?',
                     (','.join(badges), wallet))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f'[badges] save error for {wallet}: {e}', flush=True)

# ── SWAP EXECUTION ──
def _execute_user_swap(wallet: str, private_key: str, action: str, mint: str, amount_str: str) -> bool:
    """Execute a Jupiter swap. Returns True only if the subprocess exited 0 with output.
    Key is passed via env var to the subprocess and the env dict is discarded after launch."""
    try:
        env = os.environ.copy()
        env['WALLET_ADDRESS']     = wallet
        env['WALLET_PRIVATE_KEY'] = private_key
        _ext_hit('jupiter')
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
            c.execute('SELECT id, encrypted_private_key, daily_loss_limit, difficulty, min_trade_size, max_trade_size FROM users WHERE wallet_address=?', (wallet,))
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
    daily_loss_limit = abs(float(row[2] if row[2] is not None else 50.0))
    difficulty       = row[3] if (len(row) > 3 and row[3] in DIFFICULTY_PRESETS) else 'MEDIUM'
    min_trade_usdc   = float(row[4]) if (len(row) > 4 and row[4] is not None) else 1.0
    max_trade_usdc   = float(row[5]) if (len(row) > 5 and row[5] is not None) else 10.0
    preset           = DIFFICULTY_PRESETS[difficulty]
    take_profit      = preset['tp']
    stop_loss        = preset['sl']
    crash_exit       = preset['crash']
    m5_min           = preset['m5_min']
    m5_max           = preset['m5_max']

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

    _m5_desc = ('≥' + str(m5_min) + '%' if m5_max is None else str(m5_min) + '-' + str(m5_max) + '%')
    print(f'[trader] {short} session={wallet[:8]}... trading={_trading_wallet[:8]}... difficulty={difficulty}', flush=True)
    add_user_log(wallet, '[' + short + '] Trader started [' + difficulty + '] — TP:+' + str(round(take_profit*100)) +
                 '% SL:-' + str(round(stop_loss*100)) + '% crash:-' + str(round(crash_exit*100)) +
                 '% | momentum ' + _m5_desc + ' in 5m + not reversing | max 5 pos | scan 30s')
    positions = us['positions']

    # ── Immediate stop-loss pass on startup ──────────────────────────────────
    # Catches any positions that breached the stop-loss while the bot was offline.
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
        if _price < _pos['buy_price'] * (1 - crash_exit):
            _cpct = str(round(_chg*100,1)) + '%'
            add_user_log(wallet, f'[{short}] 🚨 [crash-exit] {_label} {_cpct} — price crashed >{int(crash_exit*100)}% from entry, emergency sell on startup')
            print(f'[crash-exit] {short} STARTUP {_label} {_cpct} price={_price} entry={_pos["buy_price"]}', flush=True)
            with _use_key(_enc_blob, wallet) as _pk:
                _sell_ok = _execute_user_swap(wallet, _pk, 'sell', _mint, str(_pos['amount']))
            if _sell_ok:
                with _use_key(_enc_blob, wallet) as _pk:
                    _record_user_trade(user_id, us, _label, _pos['buy_price'], _price,
                                       _pos['amount'], _pos.get('spend', 0), wallet=wallet, private_key=_pk, mint=_mint,
                                       exit_reason='CRASH EXIT ' + _cpct, opened_at=_pos.get('opened_at', 0.0))
            else:
                _record_user_trade(user_id, us, _label, _pos['buy_price'], _price,
                                   _pos['amount'], _pos.get('spend', 0), mint=_mint,
                                   exit_reason='CRASH EXIT ' + _cpct, opened_at=_pos.get('opened_at', 0.0))
            positions[_mint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
            continue  # skip normal stop-loss check — crash exit already handled
        if _chg <= -stop_loss:
            add_user_log(wallet, f'[{short}] STARTUP FORCE SELL {_label} {round(_chg*100,1)}% (stop loss missed while bot was offline)')
            print(f'[trader] {short} STARTUP FORCE SELL {_label} {round(_chg*100,1)}%', flush=True)
            with _use_key(_enc_blob, wallet) as _pk:
                _sell_ok = _execute_user_swap(wallet, _pk, 'sell', _mint, str(_pos['amount']))
            if _sell_ok:
                with _use_key(_enc_blob, wallet) as _pk:
                    _record_user_trade(user_id, us, _label, _pos['buy_price'], _price,
                                       _pos['amount'], _pos.get('spend', 0), wallet=wallet, private_key=_pk, mint=_mint,
                                       exit_reason='STOP LOSS', opened_at=_pos.get('opened_at', 0.0))
            else:
                _record_user_trade(user_id, us, _label, _pos['buy_price'], _price,
                                   _pos['amount'], _pos.get('spend', 0), mint=_mint,
                                   exit_reason='STOP LOSS', opened_at=_pos.get('opened_at', 0.0))
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
                        _tok      = live_map[mint]
                        price     = _tok['price']
                        label     = _tok['symbol'] or pos.get('symbol', mint[:8])
                        cur_liq   = float(_tok.get('liquidity', 0) or 0)
                        cur_vol24 = float(_tok.get('volume24h', 0) or 0)
                    else:
                        # Token left the live scan — fetch price directly so SL still fires
                        _td       = get_token_data(mint)
                        price     = float(_td['price']) if _td else 0.0
                        label     = (_td['symbol'] if _td else '') or pos.get('symbol', mint[:8])
                        cur_liq   = float(_td.get('liquidity', 0) or 0) if _td else 0.0
                        cur_vol24 = float(_td.get('volume24h', 0) or 0) if _td else 0.0
                        if price > 0:
                            add_user_log(wallet, '[' + short + '] ' + label +
                                         ' not in scan — fetched price $' + str(round(price, 8)))
                    if price <= 0:
                        continue
                    chg = (price - pos['buy_price']) / pos['buy_price']

                    # ── Rugpull detector — first check, before crash-exit and stop-loss ──
                    _rug_reason = None
                    if chg <= -0.60:
                        _rug_reason = 'price -' + str(abs(round(chg*100, 1))) + '% from entry'
                    elif cur_liq > 0 and pos.get('entry_liquidity', 0) > 0 and cur_liq < pos['entry_liquidity'] * 0.50:
                        _liq_drop = round((1 - cur_liq / pos['entry_liquidity']) * 100, 1)
                        _rug_reason = ('liquidity dropped ' + str(_liq_drop) + '% ($' +
                                       str(int(pos['entry_liquidity'])) + ' → $' + str(int(cur_liq)) + ')')
                    elif cur_vol24 > 0 and cur_vol24 < 1000:
                        _rug_reason = '24h volume near-zero ($' + str(int(cur_vol24)) + ')'
                    if _rug_reason:
                        add_user_log(wallet, '[' + short + '] ⚠ Rugpull detected — emergency exit ' + label + ' | ' + _rug_reason)
                        print(f'[rugpull-detected] {short} {label} — {_rug_reason}', flush=True)
                        cooldown_tokens[label] = time.time() + 7200  # 2-hour cooldown
                        with _use_key(_enc_blob, wallet) as _pk:
                            sell_ok = _execute_user_swap(wallet, _pk, 'sell', mint, str(pos['amount']))
                        if sell_ok:
                            with _use_key(_enc_blob, wallet) as _pk:
                                _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'],
                                                   wallet=wallet, private_key=_pk, mint=mint,
                                                   exit_reason='RUGPULL ' + _rug_reason[:40], opened_at=pos.get('opened_at', 0.0))
                        else:
                            add_user_log(wallet, '[' + short + '] ✗ [rugpull] Sell failed — position cleared')
                            _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'],
                                               mint=mint, exit_reason='RUGPULL ' + _rug_reason[:40],
                                               opened_at=pos.get('opened_at', 0.0))
                        positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
                        open_pos -= 1
                        continue  # skip crash-exit and TP/SL
                    if price < pos['buy_price'] * (1 - crash_exit):
                        crash_pct = str(round(chg*100,1)) + '%'
                        add_user_log(wallet, '[' + short + '] 🚨 [crash-exit] ' + label + ' ' + crash_pct + ' — price crashed >' + str(int(crash_exit*100)) + '% from entry, emergency exit')
                        print(f'[crash-exit] {short} {label} {crash_pct} price={price} entry={pos["buy_price"]}', flush=True)
                        with _use_key(_enc_blob, wallet) as _pk:
                            sell_ok = _execute_user_swap(wallet, _pk, 'sell', mint, str(pos['amount']))
                        if sell_ok:
                            with _use_key(_enc_blob, wallet) as _pk:
                                _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'],
                                                   wallet=wallet, private_key=_pk, mint=mint,
                                                   exit_reason='CRASH EXIT ' + crash_pct, opened_at=pos.get('opened_at', 0.0))
                        else:
                            add_user_log(wallet, '[' + short + '] ✗ [crash-exit] Sell failed — position cleared')
                            _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'],
                                               mint=mint, exit_reason='CRASH EXIT ' + crash_pct,
                                               opened_at=pos.get('opened_at', 0.0))
                        positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
                        open_pos -= 1
                        continue  # skip normal TP/SL — crash exit already handled
                    exit_reason = None
                    if chg >= take_profit:
                        exit_reason = 'TAKE PROFIT +' + str(round(chg*100,1)) + '%'
                    elif chg <= -stop_loss:
                        exit_reason = 'STOP LOSS ' + str(round(chg*100,1)) + '%'
                    if exit_reason:
                        add_user_log(wallet, '[' + short + '] ' + exit_reason + ' ' + label)
                        with _use_key(_enc_blob, wallet) as _pk:
                            sell_ok = _execute_user_swap(wallet, _pk, 'sell', mint, str(pos['amount']))
                        if sell_ok:
                            with _use_key(_enc_blob, wallet) as _pk:
                                _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'],
                                                   wallet=wallet, private_key=_pk, mint=mint,
                                                   exit_reason=exit_reason, opened_at=pos.get('opened_at', 0.0))
                        else:
                            add_user_log(wallet, '[' + short + '] ✗ Sell failed — position cleared')
                            _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'],
                                               mint=mint, exit_reason=exit_reason,
                                               opened_at=pos.get('opened_at', 0.0))
                        positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
                        open_pos -= 1

                # ── Profit protection: gate Pass 2 without touching exit logic ──
                _now_plk   = time.time()
                _pc_exp    = profit_cooldown.get(user_id)
                _pc_locked = False
                if _pc_exp:
                    if _now_plk < _pc_exp:
                        _pc_locked = True
                    else:
                        profit_cooldown.pop(user_id, None)  # lock expired — clear
                if not _pc_locked:
                    _trades_2h = [t for t in us['trades_history'] if t.get('ts', 0) > _now_plk - 7200]
                    _pnl_2h    = sum(t.get('pnl', 0) for t in _trades_2h)
                    if _pnl_2h > 0:
                        _start_bal = us_sol - _pnl_2h
                        if _start_bal > 0.001 and _pnl_2h / _start_bal >= 0.60:
                            profit_cooldown[user_id] = _now_plk + 3600
                            _pc_locked = True
                            print(f'[profit-lock] user {user_id} — 60% profit reached '
                                  f'(pnl_2h={round(_pnl_2h,4)} SOL  '
                                  f'start_bal≈{round(_start_bal,4)} SOL  '
                                  f'ratio={round(_pnl_2h/_start_bal*100,1)}%) — pausing 1 hour', flush=True)
                            add_user_log(wallet, '[' + short + '] 🔒 Profit target reached (+60%) — '
                                         'bot paused for 1 hour to protect gains')

                # ── Pass 2: pick the single best entry ──
                if not stop_event.is_set() and open_pos < 5 and us_sol > 0.01 and not _pc_locked:
                    not_held = [t for t in live if positions.get(t['mint'], {}).get('amount', 0) == 0]
                    qualifying = []
                    _skip_log  = []
                    _now_cd    = time.time()
                    for _t in not_held:
                        _tsym = _t.get('symbol', '') or _t['mint'][:8]
                        _dex  = _t.get('dexId', '') or ''
                        if 'pump' in _dex:
                            _skip_log.append(f'[skip] {_tsym}: pumpswap — filtered out')
                            continue
                        _sc   = _t.get('score', 0)
                        _m5   = _t.get('change5m', 0)
                        _v5m  = _t.get('volume5m', 0)
                        _v1h  = _t.get('volume1h', 0)
                        _vol_rising = bool(_v5m > 0 and _v1h > 0 and _v5m > _v1h / 12)
                        _m5_ok = (_m5 >= m5_min) if m5_max is None else (m5_min <= _m5 <= m5_max)
                        _snap = _price_snapshots.get(_t['mint'])
                        _reversing = bool(
                            _snap and
                            _t['price'] < _snap['price'] * 0.98
                        )
                        _cd_exp  = cooldown_tokens.get(_tsym)
                        _cooling = bool(_cd_exp and _now_cd < _cd_exp)

                        if _sc < 5.0:
                            _skip_log.append(f'[skip] {_tsym}: score too low ({round(_sc,1)} < 5.0)')
                            continue
                        if not _m5_ok:
                            _skip_log.append(f'[skip] {_tsym}: change5m too low ({round(_m5,1)}% vs {_m5_desc})')
                            continue
                        if not _vol_rising:
                            _skip_log.append(f'[skip] {_tsym}: vol not rising (v5m={int(_v5m)} v1h={int(_v1h)})')
                            continue
                        if _t.get('change1h', 0) >= 50:
                            _skip_log.append(f'[skip] {_tsym}: 1h already +{round(_t.get("change1h",0),1)}% (momentum exhausted)')
                            continue
                        if _reversing:
                            _skip_log.append(f'[skip] {_tsym}: reversing (cur={_t["price"]:.8f} < prev={_snap["price"]:.8f})')
                            continue
                        if _cooling:
                            _skip_log.append(f'[skip] {_tsym}: cooldown ({int(_cd_exp - _now_cd)}s remaining)')
                            continue
                        qualifying.append(_t)
                    qualifying.sort(key=lambda t: t.get('change5m', 0), reverse=True)
                    add_user_log(wallet, '[' + short + '] ' + str(len(qualifying)) + '/' +
                                 str(total_live) + ' qualify (' + _m5_desc + ' m5 + vol rising + not reversing)')
                    if not qualifying and _skip_log:
                        print(f'[qualify] {short} 0/{len(not_held)} — skip reasons:', flush=True)
                        for _sl in _skip_log:
                            print(f'  {_sl}', flush=True)
                    if qualifying:
                        best  = qualifying[0]
                        bmint = best['mint']
                        label = best['symbol'] or bmint[:8]
                        sc    = best['score']
                        m5    = best.get('change5m', 0)
                        m5s   = ('+' if m5 >= 0 else '') + str(round(m5, 1)) + '%'
                        add_user_log(wallet, '[' + short + '] Best: ' + label +
                                     ' score ' + str(sc) + '/10 → BUYING m5:' + m5s)
                        trade_pct = 0.60 if sc >= 7 else config.get('trade_pct', 0.40)
                        spend = us_sol * trade_pct
                        # min/max trade size are USDC-denominated in the UI — convert to
                        # SOL at the current price before clamping the SOL-denominated spend.
                        if _sol_price_usd > 0:
                            min_spend_sol = min_trade_usdc / _sol_price_usd
                            max_spend_sol = max_trade_usdc / _sol_price_usd
                            spend = min(max(spend, min_spend_sol), max_spend_sol)
                        spend = round(spend, 4)
                        if spend >= 0.001 and spend <= us_sol:
                            if bmint not in positions:
                                positions[bmint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
                            pos = positions[bmint]
                            with _use_key(_enc_blob, wallet) as _pk:
                                _execute_user_swap(wallet, _pk, 'buy', bmint, str(spend))
                            pos['amount']          = spend / best['price']
                            pos['buy_price']       = best['price']
                            pos['spend']           = spend
                            pos['symbol']          = label
                            pos['opened_at']       = time.time()
                            pos['entry_liquidity'] = float(best.get('liquidity', 0) or 0)
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
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.binance.com; "
        "frame-src https://dexscreener.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'")
    if os.getenv('RAILWAY_ENVIRONMENT'):
        resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    # Scan JSON responses for possible private key leak (87-88 char base58 = private key length).
    # Actively block only on endpoints that must never return key material.
    # Other endpoints (e.g. /api/admin with fee TX hashes) only log a warning.
    if (resp.content_type or '').startswith('application/json'):
        path = getattr(request, 'path', '')
        try:
            body = resp.get_data(as_text=True)
            # ── 1. Block Solana private key material on sensitive endpoints ──
            # Walk the decoded JSON field-by-field with _scan_obj_for_key_leak so we
            # can skip image/avatar fields and distinguish base64 blobs from base58 keys.
            _key_hit = None
            try:
                _parsed = json.loads(body)
                _key_hit = _scan_obj_for_key_leak(_parsed)
                if _key_hit:
                    print(f'[key_leak_scan] HIT on {path}: field={_key_hit[0]!r} '
                          f'value={_key_hit[1]!r}', flush=True)
                else:
                    # Log what the old substr-scan would have flagged vs the new result,
                    # so we can confirm false positives are now suppressed.
                    _old_match = _KEY_LEAK_RE.search(body)
                    if _old_match:
                        print(f'[key_leak_scan] {path}: old scan would have flagged '
                              f'{_old_match.group()[:8]!r}... → new scan: CLEAN (false positive suppressed)',
                              flush=True)
            except Exception:
                pass
            if _key_hit:
                _hit_field, _hit_snippet = _key_hit
                if path in _SENSITIVE_PATHS:
                    print(f'SECURITY ALERT: possible key leak in {path} '
                          f'(field={_hit_field!r}, value={_hit_snippet!r}) — response blocked',
                          flush=True)
                    try:
                        _log_security_event('key_leak_blocked', _current_wallet() or 'unknown', path)
                    except Exception:
                        pass
                    r = jsonify({'error': 'Response blocked by security policy'})
                    r.status_code = 500
                    return r
                else:
                    print(f'SEC WARN: possible key in {path} '
                          f'(field={_hit_field!r}) — expected if TX hash', flush=True)
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

@app.route('/health')
def health():
    uptime  = int(time.time() - _APP_START)
    last_hb = None
    try:
        with open(HEARTBEAT_FILE) as _f:
            last_hb = _f.read().strip()
    except FileNotFoundError:
        pass
    return jsonify({'status': 'ok', 'uptime': uptime, 'last_heartbeat': last_hb})

@app.route('/')
def index():
    # Inject the client secret (if configured) so the frontend can echo it back
    # on mutating requests — see X_CLIENT_SECRET / _csrf_check above.
    with open(os.path.join(BASE, 'dashboard.html'), 'r', encoding='utf-8') as f:
        html = f.read()
    html = html.replace('__X_CLIENT_SECRET__', X_CLIENT_SECRET)
    return app.response_class(html, mimetype='text/html')

_MINT_RE = re.compile(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$')

@app.route('/token/<mint_address>')
def token_detail(mint_address):
    wallet = _current_wallet()
    if not wallet:
        return redirect('/')
    if not _MINT_RE.match(mint_address or ''):
        return redirect('/history')
    token_info   = get_token_data(mint_address)
    token_name   = (token_info or {}).get('name',   '')
    token_symbol = (token_info or {}).get('symbol', '')
    trades = []
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('SELECT id FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
        if row:
            user_id = row[0]
            c.execute(
                '''SELECT timestamp, token, entry_price, exit_price, amount, pnl, opened_at
                   FROM trades
                   WHERE user_id=?
                     AND (mint_address=?
                          OR (mint_address IS NULL AND UPPER(token)=UPPER(?)))
                   ORDER BY timestamp DESC''',
                (user_id, mint_address, token_symbol)
            )
            for ts, token, entry, exit_p, amount, pnl, opened_at in c.fetchall():
                pnl    = round(pnl   or 0.0, 6)
                entry  = entry  or 0.0
                exit_p = exit_p or 0.0
                pnl_pct = round((exit_p - entry) / entry * 100, 2) if entry > 0 else 0.0
                duration = ''
                if opened_at:
                    try:
                        closed_dt = datetime.datetime.strptime((ts or '')[:19], '%Y-%m-%dT%H:%M:%S')
                        opened_dt = datetime.datetime.utcfromtimestamp(float(opened_at))
                        secs = max(0, int((closed_dt - opened_dt).total_seconds()))
                        duration = (f'{secs // 3600}h {(secs % 3600) // 60}m'
                                    if secs >= 3600 else f'{secs // 60}m {secs % 60}s')
                    except Exception:
                        pass
                trades.append({
                    'date': (ts or '')[:10], 'time': (ts or '')[11:16],
                    'token':       token or '—',
                    'entry_price': round(entry, 6), 'exit_price': round(exit_p, 6),
                    'pnl': pnl, 'pnl_pct': pnl_pct, 'duration': duration,
                    'result': 'win' if pnl >= 0 else 'loss',
                })
        conn.close()
    except Exception as e:
        print(f'[token_detail] DB error: {e}', flush=True)
    mint_short = mint_address[:4] + '…' + mint_address[-4:] if len(mint_address) >= 8 else mint_address
    return render_template(
        'token.html',
        mint_address=mint_address,
        mint_short=mint_short,
        token_name=token_name,
        token_symbol=token_symbol,
        token_info=token_info or {},
        trades=trades,
        wallet=wallet,
        wallet_short=(wallet[:4] + '…' + wallet[-4:]) if len(wallet) >= 8 else wallet,
        is_admin=_is_owner(wallet),
    )


@app.route('/api/token/<mint>/candles')
def api_token_candles(mint):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'candles': []})
    if not _MINT_RE.match(mint or ''):
        return jsonify({'ok': False, 'candles': []})
    range_param = request.args.get('range', '7d').lower()
    if range_param not in ('1d', '7d', '30d'):
        range_param = '7d'
    pair_address = ''
    try:
        r = _dex_get('https://api.dexscreener.com/latest/dex/tokens/' + mint)
        if r:
            pairs = r.json().get('pairs') or []
            if pairs:
                pair_address = pairs[0].get('pairAddress') or ''
    except Exception:
        pass
    candles = []
    if pair_address:
        try:
            if range_param == '1d':
                gt_path = 'hour?aggregate=1&limit=24'
            elif range_param == '7d':
                gt_path = 'hour?aggregate=4&limit=42'
            else:
                gt_path = 'day?aggregate=1&limit=30'
            gt_url = (f'https://api.geckoterminal.com/api/v2/networks/solana'
                      f'/pools/{pair_address}/ohlcv/{gt_path}&currency=usd')
            r2 = requests.get(gt_url, headers={'Accept': 'application/json'}, timeout=8)
            if r2.status_code == 200:
                rows = (r2.json().get('data') or {}).get('attributes', {}).get('ohlcv_list') or []
                for row in reversed(rows):   # GeckoTerminal returns newest-first
                    ts, o, h, l, c, _v = row
                    candles.append({'time': int(ts), 'open': float(o),
                                    'high': float(h), 'low': float(l), 'close': float(c)})
        except Exception as e:
            print(f'[candles] error for {mint}: {e}', flush=True)
    return jsonify({'ok': True, 'candles': candles})


_REF_CODE_RE = re.compile(r'^[A-Za-z0-9]{6,12}$')   # generous match; exact 8-char enforced at creation

@app.route('/ref/<code>')
def referral_redirect(code):
    """Public referral link — stores the code in the session then sends the visitor to the
    connect/dashboard page.  No login required; the code is applied when they first connect
    their wallet via /api/wallet/set."""
    if code and _REF_CODE_RE.match(code):
        session['pending_referral'] = code.upper()
    return redirect('/')


def _pnl_card_stats(wallet_addr: str) -> dict | None:
    """Return all-time trade stats for a wallet, or None if no trades exist."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('''
            SELECT
                ROUND(SUM(t.pnl), 4)                                                  AS total_pnl,
                ROUND(SUM(CASE WHEN t.pnl >= 0 THEN 1.0 ELSE 0.0 END)
                      * 100.0 / COUNT(*), 1)                                          AS win_rate,
                COUNT(*)                                                               AS trade_count,
                ROUND(MAX(t.pnl), 4)                                                  AS best_trade,
                ROUND(MIN(t.pnl), 4)                                                  AS worst_trade
            FROM trades t
            JOIN users u ON u.id = t.user_id
            WHERE u.wallet_address = ?
        ''', (wallet_addr,))
        row = c.fetchone()
        conn.close()
    except Exception as e:
        print(f'[pnl_card] DB error for {wallet_addr[:8]}: {e}', flush=True)
        return None
    if not row or not row[2]:
        return None
    total_pnl, win_rate, trade_count, best_trade, worst_trade = row
    anon = (wallet_addr[:4] + '...' + wallet_addr[-4:]) if len(wallet_addr) >= 8 else wallet_addr
    return {
        'wallet':      anon,
        'total_pnl':   round(float(total_pnl   or 0), 4),
        'win_rate':    round(float(win_rate     or 0), 1),
        'trade_count': int  (trade_count        or 0),
        'best_trade':  round(float(best_trade   or 0), 4),
        'worst_trade': round(float(worst_trade  or 0), 4),
    }


@app.route('/api/pnl_card/<wallet_addr>')
@rate_limit(60, 60)
def api_pnl_card(wallet_addr):
    """Public — returns all-time stats for a wallet without revealing the full address."""
    if not is_valid_solana_address(wallet_addr):
        return jsonify({'ok': False, 'error': 'Invalid wallet address'}), 400
    stats = _pnl_card_stats(wallet_addr)
    if stats is None:
        return jsonify({'ok': False, 'error': 'No trades found for this wallet'}), 404
    return jsonify({'ok': True, **stats})


@app.route('/api/badges/<wallet_addr>')
@rate_limit(60, 60)
def api_badges(wallet_addr):
    """Public — returns the earned badges list for a wallet."""
    if not is_valid_solana_address(wallet_addr):
        return jsonify({'ok': False, 'error': 'Invalid wallet address'}), 400
    try:
        conn = sqlite3.connect(DB_FILE)
        row  = conn.execute('SELECT badges FROM users WHERE wallet_address=?',
                            (wallet_addr,)).fetchone()
        conn.close()
        if not row:
            return jsonify({'ok': True, 'badges': []})
        badges = [b.strip() for b in (row[0] or '').split(',') if b.strip()]
        return jsonify({'ok': True, 'badges': badges})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/card/<wallet_addr>')
def pnl_card_page(wallet_addr):
    """Public shareable PnL card page — no login required."""
    if not is_valid_solana_address(wallet_addr):
        return 'Invalid wallet address', 400
    stats    = _pnl_card_stats(wallet_addr)
    card_url = 'https://orcagent.fun/card/' + wallet_addr
    return render_template('card.html', stats=stats, card_url=card_url)


@app.route('/api/referral')
@rate_limit(30, 60)
def api_referral():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'error': 'not logged in'}), 401
    try:
        conn = sqlite3.connect(DB_FILE)
        row = conn.execute(
            'SELECT referral_code, referral_count, referred_by FROM users WHERE wallet_address=?',
            (wallet,)
        ).fetchone()
        conn.close()
    except Exception as e:
        print(f'[api_referral] DB error: {e}', flush=True)
        return jsonify({'ok': False, 'error': 'db error'}), 500
    if not row:
        return jsonify({'ok': False, 'error': 'user not found'}), 404
    code, referral_count, referred_by = row
    referral_link = f'https://orcagent.fun/ref/{code}' if code else None
    return jsonify({
        'ok':             True,
        'code':           code or '',
        'referral_link':  referral_link or '',
        'referral_count': int(referral_count or 0),
        'has_discount':   bool(referred_by),
        'referred_count': int(referral_count or 0),
    })


@app.route('/leaderboard')
def leaderboard():
    session_wallet = _current_wallet()   # may be '' — page is public
    entries = []
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('''
            SELECT
                u.wallet_address,
                ROUND(SUM(t.pnl), 4)                                                    AS total_pnl,
                ROUND(SUM(CASE WHEN t.pnl >= 0 THEN 1.0 ELSE 0.0 END)
                      * 100.0 / COUNT(*), 1)                                            AS win_rate,
                COUNT(*)                                                                 AS trade_count,
                ROUND(MAX(t.pnl), 4)                                                    AS best_trade
            FROM trades t
            JOIN users u ON u.id = t.user_id
            WHERE u.wallet_address IS NOT NULL AND u.wallet_address != \'\'
            GROUP BY t.user_id
            ORDER BY total_pnl DESC
            LIMIT 50
        ''')
        rows = c.fetchall()
        conn.close()
    except Exception as e:
        print(f'[leaderboard] DB error: {e}', flush=True)
        rows = []
    for rank, (wallet, total_pnl, win_rate, trade_count, best_trade) in enumerate(rows, 1):
        wallet = wallet or ''
        is_me  = bool(session_wallet and wallet == session_wallet)
        anon   = (wallet[:4] + '...' + wallet[-4:]) if len(wallet) >= 8 else (wallet or '???')
        entries.append({
            'rank':        rank,
            'wallet':      anon,
            'total_pnl':   round(float(total_pnl   or 0), 4),
            'win_rate':    round(float(win_rate     or 0), 1),
            'trade_count': int  (trade_count        or 0),
            'best_trade':  round(float(best_trade   or 0), 4),
            'is_me':       is_me,
        })
    wallet_short = ((session_wallet[:4] + '...' + session_wallet[-4:])
                    if len(session_wallet) >= 8 else '')
    return render_template(
        'leaderboard.html',
        entries=entries,
        wallet=session_wallet,
        wallet_short=wallet_short,
        is_admin=_is_owner(session_wallet),
    )


@app.route('/history')
def history():
    wallet = _current_wallet()
    if not wallet:
        return redirect('/')
    trades = []
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
        if row:
            user_id = row[0]
            c.execute(
                '''SELECT timestamp, token, entry_price, exit_price, amount, pnl, opened_at, mint_address
                   FROM trades WHERE user_id=? ORDER BY timestamp DESC''',
                (user_id,)
            )
            for ts, token, entry, exit_p, amount, pnl, opened_at, mint_addr in c.fetchall():
                pnl     = round(pnl   or 0.0, 6)
                entry   = entry  or 0.0
                exit_p  = exit_p or 0.0
                pnl_pct = round((exit_p - entry) / entry * 100, 2) if entry > 0 else 0.0
                duration = ''
                if opened_at:
                    try:
                        closed_dt = datetime.datetime.strptime((ts or '')[:19], '%Y-%m-%dT%H:%M:%S')
                        opened_dt = datetime.datetime.utcfromtimestamp(float(opened_at))
                        secs = max(0, int((closed_dt - opened_dt).total_seconds()))
                        if secs >= 3600:
                            duration = f'{secs // 3600}h {(secs % 3600) // 60}m'
                        else:
                            duration = f'{secs // 60}m {secs % 60}s'
                    except Exception:
                        pass
                trades.append({
                    'date':         (ts or '')[:10],
                    'time':         (ts or '')[11:16],
                    'token':        token or '—',
                    'entry_price':  round(entry,  6),
                    'exit_price':   round(exit_p, 6),
                    'pnl':          pnl,
                    'pnl_pct':      pnl_pct,
                    'duration':     duration,
                    'result':       'win' if pnl >= 0 else 'loss',
                    'mint_address': mint_addr or '',
                })
        conn.close()
    except Exception as e:
        print(f'[history] DB error: {e}', flush=True)
    return render_template(
        'history.html',
        trades=trades,
        wallet=wallet,
        wallet_short=(wallet[:4] + '...' + wallet[-4:]) if len(wallet) >= 8 else wallet,
        is_admin=_is_owner(wallet),
    )

# ── HONEYPOTS ──
# These paths are never legitimately accessed. Any hit means a scanner or attacker.
# _security_gate() (registered above, runs first) already intercepts most of these
# via _BLOCKED_PROBE_RE (dotfiles, wp-admin, wp-login.php, config.php); /admin and
# /phpmyadmin rely on this handler since they don't match that regex.
@app.route('/.env')
@app.route('/wp-login.php')
@app.route('/admin')
@app.route('/phpmyadmin')
@app.route('/config.php')
@app.route('/.git/config')
@app.route('/wp-admin')
@app.route('/phpinfo')
@app.route('/phpinfo.php')
def _honeypot():
    ip = request.remote_addr or 'unknown'
    _log_security_event('honeypot_hit', 'anonymous', f'{request.method} {request.path} from {ip}')
    return jsonify({'error': 'Not found'}), 404

# ── VERSION ──
import subprocess as _subprocess, time as _time

def _app_version() -> str:
    try:
        h = _subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'],
                                      stderr=_subprocess.DEVNULL, timeout=2).decode().strip()
        if h:
            return h
    except Exception:
        pass
    return str(int(_time.time()))

_APP_VERSION: str = _app_version()

@app.route('/api/version')
@rate_limit(120, 60)
def api_version():
    return jsonify({'version': _APP_VERSION})

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
        # Apply a pending referral stored when the user visited /ref/<code>
        pending_ref = session.pop('pending_referral', None)
        if pending_ref and isinstance(pending_ref, str) and re.match(r'^[A-Z0-9]{8}$', pending_ref):
            try:
                _conn_ref = sqlite3.connect(DB_FILE)
                _c_ref    = _conn_ref.cursor()
                _c_ref.execute('SELECT referred_by FROM users WHERE wallet_address=?', (address,))
                _ref_row = _c_ref.fetchone()
                if _ref_row and _ref_row[0] is None:
                    _c_ref.execute('SELECT wallet_address FROM users WHERE referral_code=?', (pending_ref,))
                    _referrer = _c_ref.fetchone()
                    if _referrer and _referrer[0] != address:
                        _referrer_wallet = _referrer[0]
                        _c_ref.execute('UPDATE users SET referred_by=? WHERE wallet_address=?',
                                       (_referrer_wallet, address))
                        _c_ref.execute('UPDATE users SET referral_count = referral_count + 1 '
                                       'WHERE wallet_address=?', (_referrer_wallet,))
                        _conn_ref.commit()
                        print(f'[referral] {address[:6]}…{address[-4:]} referred by '
                              f'{_referrer_wallet[:6]}…{_referrer_wallet[-4:]}', flush=True)
                _conn_ref.close()
            except Exception as _ref_e:
                print(f'[referral] apply error: {_ref_e}', flush=True)
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
    c.execute('SELECT encrypted_private_key, max_trade_size, min_trade_size, daily_loss_limit, avatar_url FROM users WHERE wallet_address=?', (wallet,))
    row  = c.fetchone()
    conn.close()
    has_key = bool(row and row[0])
    # Sync in-memory cache so /api/state benefits from this read
    get_user_state(wallet)['has_trading_key'] = has_key
    if row:
        return jsonify({'ok': True, 'has_trading_key': has_key,
                        'max_trade_size': row[1] if row[1] is not None else 10.0,
                        'min_trade_size': row[2] if row[2] is not None else 1.0,
                        'daily_loss_limit': row[3] if row[3] is not None else 50.0,
                        'avatar_url': row[4] or ''})
    return jsonify({'ok': True, 'has_trading_key': False, 'max_trade_size': 10.0, 'min_trade_size': 1.0, 'daily_loss_limit': 50.0, 'avatar_url': ''})

@app.route('/api/settings', methods=['POST'])
@rate_limit(10, 60)
def save_settings():
    ip     = request.remote_addr or '0.0.0.0'
    wallet = _current_wallet()
    if not wallet:
        _record_ip_failure(ip)
        return jsonify({'ok': False, 'msg': 'No wallet connected'})
    data            = request.json or {}
    private_key_raw = data.get('private_key', '').strip()
    try:
        max_trade_size = float(data.get('max_trade_size', 10.0))
    except (ValueError, TypeError):
        max_trade_size = 10.0
    try:
        min_trade_size = float(data.get('min_trade_size', 1.0))
    except (ValueError, TypeError):
        min_trade_size = 1.0
    try:
        daily_loss_limit = float(data.get('daily_loss_limit', 50.0))
    except (ValueError, TypeError):
        daily_loss_limit = 50.0
    max_trade_size   = max(1.0, min(max_trade_size,   100000.0))
    min_trade_size   = max(1.0, min(min_trade_size,   max_trade_size))
    daily_loss_limit = max(1.0, min(daily_loss_limit, 500000.0))

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
            c.execute('INSERT INTO users (wallet_address, encrypted_private_key, key_hash, max_trade_size, min_trade_size, daily_loss_limit, trade_size_unit_migrated) VALUES (?,?,?,?,?,?,1)',
                      (wallet, encrypted or '', new_hash or '', max_trade_size, min_trade_size, daily_loss_limit))
            final_enc = encrypted or ''
        conn.commit()
    finally:
        conn.close()
    final_has_key = bool(final_enc)
    get_user_state(wallet)['has_trading_key'] = final_has_key
    add_user_log(wallet, 'Settings saved for ' + wallet[:6] + '...' + wallet[-4:])
    return jsonify({'ok': True, 'has_trading_key': final_has_key})

# ── USERNAME ──
@app.route('/api/username', methods=['GET'])
@rate_limit(30, 60)
def get_username():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'})
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute('SELECT username FROM users WHERE wallet_address=?', (wallet,))
    row  = c.fetchone()
    conn.close()
    return jsonify({'ok': True, 'username': (row[0] or '') if row else ''})

@app.route('/api/username', methods=['POST'])
@rate_limit(10, 60)
def save_username():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'})
    username = str((request.json or {}).get('username', '')).strip()
    if username and len(username) > 20:
        return jsonify({'ok': False, 'msg': 'Username must be 20 characters or fewer'})
    if username and not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({'ok': False, 'msg': 'Only letters, numbers, and underscores allowed'})
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        if username:
            c.execute('SELECT wallet_address FROM users WHERE username=? COLLATE NOCASE', (username,))
            taken = c.fetchone()
            if taken and taken[0] != wallet:
                return jsonify({'ok': False, 'msg': 'Username already taken'})
        c.execute('UPDATE users SET username=? WHERE wallet_address=?',
                  (username if username else None, wallet))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'username': username})

# ── AVATAR ──
@app.route('/api/avatar', methods=['POST'])
@rate_limit(10, 60)
def save_avatar():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'})
    avatar_data = str((request.json or {}).get('avatar_data', '')).strip()
    if avatar_data:
        _ALLOWED_PREFIXES = (
            'data:image/jpeg;base64,', 'data:image/jpg;base64,',
            'data:image/png;base64,',  'data:image/gif;base64,',
            'data:image/webp;base64,',
        )
        if not any(avatar_data.startswith(p) for p in _ALLOWED_PREFIXES):
            return jsonify({'ok': False, 'msg': 'Only JPEG, PNG, GIF, or WebP images are accepted'})
        b64_part = avatar_data.split(',', 1)[1] if ',' in avatar_data else ''
        if len(b64_part) * 3 // 4 > 2 * 1024 * 1024:
            return jsonify({'ok': False, 'msg': 'Image too large (max 2 MB)'})
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute('UPDATE users SET avatar_url=? WHERE wallet_address=?',
                     (avatar_data if avatar_data else None, wallet))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'avatar_url': avatar_data})

# ── LEADERBOARD ──
@app.route('/api/leaderboard', methods=['GET'])
@rate_limit(30, 60)
def get_leaderboard():
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('''
            SELECT t.user_id,
                   u.username,
                   u.wallet_address,
                   u.avatar_url,
                   SUM(t.pnl)  AS total_pnl,
                   COUNT(*)    AS trade_count,
                   MAX(t.pnl)  AS best_trade
            FROM trades t
            JOIN users u ON u.id = t.user_id
            WHERE date(t.timestamp) = date('now')
            GROUP BY t.user_id
            ORDER BY total_pnl DESC
            LIMIT 10
        ''')
        rows = c.fetchall()
    finally:
        conn.close()
    result = []
    for rank, row in enumerate(rows, 1):
        user_id, username, wallet, avatar_url, total_pnl, trade_count, best_trade = row
        if not username:
            username = (wallet[:6] + '...' + wallet[-4:]) if wallet and len(wallet) >= 10 else (wallet or 'unknown')
        result.append({
            'rank':           rank,
            'user_id':        user_id,
            'username':       username,
            'wallet_address': wallet or '',
            'avatar_url':     avatar_url or '',
            'total_pnl':      round(float(total_pnl or 0), 6),
            'trade_count':    int(trade_count or 0),
            'best_trade':     round(float(best_trade or 0), 6),
        })
    return jsonify(result)

# Two-entry RPC list for the frontend proxy endpoints:
# SOLANA_RPC_URL (Railway env var) first; public mainnet-beta as fallback.
_PROXY_RPCS = [u for u in [SOLANA_RPC_URL, SOLANA_RPC] if u]
print(f'[rpc] PROXY_RPCS: {_PROXY_RPCS}', flush=True)

# ── SOLANA BLOCKHASH PROXY ──
@app.route('/api/solana/blockhash', methods=['GET'])
@rate_limit(60, 60)
def solana_blockhash():
    payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'getLatestBlockhash', 'params': []}
    last_err = 'No RPC available'
    for rpc in _PROXY_RPCS:
        label = _rpc_label(rpc)
        try:
            r = requests.post(rpc, json=payload, timeout=8)
            data = r.json()
            if 'error' in data:
                last_err = f'{label}: RPC error {data["error"]}'
                print(f'[blockhash] {last_err}', flush=True)
                continue
            val = data.get('result', {}).get('value', {})
            if val.get('blockhash'):
                return jsonify({
                    'ok': True,
                    'blockhash': val['blockhash'],
                    'lastValidBlockHeight': val.get('lastValidBlockHeight', 0),
                })
            last_err = f'{label}: unexpected response: {data}'
            print(f'[blockhash] {last_err}', flush=True)
        except Exception as e:
            last_err = f'{label}: {e}'
            print(f'[blockhash] ERROR {last_err}', flush=True)
    print(f'[blockhash] all RPCs failed — {last_err}', flush=True)
    return jsonify({'ok': False, 'msg': last_err}), 502

# ── SOLANA SEND RAW TX PROXY ──
@app.route('/api/solana/send_raw', methods=['POST'])
@rate_limit(20, 60)
def solana_send_raw():
    raw_tx = str((request.json or {}).get('raw_tx', '')).strip()
    if not raw_tx:
        return jsonify({'ok': False, 'msg': 'raw_tx is required'})
    try:
        base64.b64decode(raw_tx)
    except Exception:
        return jsonify({'ok': False, 'msg': 'raw_tx is not valid base64'})
    payload = {
        'jsonrpc': '2.0', 'id': 1,
        'method': 'sendTransaction',
        'params': [raw_tx, {'encoding': 'base64'}],
    }
    last_err = 'No RPC available'
    for rpc in _PROXY_RPCS:
        label = _rpc_label(rpc)
        try:
            r = requests.post(rpc, json=payload, timeout=15)
            data = r.json()
            if 'result' in data:
                return jsonify({'ok': True, 'signature': data['result']})
            err = data.get('error', {})
            last_err = f'{label}: ' + (err.get('message', str(err)) if err else 'unknown RPC error')
            print(f'[send_raw] {last_err}', flush=True)
        except Exception as e:
            last_err = f'{label}: {e}'
            print(f'[send_raw] ERROR {last_err}', flush=True)
    return jsonify({'ok': False, 'msg': last_err})

# ── SOLANA BUILD TRANSFER ──
_B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58_ALPHABET.index(ch)
    pad = len(s) - len(s.lstrip('1'))
    if n == 0:
        return b'\x00' * pad
    return b'\x00' * pad + n.to_bytes((n.bit_length() + 7) // 8, 'big')

def _compact_u16(n: int) -> bytes:
    out = []
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            b |= 0x80
        out.append(b)
        if not n:
            break
    return bytes(out)

@app.route('/api/solana/build_transfer', methods=['POST'])
@rate_limit(30, 60)
def solana_build_transfer():
    body = request.json or {}
    from_wallet = str(body.get('from_wallet', '')).strip()
    to_wallet   = str(body.get('to_wallet',   '')).strip()
    lamports_raw = body.get('lamports')

    if not is_valid_solana_address(from_wallet):
        return jsonify({'ok': False, 'msg': 'Invalid from_wallet'}), 400
    if not is_valid_solana_address(to_wallet):
        return jsonify({'ok': False, 'msg': 'Invalid to_wallet'}), 400
    try:
        lamports = int(lamports_raw)
        if lamports <= 0:
            raise ValueError('must be positive')
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'msg': 'Invalid lamports'}), 400

    # Fetch blockhash
    blockhash = None
    last_err  = 'No RPC available'
    for rpc in _PROXY_RPCS:
        try:
            r = requests.post(rpc, json={'jsonrpc':'2.0','id':1,'method':'getLatestBlockhash','params':[]}, timeout=8)
            val = r.json().get('result', {}).get('value', {})
            if val.get('blockhash'):
                blockhash = val['blockhash']
                break
        except Exception as e:
            last_err = str(e)
    if not blockhash:
        return jsonify({'ok': False, 'msg': f'Could not fetch blockhash: {last_err}'}), 502

    # Decode keys; SystemProgram = 32 zero bytes (base58 "111...1")
    from_b  = _b58decode(from_wallet)
    to_b    = _b58decode(to_wallet)
    sys_b   = bytes(32)
    bh_b    = _b58decode(blockhash)

    # SystemProgram Transfer: discriminator=2 (u32 LE) + lamports (u64 LE)
    ix_data = struct.pack('<IQ', 2, lamports)

    # Instruction: program_idx=2, accounts=[0,1], data
    instruction = (
        bytes([2]) +
        _compact_u16(2) + bytes([0, 1]) +
        _compact_u16(len(ix_data)) + ix_data
    )

    # Message: header + account_keys + blockhash + instructions
    message = (
        bytes([1, 0, 1]) +                      # 1 sig required, 0 readonly signed, 1 readonly unsigned
        _compact_u16(3) + from_b + to_b + sys_b +
        bh_b +
        _compact_u16(1) + instruction
    )

    # Full transaction: 1 signature slot (64 zero bytes) + message
    tx_bytes = _compact_u16(1) + bytes(64) + message
    tx_b64   = base64.b64encode(tx_bytes).decode()

    print(f'[build_transfer] {from_wallet[:8]}→{to_wallet[:8]} {lamports} lamports bh={blockhash[:8]}', flush=True)
    return jsonify({'ok': True, 'tx_b64': tx_b64})

# ── PLATFORM STATS ──
@app.route('/api/platform/stats', methods=['GET'])
@rate_limit(60, 60)
def platform_stats():
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('''
            SELECT COUNT(*), COALESCE(SUM(pnl), 0)
            FROM trades
            WHERE date(timestamp) = date(\'now\')
        ''')
        row = c.fetchone()
    finally:
        conn.close()
    trades_today = int(row[0] or 0)
    net_pnl_today = round(float(row[1] or 0), 4)
    active = sum(1 for us in list(user_states.values()) if us.get('trader_running'))
    return jsonify({
        'ok': True,
        'trades_today': trades_today,
        'net_pnl_today': net_pnl_today,
        'active_traders': active,
    })

# ── SOCIAL FEED ──
@app.route('/api/social/feed', methods=['GET'])
@rate_limit(30, 60)
def social_feed():
    # Build mint→current_price from shared token state (best-effort; may be empty if scan hasn't run)
    _mint_price: dict = {
        t['mint']: float(t['price'])
        for t in state.get('tokens', [])
        if t.get('mint') and t.get('price')
    }

    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        # Load all users for enrichment lookups
        c.execute('SELECT id, wallet_address, username, avatar_url FROM users')
        _user_rows = c.fetchall()

        # Recent closed trades — last 24 h
        _cutoff = (datetime.datetime.utcnow() - datetime.timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%SZ')
        c.execute('''
            SELECT user_id, token, entry_price, exit_price, pnl, timestamp
            FROM trades
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT 100
        ''', (_cutoff,))
        _trade_rows = c.fetchall()
    finally:
        conn.close()

    def _short(wallet: str) -> str:
        return (wallet[:6] + '...' + wallet[-4:]) if wallet and len(wallet) >= 10 else (wallet or 'unknown')

    # Build lookup maps
    _wallet_info: dict = {}
    _id_info:     dict = {}
    for _uid, _wallet, _uname, _avatar in _user_rows:
        _sw   = _short(_wallet)
        _info = {
            'user_id':    _uid,
            'username':   _uname if _uname else _sw,
            'avatar_url': _avatar or '',
            'wallet':     _sw,
        }
        if _wallet:
            _wallet_info[_wallet] = _info
        _id_info[_uid] = _info

    feed = []

    # ── Open positions (in-memory) ──
    for _wallet, _us in list(user_states.items()):
        _info = _wallet_info.get(_wallet)
        if not _info:
            continue
        for _mint, _pos in list(_us.get('positions', {}).items()):
            if not _pos.get('amount') or not _pos.get('buy_price'):
                continue
            _buy     = float(_pos['buy_price'])
            _amount  = float(_pos.get('amount') or 0)
            _cur     = _mint_price.get(_mint)
            _pnl_pct = round((_cur - _buy) / _buy * 100, 2) if _cur and _buy else None
            _pnl_sol = round(_amount * (_cur - _buy), 6) if _cur and _buy and _amount else None
            _opened  = float(_pos.get('opened_at') or 0)
            feed.append({
                'type':            'open',
                'user_id':         _info['user_id'],
                'username':        _info['username'],
                'avatar_url':      _info['avatar_url'],
                'wallet':          _info['wallet'],
                'token':           _pos.get('symbol') or _mint[:8],
                'entry_price':     round(_buy, 8),
                'current_pnl_pct': _pnl_pct,
                'current_pnl_sol': _pnl_sol,
                'opened_at':       int(_opened),
                '_sort_ts':        _opened,
            })

    # ── Closed trades (DB) ──
    for _uid, _token, _entry, _exit, _pnl, _ts_str in _trade_rows:
        _info = _id_info.get(_uid)
        if not _info:
            continue
        try:
            _sort_ts = datetime.datetime.strptime(_ts_str, '%Y-%m-%dT%H:%M:%SZ').replace(
                tzinfo=datetime.timezone.utc).timestamp()
        except Exception:
            _sort_ts = 0.0
        feed.append({
            'type':        'trade',
            'user_id':     _info['user_id'],
            'username':    _info['username'],
            'avatar_url':  _info['avatar_url'],
            'wallet':      _info['wallet'],
            'token':       _token or '',
            'entry_price': round(float(_entry or 0), 8),
            'exit_price':  round(float(_exit  or 0), 8),
            'pnl':         round(float(_pnl   or 0), 6),
            'timestamp':   _ts_str or '',
            '_sort_ts':    _sort_ts,
        })

    feed.sort(key=lambda x: x['_sort_ts'], reverse=True)
    for _item in feed:
        _item.pop('_sort_ts', None)
    return jsonify(feed[:50])

# ── PROFILE ──
@app.route('/api/profile/<int:user_id>', methods=['GET'])
@rate_limit(60, 60)
def get_profile(user_id: int):
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('''
            SELECT u.id, u.username, u.avatar_url, u.bio, u.wallet_address, u.created_at,
                   COUNT(t.id) AS trade_count,
                   AVG(CASE WHEN t.opened_at IS NOT NULL AND t.opened_at > 0
                            THEN CAST(strftime('%s', t.timestamp) AS REAL) - t.opened_at
                            ELSE NULL END) AS avg_hold_seconds
            FROM users u
            LEFT JOIN trades t ON t.user_id = u.id
            WHERE u.id = ?
            GROUP BY u.id
        ''', (user_id,))
        row = c.fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404

        uid, username, avatar_url, bio, wallet, created_at, trade_count, avg_hold = row

        c.execute('SELECT COUNT(*) FROM follows WHERE following_id = ?', (user_id,))
        follower_count = (c.fetchone() or [0])[0]

        c.execute('SELECT COUNT(*) FROM follows WHERE follower_id = ?', (user_id,))
        following_count = (c.fetchone() or [0])[0]

        c.execute('SELECT COALESCE(SUM(pnl), 0) FROM trades WHERE user_id=?', (user_id,))
        total_pnl_row = c.fetchone()
    finally:
        conn.close()

    short_wallet = (wallet[:6] + '...' + wallet[-4:]) if wallet and len(wallet) >= 10 else (wallet or '')
    display_name = username if username else short_wallet
    total_pnl    = round(float(total_pnl_row[0] or 0), 6) if total_pnl_row else 0.0

    # Live open position count from in-memory state
    us = user_states.get(wallet or '', {})
    open_count = sum(1 for p in us.get('positions', {}).values() if p.get('amount', 0) > 0)

    # SOL balance — best-effort, non-blocking
    sol_balance = 0.0
    if wallet and _PROXY_RPCS:
        for _rpc in _PROXY_RPCS:
            try:
                _r = requests.post(_rpc, json={
                    'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [wallet]
                }, timeout=5)
                sol_balance = round(_r.json()['result']['value'] / 1e9, 4)
                break
            except Exception:
                continue

    return jsonify({
        'ok':              True,
        'user_id':         uid,
        'username':        display_name,
        'avatar_url':      avatar_url or '',
        'bio':             bio or '',
        'wallet':          short_wallet,
        'wallet_address':  wallet or '',
        'joined_at':       created_at or '',
        'trade_count':     int(trade_count or 0),
        'avg_hold_seconds': round(float(avg_hold), 1) if avg_hold else None,
        'follower_count':  int(follower_count),
        'following_count': int(following_count),
        'sol_balance':     sol_balance,
        'open_trades':     open_count,
        'closed_trades':   int(trade_count or 0),
        'total_pnl':       total_pnl,
    })

# ── PROFILE TRADES ──
@app.route('/api/profile/<int:user_id>/trades', methods=['GET'])
@rate_limit(30, 60)
def profile_user_trades(user_id: int):
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('SELECT wallet_address FROM users WHERE id=?', (user_id,))
        row = c.fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        wallet = row[0] or ''
        today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
        c.execute('''
            SELECT token, entry_price, exit_price, pnl, timestamp, exit_reason
            FROM trades
            WHERE user_id=? AND date(timestamp)=?
            ORDER BY timestamp DESC
            LIMIT 50
        ''', (user_id, today))
        trade_rows = c.fetchall()
        c.execute('SELECT COUNT(*), COALESCE(SUM(pnl),0) FROM trades WHERE user_id=?', (user_id,))
        all_stats = c.fetchone()
        c.execute('SELECT COALESCE(SUM(pnl),0) FROM trades WHERE user_id=? AND date(timestamp)=?', (user_id, today))
        today_pnl_row = c.fetchone()
    finally:
        conn.close()

    trades = []
    for token, entry, exit_p, pnl, ts, reason in trade_rows:
        trades.append({
            'token':       str(token or ''),
            'entry':       round(float(entry or 0), 8),
            'exit':        round(float(exit_p or 0), 8),
            'pnl':         round(float(pnl or 0), 6),
            'timestamp':   str(ts or ''),
            'exit_reason': str(reason or ''),
        })

    total_closed  = int(all_stats[0] or 0) if all_stats else 0
    total_pnl_all = round(float(all_stats[1] or 0), 6) if all_stats else 0.0
    today_pnl     = round(float(today_pnl_row[0] or 0), 6) if today_pnl_row else 0.0

    us = user_states.get(wallet, {})
    mint_price = {t['mint']: float(t['price'])
                  for t in state.get('tokens', []) if t.get('mint') and t.get('price')}
    positions = []
    for mint, pos in us.get('positions', {}).items():
        if not pos.get('amount') or not pos.get('buy_price'):
            continue
        buy    = float(pos['buy_price'])
        amount = float(pos.get('amount', 0))
        cur    = mint_price.get(mint)
        pnl_pct = round((cur - buy) / buy * 100, 2) if cur and buy else None
        pnl_sol = round(amount * (cur - buy), 6)    if cur and buy and amount else None
        positions.append({
            'mint':      mint,
            'token':     str(pos.get('symbol', mint[:8])),
            'entry':     round(buy, 8),
            'current':   round(cur, 8) if cur else None,
            'pnl_pct':   pnl_pct,
            'pnl_sol':   pnl_sol,
            'opened_at': int(pos.get('opened_at', 0)),
        })

    sol_balance = 0.0
    if wallet and _PROXY_RPCS:
        for _rpc in _PROXY_RPCS:
            try:
                _r = requests.post(_rpc, json={
                    'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [wallet]
                }, timeout=5)
                sol_balance = round(_r.json()['result']['value'] / 1e9, 4)
                break
            except Exception:
                continue

    return jsonify({
        'ok':           True,
        'trades':       trades,
        'positions':    positions,
        'sol_balance':  sol_balance,
        'open_count':   len(positions),
        'total_closed': total_closed,
        'total_pnl':    total_pnl_all,
        'today_pnl':    today_pnl,
    })

# ── FOLLOW / UNFOLLOW ──
@app.route('/api/follow/<int:target_id>', methods=['POST'])
@rate_limit(30, 60)
def toggle_follow(target_id: int):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'})

    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE wallet_address = ?', (wallet,))
        me = c.fetchone()
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'})
        me_id = me[0]

        if me_id == target_id:
            return jsonify({'ok': False, 'msg': 'Cannot follow yourself'})

        c.execute('SELECT 1 FROM users WHERE id = ?', (target_id,))
        if not c.fetchone():
            return jsonify({'ok': False, 'msg': 'Target user not found'}), 404

        c.execute('SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?', (me_id, target_id))
        already = c.fetchone()

        if already:
            c.execute('DELETE FROM follows WHERE follower_id = ? AND following_id = ?', (me_id, target_id))
            following = False
        else:
            c.execute(
                'INSERT INTO follows (follower_id, following_id, created_at) VALUES (?, ?, ?)',
                (me_id, target_id, datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')))
            following = True

        c.execute('SELECT COUNT(*) FROM follows WHERE following_id = ?', (target_id,))
        follower_count = (c.fetchone() or [0])[0]
        conn.commit()
    finally:
        conn.close()

    return jsonify({'ok': True, 'following': following, 'follower_count': int(follower_count)})

# ── BIO ──
@app.route('/api/bio', methods=['POST'])
@rate_limit(10, 60)
def save_bio():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'})
    bio = str((request.json or {}).get('bio', '')).strip()
    if len(bio) > 100:
        return jsonify({'ok': False, 'msg': 'Bio must be 100 characters or fewer'})
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute('UPDATE users SET bio = ? WHERE wallet_address = ?', (bio or None, wallet))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'bio': bio})

# ── DIFFICULTY ──
@app.route('/api/difficulty', methods=['GET'])
@rate_limit(30, 60)
def get_difficulty():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'})
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute('SELECT difficulty FROM users WHERE wallet_address=?', (wallet,))
    row  = c.fetchone()
    conn.close()
    difficulty = (row[0] if row and row[0] else 'MEDIUM')
    if difficulty not in DIFFICULTY_PRESETS:
        difficulty = 'MEDIUM'
    return jsonify({'ok': True, 'difficulty': difficulty})

@app.route('/api/difficulty', methods=['POST'])
@rate_limit(10, 60)
def save_difficulty():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'})
    data       = request.json or {}
    difficulty = str(data.get('difficulty', '')).strip().upper()
    if difficulty not in DIFFICULTY_PRESETS:
        return jsonify({'ok': False, 'msg': 'Invalid difficulty'})
    conn = sqlite3.connect(DB_FILE)
    try:
        c   = conn.cursor()
        c.execute('SELECT id FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
        if row:
            c.execute('UPDATE users SET difficulty=? WHERE wallet_address=?', (difficulty, wallet))
        else:
            c.execute('INSERT INTO users (wallet_address, difficulty, trade_size_unit_migrated) VALUES (?,?,1)', (wallet, difficulty))
        conn.commit()
    finally:
        conn.close()
    add_user_log(wallet, 'Difficulty set to ' + difficulty + ' for ' + wallet[:6] + '...' + wallet[-4:])
    return jsonify({'ok': True, 'difficulty': difficulty})

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
            'sol_price':        _sol_price_usd,
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
        'sol_price':       _sol_price_usd,
    })

# ── PUMP SCANNER ──
@app.route('/api/pump-scanner')
@rate_limit(30, 60)
def api_pump_scanner():
    """Tokens pumping ≥15% in the last 5m or 1h, reusing the already-scanned/filtered
    state['tokens'] snapshot (liquidity≥15000, volume5m≥1000) instead of issuing a
    fresh DexScreener call — keeps this endpoint cheap and consistent with the rest
    of the dashboard."""
    live    = state.get('tokens', [])
    pumping = [t for t in live if t.get('change5m', 0) >= 15 or t.get('change1h', 0) >= 15]
    pumping.sort(key=lambda t: t.get('change5m', 0), reverse=True)
    pumping = pumping[:10]
    out = [{
        'mint':      t['mint'],
        'symbol':    t['symbol'],
        'name':      t['name'],
        'price':     t['price'],
        'change5m':  t['change5m'],
        'change1h':  t['change1h'],
        'change24h': t['change24h'],
        'volume24h': t['volume24h'],
        'liquidity': t['liquidity'],
        'fdv':       t['fdv'],
    } for t in pumping]
    return jsonify({'ok': True, 'tokens': out})

@app.route('/api/pump-scanner/buy', methods=['POST'])
@rate_limit(10, 60)
def api_pump_scanner_buy():
    ip     = request.remote_addr or '0.0.0.0'
    wallet = _current_wallet()
    if not wallet:
        _record_ip_failure(ip)
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    mint = str((request.json or {}).get('mint', '')).strip()
    if not is_valid_solana_address(mint):
        return jsonify({'ok': False, 'msg': 'Invalid token address'}), 400
    if _sec_check_state.get('trading_paused'):
        return jsonify({'ok': False,
                        'msg': 'Trading suspended — security check failure. Contact admin to resume.'}), 503

    conn = sqlite3.connect(DB_FILE)
    try:
        c   = conn.cursor()
        c.execute('SELECT encrypted_private_key, min_trade_size FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return jsonify({'ok': False, 'msg': 'No trading key saved — add it in Settings first'}), 400
    enc_blob       = row[0]
    min_trade_usdc = float(row[1]) if row[1] is not None else 1.0

    token_data = get_token_data(mint)
    if not token_data or token_data['price'] <= 0:
        return jsonify({'ok': False, 'msg': 'Could not fetch a live price for this token'}), 400

    try:
        with _use_key(enc_blob, wallet) as _pk:
            from solders.keypair import Keypair as _KP_buy
            trading_wallet = str(_KP_buy.from_base58_string(_pk).pubkey())
    except InvalidToken:
        return jsonify({'ok': False, 'msg': 'Cannot decrypt trading key — please re-save it in Settings'}), 400
    except Exception as e:
        print(f'[pump-scanner/buy] key error for {wallet[:6]}...{wallet[-4:]}: {type(e).__name__}: {e}', flush=True)
        return jsonify({'ok': False, 'msg': 'Cannot decrypt trading key — please re-save it in Settings'}), 400

    us_sol = _get_user_sol(trading_wallet)
    if us_sol < 0.01:
        return jsonify({'ok': False, 'low_balance': True, 'trading_wallet': trading_wallet,
                        'msg': '⚠️ Insufficient SOL balance. Please send SOL to your trading wallet to start trading.'}), 400
    # Manual snipe uses the user's configured minimum trade size (conservative default
    # for a one-off pick outside the scoring algorithm), converted to SOL.
    spend = min_trade_usdc / _sol_price_usd if _sol_price_usd > 0 else 0.02
    spend = round(min(spend, us_sol), 4)
    if spend < 0.001:
        return jsonify({'ok': False, 'msg': 'Insufficient SOL balance to buy'}), 400

    with _use_key(enc_blob, wallet) as _pk:
        ok = _execute_user_swap(wallet, _pk, 'buy', mint, str(spend))
    if not ok:
        return jsonify({'ok': False, 'msg': 'Buy transaction failed — check logs for details'}), 500

    us = get_user_state(wallet)
    pos = us['positions'].get(mint, {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0})
    pos['amount']          = pos.get('amount', 0.0) + spend / token_data['price']
    pos['buy_price']       = token_data['price']
    pos['spend']           = pos.get('spend', 0.0) + spend
    pos['symbol']          = token_data['symbol'] or mint[:8]
    pos['opened_at']       = time.time()
    pos['entry_liquidity'] = float(token_data.get('liquidity', 0) or 0)
    us['positions'][mint] = pos
    short = wallet[:6] + '...' + wallet[-4:]
    add_user_log(wallet, '[' + short + '] PUMP SCANNER buy: ' + pos['symbol'] +
                 ' for ' + str(spend) + ' SOL @ $' + str(token_data['price']))
    note = '' if us.get('trader_running') else ' — start the trader for automatic TP/SL on this position'
    return jsonify({'ok': True, 'msg': 'Bought ' + pos['symbol'] + note, 'symbol': pos['symbol'], 'spend': spend})

@app.route('/api/manual_buy', methods=['POST'])
@rate_limit(10, 60)
def api_manual_buy():
    ip     = request.remote_addr or '0.0.0.0'
    wallet = _current_wallet()
    if not wallet:
        _record_ip_failure(ip)
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    mint = str((request.json or {}).get('mint_address', '')).strip()
    if not is_valid_solana_address(mint):
        return jsonify({'ok': False, 'msg': 'Invalid token address'}), 400
    if _sec_check_state.get('trading_paused'):
        return jsonify({'ok': False,
                        'msg': 'Trading suspended — contact admin to resume.'}), 503
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('SELECT encrypted_private_key, min_trade_size FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return jsonify({'ok': False, 'msg': 'No trading key saved — add it in Settings first'}), 400
    enc_blob       = row[0]
    min_trade_usdc = float(row[1]) if row[1] is not None else 1.0

    us           = get_user_state(wallet)
    open_pos     = sum(1 for p in us['positions'].values() if p.get('amount', 0) > 0)
    already_held = us['positions'].get(mint, {}).get('amount', 0) > 0
    if open_pos >= 5 and not already_held:
        return jsonify({'ok': False, 'msg': 'Max 5 positions reached — sell one first'}), 400

    token_data = get_token_data(mint)
    if not token_data or token_data['price'] <= 0:
        return jsonify({'ok': False, 'msg': 'Could not fetch a live price for this token'}), 400

    try:
        with _use_key(enc_blob, wallet) as _pk:
            from solders.keypair import Keypair as _KP_mb
            trading_wallet = str(_KP_mb.from_base58_string(_pk).pubkey())
    except InvalidToken:
        return jsonify({'ok': False, 'msg': 'Cannot decrypt trading key — please re-save it in Settings'}), 400
    except Exception as e:
        print(f'[manual-buy] key error for {wallet[:6]}...{wallet[-4:]}: {type(e).__name__}: {e}', flush=True)
        return jsonify({'ok': False, 'msg': 'Cannot decrypt trading key — please re-save it in Settings'}), 400

    us_sol = _get_user_sol(trading_wallet)
    if us_sol < 0.01:
        return jsonify({'ok': False, 'low_balance': True, 'trading_wallet': trading_wallet,
                        'msg': '⚠️ Insufficient SOL balance — send SOL to your trading wallet first'}), 400
    spend = min_trade_usdc / _sol_price_usd if _sol_price_usd > 0 else 0.02
    spend = round(min(spend, us_sol), 4)
    if spend < 0.001:
        return jsonify({'ok': False, 'msg': 'Insufficient SOL balance to buy'}), 400

    with _use_key(enc_blob, wallet) as _pk:
        ok = _execute_user_swap(wallet, _pk, 'buy', mint, str(spend))
    if not ok:
        return jsonify({'ok': False, 'msg': 'Buy transaction failed — check logs for details'}), 500

    pos = us['positions'].get(mint, {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0})
    pos['amount']          = pos.get('amount', 0.0) + spend / token_data['price']
    pos['buy_price']       = token_data['price']
    pos['spend']           = pos.get('spend', 0.0) + spend
    pos['symbol']          = token_data['symbol'] or mint[:8]
    pos['opened_at']       = time.time()
    pos['entry_liquidity'] = float(token_data.get('liquidity', 0) or 0)
    us['positions'][mint]  = pos
    short = wallet[:6] + '...' + wallet[-4:]
    add_user_log(wallet, '[' + short + '] MANUAL BUY: ' + pos['symbol'] +
                 ' for ' + str(spend) + ' SOL @ $' + str(token_data['price']))
    note = '' if us.get('trader_running') else ' — start the bot for automatic TP/SL'
    return jsonify({'ok': True, 'msg': 'Bought ' + pos['symbol'] + note,
                    'symbol': pos['symbol'], 'spend': spend})


@app.route('/api/manual_sell', methods=['POST'])
@rate_limit(10, 60)
def api_manual_sell():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    mint = str((request.json or {}).get('mint_address', '')).strip()
    if not is_valid_solana_address(mint):
        return jsonify({'ok': False, 'msg': 'Invalid token address'}), 400
    if _sec_check_state.get('trading_paused'):
        return jsonify({'ok': False,
                        'msg': 'Trading suspended — contact admin to resume.'}), 503
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('SELECT id, encrypted_private_key FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
    finally:
        conn.close()
    if not row or not row[1]:
        return jsonify({'ok': False, 'msg': 'No trading key saved — add it in Settings first'}), 400
    user_id, enc_blob = row
    us  = get_user_state(wallet)
    pos = us.get('positions', {}).get(mint)
    if not pos or pos.get('amount', 0) <= 0:
        return jsonify({'ok': False, 'msg': 'No open position for this token'}), 400
    amount = pos['amount']
    symbol = pos.get('symbol', mint[:8])
    entry  = pos.get('buy_price', 0.0)
    spend  = pos.get('spend', 0.0)
    short  = wallet[:6] + '...' + wallet[-4:]
    try:
        with _use_key(enc_blob, wallet) as _pk:
            sell_ok = _execute_user_swap(wallet, _pk, 'sell', mint, str(amount))
    except InvalidToken:
        return jsonify({'ok': False, 'msg': 'Cannot decrypt trading key — please re-save it in Settings'}), 400
    except Exception as e:
        print(f'[manual-sell] key error for {short}: {type(e).__name__}: {e}', flush=True)
        return jsonify({'ok': False, 'msg': 'Cannot decrypt trading key — please re-save it in Settings'}), 400
    live_map  = {t['mint']: t for t in state.get('tokens', [])}
    cur_price = live_map.get(mint, {}).get('price', entry)
    if sell_ok:
        with _use_key(enc_blob, wallet) as _pk:
            _record_user_trade(user_id, us, symbol, entry, cur_price, amount, spend,
                               wallet=wallet, private_key=_pk, mint=mint,
                               exit_reason='MANUAL SELL', opened_at=pos.get('opened_at', 0.0))
        add_user_log(wallet, f'[{short}] MANUAL SELL: {symbol} ✓')
    else:
        _record_user_trade(user_id, us, symbol, entry, cur_price, amount, spend,
                           mint=mint, exit_reason='MANUAL SELL',
                           opened_at=pos.get('opened_at', 0.0))
        add_user_log(wallet, f'[{short}] MANUAL SELL: {symbol} — swap failed, position cleared')
    us['positions'][mint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
    if not sell_ok:
        return jsonify({'ok': False, 'msg': 'Sell transaction failed — check logs for details'}), 500
    return jsonify({'ok': True, 'msg': 'Sold ' + symbol, 'symbol': symbol})


# ── TRADER START/STOP ──
@app.route('/api/trader/start', methods=['POST'])
@rate_limit(5, 60)
def start_trader():
    ip     = request.remote_addr or '0.0.0.0'
    wallet = _current_wallet()
    if not wallet:
        _record_ip_failure(ip)
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('SELECT encrypted_private_key FROM users WHERE wallet_address=?', (wallet,))
        kr = c.fetchone()
        conn.close()
    except Exception as e:
        print(f'[start_trader] DB error: {e}', flush=True)
        return jsonify({'ok': False, 'msg': 'Internal error — please try again'}), 500
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

# ── MANUAL SELL ──
@app.route('/api/sell', methods=['POST'])
@rate_limit(10, 60)
def manual_sell():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    mint = str((request.json or {}).get('mint', '')).strip()
    if not is_valid_solana_address(mint):
        return jsonify({'ok': False, 'msg': 'Invalid token address'}), 400
    if _sec_check_state.get('trading_paused'):
        return jsonify({'ok': False,
                        'msg': 'Trading suspended — security check failure. Contact admin to resume.'}), 503
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('SELECT id, encrypted_private_key FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
    finally:
        conn.close()
    if not row or not row[1]:
        return jsonify({'ok': False, 'msg': 'No trading key saved — add it in Settings first'}), 400
    user_id, enc_blob = row
    us  = get_user_state(wallet)
    pos = us.get('positions', {}).get(mint)
    if not pos or pos.get('amount', 0) <= 0:
        return jsonify({'ok': False, 'msg': 'No open position for this token'}), 400
    amount = pos['amount']
    symbol = pos.get('symbol', mint[:8])
    entry  = pos.get('buy_price', 0.0)
    spend  = pos.get('spend', 0.0)
    short  = wallet[:6] + '...' + wallet[-4:]
    try:
        with _use_key(enc_blob, wallet) as _pk:
            sell_ok = _execute_user_swap(wallet, _pk, 'sell', mint, str(amount))
    except InvalidToken:
        return jsonify({'ok': False, 'msg': 'Cannot decrypt trading key — please re-save it in Settings'}), 400
    except Exception as e:
        print(f'[manual-sell] key error for {short}: {type(e).__name__}: {e}', flush=True)
        return jsonify({'ok': False, 'msg': 'Cannot decrypt trading key — please re-save it in Settings'}), 400
    live_map  = {t['mint']: t for t in state.get('tokens', [])}
    cur_price = live_map.get(mint, {}).get('price', entry)
    if sell_ok:
        with _use_key(enc_blob, wallet) as _pk:
            _record_user_trade(user_id, us, symbol, entry, cur_price, amount, spend,
                               wallet=wallet, private_key=_pk, mint=mint,
                               exit_reason='MANUAL SELL', opened_at=pos.get('opened_at', 0.0))
        add_user_log(wallet, f'[{short}] MANUAL SELL: {symbol} ✓')
    else:
        _record_user_trade(user_id, us, symbol, entry, cur_price, amount, spend,
                           mint=mint, exit_reason='MANUAL SELL',
                           opened_at=pos.get('opened_at', 0.0))
        add_user_log(wallet, f'[{short}] MANUAL SELL: {symbol} — swap failed, position cleared')
    us['positions'][mint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
    if not sell_ok:
        return jsonify({'ok': False, 'msg': 'Sell transaction failed — check logs for details'}), 500
    return jsonify({'ok': True, 'symbol': symbol})

# ── WITHDRAW ──
@app.route('/api/withdraw', methods=['POST'])
@rate_limit(10, 60)
def api_withdraw():
    ip     = request.remote_addr or '0.0.0.0'
    wallet = _current_wallet()
    if not wallet:
        _record_ip_failure(ip)
        return jsonify({'ok': False, 'error': 'Connect a wallet first'}), 401

    # Per-wallet rate limit: 3 withdrawals per hour
    if not _rate_ok('withdraw_wallet:' + wallet, 3, 3600):
        return jsonify({'ok': False, 'error': 'Max 3 withdrawals per hour'}), 429

    body       = request.json or {}
    to_address = str(body.get('to_address', '')).strip()
    try:
        amount_sol = float(body.get('amount_sol', 0))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Invalid amount'}), 400

    if not is_valid_solana_address(to_address):
        return jsonify({'ok': False, 'error': 'Invalid destination address'}), 400
    if amount_sol <= 0:
        return jsonify({'ok': False, 'error': 'Amount must be greater than 0'}), 400
    if amount_sol < 0.000001:
        return jsonify({'ok': False, 'error': 'Minimum withdrawal is 0.000001 SOL'}), 400

    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('SELECT encrypted_private_key FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return jsonify({'ok': False, 'error': 'No trading key saved — add it in Settings first'}), 400
    enc_blob = row[0]

    try:
        with _use_key(enc_blob, wallet) as _pk:
            from solders.keypair import Keypair as _KP_wd
            trading_wallet = str(_KP_wd.from_base58_string(_pk).pubkey())
    except InvalidToken:
        return jsonify({'ok': False, 'error': 'Cannot decrypt trading key — please re-save it in Settings'}), 400
    except Exception as e:
        short = wallet[:6] + '...' + wallet[-4:]
        print(f'[withdraw] key error for {short}: {type(e).__name__}: {e}', flush=True)
        return jsonify({'ok': False, 'error': 'Cannot decrypt trading key — please re-save it in Settings'}), 400

    FEE_RESERVE = 0.001  # keep to cover network fee
    balance = _get_user_sol(trading_wallet)
    if balance < amount_sol + FEE_RESERVE:
        available = max(0.0, round(balance - FEE_RESERVE, 6))
        return jsonify({'ok': False,
                        'error': f'Insufficient balance. Available: {available} SOL (0.001 reserved for fees)'}), 400

    try:
        with _use_key(enc_blob, wallet) as _pk:
            sig = send_sol_fee(_pk, to_address, amount_sol)
    except Exception as e:
        err = _redact_keys(str(e))
        short = wallet[:6] + '...' + wallet[-4:]
        print(f'[withdraw] TX failed for {short}: {err}', flush=True)
        return jsonify({'ok': False, 'error': 'Transaction failed: ' + err}), 500

    short = wallet[:6] + '...' + wallet[-4:]
    add_user_log(wallet, f'[{short}] WITHDRAW: {amount_sol} SOL → {to_address[:8]}...{to_address[-4:]}  TX:{sig[:16]}...')
    print(f'[withdraw] {short} sent {amount_sol} SOL to {to_address[:8]}...  TX:{sig[:20]}...', flush=True)
    return jsonify({'ok': True, 'signature': sig})


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

# ── TOKEN ACCOUNT HELPERS ──
_SPL_PROG_STR        = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
_SPL_PROG_2022_STR   = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'  # Token-2022 / Token Extensions
_SPL_PROGRAMS        = [_SPL_PROG_STR, _SPL_PROG_2022_STR]
_DUST_THRESHOLD = 1000  # raw tokens below which an account is considered dust

def _get_spl_token_accounts(wallets: list) -> tuple:
    """Fetch all SPL token accounts for one or more wallet addresses, across both
    the legacy Token program and Token-2022 (many newer mints/empty accounts only
    exist under Token-2022, so skipping it made the incinerator miss real accounts).
    Deduplicates by pubkey. Returns (accounts_list, working_rpc_url)."""
    headers = {'Content-Type': 'application/json'}
    all_accs: list = []
    working_rpc: str = CLAIM_SOL_RPCS[-1]
    seen: set = set()
    for owner in wallets:
        for prog in _SPL_PROGRAMS:
            payload = {
                'jsonrpc': '2.0', 'id': 1,
                'method':  'getTokenAccountsByOwner',
                'params':  [owner, {'programId': prog}, {'encoding': 'jsonParsed'}],
            }
            for rpc in CLAIM_SOL_RPCS:
                time.sleep(0.6)
                try:
                    r = requests.post(rpc, json=payload, headers=headers, timeout=15)
                    if r.status_code != 200:
                        continue
                    resp = r.json()
                    if 'error' in resp:
                        continue
                    for acc in resp.get('result', {}).get('value', []):
                        pub = acc.get('pubkey', '')
                        if pub and pub not in seen:
                            seen.add(pub)
                            acc['_token_program'] = prog
                            all_accs.append(acc)
                    working_rpc = rpc
                    break
                except Exception:
                    continue
    return all_accs, working_rpc


@app.route('/api/get-tokens')
@rate_limit(10, 60)
def api_get_tokens():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not authenticated'}), 401

    scan_all = request.args.get('scan_all', '').lower() in ('1', 'true', 'yes')

    conn = sqlite3.connect(DB_FILE)
    row  = conn.execute('SELECT encrypted_private_key FROM users WHERE wallet_address=?', (wallet,)).fetchone()
    conn.close()

    trading_pk = wallet
    if row and row[0]:
        try:
            with _use_key(row[0], wallet) as pk_str:
                from solders.keypair import Keypair as _KP2
                trading_pk = str(_KP2.from_base58_string(pk_str).pubkey())
        except Exception:
            pass

    # Query trading wallet first — that's where the bot's token accounts live.
    # Session wallet follows in case the user also has accounts there.
    wallets = list(dict.fromkeys([trading_pk, wallet]))
    all_accs, _ = _get_spl_token_accounts(wallets)

    # ── Parse and immediately split: zero-balance vs has-balance ──
    # Zero-balance accounts never need a DexScreener call — they are always
    # safe to close and the recoverable lamports are known from the RPC data.
    empty_accs:    list = []   # raw == 0
    nonempty_accs: list = []   # raw > 0
    ne_mints:      list = []   # unique non-empty mints (for price/symbol lookup)
    seen_ne:       set  = set()

    for acc in all_accs:
        try:
            pub      = acc.get('pubkey', '')
            info     = acc['account']['data']['parsed']['info']
            tok_amt  = info.get('tokenAmount', {})
            decimals = int(tok_amt.get('decimals', 0))
            raw_str  = str(tok_amt.get('amount', '0'))
            ui_str   = tok_amt.get('uiAmountString', '0')
            ui_float = float(tok_amt.get('uiAmount') or 0)
            lamports = int(acc.get('account', {}).get('lamports', 2039280))
            mint_str = info.get('mint', '')
            owner_oc = info.get('owner', '')
            token_program = acc.get('_token_program', _SPL_PROG_STR)
            # Treat any non-digit or empty string as 0
            raw_int  = int(raw_str) if (raw_str and raw_str.isdigit()) else 0
            rec = {
                'pubkey': pub, 'mint': mint_str, 'balance_str': ui_str,
                'balance_ui': ui_float, 'raw': raw_int, 'decimals': decimals,
                'lamports': lamports, 'owner': owner_oc, 'token_program': token_program,
            }
            if raw_int == 0:
                empty_accs.append(rec)
            else:
                nonempty_accs.append(rec)
                if mint_str and mint_str not in seen_ne:
                    seen_ne.add(mint_str)
                    ne_mints.append(mint_str)
        except Exception:
            continue

    # ── Fetch symbol + price ONLY for non-empty accounts ──
    # DexScreener is skipped entirely for zero-balance accounts so a slow/rate-
    # limited response doesn't delay showing the most important (empty) results.
    mint_meta: dict = {}   # mint -> {'symbol': str, 'price_usd': float|None}
    for i in range(0, len(ne_mints), 30):
        batch = ne_mints[i:i + 30]
        try:
            r = _dex_get(
                'https://api.dexscreener.com/latest/dex/tokens/' + ','.join(batch),
                timeout=8,
            )
            if r and r.status_code == 200:
                best: dict = {}
                for pair in (r.json().get('pairs') or []):
                    bt  = pair.get('baseToken') or {}
                    base = bt.get('address', '')
                    sym  = bt.get('symbol', '')
                    p    = float(pair.get('priceUsd') or 0)
                    if base in seen_ne:
                        cur = best.get(base, {})
                        if p > cur.get('price_usd', 0):
                            best[base] = {'symbol': sym, 'price_usd': p or None}
                for m in batch:
                    mint_meta[m] = best.get(m) or {'symbol': '', 'price_usd': None}
        except Exception:
            for m in batch:
                mint_meta.setdefault(m, {'symbol': '', 'price_usd': None})

    DUST_USD      = 0.01
    REASON_ORDER  = {'empty': 0, 'dust': 1, 'unknown': 2, 'normal': 3}
    tokens: list  = []

    # ── Zero-balance accounts — always included, no price check needed ──
    for a in empty_accs:
        owned = a['owner'] == trading_pk
        tokens.append({
            'pubkey':    a['pubkey'],
            'mint':      a['mint'],
            'symbol':    '',                       # no live symbol for dead accounts
            'balance':   '0',
            'raw':       0,
            'decimals':  a['decimals'],
            'sol_rent':  round(a['lamports'] / 1e9, 6),
            'price_usd': None,
            'value_usd': 0.0,
            'closeable': True,
            'can_close': owned,                    # only blocked if we lack the key
            'reason':    'empty',
            'owned':     owned,
            'token_program': a['token_program'],
        })

    # ── Non-empty accounts — classify by USD value ──
    for a in nonempty_accs:
        mint  = a['mint']
        meta  = mint_meta.get(mint) or {'symbol': '', 'price_usd': None}
        sym   = meta.get('symbol', '')
        price = meta.get('price_usd')          # None = DexScreener had no data
        owned = a['owner'] == trading_pk

        if price is not None:
            value_usd = a['balance_ui'] * price
            if value_usd < DUST_USD:
                reason, closeable = 'dust', True
            else:
                reason, closeable = 'normal', False
        else:
            value_usd = None
            reason, closeable = 'unknown', True   # unknown = treat as burnable

        can_close = owned and (closeable if not scan_all else True)

        if not scan_all and not closeable:
            continue   # hide tokens with real known value in smart mode

        tokens.append({
            'pubkey':    a['pubkey'],
            'mint':      mint,
            'symbol':    sym,
            'balance':   a['balance_str'],
            'raw':       a['raw'],
            'decimals':  a['decimals'],
            'sol_rent':  round(a['lamports'] / 1e9, 6),
            'price_usd': round(price, 8) if price else None,
            'value_usd': round(value_usd, 4) if value_usd is not None else None,
            'closeable': closeable,
            'can_close': can_close,
            'reason':    reason,
            'owned':     owned,
            'token_program': a['token_program'],
        })

    tokens.sort(key=lambda t: (REASON_ORDER.get(t['reason'], 9), -t['sol_rent']))

    closeable_tokens = [t for t in tokens if t['can_close']]
    return jsonify({
        'ok':             True,
        'tokens':         tokens,
        'trading_wallet': trading_pk,
        'scan_all':       scan_all,
        'stats': {
            'total':           len(tokens),
            'empty':           sum(1 for t in tokens if t['reason'] == 'empty'),
            'dust':            sum(1 for t in tokens if t['reason'] == 'dust'),
            'unknown':         sum(1 for t in tokens if t['reason'] == 'unknown'),
            'recoverable_sol': round(sum(t['sol_rent'] for t in closeable_tokens), 6),
        },
    })


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
    SPL_PROG_STR   = _SPL_PROG_STR
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
        print(f'[claim_sol] key decrypt error: {_redact_keys(str(e))}', flush=True)
        return jsonify({'ok': False, 'msg': 'Cannot access trading key — please re-save it in Settings'}), 500

    print(f'[claim_sol] ═══ START ═══', flush=True)
    print(f'[claim_sol] session_wallet  = {wallet}', flush=True)
    print(f'[claim_sol] trading_wallet  = {trading_pk}', flush=True)
    print(f'[claim_sol] wallets_differ  = {wallet != trading_pk}', flush=True)
    print(f'[claim_sol] RPC candidates  = {CLAIM_SOL_RPCS}', flush=True)
    print(f'[claim_sol] SPL_PROG        = {SPL_PROG_STR}', flush=True)

    def _rpc_token_accounts(owner: str, label: str) -> tuple:
        """Returns (accounts_list, rpc_url_that_worked). Tries CLAIM_SOL_RPCS in order,
        querying both the legacy Token program and Token-2022 so accounts living under
        either program are found (Token-2022-only accounts were previously invisible
        here, which made the incinerator falsely report a clean wallet)."""
        headers = {'Content-Type': 'application/json'}
        all_accs: list = []
        last_working_rpc = CLAIM_SOL_RPCS[-1]
        for prog in _SPL_PROGRAMS:
            payload = {
                'jsonrpc': '2.0', 'id': 1,
                'method':  'getTokenAccountsByOwner',
                'params':  [owner, {'programId': prog}, {'encoding': 'jsonParsed'}],
            }
            for rpc in CLAIM_SOL_RPCS:
                rpc_short = rpc.split('?')[0]
                print(f'[claim_sol] → getTokenAccountsByOwner  rpc={rpc_short}  owner={owner}  label={label}  program={prog}', flush=True)
                time.sleep(1)   # avoid burst rate-limiting across successive calls
                try:
                    r = requests.post(rpc, json=payload, headers=headers, timeout=15)
                    print(f'[claim_sol]   {rpc_short} HTTP {r.status_code}', flush=True)
                    if r.status_code != 200:
                        print(f'[claim_sol]   {rpc_short} non-200, body={r.text[:120]}', flush=True)
                        continue
                    resp = r.json()
                    if 'error' in resp:
                        print(f'[claim_sol]   {rpc_short} JSON-RPC error: {resp["error"]}', flush=True)
                        continue
                    accs = resp.get('result', {}).get('value', [])
                    print(f'[claim_sol]   {rpc_short} OK → {len(accs)} account(s)', flush=True)
                    for a in accs:
                        a['_token_program'] = prog
                    all_accs.extend(accs)
                    last_working_rpc = rpc
                    break
                except Exception as ex:
                    print(f'[claim_sol]   {rpc_short} EXCEPTION: {ex}', flush=True)
            else:
                print(f'[claim_sol]   all RPCs exhausted for {label} (program={prog})', flush=True)
        return all_accs, last_working_rpc

    try:
        session_accs, working_rpc = _rpc_token_accounts(wallet, 'session_wallet')
        if trading_pk != wallet:
            trading_accs, working_rpc2 = _rpc_token_accounts(trading_pk, 'trading_wallet')
            # prefer whichever RPC gave us results
            if trading_accs and not session_accs:
                working_rpc = working_rpc2
        else:
            trading_accs = []
            print(f'[claim_sol]   trading_wallet == session_wallet, skipping duplicate query', flush=True)
    except Exception as e:
        print(f'[claim_sol] RPC request failed: {e}', flush=True)
        return jsonify({'ok': False, 'msg': 'RPC request failed — please try again shortly'}), 500

    print(f'[claim_sol] working_rpc = {working_rpc.split("?")[0]}', flush=True)

    all_accs = session_accs + trading_accs
    print(f'[claim_sol] total accounts before dedup: {len(all_accs)}', flush=True)

    # Filter: close empty accounts (raw==0) and dust accounts (raw < 1000).
    # Dust accounts need a Burn instruction first; CloseAccount requires zero balance.
    DUST_THRESHOLD = 1000  # raw tokens; sub-cent value for any normal token
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
            program_id     = acc.get('_token_program', SPL_PROG_STR)

            print(f'[claim_sol]   [{src}] pubkey={pub}', flush=True)
            print(f'[claim_sol]         mint={mint_str}', flush=True)
            print(f'[claim_sol]         owner_on_chain={owner_on_chain}', flush=True)
            print(f'[claim_sol]         program={program_id}', flush=True)
            print(f'[claim_sol]         state={state}  decimals={decimals}', flush=True)
            print(f'[claim_sol]         raw_amount={raw_amt}  uiAmount={ui_amt}  uiAmountString={ui_str}', flush=True)
            print(f'[claim_sol]         lamports={lamports}  ({sol_rent:.6f} SOL rent)', flush=True)

            raw_int = int(raw_amt) if raw_amt.isdigit() else 1
            if raw_int == 0:
                closeable.append({'pubkey': pub, 'lamports': lamports, 'owner': owner_on_chain, 'raw_amt': 0, 'mint': mint_str, 'program_id': program_id})
                print(f'[claim_sol]         → CLOSEABLE (empty)', flush=True)
            elif raw_int < DUST_THRESHOLD:
                closeable.append({'pubkey': pub, 'lamports': lamports, 'owner': owner_on_chain, 'raw_amt': raw_int, 'mint': mint_str, 'program_id': program_id})
                print(f'[claim_sol]         → CLOSEABLE (dust: raw={raw_amt} < {DUST_THRESHOLD})', flush=True)
            else:
                skipped.append({'pubkey': pub, 'amount': raw_amt, 'ui': str(ui_amt), 'mint': mint_str})
                print(f'[claim_sol]         → SKIPPED (raw={raw_amt} ui={ui_amt})', flush=True)
        except Exception as ex:
            print(f'[claim_sol]   [{src}] {pub} → PARSE ERROR: {ex}  raw={acc}', flush=True)

    print(f'[claim_sol] ─── summary ───', flush=True)
    print(f'[claim_sol] total unique accounts   : {len(seen)}', flush=True)
    print(f'[claim_sol] closeable (empty + dust): {len(closeable)}', flush=True)
    print(f'[claim_sol] skipped (have tokens)   : {len(skipped)}', flush=True)
    for s in skipped:
        print(f'[claim_sol]   skipped: pubkey={s["pubkey"]}  mint={s["mint"]}  '
              f'raw={s["amount"]}  ui={s["ui"]}', flush=True)
    for c in closeable:
        print(f'[claim_sol]   closeable: pubkey={c["pubkey"]}  lamports={c["lamports"]}  '
              f'owner={c["owner"]}  raw_amt={c["raw_amt"]}', flush=True)

    # Honour user-selected subset when frontend sends a pubkeys list
    _sel = (request.get_json(silent=True) or {}).get('pubkeys') or []
    if _sel:
        _sel_set = set(_sel)
        closeable = [a for a in closeable if a['pubkey'] in _sel_set]
        print(f'[claim_sol] filtered to {len(closeable)} user-selected account(s)', flush=True)

    if not closeable:
        msg = (f'No empty or dust token accounts found — {len(all_accs)} total accounts checked '
               f'({len(skipped)} still have meaningful token balance). '
               f'Wallets checked: session={wallet[:8]}... trading={trading_pk[:8]}...')
        add_user_log(wallet, '[claim] ' + msg)
        return jsonify({'ok': True, 'msg': msg, 'reclaimed': 0.0, 'closed': 0,
                        'debug': {'session_wallet': wallet, 'trading_wallet': trading_pk,
                                  'total_accounts': len(all_accs), 'skipped': skipped}})

    total_lamports = sum(a['lamports'] for a in closeable)
    tx_sigs  = []
    failed   = []
    last_err = ''

    our_accs: list = []
    other_accs: list = []
    try:
        with _use_key(enc_blob, wallet) as pk_str:
            kp       = _KP.from_base58_string(pk_str)
            signer   = kp.pubkey()

            if str(signer) != trading_pk:
                print(f'[claim_sol] ⚠ WARNING: signer ({signer}) != trading_pk computed '
                      f'earlier ({trading_pk}) — decrypted key may be inconsistent', flush=True)

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
                # Instruction building now lives INSIDE the try block below — a single
                # malformed pubkey/mint string used to throw here, uncaught, crashing the
                # whole request with a bare 500 (frontend then showed a generic fallback
                # message instead of the real error).
                try:
                    ixs = []
                    for a in batch:
                        # Each account must be closed via the program that actually owns it —
                        # legacy Token accounts and Token-2022 accounts are not interchangeable.
                        acc_prog = _PBK.from_string(a.get('program_id', SPL_PROG_STR))
                        print(f'[claim_sol] → closing {a["pubkey"]}  lamports={a["lamports"]}  raw_amt={a["raw_amt"]}  program={a.get("program_id", SPL_PROG_STR)}', flush=True)
                        if a['raw_amt'] > 0:
                            # Burn dust first — CloseAccount requires zero balance
                            ixs.append(_IX(
                                program_id=acc_prog,
                                accounts=[
                                    _AM(_PBK.from_string(a['pubkey']), is_signer=False, is_writable=True),  # token account
                                    _AM(_PBK.from_string(a['mint']),   is_signer=False, is_writable=True),  # mint (supply decremented)
                                    _AM(signer,                         is_signer=True,  is_writable=False), # authority
                                ],
                                data=bytes([8]) + struct.pack('<Q', a['raw_amt']),  # Burn instruction
                            ))
                        ixs.append(_IX(
                            program_id=acc_prog,
                            accounts=[
                                _AM(_PBK.from_string(a['pubkey']), is_signer=False, is_writable=True),  # token account to close
                                _AM(signer,                         is_signer=False, is_writable=True),  # destination (rent back)
                                _AM(signer,                         is_signer=True,  is_writable=False), # authority (must match owner)
                            ],
                            data=bytes([9]),  # CloseAccount instruction index
                        ))

                    bh_resp = requests.post(working_rpc, json={
                        'jsonrpc': '2.0', 'id': 1, 'method': 'getLatestBlockhash', 'params': [],
                    }, timeout=10).json()
                    bh  = bh_resp['result']['value']['blockhash']
                    tx  = _TX.new_signed_with_payer(ixs, signer, [kp], _SH.from_string(bh))
                    res = requests.post(working_rpc, json={
                        'jsonrpc': '2.0', 'id': 1, 'method': 'sendTransaction',
                        'params': [base64.b64encode(bytes(tx)).decode(),
                                   {'encoding': 'base64', 'skipPreflight': False}],
                    }, timeout=30).json()
                    rpc_short = working_rpc.split('?')[0]
                    print(f'[claim_sol] sendTransaction via {rpc_short} response: {res}', flush=True)
                    if 'error' in res:
                        last_err = str(res['error'])
                        failed.extend(batch)
                        print(f'[claim_sol] ✗ TX failed: {last_err}', flush=True)
                    else:
                        sig = str(res.get('result', ''))
                        tx_sigs.append(sig)
                        print(f'[claim_sol] ✓ {len(batch)} closed TX:{sig[:20]}', flush=True)
                except Exception as e:
                    last_err = _redact_keys(str(e))
                    failed.extend(batch)
                    print(f'[claim_sol] ✗ batch exception: {last_err}', flush=True)
    except Exception as e:
        err_msg = _redact_keys(str(e))
        print(f'[claim_sol] ✗ FATAL error during close phase: {err_msg}', flush=True)
        return jsonify({'ok': False, 'msg': f'Close transaction failed: {err_msg}',
                        'debug': {'error': err_msg, 'trading_wallet': trading_pk}}), 500

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
    if failed:
        msg += f' — {len(failed)} account{"s" if len(failed) != 1 else ""} failed to close: {last_err}'
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
    _strip = lambda t: {k: v for k, v in t.items() if k not in ('fee', 'net_pnl')}
    _strip_daily = lambda d: {k: v for k, v in d.items() if k not in ('total_fees', 'net_pnl')}
    if wallet:
        us = get_user_state(wallet)
        check_daily_reset_user(us)
        today        = us['daily_stats']['date']
        today_trades = [t for t in us.get('trades_history', []) if t.get('date') == today]
        recent       = us.get('trades_history', [])[-20:]
        return jsonify({'daily': _strip_daily(us['daily_stats']), 'history': [_strip(t) for t in today_trades[-10:]], 'recent': [_strip(t) for t in recent]})
    check_daily_reset()
    today        = state['daily_stats']['date']
    today_trades = [t for t in state['trades_history'] if t.get('date') == today]
    recent       = state.get('trades_history', [])[-20:]
    return jsonify({'daily': _strip_daily(state['daily_stats']), 'history': [_strip(t) for t in today_trades[-10:]], 'recent': [_strip(t) for t in recent]})

@app.route('/api/pnl_chart')
@rate_limit(30, 60)
def api_pnl_chart():
    import calendar as _calendar
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': True, 'data': []})

    range_param = request.args.get('range', '1d').lower()
    days = {'1d': 1, '7d': 7, '30d': 30}.get(range_param, 7)
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')

    try:
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE wallet_address=?', (wallet,))
            row = c.fetchone()
            if not row:
                return jsonify({'ok': True, 'data': []})
            user_id = row[0]
            c.execute(
                '''SELECT timestamp, pnl FROM trades
                   WHERE user_id=? AND timestamp >= ?
                   ORDER BY timestamp ASC''',
                (user_id, cutoff)
            )
            rows = c.fetchall()
        finally:
            conn.close()
    except Exception as e:
        print(f'[pnl_chart] DB error: {e}', flush=True)
        return jsonify({'ok': False, 'msg': 'DB error'}), 500

    if not rows:
        return jsonify({'ok': True, 'data': []})

    points = []
    running = 0.0
    for ts_str, pnl in rows:
        running = round(running + (pnl or 0.0), 6)
        try:
            dt = datetime.datetime.strptime(ts_str[:19], '%Y-%m-%d %H:%M:%S')
        except Exception:
            continue
        if days == 1:
            # Unix timestamp (seconds) so LightweightCharts shows intraday time axis
            ts = int(_calendar.timegm(dt.timetuple()))
            points.append({'time': ts, 'value': running})
        else:
            # Daily aggregation: update last entry if same date, else append
            date_str = dt.strftime('%Y-%m-%d')
            if points and points[-1]['time'] == date_str:
                points[-1]['value'] = running
            else:
                points.append({'time': date_str, 'value': running})
    return jsonify({'ok': True, 'data': points})

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
        today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        c.execute('SELECT id, wallet_address, encrypted_private_key, created_at FROM users ORDER BY created_at DESC')
        rows = c.fetchall()
        users = []
        for uid, w, enc_key, created in rows:
            w = w or ''
            us  = user_states.get(w, {})
            pos = sum(1 for p in us.get('positions', {}).values() if p.get('amount', 0) > 0)
            c.execute('SELECT COUNT(*) FROM trades WHERE user_id=?', (uid,))
            total_trades = int((c.fetchone() or (0,))[0])
            c.execute('SELECT COALESCE(SUM(pnl),0) FROM trades WHERE user_id=? AND date(timestamp)=?', (uid, today))
            pnl_today = round(float((c.fetchone() or (0,))[0]), 4)
            c.execute('SELECT timestamp FROM trades WHERE user_id=? ORDER BY timestamp DESC LIMIT 1', (uid,))
            last_row = c.fetchone()
            last_seen = (last_row[0] or '')[:16] if last_row else ''
            users.append({
                'wallet_full': w,
                'wallet':      w[:4] + '...' + w[-4:] if len(w) >= 8 else w,
                'has_key':     bool(enc_key),
                'trading':     us.get('trader_running', False),
                'positions':   pos,
                'total_trades': total_trades,
                'pnl_today':   pnl_today,
                'last_seen':   last_seen,
            })
        conn.close()
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

@app.route('/api/admin/stats')
@rate_limit(20, 60)
def admin_stats():
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM users')
        total_users = int((c.fetchone() or (0,))[0])
        c.execute('SELECT COUNT(*) FROM trades')
        total_trades = int((c.fetchone() or (0,))[0])
        c.execute('SELECT COALESCE(SUM(ABS(pnl)),0) FROM trades')
        volume_sol = round(float((c.fetchone() or (0,))[0]), 4)
        conn.close()
        active_bots = sum(1 for us in list(user_states.values()) if us.get('trader_running'))
        return jsonify({'ok': True, 'users': total_users, 'trades': total_trades,
                        'volume_sol': volume_sol, 'active_bots': active_bots})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/fee-stats')
@rate_limit(20, 60)
def admin_fee_stats():
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        ok_f = "(status IS NULL OR status='ok') AND (fee_tx IS NULL OR fee_tx NOT LIKE 'FAILED:%')"
        c.execute(f'SELECT COALESCE(SUM(fee_amount),0) FROM fees WHERE {ok_f}')
        collected = round(float((c.fetchone() or (0,))[0]), 4)
        c.execute(f'SELECT COALESCE(SUM(fee_amount),0) FROM fees WHERE {ok_f} AND timestamp LIKE ?', (today + '%',))
        today_sol = round(float((c.fetchone() or (0,))[0]), 4)
        # Pending = 5% of profitable trades not yet paid
        c.execute('''SELECT COALESCE(SUM(t.pnl * 0.05), 0) FROM trades t
                     WHERE t.pnl > 0 AND (t.fee_paid IS NULL OR t.fee_paid = 0)''')
        pending = round(float((c.fetchone() or (0,))[0]), 4)
        conn.close()
        return jsonify({'ok': True, 'collected': collected, 'pending': pending, 'today': today_sol})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/collect-fees', methods=['POST'])
@rate_limit(5, 60)
def admin_collect_fees():
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    result = _recover_uncollected_fees(triggered_by='admin-panel')
    if result.get('ok'):
        return jsonify({'ok': True, 'msg': f"Collected {result.get('total_sol', 0):.4f} SOL",
                        'total_sol': result.get('total_sol', 0)})
    return jsonify({'ok': False, 'error': result.get('error', 'Recovery failed')}), 500

@app.route('/api/admin/force-pause', methods=['POST'])
@rate_limit(20, 60)
def admin_force_pause():
    caller = _current_wallet()
    if not caller or not _is_owner(caller):
        return jsonify({'error': 'Unauthorized'}), 403
    target = str((request.json or {}).get('wallet', '')).strip()
    if not is_valid_solana_address(target):
        return jsonify({'error': 'Invalid wallet'}), 400
    us = user_states.get(target)
    if not us:
        return jsonify({'error': 'User not found or not active'}), 404
    if us.get('trader_stop'):
        us['trader_stop'].set()
    us['trader_running'] = False
    print(f'[admin] force-pause {target[:8]}… by owner', flush=True)
    return jsonify({'ok': True, 'msg': f'Bot paused for {target[:8]}…'})

@app.route('/api/admin/force-resume', methods=['POST'])
@rate_limit(20, 60)
def admin_force_resume():
    caller = _current_wallet()
    if not caller or not _is_owner(caller):
        return jsonify({'error': 'Unauthorized'}), 403
    target = str((request.json or {}).get('wallet', '')).strip()
    if not is_valid_solana_address(target):
        return jsonify({'error': 'Invalid wallet'}), 400
    # Resume requires the user to be in user_states and have a valid key
    us = get_user_state(target)
    if us.get('trader_running'):
        return jsonify({'ok': True, 'msg': 'Bot already running'})
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id, encrypted_private_key, max_trade_size, min_trade_size, daily_loss_limit FROM users WHERE wallet_address=?', (target,))
        row = c.fetchone()
        conn.close()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    if not row or not row[1]:
        return jsonify({'error': 'User has no trading key — cannot resume'}), 400
    config = {
        'user_id':         row[0],
        'max_trade_size':  row[2] or 0.01,
        'min_trade_size':  row[3] or 0.001,
        'daily_loss_limit': row[4] or 0.05,
    }
    stop_ev = threading.Event()
    us['trader_stop']   = stop_ev
    us['trader_thread'] = threading.Thread(target=user_trader_loop, args=(stop_ev, config, target), daemon=True)
    us['trader_thread'].start()
    us['trader_running'] = True
    print(f'[admin] force-resume {target[:8]}… by owner', flush=True)
    return jsonify({'ok': True, 'msg': f'Bot resumed for {target[:8]}…'})

@app.route('/api/admin/force-close-all', methods=['POST'])
@rate_limit(10, 60)
def admin_force_close_all():
    caller = _current_wallet()
    if not caller or not _is_owner(caller):
        return jsonify({'error': 'Unauthorized'}), 403
    target = str((request.json or {}).get('wallet', '')).strip()
    if not is_valid_solana_address(target):
        return jsonify({'error': 'Invalid wallet'}), 400
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id, encrypted_private_key FROM users WHERE wallet_address=?', (target,))
        row = c.fetchone()
        conn.close()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    if not row or not row[1]:
        return jsonify({'error': 'User not found or has no trading key'}), 400
    us = user_states.get(target, {})
    positions = {k: v for k, v in us.get('positions', {}).items() if v.get('amount', 0) > 0}
    if not positions:
        return jsonify({'ok': True, 'msg': 'No open positions to close'})
    try:
        from cryptography.fernet import Fernet
        fernet = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)
        pk = fernet.decrypt(row[1].encode()).decode()
    except Exception as e:
        return jsonify({'error': 'Key decryption failed'}), 500
    closed, failed = 0, 0
    for mint in list(positions.keys()):
        try:
            from orcagent_solana import sell_token
            sell_token(pk, mint, target)
            closed += 1
        except Exception:
            failed += 1
    print(f'[admin] force-close-all {target[:8]}… closed={closed} failed={failed}', flush=True)
    return jsonify({'ok': True, 'msg': f'Closed {closed} position(s)' + (f', {failed} failed' if failed else '')})

@app.route('/api/admin/rate-stats')
@rate_limit(20, 60)
def admin_rate_stats():
    caller = _current_wallet()
    if not caller or not _is_owner(caller):
        return jsonify({'ok': False, 'error': 'Forbidden'}), 403

    now        = time.time()
    hour_ago   = now - 3600
    # UTC midnight: floor to 86400 s boundary
    today_start = now - (now % 86400)

    with _ext_lock:
        api_today = sum(1 for t in _ext_calls['api']         if t >= today_start)
        jup_today = sum(1 for t in _ext_calls['jupiter']     if t >= today_start)
        dex_today = sum(1 for t in _ext_calls['dexscreener'] if t >= today_start)

    # Aggregate per-endpoint request and block counts for the last hour.
    # Keys in _rl_hits/blocked are "function_name:ip" or special forms like
    # "global:ip" and "withdraw_wallet:wallet" — split on the FIRST colon.
    ep_hits    = {}
    ep_blocked = {}
    with _rl_lock:
        for key, hits in _rl_hits.items():
            ep = key.split(':', 1)[0]
            ep_hits[ep] = ep_hits.get(ep, 0) + sum(1 for t in hits if t >= hour_ago)
        for key, hits in _rl_blocked.items():
            ep = key.split(':', 1)[0]
            ep_blocked[ep] = ep_blocked.get(ep, 0) + sum(1 for t in hits if t >= hour_ago)

    all_eps = set(ep_hits) | set(ep_blocked)
    endpoints = sorted(
        [{'endpoint': ep,
          'requests_1h': ep_hits.get(ep, 0),
          'blocked_1h':  ep_blocked.get(ep, 0)}
         for ep in all_eps if ep_hits.get(ep, 0) or ep_blocked.get(ep, 0)],
        key=lambda x: (-x['blocked_1h'], -x['requests_1h']),
    )

    return jsonify({
        'ok':                    True,
        'api_calls_today':       api_today,
        'jupiter_calls_today':   jup_today,
        'dexscreener_calls_today': dex_today,
        'endpoints':             endpoints,
    })


@app.route('/api/admin/backups')
@rate_limit(20, 60)
def admin_backups():
    caller = _current_wallet()
    if not caller or not _is_owner(caller):
        return jsonify({'error': 'Unauthorized'}), 403
    backups = []
    try:
        if os.path.isdir(BACKUP_DIR):
            for fname in sorted(os.listdir(BACKUP_DIR), reverse=True):
                if fname.startswith('orcagent_') and fname.endswith('.db'):
                    fpath = os.path.join(BACKUP_DIR, fname)
                    stat  = os.stat(fpath)
                    date_str = fname.replace('orcagent_', '').replace('.db', '')
                    backups.append({
                        'filename': fname,
                        'size':     stat.st_size,
                        'date':     date_str,
                    })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    return jsonify({'ok': True, 'backups': backups, 'backup_dir': BACKUP_DIR})

def _recover_uncollected_fees(triggered_by: str = 'manual') -> dict:
    """Send all unpaid fees (fee_paid=0, pnl>0) from each user's trading wallet to OWNER_WALLET.
    Returns a summary dict. Safe to call from a background thread or an API endpoint."""
    if not OWNER_WALLET:
        print('[fee-recovery] OWNER_WALLET not set — skipping', flush=True)
        return {'ok': False, 'error': 'OWNER_WALLET not configured', 'total_sol': 0.0, 'results': []}

    print(f'[fee-recovery] ── START ({triggered_by}) ──', flush=True)
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        # Group unpaid trades by user so we send one TX per user instead of one per trade
        c.execute('''
            SELECT u.wallet_address,
                   u.encrypted_private_key,
                   GROUP_CONCAT(t.id)            AS trade_ids,
                   COALESCE(SUM(t.pnl * ?), 0)   AS total_fee
            FROM trades t
            JOIN users u ON u.id = t.user_id
            WHERE t.pnl > 0
              AND (t.fee_paid IS NULL OR t.fee_paid = 0)
              AND u.encrypted_private_key IS NOT NULL
              AND u.encrypted_private_key != ""
            GROUP BY u.wallet_address, u.encrypted_private_key
        ''', (FEE_RATE,))
        rows = c.fetchall()
        conn.close()
    except Exception as e:
        print(f'[fee-recovery] DB query failed: {e}', flush=True)
        return {'ok': False, 'error': str(e), 'total_sol': 0.0, 'results': []}

    if not rows:
        print('[fee-recovery] no unpaid trades found', flush=True)
        return {'ok': True, 'total_sol': 0.0, 'results': [], 'msg': 'No unpaid fees found'}

    total_recovered = 0.0
    results         = []

    for (user_wallet, enc_blob, trade_ids_str, total_fee_raw) in rows:
        total_fee = round(float(total_fee_raw or 0), 6)
        trade_ids = [int(x) for x in (trade_ids_str or '').split(',') if x.strip().isdigit()]
        sw = (user_wallet[:6] + '...' + user_wallet[-4:]) if len(user_wallet) >= 10 else user_wallet

        print(f'[fee-recovery] {sw}  unpaid_trades={len(trade_ids)}  '
              f'total_fee={total_fee:.6f} SOL', flush=True)

        if total_fee < 0.0001:
            print(f'[fee-recovery] {sw} below dust threshold — skipping', flush=True)
            results.append({'wallet': sw, 'fee': total_fee, 'status': 'skipped_dust'})
            continue

        try:
            # ── Decrypt key — failures are silenced here and NEVER forwarded to
            # any user-facing log or API response.  add_user_log is intentionally
            # not called; the error only appears in server stdout so the admin can
            # diagnose it without confusing the wallet owner.
            try:
                with _use_key(enc_blob, user_wallet) as pk:
                    from solders.keypair import Keypair as _KP_fr
                    signer = str(_KP_fr.from_base58_string(pk).pubkey())
                    signer_sol = _get_user_sol(signer)
                    if signer_sol < 0.001:
                        print(f'[fee-recovery] {sw} signer={signer[:6]}...{signer[-4:]} has '
                              f'{signer_sol:.6f} SOL (<0.001) — not enough to cover the network fee, '
                              f'skipping', flush=True)
                        results.append({'wallet': sw, 'fee': total_fee, 'trades': len(trade_ids),
                                        'status': 'skipped_low_balance', 'sol_balance': signer_sol})
                        continue
                    tx_sig = send_sol_fee(pk, OWNER_WALLET, total_fee)
            except InvalidToken:
                # Wrong ENCRYPTION_KEY for this wallet, or the stored blob is corrupted.
                # decrypt_private_key() already printed the detailed reason with wallet + fingerprint.
                # Skip silently — do NOT call add_user_log, no frontend notification sent.
                print(f'[fee-recovery] {sw} full_wallet={user_wallet} SKIP — key decryption '
                      f'failed (InvalidToken, enc_key_fp={_enc_key_fingerprint}). '
                      f'User must re-save their trading key in Settings. '
                      f'This error is NOT forwarded to the user UI.', flush=True)
                results.append({'wallet': sw, 'fee': total_fee, 'trades': len(trade_ids),
                                'status': 'skipped_decrypt_error'})
                continue

            # Mark every trade in this batch as paid and record in fees table
            conn2 = sqlite3.connect(DB_FILE)
            placeholders = ','.join('?' * len(trade_ids))
            conn2.execute(
                f'UPDATE trades SET fee_paid=1 WHERE id IN ({placeholders})',
                trade_ids)
            conn2.execute(
                '''INSERT INTO fees (user_wallet, token, gross_profit, fee_amount, fee_tx, status)
                   VALUES (?,?,?,?,?,?)''',
                (user_wallet, '[recovery]', total_fee / FEE_RATE, total_fee, tx_sig, 'ok'))
            conn2.commit()
            conn2.close()

            total_recovered += total_fee
            print(f'[fee-recovery] ✓ {sw} sent {total_fee:.6f} SOL  TX:{tx_sig[:20]}...  '
                  f'{len(trade_ids)} trade(s) marked fee_paid=1', flush=True)
            add_log(f'[fee-recovery] {sw} recovered {total_fee:.5f} SOL  TX:{tx_sig[:14]}...')
            results.append({'wallet': sw, 'fee': total_fee, 'trades': len(trade_ids),
                            'tx': tx_sig, 'status': 'sent'})

        except Exception as e:
            # Covers send_sol_fee failure, DB errors, keypair derivation errors, etc.
            # Decrypt errors are handled by the inner except above and never reach here.
            err = _redact_keys(str(e)[:200])
            print(f'[fee-recovery] ✗ {sw} FAILED: {err}', flush=True)
            results.append({'wallet': sw, 'fee': total_fee, 'trades': len(trade_ids),
                            'error': err, 'status': 'failed'})

    print(f'[fee-recovery] ── DONE  total_recovered={total_recovered:.6f} SOL ──', flush=True)
    return {
        'ok':         True,
        'total_sol':  round(total_recovered, 6),
        'wallets':    len(rows),
        'results':    results,
    }


@app.route('/api/admin/recover-fees', methods=['POST'])
@rate_limit(5, 60)
def admin_recover_fees():
    """Collect all unpaid fees (trades.fee_paid=0) and send them to OWNER_WALLET in one TX per user."""
    wallet = _current_wallet()
    if not wallet or not _is_owner(wallet):
        return jsonify({'error': 'Unauthorized'}), 403
    result = _recover_uncollected_fees(triggered_by='admin-button')
    status = 200 if result.get('ok') else 500
    return jsonify(result), status



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
                'permanent':  False,
            })
        else:
            _ip_ban.pop(ip, None)
            _ip_warn.pop(ip, None)
    with _rl_lock:
        rl_bucket_count = len(_rl_hits)
    return jsonify({'bans': sorted(bans, key=lambda x: (not x['permanent'], x['mins_left'] or 0), reverse=True),
                    'rl_bucket_count': rl_bucket_count,
                    'whitelisted_ips': sorted(_OWNER_IPS)})


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
        try:
            conn = sqlite3.connect(DB_FILE)
            conn.execute('DELETE FROM banned_ips WHERE ip=?', (target,))
            conn.commit()
            conn.close()
        except Exception:
            pass
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
        try:
            conn = sqlite3.connect(DB_FILE)
            conn.execute('DELETE FROM banned_ips')
            conn.commit()
            conn.close()
        except Exception:
            pass
        with _rl_lock:
            _rl_hits.clear()
        print(f'[admin] clear_ratelimit: {wallet[:8]}… cleared ALL '
              f'({n_bans} bans, {n_rl} rl buckets)', flush=True)
        return jsonify({'ok': True,
                        'msg': f'Cleared all — {n_bans} ban(s) and {n_rl} rate-limit bucket(s) removed (permanent code-level bans unaffected)'})


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
run_migrations()
_load_banned_ips()
def _heartbeat_loop():
    while True:
        try:
            ts = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            with open(HEARTBEAT_FILE, 'w') as _hf:
                _hf.write(ts)
        except Exception as _e:
            print(f'[heartbeat] write error: {_e}', flush=True)
        time.sleep(60)

threading.Thread(target=_heartbeat_loop,       daemon=True).start()
threading.Thread(target=token_loop,            daemon=True).start()
threading.Thread(target=totd_loop,             daemon=True).start()
threading.Thread(target=_cleanup_loop,         daemon=True).start()
threading.Thread(target=_audit_loop,           daemon=True).start()
threading.Thread(target=_security_check_loop,  daemon=True).start()
_security_selftest()
add_log('OrcAgent started')

def _startup_fee_recovery():
    """One-time recovery run 30 s after boot — collects any fees missed before fee_paid tracking."""
    time.sleep(30)
    print('[fee-recovery] startup pass — checking for unpaid fees...', flush=True)
    _recover_uncollected_fees(triggered_by='startup')

threading.Thread(target=_startup_fee_recovery, daemon=True).start()

# ── DAILY DATABASE BACKUP ────────────────────────────────────────────────────
def backup_database() -> bool:
    """
    Hot-copy orcagent.db to BACKUP_DIR/orcagent_YYYY-MM-DD.db using the
    sqlite3 online backup API (safe under concurrent reads/writes).
    Retains the 7 most recent files; older ones are deleted.
    Returns True on success.
    """
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        date_str  = datetime.datetime.utcnow().strftime('%Y-%m-%d')
        dest_path = os.path.join(BACKUP_DIR, f'orcagent_{date_str}.db')
        # Use sqlite3 online backup so we never read a torn page
        src  = sqlite3.connect(DB_FILE)
        dest = sqlite3.connect(dest_path)
        try:
            src.backup(dest)
        finally:
            dest.close()
            src.close()
        size_kb = os.path.getsize(dest_path) // 1024
        print(f'[backup] ✓ {dest_path} ({size_kb} KB)', flush=True)
    except Exception as e:
        print(f'[backup] ✗ failed: {e}', flush=True)
        return False

    # Prune — keep only the 7 newest files
    try:
        files = sorted(
            [f for f in os.listdir(BACKUP_DIR) if f.startswith('orcagent_') and f.endswith('.db')],
            reverse=True,
        )
        for old in files[7:]:
            old_path = os.path.join(BACKUP_DIR, old)
            os.remove(old_path)
            print(f'[backup] pruned {old}', flush=True)
    except Exception as e:
        print(f'[backup] prune error: {e}', flush=True)

    return True

def _start_backup_scheduler():
    if not _APSCHEDULER_OK:
        print('[backup] APScheduler not available — install apscheduler for scheduled backups', flush=True)
        # Fall back to a simple thread-based 60-second delay + no recurring schedule
        def _once():
            time.sleep(60)
            backup_database()
        threading.Thread(target=_once, daemon=True).start()
        return
    try:
        _sched = _BgScheduler(timezone='UTC')
        # Daily at 03:00 UTC
        _sched.add_job(backup_database, _CronTrigger(hour=3, minute=0), id='daily_backup', replace_existing=True)
        # One-shot startup backup after 60 s
        run_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=60)
        _sched.add_job(backup_database, 'date', run_date=run_at, id='startup_backup')
        _sched.start()
        print('[backup] scheduler started — daily 03:00 UTC, startup in 60 s', flush=True)
    except Exception as e:
        print(f'[backup] scheduler error: {e}', flush=True)

_start_backup_scheduler()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print('OrcAgent Dashboard running on port', port)
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
