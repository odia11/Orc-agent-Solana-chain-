import threading, time, json, os, sys, subprocess, requests, logging, datetime, sqlite3, re, functools, struct, base64, math, hashlib, hmac, secrets, binascii, shutil, uuid, html as _html_lib, traceback
from datetime import timedelta
import bcrypt as _bcrypt
try:
    import nacl.public as _nacl_public
    import nacl.signing as _nacl_signing
    _NACL_OK = True
except ImportError:
    _NACL_OK = False
    _nacl_signing = None
try:
    from apscheduler.schedulers.background import BackgroundScheduler as _BgScheduler
    from apscheduler.triggers.cron import CronTrigger as _CronTrigger
    _APSCHEDULER_OK = True
except ImportError:
    _APSCHEDULER_OK = False
try:
    from flask_compress import Compress as _Compress
    _COMPRESS_OK = True
except ImportError:
    _COMPRESS_OK = False
from contextlib import contextmanager
from flask import Flask, jsonify, request, session, render_template, redirect, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
if _COMPRESS_OK:
    app.config['COMPRESS_MIMETYPES'] = ['text/html','text/css','text/xml','text/javascript','application/json','application/javascript']
    _Compress(app)
def _load_secret_key() -> bytes:
    _env = os.getenv('SECRET_KEY')
    if _env:
        return _env.encode() if isinstance(_env, str) else _env
    _key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.secret_key')
    try:
        with open(_key_path, 'rb') as _f:
            return _f.read()
    except FileNotFoundError:
        _key = os.urandom(32)
        with open(_key_path, 'wb') as _f:
            _f.write(_key)
        return _key

app.secret_key = _load_secret_key()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'
app.config['SESSION_COOKIE_SECURE']     = bool(os.getenv('RAILWAY_ENVIRONMENT'))
app.config['SESSION_COOKIE_PATH']       = '/'
# 'orca_s' avoids conflicts with the old 'session' cookie (no domain attr).
# '.orcagent.fun' (dot prefix) lets both www and bare share the same session.
# Only set in production — local dev keeps Flask defaults.
if os.getenv('RAILWAY_ENVIRONMENT'):
    app.config['SESSION_COOKIE_NAME']   = 'orca_s'
    app.config['SESSION_COOKIE_DOMAIN'] = '.orcagent.fun'
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
    ua = (request.headers.get('User-Agent') or '').strip()
    if ip not in _OWNER_IPS and (
        not ua or _BOT_UA_RE.search(ua)
    ):
        if request.path in _BOT_BLOCKED_PATHS:
            _log_security_event('bot_blocked', session.get('wallet', 'anonymous'),
                                f'{request.method} {request.path} ua={ua!r:.120} from {ip}')
            return jsonify({'error': 'Forbidden'}), 403
        _log_security_event('bot_probe', session.get('wallet', 'anonymous'),
                            f'{request.method} {request.path} ua={ua!r:.120} from {ip}')
    if (ip not in _OWNER_IPS and not _is_owner(session.get('wallet', ''))
            and not _rate_ok('global:' + ip, 500, 60)):
        return jsonify({'error': 'Too many requests'}), 429
    _ext_hit('api')
    return None

@app.before_request
def _refresh_session():
    if session.get('wallet'):
        session.modified = True  # extend cookie lifetime on every API call

# /api/wallet/set is the auth-bootstrap endpoint — it establishes the session so it
# cannot require a session-scoped CSRF token. Origin check still protects it.
_CSRF_EXEMPT_PATHS = frozenset({'/api/wallet/set', '/api/wallet/connect-readonly', '/api/login_password', '/api/connect-wallet', '/api/instant-trade', '/api/phantom/init', '/api/phantom/decrypt', '/api/wallet/send'})

def csrf_exempt(f):
    """Decorator: mark a view function as exempt from CSRF token validation.
    Origin and client-secret checks in _csrf_check() still apply.
    Use on API routes whose callers cannot forward the session CSRF token."""
    f._csrf_exempt = True
    return f

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
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE') or not request.path.startswith('/api/'):
        return None
    # Fully exempt paths skip ALL sub-checks (client-secret, origin, token).
    # These routes either bootstrap auth (no session yet) or handle their own
    # auth/CORS (instant-trade has its own CORS after_request + session wallet check).
    if request.path in _CSRF_EXEMPT_PATHS:
        return None
    # Function-level exemption via @csrf_exempt decorator
    _ep = app.view_functions.get(request.endpoint)
    if _ep and getattr(_ep, '_csrf_exempt', False):
        return None
    # ── 0. Shared client secret (only enforced if API_SHARED_SECRET is configured) ──
    if API_SHARED_SECRET:
        sent = request.headers.get('X-API-Shared-Secret', '')
        if not sent or not hmac.compare_digest(sent.encode(), API_SHARED_SECRET.encode()):
            _log_security_event('client_secret_fail', session.get('wallet', 'unknown'),
                                f'bad/missing X-API-Shared-Secret on {request.path}')
            return jsonify({'error': 'Forbidden'}), 403
    # ── 1. Origin / Host validation ──────────────────────────────────────────
    origin = request.headers.get('Origin', '')
    if origin:
        host = request.headers.get('Host', '') or ''
        # Strip www. from both sides before comparing so that a browser on
        # www.orcagent.fun posting to orcagent.fun (after redirect) still passes.
        host_bare   = host.split(':')[0].removeprefix('www.')
        origin_bare = origin.split('//')[-1].split(':')[0].removeprefix('www.')
        if origin_bare not in ('localhost', '127.0.0.1') and origin_bare != host_bare:
            return jsonify({'error': 'CSRF check failed'}), 403
    # ── 2. CSRF token for authenticated sessions ──────────────────────────────
    if session.get('wallet'):
        tok = (request.headers.get('X-CSRF-Token', '') or
               request.headers.get('X-CSRFToken', '') or
               (request.get_json(silent=True) or {}).get('csrf_token', ''))
        # If session has no csrf_token yet (pre-dates CSRF system, or old cookie
        # without the token), generate one now and let this request through.
        # Origin + client-secret checks above already validated the caller.
        if not session.get('csrf_token'):
            session['csrf_token'] = secrets.token_hex(32)
        if not _validate_csrf(tok):
            _log_security_event('csrf_fail', session.get('wallet', 'unknown'),
                                f'bad/missing token on {request.path}')
            print(f'[csrf_fail] path={request.path} wallet={session.get("wallet","?")} '
                  f'tok_sent={bool(tok)} headers={dict(request.headers)}', flush=True)
            return jsonify({
                'error': 'CSRF validation failed',
                'logged_in': bool(session.get('wallet')),
                'hint': 'Send the token from GET /api/csrf-token in X-CSRF-Token header'
            }), 403

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

BASE         = os.path.dirname(os.path.abspath(__file__))
DM_IMAGES_DIR   = os.path.join(BASE, 'static', 'dm_images')
CHAT_IMAGES_DIR = os.path.join(BASE, 'static', 'chat_images')
os.makedirs(DM_IMAGES_DIR,   exist_ok=True)
os.makedirs(CHAT_IMAGES_DIR, exist_ok=True)
# Use Railway persistent volume when available so the DB and logs survive redeploys.
_DATA_DIR    = '/data' if os.path.exists('/data') else BASE
LOG_FILE     = os.path.join(_DATA_DIR, 'trades.log')
DB_FILE        = os.path.join(_DATA_DIR, 'orcagent.db')
BACKUP_DIR     = os.path.join(_DATA_DIR, 'backups')
HEARTBEAT_FILE = os.path.join(_DATA_DIR, 'heartbeat.txt')
_APP_START     = time.time()
print(f"[startup] persistent storage: {os.path.exists('/data')}  db={DB_FILE}", flush=True)

TAKE_PROFIT     = 0.05   # 5%  — universal take profit
STOP_LOSS       = 0.03   # 3%  — universal stop loss
EXIT_PERCENTAGE = 1.0    # sell 100% of position on any exit
CRASH_EXIT      = 0.15   # 15% — emergency exit on extreme drop

WALLET_ADDRESS   = os.environ.get('WALLET_ADDRESS', '')
USDC_MINT        = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
SOL_MINT         = 'So11111111111111111111111111111111111111112'
SOLANA_RPC       = 'https://api.mainnet-beta.solana.com'
SOLANA_RPC_URL   = os.environ.get('SOLANA_RPC_URL', '')   # set in Railway — overrides all fallbacks
HELIUS_RPC       = os.environ.get('HELIUS_RPC', '')        # full Helius URL e.g. https://mainnet.helius-rpc.com/?api-key=xxx
HELIUS_API_KEY   = os.environ.get('HELIUS_API_KEY', '')
OWNER_WALLET     = os.environ.get('OWNER_WALLET', '')
ADMIN_WALLET     = 'HC5ahspSox3XRmDbzXjXVoAASuY89RCmGUKwp87FRJS5'
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
JUPITER_PROXY    = os.environ.get('JUPITER_PROXY_URL', '').rstrip('/')
PROXY_SECRET     = os.environ.get('JUPITER_PROXY_SECRET', '')
print(f'[startup] JUPITER_PROXY_URL = {(JUPITER_PROXY[:40] + "...") if len(JUPITER_PROXY) > 40 else (JUPITER_PROXY or "(not set — using api.jup.ag directly)")}', flush=True)
# Optional shared secret the frontend echoes back on every mutating request.
# Defense-in-depth against scripted bots that POST straight to the API without ever
# loading the page (and therefore never seeing this value). Skipped entirely when unset,
# so local/dev deployments without the env var keep working unchanged.
API_SHARED_SECRET  = os.environ.get('API_SHARED_SECRET', '')
FEE_RATE_DEFAULT = 0.02  # 2% performance fee on profitable trades only

def _get_fee_rate():
    try:
        conn = sqlite3.connect(DB_FILE)
        row = conn.execute("SELECT value FROM platform_settings WHERE key='fee_rate'").fetchone()
        conn.close()
        return float(row[0]) if row else FEE_RATE_DEFAULT
    except Exception:
        return FEE_RATE_DEFAULT
FEE_WALLET       = 'BM3A4wVCc4AG4rgHDETa7yCtxCKRvc55ptA9Dx3xYT8i'  # hardcoded fee recipient

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
    # Strip query string before truncating — query params may contain API keys
    return url.split('?')[0][:40]
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

# Sensitive paths that are hard-blocked for bot/empty User-Agents
_BOT_BLOCKED_PATHS = frozenset({
    '/api/login_password',
    '/api/instant-trade',
    '/api/wallet/send',
    '/api/connect-wallet',
})

# User-Agent patterns that indicate automated clients, not real browsers
_BOT_UA_RE = re.compile(
    r'curl|python-requests|python-urllib|scrapy|wget|httpx|aiohttp|bot|spider|crawl',
    re.IGNORECASE,
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
            # Owner IP and owner wallet are never rate-limited or banned
            if ip in _OWNER_IPS or _is_owner(session.get('wallet', '')):
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
        c.execute("ALTER TABLE users ADD COLUMN trade_pct REAL DEFAULT 0.20")
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
        c.execute("ALTER TABLE trades ADD COLUMN source TEXT DEFAULT 'bot'")
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
    c.execute('''CREATE TABLE IF NOT EXISTS copy_relationships (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        copier_wallet  TEXT NOT NULL,
        copied_wallet  TEXT NOT NULL,
        active         INTEGER DEFAULT 1,
        created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(copier_wallet, copied_wallet)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS x_connections (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_address    TEXT NOT NULL UNIQUE,
        x_user_id         TEXT NOT NULL,
        x_handle          TEXT NOT NULL,
        access_token      TEXT NOT NULL,
        refresh_token     TEXT,
        token_expires_at  TIMESTAMP,
        share_on_big_trade INTEGER DEFAULT 0,
        share_on_badge    INTEGER DEFAULT 0,
        created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS platform_settings (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS user_blacklist (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id   INTEGER NOT NULL,
        mint      TEXT NOT NULL,
        symbol    TEXT DEFAULT '',
        added_at  TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, mint),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_blacklist_user ON user_blacklist(user_id)')
    c.execute('''CREATE TABLE IF NOT EXISTS direct_messages (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id   INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        message     TEXT NOT NULL,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_read     INTEGER DEFAULT 0
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_dm_receiver ON direct_messages(receiver_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_dm_sender ON direct_messages(sender_id)')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_wallet   TEXT NOT NULL,
        receiver_wallet TEXT NOT NULL,
        content         TEXT NOT NULL,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_read         INTEGER DEFAULT 0
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_wallet)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_messages_sender   ON messages(sender_wallet)')
    c.execute('''CREATE TABLE IF NOT EXISTS profile_comments (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        profile_user_id INTEGER NOT NULL,
        author_id       INTEGER NOT NULL,
        message         TEXT NOT NULL,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_pcomments_profile ON profile_comments(profile_user_id)')
    c.execute('''CREATE TABLE IF NOT EXISTS group_chat (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id      INTEGER NOT NULL,
        message      TEXT,
        message_type TEXT DEFAULT 'text',
        image_url    TEXT,
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_group_chat_created ON group_chat(created_at)')
    c.execute('''CREATE TABLE IF NOT EXISTS post_likes (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        post_id    TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, post_id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_post_likes_post ON post_likes(post_id)')
    c.execute('''CREATE TABLE IF NOT EXISTS post_reactions (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        post_id    TEXT NOT NULL,
        emoji      TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, post_id, emoji),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_post_reactions_post ON post_reactions(post_id)')
    c.execute('''CREATE TABLE IF NOT EXISTS auth_nonces (
        nonce      TEXT PRIMARY KEY,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip         TEXT
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_auth_nonces_created ON auth_nonces(created_at)')
    c.execute('''CREATE TABLE IF NOT EXISTS feed_replies (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        post_id    TEXT NOT NULL,
        message    TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_feed_replies_post ON feed_replies(post_id)')
    c.execute('''CREATE TABLE IF NOT EXISTS feed_reply_likes (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id  INTEGER NOT NULL,
        reply_id INTEGER NOT NULL,
        UNIQUE(user_id, reply_id),
        FOREIGN KEY(reply_id) REFERENCES feed_replies(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS notifications (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        type       TEXT NOT NULL,
        content    TEXT NOT NULL,
        link       TEXT,
        is_read    INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read)')
    c.execute('''CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id       INTEGER NOT NULL,
        credential_id TEXT NOT NULL UNIQUE,
        public_key    TEXT NOT NULL,
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_webauthn_cred ON webauthn_credentials(credential_id)')
    c.execute('''CREATE TABLE IF NOT EXISTS community_messages
        (id INTEGER PRIMARY KEY AUTOINCREMENT, wallet TEXT, content TEXT,
         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS feed_posts (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet     TEXT NOT NULL,
        content    TEXT NOT NULL,
        likes      INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_feed_posts_created ON feed_posts(created_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_feed_posts_wallet_created ON feed_posts(wallet, created_at)')
    c.execute('''CREATE TABLE IF NOT EXISTS user_tokens (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id       INTEGER NOT NULL,
        token_address TEXT    NOT NULL,
        symbol        TEXT    NOT NULL DEFAULT '',
        amount        REAL    NOT NULL DEFAULT 0,
        avg_price     REAL    NOT NULL DEFAULT 0,
        updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, token_address)
    )''')
    conn.commit()
    conn.close()

def run_migrations():
    con = sqlite3.connect(DB_FILE)
    for sql in [
        "ALTER TABLE users ADD COLUMN badges TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN copy_source TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN referral_code TEXT DEFAULT NULL",
        "ALTER TABLE direct_messages ADD COLUMN message_type TEXT DEFAULT 'text'",
        "ALTER TABLE users ADD COLUMN webauthn_ready INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT NULL",
        "ALTER TABLE user_tokens ADD COLUMN avg_price REAL NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN copy_amount REAL DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN bot_enabled INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN breakout_trigger REAL DEFAULT 3.0",
        "ALTER TABLE users ADD COLUMN take_profit REAL DEFAULT 15.0",
        "ALTER TABLE users ADD COLUMN stop_loss REAL DEFAULT 8.0",
        "ALTER TABLE users ADD COLUMN max_positions INTEGER DEFAULT 3",
        "ALTER TABLE users ADD COLUMN pref_notifications INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN pref_scam_filter INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN pref_sound_alerts INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'",
        "ALTER TABLE direct_messages ADD COLUMN edited_at TIMESTAMP DEFAULT NULL",
    ]:
        try:
            con.execute(sql)
            con.commit()
        except Exception:
            pass
    # admin_roles table — separate from users so it survives account deletion
    con.execute('''CREATE TABLE IF NOT EXISTS admin_roles (
        wallet_address TEXT PRIMARY KEY,
        role           TEXT NOT NULL DEFAULT 'Moderator',
        invited_by     TEXT,
        invited_at     TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    # admin_invites — pending invites shown as modal when user next logs in
    con.execute('''CREATE TABLE IF NOT EXISTS admin_invites (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet     TEXT NOT NULL,
        role       TEXT NOT NULL DEFAULT 'Moderator',
        invited_by TEXT NOT NULL DEFAULT '',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        status     TEXT NOT NULL DEFAULT 'pending'
    )''')
    con.commit()
    con.close()

# ── ROLE HELPERS ──

def get_user_role(wallet: str) -> str:
    """Return role for a wallet: 'admin', 'moderator', 'analyst', or 'user'."""
    if not wallet:
        return 'user'
    if wallet == ADMIN_WALLET:
        return 'admin'
    try:
        conn = sqlite3.connect(DB_FILE)
        # admin_roles table takes precedence (roles granted via admin panel)
        row = conn.execute(
            'SELECT role FROM admin_roles WHERE wallet_address=?', (wallet,)
        ).fetchone()
        if row:
            conn.close()
            return row[0].lower()
        # fall back to users table role column
        row = conn.execute(
            'SELECT role FROM users WHERE wallet_address=?', (wallet,)
        ).fetchone()
        conn.close()
        if row and row[0]:
            return row[0].lower()
    except Exception:
        pass
    return 'user'


def _require_role(*allowed_roles):
    """Return a 403 response tuple if session wallet lacks a required role, else None."""
    wallet = session.get('wallet', '')
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
    if get_user_role(wallet) not in allowed_roles:
        return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
    return None


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
    'tx', 'signature', 'sig',
    'wallet', 'wallet_address', 'truncated_wallet', 'short_wallet',
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

# Response cache: url → (timestamp, response_text)
# search?q= entries TTL 10 s; everything else TTL 30 s
_dex_resp_cache: dict = {}

class _DexCachedResp:
    """Minimal requests.Response stand-in for cached DexScreener data."""
    status_code = 200
    def __init__(self, text: str):
        self._text = text
    def json(self):
        return json.loads(self._text)

def _dex_get(url: str, timeout: int = 10):
    """GET a DexScreener URL with shared headers, 429 backoff, and response cache.
    Returns the Response (or cached stand-in), or None if unavailable."""
    global _dex_429_until
    now = time.time()
    ttl = 10 if 'search?q=' in url else 30
    # Serve from cache if fresh
    cached = _dex_resp_cache.get(url)
    if cached and now - cached[0] < ttl:
        return _DexCachedResp(cached[1])
    with _dex_lock:
        if now < _dex_429_until:
            # In backoff — return stale cached data if we have any
            return _DexCachedResp(cached[1]) if cached else None
    try:
        _ext_hit('dexscreener')
        r = requests.get(url, headers=_DEX_HEADERS, timeout=timeout)
        if r.status_code == 429:
            with _dex_lock:
                _dex_429_until = time.time() + 60
            add_log('DexScreener rate-limited (429) — backing off 60 s, serving cached data')
            return _DexCachedResp(cached[1]) if cached else None
        if r.status_code == 200:
            with _dex_lock:
                _dex_resp_cache[url] = (time.time(), r.text)
                # Evict entries older than 5 min if cache grows large
                if len(_dex_resp_cache) > 500:
                    cutoff = time.time() - 300
                    stale = [k for k, v in _dex_resp_cache.items() if v[0] < cutoff]
                    for k in stale:
                        del _dex_resp_cache[k]
        return r
    except Exception:
        return None

# ── PER-USER STATE ──
user_states: dict = {}

# ── PHANTOM DEEP-LINK SESSIONS (server-side keypair, TTL 10 min) ──
_phantom_sessions: dict = {}   # token_hex → {sk: bytes, created: float}
_B58_ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_B58_MAP   = {c: i for i, c in enumerate(_B58_ALPHA)}

def _b58enc(buf: bytes) -> str:
    d = []
    for byte in buf:
        c = byte
        for j in range(len(d)):
            c += d[j] << 8; d[j] = c % 58; c //= 58
        while c: d.append(c % 58); c //= 58
    n_leading = next((i for i, b in enumerate(buf) if b != 0), len(buf))
    return '1' * n_leading + ''.join(_B58_ALPHA[x] for x in reversed(d))

def _b58dec(s: str) -> bytes:
    d = []
    for char in s:
        c = _B58_MAP[char]
        for j in range(len(d)):
            c += d[j] * 58; d[j] = c & 255; c >>= 8
        while c: d.append(c & 255); c >>= 8
    n_leading = len(s) - len(s.lstrip('1'))
    return bytes([0] * n_leading) + bytes(reversed(d))

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

def _autostart_if_ready(wallet: str):
    """Disabled — bot must be started manually via /api/bot/start.
    Kept as a no-op so any lingering call sites are safe."""
    fetch_user_balances(wallet)

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
        penalties += 1.5;  risk_flags.append('LOW LIQ')
    elif liq < 50_000:
        penalties += 0.5;  risk_flags.append('LOW LIQ')
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
                       exit_reason: str = '', opened_at: float = 0.0, pref_notifications: bool = True):
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
    print(f'[fee] {short_w} {symbol} pnl={pnl:.6f} SOL  '
          f'pnl_positive={pnl>0}  has_key={bool(private_key and wallet)}  '
          f'fee_wallet={FEE_WALLET[:8]}…', flush=True)

    # Collect fees from ALL profitable trades regardless of who the session wallet belongs to.
    # The fee goes FROM the trading keypair TO FEE_WALLET — these are different addresses,
    # so even the platform owner's trades generate a valid transfer.
    if pnl > 0.0 and wallet and private_key:
        _fee_rate = _get_fee_rate()
        fee_amount = round(pnl * _fee_rate, 6)
        print(f'[fee] {short_w} {symbol} fee owed = {fee_amount:.6f} SOL '
              f'({_fee_rate * 100:.1f}% of {pnl:.6f} SOL profit)', flush=True)

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
                tx_sig   = None
                err_msg  = None
                try:
                    # check balance before attempting transfer (mirrors recovery-path guard)
                    from solders.keypair import Keypair as _KP_fee
                    signer_pub = str(_KP_fee.from_base58_string(pk).pubkey())
                    signer_sol  = _get_user_sol(signer_pub)
                    NET_FEE     = 0.000005  # ~5000 lamports for a simple SOL transfer tx
                    if signer_sol < fee + NET_FEE:
                        err_msg = (f'insufficient balance: {signer_sol:.6f} SOL '
                                   f'(need {fee:.6f} + {NET_FEE} network fee)')
                        print(f'[fee] ✗ {sw} {sym} {err_msg}', flush=True)
                    else:
                        tx_sig = send_sol_fee(pk, FEE_WALLET, fee)
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
                        # FIX 2: mark fee_paid by row ID, not timestamp (timestamp is second-level
                        # precision and could match two trades from the same user in the same second)
                        row = conn2.execute(
                            'SELECT id FROM trades WHERE user_id=? AND timestamp=? AND fee_paid=0 '
                            'ORDER BY rowid LIMIT 1', (uid, trade_ts)).fetchone()
                        if row:
                            conn2.execute('UPDATE trades SET fee_paid=1 WHERE id=?', (row[0],))
                        else:
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
    if wallet and abs(pnl_pct) >= 20:
        _xrow = sqlite3.connect(DB_FILE).execute(
            'SELECT share_on_big_trade FROM x_connections WHERE wallet_address=?',
            (wallet,)).fetchone()
        if _xrow and _xrow[0]:
            _sign  = '+' if pnl_pct >= 0 else ''
            _tweet = f'Just closed ${symbol} {_sign}{pnl_pct:.1f}% ({_sign}{pnl:.4f} SOL) on @OrcAgent 🐋'
            threading.Thread(target=_post_to_x, args=(wallet, _tweet), daemon=True).start()
    if pref_notifications and user_id:
        pnl_sign     = '+' if pnl >= 0 else ''
        notif_content = (f'Trade closed: ${symbol} '
                         f'{pnl_sign}{pnl_pct:.1f}% ({pnl_sign}{pnl:.4f} SOL) — {exit_reason}' if exit_reason
                         else f'Trade closed: ${symbol} {pnl_sign}{pnl_pct:.1f}% ({pnl_sign}{pnl:.4f} SOL)')
        try:
            _nc = sqlite3.connect(DB_FILE)
            _nc.execute(
                'INSERT INTO notifications (user_id, type, content, link) VALUES (?,?,?,?)',
                (user_id, 'trade', notif_content, '/history'))
            _nc.commit()
            _nc.close()
        except Exception as _ne:
            print(f'[notif] trade notification failed: {_ne}', flush=True)

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
        old_row    = conn.execute('SELECT badges FROM users WHERE wallet_address=?', (wallet,)).fetchone()
        old_badges = set((old_row[0] or '').split(',')) if old_row else set()
        new_badges = set(badges) - old_badges - {''}
        conn.execute('UPDATE users SET badges=? WHERE wallet_address=?',
                     (','.join(badges), wallet))
        conn.commit()
        if new_badges:
            xrow = conn.execute(
                'SELECT share_on_badge FROM x_connections WHERE wallet_address=?',
                (wallet,)
            ).fetchone()
            if xrow and xrow[0]:
                for badge in new_badges:
                    _tweet = f'Just unlocked the {badge} badge on @OrcAgent 🏆'
                    threading.Thread(target=_post_to_x, args=(wallet, _tweet), daemon=True).start()
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
            env=env, capture_output=True, text=True, timeout=120
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

def _check_mint_safety(mint_address: str) -> dict:
    try:
        r = requests.post(SOLANA_RPC, json={
            'jsonrpc': '2.0', 'id': 1, 'method': 'getAccountInfo',
            'params': [mint_address, {'encoding': 'base64'}]
        }, timeout=5)
        raw = r.json()['result']['value']['data'][0]
        data = base64.b64decode(raw)
        mint_auth_active   = data[0:4] != b'\x00\x00\x00\x00'
        freeze_auth_active = data[46:50] != b'\x00\x00\x00\x00'
        return {'mint_authority_active': mint_auth_active,
                'freeze_authority_active': freeze_auth_active, 'ok': True}
    except Exception:
        return {'mint_authority_active': True, 'freeze_authority_active': True, 'ok': False}

def _check_lp_locked(mint_address: str) -> dict:
    try:
        r = requests.get(
            f'https://api.rugcheck.xyz/v1/tokens/{mint_address}/report/summary',
            headers={'Accept': 'application/json'}, timeout=6
        )
        data = r.json()
        lp_pct = data.get('lpLockedPct')
        if lp_pct is None and isinstance(data.get('markets'), list) and data['markets']:
            lp_pct = data['markets'][0].get('lp', {}).get('lpLockedPct', 0)
        print(f'[rugcheck] {mint_address[:8]} lpLockedPct={lp_pct} raw_keys={list(data.keys())}', flush=True)
        return {'lp_locked_pct': float(lp_pct or 0), 'ok': True}
    except Exception as e:
        print(f'[rugcheck] error for {mint_address[:8]}: {e}', flush=True)
        return {'lp_locked_pct': 0, 'ok': False}

# ── PER-USER TRADER ──
def user_trader_loop(stop_event, config, wallet: str):
    us    = get_user_state(wallet)
    short = wallet[:6] + '...' + wallet[-4:]
    try:
        conn = sqlite3.connect(DB_FILE)
        try:
            c   = conn.cursor()
            c.execute('SELECT id, encrypted_private_key, daily_loss_limit, min_trade_size, max_trade_size, breakout_trigger, take_profit, stop_loss, max_positions, pref_scam_filter, pref_notifications, trade_pct FROM users WHERE wallet_address=?', (wallet,))
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
    min_trade_usdc   = float(row[3]) if (len(row) > 3 and row[3] is not None) else 1.0
    max_trade_usdc   = float(row[4]) if (len(row) > 4 and row[4] is not None) else 10.0
    take_profit   = (float(row[6]) / 100) if row[6] is not None else TAKE_PROFIT
    stop_loss     = (float(row[7]) / 100) if row[7] is not None else STOP_LOSS
    crash_exit    = CRASH_EXIT
    m5_min        = float(row[5]) if row[5] is not None else 8
    m5_max             = None
    max_positions      = int(row[8])  if row[8]  is not None else 5
    pref_scam_filter   = bool(row[9]  if row[9]  is not None else 1)
    pref_notifications = bool(row[10] if row[10] is not None else 1)
    user_trade_pct = float(row[11]) if (len(row) > 11 and row[11] is not None) else 0.20

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
    print(f'[trader] {short} session={wallet[:8]}... trading={_trading_wallet[:8]}...', flush=True)
    print(f'[trader] STRATEGY SETTINGS:', flush=True)
    print(f'[trader]   entry  : change5m >= {m5_min}% OR change1h >= {m5_min}% + vol rising + not reversing >5%', flush=True)
    print(f'[trader]   TP     : +{round(take_profit*100)}%', flush=True)
    print(f'[trader]   SL     : -{round(stop_loss*100)}%', flush=True)
    print(f'[trader]   exit   : {round(EXIT_PERCENTAGE*100)}% of position', flush=True)
    print(f'[trader]   max pos: 5  |  scan interval: 30s', flush=True)
    add_user_log(wallet, '[' + short + '] Trader started — TP:+' + str(round(take_profit*100)) +
                 '% SL:-' + str(round(stop_loss*100)) +
                 '% | entry: ' + _m5_desc + ' 5m OR 1h + not reversing | max 5 pos | scan 30s')
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
                                       exit_reason='CRASH EXIT ' + _cpct, opened_at=_pos.get('opened_at', 0.0),
                                       pref_notifications=pref_notifications)
            else:
                _record_user_trade(user_id, us, _label, _pos['buy_price'], _price,
                                   _pos['amount'], _pos.get('spend', 0), mint=_mint,
                                   exit_reason='CRASH EXIT ' + _cpct, opened_at=_pos.get('opened_at', 0.0),
                                   pref_notifications=pref_notifications)
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
                                       exit_reason='STOP LOSS', opened_at=_pos.get('opened_at', 0.0),
                                       pref_notifications=pref_notifications)
            else:
                _record_user_trade(user_id, us, _label, _pos['buy_price'], _price,
                                   _pos['amount'], _pos.get('spend', 0), mint=_mint,
                                   exit_reason='STOP LOSS', opened_at=_pos.get('opened_at', 0.0),
                                   pref_notifications=pref_notifications)
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
                print(f'[bot] {short} running=True tokens={total_live} pos={open_pos}/5 sol={round(us_sol,4)} scanning...', flush=True)

                _GAS_MIN = 0.005  # minimum SOL needed to pay transaction fees
                if us_sol < _GAS_MIN:
                    _gas_msg = (f'[{short}] ⚠ LOW SOL — trading wallet has {round(us_sol, 6)} SOL '
                                f'(need ≥{_GAS_MIN} for gas). Buys skipped. '
                                f'Fund: {_trading_wallet}')
                    add_user_log(wallet, _gas_msg)
                    print(f'[bot] {short} SKIPPING BUYS — insufficient SOL ({round(us_sol,6)}) '
                          f'in trading wallet {_trading_wallet}', flush=True)
                    # Exit checks (Pass 1) still run below — sells return SOL.
                elif total_live == 0:
                    add_user_log(wallet, '[' + short + '] Waiting for token data... SOL:' + str(round(us_sol, 4)) + ' Pos:' + str(open_pos) + '/' + str(max_positions))
                else:
                    add_user_log(wallet, '[' + short + '] Scanning ' + str(total_live) +
                                 ' tokens... SOL:' + str(round(us_sol, 4)) + ' Pos:' + str(open_pos) + '/' + str(max_positions))

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
                                                   exit_reason='RUGPULL ' + _rug_reason[:40], opened_at=pos.get('opened_at', 0.0),
                                                   pref_notifications=pref_notifications)
                        else:
                            add_user_log(wallet, '[' + short + '] ✗ [rugpull] Sell failed — position cleared')
                            _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'],
                                               mint=mint, exit_reason='RUGPULL ' + _rug_reason[:40],
                                               opened_at=pos.get('opened_at', 0.0),
                                               pref_notifications=pref_notifications)
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
                                                   exit_reason='CRASH EXIT ' + crash_pct, opened_at=pos.get('opened_at', 0.0),
                                                   pref_notifications=pref_notifications)
                        else:
                            add_user_log(wallet, '[' + short + '] ✗ [crash-exit] Sell failed — position cleared')
                            _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'],
                                               mint=mint, exit_reason='CRASH EXIT ' + crash_pct,
                                               opened_at=pos.get('opened_at', 0.0),
                                               pref_notifications=pref_notifications)
                        positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
                        open_pos -= 1
                        continue  # skip normal TP/SL — crash exit already handled
                    exit_reason = None
                    if chg <= -stop_loss:
                        exit_reason = 'STOP LOSS ' + str(round(chg*100,1)) + '%'
                    elif chg >= take_profit:
                        exit_reason = 'TAKE PROFIT +' + str(round(chg*100,1)) + '%'
                    if exit_reason:
                        add_user_log(wallet, '[' + short + '] ' + exit_reason + ' ' + label)
                        with _use_key(_enc_blob, wallet) as _pk:
                            sell_ok = _execute_user_swap(wallet, _pk, 'sell', mint, str(pos['amount']))
                        if sell_ok:
                            with _use_key(_enc_blob, wallet) as _pk:
                                _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'],
                                                   wallet=wallet, private_key=_pk, mint=mint,
                                                   exit_reason=exit_reason, opened_at=pos.get('opened_at', 0.0),
                                                   pref_notifications=pref_notifications)
                        else:
                            add_user_log(wallet, '[' + short + '] ✗ Sell failed — position cleared')
                            _record_user_trade(user_id, us, label, pos['buy_price'], price, pos['amount'], pos['spend'],
                                               mint=mint, exit_reason=exit_reason,
                                               opened_at=pos.get('opened_at', 0.0),
                                               pref_notifications=pref_notifications)
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
                if not stop_event.is_set() and open_pos < max_positions and us_sol >= _GAS_MIN and not _pc_locked:
                    # Re-fetch blacklist each scan so additions take effect immediately
                    try:
                        _bl_conn = sqlite3.connect(DB_FILE)
                        _blacklisted = frozenset(
                            r[0] for r in _bl_conn.execute(
                                'SELECT mint FROM user_blacklist WHERE user_id=?',
                                (user_id,)).fetchall())
                        _bl_conn.close()
                    except Exception:
                        _blacklisted = frozenset()
                    not_held = [t for t in live if positions.get(t['mint'], {}).get('amount', 0) == 0]
                    qualifying = []
                    _skip_log  = []
                    _now_cd    = time.time()
                    for _t in not_held:
                        _tsym = _t.get('symbol', '') or _t['mint'][:8]
                        if _t['mint'] in _blacklisted:
                            _skip_log.append(f'[skip] {_tsym}: blacklisted by user')
                            continue
                        if pref_scam_filter:
                            _rf = _t.get('breakdown', {}).get('risk_flags', [])
                            if 'VERY LOW LIQ' in _rf:
                                _skip_log.append(f'[skip] {_tsym}: scam filter — VERY LOW LIQ')
                                continue
                        _dex  = _t.get('dexId', '') or ''
                        _sc   = _t.get('score', 0)
                        _m5   = _t.get('change5m', 0)
                        _h1   = _t.get('change1h', 0)
                        _v5m  = _t.get('volume5m', 0)
                        _v1h  = _t.get('volume1h', 0)
                        _vol_rising = bool(_v5m > 0 and _v1h > 0 and _v5m > _v1h / 12)
                        _m5_ok = (_m5 >= m5_min or _h1 >= m5_min) if m5_max is None else (m5_min <= _m5 <= m5_max or m5_min <= _h1 <= m5_max)
                        _snap = _price_snapshots.get(_t['mint'])
                        _reversing = bool(
                            _snap and
                            _t['price'] < _snap['price'] * 0.95
                        )
                        _cd_exp  = cooldown_tokens.get(_tsym)
                        _cooling = bool(_cd_exp and _now_cd < _cd_exp)

                        if _sc < 5.0:
                            _skip_log.append(f'[skip] {_tsym}: score too low ({round(_sc,1)} < 5.0)')
                            continue
                        if not _m5_ok:
                            _skip_log.append(f'[skip] {_tsym}: trend too low (5m:{round(_m5,1)}% 1h:{round(_h1,1)}% — need {_m5_desc} on either)')
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
                                 str(total_live) + ' qualify (' + _m5_desc + ' 5m OR 1h + vol rising + not reversing)')
                    print(f'[scan] threshold={m5_min}% — {len(qualifying)}/{len(not_held)} qualify — top skips:', flush=True)
                    for _sl in _skip_log[:5]:
                        print(f'  {_sl}', flush=True)
                    if qualifying:
                        for _qt in qualifying[:3]:
                            print(f'  [qualify] {_qt.get("symbol","")} score={_qt.get("score",0)} '
                                  f'5m={round(_qt.get("change5m",0),1)}% 1h={round(_qt.get("change1h",0),1)}%', flush=True)
                    if qualifying:
                        best  = qualifying[0]
                        bmint = best['mint']
                        label = best['symbol'] or bmint[:8]
                        sc    = best['score']
                        m5    = best.get('change5m', 0)
                        m5s   = ('+' if m5 >= 0 else '') + str(round(m5, 1)) + '%'
                        add_user_log(wallet, '[' + short + '] Best: ' + label +
                                     ' score ' + str(sc) + '/10 → BUYING m5:' + m5s)
                        _safety = _check_mint_safety(bmint)
                        if _safety['mint_authority_active'] or _safety['freeze_authority_active']:
                            add_user_log(wallet, '[' + short + '] SKIPPING ' + label +
                                         ' — mint/freeze authority still active (rug risk)')
                            continue
                        _lp = _check_lp_locked(bmint)
                        if _lp['ok'] and _lp['lp_locked_pct'] < 50:
                            add_user_log(wallet, '[' + short + '] SKIPPING ' + label +
                                         ' — only ' + str(round(_lp['lp_locked_pct'])) + '% of LP locked (rug risk)')
                            continue
                        trade_pct = 0.60 if sc >= 7 else user_trade_pct
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
                                _buy_ok = _execute_user_swap(wallet, _pk, 'buy', bmint, str(spend))
                            if _buy_ok:
                                pos['amount']          = spend / best['price']
                                pos['buy_price']       = best['price']
                                pos['spend']           = spend
                                pos['symbol']          = label
                                pos['opened_at']       = time.time()
                                pos['entry_liquidity'] = float(best.get('liquidity', 0) or 0)
                                open_pos += 1
                                _trigger_copy_buy(wallet, bmint, best['price'], label, float(best.get('liquidity', 0) or 0))
                            else:
                                add_user_log(wallet, '[' + short + '] ✗ BUY failed — ' + label + ' position NOT recorded')
                                positions.pop(bmint, None)
            except Exception as e:
                print(f'[bot] {short} LOOP ERROR: {e}', flush=True)
                add_user_log(wallet, '[' + short + '] Trader error: ' + str(e))
            stop_event.wait(config.get('interval', 30))
    finally:
        print(f'[bot] {short} loop exited — running set to False', flush=True)
        add_user_log(wallet, '[' + short + '] Trader stopped')
        us['trader_running'] = False


# ── COPY TRADING ──────────────────────────────────────
def _trigger_copy_buy(buyer_wallet: str, mint: str, price: float, symbol: str, liquidity: float):
    """Fire-and-forget: buy `mint` for every user whose copy_source = buyer_wallet."""
    def _run():
        try:
            conn = sqlite3.connect(DB_FILE)
            try:
                rows = conn.execute(
                    'SELECT wallet_address, encrypted_private_key, min_trade_size, copy_amount FROM users '
                    'WHERE copy_source=? AND encrypted_private_key != "" AND encrypted_private_key IS NOT NULL',
                    (buyer_wallet,)
                ).fetchall()
            finally:
                conn.close()
        except Exception as e:
            print(f'[copy-trade] DB error: {e}', flush=True)
            return

        for c_wallet, c_enc, c_min_usdc, c_copy_amount in rows:
            try:
                c_short = c_wallet[:6] + '...' + c_wallet[-4:]
                c_us    = get_user_state(c_wallet)
                open_pos = sum(1 for p in c_us['positions'].values() if p.get('amount', 0) > 0)
                if open_pos >= 5:
                    add_user_log(c_wallet, f'[copy] Skip {symbol}: max positions reached')
                    continue
                if c_us['positions'].get(mint, {}).get('amount', 0) > 0:
                    continue  # already holding

                # Decrypt key to get trading wallet address for balance check
                try:
                    from solders.keypair import Keypair as _KP_ct
                    with _use_key(c_enc, c_wallet) as _pk:
                        trading_wallet = str(_KP_ct.from_base58_string(_pk).pubkey())
                except Exception:
                    add_user_log(c_wallet, f'[copy] Skip {symbol}: cannot decrypt key')
                    continue

                c_sol = _get_user_sol(trading_wallet)
                if c_sol < 0.01:
                    add_user_log(c_wallet, f'[copy] Skip {symbol}: insufficient SOL ({c_sol})')
                    continue

                if c_copy_amount and float(c_copy_amount) > 0:
                    spend = round(min(float(c_copy_amount), c_sol * 0.9), 4)
                else:
                    min_spend_sol = (float(c_min_usdc or 1.0) / _sol_price_usd) if _sol_price_usd > 0 else 0.02
                    spend = round(min(min_spend_sol, c_sol * 0.5), 4)
                if spend < 0.001:
                    continue

                with _use_key(c_enc, c_wallet) as _pk:
                    ok = _execute_user_swap(c_wallet, _pk, 'buy', mint, str(spend))
                if not ok:
                    add_user_log(c_wallet, f'[copy] {symbol} buy tx failed')
                    continue

                pos = c_us['positions'].get(mint, {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0})
                pos['amount']          = pos.get('amount', 0.0) + spend / price
                pos['buy_price']       = price
                pos['spend']           = pos.get('spend', 0.0) + spend
                pos['symbol']          = symbol
                pos['opened_at']       = time.time()
                pos['entry_liquidity'] = liquidity
                c_us['positions'][mint] = pos
                add_user_log(c_wallet, f'[copy] {c_short} COPY BUY {symbol} {spend} SOL (copying {buyer_wallet[:6]}…{buyer_wallet[-4:]})')
            except Exception as e:
                print(f'[copy-trade] error for {c_wallet[:6]}: {e}', flush=True)

    threading.Thread(target=_run, daemon=True).start()


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
        "img-src 'self' data: blob: https:; "
        "connect-src 'self' "
            "https://api.binance.com "
            "https://api.mainnet-beta.solana.com "
            "https://mainnet.helius-rpc.com "
            "https://api.jup.ag "
            "https://quote-api.jup.ag "
            "https://api.dexscreener.com "
            "https://dexscreener.com "
            "https://api.helius.xyz "
            "wss: ws:; "
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
    # on mutating requests — see API_SHARED_SECRET / _csrf_check above.
    with open(os.path.join(BASE, 'dashboard.html'), 'r', encoding='utf-8') as f:
        html = f.read()
    html = html.replace('__API_SHARED_SECRET__', API_SHARED_SECRET)
    _sw = session.get('wallet', '')
    print(f'[phantom-debug] index() session_wallet={_sw!r} '
          f'cookies_received={list(request.cookies.keys())} '
          f'host={request.headers.get("Host")}', flush=True)
    _ss = (_sw[:4] + '...' + _sw[-4:]) if len(_sw) > 8 else _sw
    html = html.replace('__SESSION_WALLET__', _sw)
    html = html.replace('__SESSION_SHORT__',  _ss)
    resp = app.response_class(html, mimetype='text/html')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/dashboard')
def dashboard_redirect():
    qs = request.query_string.decode('utf-8')
    target = '/?' + qs if qs else '/'
    return redirect(target, 302)

@app.route('/api/phantom/init', methods=['POST'])
def api_phantom_init():
    """Generate a NaCl keypair server-side for Phantom v1 deep-link.
    Returns {ok, dapp_pk (b58), token}. Token is used by /api/phantom/decrypt."""
    if not _NACL_OK:
        return jsonify({'ok': False, 'error': 'nacl unavailable'}), 500
    # Evict expired sessions (TTL 10 min)
    now = time.time()
    expired = [t for t, v in _phantom_sessions.items() if now - v['created'] > 600]
    for t in expired:
        _phantom_sessions.pop(t, None)
    sk_obj = _nacl_public.PrivateKey.generate()
    dapp_pk_bytes = bytes(sk_obj.public_key)
    dapp_sk_bytes = bytes(sk_obj)
    token = secrets.token_hex(32)
    _phantom_sessions[token] = {'sk': dapp_sk_bytes, 'created': now}
    print(f'[phantom] init token={token[:8]}… pk={_b58enc(dapp_pk_bytes)[:12]}…', flush=True)
    return jsonify({'ok': True, 'dapp_pk': _b58enc(dapp_pk_bytes), 'token': token})


@app.route('/api/phantom/decrypt', methods=['POST'])
def api_phantom_decrypt():
    """Decrypt Phantom v1 callback payload using the stored server-side keypair.
    Body: {token, phantom_pk, nonce, data} — all b58-encoded strings."""
    if not _NACL_OK:
        return jsonify({'ok': False, 'error': 'nacl unavailable'}), 500
    body = request.get_json(silent=True) or {}
    token       = body.get('token', '')
    phantom_pk_b58 = body.get('phantom_pk', '')
    nonce_b58   = body.get('nonce', '')
    data_b58    = body.get('data', '')
    if not all([token, phantom_pk_b58, nonce_b58, data_b58]):
        return jsonify({'ok': False, 'error': 'missing params'}), 400
    session_data = _phantom_sessions.pop(token, None)
    if not session_data:
        print(f'[phantom] decrypt — token not found: {token[:8]}…', flush=True)
        return jsonify({'ok': False, 'error': 'session expired or invalid'}), 400
    try:
        phantom_pk_obj = _nacl_public.PublicKey(_b58dec(phantom_pk_b58))
        dapp_sk_obj    = _nacl_public.PrivateKey(session_data['sk'])
        box            = _nacl_public.Box(dapp_sk_obj, phantom_pk_obj)
        decrypted      = box.decrypt(_b58dec(data_b58), _b58dec(nonce_b58))
        payload        = json.loads(decrypted.decode('utf-8'))
        wallet_address = payload.get('public_key', '')
        if not wallet_address:
            return jsonify({'ok': False, 'error': 'no public_key in payload'}), 400
        if not is_valid_solana_address(wallet_address):
            return jsonify({'ok': False, 'error': 'invalid wallet address in payload'}), 400
        print(f'[phantom] decrypt OK wallet={wallet_address[:8]}…', flush=True)
        # NaCl handshake proved ownership — establish session directly (no nonce/sig needed)
        session.permanent = True
        session.modified  = True
        session['wallet'] = wallet_address
        csrf_tok = _get_csrf_token()
        try:
            get_or_create_user(wallet_address)
        except Exception:
            pass
        threading.Thread(target=fetch_user_balances, args=(wallet_address,), daemon=True).start()
        add_user_log(wallet_address, 'Wallet connected (mobile): ' + wallet_address[:6] + '...' + wallet_address[-4:])
        ip = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()
        threading.Thread(target=_check_wallet_multi_ip, args=(wallet_address, ip), daemon=True).start()
        print(f'[phantom-debug] is_secure={request.is_secure} '
              f'x_fwd_proto={request.headers.get("X-Forwarded-Proto")} '
              f'host={request.headers.get("Host")} '
              f'session_after_set={dict(session)}', flush=True)
        return jsonify({'ok': True, 'wallet_address': wallet_address, 'csrf_token': csrf_tok})
    except Exception as e:
        print(f'[phantom] decrypt ERROR: {e}', flush=True)
        return jsonify({'ok': False, 'error': str(e)}), 400


@app.route('/api/phantom/decrypt-signature', methods=['POST'])
def api_phantom_decrypt_signature():
    """Decrypt a Phantom v1 signMessage callback payload.
    Body: {token, phantom_pk, nonce, data} — all b58-encoded strings.
    The decrypted payload contains a 'signature' field (b58).
    Returns {ok, signature}."""
    if not _NACL_OK:
        return jsonify({'ok': False, 'error': 'nacl unavailable'}), 500
    body = request.get_json(silent=True) or {}
    token          = body.get('token', '')
    phantom_pk_b58 = body.get('phantom_pk', '')
    nonce_b58      = body.get('nonce', '')
    data_b58       = body.get('data', '')
    if not all([token, phantom_pk_b58, nonce_b58, data_b58]):
        return jsonify({'ok': False, 'error': 'missing params'}), 400
    session_data = _phantom_sessions.pop(token, None)
    if not session_data:
        print(f'[phantom] decrypt-sig — token not found: {token[:8]}…', flush=True)
        return jsonify({'ok': False, 'error': 'session expired or invalid'}), 400
    try:
        phantom_pk_obj = _nacl_public.PublicKey(_b58dec(phantom_pk_b58))
        dapp_sk_obj    = _nacl_public.PrivateKey(session_data['sk'])
        box            = _nacl_public.Box(dapp_sk_obj, phantom_pk_obj)
        decrypted      = box.decrypt(_b58dec(data_b58), _b58dec(nonce_b58))
        payload        = json.loads(decrypted.decode('utf-8'))
        signature_b58  = payload.get('signature', '')
        if not signature_b58:
            return jsonify({'ok': False, 'error': 'no signature in payload'}), 400
        print(f'[phantom] decrypt-sig OK sig={signature_b58[:12]}…', flush=True)
        return jsonify({'ok': True, 'signature': signature_b58})
    except Exception as e:
        print(f'[phantom] decrypt-sig ERROR: {e}', flush=True)
        return jsonify({'ok': False, 'error': str(e)}), 400


@app.route('/phantom-callback')
def phantom_callback():
    resp = make_response(render_template('phantom_callback.html'))
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma']        = 'no-cache'
    resp.headers['Expires']       = '0'
    return resp

@app.route('/api/test-auth')
def api_test_auth():
    """Temporary diagnostic: call from live_market to confirm session reaches Flask."""
    wallet = session.get('wallet', '')
    csrf_in_session = 'csrf_token' in session
    return jsonify({
        'authenticated': bool(wallet),
        'wallet':        (wallet[:4] + '...' + wallet[-4:]) if len(wallet) >= 8 else wallet or None,
        'csrf_token_set': csrf_in_session,
        'session_keys':  list(session.keys()),
        'host':          request.host,
        'origin':        request.headers.get('Origin', ''),
        'x_client_secret_required': bool(API_SHARED_SECRET),
        'x_client_secret_sent':     bool(request.headers.get('X-API-Shared-Secret')),
    })

@app.route('/api/my-trades')
def api_my_trades():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'error': 'not logged in'}), 401
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute('SELECT id FROM users WHERE wallet_address=?', (wallet,)).fetchone()
        if not row:
            return jsonify({'trades': []})
        user_id = row['id']
        trades = conn.execute(
            'SELECT token, entry_price, exit_price, amount, pnl, timestamp, opened_at, mint_address '
            'FROM trades WHERE user_id=? AND exit_price IS NOT NULL AND exit_price != 0 '
            'ORDER BY timestamp DESC LIMIT 5',
            (user_id,)
        ).fetchall()
        result = []
        for t in trades:
            entry  = t['entry_price'] or 0
            exit_p = t['exit_price']  or 0
            pnl_pct = round(((exit_p - entry) / entry * 100), 2) if entry else 0
            result.append({
                'symbol':        t['token'],
                'token':         t['token'],
                'entry_price':   entry,
                'exit_price':    exit_p,
                'amount':        float(t['amount'] or 0),
                'pnl':           t['pnl'],
                'pnl_pct':       pnl_pct,
                'pnl_sol':       t['pnl'],
                'opened_at':     t['opened_at'],
                'timestamp':     t['timestamp'],
                'token_address': t['mint_address'] or '',
            })
        return jsonify({'trades': result})
    finally:
        conn.close()

@app.route('/api/connect-wallet', methods=['POST'])
def api_connect_wallet():
    return set_wallet()

@app.route('/profile')
def profile():
    wallet = _current_wallet()
    if not wallet:
        return redirect('/')
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        user = conn.execute(
            'SELECT id, username, avatar_url, bio, created_at FROM users WHERE wallet_address=?',
            (wallet,)
        ).fetchone()
        if not user:
            return redirect('/')
        user_id = user['id']
        stats = conn.execute(
            'SELECT COUNT(*) AS total, '
            'SUM(CASE WHEN pnl >= 0 THEN 1 ELSE 0 END) AS wins, '
            'SUM(pnl) AS total_pnl '
            'FROM trades WHERE user_id=? AND exit_price IS NOT NULL AND exit_price != 0',
            (user_id,)
        ).fetchone()
        posts = conn.execute(
            'SELECT content, likes, created_at FROM feed_posts '
            'WHERE wallet=? ORDER BY created_at DESC LIMIT 5',
            (wallet,)
        ).fetchall()
        followers = conn.execute(
            'SELECT COUNT(*) FROM follows WHERE following_id=?', (user_id,)
        ).fetchone()[0]
        following = conn.execute(
            'SELECT COUNT(*) FROM follows WHERE follower_id=?', (user_id,)
        ).fetchone()[0]
        total     = stats['total'] or 0
        wins      = stats['wins']  or 0
        win_rate  = round(wins / total * 100) if total else 0
        total_pnl = round(stats['total_pnl'] or 0, 4)
        wallet_short = (wallet[:4] + '...' + wallet[-4:]) if len(wallet) >= 8 else wallet
        sol_balance = None
        try:
            r = requests.post(SOLANA_RPC, json={
                'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [wallet]
            }, timeout=5)
            sol_balance = round(r.json()['result']['value'] / 1e9, 4)
        except Exception:
            pass
        return render_template(
            'profile.html',
            wallet=wallet,
            wallet_short=wallet_short,
            session_wallet=wallet,
            display_name=user['username'] or wallet_short,
            username=user['username'],
            avatar_url=user['avatar_url'],
            bio=user['bio'],
            created_at=(user['created_at'] or '')[:10],
            total_trades=total,
            wins=wins,
            win_rate=win_rate,
            total_pnl=total_pnl,
            pnl_positive=total_pnl >= 0,
            followers=followers,
            following=following,
            posts=[dict(p) for p in posts],
            sol_balance=sol_balance,
        )
    finally:
        conn.close()

@app.route('/profile/<wallet_address>')
def profile_view(wallet_address: str):
    """Public profile page for any wallet address."""
    session_wallet = _current_wallet()
    is_wallet = is_valid_solana_address(wallet_address)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        col = 'wallet_address' if is_wallet else 'username'
        user = conn.execute(
            f'SELECT id, username, avatar_url, bio, created_at, wallet_address FROM users WHERE {col}=?',
            (wallet_address,)
        ).fetchone()
        if not user:
            return redirect('/traders')
        wallet_address = user['wallet_address']
        user_id = user['id']
        stats = conn.execute(
            'SELECT COUNT(*) AS total, '
            'SUM(CASE WHEN pnl >= 0 THEN 1 ELSE 0 END) AS wins, '
            'SUM(pnl) AS total_pnl '
            'FROM trades WHERE user_id=? AND exit_price IS NOT NULL AND exit_price != 0',
            (user_id,)
        ).fetchone()
        posts = conn.execute(
            'SELECT content, likes, created_at FROM feed_posts '
            'WHERE wallet=? ORDER BY created_at DESC LIMIT 5',
            (wallet_address,)
        ).fetchall()
        followers = conn.execute(
            'SELECT COUNT(*) FROM follows WHERE following_id=?', (user_id,)
        ).fetchone()[0]
        following = conn.execute(
            'SELECT COUNT(*) FROM follows WHERE follower_id=?', (user_id,)
        ).fetchone()[0]
        total     = stats['total'] or 0
        wins      = stats['wins']  or 0
        win_rate  = round(wins / total * 100) if total else 0
        total_pnl = round(stats['total_pnl'] or 0, 4)
        wallet_short = (wallet_address[:4] + '...' + wallet_address[-4:]) if len(wallet_address) >= 8 else wallet_address
        sw = session_wallet or ''
        sw_short = (sw[:4] + '...' + sw[-4:]) if len(sw) >= 8 else sw
        sol_balance = None
        try:
            r = requests.post(SOLANA_RPC, json={
                'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [wallet_address]
            }, timeout=5)
            sol_balance = round(r.json()['result']['value'] / 1e9, 4)
        except Exception:
            pass
        return render_template(
            'profile.html',
            wallet=wallet_address,
            wallet_short=wallet_short,
            session_wallet=sw,
            session_wallet_short=sw_short,
            display_name=user['username'] or wallet_short,
            username=user['username'],
            avatar_url=user['avatar_url'],
            bio=user['bio'],
            created_at=(user['created_at'] or '')[:10],
            total_trades=total,
            wins=wins,
            win_rate=win_rate,
            total_pnl=total_pnl,
            pnl_positive=total_pnl >= 0,
            followers=followers,
            following=following,
            posts=[dict(p) for p in posts],
            sol_balance=sol_balance,
        )
    finally:
        conn.close()


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


@app.route('/api/token/<mint>/co-traders', methods=['GET'])
@rate_limit(60, 60)
def api_token_co_traders(mint):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'users': []}), 401
    if not _MINT_RE.match(mint or ''):
        return jsonify({'ok': False, 'users': []}), 400
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE wallet_address = ?', (wallet,))
        me_row = c.fetchone()
        if not me_row:
            conn.close()
            return jsonify({'ok': True, 'users': []})
        me_id = me_row[0]
        # Users the session wallet follows
        c.execute('''
            SELECT u.id, u.username, u.avatar_url, u.wallet_address
            FROM follows f JOIN users u ON u.id = f.following_id
            WHERE f.follower_id = ?
        ''', (me_id,))
        followed = c.fetchall()
        conn.close()
    except Exception as e:
        print(f'[co-traders] DB error: {e}', flush=True)
        return jsonify({'ok': True, 'users': []})

    # Current price from shared token state (best-effort)
    cur_price = next(
        (float(t['price']) for t in state.get('tokens', [])
         if t.get('mint') == mint and t.get('price')),
        None
    )

    result = []
    for uid, username, avatar_url, w_addr in followed:
        if not w_addr:
            continue
        us = user_states.get(w_addr)
        if not us:
            continue
        pos = us.get('positions', {}).get(mint)
        if not pos or not pos.get('amount'):
            continue
        entry = float(pos.get('buy_price') or 0)
        amount = float(pos.get('amount') or 0)
        pnl = None
        if cur_price is not None and entry > 0 and amount > 0:
            pnl = round(amount * (cur_price - entry), 6)
        short = (w_addr[:4] + '...' + w_addr[-4:]) if len(w_addr) >= 8 else w_addr
        result.append({
            'user_id':     uid,
            'username':    username or short,
            'avatar_url':  avatar_url or '',
            'wallet':      short,
            'entry_price': round(entry, 8),
            'pnl_current': pnl,
        })
    return jsonify({'ok': True, 'users': result})


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


@app.route('/api/copy-trade', methods=['POST'])
@rate_limit(20, 60)
def api_copy_trade_start():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    target = str((request.json or {}).get('target_wallet', '')).strip()
    if not is_valid_solana_address(target):
        return jsonify({'ok': False, 'msg': 'Invalid target wallet'}), 400
    if target == wallet:
        return jsonify({'ok': False, 'msg': 'Cannot copy yourself'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute('UPDATE users SET copy_source=? WHERE wallet_address=?', (target, wallet))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/copy-trade/stop', methods=['POST'])
@rate_limit(20, 60)
def api_copy_trade_stop():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute('UPDATE users SET copy_source=NULL WHERE wallet_address=?', (wallet,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/copy-trade/toggle', methods=['POST'])
@csrf_exempt
@rate_limit(20, 60)
def api_copy_trade_toggle():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    body   = request.get_json(silent=True) or {}
    # accept both 'wallet' (new) and 'target_wallet' (legacy)
    target = str(body.get('wallet') or body.get('target_wallet', '')).strip()
    # accept both 'sol_amount' (new) and 'amount_sol' (legacy)
    raw_amount = body.get('sol_amount') if body.get('sol_amount') is not None else body.get('amount_sol', 0.1)
    if not is_valid_solana_address(target):
        return jsonify({'ok': False, 'msg': 'Invalid target wallet'}), 400
    if target == wallet:
        return jsonify({'ok': False, 'msg': 'Cannot copy yourself'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        row = conn.execute('SELECT copy_source FROM users WHERE wallet_address=?', (wallet,)).fetchone()
        currently_copying_target = row and row[0] == target
        if currently_copying_target:
            conn.execute('UPDATE users SET copy_source=NULL, copy_amount=NULL WHERE wallet_address=?', (wallet,))
            new_active = 0
        else:
            try:
                amount_sol = round(float(raw_amount), 4)
                if amount_sol < 0.01 or amount_sol > 100:
                    return jsonify({'ok': False, 'msg': 'Amount must be 0.01–100 SOL'}), 400
            except (TypeError, ValueError):
                return jsonify({'ok': False, 'msg': 'Invalid amount'}), 400
            conn.execute('UPDATE users SET copy_source=?, copy_amount=? WHERE wallet_address=?',
                         (target, amount_sol, wallet))
            new_active = 1
        # sync copy_relationships table
        existing = conn.execute(
            'SELECT id FROM copy_relationships WHERE copier_wallet=? AND copied_wallet=?',
            (wallet, target)
        ).fetchone()
        if existing:
            conn.execute('UPDATE copy_relationships SET active=? WHERE id=?', (new_active, existing[0]))
        else:
            conn.execute(
                'INSERT INTO copy_relationships (copier_wallet, copied_wallet, active) VALUES (?,?,?)',
                (wallet, target, new_active)
            )
        conn.commit()
        copiers_count = conn.execute(
            'SELECT COUNT(*) FROM copy_relationships WHERE copied_wallet=? AND active=1',
            (target,)
        ).fetchone()[0]
        print(f'[copy-trade] {wallet[:8]}… {"now copying" if new_active else "stopped copying"} {target[:8]}…', flush=True)
    finally:
        conn.close()
    return jsonify({'ok': True, 'active': bool(new_active), 'copying': bool(new_active), 'copiers_count': copiers_count})


@app.route('/api/copy-trade/status', methods=['GET'])
@rate_limit(60, 60)
def api_copy_trade_status():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute('SELECT copy_source FROM users WHERE wallet_address=?', (wallet,)).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({'ok': True, 'copying': False, 'target_wallet': None})
    target = row[0]
    return jsonify({'ok': True, 'copying': bool(target), 'target_wallet': target})


@app.route('/card/<wallet_addr>')
def pnl_card_page(wallet_addr):
    """Public shareable PnL card page — no login required."""
    if not is_valid_solana_address(wallet_addr):
        return 'Invalid wallet address', 400
    stats    = _pnl_card_stats(wallet_addr)
    card_url = 'https://orcagent.fun/card/' + wallet_addr
    return render_template('card.html', stats=stats, card_url=card_url)


@app.route('/traders')
def traders():
    session_wallet = _current_wallet()
    entries        = []
    following_ids  = set()
    my_copy_source = None   # wallet address the session user is currently copying
    try:
        conn = sqlite3.connect(DB_FILE)
        c    = conn.cursor()
        # Resolve current user's id, follow list, and active copy source
        if session_wallet:
            row = c.execute('SELECT id, copy_source FROM users WHERE wallet_address=?', (session_wallet,)).fetchone()
            if row:
                me_id, my_copy_source = row[0], row[1]
                frows = c.execute('SELECT following_id FROM follows WHERE follower_id=?', (me_id,)).fetchall()
                following_ids = {r[0] for r in frows}
        c.execute('''
            SELECT
                u.id,
                u.wallet_address,
                u.username,
                u.avatar_url,
                u.badges,
                ROUND(SUM(t.pnl), 4)                                          AS total_pnl,
                ROUND(SUM(CASE WHEN t.pnl >= 0 THEN 1.0 ELSE 0.0 END)
                      * 100.0 / COUNT(*), 1)                                  AS win_rate,
                COUNT(*)                                                       AS trade_count,
                ROUND(MAX(
                    CASE WHEN t.entry_price > 0
                         THEN (t.exit_price - t.entry_price) / t.entry_price * 100.0
                         ELSE 0.0 END
                ), 1)                                                          AS best_trade_pct,
                (SELECT t2.token FROM trades t2
                 WHERE t2.user_id = u.id AND t2.entry_price > 0
                 ORDER BY (t2.exit_price - t2.entry_price) / t2.entry_price DESC
                 LIMIT 1)                                                      AS best_token,
                (SELECT COUNT(*) FROM follows f
                 WHERE f.following_id = u.id)                                 AS follower_count,
                ROUND(SUM(CASE WHEN t.timestamp >= datetime(\'now\',\'-7 days\')
                               THEN t.pnl ELSE 0.0 END), 4)                  AS week_pnl
            FROM trades t
            JOIN users u ON u.id = t.user_id
            WHERE u.wallet_address IS NOT NULL AND u.wallet_address != \'\'
            GROUP BY t.user_id
            ORDER BY total_pnl DESC
            LIMIT 100
        ''')
        rows = c.fetchall()
        conn.close()
    except Exception as e:
        print(f'[traders] DB error: {e}', flush=True)
        rows = []
    for rank, (uid, wallet, username, avatar_url, badges_str,
               total_pnl, win_rate, trade_count,
               best_trade_pct, best_token,
               follower_count, week_pnl) in enumerate(rows, 1):
        wallet = wallet or ''
        anon   = (wallet[:4] + '…' + wallet[-4:]) if len(wallet) >= 8 else (wallet or '???')
        entries.append({
            'user_id':        int(uid),
            'rank':           rank,
            'wallet':         wallet,
            'wallet_short':   anon,
            'username':       username or anon,
            'avatar_url':     avatar_url or '',
            'badges':         [b.strip() for b in (badges_str or '').split(',') if b.strip()],
            'total_pnl':      round(float(total_pnl      or 0), 4),
            'win_rate':       round(float(win_rate        or 0), 1),
            'trade_count':    int  (trade_count           or 0),
            'best_trade_pct': round(float(best_trade_pct or 0), 1),
            'best_token':     (best_token or '').upper()[:12],
            'follower_count': int  (follower_count        or 0),
            'week_pnl':       round(float(week_pnl        or 0), 4),
            'is_me':          bool(session_wallet and wallet == session_wallet),
            'is_following':   int(uid) in following_ids,
            'is_copying':     bool(my_copy_source and my_copy_source == wallet),
        })
    wallet_short = ((session_wallet[:4] + '…' + session_wallet[-4:])
                    if len(session_wallet) >= 8 else '')
    return render_template(
        'traders.html',
        entries=entries,
        wallet=session_wallet,
        wallet_short=wallet_short,
        logged_in=bool(session_wallet),
        csrf_token=_get_csrf_token() if session_wallet else '',
        client_secret=API_SHARED_SECRET,
    )

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
                ROUND(MAX(t.pnl), 4)                                                    AS best_trade,
                u.badges                                                                 AS badges
            FROM trades t
            JOIN users u ON u.id = t.user_id
            WHERE u.wallet_address IS NOT NULL AND u.wallet_address != \'\'
              AND (t.source = \'manual\' OR (t.source IS NULL AND t.mint_address IS NOT NULL))
            GROUP BY t.user_id
            ORDER BY total_pnl DESC
            LIMIT 50
        ''')
        rows = c.fetchall()
        conn.close()
    except Exception as e:
        print(f'[leaderboard] DB error: {e}', flush=True)
        rows = []
    for rank, (wallet, total_pnl, win_rate, trade_count, best_trade, badges_str) in enumerate(rows, 1):
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
            'badges':      [b.strip() for b in (badges_str or '').split(',') if b.strip()],
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


@app.route('/live-market')
def live_market():
    session_wallet = _current_wallet()
    wallet_short = ((session_wallet[:4] + '...' + session_wallet[-4:])
                    if len(session_wallet) >= 8 else '')
    return render_template('live_market.html',
                           wallet_short=wallet_short,
                           csrf_token=_get_csrf_token(),
                           client_secret=API_SHARED_SECRET)


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


@app.route('/wallet')
def wallet_page():
    print(f'[wallet] route hit — session wallet: {session.get("wallet")} | session keys: {list(session.keys())}', flush=True)
    try:
        if 'wallet' not in session:
            print('[wallet] no wallet in session, redirecting', flush=True)
            return redirect('/?connect=1')
        wallet_address = session['wallet']
        wallet_short = (wallet_address[:4] + '...' + wallet_address[-4:]) if len(wallet_address) >= 8 else ''
        print(f'[wallet] rendering template for {wallet_address}', flush=True)
        return render_template(
            'wallet.html',
            wallet_address=wallet_address,
            wallet_short=wallet_short,
            is_admin=_is_owner(wallet_address),
        )
    except Exception as e:
        print(f'[wallet] exception: {e}', flush=True)
        return f'<h1>Wallet Error: {str(e)}</h1>', 500


@app.route('/settings')
def settings_page():
    wallet = _current_wallet()
    if not wallet:
        return redirect('/?connect=1')
    wallet_short = (wallet[:4] + '...' + wallet[-4:]) if len(wallet) >= 8 else wallet
    x_handle = x_share_trade = x_share_badge = None
    conn = sqlite3.connect(DB_FILE)
    try:
        xrow = conn.execute(
            'SELECT x_handle, share_on_big_trade, share_on_badge FROM x_connections WHERE wallet_address=?',
            (wallet,)
        ).fetchone()
        if xrow:
            x_handle, x_share_trade, x_share_badge = xrow[0], bool(xrow[1]), bool(xrow[2])
    finally:
        conn.close()
    return render_template(
        'settings.html',
        wallet=wallet,
        wallet_short=wallet_short,
        is_admin=_is_owner(wallet),
        csrf_token=_get_csrf_token(),
        x_handle=x_handle,
        x_share_trade=x_share_trade,
        x_share_badge=x_share_badge,
    )


@app.route('/admin')
def admin_page():
    wallet = session.get('wallet', '')
    if not wallet or get_user_role(wallet) == 'user':
        return redirect('/')
    conn = sqlite3.connect(DB_FILE)
    try:
        users_count  = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        trades_count = conn.execute('SELECT COUNT(*) FROM trades').fetchone()[0]
        volume_sol   = conn.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM trades').fetchone()[0] or 0.0
        fees_sol     = conn.execute('SELECT COALESCE(SUM(fee_amount), 0) FROM trades').fetchone()[0] or 0.0

        raw_users = conn.execute('''
            SELECT u.wallet_address, u.username, u.created_at,
                   COUNT(t.id) as trade_count,
                   COALESCE(SUM(t.pnl), 0) as total_pnl
            FROM users u
            LEFT JOIN trades t ON t.user_id = u.id
            GROUP BY u.id
            ORDER BY u.created_at DESC
            LIMIT 100
        ''').fetchall()

        raw_posts = conn.execute('''
            SELECT fp.id, fp.wallet, fp.content, fp.created_at, u.username
            FROM feed_posts fp
            LEFT JOIN users u ON fp.wallet = u.wallet_address
            ORDER BY fp.created_at DESC
            LIMIT 50
        ''').fetchall()
    finally:
        conn.close()

    users = []
    for row in raw_users:
        w, username, created_at, trade_count, total_pnl = row
        ws = (w[:4] + '…' + w[-4:]) if len(w) >= 8 else w
        ini = (username[:2] if username else w[:2]).upper()
        pnl_val = total_pnl or 0.0
        users.append({
            'wallet':       w,
            'wallet_short': ws,
            'username':     username or '',
            'display_name': username or ws,
            'initials':     ini,
            'trades':       trade_count,
            'pnl':          f'{pnl_val:+.2f}',
            'pnl_pos':      pnl_val >= 0,
            'joined':       (created_at or '')[:10] or '—',
        })

    posts = []
    for row in raw_posts:
        post_id, w, content, created_at, username = row
        author = username or ((w[:6] + '…' + w[-4:]) if len(w) >= 10 else w)
        posts.append({
            'id':      post_id,
            'wallet':  w,
            'content': content or '',
            'author':  author,
            'time':    (created_at or '')[:16] or '—',
        })

    stats = {
        'users_count':  users_count,
        'trades_count': trades_count,
        'volume_sol':   f'{volume_sol:.2f}',
        'fees_sol':     f'{fees_sol:.4f}',
    }

    resp = make_response(render_template(
        'admin.html',
        wallet=wallet,
        users=users,
        posts=posts,
        stats=stats,
    ))
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp


@app.route('/messages')
def messages_page():
    wallet = _current_wallet()
    if not wallet:
        return redirect('/?connect=1')
    wallet_short = (wallet[:4] + '...' + wallet[-4:]) if len(wallet) >= 8 else wallet
    return render_template(
        'messages.html',
        wallet=wallet,
        wallet_short=wallet_short,
        is_admin=_is_owner(wallet),
        csrf_token=_get_csrf_token(),
    )

@app.route('/messages/<wallet_address>')
def message_thread(wallet_address):
    if 'wallet' not in session:
        return redirect('/?connect=1')
    wallet = session['wallet']
    wallet_short = (wallet[:4] + '...' + wallet[-4:]) if len(wallet) >= 8 else wallet
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute('SELECT id FROM users WHERE wallet_address=?', (wallet_address,)).fetchone()
        open_peer_id = row[0] if row else None
    finally:
        conn.close()
    return render_template(
        'messages.html',
        wallet=wallet,
        wallet_short=wallet_short,
        is_admin=_is_owner(wallet),
        open_peer_id=open_peer_id,
        csrf_token=_get_csrf_token(),
    )


@app.route('/deposit')
def deposit_page():
    return redirect('/?action=deposit')


@app.route('/withdraw')
def withdraw_page():
    return redirect('/?action=withdraw')


@app.route('/community')
def community_page():
    wallet = _current_wallet()
    if not wallet:
        return redirect('/?next=community')
    wallet_short = (wallet[:4] + '...' + wallet[-4:]) if len(wallet) >= 8 else wallet
    return redirect('/')

@app.route('/api/community/messages')
def community_messages():
    conn = sqlite3.connect(DB_FILE)
    try:
        rows = conn.execute(
            'SELECT id, wallet, content, created_at FROM community_messages ORDER BY created_at DESC LIMIT 50'
        ).fetchall()
        return jsonify([{'id': r[0], 'wallet': r[1], 'content': r[2], 'created_at': r[3]} for r in rows])
    finally:
        conn.close()

@app.route('/api/community/message', methods=['POST'])
@rate_limit(10, 60)
def post_community():
    if 'wallet' not in session:
        return jsonify({}), 401
    content = (request.json or {}).get('content', '').strip()
    if not content:
        return jsonify({'ok': False, 'msg': 'Empty content'}), 400
    if len(content) > 500:
        return jsonify({'ok': False, 'msg': 'Too long'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute(
            'INSERT INTO community_messages (wallet, content) VALUES (?,?)',
            [session['wallet'], _sanitize(content)]
        )
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()


@app.route('/api/notifications')
def get_notifications():
    if 'wallet' not in session:
        return jsonify([])
    conn = sqlite3.connect(DB_FILE)
    try:
        rows = conn.execute('''
            SELECT u.wallet_address, t.token, t.entry_price, t.exit_price, t.pnl, t.timestamp
            FROM trades t
            JOIN users u ON u.id = t.user_id
            WHERE t.timestamp > datetime("now", "-24 hours")
            ORDER BY t.timestamp DESC
            LIMIT 30
        ''').fetchall()
    finally:
        conn.close()
    result = []
    for wallet_addr, token, entry, exit_p, pnl, ts in rows:
        entry_f = float(entry or 0)
        exit_f  = float(exit_p or 0)
        pnl_pct = round((exit_f - entry_f) / entry_f * 100, 2) if entry_f else None
        result.append({
            'wallet':     wallet_addr or '',
            'symbol':     token or '',
            'pnl_pct':    pnl_pct,
            'pnl':        round(float(pnl or 0), 4),
            'created_at': ts or '',
        })
    return jsonify(result)

@app.route('/api/notifications/mine', methods=['GET'])
@rate_limit(60, 60)
def notifications_mine():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        rows = conn.execute(
            '''SELECT id, type, content, link, is_read, created_at
               FROM notifications WHERE user_id=?
               ORDER BY created_at DESC LIMIT 30''',
            (me,)
        ).fetchall()
    finally:
        conn.close()
    return jsonify({'ok': True, 'notifications': [
        {'id': r[0], 'type': r[1], 'content': r[2], 'link': r[3],
         'is_read': bool(r[4]), 'created_at': r[5]}
        for r in rows
    ]})

@app.route('/api/notifications/mine/unread_count', methods=['GET'])
@rate_limit(120, 60)
def notifications_unread_count():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        row = conn.execute(
            'SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0', (me,)
        ).fetchone()
    finally:
        conn.close()
    return jsonify({'ok': True, 'unread': row[0] if row else 0})

@app.route('/api/notifications/mine/mark_read', methods=['POST'])
@rate_limit(30, 60)
def notifications_mark_read():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        conn.execute('UPDATE notifications SET is_read=1 WHERE user_id=?', (me,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})

@app.route('/api/notifications/mine/mark_read_batch', methods=['POST'])
@rate_limit(30, 60)
def notifications_mark_read_batch():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    ids = request.get_json(silent=True) or {}
    id_list = ids.get('ids', [])
    if not isinstance(id_list, list) or not id_list:
        return jsonify({'ok': False, 'msg': 'No ids provided'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        placeholders = ','.join('?' * len(id_list))
        conn.execute(f'UPDATE notifications SET is_read=1 WHERE user_id=? AND id IN ({placeholders})',
                     [me] + id_list)
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})

@app.route('/notifications')
def notifications_page():
    wallet = _current_wallet()
    if not wallet:
        return redirect('/?next=notifications')
    wallet_short = (wallet[:4] + '...' + wallet[-4:]) if len(wallet) >= 8 else wallet
    return render_template(
        'notifications.html',
        wallet=wallet,
        wallet_short=wallet_short,
        is_admin=_is_owner(wallet),
        csrf_token=_get_csrf_token(),
    )


# ── HONEYPOTS ──
# These paths are never legitimately accessed. Any hit means a scanner or attacker.
# _security_gate() (registered above, runs first) already intercepts most of these
# via _BLOCKED_PROBE_RE (dotfiles, wp-admin, wp-login.php, config.php); /admin and
# /phpmyadmin rely on this handler since they don't match that regex.
@app.route('/.env')
@app.route('/wp-login.php')
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
@app.route('/api/wallet/connect-readonly', methods=['POST'])
@rate_limit(10, 60)
def connect_wallet_readonly():
    address = (request.json or {}).get('address', '').strip()
    if not address:
        return jsonify({'ok': False, 'msg': 'Address required'}), 400
    if not is_valid_solana_address(address):
        return jsonify({'ok': False, 'msg': 'Invalid Solana wallet address'}), 400
    session.permanent = True
    session['wallet'] = address
    session['readonly'] = True
    csrf_tok = _get_csrf_token()
    try:
        get_or_create_user(address)
    except Exception:
        pass
    add_user_log(address, 'Wallet connected (read-only): ' + address[:6] + '...' + address[-4:])
    return jsonify({'ok': True, 'wallet': address, 'readonly': True,
                    'has_trading_key': False, 'csrf_token': csrf_tok})

@app.route('/api/login_password', methods=['POST'])
@rate_limit(10, 60)
def login_password():
    ip   = request.remote_addr or '0.0.0.0'
    body = request.json or {}
    username = str(body.get('username', '')).strip()
    password = str(body.get('password', '')).strip()
    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required'}), 400

    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute(
            '''SELECT id, wallet_address, COALESCE(username,''), password_hash,
                      CASE WHEN encrypted_private_key != '' AND encrypted_private_key IS NOT NULL
                           THEN 1 ELSE 0 END,
                      COALESCE(is_admin, 0)
               FROM users
               WHERE username = ? OR wallet_address = ?
               LIMIT 1''',
            (username, username)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        _record_ip_failure(ip)
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    user_id, wallet_address, db_username, password_hash, has_trading_key, is_admin = row

    if not password_hash:
        return jsonify({'success': False, 'error': 'No password set — use Phantom or Face ID to login'}), 401

    try:
        valid = _bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        valid = False
    if not valid:
        _record_ip_failure(ip)
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    session.permanent        = True
    session.modified         = True
    session['user_id']       = user_id
    session['wallet']        = wallet_address
    session['authenticated'] = True
    csrf_tok = _get_csrf_token()
    add_user_log(wallet_address, 'Login via password')
    return jsonify({
        'success':         True,
        'redirect':        '/dashboard',
        'wallet':          wallet_address,
        'username':        db_username or '',
        'has_trading_key': bool(has_trading_key),
        'is_admin':        bool(is_admin),
        'csrf_token':      csrf_tok,
    })

@app.route('/api/set_password', methods=['POST'])
@rate_limit(10, 60)
def set_password():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'success': False, 'error': 'Login required'}), 401
    body     = request.json or {}
    password = str(body.get('password', '')).strip()
    if len(password) < 8:
        return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400
    pw_hash = _bcrypt.hashpw(password.encode('utf-8'), _bcrypt.gensalt(rounds=12)).decode('utf-8')
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute('UPDATE users SET password_hash=? WHERE wallet_address=?', (pw_hash, wallet))
        conn.commit()
    finally:
        conn.close()
    add_user_log(wallet, 'Password set/updated')
    return jsonify({'success': True})

@app.route('/api/auth/nonce', methods=['GET'])
@rate_limit(20, 60)
def auth_nonce():
    nonce = secrets.token_hex(16)
    ip    = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()
    conn  = sqlite3.connect(DB_FILE)
    try:
        conn.execute('INSERT INTO auth_nonces (nonce, ip) VALUES (?, ?)', (nonce, ip))
        conn.execute("DELETE FROM auth_nonces WHERE created_at < datetime('now', '-20 minutes')")
        conn.commit()
    finally:
        conn.close()
    resp = jsonify({
        'ok':      True,
        'nonce':   nonce,
        'message': 'Sign in to OrcAgent\n\nNonce: ' + nonce,
    })
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma']        = 'no-cache'
    return resp

@app.route('/api/auth/check-faceid', methods=['GET'])
def check_faceid():
    """Public — returns whether any WebAuthn credentials exist on the server."""
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute('SELECT COUNT(*) FROM webauthn_credentials').fetchone()
        has_any = bool(row and row[0] > 0)
    finally:
        conn.close()
    return jsonify({'has_users_with_webauthn': has_any})

@app.route('/api/auth/webauthn/has-credential', methods=['GET'])
@rate_limit(30, 60)
def webauthn_has_credential():
    """Public — check whether a specific credential_id is registered on this server.
    The client passes the stored credential_id as a query parameter or X-Credential-Id header."""
    credential_id = (
        request.args.get('credential_id') or
        request.headers.get('X-Credential-Id') or ''
    ).strip()
    if not credential_id:
        return jsonify({'has_credential': False})
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute(
            'SELECT 1 FROM webauthn_credentials WHERE credential_id=?', (credential_id,)
        ).fetchone()
        has_cred = row is not None
    finally:
        conn.close()
    return jsonify({'has_credential': has_cred})

@app.route('/api/auth/webauthn/register', methods=['POST'])
@rate_limit(10, 60)
def webauthn_register():
    # Registration requires an active session — user must already be logged in
    user_id = session.get('user_id')
    wallet  = session.get('wallet') or ''
    if not user_id:
        return jsonify({'success': False, 'msg': 'Login required before setting up Face ID'}), 401

    body          = request.json or {}
    credential_id = str(body.get('credential_id', '')).strip()
    public_key    = str(body.get('public_key',    '')).strip()
    if not credential_id or not public_key:
        return jsonify({'success': False, 'msg': 'credential_id and public_key are required'}), 400

    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute(
            '''INSERT INTO webauthn_credentials (user_id, credential_id, public_key)
               VALUES (?, ?, ?)
               ON CONFLICT(credential_id) DO UPDATE SET public_key=excluded.public_key''',
            (user_id, credential_id, public_key)
        )
        conn.execute('UPDATE users SET webauthn_ready=1 WHERE id=?', (user_id,))
        conn.commit()
    finally:
        conn.close()
    add_user_log(wallet, 'WebAuthn credential registered')
    return jsonify({'success': True})

@app.route('/api/auth/webauthn/login', methods=['POST'])
@rate_limit(10, 60)
def webauthn_login():
    body          = request.json or {}
    credential_id = str(body.get('credential_id', '')).strip()
    if not credential_id:
        return jsonify({'success': False, 'msg': 'credential_id required'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute(
            '''SELECT wc.user_id, u.wallet_address, COALESCE(u.username, ''),
                      CASE WHEN u.encrypted_private_key != '' AND u.encrypted_private_key IS NOT NULL
                           THEN 1 ELSE 0 END,
                      COALESCE(u.is_admin, 0)
               FROM webauthn_credentials wc
               JOIN users u ON u.id = wc.user_id
               WHERE wc.credential_id = ?''',
            (credential_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({'success': False, 'msg': 'Credential not found — register first'}), 404
    user_id, wallet_address, username, has_trading_key, is_admin = row
    # Restore full session — identical to what /api/wallet/set establishes
    session.permanent           = True
    session['user_id']          = user_id
    session['wallet']           = wallet_address
    session['authenticated']    = True
    csrf_tok = _get_csrf_token()
    add_user_log(wallet_address, 'Login via WebAuthn Face ID')
    return jsonify({
        'success':         True,
        'user_id':         user_id,
        'wallet':          wallet_address,
        'username':        username or '',
        'has_trading_key': bool(has_trading_key),
        'is_admin':        bool(is_admin),
        'csrf_token':      csrf_tok,
    })

@app.route('/api/wallet/set', methods=['POST'])
@rate_limit(10, 60)
def set_wallet():
    ip      = request.remote_addr or '0.0.0.0'
    address = (request.json or {}).get('address', '').strip()
    if address:
        if not is_valid_solana_address(address):
            return jsonify({'ok': False, 'msg': 'Invalid Solana wallet address'}), 400
        # ── Nonce + signature verification ──────────────────────────────────
        body      = request.json or {}
        nonce     = str(body.get('nonce', '')).strip()
        signature = str(body.get('signature', '')).strip()
        _nonce_conn = sqlite3.connect(DB_FILE)
        try:
            row = _nonce_conn.execute(
                'SELECT created_at FROM auth_nonces WHERE nonce=?', (nonce,)
            ).fetchone()
            if row:
                _nonce_conn.execute('DELETE FROM auth_nonces WHERE nonce=?', (nonce,))
                _nonce_conn.commit()
        finally:
            _nonce_conn.close()
        if not row:
            return jsonify({'ok': False, 'msg': 'Nonce expired, try again'}), 400
        try:
            created = datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S')
            age_s   = (datetime.datetime.utcnow() - created).total_seconds()
        except Exception:
            age_s   = 9999
        if age_s > 1200:
            return jsonify({'ok': False, 'msg': 'Nonce expired, try again'}), 400
        if not _NACL_OK or _nacl_signing is None:
            return jsonify({'ok': False, 'msg': 'Signature verification unavailable'}), 503
        expected_msg = 'Sign in to OrcAgent\n\nNonce: ' + nonce
        try:
            _nacl_signing.VerifyKey(_b58dec(address)).verify(
                expected_msg.encode(), _b58dec(signature)
            )
        except Exception:
            return jsonify({'ok': False, 'msg': 'Signature verification failed'}), 401
        # ────────────────────────────────────────────────────────────────────
        # Check if wallet already exists in DB before upsert
        is_new_user = True
        try:
            _ck = sqlite3.connect(DB_FILE)
            _ckc = _ck.cursor()
            _ckc.execute('SELECT 1 FROM users WHERE wallet_address=?', (address,))
            is_new_user = _ckc.fetchone() is None
            _ck.close()
        except Exception:
            pass
        session.permanent = True
        session.modified  = True
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
        user_status = 'new_user' if is_new_user else 'existing'
        return jsonify({'ok': True, 'success': True, 'redirect': '/dashboard',
                        'wallet': address, 'has_trading_key': has_trading_key,
                        'is_admin': _is_owner(address), 'csrf_token': csrf_tok,
                        'status': user_status})
    else:
        prev = _current_wallet()
        session.pop('wallet', None)
        if prev:
            add_user_log(prev, 'Wallet disconnected')
    return jsonify({'ok': True, 'wallet': session.get('wallet', '')})

@app.route('/api/logout', methods=['POST'])
@csrf_exempt
def logout():
    session.clear()
    return jsonify({'status': 'ok'})

# ── SETTINGS ──
@app.route('/api/settings', methods=['GET'])
@rate_limit(60, 60)
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
    try:
        trade_pct = float(data.get('trade_pct', 20.0)) / 100
    except (ValueError, TypeError):
        trade_pct = 0.20
    trade_pct = max(0.05, min(trade_pct, 1.0))

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
                c.execute('UPDATE users SET encrypted_private_key=?, key_hash=?, max_trade_size=?, min_trade_size=?, daily_loss_limit=?, trade_pct=? WHERE wallet_address=?',
                          (encrypted, new_hash, max_trade_size, min_trade_size, daily_loss_limit, trade_pct, wallet))
                final_enc = encrypted
            else:
                # No new key — only update settings, leave encrypted_private_key untouched
                c.execute('UPDATE users SET max_trade_size=?, min_trade_size=?, daily_loss_limit=?, trade_pct=? WHERE wallet_address=?',
                          (max_trade_size, min_trade_size, daily_loss_limit, trade_pct, wallet))
                final_enc = row[1]
        else:
            c.execute('INSERT INTO users (wallet_address, encrypted_private_key, key_hash, max_trade_size, min_trade_size, daily_loss_limit, trade_pct, trade_size_unit_migrated) VALUES (?,?,?,?,?,?,?,1)',
                      (wallet, encrypted or '', new_hash or '', max_trade_size, min_trade_size, daily_loss_limit, trade_pct))
            final_enc = encrypted or ''
        conn.commit()
    finally:
        conn.close()
    final_has_key = bool(final_enc)
    get_user_state(wallet)['has_trading_key'] = final_has_key
    add_user_log(wallet, 'Settings saved for ' + wallet[:6] + '...' + wallet[-4:])
    return jsonify({
        'ok': True,
        'has_trading_key': final_has_key,
        'prompt_faceid': bool(private_key_raw and final_has_key),
    })

# ── SETTINGS/GET + SETTINGS/SAVE (per-user strategy + prefs) ──
@app.route('/api/settings/get', methods=['GET'])
@csrf_exempt
@rate_limit(60, 60)
def settings_get():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not connected'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute(
            '''SELECT encrypted_private_key, breakout_trigger, take_profit,
                      stop_loss, max_positions, pref_notifications,
                      pref_scam_filter, pref_sound_alerts, bot_enabled,
                      avatar_url, username
               FROM users WHERE wallet_address=?''', (wallet,)).fetchone()
    finally:
        conn.close()
    us = get_user_state(wallet)
    bot_running = bool(us.get('trader_running', False))
    if not row:
        return jsonify({'ok': True, 'has_trading_key': False,
                        'breakout_trigger': 3.0, 'take_profit': 15.0,
                        'stop_loss': 8.0, 'max_positions': 3,
                        'pref_notifications': True, 'pref_scam_filter': True,
                        'pref_sound_alerts': False, 'bot_running': bot_running})
    return jsonify({
        'ok': True,
        'has_trading_key': bool(row[0]),
        'breakout_trigger': row[1] if row[1] is not None else 3.0,
        'take_profit':      row[2] if row[2] is not None else 15.0,
        'stop_loss':        row[3] if row[3] is not None else 8.0,
        'max_positions':    row[4] if row[4] is not None else 3,
        'pref_notifications': bool(row[5] if row[5] is not None else 1),
        'pref_scam_filter':   bool(row[6] if row[6] is not None else 1),
        'pref_sound_alerts':  bool(row[7] if row[7] is not None else 0),
        'bot_running': bot_running,
        'avatar_url': row[9] or '',
        'username':   row[10] or '',
    })

@app.route('/api/settings/save', methods=['POST'])
@csrf_exempt
@rate_limit(20, 60)
def settings_save():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not connected'}), 401
    data = request.get_json(silent=True) or {}
    updates = []
    params = []
    if 'breakout_trigger' in data:
        try:
            v = float(data['breakout_trigger'])
            updates.append('breakout_trigger=?'); params.append(max(0.1, min(v, 100.0)))
        except (ValueError, TypeError): pass
    if 'take_profit' in data:
        try:
            v = float(data['take_profit'])
            updates.append('take_profit=?'); params.append(max(0.1, min(v, 1000.0)))
        except (ValueError, TypeError): pass
    if 'stop_loss' in data:
        try:
            v = float(data['stop_loss'])
            updates.append('stop_loss=?'); params.append(max(0.1, min(v, 100.0)))
        except (ValueError, TypeError): pass
    if 'max_positions' in data:
        try:
            v = int(data['max_positions'])
            updates.append('max_positions=?'); params.append(max(1, min(v, 20)))
        except (ValueError, TypeError): pass
    if 'pref_notifications' in data:
        updates.append('pref_notifications=?')
        params.append(1 if data['pref_notifications'] else 0)
    if 'pref_scam_filter' in data:
        updates.append('pref_scam_filter=?')
        params.append(1 if data['pref_scam_filter'] else 0)
    if 'pref_sound_alerts' in data:
        updates.append('pref_sound_alerts=?')
        params.append(1 if data['pref_sound_alerts'] else 0)
    if not updates:
        return jsonify({'ok': True, 'msg': 'Nothing to update'})
    params.append(wallet)
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute('INSERT OR IGNORE INTO users (wallet_address) VALUES (?)', (wallet,))
        conn.execute(f'UPDATE users SET {", ".join(updates)} WHERE wallet_address=?', params)
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})

# ── WALLET KEY MANAGEMENT ──
@app.route('/api/wallet/set-key', methods=['POST'])
@csrf_exempt
@rate_limit(5, 60)
def wallet_set_key():
    ip = request.remote_addr or '0.0.0.0'
    wallet = _current_wallet()
    if not wallet:
        _record_ip_failure(ip)
        return jsonify({'ok': False, 'msg': 'Not connected'}), 401
    data = request.get_json(silent=True) or {}
    private_key_raw = data.get('private_key', '').strip()
    if not private_key_raw:
        return jsonify({'ok': False, 'msg': 'No key provided'})
    if not is_valid_solana_private_key(private_key_raw):
        _record_ip_failure(ip)
        return jsonify({'ok': False, 'msg': 'Invalid key format — paste the full base58 key from your wallet'})
    try:
        encrypted = encrypt_private_key(private_key_raw, wallet)
        _verify = decrypt_private_key(encrypted, wallet)
        if _verify != private_key_raw:
            raise ValueError('Round-trip verify failed')
        _verify = None
        new_hash = hashlib.sha256(private_key_raw.encode()).hexdigest()
    except Exception:
        return jsonify({'ok': False, 'msg': 'Failed to encrypt private key'})
    _log_security_event('key_saved', wallet)
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute('INSERT OR IGNORE INTO users (wallet_address) VALUES (?)', (wallet,))
        conn.execute('UPDATE users SET encrypted_private_key=?, key_hash=? WHERE wallet_address=?',
                     (encrypted, new_hash, wallet))
        conn.commit()
    finally:
        conn.close()
    get_user_state(wallet)['has_trading_key'] = True
    add_user_log(wallet, 'Private key saved/updated')
    return jsonify({'ok': True, 'has_trading_key': True})

@app.route('/api/wallet/reveal-key', methods=['POST'])
@csrf_exempt
@rate_limit(3, 300)
def wallet_reveal_key():
    ip = request.remote_addr or '0.0.0.0'
    wallet = _current_wallet()
    if not wallet:
        _record_ip_failure(ip)
        return jsonify({'ok': False, 'msg': 'Not connected'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute('SELECT encrypted_private_key FROM users WHERE wallet_address=?',
                           (wallet,)).fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return jsonify({'ok': False, 'msg': 'No private key saved'})
    try:
        raw = decrypt_private_key(row[0], wallet)
    except Exception:
        return jsonify({'ok': False, 'msg': 'Failed to decrypt key'})
    _log_security_event('key_revealed', wallet)
    return jsonify({'ok': True, 'private_key': raw})

# ── USERNAME ──
@app.route('/api/blacklist', methods=['GET'])
@rate_limit(60, 60)
def api_blacklist_get():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'error': 'not logged in'}), 401
    user_id = get_or_create_user(wallet)
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        'SELECT mint, symbol, added_at FROM user_blacklist WHERE user_id=? ORDER BY added_at DESC',
        (user_id,)).fetchall()
    conn.close()
    return jsonify({'ok': True, 'tokens': [{'mint': r[0], 'symbol': r[1], 'added_at': r[2]} for r in rows]})

@app.route('/api/blacklist/add', methods=['POST'])
@rate_limit(10, 60)
def api_blacklist_add():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'error': 'not logged in'}), 401
    data   = request.get_json(silent=True) or {}
    mint   = (data.get('mint') or '').strip()
    symbol = (data.get('symbol') or '').strip()[:20]
    if not is_valid_solana_address(mint):
        return jsonify({'ok': False, 'error': 'invalid mint'}), 400
    user_id = get_or_create_user(wallet)
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        'INSERT OR IGNORE INTO user_blacklist (user_id, mint, symbol) VALUES (?,?,?)',
        (user_id, mint, symbol))
    conn.commit()
    conn.close()
    add_user_log(wallet, f'[blacklist] {symbol or mint[:8]} avoided — bot will skip this token')
    return jsonify({'ok': True})

@app.route('/api/blacklist/remove', methods=['POST'])
@rate_limit(10, 60)
def api_blacklist_remove():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'error': 'not logged in'}), 401
    data = request.get_json(silent=True) or {}
    mint = (data.get('mint') or '').strip()
    if not is_valid_solana_address(mint):
        return jsonify({'ok': False, 'error': 'invalid mint'}), 400
    user_id = get_or_create_user(wallet)
    conn = sqlite3.connect(DB_FILE)
    conn.execute('DELETE FROM user_blacklist WHERE user_id=? AND mint=?', (user_id, mint))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/username', methods=['GET'])
@rate_limit(60, 60)
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
@rate_limit(60, 60)
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
                   MAX(t.pnl)  AS best_trade,
                   u.badges    AS badges
            FROM trades t
            JOIN users u ON u.id = t.user_id
            WHERE date(t.timestamp) = date('now')
              AND (t.source = 'manual' OR (t.source IS NULL AND t.mint_address IS NOT NULL))
            GROUP BY t.user_id
            ORDER BY total_pnl DESC
            LIMIT 10
        ''')
        rows = c.fetchall()
    finally:
        conn.close()
    result = []
    for rank, row in enumerate(rows, 1):
        user_id, username, wallet, avatar_url, total_pnl, trade_count, best_trade, badges_str = row
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
            'badges':         [b.strip() for b in (badges_str or '').split(',') if b.strip()],
        })
    return jsonify(result)

@app.route('/api/stats', methods=['GET'])
@rate_limit(60, 60)
def api_stats():
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute(
            "SELECT COUNT(*), COALESCE(SUM(pnl),0) FROM trades "
            "WHERE timestamp >= datetime('now','-24 hours')"
        )
        trades_24h, net_sol_24h = c.fetchone()
        c.execute("SELECT COUNT(*) FROM users WHERE trading_active=1")
        online = c.fetchone()[0]
    finally:
        conn.close()
    return jsonify({
        'trades_24h':  int(trades_24h or 0),
        'net_sol_24h': round(float(net_sol_24h or 0), 4),
        'online':      int(online or 0),
    })

@app.route('/api/wallet/activity', methods=['GET'])
@rate_limit(30, 60)
def wallet_activity():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        user_row = conn.execute(
            'SELECT id FROM users WHERE wallet_address=?', (wallet,)
        ).fetchone()
        if not user_row:
            return jsonify({'ok': True, 'activity': []})
        uid = user_row[0]
        rows = conn.execute(
            'SELECT token, entry_price, exit_price, amount, pnl, timestamp '
            'FROM trades WHERE user_id=? ORDER BY timestamp DESC LIMIT 10',
            (uid,)
        ).fetchall()
    finally:
        conn.close()

    now = datetime.datetime.utcnow()
    activity = []
    for token, entry_price, exit_price, amount, pnl, timestamp in rows:
        sym = (token or '?').lstrip('$').upper()
        is_buy = float(amount or 0) > 0
        trade_type = 'Buy' if is_buy else 'Sell'
        color = '#3ad29b' if is_buy else '#f76b62'
        amt_sol = float(amount if is_buy else (pnl or 0))
        sub = ('Bought' if is_buy else 'Sold') + ' $' + sym
        try:
            ts = datetime.datetime.fromisoformat((timestamp or '').replace('Z', ''))
            delta = now - ts
            secs = int(delta.total_seconds())
            if secs < 60:
                rel = f'{secs}s ago'
            elif secs < 3600:
                rel = f'{secs // 60}m ago'
            elif secs < 86400:
                rel = f'{secs // 3600}h ago'
            else:
                rel = f'{secs // 86400}d ago'
        except Exception:
            rel = (timestamp or '')[:10]
        activity.append({
            'type':       trade_type,
            'sub':        sub,
            'amount_sol': round(amt_sol, 4),
            'color':      color,
            'time':       rel,
        })
    return jsonify({'ok': True, 'activity': activity})


@app.route('/api/wallet/send', methods=['POST'])
@csrf_exempt
@rate_limit(3, 60)
def wallet_send():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'error': 'Not logged in'}), 401
    data      = request.get_json(silent=True) or {}
    to_addr   = (data.get('to') or '').strip()
    try:
        amount = float(data.get('amount_sol', 0))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Invalid amount'})
    if not is_valid_solana_address(to_addr):
        return jsonify({'ok': False, 'error': 'Invalid destination address'})
    if amount <= 0 or amount > 500:
        return jsonify({'ok': False, 'error': 'Amount must be > 0 and ≤ 500 SOL'})
    if to_addr == wallet:
        return jsonify({'ok': False, 'error': 'Cannot send to yourself'})
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute(
            'SELECT encrypted_private_key FROM users WHERE wallet_address=?', (wallet,)
        ).fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return jsonify({'ok': False, 'error': 'No private key saved — add one in Settings first'})
    try:
        with _use_key(row[0], wallet) as raw_key:
            sig = send_sol_fee(raw_key, to_addr, amount)
    except Exception as e:
        _log_security_event('send_failed', wallet, str(e)[:200])
        return jsonify({'ok': False, 'error': f'Send failed: {str(e)[:120]}'}), 500
    _log_security_event('sol_sent', wallet, f'to={to_addr[:8]}... amount={amount}')
    add_user_log(wallet, f'Sent {amount} SOL to {to_addr[:8]}...')
    return jsonify({'ok': True, 'signature': sig})


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
@rate_limit(120, 60)
def social_feed():
    feed_filter = request.args.get('filter', 'all')
    my_wallet = session.get('wallet', '')
    conn = sqlite3.connect(DB_FILE)
    where_clause = ''
    if feed_filter == 'following':
        row = conn.execute('SELECT id FROM users WHERE wallet_address=?', (my_wallet,)).fetchone()
        my_uid = row[0] if row else -1
        where_clause = '''WHERE wallet IN (
            SELECT u2.wallet_address FROM follows f
            JOIN users u2 ON f.following_id = u2.id
            WHERE f.follower_id = ?)'''
    try:
        rows = conn.execute('''
            SELECT * FROM (
                SELECT fp.id, fp.wallet, fp.content, fp.created_at,
                       (SELECT COUNT(*) FROM post_likes   WHERE post_id = 'p'||fp.id) as like_count,
                       (SELECT COUNT(*) FROM feed_replies WHERE post_id = 'p'||fp.id) as reply_count,
                       u.username, NULL as symbol, NULL as pnl_pct,
                       (fp.wallet = ?) as is_own, NULL as entry_price, NULL as exit_price,
                       u.avatar_url
                FROM feed_posts fp
                LEFT JOIN users u ON fp.wallet = u.wallet_address
                UNION ALL
                SELECT t.id, u.wallet_address as wallet, NULL as content,
                       t.timestamp as created_at,
                       (SELECT COUNT(*) FROM post_likes   WHERE post_id = 't'||t.id) as like_count,
                       (SELECT COUNT(*) FROM feed_replies WHERE post_id = 't'||t.id) as reply_count,
                       u.username,
                       t.token as symbol,
                       CASE WHEN t.entry_price > 0 AND t.exit_price > 0
                            THEN ROUND((t.exit_price - t.entry_price) / t.entry_price * 100, 2)
                            ELSE 0 END as pnl_pct,
                       (u.wallet_address = ?) as is_own, t.entry_price, t.exit_price,
                       u.avatar_url
                FROM trades t
                LEFT JOIN users u ON t.user_id = u.id
            )
        ''' + where_clause + '''
            ORDER BY
              CASE WHEN created_at LIKE '%T%'
                   THEN replace(replace(created_at,'T',' '),'Z','')
                   ELSE created_at END DESC LIMIT 50
        ''', (my_wallet, my_wallet) + ((my_uid,) if feed_filter == 'following' else ())).fetchall()
    finally:
        conn.close()

    feed = []
    for row in rows:
        rid, wallet, content, created_at, like_count, reply_count, username, symbol, pnl_pct, is_own, entry_price, exit_price, avatar_url = row
        short = (wallet[:6] + '...' + wallet[-4:]) if wallet and len(wallet) >= 10 else (wallet or '')
        display = username if username else short
        feed.append({
            'id':          rid,
            'wallet':      short,
            'content':     content or '',
            'created_at':  created_at or '',
            'like_count':  like_count or 0,
            'reply_count': reply_count or 0,
            'username':    display,
            'symbol':      symbol or '',
            'pnl_pct':     pnl_pct or 0,
            'entry_price': entry_price or 0,
            'exit_price':  exit_price or 0,
            'type':        'text' if content else 'trade',
            'is_own':      bool(is_own),
            'avatar_url':  avatar_url or '',
        })
    return jsonify(feed)

_CORS_ALLOWLIST = {'https://www.orcagent.fun', 'https://orcagent.fun'}

@app.after_request
def _instant_trade_cors(resp):
    """Add CORS headers on every response from /api/instant-trade (preflight + actual)."""
    if request.path == '/api/instant-trade':
        origin = request.headers.get('Origin', '')
        if origin in _CORS_ALLOWLIST:
            resp.headers['Access-Control-Allow-Origin']      = origin
            resp.headers['Access-Control-Allow-Credentials'] = 'true'
            resp.headers['Access-Control-Allow-Methods']     = 'POST, OPTIONS'
            resp.headers['Access-Control-Allow-Headers']     = (
                'Content-Type, X-CSRF-Token, X-API-Shared-Secret, X-Requested-With'
            )
            resp.headers['Access-Control-Max-Age'] = '86400'
    return resp

@app.route('/api/instant-trade', methods=['POST', 'OPTIONS'])
@rate_limit(10, 60)
def api_instant_trade():
    # CORS preflight — _instant_trade_cors after_request stamps the headers automatically.
    if request.method == 'OPTIONS':
        return app.response_class('', status=200)

    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json', 'received': request.content_type}), 400

    try:
        print(f'[instant-trade] session keys: {list(session.keys())}, wallet: {session.get("wallet")}', flush=True)

        wallet = _current_wallet()
        if not wallet:
            return jsonify({'error': 'not logged in', 'logged_in': False}), 401

        data          = request.get_json(silent=True) or {}
        symbol        = str(data.get('symbol',        '')).strip().upper()
        token_address = str(data.get('token_address', '')).strip()
        pair_address  = str(data.get('pair_address',  '')).strip()
        side          = str(data.get('side',          '')).strip().lower()
        try:
            amount_sol = float(data.get('amount_sol', 0))
        except (TypeError, ValueError):
            amount_sol = 0.0

        print(f'[instant-trade] side={side!r} token={token_address!r} amount={amount_sol}', flush=True)

        if side not in ('buy', 'sell'):
            return jsonify({'error': 'side must be buy or sell'}), 400
        if not token_address:
            return jsonify({'error': 'token_address is required'}), 400
        if side == 'buy' and amount_sol <= 0:
            return jsonify({'error': 'amount_sol must be > 0 for buy'}), 400
        if side == 'buy':
            fetch_user_balances(wallet)
            current_sol = get_user_state(wallet).get('sol', 0)
            if current_sol < amount_sol + 0.005:
                return jsonify({'error': f'Insufficient SOL balance. You have {current_sol:.4f} SOL, need at least {amount_sol + 0.005:.4f} SOL (includes network fee).'}), 400

        # Fetch encrypted key
        try:
            conn = sqlite3.connect(DB_FILE)
            row  = conn.execute(
                'SELECT encrypted_private_key FROM users WHERE wallet_address=?', (wallet,)
            ).fetchone()
            conn.close()
        except Exception as e:
            print(f'[instant-trade] DB key fetch error: {e}', flush=True)
            traceback.print_exc()
            return jsonify({'error': f'DB error: {e}'}), 500
        if not row or not row[0]:
            return jsonify({'error': 'No private key saved — add it in Settings'}), 400

        try:
            private_key = decrypt_private_key(row[0], wallet)
        except Exception as e:
            print(f'[instant-trade] decrypt error: {e}', flush=True)
            traceback.print_exc()
            return jsonify({'error': 'Could not decrypt private key'}), 500

        # Run swap in subprocess (same pattern as _execute_user_swap but captures sig)
        try:
            env                       = os.environ.copy()
            env['WALLET_ADDRESS']     = wallet
            env['WALLET_PRIVATE_KEY'] = private_key
            _ext_hit('jupiter')
            amount_str = str(amount_sol) if side == 'buy' else '0'
            print(f'[instant-trade] launching subprocess: {side} {token_address} {amount_str}', flush=True)
            result = subprocess.run(
                [sys.executable, os.path.join(BASE, 'orcagent_solana.py'),
                 side, token_address, amount_str],
                env=env, capture_output=True, text=True, timeout=120
            )
            env['WALLET_PRIVATE_KEY'] = ''
            private_key               = ''
        except subprocess.TimeoutExpired:
            return jsonify({'error': 'Trade timed out (>120s)'}), 504
        except Exception as e:
            print(f'[instant-trade] subprocess launch error: {e}', flush=True)
            traceback.print_exc()
            return jsonify({'error': f'Swap subprocess error: {e}'}), 500

        stdout = _redact_keys(result.stdout.strip())
        stderr = _redact_keys(result.stderr.strip())
        print(f'[instant-trade] returncode={result.returncode} stdout={stdout[-300:]!r} stderr={stderr[-300:]!r}', flush=True)
        add_user_log(wallet, f'instant-trade {side} {symbol}: ' + (stdout[-300:] or stderr[-200:]))

        if result.returncode != 0:
            err_msg = (stderr.split('\n')[-1] if stderr else '') or \
                      (stdout.split('\n')[-1] if stdout else '') or \
                      'Swap failed (no output)'
            return jsonify({'error': err_msg[-200:], 'detail': stderr[-500:]}), 500

        # Extract TX signature from stdout: "… TX:<sig>"
        sig = None
        for line in stdout.split('\n'):
            if 'TX:' in line:
                sig = line.split('TX:')[-1].strip().split()[0]
                break

        if not sig:
            return jsonify({'error': 'Swap ran but no signature returned', 'stdout': stdout[-300:]}), 500

        # Update DB: trades log + user_tokens portfolio
        new_balance = None
        try:
            conn     = sqlite3.connect(DB_FILE)
            user_row = conn.execute(
                'SELECT id FROM users WHERE wallet_address=?', (wallet,)
            ).fetchone()
            if user_row:
                uid = user_row[0]
                now = datetime.datetime.utcnow().isoformat()
                conn.execute(
                    'INSERT INTO trades '
                    '(user_id, token, entry_price, exit_price, amount, pnl, fee_amount, timestamp, mint_address, source) '
                    'VALUES (?,?,?,?,?,?,?,?,?,?)',
                    (uid, symbol, 0, 0, amount_sol if side == 'buy' else 0,
                     0, 0, now, token_address, 'manual')
                )
                if side == 'buy':
                    # Fetch current token price for avg_price tracking
                    _buy_price_usd = 0.0
                    try:
                        _pr = _dex_get(
                            'https://api.dexscreener.com/latest/dex/tokens/' + token_address,
                            timeout=6
                        )
                        if _pr and _pr.status_code == 200:
                            _sol_pairs = [p for p in (_pr.json().get('pairs') or [])
                                          if p.get('chainId') == 'solana']
                            if _sol_pairs:
                                _best = max(_sol_pairs,
                                            key=lambda p: float((p.get('liquidity') or {}).get('usd') or 0))
                                _buy_price_usd = float(_best.get('priceUsd') or 0)
                    except Exception:
                        pass
                    conn.execute(
                        '''INSERT INTO user_tokens (user_id, token_address, symbol, amount, avg_price, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?)
                           ON CONFLICT(user_id, token_address) DO UPDATE SET
                               symbol     = excluded.symbol,
                               amount     = user_tokens.amount + excluded.amount,
                               avg_price  = CASE
                                   WHEN excluded.avg_price > 0 AND (user_tokens.amount + excluded.amount) > 0
                                   THEN (user_tokens.amount * user_tokens.avg_price
                                         + excluded.amount * excluded.avg_price)
                                        / (user_tokens.amount + excluded.amount)
                                   ELSE COALESCE(NULLIF(user_tokens.avg_price, 0), excluded.avg_price)
                               END,
                               updated_at = excluded.updated_at''',
                        (uid, token_address, symbol, amount_sol, _buy_price_usd, now)
                    )
                else:
                    conn.execute(
                        '''INSERT INTO user_tokens (user_id, token_address, symbol, amount, updated_at)
                           VALUES (?, ?, ?, 0, ?)
                           ON CONFLICT(user_id, token_address) DO UPDATE SET
                               amount     = 0,
                               updated_at = excluded.updated_at''',
                        (uid, token_address, symbol, now)
                    )
                conn.commit()
            conn.close()
        except Exception as e:
            print(f'[instant-trade] DB record error: {e}', flush=True)
            traceback.print_exc()

        # Fetch updated SOL balance from RPC (best-effort)
        try:
            for _rpc in _PROXY_RPCS:
                try:
                    _rb = requests.post(_rpc, json={
                        'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [wallet]
                    }, timeout=5)
                    new_balance = round(_rb.json()['result']['value'] / 1e9, 4)
                    break
                except Exception:
                    continue
        except Exception:
            pass

        return jsonify({
            'success':     True,
            'tx':          sig,
            'side':        side,
            'symbol':      symbol,
            'new_balance': new_balance,
        })

    except Exception as e:
        print(f'[instant-trade] ERROR: {e}', flush=True)
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/feed/post', methods=['POST'])
@rate_limit(15, 60)
def feed_post_create():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    body = request.json or {}
    content = _sanitize(str(body.get('content', '')))
    if not content:
        return jsonify({'ok': False, 'msg': 'Content cannot be empty'}), 400
    if len(content) > 500:
        return jsonify({'ok': False, 'msg': 'Too long (max 500)'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        cur = conn.execute(
            'INSERT INTO feed_posts (wallet, content, created_at) VALUES (?,?,?)',
            (wallet, content, now)
        )
        conn.commit()
        return jsonify({'ok': True, 'id': cur.lastrowid})
    finally:
        conn.close()

@app.route('/api/feed/post/<int:post_id>', methods=['DELETE'])
@rate_limit(20, 60)
def feed_post_delete(post_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute(
            'SELECT wallet FROM feed_posts WHERE id=?', (post_id,)
        ).fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'Post not found'}), 404
        if row[0] != wallet:
            return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
        conn.execute('DELETE FROM feed_posts WHERE id=?', (post_id,))
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()

@app.route('/api/post/<int:post_id>/edit', methods=['POST'])
@csrf_exempt
@rate_limit(20, 60)
def feed_post_edit(post_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    body = request.json or {}
    content = _sanitize(str(body.get('content', '')))
    if not content:
        return jsonify({'ok': False, 'msg': 'Content cannot be empty'}), 400
    if len(content) > 500:
        return jsonify({'ok': False, 'msg': 'Too long (max 500 chars)'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute('SELECT wallet FROM feed_posts WHERE id=?', (post_id,)).fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'Post not found'}), 404
        if row[0] != wallet:
            return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
        conn.execute('UPDATE feed_posts SET content=? WHERE id=?', (content, post_id))
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()

@app.route('/api/post/<int:post_id>/delete', methods=['POST'])
@csrf_exempt
@rate_limit(20, 60)
def feed_post_delete_v2(post_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    is_admin = (
        _is_owner(wallet)
        or hmac.compare_digest(wallet.encode(), ADMIN_WALLET.encode())
    )
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute('SELECT wallet FROM feed_posts WHERE id=?', (post_id,)).fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'Post not found'}), 404
        if row[0] != wallet and not is_admin:
            return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
        conn.execute('DELETE FROM feed_posts WHERE id=?', (post_id,))
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()

@app.route('/api/trades/<int:trade_id>', methods=['DELETE'])
@rate_limit(20, 60)
def trade_delete(trade_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        uid = _get_uid(conn, wallet)
        if not uid:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        row = conn.execute('SELECT user_id FROM trades WHERE id=?', (trade_id,)).fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'Trade not found'}), 404
        if row[0] != uid:
            return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
        conn.execute('DELETE FROM trades WHERE id=?', (trade_id,))
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()

# ── FEED INTERACTIONS ──
@app.route('/api/feed/like/<path:post_id>', methods=['POST'])
@rate_limit(60, 60)
def toggle_feed_like(post_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        existing = conn.execute(
            'SELECT id FROM post_likes WHERE user_id=? AND post_id=?', (me, post_id)
        ).fetchone()
        if existing:
            conn.execute('DELETE FROM post_likes WHERE user_id=? AND post_id=?', (me, post_id))
            liked = False
        else:
            conn.execute('INSERT INTO post_likes (user_id, post_id) VALUES (?,?)', (me, post_id))
            liked = True
        count = conn.execute('SELECT COUNT(*) FROM post_likes WHERE post_id=?', (post_id,)).fetchone()[0]
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'liked': liked, 'count': int(count)})

@app.route('/api/feed/likes/<path:post_id>', methods=['GET'])
@rate_limit(120, 60)
def get_feed_likes(post_id):
    conn = sqlite3.connect(DB_FILE)
    try:
        count = conn.execute('SELECT COUNT(*) FROM post_likes WHERE post_id=?', (post_id,)).fetchone()[0]
        wallet = _current_wallet()
        liked = False
        if wallet:
            me = _get_uid(conn, wallet)
            if me:
                liked = bool(conn.execute(
                    'SELECT 1 FROM post_likes WHERE user_id=? AND post_id=?', (me, post_id)
                ).fetchone())
    finally:
        conn.close()
    return jsonify({'ok': True, 'count': int(count), 'liked': liked})

_REACTION_EMOJIS = frozenset({'👍', '❤️', '😂', '🔥', '💰', '🚀', '😢', '😮'})

@app.route('/api/feed/react/<path:post_id>', methods=['POST'])
@rate_limit(60, 60)
def toggle_feed_reaction(post_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    data = request.get_json(silent=True) or {}
    emoji = str(data.get('emoji', '')).strip()
    if emoji not in _REACTION_EMOJIS:
        return jsonify({'ok': False, 'msg': 'Invalid emoji'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        existing = conn.execute(
            'SELECT id FROM post_reactions WHERE user_id=? AND post_id=? AND emoji=?',
            (me, post_id, emoji)
        ).fetchone()
        if existing:
            conn.execute(
                'DELETE FROM post_reactions WHERE user_id=? AND post_id=? AND emoji=?',
                (me, post_id, emoji)
            )
            active = False
        else:
            conn.execute(
                'INSERT INTO post_reactions (user_id, post_id, emoji) VALUES (?,?,?)',
                (me, post_id, emoji)
            )
            active = True
            owner_uid = _post_owner_uid(conn, post_id)
            if owner_uid and owner_uid != me:
                reactor_row = conn.execute('SELECT COALESCE(username,"") FROM users WHERE id=?', (me,)).fetchone()
                reactor_name = (reactor_row[0] if reactor_row and reactor_row[0] else wallet[:8]+'…')
                conn.execute(
                    'INSERT INTO notifications (user_id, type, content, link) VALUES (?,?,?,?)',
                    (owner_uid, 'reaction', reactor_name+': reacted '+emoji+' to your post', '/#post-'+post_id))
        conn.commit()
        counts = {row[0]: row[1] for row in conn.execute(
            'SELECT emoji, COUNT(*) FROM post_reactions WHERE post_id=? GROUP BY emoji',
            (post_id,)
        ).fetchall()}
        mine = [row[0] for row in conn.execute(
            'SELECT emoji FROM post_reactions WHERE user_id=? AND post_id=?',
            (me, post_id)
        ).fetchall()]
    finally:
        conn.close()
    return jsonify({'ok': True, 'emoji': emoji, 'active': active,
                    'counts': counts, 'mine': mine})

@app.route('/api/feed/reactions/batch', methods=['GET'])
@rate_limit(60, 60)
def feed_reactions_batch():
    raw = request.args.get('ids', '')
    post_ids = [p.strip() for p in raw.split(',') if re.match(r'^[A-Za-z0-9_]{1,64}$', p.strip())][:50]
    if not post_ids:
        return jsonify({'ok': True, 'reactions': {}})
    wallet = _current_wallet()
    conn = sqlite3.connect(DB_FILE)
    try:
        ph = ','.join('?' * len(post_ids))
        count_rows = conn.execute(
            f'SELECT post_id, emoji, COUNT(*) FROM post_reactions WHERE post_id IN ({ph}) GROUP BY post_id, emoji',
            post_ids
        ).fetchall()
        reactions = {}
        for pid, emoji, n in count_rows:
            reactions.setdefault(pid, {}).setdefault('counts', {})[emoji] = n
        mine_map = {}
        if wallet:
            me = _get_uid(conn, wallet)
            if me:
                mine_rows = conn.execute(
                    f'SELECT post_id, emoji FROM post_reactions WHERE user_id=? AND post_id IN ({ph})',
                    [me] + post_ids
                ).fetchall()
                for pid, emoji in mine_rows:
                    mine_map.setdefault(pid, []).append(emoji)
    finally:
        conn.close()
    result = {}
    for pid in post_ids:
        result[pid] = {
            'counts': reactions.get(pid, {}).get('counts', {}),
            'mine':   mine_map.get(pid, [])
        }
    return jsonify({'ok': True, 'reactions': result})

def _post_owner_uid(conn, post_id):
    if post_id.startswith('p'):
        row = conn.execute(
            "SELECT u.id FROM feed_posts fp JOIN users u ON fp.wallet=u.wallet_address WHERE fp.id=?",
            (post_id[1:],)).fetchone()
    elif post_id.startswith('t'):
        row = conn.execute("SELECT user_id FROM trades WHERE id=?", (post_id[1:],)).fetchone()
    else:
        row = None
    return row[0] if row else None


@app.route('/api/feed/reply', methods=['POST'])
@rate_limit(15, 60)
def post_feed_reply():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    body = request.json or {}
    post_id = str(body.get('post_id', '')).strip()
    message = _sanitize(str(body.get('message', '')).strip())
    if not post_id:
        return jsonify({'ok': False, 'msg': 'post_id required'}), 400
    if not message:
        return jsonify({'ok': False, 'msg': 'Message cannot be empty'}), 400
    if len(message) > 500:
        return jsonify({'ok': False, 'msg': 'Message too long (max 500 chars)'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        cur = conn.execute(
            'INSERT INTO feed_replies (user_id, post_id, message, created_at) VALUES (?,?,?,?)',
            (me, post_id, message, now)
        )
        conn.commit()
        owner_uid = _post_owner_uid(conn, post_id)
        if owner_uid and owner_uid != me:
            replier_row = conn.execute('SELECT COALESCE(username,"") FROM users WHERE id=?', (me,)).fetchone()
            replier_name = (replier_row[0] if replier_row and replier_row[0] else wallet[:8]+'…')
            preview = message[:60] + ('…' if len(message) > 60 else '')
            conn.execute(
                'INSERT INTO notifications (user_id, type, content, link) VALUES (?,?,?,?)',
                (owner_uid, 'reply', replier_name+': replied to your post — '+preview, '/#post-'+post_id))
            conn.commit()
        reply_id = cur.lastrowid
        row = conn.execute(
            'SELECT COALESCE(username,""), COALESCE(avatar_url,"") FROM users WHERE id=?', (me,)
        ).fetchone()
    finally:
        conn.close()
    return jsonify({
        'ok': True, 'id': reply_id, 'user_id': me,
        'username': row[0] if row else '',
        'avatar_url': row[1] if row else '',
        'message': message,
        'created_at': now,
    })

@app.route('/api/feed/replies/<path:post_id>', methods=['GET'])
@rate_limit(60, 60)
def get_feed_replies(post_id):
    wallet = _current_wallet()
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet) if wallet else None
        rows = conn.execute(
            '''SELECT r.id,
                      COALESCE(u.username, ''),
                      COALESCE(u.wallet_address, ''),
                      COALESCE(u.avatar_url, ''),
                      r.message,
                      r.created_at,
                      r.user_id,
                      (SELECT COUNT(*) FROM feed_reply_likes WHERE reply_id = r.id) AS like_count
               FROM feed_replies r
               LEFT JOIN users u ON u.id = r.user_id
               WHERE r.post_id = ?
               ORDER BY r.created_at ASC''',
            (post_id,)
        ).fetchall()
        liked = set()
        if me and rows:
            ids = [r[0] for r in rows]
            placeholders = ','.join('?' * len(ids))
            liked_rows = conn.execute(
                f'SELECT reply_id FROM feed_reply_likes WHERE user_id=? AND reply_id IN ({placeholders})',
                [me] + ids
            ).fetchall()
            liked = {lr[0] for lr in liked_rows}
    finally:
        conn.close()
    return jsonify({'ok': True, 'replies': [
        {
            'id':           r[0],
            'username':     r[1],
            'wallet':       r[2],
            'avatar_url':   r[3],
            'message':      r[4],
            'created_at':   r[5],
            'user_id':      r[6],
            'like_count':   r[7],
            'liked_by_me':  r[0] in liked,
            'is_mine':      me is not None and r[6] == me,
        }
        for r in rows
    ]})

@app.route('/api/feed/reply/like/<int:reply_id>', methods=['POST'])
@rate_limit(30, 60)
def toggle_feed_reply_like(reply_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'error': 'not logged in'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'error': 'not logged in'}), 401
        existing = conn.execute(
            'SELECT id FROM feed_reply_likes WHERE user_id=? AND reply_id=?',
            (me, reply_id)
        ).fetchone()
        if existing:
            conn.execute('DELETE FROM feed_reply_likes WHERE user_id=? AND reply_id=?', (me, reply_id))
        else:
            conn.execute('INSERT INTO feed_reply_likes (user_id, reply_id) VALUES (?,?)', (me, reply_id))
        conn.commit()
        if not existing:
            owner_row = conn.execute('SELECT user_id FROM feed_replies WHERE id=?', (reply_id,)).fetchone()
            if owner_row and owner_row[0] != me:
                liker_row = conn.execute('SELECT COALESCE(username,"") FROM users WHERE id=?', (me,)).fetchone()
                liker_name = (liker_row[0] if liker_row and liker_row[0] else wallet[:8]+'…')
                conn.execute(
                    'INSERT INTO notifications (user_id, type, content, link) VALUES (?,?,?,?)',
                    (owner_row[0], 'reply_like', liker_name+': liked your reply', ''))
                conn.commit()
        count = conn.execute(
            'SELECT COUNT(*) FROM feed_reply_likes WHERE reply_id=?', (reply_id,)
        ).fetchone()[0]
    finally:
        conn.close()
    return jsonify({'ok': True, 'liked': not existing, 'like_count': count})

@app.route('/api/feed/reply/<int:reply_id>', methods=['DELETE'])
@rate_limit(30, 60)
def delete_feed_reply(reply_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'error': 'not logged in'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'error': 'not logged in'}), 401
        row = conn.execute(
            'SELECT user_id FROM feed_replies WHERE id=?', (reply_id,)
        ).fetchone()
        if not row:
            return jsonify({'ok': False, 'error': 'reply not found'}), 404
        if row[0] != me:
            return jsonify({'ok': False, 'error': 'forbidden'}), 403
        conn.execute('DELETE FROM feed_reply_likes WHERE reply_id=?', (reply_id,))
        conn.execute('DELETE FROM feed_replies WHERE id=?', (reply_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})

@app.route('/api/feed/share-to-x/<path:post_id>', methods=['POST'])
@rate_limit(10, 60)
def share_feed_to_x(post_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    conn = sqlite3.connect(DB_FILE)
    xrow = conn.execute('SELECT 1 FROM x_connections WHERE wallet_address=?', (wallet,)).fetchone()
    if not xrow:
        conn.close()
        return jsonify({'ok': False, 'msg': 'Connect X in Settings first'}), 400
    if post_id.startswith('p'):
        row = conn.execute('SELECT content FROM feed_posts WHERE id=?', (post_id[1:],)).fetchone()
        raw = row[0] if row else ''
        chart_idx = raw.find('__CHART__')
        if chart_idx != -1:
            caption = raw[:chart_idx].strip()
            try:
                chart_data = json.loads(raw[chart_idx+9:])
                symbol = chart_data.get('symbol', '')
            except Exception:
                symbol = ''
            text = caption if caption else ('Check out $'+symbol+' on OrcAgent' if symbol else '')
        else:
            text = raw.split('__TRADE__')[0].strip()
        text = text[:250]
    elif post_id.startswith('t'):
        row = conn.execute('SELECT token FROM trades WHERE id=?', (post_id[1:],)).fetchone()
        text = ('Check out my trade on $'+row[0]+' via @OrcAgent') if row else ''
    else:
        text = ''
    conn.close()
    if not text:
        return jsonify({'ok': False, 'msg': 'Nothing to share'}), 400
    ok = _post_to_x(wallet, text)
    return jsonify({'ok': ok, 'msg': 'Shared to X!' if ok else 'Failed to share to X'})

# ── PROFILE ──
@app.route('/api/me', methods=['GET'])
@rate_limit(60, 60)
def api_me():
    """Lightweight current-user endpoint used by sidebar profile loaders."""
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute(
            'SELECT id, username, avatar_url FROM users WHERE wallet_address=?', (wallet,)
        ).fetchone()
    finally:
        conn.close()
    user_id    = row[0] if row else None
    username   = row[1] if row else None
    avatar_url = row[2] if row else None
    us      = get_user_state(wallet)
    balance = us.get('balance', 0.0)
    return jsonify({
        'ok':       True,
        'user_id':  user_id,
        'wallet':   wallet,
        'username': username or '',
        'avatar':   avatar_url or '',
        'balance':  balance,
    })


@app.route('/api/profile/me', methods=['GET'])
@rate_limit(60, 60)
def api_profile_me():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute(
            'SELECT id, username, avatar_url FROM users WHERE wallet_address=?', (wallet,)
        ).fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        uid, username, avatar_url = row
        follower_count  = (conn.execute('SELECT COUNT(*) FROM follows WHERE following_id=?', (uid,)).fetchone() or [0])[0]
        following_count = (conn.execute('SELECT COUNT(*) FROM follows WHERE follower_id=?',  (uid,)).fetchone() or [0])[0]
        today_row = conn.execute(
            'SELECT COUNT(*), COALESCE(SUM(pnl),0) FROM trades WHERE user_id=? AND date(timestamp)=?',
            (uid, today)
        ).fetchone()
    finally:
        conn.close()
    short = (wallet[:6] + '...' + wallet[-4:]) if len(wallet) >= 10 else wallet
    display = username if username else short
    return jsonify({
        'ok':             True,
        'user_id':        uid,
        'username':       display,
        'avatar_url':     avatar_url or '',
        'wallet':         short,
        'follower_count': int(follower_count),
        'following_count':int(following_count),
        'today_trades':   int(today_row[0] or 0) if today_row else 0,
        'today_pnl':      round(float(today_row[1] or 0), 6) if today_row else 0.0,
    })


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
                            ELSE NULL END) AS avg_hold_seconds,
                   u.badges
            FROM users u
            LEFT JOIN trades t ON t.user_id = u.id
            WHERE u.id = ?
            GROUP BY u.id
        ''', (user_id,))
        row = c.fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404

        uid, username, avatar_url, bio, wallet, created_at, trade_count, avg_hold, badges_str = row

        c.execute('SELECT COUNT(*) FROM follows WHERE following_id = ?', (user_id,))
        follower_count = (c.fetchone() or [0])[0]

        c.execute('SELECT COUNT(*) FROM follows WHERE follower_id = ?', (user_id,))
        following_count = (c.fetchone() or [0])[0]

        viewer_wallet = _current_wallet()
        is_following = False
        if viewer_wallet:
            c.execute('SELECT id FROM users WHERE wallet_address=?', (viewer_wallet,))
            vrow = c.fetchone()
            if vrow:
                c.execute('SELECT 1 FROM follows WHERE follower_id=? AND following_id=?', (vrow[0], user_id))
                is_following = c.fetchone() is not None

        c.execute('SELECT COALESCE(SUM(pnl), 0) FROM trades WHERE user_id=?', (user_id,))
        total_pnl_row = c.fetchone()
        c.execute(
            'SELECT ROUND(COUNT(CASE WHEN pnl > 0 THEN 1 END) * 100.0 / NULLIF(COUNT(*), 0), 1) '
            'FROM trades WHERE user_id=?',
            (user_id,)
        )
        win_rate_row = c.fetchone()
        c.execute(
            'SELECT COUNT(*) FROM copy_relationships WHERE copied_wallet=? AND active=1',
            (wallet,)
        )
        copiers_count_row = c.fetchone()
    finally:
        conn.close()

    short_wallet = (wallet[:6] + '...' + wallet[-4:]) if wallet and len(wallet) >= 10 else (wallet or '')
    display_name = username if username else short_wallet
    total_pnl    = round(float(total_pnl_row[0] or 0), 6) if total_pnl_row else 0.0
    win_rate     = round(float(win_rate_row[0] or 0), 1) if (win_rate_row and win_rate_row[0] is not None) else 0.0
    copiers_count = int(copiers_count_row[0] or 0) if copiers_count_row else 0

    # Live open position count from in-memory state
    us = user_states.get(wallet or '', {})
    open_count  = sum(1 for p in us.get('positions', {}).values() if p.get('amount', 0) > 0)
    bot_active  = bool(us.get('trader_running', False))

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
        'win_rate':        win_rate,
        'copiers_count':   copiers_count,
        'bot_active':      bot_active,
        'badges':          [b.strip() for b in (badges_str or '').split(',') if b.strip()],
        'is_following':    is_following,
    })

# ── PROFILE TRADES ──
@app.route('/api/profile/<int:user_id>/trades', methods=['GET'])
@rate_limit(60, 60)
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
@rate_limit(60, 60)
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


@app.route('/api/follow/toggle', methods=['POST'])
@csrf_exempt
@rate_limit(60, 60)
def follow_toggle_by_wallet():
    """Wallet-address-based follow toggle used by traders.html."""
    me_wallet = _current_wallet()
    if not me_wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    body = request.get_json(silent=True) or {}
    target_wallet = str(body.get('wallet', '')).strip()
    if not is_valid_solana_address(target_wallet):
        return jsonify({'ok': False, 'msg': 'Invalid wallet address'}), 400
    if target_wallet == me_wallet:
        return jsonify({'ok': False, 'msg': 'Cannot follow yourself'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE wallet_address=?', (me_wallet,))
        me_row = c.fetchone()
        if not me_row:
            return jsonify({'ok': False, 'msg': 'Your account not found'}), 404
        me_id = me_row[0]
        c.execute('SELECT id FROM users WHERE wallet_address=?', (target_wallet,))
        tgt_row = c.fetchone()
        if not tgt_row:
            return jsonify({'ok': False, 'msg': 'Target user not found'}), 404
        target_id = tgt_row[0]
        c.execute('SELECT 1 FROM follows WHERE follower_id=? AND following_id=?', (me_id, target_id))
        already = c.fetchone()
        if already:
            c.execute('DELETE FROM follows WHERE follower_id=? AND following_id=?', (me_id, target_id))
            following = False
        else:
            c.execute(
                'INSERT INTO follows (follower_id, following_id, created_at) VALUES (?,?,?)',
                (me_id, target_id, datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')))
            following = True
        c.execute('SELECT COUNT(*) FROM follows WHERE following_id=?', (target_id,))
        follower_count = (c.fetchone() or [0])[0]
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'following': following, 'follower_count': int(follower_count)})


# ── FOLLOWERS / FOLLOWING LISTS ──
def _viewer_follows_set(c, viewer_wallet, uid_list):
    """Return the set of user IDs (from uid_list) that the current viewer follows.
    Single query so callers don't need N round-trips."""
    if not viewer_wallet or not uid_list:
        return set()
    c.execute('SELECT id FROM users WHERE wallet_address=?', (viewer_wallet,))
    vrow = c.fetchone()
    if not vrow:
        return set()
    placeholders = ','.join('?' * len(uid_list))
    c.execute(f'SELECT following_id FROM follows WHERE follower_id=? AND following_id IN ({placeholders})',
              [vrow[0]] + list(uid_list))
    return {r[0] for r in c.fetchall()}

@app.route('/api/profile/<int:user_id>/followers', methods=['GET'])
@rate_limit(60, 60)
def get_followers(user_id: int):
    viewer_wallet = _current_wallet()
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('''
            SELECT u.id, u.username, u.avatar_url, u.wallet_address
            FROM follows f
            JOIN users u ON u.id = f.follower_id
            WHERE f.following_id = ?
            ORDER BY f.created_at DESC
            LIMIT 200
        ''', (user_id,))
        rows = c.fetchall()
        viewer_follows = _viewer_follows_set(c, viewer_wallet, [r[0] for r in rows])
    finally:
        conn.close()
    users = []
    for uid, username, avatar_url, wallet in rows:
        short = (wallet[:6] + '…' + wallet[-4:]) if wallet and len(wallet) >= 10 else (wallet or '')
        users.append({'user_id': uid, 'username': username or short, 'avatar_url': avatar_url or '',
                      'wallet': short, 'wallet_address': wallet or '', 'is_following': uid in viewer_follows})
    return jsonify({'ok': True, 'users': users})

@app.route('/api/profile/<int:user_id>/following', methods=['GET'])
@rate_limit(60, 60)
def get_following(user_id: int):
    viewer_wallet = _current_wallet()
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('''
            SELECT u.id, u.username, u.avatar_url, u.wallet_address
            FROM follows f
            JOIN users u ON u.id = f.following_id
            WHERE f.follower_id = ?
            ORDER BY f.created_at DESC
            LIMIT 200
        ''', (user_id,))
        rows = c.fetchall()
        viewer_follows = _viewer_follows_set(c, viewer_wallet, [r[0] for r in rows])
    finally:
        conn.close()
    users = []
    for uid, username, avatar_url, wallet in rows:
        short = (wallet[:6] + '…' + wallet[-4:]) if wallet and len(wallet) >= 10 else (wallet or '')
        users.append({'user_id': uid, 'username': username or short, 'avatar_url': avatar_url or '',
                      'wallet': short, 'wallet_address': wallet or '', 'is_following': uid in viewer_follows})
    return jsonify({'ok': True, 'users': users})

def _follow_list_rows(rows, today, viewer_wallet=None):
    """Shared helper: enrich (uid, username, avatar_url, wallet) rows with pnl_today and is_following."""
    if not rows:
        return []
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        viewer_follows = _viewer_follows_set(c, viewer_wallet, [r[0] for r in rows])
        users = []
        for uid, username, avatar_url, wallet in rows:
            short = (wallet[:4] + '...' + wallet[-4:]) if wallet and len(wallet) >= 8 else (wallet or '')
            c.execute('SELECT COALESCE(SUM(pnl),0) FROM trades WHERE user_id=? AND date(timestamp)=?', (uid, today))
            pnl_today = round(float((c.fetchone() or (0,))[0]), 4)
            users.append({
                'user_id':        uid,
                'username':       username or short,
                'avatar_url':     avatar_url or '',
                'wallet':         short,
                'wallet_address': wallet or '',
                'pnl_today':      pnl_today,
                'is_following':   uid in viewer_follows,
            })
    finally:
        conn.close()
    return users

@app.route('/api/profile/<wallet>/followers', methods=['GET'])
@rate_limit(60, 60)
def get_followers_by_wallet(wallet: str):
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    viewer_wallet = _current_wallet()
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE wallet_address = ?', (wallet,))
        row = c.fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        user_id = row[0]
        c.execute('''
            SELECT u.id, u.username, u.avatar_url, u.wallet_address
            FROM follows f JOIN users u ON u.id = f.follower_id
            WHERE f.following_id = ?
            ORDER BY f.created_at DESC LIMIT 200
        ''', (user_id,))
        rows = c.fetchall()
    finally:
        conn.close()
    return jsonify({'ok': True, 'users': _follow_list_rows(rows, today, viewer_wallet)})

@app.route('/api/profile/<wallet>/following', methods=['GET'])
@rate_limit(60, 60)
def get_following_by_wallet(wallet: str):
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    viewer_wallet = _current_wallet()
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE wallet_address = ?', (wallet,))
        row = c.fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        user_id = row[0]
        c.execute('''
            SELECT u.id, u.username, u.avatar_url, u.wallet_address
            FROM follows f JOIN users u ON u.id = f.following_id
            WHERE f.follower_id = ?
            ORDER BY f.created_at DESC LIMIT 200
        ''', (user_id,))
        rows = c.fetchall()
    finally:
        conn.close()
    return jsonify({'ok': True, 'users': _follow_list_rows(rows, today, viewer_wallet)})

# ── X (TWITTER) HELPERS ──
def _post_to_x(wallet: str, text: str) -> bool:
    """Post a tweet on behalf of wallet. Returns True on success, False otherwise."""
    try:
        conn = sqlite3.connect(DB_FILE)
        try:
            row = conn.execute(
                'SELECT access_token, refresh_token, token_expires_at FROM x_connections WHERE wallet_address=?',
                (wallet,)
            ).fetchone()
        finally:
            conn.close()
        if not row:
            return False
        access_token, refresh_token, token_expires_at_str = row
        # refresh if expired or expiring within 60 seconds
        if token_expires_at_str:
            try:
                exp = datetime.datetime.fromisoformat(token_expires_at_str)
                if datetime.datetime.utcnow() >= exp - datetime.timedelta(seconds=60):
                    token_expires_at_str = None  # force refresh
            except ValueError:
                token_expires_at_str = None
        if not token_expires_at_str:
            client_id     = os.getenv('X_CLIENT_ID', '')
            client_secret = os.getenv('X_CLIENT_SECRET', '')
            resp = requests.post(
                'https://api.x.com/2/oauth2/token',
                data={'grant_type': 'refresh_token', 'refresh_token': refresh_token,
                      'client_id': client_id},
                auth=(client_id, client_secret),
                timeout=15,
            )
            if resp.status_code != 200:
                print(f'[x] token refresh failed for {wallet[:8]}: {resp.status_code} {resp.text[:120]}', flush=True)
                return False
            td = resp.json()
            access_token  = td.get('access_token', access_token)
            refresh_token = td.get('refresh_token', refresh_token)
            expires_in    = int(td.get('expires_in', 7200))
            new_exp       = (datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)).isoformat()
            conn2 = sqlite3.connect(DB_FILE)
            try:
                conn2.execute(
                    'UPDATE x_connections SET access_token=?, refresh_token=?, token_expires_at=? WHERE wallet_address=?',
                    (access_token, refresh_token, new_exp, wallet)
                )
                conn2.commit()
            finally:
                conn2.close()
        # post the tweet
        tweet_resp = requests.post(
            'https://api.x.com/2/tweets',
            json={'text': text},
            headers={'Authorization': 'Bearer ' + access_token},
            timeout=15,
        )
        if not (200 <= tweet_resp.status_code < 300):
            print(f'[x] tweet failed for {wallet[:8]}: {tweet_resp.status_code} {tweet_resp.text[:120]}', flush=True)
            return False
        return True
    except Exception as e:
        print(f'[x] _post_to_x error for {wallet[:8]}: {e}', flush=True)
        return False

# ── X (TWITTER) OAUTH ──
@app.route('/api/x/connect', methods=['GET'])
@rate_limit(20, 60)
def x_connect():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    client_id = os.getenv('X_CLIENT_ID', '')
    callback_url = os.getenv('X_CALLBACK_URL', '')
    if not client_id or not callback_url:
        return jsonify({'ok': False, 'msg': 'X OAuth not configured'}), 500
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    state = secrets.token_urlsafe(16)
    session['x_code_verifier'] = code_verifier
    session['x_oauth_state']   = state
    session['x_oauth_wallet']  = wallet
    params = {
        'response_type':         'code',
        'client_id':             client_id,
        'redirect_uri':          callback_url,
        'scope':                 'tweet.read tweet.write users.read offline.access',
        'state':                 state,
        'code_challenge':        code_challenge,
        'code_challenge_method': 'S256',
    }
    import urllib.parse
    auth_url = 'https://x.com/i/oauth2/authorize?' + urllib.parse.urlencode(params)
    return redirect(auth_url)

@app.route('/api/x/callback', methods=['GET'])
@rate_limit(20, 60)
def x_callback():
    code     = request.args.get('code', '').strip()
    state    = request.args.get('state', '').strip()
    error    = request.args.get('error', '')
    if error:
        return redirect('/settings?x_error=' + error)
    # 1. verify state
    if not state or state != session.get('x_oauth_state'):
        return redirect('/settings?x_error=state_mismatch')
    code_verifier = session.get('x_code_verifier', '')
    wallet        = session.get('x_oauth_wallet', '')
    if not code or not code_verifier or not wallet:
        return redirect('/settings?x_error=missing_params')
    client_id     = os.getenv('X_CLIENT_ID', '')
    client_secret = os.getenv('X_CLIENT_SECRET', '')
    callback_url  = os.getenv('X_CALLBACK_URL', '')
    # 2. exchange code for tokens
    try:
        token_resp = requests.post(
            'https://api.x.com/2/oauth2/token',
            data={
                'grant_type':    'authorization_code',
                'code':          code,
                'redirect_uri':  callback_url,
                'code_verifier': code_verifier,
            },
            auth=(client_id, client_secret),
            timeout=15,
        )
        token_data = token_resp.json()
    except Exception:
        return redirect('/settings?x_error=token_request_failed')
    if 'access_token' not in token_data:
        return redirect('/settings?x_error=no_access_token')
    access_token  = token_data['access_token']
    refresh_token = token_data.get('refresh_token')
    expires_in    = token_data.get('expires_in', 7200)
    token_expires_at = (datetime.datetime.utcnow() +
                        datetime.timedelta(seconds=int(expires_in))).isoformat()
    # 3. fetch X user info
    try:
        me_resp = requests.get(
            'https://api.x.com/2/users/me',
            headers={'Authorization': 'Bearer ' + access_token},
            timeout=10,
        )
        me_data = me_resp.json().get('data', {})
    except Exception:
        return redirect('/settings?x_error=userinfo_failed')
    x_user_id = str(me_data.get('id', ''))
    x_handle  = str(me_data.get('username', ''))
    if not x_user_id or not x_handle:
        return redirect('/settings?x_error=no_user_info')
    # 4. upsert into x_connections
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute('''
            INSERT INTO x_connections
                (wallet_address, x_user_id, x_handle, access_token, refresh_token, token_expires_at)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(wallet_address) DO UPDATE SET
                x_user_id        = excluded.x_user_id,
                x_handle         = excluded.x_handle,
                access_token     = excluded.access_token,
                refresh_token    = excluded.refresh_token,
                token_expires_at = excluded.token_expires_at
        ''', (wallet, x_user_id, x_handle, access_token, refresh_token, token_expires_at))
        conn.commit()
    finally:
        conn.close()
    # 5. clean up session
    session.pop('x_oauth_state',   None)
    session.pop('x_code_verifier', None)
    session.pop('x_oauth_wallet',  None)
    return redirect('/settings?x_connected=1')

@app.route('/api/x/prefs', methods=['POST'])
@rate_limit(20, 60)
def x_prefs():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    data = request.get_json(silent=True) or {}
    updates, params = [], []
    if 'share_on_big_trade' in data:
        updates.append('share_on_big_trade=?'); params.append(1 if data['share_on_big_trade'] else 0)
    if 'share_on_badge' in data:
        updates.append('share_on_badge=?'); params.append(1 if data['share_on_badge'] else 0)
    if not updates:
        return jsonify({'ok': True})
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute(f'UPDATE x_connections SET {",".join(updates)} WHERE wallet_address=?',
                     params + [wallet])
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})

@app.route('/api/x/disconnect', methods=['POST'])
@rate_limit(10, 60)
def x_disconnect():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not logged in'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute('DELETE FROM x_connections WHERE wallet_address=?', (wallet,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})

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

# ── DIFFICULTY (deprecated — universal strategy, no difficulty modes) ──
@app.route('/api/difficulty', methods=['GET'])
@rate_limit(60, 60)
def get_difficulty():
    return jsonify({'ok': True, 'difficulty': 'UNIVERSAL',
                    'tp': TAKE_PROFIT, 'sl': STOP_LOSS})

@app.route('/api/difficulty', methods=['POST'])
@rate_limit(10, 60)
def save_difficulty():
    return jsonify({'ok': True, 'difficulty': 'UNIVERSAL'})

# ── DIRECT MESSAGES & PROFILE COMMENTS ──

# Regex for upload-generated filenames: uuid4().hex (32 hex chars) + allowed extension.
# Any stored image URL that does NOT match this pattern is rejected.
_UPLOAD_FILENAME_RE = re.compile(r'^[0-9a-f]{32}\.(jpg|jpeg|png|gif|webp)$')

def _verify_image_magic(data: bytes) -> bool:
    """Return True only if the first bytes match a known image format signature.
    Content-type and extension can be spoofed; magic bytes cannot."""
    if len(data) < 12:
        return False
    if data[:3] == b'\xff\xd8\xff':
        return True                          # JPEG
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return True                          # PNG
    if data[:6] in (b'GIF87a', b'GIF89a'):
        return True                          # GIF
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        return True                          # WebP
    return False

def _sanitize(text: str) -> str:
    """Strip HTML tags to prevent XSS in user-generated content.
    Two-pass approach: first strip raw tags, then decode HTML entities and
    strip again — catches payloads like &lt;script&gt; that survive a single pass."""
    stripped = re.sub(r'<[^>]+>', '', text)
    decoded  = _html_lib.unescape(stripped)
    return re.sub(r'<[^>]+>', '', decoded).strip()

def _get_uid(conn, wallet: str):
    row = conn.execute('SELECT id FROM users WHERE wallet_address=?', (wallet,)).fetchone()
    return row[0] if row else None

def _mutual_follow(conn, a: int, b: int) -> bool:
    return (
        bool(conn.execute('SELECT 1 FROM follows WHERE follower_id=? AND following_id=?', (a, b)).fetchone()) and
        bool(conn.execute('SELECT 1 FROM follows WHERE follower_id=? AND following_id=?', (b, a)).fetchone())
    )

def _any_follow(conn, a: int, b: int) -> bool:
    """True if a follows b OR b follows a."""
    return bool(conn.execute(
        'SELECT 1 FROM follows WHERE (follower_id=? AND following_id=?) OR (follower_id=? AND following_id=?)',
        (a, b, b, a)
    ).fetchone())

def _is_following_ids(conn, follower: int, following: int) -> bool:
    return bool(conn.execute(
        'SELECT 1 FROM follows WHERE follower_id=? AND following_id=?', (follower, following)
    ).fetchone())

@app.route('/api/user/find')
@rate_limit(30, 60)
def find_user():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({})
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute(
            'SELECT wallet_address FROM users WHERE wallet_address=? OR username=? COLLATE NOCASE LIMIT 1',
            (q, q)
        ).fetchone()
    finally:
        conn.close()
    return jsonify({'wallet': row[0]} if row else {})

@app.route('/api/users/search', methods=['GET'])
@rate_limit(60, 60)
def search_users():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    q = _sanitize(request.args.get('q', '').strip())
    if not q:
        return jsonify({'ok': True, 'users': []})
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        rows = conn.execute(
            '''SELECT id, username, wallet_address, avatar_url
               FROM users
               WHERE username LIKE ? AND id != ?
               ORDER BY username ASC
               LIMIT 5''',
            ('%' + q + '%', me or 0)
        ).fetchall()
    except Exception as e:
        return jsonify({'ok': False, 'msg': 'Server error: ' + str(e)}), 500
    finally:
        conn.close()
    return jsonify({'ok': True, 'users': [
        {'user_id': r[0], 'username': r[1] or '',
         'wallet': r[2] or '', 'avatar_url': r[3] or ''}
        for r in rows
    ]})

@app.route('/api/tokens/search', methods=['GET'])
@rate_limit(60, 60)
def search_tokens():
    q = _sanitize(request.args.get('q', '').strip())
    if not q or len(q) < 2:
        return jsonify({'ok': True, 'tokens': []})
    try:
        url = 'https://api.dexscreener.com/latest/dex/search?q=' + requests.utils.quote(q, safe='')
        r = _dex_get(url, timeout=6)
        if not r or r.status_code != 200:
            return jsonify({'ok': True, 'tokens': []})
        pairs = r.json().get('pairs') or []
        seen, results = set(), []
        for p in pairs:
            if (p.get('chainId') or '').lower() != 'solana':
                continue
            base  = p.get('baseToken') or {}
            addr  = base.get('address', '')
            if not addr or addr in seen:
                continue
            seen.add(addr)
            raw_price  = p.get('priceUsd')
            raw_change = (p.get('priceChange') or {}).get('h24')
            results.append({
                'symbol':           base.get('symbol', ''),
                'name':             base.get('name', ''),
                'address':          addr,
                'price':            float(raw_price)  if raw_price  is not None else None,
                'price_change_24h': float(raw_change) if raw_change is not None else None,
            })
            if len(results) >= 5:
                break
        return jsonify({'ok': True, 'tokens': results})
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e)}), 500

@app.route('/api/token/info/<mint_address>', methods=['GET'])
@rate_limit(60, 60)
def api_token_info(mint_address):
    mint = _sanitize(mint_address.strip())
    if not mint or not is_valid_solana_address(mint):
        return jsonify({'ok': False, 'msg': 'Invalid address'}), 400
    try:
        url = 'https://api.dexscreener.com/latest/dex/tokens/' + requests.utils.quote(mint, safe='')
        r = _dex_get(url, timeout=8)
        if not r or r.status_code != 200:
            return jsonify({'ok': False, 'msg': 'Token not found'}), 404
        pairs = r.json().get('pairs') or []
        if not pairs:
            return jsonify({'ok': False, 'msg': 'Token not found'}), 404
        # Pick the Solana pair with highest liquidity (most representative)
        pairs_sol = [p for p in pairs if p.get('chainId') == 'solana'] or pairs
        p    = max(pairs_sol, key=lambda x: float((x.get('liquidity') or {}).get('usd') or 0))
        base = p.get('baseToken') or {}
        info = p.get('info') or {}
        pc   = p.get('priceChange') or {}
        vol  = p.get('volume') or {}
        liq  = p.get('liquidity') or {}
        txns = p.get('txns') or {}
        def _f(v):
            try: return float(v) if v not in (None, '', 'null') else 0.0
            except (TypeError, ValueError): return 0.0
        def _txn(period, side):
            return int(_f((txns.get(period) or {}).get(side)))
        pc_5m  = _f(pc.get('m5'))
        pc_1h  = _f(pc.get('h1'))
        pc_6h  = _f(pc.get('h6'))
        pc_24h = _f(pc.get('h24'))
        mcap   = _f(p.get('marketCap')) or _f(p.get('fdv'))
        fdv    = _f(p.get('fdv'))
        liq_usd = _f(liq.get('usd'))
        # socials
        socials = info.get('socials') or []
        twitter = next((s.get('url') for s in socials if (s.get('type') or '').lower() == 'twitter'), None)
        # price in SOL: DexScreener doesn't expose priceNative directly on all pairs,
        # but priceNative is the quote-token price (usually SOL for Solana pairs)
        price_sol = _f(p.get('priceNative'))
        return jsonify({
            'ok':                True,
            # identity
            'symbol':            base.get('symbol', ''),
            'name':              base.get('name', ''),
            'address':           base.get('address', mint),
            'pair_address':      p.get('pairAddress', ''),
            'dex_name':          p.get('dexId', ''),
            'chain':             p.get('chainId', 'solana'),
            # price
            'price':             _f(p.get('priceUsd')),
            'price_usd':         _f(p.get('priceUsd')),
            'price_sol':         price_sol,
            # market
            'fdv':               fdv,
            'market_cap':        mcap,
            'mcap':              mcap,
            'liquidity_usd':     liq_usd,
            'liquidity':         liq_usd,
            # volume
            'volume_5m':         _f(vol.get('m5')),
            'volume_1h':         _f(vol.get('h1')),
            'volume_24h':        _f(vol.get('h24')),
            # price changes
            'price_change_5m':   pc_5m,
            'price_change_1h':   pc_1h,
            'price_change_6h':   pc_6h,
            'price_change_24h':  pc_24h,
            'price_change':      {'m5': pc_5m, 'h1': pc_1h, 'h6': pc_6h, 'h24': pc_24h},
            # transactions
            'txns_5m_buys':      _txn('m5', 'buys'),
            'txns_5m_sells':     _txn('m5', 'sells'),
            'txns_1h_buys':      _txn('h1', 'buys'),
            'txns_1h_sells':     _txn('h1', 'sells'),
            'txns_24h':          _txn('h24', 'buys') + _txn('h24', 'sells'),
            'traders_24h':       _txn('h24', 'buys') + _txn('h24', 'sells'),
            'buyers_24h':        _txn('h24', 'buys'),
            'sellers_24h':       _txn('h24', 'sells'),
            # volume split (DexScreener doesn't break this out; use txn ratio as proxy)
            'buy_volume_24h':    None,
            'sell_volume_24h':   None,
            # images
            'image_url':         info.get('imageUrl'),
            'logo_url':          info.get('imageUrl'),
            'banner_url':        info.get('header'),
            # socials / links
            'twitter_url':       twitter,
            'dexscreener_url':   p.get('url') or f'https://dexscreener.com/solana/{mint}',
        })
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e)}), 500


@app.route('/api/trade/buy', methods=['POST'])
@rate_limit(10, 60)
def api_trade_buy():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    data         = request.get_json(silent=True) or {}
    mint         = _sanitize(str(data.get('token_address', '')).strip())
    symbol       = _sanitize(str(data.get('token_symbol', '')).strip())[:20]
    amount_sol   = data.get('amount_sol')
    if not mint or not is_valid_solana_address(mint):
        return jsonify({'ok': False, 'msg': 'Invalid token address'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute(
            'SELECT id, encrypted_private_key, min_trade_size, max_trade_size FROM users WHERE wallet_address=?',
            (wallet,)
        ).fetchone()
    finally:
        conn.close()
    if not row or not row[1]:
        return jsonify({'ok': False, 'msg': 'No trading key configured'}), 400
    user_id, enc_blob = row[0], row[1]
    min_size = float(row[2]) if row[2] is not None else 1.0
    max_size = float(row[3]) if row[3] is not None else 10.0
    if amount_sol is None:
        amount_sol = max_size
    try:
        amount_sol = float(amount_sol)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'msg': 'Invalid amount'}), 400
    amount_sol = max(min_size, min(max_size, amount_sol))
    td = get_token_data(mint)
    entry_price = float(td['price']) if td and td.get('price') else 0.0
    if not symbol and td:
        symbol = td.get('symbol', mint[:8])
    buy_ok = False
    with _use_key(enc_blob, wallet) as pk:
        buy_ok = _execute_user_swap(wallet, pk, 'buy', mint, str(amount_sol))
    if not buy_ok:
        return jsonify({'ok': False, 'msg': 'Swap failed — check logs'}), 502
    us        = get_user_state(wallet)
    positions = us['positions']
    pos = positions.get(mint, {})
    pos['amount']    = pos.get('amount', 0.0) + (amount_sol / entry_price if entry_price > 0 else 0.0)
    pos['buy_price'] = entry_price
    pos['spend']     = pos.get('spend', 0.0) + amount_sol
    pos['symbol']    = symbol
    pos['opened_at'] = time.time()
    positions[mint]  = pos
    return jsonify({'ok': True, 'amount_sol': amount_sol, 'entry_price': entry_price, 'symbol': symbol})


@app.route('/api/trade/sell', methods=['POST'])
@rate_limit(10, 60)
def api_trade_sell():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    data   = request.get_json(silent=True) or {}
    mint   = _sanitize(str(data.get('token_address', '')).strip())
    symbol = _sanitize(str(data.get('token_symbol', '')).strip())[:20]
    if not mint or not is_valid_solana_address(mint):
        return jsonify({'ok': False, 'msg': 'Invalid token address'}), 400
    us  = get_user_state(wallet)
    pos = us['positions'].get(mint, {})
    if not pos.get('amount', 0.0) > 0:
        return jsonify({'ok': False, 'msg': 'No open position for this token'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute(
            'SELECT id, encrypted_private_key FROM users WHERE wallet_address=?', (wallet,)
        ).fetchone()
    finally:
        conn.close()
    if not row or not row[1]:
        return jsonify({'ok': False, 'msg': 'No trading key configured'}), 400
    user_id, enc_blob = row[0], row[1]
    td          = get_token_data(mint)
    exit_price  = float(td['price']) if td and td.get('price') else 0.0
    if not symbol:
        symbol = pos.get('symbol') or (td.get('symbol', mint[:8]) if td else mint[:8])
    sell_ok = False
    with _use_key(enc_blob, wallet) as pk:
        sell_ok = _execute_user_swap(wallet, pk, 'sell', mint, str(pos['amount']))
    entry     = pos.get('buy_price', 0.0)
    pnl       = round(pos['amount'] * (exit_price - entry), 4) if entry > 0 else 0.0
    opened_at = pos.get('opened_at', 0.0)
    if sell_ok:
        with _use_key(enc_blob, wallet) as pk:
            _record_user_trade(user_id, us, symbol, entry, exit_price,
                               pos['amount'], pos.get('spend', 0.0),
                               wallet=wallet, private_key=pk, mint=mint,
                               exit_reason='MANUAL SELL', opened_at=opened_at)
    else:
        _record_user_trade(user_id, us, symbol, entry, exit_price,
                           pos['amount'], pos.get('spend', 0.0),
                           mint=mint, exit_reason='MANUAL SELL (swap failed)',
                           opened_at=opened_at)
    us['positions'][mint] = {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0}
    return jsonify({'ok': True, 'pnl': pnl, 'exit_price': exit_price, 'sell_executed': sell_ok})


@app.route('/api/trade/position/<token_address>', methods=['GET'])
@rate_limit(60, 60)
def api_trade_position(token_address):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    mint = _sanitize(token_address.strip())
    if not mint or not is_valid_solana_address(mint):
        return jsonify({'ok': False, 'msg': 'Invalid token address'}), 400
    pos = get_user_state(wallet)['positions'].get(mint, {})
    amount      = pos.get('amount', 0.0)
    entry_price = pos.get('buy_price', 0.0)
    has_position = amount > 0 and entry_price > 0
    current_pnl  = None
    if has_position:
        td = get_token_data(mint)
        if td and td.get('price'):
            cur_price   = float(td['price'])
            current_pnl = round(amount * (cur_price - entry_price), 4)
    return jsonify({
        'ok':           True,
        'has_position': has_position,
        'amount':       amount if has_position else 0.0,
        'entry_price':  entry_price if has_position else None,
        'current_pnl':  current_pnl,
    })


# ── WALLET TOKEN CACHE ──
_wallet_tokens_cache: dict = {}   # wallet → {'ts': float, 'tokens': list, 'total_usd': float, 'total_sol': float}
_WALLET_CACHE_TTL = 30            # seconds

TOKEN_PROGRAM_ID      = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
TOKEN_2022_PROGRAM_ID = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'

def _fetch_wallet_tokens(wallet: str) -> dict:
    """Fetch all SPL tokens + SOL for wallet, price each via DexScreener. Cached 30 s."""
    cached = _wallet_tokens_cache.get(wallet)
    if cached and time.time() - cached['ts'] < _WALLET_CACHE_TTL:
        return cached

    result: list = []
    total_usd = 0.0
    sol_price_usd = 0.0

    # ── SOL balance ──
    sol_balance = 0.0
    try:
        r = requests.post(SOLANA_RPC, json={
            'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [wallet]
        }, timeout=8)
        sol_balance = round(r.json()['result']['value'] / 1e9, 6)
    except Exception:
        pass

    # ── SOL price from DexScreener ──
    try:
        sr = _dex_get('https://api.dexscreener.com/latest/dex/tokens/' + SOL_MINT, timeout=6)
        if sr and sr.status_code == 200:
            pairs = sr.json().get('pairs') or []
            pairs_sol = [p for p in pairs if p.get('chainId') == 'solana'] or pairs
            if pairs_sol:
                best = max(pairs_sol, key=lambda x: float((x.get('liquidity') or {}).get('usd') or 0))
                sol_price_usd = float(best.get('priceUsd') or 0)
                info = best.get('info') or {}
                sol_logo = info.get('imageUrl') or ''
                sol_pc24 = float((best.get('priceChange') or {}).get('h24') or 0)
    except Exception:
        sol_logo = ''
        sol_pc24 = 0.0

    sol_value = round(sol_balance * sol_price_usd, 4)
    total_usd += sol_value
    result.append({
        'symbol':           'SOL',
        'name':             'Solana',
        'mint':             SOL_MINT,
        'amount':           sol_balance,
        'decimals':         9,
        'price_usd':        sol_price_usd,
        'value_usd':        sol_value,
        'price_change_24h': sol_pc24,
        'logo_url':         sol_logo,
    })

    # ── SPL token accounts (legacy Token Program + Token-2022) ──
    print(f'[wallet-tokens] wallet={wallet!r} len={len(wallet)}', flush=True)
    mints_needed: list = []
    raw_accounts: list = []
    _seen_mints: set = set()
    _rpcs_to_try = [SOLANA_RPC] + [ep for ep in _PROXY_RPCS if ep != SOLANA_RPC]
    for _prog_id in (TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID):
        _prog_accounts: list = []
        for _rpc_url in _rpcs_to_try:
            try:
                _rpc_r = requests.post(_rpc_url, json={
                    'jsonrpc': '2.0', 'id': 1,
                    'method': 'getTokenAccountsByOwner',
                    'params': [wallet, {'programId': _prog_id}, {'encoding': 'jsonParsed'}],
                }, timeout=12)
                _rpc_raw = _rpc_r.json()
                _prog_accounts = _rpc_raw.get('result', {}).get('value') or []
                print(f'[wallet-tokens] prog={_prog_id[:8]} rpc={_rpc_url}: {len(_prog_accounts)} accounts', flush=True)
                if _prog_accounts:
                    break
            except Exception as _rpc_err:
                print(f'[wallet-tokens] prog={_prog_id[:8]} rpc={_rpc_url} error: {_rpc_err}', flush=True)
        for acc in _prog_accounts:
            info     = (acc.get('account') or {}).get('data', {}).get('parsed', {}).get('info') or {}
            mint     = info.get('mint', '')
            ta       = info.get('tokenAmount') or {}
            ui_amount = float(ta.get('uiAmount') or 0)
            decimals  = int(ta.get('decimals', 0))
            if ui_amount < 0.000001 or not mint or mint == SOL_MINT or mint in _seen_mints:
                continue
            _seen_mints.add(mint)
            raw_accounts.append({'mint': mint, 'amount': ui_amount, 'decimals': decimals})
            mints_needed.append(mint)
    print(f'[wallet-tokens] total SPL accounts after merge: {len(raw_accounts)}', flush=True)

    # ── DB fallback: if RPC returned no SPL tokens, read user_tokens table ──
    if not raw_accounts:
        print(f'[wallet-tokens] RPC empty — falling back to user_tokens DB', flush=True)
        try:
            _fb_conn = sqlite3.connect(DB_FILE)
            _uid_row = _fb_conn.execute(
                'SELECT id FROM users WHERE wallet_address=?', (wallet,)
            ).fetchone()
            if _uid_row:
                _fb_rows = _fb_conn.execute(
                    'SELECT token_address, symbol, amount, avg_price FROM user_tokens'
                    ' WHERE user_id=? AND amount > 0',
                    (_uid_row[0],)
                ).fetchall()
                for _ta, _sym, _amt, _avg in _fb_rows:
                    if not _ta or _ta in _seen_mints:
                        continue
                    _seen_mints.add(_ta)
                    raw_accounts.append({'mint': _ta, 'amount': float(_amt),
                                         'decimals': 0, 'symbol_hint': _sym,
                                         'avg_price': float(_avg or 0)})
                    mints_needed.append(_ta)
                print(f'[wallet-tokens] DB fallback: {len(_fb_rows)} rows, {len(raw_accounts)} usable', flush=True)
            _fb_conn.close()
        except Exception as _fb_err:
            print(f'[wallet-tokens] DB fallback error: {_fb_err}', flush=True)

    # ── Batch DexScreener price lookup (max 30 per request) ──
    price_map: dict = {}
    BATCH = 30
    for i in range(0, len(mints_needed), BATCH):
        batch = mints_needed[i:i + BATCH]
        try:
            url = 'https://api.dexscreener.com/latest/dex/tokens/' + ','.join(batch)
            dr = _dex_get(url, timeout=10)
            if not dr or dr.status_code != 200:
                continue
            for p in (dr.json().get('pairs') or []):
                if p.get('chainId') != 'solana':
                    continue
                base_mint = (p.get('baseToken') or {}).get('address', '')
                if not base_mint or base_mint in price_map:
                    continue
                base = p.get('baseToken') or {}
                info = p.get('info') or {}
                price_map[base_mint] = {
                    'symbol':           base.get('symbol', ''),
                    'name':             base.get('name', ''),
                    'price_usd':        float(p.get('priceUsd') or 0),
                    'price_change_24h': float((p.get('priceChange') or {}).get('h24') or 0),
                    'logo_url':         info.get('imageUrl') or '',
                }
        except Exception:
            continue

    # ── Load avg_price from user_tokens for PnL display ──
    _avg_prices: dict = {}
    try:
        _ap_conn = sqlite3.connect(DB_FILE)
        _ap_uid  = _ap_conn.execute(
            'SELECT id FROM users WHERE wallet_address=?', (wallet,)
        ).fetchone()
        if _ap_uid:
            for _ta, _avg in _ap_conn.execute(
                'SELECT token_address, avg_price FROM user_tokens WHERE user_id=?',
                (_ap_uid[0],)
            ).fetchall():
                _avg_prices[_ta] = float(_avg or 0)
        _ap_conn.close()
    except Exception:
        pass

    # ── Assemble SPL token rows ──
    for acc in raw_accounts:
        mint   = acc['mint']
        amount = acc['amount']
        pd     = price_map.get(mint, {})
        price  = pd.get('price_usd', 0.0)
        value  = round(amount * price, 4)
        total_usd += value
        avg_price = acc.get('avg_price') or _avg_prices.get(mint, 0)
        result.append({
            'symbol':           pd.get('symbol') or acc.get('symbol_hint') or mint[:6],
            'name':             pd.get('name') or '',
            'mint':             mint,
            'amount':           amount,
            'decimals':         acc['decimals'],
            'price_usd':        price,
            'value_usd':        value,
            'price_change_24h': pd.get('price_change_24h', 0.0),
            'logo_url':         pd.get('logo_url', ''),
            'avg_price':        avg_price,
        })

    # Sort by value descending (SOL already at index 0 from insertion order, but re-sort anyway)
    result.sort(key=lambda x: x['value_usd'], reverse=True)

    total_sol = round(total_usd / sol_price_usd, 4) if sol_price_usd else 0.0
    out = {'ts': time.time(), 'tokens': result, 'total_usd': round(total_usd, 4), 'total_sol': total_sol}
    _wallet_tokens_cache[wallet] = out
    return out


@app.route('/api/wallet/tokens', methods=['GET'])
@rate_limit(20, 60)
def api_wallet_tokens():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    if request.args.get('bust'):
        _wallet_tokens_cache.pop(wallet, None)
    try:
        data = _fetch_wallet_tokens(wallet)
        tokens = [{**t, 'usd_value': t['value_usd']} for t in data['tokens']]
        print(f'[wallet-tokens] tokens found: {len(tokens)}', flush=True)
        return jsonify({'ok': True, 'tokens': tokens, 'cached': False})
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e)}), 500


@app.route('/api/wallet/total', methods=['GET'])
@rate_limit(30, 60)
def api_wallet_total():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    try:
        data = _fetch_wallet_tokens(wallet)
        return jsonify({
            'ok':        True,
            'total_usd': data['total_usd'],
            'total_sol': data['total_sol'],
            'token_count': len(data['tokens']),
        })
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e)}), 500


@app.route('/api/wallet/balance', methods=['GET'])
@rate_limit(30, 60)
def api_wallet_balance():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    try:
        r = requests.post(SOLANA_RPC, json={
            'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [wallet]
        }, timeout=8)
        lamports = r.json()['result']['value']
        sol = round(lamports / 1e9, 6)
        usd = round(sol * _sol_price_usd, 4) if _sol_price_usd else None
        return jsonify({'ok': True, 'sol': sol, 'usd': usd, 'sol_price_usd': _sol_price_usd})
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e)}), 500


@app.route('/api/wallet/transactions', methods=['GET'])
@rate_limit(30, 60)
def api_wallet_transactions():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        uid = _get_uid(conn, wallet)
        if not uid:
            return jsonify({'ok': True, 'transactions': []})
        rows = conn.execute('''
            SELECT token, entry_price, exit_price, amount, pnl, timestamp
            FROM trades
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT 20
        ''', (uid,)).fetchall()
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e)}), 500
    finally:
        conn.close()
    txns = []
    for row in rows:
        token, entry, exit_p, amount, pnl, ts = row
        exit_f  = float(exit_p or 0)
        pnl_sol = float(pnl or 0)
        is_sell = exit_f > 0
        txns.append({
            'type':       'Sold' if is_sell else 'Bought',
            'token':      token or '',
            'amount_sol': round(abs(pnl_sol), 4),
            'pnl':        pnl_sol,
            'created_at': ts or '',
        })
    return jsonify({'ok': True, 'transactions': txns})


@app.route('/api/messages/unread', methods=['GET'])
@rate_limit(60, 60)
def messages_unread():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': True, 'unread': 0})
        count = conn.execute(
            'SELECT COUNT(*) FROM direct_messages WHERE receiver_id=? AND is_read=0', (me,)
        ).fetchone()[0]
    finally:
        conn.close()
    return jsonify({'ok': True, 'unread': count})

@app.route('/api/messages', methods=['GET'])
@rate_limit(60, 60)
def list_conversations():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': True, 'conversations': []})
        rows = conn.execute('''
            SELECT peer_id,
                   (SELECT wallet_address FROM users WHERE id=peer_id) AS peer_wallet,
                   (SELECT username     FROM users WHERE id=peer_id) AS peer_username,
                   last_msg, last_ts,
                   (SELECT COUNT(*) FROM direct_messages
                    WHERE receiver_id=? AND sender_id=peer_id AND is_read=0) AS unread,
                   (SELECT avatar_url   FROM users WHERE id=peer_id) AS peer_avatar
            FROM (
                SELECT
                    CASE WHEN sender_id=? THEN receiver_id ELSE sender_id END AS peer_id,
                    message AS last_msg,
                    created_at AS last_ts,
                    ROW_NUMBER() OVER (
                        PARTITION BY CASE WHEN sender_id=? THEN receiver_id ELSE sender_id END
                        ORDER BY created_at DESC
                    ) AS rn
                FROM direct_messages
                WHERE sender_id=? OR receiver_id=?
            ) WHERE rn=1
            ORDER BY last_ts DESC
            LIMIT 100
        ''', (me, me, me, me, me)).fetchall()
    finally:
        conn.close()
    return jsonify({'ok': True, 'conversations': [
        {'peer_id': r[0], 'peer_wallet': r[1], 'peer_username': r[2],
         'last_msg': r[3], 'last_ts': r[4], 'unread': r[5], 'peer_avatar': r[6] or ''}
        for r in rows
    ]})

@app.route('/api/messages/<int:peer_id>', methods=['GET'])
@rate_limit(60, 60)
def get_dm_history(peer_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    peer_id = int(peer_id)
    conn = sqlite3.connect(DB_FILE)
    rows = []
    try:
        me = _get_uid(conn, wallet)
        if not me:
            print(f'[dm_get] user not found for wallet {wallet}', flush=True)
            return jsonify({'ok': True, 'messages': []})
        print(f'[dm_get] me={me} peer={peer_id}', flush=True)
        rows = conn.execute(
            'SELECT id, sender_id, receiver_id, message, created_at, is_read, '
            'COALESCE(message_type, "text"), edited_at '
            'FROM direct_messages '
            'WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?) '
            'ORDER BY created_at ASC LIMIT 200',
            (me, peer_id, peer_id, me)
        ).fetchall()
        print(f'[dm_get] found {len(rows)} messages', flush=True)
        conn.execute(
            'UPDATE direct_messages SET is_read=1 '
            'WHERE receiver_id=? AND sender_id=? AND is_read=0',
            (me, peer_id)
        )
        conn.commit()
    except Exception as e:
        print(f'[dm_get] ERROR me={me if "me" in dir() else "?"} peer={peer_id}: {e}', flush=True)
        return jsonify({'ok': True, 'messages': []})
    finally:
        conn.close()
    return jsonify({'ok': True, 'messages': [
        {'id': r[0], 'sender_id': r[1], 'receiver_id': r[2],
         'message': r[3], 'created_at': r[4], 'is_read': bool(r[5]),
         'message_type': r[6], 'edited_at': r[7]}
        for r in rows
    ]})

@app.route('/api/messages/upload-image', methods=['POST'])
@rate_limit(10, 60)
def upload_dm_image():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    f = request.files.get('image')
    if not f:
        return jsonify({'ok': False, 'msg': 'No image provided'}), 400
    ALLOWED_MIME = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}
    ALLOWED_EXT  = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
    MAX_BYTES    = 5 * 1024 * 1024
    if f.content_type not in ALLOWED_MIME:
        return jsonify({'ok': False, 'msg': 'Only jpg/png/gif/webp allowed'}), 400
    data = f.read()
    if len(data) > MAX_BYTES:
        return jsonify({'ok': False, 'msg': 'Image too large (max 5 MB)'}), 400
    if not _verify_image_magic(data):
        return jsonify({'ok': False, 'msg': 'File content does not match a valid image format'}), 400
    raw_ext = secure_filename(f.filename or '').rsplit('.', 1)
    ext = raw_ext[-1].lower() if len(raw_ext) == 2 else ''
    if ext not in ALLOWED_EXT:
        ext = f.content_type.split('/')[-1].replace('jpeg', 'jpg')
    filename  = f'{uuid.uuid4().hex}.{ext}'
    save_path = os.path.join(DM_IMAGES_DIR, filename)
    with open(save_path, 'wb') as out:
        out.write(data)
    return jsonify({'ok': True, 'success': True, 'url': f'/static/dm_images/{filename}'})

@app.route('/api/messages/<int:peer_id>', methods=['POST'])
@rate_limit(20, 60)
def send_dm(peer_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    body = request.json or {}
    message_type = body.get('message_type', 'text')
    if message_type == 'image':
        text = str(body.get('message', ''))
        _dm_prefix = '/static/dm_images/'
        if not text.startswith(_dm_prefix):
            return jsonify({'ok': False, 'msg': 'Invalid image path'}), 400
        if not _UPLOAD_FILENAME_RE.match(text[len(_dm_prefix):]):
            return jsonify({'ok': False, 'msg': 'Invalid image filename'}), 400
    else:
        message_type = 'text'
        text = _sanitize(str(body.get('message', '')))
        if not text:
            return jsonify({'ok': False, 'msg': 'Message cannot be empty'}), 400
        if len(text) > 500:
            return jsonify({'ok': False, 'msg': 'Message too long (max 500 characters)'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        if me == int(peer_id):
            return jsonify({'ok': False, 'msg': 'Cannot message yourself'}), 400
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        cur = conn.execute(
            'INSERT INTO direct_messages (sender_id, receiver_id, message, message_type, created_at) VALUES (?,?,?,?,?)',
            (me, peer_id, text, message_type, now)
        )
        message_id = cur.lastrowid
        sender_row  = conn.execute('SELECT username FROM users WHERE id=?', (me,)).fetchone()
        sender_name = (sender_row[0] if sender_row and sender_row[0] else wallet[:8] + '…')
        preview     = text[:60] + ('…' if len(text) > 60 else '')
        conn.execute(
            'INSERT INTO notifications (user_id, type, content, link) VALUES (?,?,?,?)',
            (peer_id, 'message', sender_name + ': ' + preview, '/messages/' + wallet)
        )
        conn.commit()
    except Exception as e:
        return jsonify({'ok': False, 'msg': 'Server error: ' + str(e)}), 500
    finally:
        conn.close()
    return jsonify({'ok': True, 'success': True, 'message_id': message_id,
                    'created_at': now, 'message': text, 'message_type': message_type})

@app.route('/api/messages/<int:message_id>', methods=['DELETE'])
@rate_limit(30, 60)
def delete_dm(message_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        row = conn.execute(
            'SELECT sender_id FROM direct_messages WHERE id=?', (message_id,)
        ).fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'Message not found'}), 404
        if row[0] != me:
            return jsonify({'ok': False, 'msg': 'Not your message'}), 403
        conn.execute('DELETE FROM direct_messages WHERE id=?', (message_id,))
        conn.commit()
    except Exception as e:
        return jsonify({'ok': False, 'msg': 'Server error: ' + str(e)}), 500
    finally:
        conn.close()
    return jsonify({'ok': True})

@app.route('/api/messages/<int:message_id>', methods=['PUT'])
@rate_limit(30, 60)
def edit_dm(message_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    body = request.get_json(silent=True) or {}
    text = _sanitize(str(body.get('message', '')))
    if not text:
        return jsonify({'ok': False, 'msg': 'Message cannot be empty'}), 400
    if len(text) > 500:
        return jsonify({'ok': False, 'msg': 'Message too long (max 500 characters)'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        row = conn.execute(
            'SELECT sender_id FROM direct_messages WHERE id=?', (message_id,)
        ).fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'Message not found'}), 404
        if row[0] != me:
            return jsonify({'ok': False, 'msg': 'Not your message'}), 403
        conn.execute(
            'UPDATE direct_messages SET message=?, edited_at=CURRENT_TIMESTAMP WHERE id=?',
            (text, message_id)
        )
        conn.commit()
        edited_at = conn.execute(
            'SELECT edited_at FROM direct_messages WHERE id=?', (message_id,)
        ).fetchone()[0]
    except Exception as e:
        return jsonify({'ok': False, 'msg': 'Server error: ' + str(e)}), 500
    finally:
        conn.close()
    return jsonify({'ok': True, 'message': text, 'edited_at': edited_at})

@app.route('/api/chat', methods=['GET'])
@rate_limit(60, 60)
def get_group_chat():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        rows = conn.execute(
            '''SELECT gc.id, gc.user_id, gc.message, gc.message_type, gc.image_url, gc.created_at,
                      COALESCE(u.username, '') AS username,
                      COALESCE(u.avatar_url, '') AS avatar_url,
                      u.wallet_address
               FROM group_chat gc
               JOIN users u ON u.id = gc.user_id
               ORDER BY gc.created_at DESC
               LIMIT 50''',
        ).fetchall()
    finally:
        conn.close()
    me_id = None
    conn2 = sqlite3.connect(DB_FILE)
    try:
        me_id = _get_uid(conn2, wallet)
    finally:
        conn2.close()
    messages = [
        {
            'id': r[0], 'user_id': r[1], 'message': r[2],
            'message_type': r[3] or 'text', 'image_url': r[4],
            'created_at': r[5], 'username': r[6], 'avatar_url': r[7],
            'wallet_address': r[8], 'is_mine': r[1] == me_id,
        }
        for r in reversed(rows)
    ]
    return jsonify({'ok': True, 'messages': messages})

@app.route('/api/chat', methods=['POST'])
@rate_limit(15, 60)
def post_group_chat():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    body = request.json or {}
    message_type = body.get('message_type', 'text')
    if message_type == 'image':
        image_url = str(body.get('image_url', ''))
        _chat_prefix = '/static/chat_images/'
        if not image_url.startswith(_chat_prefix):
            return jsonify({'ok': False, 'msg': 'Invalid image path'}), 400
        if not _UPLOAD_FILENAME_RE.match(image_url[len(_chat_prefix):]):
            return jsonify({'ok': False, 'msg': 'Invalid image filename'}), 400
        message = None
    else:
        message_type = 'text'
        message = _sanitize(str(body.get('message', '')))
        if not message:
            return jsonify({'ok': False, 'msg': 'Message cannot be empty'}), 400
        if len(message) > 500:
            return jsonify({'ok': False, 'msg': 'Message too long (max 500 characters)'}), 400
        image_url = None
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        cur = conn.execute(
            'INSERT INTO group_chat (user_id, message, message_type, image_url, created_at) VALUES (?,?,?,?,?)',
            (me, message, message_type, image_url, now)
        )
        conn.commit()
        msg_id = cur.lastrowid
        row = conn.execute(
            'SELECT COALESCE(username,""), COALESCE(avatar_url,""), wallet_address FROM users WHERE id=?', (me,)
        ).fetchone()
    except Exception as e:
        return jsonify({'ok': False, 'msg': 'Server error: ' + str(e)}), 500
    finally:
        conn.close()
    return jsonify({
        'ok': True, 'id': msg_id, 'user_id': me,
        'message': message, 'message_type': message_type, 'image_url': image_url,
        'created_at': now, 'username': row[0] if row else '',
        'avatar_url': row[1] if row else '', 'wallet_address': row[2] if row else '',
        'is_mine': True,
    })

@app.route('/api/chat/<int:message_id>', methods=['DELETE'])
@rate_limit(20, 60)
def delete_group_chat(message_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        row = conn.execute(
            'SELECT user_id FROM group_chat WHERE id=?', (message_id,)
        ).fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'Message not found'}), 404
        if row[0] != me:
            return jsonify({'ok': False, 'msg': 'Not your message'}), 403
        conn.execute('DELETE FROM group_chat WHERE id=?', (message_id,))
        conn.commit()
    except Exception as e:
        return jsonify({'ok': False, 'msg': 'Server error: ' + str(e)}), 500
    finally:
        conn.close()
    return jsonify({'ok': True})

@app.route('/api/chat/upload-image', methods=['POST'])
@rate_limit(10, 60)
def upload_chat_image():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    f = request.files.get('image')
    if not f:
        return jsonify({'ok': False, 'msg': 'No image provided'}), 400
    ALLOWED_MIME = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}
    ALLOWED_EXT  = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
    MAX_BYTES    = 5 * 1024 * 1024
    if f.content_type not in ALLOWED_MIME:
        return jsonify({'ok': False, 'msg': 'Only jpg/png/gif/webp allowed'}), 400
    data = f.read()
    if len(data) > MAX_BYTES:
        return jsonify({'ok': False, 'msg': 'Image too large (max 5 MB)'}), 400
    if not _verify_image_magic(data):
        return jsonify({'ok': False, 'msg': 'File content does not match a valid image format'}), 400
    raw_ext = secure_filename(f.filename or '').rsplit('.', 1)
    ext = raw_ext[-1].lower() if len(raw_ext) == 2 else ''
    if ext not in ALLOWED_EXT:
        ext = f.content_type.split('/')[-1].replace('jpeg', 'jpg')
    filename  = f'{uuid.uuid4().hex}.{ext}'
    save_path = os.path.join(CHAT_IMAGES_DIR, filename)
    with open(save_path, 'wb') as out:
        out.write(data)
    return jsonify({'ok': True, 'success': True, 'url': f'/static/chat_images/{filename}'})

@app.route('/api/trades/open', methods=['GET'])
@rate_limit(60, 60)
def api_open_trades():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    us = get_user_state(wallet)
    result = []
    for mint, pos in list(us.get('positions', {}).items()):
        if pos.get('amount', 0) <= 0:
            continue
        entry = float(pos.get('buy_price', 0) or 0)
        current_price = None
        pnl_pct = None
        try:
            td = get_token_data(mint)
            if td and td.get('price', 0) > 0:
                current_price = td['price']
                if entry > 0:
                    pnl_pct = round((current_price - entry) / entry * 100, 2)
        except Exception:
            pass
        result.append({
            'trade_id': None,
            'token_symbol': pos.get('symbol', mint[:8]),
            'token_address': mint,
            'entry_price': entry,
            'current_price': current_price,
            'pnl_pct': pnl_pct,
            'amount_sol': float(pos.get('spend', 0) or 0),
        })
    return jsonify({'ok': True, 'trades': result})


@app.route('/api/messages/<int:peer_id>/share-trade', methods=['POST'])
@rate_limit(10, 60)
def share_trade_dm(peer_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    token_address = str((request.json or {}).get('token_address', '')).strip()
    if not is_valid_solana_address(token_address):
        return jsonify({'ok': False, 'msg': 'Invalid token address'}), 400
    us = get_user_state(wallet)
    pos = us.get('positions', {}).get(token_address)
    if not pos or pos.get('amount', 0) <= 0:
        return jsonify({'ok': False, 'msg': 'No open position for this token'}), 400
    trade_payload = json.dumps({
        'type': 'trade_share',
        'token_address': token_address,
        'token_symbol': pos.get('symbol', token_address[:8]),
        'entry_price': float(pos.get('buy_price', 0) or 0),
        'amount_sol': float(pos.get('spend', 0) or 0),
    })
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        if me == int(peer_id):
            return jsonify({'ok': False, 'msg': 'Cannot message yourself'}), 400
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        cur = conn.execute(
            'INSERT INTO direct_messages (sender_id, receiver_id, message, message_type, created_at) VALUES (?,?,?,?,?)',
            (me, peer_id, trade_payload, 'trade_share', now)
        )
        conn.commit()
        message_id = cur.lastrowid
    except Exception as e:
        return jsonify({'ok': False, 'msg': 'Server error: ' + str(e)}), 500
    finally:
        conn.close()
    return jsonify({'ok': True, 'message_id': message_id, 'created_at': now})


# ── WALLET-BASED DM SYSTEM ──

@app.route('/api/messages/unread_count', methods=['GET'])
@rate_limit(120, 60)
def wallet_unread_count():
    me = _current_wallet()
    if not me:
        return jsonify({'count': 0})
    conn = sqlite3.connect(DB_FILE)
    try:
        count = conn.execute(
            'SELECT COUNT(*) FROM messages WHERE receiver_wallet=? AND is_read=0', (me,)
        ).fetchone()[0]
    finally:
        conn.close()
    return jsonify({'count': count})


@app.route('/api/messages/conversations', methods=['GET'])
@rate_limit(60, 60)
def wallet_conversations():
    me = _current_wallet()
    if not me:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        rows = conn.execute('''
            SELECT
                sub.peer,
                (SELECT content FROM messages
                 WHERE (sender_wallet=? AND receiver_wallet=sub.peer)
                    OR (sender_wallet=sub.peer AND receiver_wallet=?)
                 ORDER BY created_at DESC LIMIT 1) AS last_msg,
                sub.max_ts,
                (SELECT COUNT(*) FROM messages
                 WHERE receiver_wallet=? AND sender_wallet=sub.peer AND is_read=0) AS unread
            FROM (
                SELECT
                    CASE WHEN sender_wallet=? THEN receiver_wallet ELSE sender_wallet END AS peer,
                    MAX(created_at) AS max_ts
                FROM messages
                WHERE sender_wallet=? OR receiver_wallet=?
                GROUP BY peer
            ) sub
            ORDER BY sub.max_ts DESC
            LIMIT 100
        ''', (me, me, me, me, me, me)).fetchall()
    finally:
        conn.close()
    return jsonify({'ok': True, 'conversations': [
        {'peer_wallet': r[0], 'last_message': r[1], 'timestamp': r[2], 'unread_count': r[3]}
        for r in rows
    ]})


@app.route('/api/messages/<wallet>', methods=['GET'])
@rate_limit(60, 60)
def get_wallet_thread(wallet):
    me = _current_wallet()
    if not me:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    if not is_valid_solana_address(wallet):
        return jsonify({'ok': False, 'msg': 'Invalid wallet address'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        rows = conn.execute('''
            SELECT id, sender_wallet, receiver_wallet, content, created_at, is_read
            FROM messages
            WHERE (sender_wallet=? AND receiver_wallet=?)
               OR (sender_wallet=? AND receiver_wallet=?)
            ORDER BY created_at ASC
            LIMIT 200
        ''', (me, wallet, wallet, me)).fetchall()
        conn.execute(
            'UPDATE messages SET is_read=1 WHERE receiver_wallet=? AND sender_wallet=? AND is_read=0',
            (me, wallet)
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'messages': [
        {
            'id': r[0], 'sender_wallet': r[1], 'receiver_wallet': r[2],
            'content': r[3], 'created_at': r[4], 'is_read': bool(r[5]),
            'mine': r[1] == me
        }
        for r in rows
    ]})


@app.route('/api/messages/<wallet>', methods=['POST'])
@rate_limit(20, 60)
def send_wallet_message(wallet):
    me = _current_wallet()
    if not me:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    if not is_valid_solana_address(wallet):
        return jsonify({'ok': False, 'msg': 'Invalid wallet address'}), 400
    if wallet == me:
        return jsonify({'ok': False, 'msg': 'Cannot message yourself'}), 400
    content = str((request.json or {}).get('content', '')).strip()
    if not content:
        return jsonify({'ok': False, 'msg': 'content required'}), 400
    if len(content) > 2000:
        return jsonify({'ok': False, 'msg': 'Message too long (max 2000 chars)'}), 400
    now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_FILE)
    try:
        cur = conn.execute(
            'INSERT INTO messages (sender_wallet, receiver_wallet, content, created_at) VALUES (?,?,?,?)',
            (me, wallet, content, now)
        )
        conn.commit()
        msg_id = cur.lastrowid
    except Exception as e:
        return jsonify({'ok': False, 'msg': 'Server error: ' + str(e)}), 500
    finally:
        conn.close()
    return jsonify({'ok': True, 'message': {
        'id': msg_id, 'sender_wallet': me, 'receiver_wallet': wallet,
        'content': content, 'created_at': now, 'is_read': False, 'mine': True
    }})


@app.route('/api/trades/copy-from-message', methods=['POST'])
@rate_limit(5, 60)
def copy_trade_from_message():
    ip = request.remote_addr or '0.0.0.0'
    wallet = _current_wallet()
    if not wallet:
        _record_ip_failure(ip)
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    body = request.json or {}
    token_address = str(body.get('token_address', '')).strip()
    amount_sol    = float(body.get('amount_sol', 0) or 0)
    if not is_valid_solana_address(token_address):
        return jsonify({'ok': False, 'msg': 'Invalid token address'}), 400
    if amount_sol <= 0:
        return jsonify({'ok': False, 'msg': 'amount_sol must be greater than 0'}), 400
    if _sec_check_state.get('trading_paused'):
        return jsonify({'ok': False, 'msg': 'Trading suspended — contact admin to resume.'}), 503
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute('SELECT id, encrypted_private_key, min_trade_size FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
        bl = c.execute('SELECT 1 FROM user_blacklist WHERE user_id=? AND mint=?',
                       (row[0], token_address)).fetchone() if row else None
    finally:
        conn.close()
    if not row or not row[1]:
        return jsonify({'ok': False, 'msg': 'No trading key saved — add it in Settings first'}), 400
    if bl:
        return jsonify({'ok': False, 'msg': 'This token is on your avoid list'}), 400
    enc_blob = row[1]
    us = get_user_state(wallet)
    open_pos     = sum(1 for p in us['positions'].values() if p.get('amount', 0) > 0)
    already_held = us['positions'].get(token_address, {}).get('amount', 0) > 0
    if open_pos >= 5 and not already_held:
        return jsonify({'ok': False, 'msg': 'Max 5 positions reached — sell one first'}), 400
    token_data = get_token_data(token_address)
    if not token_data or token_data['price'] <= 0:
        return jsonify({'ok': False, 'msg': 'Could not fetch a live price for this token'}), 400
    try:
        with _use_key(enc_blob, wallet) as _pk:
            from solders.keypair import Keypair as _KP_ct
            trading_wallet = str(_KP_ct.from_base58_string(_pk).pubkey())
    except InvalidToken:
        return jsonify({'ok': False, 'msg': 'Cannot decrypt trading key — please re-save it in Settings'}), 400
    except Exception as e:
        print(f'[copy-trade] key error for {wallet[:6]}...{wallet[-4:]}: {type(e).__name__}: {e}', flush=True)
        return jsonify({'ok': False, 'msg': 'Cannot decrypt trading key — please re-save it in Settings'}), 400
    us_sol = _get_user_sol(trading_wallet)
    if us_sol < 0.01:
        return jsonify({'ok': False, 'low_balance': True, 'trading_wallet': trading_wallet,
                        'msg': '⚠️ Insufficient SOL balance — send SOL to your trading wallet first'}), 400
    spend = round(min(amount_sol, us_sol), 4)
    if spend < 0.001:
        return jsonify({'ok': False, 'msg': 'Insufficient SOL balance to copy this trade'}), 400
    with _use_key(enc_blob, wallet) as _pk:
        ok = _execute_user_swap(wallet, _pk, 'buy', token_address, str(spend))
    if not ok:
        return jsonify({'ok': False, 'msg': 'Buy transaction failed — check logs for details'}), 500
    pos = us['positions'].get(token_address, {'amount': 0.0, 'buy_price': 0.0, 'spend': 0.0})
    pos['amount']          = pos.get('amount', 0.0) + spend / token_data['price']
    pos['buy_price']       = token_data['price']
    pos['spend']           = pos.get('spend', 0.0) + spend
    pos['symbol']          = token_data['symbol'] or token_address[:8]
    pos['opened_at']       = time.time()
    pos['entry_liquidity'] = float(token_data.get('liquidity', 0) or 0)
    us['positions'][token_address] = pos
    short = wallet[:6] + '...' + wallet[-4:]
    add_user_log(wallet, '[' + short + '] COPY TRADE: ' + pos['symbol'] +
                 ' for ' + str(spend) + ' SOL @ $' + str(token_data['price']))
    _trigger_copy_buy(wallet, token_address, token_data['price'], pos['symbol'],
                      float(token_data.get('liquidity', 0) or 0))
    note = '' if us.get('trader_running') else ' — start the bot for automatic TP/SL'
    return jsonify({'ok': True, 'success': True, 'trade_id': None, 'symbol': pos['symbol'],
                    'spend': spend, 'msg': 'Copied ' + pos['symbol'] + note})


@app.route('/api/comments/<int:profile_uid>', methods=['GET'])
@rate_limit(60, 60)
def get_profile_comments(profile_uid):
    conn = sqlite3.connect(DB_FILE)
    try:
        rows = conn.execute('''
            SELECT pc.id, pc.author_id, u.wallet_address, u.username, pc.message, pc.created_at
            FROM profile_comments pc
            JOIN users u ON u.id = pc.author_id
            WHERE pc.profile_user_id=?
            ORDER BY pc.created_at DESC
            LIMIT 100
        ''', (profile_uid,)).fetchall()
    finally:
        conn.close()
    return jsonify({'ok': True, 'comments': [
        {'id': r[0], 'author_id': r[1], 'author_wallet': r[2],
         'author_username': r[3], 'message': r[4], 'created_at': r[5]}
        for r in rows
    ]})

@app.route('/api/comments/<int:profile_uid>', methods=['POST'])
@rate_limit(10, 60)
def post_profile_comment(profile_uid):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    text = _sanitize(str((request.json or {}).get('message', '')))
    if not text:
        return jsonify({'ok': False, 'msg': 'Comment cannot be empty'}), 400
    if len(text) > 280:
        return jsonify({'ok': False, 'msg': 'Comment too long (max 280 characters)'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        if not _is_following_ids(conn, me, profile_uid):
            return jsonify({'ok': False, 'msg': 'You must follow this trader to comment'}), 403
        cur = conn.execute(
            'INSERT INTO profile_comments (profile_user_id, author_id, message) VALUES (?,?,?)',
            (profile_uid, me, text)
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'id': cur.lastrowid, 'message': text})

@app.route('/api/comments/<int:comment_id>', methods=['DELETE'])
@rate_limit(20, 60)
def delete_profile_comment(comment_id):
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'}), 401
    conn = sqlite3.connect(DB_FILE)
    try:
        me = _get_uid(conn, wallet)
        if not me:
            return jsonify({'ok': False, 'msg': 'User not found'}), 404
        row = conn.execute(
            'SELECT author_id, profile_user_id FROM profile_comments WHERE id=?', (comment_id,)
        ).fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'Comment not found'}), 404
        author_id, profile_uid = row
        if me != author_id and me != profile_uid:
            return jsonify({'ok': False, 'msg': 'Not authorized to delete this comment'}), 403
        conn.execute('DELETE FROM profile_comments WHERE id=?', (comment_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})

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
@rate_limit(60, 60)
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
        c.execute('SELECT id, encrypted_private_key, min_trade_size FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
        bl = c.execute('SELECT 1 FROM user_blacklist WHERE user_id=? AND mint=?',
                       (row[0], mint)).fetchone() if row else None
    finally:
        conn.close()
    if not row or not row[1]:
        return jsonify({'ok': False, 'msg': 'No trading key saved — add it in Settings first'}), 400
    if bl:
        return jsonify({'ok': False, 'msg': 'This token is on your avoid list'}), 400
    enc_blob       = row[1]
    min_trade_usdc = float(row[2]) if row[2] is not None else 1.0

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
    _trigger_copy_buy(wallet, mint, token_data['price'], pos['symbol'], float(token_data.get('liquidity', 0) or 0))
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
        c.execute('SELECT id, encrypted_private_key, min_trade_size FROM users WHERE wallet_address=?', (wallet,))
        row = c.fetchone()
        bl = c.execute('SELECT 1 FROM user_blacklist WHERE user_id=? AND mint=?',
                       (row[0], mint)).fetchone() if row else None
    finally:
        conn.close()
    if not row or not row[1]:
        return jsonify({'ok': False, 'msg': 'No trading key saved — add it in Settings first'}), 400
    if bl:
        return jsonify({'ok': False, 'msg': 'This token is on your avoid list'}), 400
    enc_blob       = row[1]
    min_trade_usdc = float(row[2]) if row[2] is not None else 1.0

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
        return jsonify({'ok': False, 'msg': 'Insufficient SOL balance'}), 400

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
    _trigger_copy_buy(wallet, mint, token_data['price'], pos['symbol'], float(token_data.get('liquidity', 0) or 0))
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

# ── /api/bot/start + /api/bot/stop — canonical manual-start routes ────────────
@app.route('/api/bot/start', methods=['POST'])
@rate_limit(5, 60)
def bot_start():
    ip     = request.remote_addr or '0.0.0.0'
    wallet = _current_wallet()
    if not wallet:
        _record_ip_failure(ip)
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    try:
        conn = sqlite3.connect(DB_FILE)
        kr   = conn.execute('SELECT encrypted_private_key FROM users WHERE wallet_address=?', (wallet,)).fetchone()
        conn.close()
    except Exception as e:
        print(f'[bot/start] DB error: {e}', flush=True)
        return jsonify({'ok': False, 'msg': 'Internal error'}), 500
    if not kr or not kr[0]:
        return jsonify({'ok': False, 'msg': 'No trading key saved — add it in Settings first'}), 400
    if _sec_check_state.get('trading_paused'):
        return jsonify({'ok': False, 'msg': 'Trading suspended — security check failure'}), 503
    with _trader_lock:
        us = get_user_state(wallet)
        if us['trader_running']:
            return jsonify({'ok': True, 'status': 'running'})
        config = request.json or {}
        us['trader_stop']   = threading.Event()
        us['trader_thread'] = threading.Thread(target=user_trader_loop, args=(us['trader_stop'], config, wallet), daemon=True)
        us['trader_thread'].start()
        us['trader_running'] = True
    try:
        _en_conn = sqlite3.connect(DB_FILE)
        _en_conn.execute('UPDATE users SET bot_enabled=1 WHERE wallet_address=?', (wallet,))
        _en_conn.commit()
        _en_conn.close()
    except Exception:
        pass
    short = (wallet[:6] + '...' + wallet[-4:]) if len(wallet) >= 10 else wallet
    print(f'[bot/start] {short} manually started', flush=True)
    return jsonify({'ok': True, 'status': 'running'})

@app.route('/api/bot/stop', methods=['POST'])
@rate_limit(10, 60)
def bot_stop():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Connect a wallet first'}), 401
    us = get_user_state(wallet)
    if us.get('trader_stop'):
        us['trader_stop'].set()
    us['trader_running'] = False
    try:
        _dis_conn = sqlite3.connect(DB_FILE)
        _dis_conn.execute('UPDATE users SET bot_enabled=0 WHERE wallet_address=?', (wallet,))
        _dis_conn.commit()
        _dis_conn.close()
    except Exception:
        pass
    short = (wallet[:6] + '...' + wallet[-4:]) if len(wallet) >= 10 else wallet
    print(f'[bot/stop] {short} manually stopped', flush=True)
    return jsonify({'ok': True, 'status': 'stopped'})

@app.route('/api/bot/status', methods=['GET'])
@rate_limit(60, 60)
def bot_status():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'running': False}), 401
    us = get_user_state(wallet)
    running = bool(us.get('trader_running', False))
    open_positions = sum(1 for p in us.get('positions', {}).values() if p.get('amount', 0) > 0)
    # SOL balance from in-memory state
    sol_ready = round(float(us.get('sol', 0) or 0), 4)
    # Win rate: last 30 trades
    win_rate = 0.0
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        uid_row = conn.execute('SELECT id FROM users WHERE wallet_address=?', (wallet,)).fetchone()
        if uid_row:
            c.execute(
                'SELECT COUNT(*) FROM trades WHERE user_id=? AND pnl IS NOT NULL AND timestamp >= datetime(\'now\',\'-7 days\')',
                (uid_row[0],)
            )
            total = c.fetchone()[0] or 0
            c.execute(
                'SELECT COUNT(*) FROM trades WHERE user_id=? AND pnl > 0 AND timestamp >= datetime(\'now\',\'-7 days\')',
                (uid_row[0],)
            )
            wins = c.fetchone()[0] or 0
            win_rate = round(wins / total * 100, 1) if total > 0 else 0.0
        conn.close()
    except Exception:
        pass
    return jsonify({
        'ok': True,
        'running': running,
        'sol_ready': sol_ready,
        'open_positions': open_positions,
        'win_rate': win_rate,
    })

@app.route('/api/bot/positions', methods=['GET'])
@rate_limit(30, 60)
def bot_positions():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'positions': [], 'total_pnl_sol': 0.0}), 401
    us = get_user_state(wallet)
    raw_positions = us.get('positions', {})
    live_map = {t['mint']: t for t in state.get('tokens', [])}
    result = []
    total_pnl_sol = 0.0
    for mint, pos in raw_positions.items():
        if pos.get('amount', 0) <= 0 or pos.get('buy_price', 0) <= 0:
            continue
        symbol     = pos.get('symbol', mint[:8]) or mint[:8]
        buy_price  = float(pos.get('buy_price', 0))
        amount     = float(pos.get('amount', 0))
        spend      = float(pos.get('spend', 0))
        live       = live_map.get(mint)
        if live:
            cur_price = float(live.get('price', 0) or 0)
        else:
            td        = get_token_data(mint)
            cur_price = float(td['price']) if td else 0.0
        if buy_price > 0 and cur_price > 0:
            pnl_pct = round((cur_price - buy_price) / buy_price * 100, 2)
            pnl_sol = round(amount * (cur_price - buy_price), 6)
        else:
            pnl_pct = 0.0
            pnl_sol = 0.0
        total_pnl_sol += pnl_sol
        result.append({
            'symbol':        symbol,
            'mint':          mint,
            'entry_price':   buy_price,
            'current_price': cur_price,
            'pnl_pct':       pnl_pct,
            'pnl_sol':       pnl_sol,
            'spend':         spend,
        })
    result.sort(key=lambda x: x['pnl_sol'], reverse=True)
    return jsonify({
        'ok':           True,
        'positions':    result,
        'total_pnl_sol': round(total_pnl_sol, 6),
    })

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
@rate_limit(30, 60)
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
@rate_limit(30, 60)
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


@app.route('/api/burn-tokens', methods=['POST'])
@rate_limit(3, 60)
def api_burn_tokens():
    """Close a caller-supplied list of empty/dust SPL token accounts and reclaim rent.
    Body: {"accounts": ["<token_account_address>", ...]}  (max 25)
    Returns: {"success": bool, "recovered_sol": float, "failed": ["<addr>", ...], "txs": [...]}
    """
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    data     = request.get_json(silent=True) or {}
    raw_list = data.get('accounts', [])
    if not isinstance(raw_list, list) or not raw_list:
        return jsonify({'success': False, 'error': 'accounts must be a non-empty list'}), 400
    if len(raw_list) > 25:
        return jsonify({'success': False, 'error': 'Max 25 accounts per request'}), 400
    account_addresses = []
    for addr in raw_list:
        addr = str(addr).strip()
        if not is_valid_solana_address(addr):
            return jsonify({'success': False, 'error': f'Invalid account address: {addr}'}), 400
        account_addresses.append(addr)

    conn = sqlite3.connect(DB_FILE)
    row  = conn.execute('SELECT encrypted_private_key FROM users WHERE wallet_address=?', (wallet,)).fetchone()
    conn.close()
    if not row or not row[0]:
        return jsonify({'success': False, 'error': 'No trading key — configure in Settings first'}), 400

    from solders.keypair     import Keypair     as _KP_bt
    from solders.pubkey      import Pubkey      as _PBK_bt
    from solders.instruction import Instruction as _IX_bt, AccountMeta as _AM_bt
    from solders.transaction import Transaction as _TX_bt
    from solders.hash        import Hash        as _SH_bt

    try:
        with _use_key(row[0], wallet) as pk_str:
            kp     = _KP_bt.from_base58_string(pk_str)
            signer = kp.pubkey()
    except Exception as e:
        print(f'[burn-tokens] key decrypt error: {_redact_keys(str(e))}', flush=True)
        return jsonify({'success': False, 'error': 'Cannot decrypt trading key — please re-save in Settings'}), 500

    working_rpc = CLAIM_SOL_RPCS[-1]
    headers     = {'Content-Type': 'application/json'}

    # ── Fetch account info for each requested address ──────────────────────────
    closeable     = []   # {pubkey, lamports, raw_amt, mint, owner, program_id}
    failed_fetch  = []   # pubkeys we couldn't resolve
    skip_no_auth  = []   # pubkeys owned by a different key

    for addr in account_addresses:
        resolved = False
        for rpc in CLAIM_SOL_RPCS:
            try:
                r = requests.post(rpc, json={
                    'jsonrpc': '2.0', 'id': 1,
                    'method': 'getAccountInfo',
                    'params': [addr, {'encoding': 'jsonParsed'}],
                }, headers=headers, timeout=15)
                if r.status_code != 200:
                    continue
                resp   = r.json()
                if 'error' in resp:
                    continue
                value  = resp.get('result', {}).get('value')
                if value is None:
                    failed_fetch.append(addr)
                    resolved = True
                    break

                parsed_data = value.get('data', {})
                if not isinstance(parsed_data, dict) or parsed_data.get('program') not in ('spl-token', 'spl-token-2022'):
                    failed_fetch.append(addr)
                    resolved = True
                    break

                info        = parsed_data.get('parsed', {}).get('info', {})
                tok         = info.get('tokenAmount', {})
                raw_str     = tok.get('amount', '0') or '0'
                raw_amt     = int(raw_str) if raw_str.isdigit() else 0
                lamports    = int(value.get('lamports', 0))
                mint_str    = info.get('mint', '')
                authority   = info.get('owner', '')   # wallet that controls this token account
                prog_id     = value.get('owner', _SPL_PROG_STR)  # token program that owns the account

                working_rpc = rpc
                if authority != str(signer):
                    skip_no_auth.append(addr)
                else:
                    closeable.append({
                        'pubkey':     addr,
                        'lamports':   lamports,
                        'raw_amt':    raw_amt,
                        'mint':       mint_str,
                        'owner':      authority,
                        'program_id': prog_id,
                    })
                resolved = True
                break
            except Exception as ex:
                print(f'[burn-tokens] getAccountInfo {addr} rpc={rpc.split("?")[0]} exc={ex}', flush=True)

        if not resolved:
            failed_fetch.append(addr)

    failed = skip_no_auth + failed_fetch

    if not closeable:
        return jsonify({
            'success':       False,
            'error':         'No closeable accounts found (wrong authority or fetch error)',
            'recovered_sol': 0.0,
            'failed':        failed,
        })

    # ── Build and send CloseAccount (+ Burn for dust) transactions ─────────────
    tx_sigs      = []
    close_failed = []

    for i in range(0, len(closeable), 5):
        batch = closeable[i:i+5]
        try:
            ixs = []
            for a in batch:
                acc_prog = _PBK_bt.from_string(a['program_id'])
                if a['raw_amt'] > 0:
                    # Burn dust first — CloseAccount requires zero balance
                    ixs.append(_IX_bt(
                        program_id=acc_prog,
                        accounts=[
                            _AM_bt(_PBK_bt.from_string(a['pubkey']), is_signer=False, is_writable=True),
                            _AM_bt(_PBK_bt.from_string(a['mint']),   is_signer=False, is_writable=True),
                            _AM_bt(signer,                            is_signer=True,  is_writable=False),
                        ],
                        data=bytes([8]) + struct.pack('<Q', a['raw_amt']),
                    ))
                ixs.append(_IX_bt(
                    program_id=acc_prog,
                    accounts=[
                        _AM_bt(_PBK_bt.from_string(a['pubkey']), is_signer=False, is_writable=True),
                        _AM_bt(signer,                            is_signer=False, is_writable=True),
                        _AM_bt(signer,                            is_signer=True,  is_writable=False),
                    ],
                    data=bytes([9]),
                ))

            bh_resp = requests.post(working_rpc, json={
                'jsonrpc': '2.0', 'id': 1, 'method': 'getLatestBlockhash', 'params': [],
            }, timeout=10).json()
            bh  = bh_resp['result']['value']['blockhash']
            tx  = _TX_bt.new_signed_with_payer(ixs, signer, [kp], _SH_bt.from_string(bh))
            res = requests.post(working_rpc, json={
                'jsonrpc': '2.0', 'id': 1, 'method': 'sendTransaction',
                'params': [base64.b64encode(bytes(tx)).decode(),
                           {'encoding': 'base64', 'skipPreflight': False}],
            }, timeout=30).json()
            print(f'[burn-tokens] sendTransaction response: {res}', flush=True)
            if 'error' in res:
                close_failed.extend(a['pubkey'] for a in batch)
            else:
                tx_sigs.append(str(res.get('result', '')))
        except Exception as e:
            print(f'[burn-tokens] batch exception: {_redact_keys(str(e))}', flush=True)
            close_failed.extend(a['pubkey'] for a in batch)

    closed_set    = set(close_failed)
    closed_accs   = [a for a in closeable if a['pubkey'] not in closed_set]
    recovered_sol = sum(a['lamports'] for a in closed_accs) / 1e9
    all_failed    = failed + close_failed

    add_user_log(wallet, f'[burn-tokens] closed={len(closed_accs)} failed={len(all_failed)} '
                         f'recovered={recovered_sol:.6f} SOL')
    threading.Thread(target=fetch_user_balances, args=(wallet,), daemon=True).start()
    return jsonify({
        'success':       len(close_failed) == 0 and not failed_fetch,
        'recovered_sol': round(recovered_sol, 6),
        'closed':        len(closed_accs),
        'failed':        all_failed,
        'txs':           tx_sigs,
    })


# ── MARKET / TOTD / TRADES ──
@app.route('/api/market')
@rate_limit(60, 60)
def api_market():
    return jsonify({'tokens': state['tokens']})

@app.route('/api/market/top', methods=['GET'])
@rate_limit(60, 60)
def api_market_top():
    tokens = state.get('tokens', [])
    top = sorted(
        [t for t in tokens if t.get('price_change_24h') is not None],
        key=lambda t: abs(float(t.get('price_change_24h') or 0)),
        reverse=True
    )[:5]
    return jsonify({'ok': True, 'tokens': top})

@app.route('/api/market/tokens', methods=['GET'])
@rate_limit(60, 60)
def api_market_tokens_search():
    q = request.args.get('q', '')
    if not q:
        return jsonify([])
    try:
        r = requests.get(f'https://api.dexscreener.com/latest/dex/search?q={q}', timeout=5)
        pairs = r.json().get('pairs', [])[:10]
        tokens = [
            {
                'symbol': p['baseToken']['symbol'],
                'mint':   p['baseToken']['address'],
                'name':   p['baseToken'].get('name', ''),
                'price':  p.get('priceUsd', '?'),
            }
            for p in pairs if p.get('chainId') == 'solana'
        ]
        return jsonify(tokens[:8])
    except Exception:
        return jsonify([])


_market_live_cache: dict = {'ts': 0.0, 'data': []}
_market_live_lock         = threading.Lock()

@app.route('/api/market/live', methods=['GET'])
@rate_limit(60, 60)
def api_market_live():
    now = time.time()
    with _market_live_lock:
        if now - _market_live_cache['ts'] < 15:
            return jsonify({'ok': True, 'tokens': _market_live_cache['data'], 'cached': True})

    def _f(v):
        try:
            return float(v) if v not in (None, '', 'null') else 0.0
        except (TypeError, ValueError):
            return 0.0

    def _extract(p, addr_override=None):
        base  = p.get('baseToken') or {}
        addr  = base.get('address', '') or addr_override or ''
        if not addr:
            return None
        info  = p.get('info') or {}
        pc    = p.get('priceChange') or {}
        vol   = p.get('volume') or {}
        liq   = p.get('liquidity') or {}
        txns  = p.get('txns') or {}
        h24t  = txns.get('h24') or {}
        return {
            'symbol':            base.get('symbol', ''),
            'name':              base.get('name', ''),
            'address':           addr,
            'price':             _f(p.get('priceUsd')),
            'mcap':              _f(p.get('marketCap')),
            'volume_24h':        _f(vol.get('h24')),
            'liquidity':         _f(liq.get('usd')),
            'txns_24h':          int(_f(h24t.get('buys')) + _f(h24t.get('sells'))),
            'traders_24h':       int(_f(h24t.get('buys')) + _f(h24t.get('sells'))),
            'price_change_5m':   _f(pc.get('m5')),
            'price_change_1h':   _f(pc.get('h1')),
            'price_change_6h':   _f(pc.get('h6')),
            'price_change_24h':  _f(pc.get('h24')),
            'image_url':         info.get('imageUrl'),
        }

    seen        = set()
    result      = []
    boost_addrs = []

    # ── Step 1: boosted token addresses ──────────────────────────────────────
    r = _dex_get('https://api.dexscreener.com/token-boosts/top/v1')
    if r and r.status_code == 200:
        try:
            for item in (r.json() if isinstance(r.json(), list) else []):
                if item.get('chainId') == 'solana':
                    a = item.get('tokenAddress', '')
                    if a and a not in seen:
                        seen.add(a)
                        boost_addrs.append(a)
        except Exception:
            pass

    # ── Step 2: batch-fetch pair data for boosted tokens (≤30 per call) ──────
    best_pair: dict = {}   # addr → best pair dict
    for i in range(0, min(len(boost_addrs), 30), 30):
        batch = boost_addrs[i:i + 30]
        if not batch:
            break
        url_b = 'https://api.dexscreener.com/latest/dex/tokens/' + ','.join(batch)
        rb = _dex_get(url_b, timeout=10)
        if rb and rb.status_code == 200:
            try:
                for p in (rb.json().get('pairs') or []):
                    if p.get('chainId') != 'solana':
                        continue
                    a = (p.get('baseToken') or {}).get('address', '')
                    if not a:
                        continue
                    # keep the pair with highest liquidity for this token
                    existing = best_pair.get(a)
                    cur_liq  = _f((p.get('liquidity') or {}).get('usd'))
                    old_liq  = _f((existing.get('liquidity') or {}).get('usd')) if existing else -1
                    if cur_liq > old_liq:
                        best_pair[a] = p
            except Exception:
                pass

    # ── Step 3: trending search as fallback / top-up ─────────────────────────
    trending_pairs = []
    rt = _dex_get('https://api.dexscreener.com/latest/dex/search?q=solana&rankBy=trendingScoreH6')
    if rt and rt.status_code == 200:
        try:
            d = rt.json()
            for p in (d.get('pairs') if isinstance(d, dict) else (d if isinstance(d, list) else [])):
                if p.get('chainId') == 'solana':
                    trending_pairs.append(p)
        except Exception:
            pass

    # ── Step 4: assemble result — boosted first, then trending ───────────────
    added = set()
    for addr in boost_addrs:
        if len(result) >= 20:
            break
        p = best_pair.get(addr)
        if p:
            tok = _extract(p)
            if tok and tok['address'] not in added:
                result.append(tok)
                added.add(tok['address'])

    for p in trending_pairs:
        if len(result) >= 20:
            break
        tok = _extract(p)
        if tok and tok['address'] not in added:
            result.append(tok)
            added.add(tok['address'])

    with _market_live_lock:
        _market_live_cache['ts']   = time.time()
        _market_live_cache['data'] = result

    return jsonify({'ok': True, 'tokens': result, 'cached': False})

@app.route('/api/totd')
@rate_limit(60, 60)
def api_totd():
    updated = state.get('totd_updated_at', 0)
    next_in = max(0.0, TOTD_INTERVAL - (time.time() - updated)) if updated else 0.0
    return jsonify({'token': state.get('token_of_the_day'), 'updated_at': updated, 'next_update_in': round(next_in)})

@app.route('/api/carousel')
@rate_limit(60, 60)
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

def _trades_from_db(wallet: str, today: str) -> tuple:
    """Reconstruct daily stats + trade history from the SQLite trades table.
    Used as a fallback when in-memory trades_history is empty (server restart / new session).
    Returns (daily_dict, history_list, recent_list) — empty tuple values on error."""
    import calendar as _cal
    try:
        conn = sqlite3.connect(DB_FILE)
        try:
            uid_row = conn.execute(
                'SELECT id FROM users WHERE wallet_address=?', (wallet,)
            ).fetchone()
            if not uid_row:
                print(f'[trades_from_db] wallet={wallet[:8]}… not in users table', flush=True)
                return {}, [], []
            uid = uid_row[0]
            # Timestamps stored as 'YYYY-MM-DDTHH:MM:SSZ'
            today_rows = conn.execute(
                '''SELECT token, entry_price, exit_price, amount, pnl, timestamp, mint_address
                   FROM trades
                   WHERE user_id=? AND timestamp >= ? AND timestamp <= ?
                     AND pnl IS NOT NULL
                   ORDER BY timestamp ASC''',
                (uid, today + 'T00:00:00Z', today + 'T23:59:59Z')
            ).fetchall()
            recent_rows = conn.execute(
                '''SELECT token, entry_price, exit_price, amount, pnl, timestamp, mint_address
                   FROM trades
                   WHERE user_id=? AND pnl IS NOT NULL
                   ORDER BY timestamp DESC LIMIT 20''',
                (uid,)
            ).fetchall()
            total_count = conn.execute(
                'SELECT COUNT(*) FROM trades WHERE user_id=?', (uid,)
            ).fetchone()[0]
        finally:
            conn.close()
    except Exception as e:
        print(f'[trades_from_db] DB error: {e}', flush=True)
        return {}, [], []

    def _row_to_trade(r):
        token, entry, exit_p, amount, pnl, ts_str, mint = r
        pnl    = pnl    or 0.0
        entry  = entry  or 0.0
        exit_p = exit_p or 0.0
        amount = amount or 0.0
        pnl_pct  = round((exit_p - entry) / entry * 100, 2) if entry > 0 else 0.0
        spend    = round(amount * entry, 6)
        ts_unix  = 0
        time_str = ''
        try:
            dt = datetime.datetime.strptime(ts_str[:19].replace('T', ' '), '%Y-%m-%d %H:%M:%S')
            ts_unix  = int(_cal.timegm(dt.timetuple()))
            time_str = dt.strftime('%H:%M')
        except Exception as pe:
            print(f'[trades_from_db] parse error ts={ts_str!r}: {pe}', flush=True)
        return {
            'symbol':      token or '???',
            'entry':       entry,
            'exit':        exit_p,
            'pnl':         round(pnl, 4),
            'pnl_pct':     pnl_pct,
            'ts':          ts_unix,
            'time':        time_str,
            'date':        today,
            'mint':        mint or '',
            'spend':       spend,
            'exit_reason': '',
        }

    history = [_row_to_trade(r) for r in today_rows]
    recent  = [_row_to_trade(r) for r in recent_rows]

    total_pnl   = round(sum(t['pnl']   for t in history), 4)
    total_spend = sum(t['spend'] for t in history)
    wins        = sum(1 for t in history if t['pnl'] > 0)
    n           = len(history)
    pnl_pcts    = [t['pnl_pct'] for t in history]

    curve   = []
    running = 0.0
    for t in history:
        running = round(running + t['pnl'], 4)
        curve.append({'t': t['time'], 'v': running})

    daily = {
        'date':          today,
        'total_pnl':     total_pnl,
        'total_pnl_pct': round(total_pnl / total_spend * 100, 2) if total_spend else 0.0,
        'trades':        n,
        'wins':          wins,
        'best':          max(pnl_pcts) if pnl_pcts else None,
        'worst':         min(pnl_pcts) if pnl_pcts else None,
        'curve':         curve,
    }
    print(f'[trades_from_db] wallet={wallet[:8]}… today={today} '
          f'today_trades={n} total_pnl={total_pnl:.4f} '
          f'total_db_trades={total_count} recent={len(recent)}', flush=True)
    return daily, history[-10:], recent


@app.route('/api/trades')
@rate_limit(60, 60)
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
        print(f'[api_trades] wallet={wallet[:8]}… today={today} '
              f'in_mem_today={len(today_trades)} in_mem_recent={len(recent)}', flush=True)
        # Fall back to DB when in-memory history is empty (server restart / new deploy)
        if not today_trades:
            db_daily, db_history, db_recent = _trades_from_db(wallet, today)
            if db_daily:
                return jsonify({'daily': db_daily, 'history': db_history, 'recent': db_recent})
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
    # Timestamps are stored as ISO-8601 with T separator and Z suffix (e.g. '2026-06-22T14:30:00Z').
    # Cutoff must use the same format so the string comparison in SQLite is correct.
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')

    try:
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE wallet_address=?', (wallet,))
            row = c.fetchone()
            if not row:
                print(f'[pnl_chart] wallet={wallet[:8]}… not found in users table', flush=True)
                return jsonify({'ok': True, 'data': []})
            user_id = row[0]
            c.execute(
                '''SELECT timestamp, pnl FROM trades
                   WHERE user_id=? AND timestamp >= ?
                     AND pnl IS NOT NULL AND pnl != 0
                   ORDER BY timestamp ASC''',
                (user_id, cutoff)
            )
            rows = c.fetchall()
            # Debug: also count total trades for this user so we can see how many are filtered
            c.execute('SELECT COUNT(*), SUM(CASE WHEN pnl IS NOT NULL AND pnl != 0 THEN 1 ELSE 0 END) FROM trades WHERE user_id=?', (user_id,))
            dbg = c.fetchone()
            print(f'[pnl_chart] wallet={wallet[:8]}… user_id={user_id} range={range_param} '
                  f'cutoff={cutoff} total_trades={dbg[0]} non_zero_pnl={dbg[1]} '
                  f'in_range={len(rows)}', flush=True)
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
            # Stored as ISO-8601: '2026-06-22T14:30:00Z' — replace T with space and strip Z
            dt = datetime.datetime.strptime(ts_str[:19].replace('T', ' '), '%Y-%m-%d %H:%M:%S')
        except Exception as parse_err:
            print(f'[pnl_chart] timestamp parse failed: {ts_str!r} → {parse_err}', flush=True)
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
    err = _require_role('admin', 'analyst')
    if err: return err
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
    err = _require_role('admin', 'moderator')
    if err: return err
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
    err = _require_role('admin', 'analyst')
    if err: return err
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
    err = _require_role('admin', 'moderator', 'analyst')
    if err: return err
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
    err = _require_role('admin', 'analyst')
    if err: return err

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
        ''', (_get_fee_rate(),))
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
                    tx_sig = send_sol_fee(pk, FEE_WALLET, total_fee)
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
                (user_wallet, '[recovery]', total_fee / _get_fee_rate(), total_fee, tx_sig, 'ok'))
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
    err = _require_role('admin', 'moderator', 'analyst')
    if err: return err
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
    err = _require_role('admin', 'analyst')
    if err: return err
    wallet = _current_wallet()
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
                    'whitelisted_ips': sorted(_OWNER_IPS) if _is_owner(wallet) else []})


@app.route('/api/admin/user/ban', methods=['POST'])
@csrf_exempt
def admin_ban_user():
    err = _require_role('admin', 'moderator')
    if err: return err
    data   = request.get_json(silent=True) or {}
    target = data.get('wallet', '').strip()
    if not target:
        return jsonify({'ok': False, 'msg': 'Missing wallet'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute('DELETE FROM users WHERE wallet_address=?', (target,))
        conn.execute('DELETE FROM feed_posts WHERE wallet=?', (target,))
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()


@app.route('/api/admin/ban', methods=['POST'])
@csrf_exempt
def admin_ban_v2():
    err = _require_role('admin', 'moderator')
    if err: return err
    target = (request.get_json(silent=True) or {}).get('wallet', '').strip()
    if not target:
        return jsonify({'ok': False, 'msg': 'Missing wallet'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute('DELETE FROM users WHERE wallet_address=?', (target,))
        conn.execute('DELETE FROM feed_posts WHERE wallet=?', (target,))
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()


@app.route('/api/admin/post/delete', methods=['POST'])
@csrf_exempt
def admin_delete_post():
    err = _require_role('admin', 'moderator')
    if err: return err
    post_id = (request.get_json(silent=True) or {}).get('post_id')
    if not post_id:
        return jsonify({'ok': False, 'msg': 'Missing post_id'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute('SELECT id FROM feed_posts WHERE id=?', (post_id,)).fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'Post not found'}), 404
        conn.execute('DELETE FROM feed_posts WHERE id=?', (post_id,))
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()


@app.route('/api/admin/trades')
@csrf_exempt
@rate_limit(20, 60)
def admin_trades():
    err = _require_role('admin', 'moderator', 'analyst')
    if err: return err
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''
            SELECT t.id, u.wallet_address, t.token, t.entry_price, t.exit_price,
                   t.amount, t.pnl, t.fee_amount, t.timestamp
            FROM trades t
            LEFT JOIN users u ON t.user_id = u.id
            ORDER BY t.timestamp DESC LIMIT 200
        ''')
        rows = c.fetchall()
        conn.close()
        trades = []
        for r in rows:
            w = r[1] or ''
            trades.append({
                'id':          r[0],
                'wallet':      (w[:4] + '…' + w[-4:]) if len(w) >= 8 else w,
                'wallet_full': w,
                'token':       r[2] or '—',
                'entry':       round(r[3] or 0, 6),
                'exit':        round(r[4] or 0, 6),
                'amount':      round(r[5] or 0, 4),
                'pnl':         round(r[6] or 0, 4),
                'fee':         round(r[7] or 0, 4),
                'ts':          (r[8] or '')[:16],
            })
        return jsonify({'ok': True, 'trades': trades, 'total': len(trades)})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/posts')
@csrf_exempt
@rate_limit(20, 60)
def admin_posts():
    err = _require_role('admin', 'moderator', 'analyst')
    if err: return err
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''
            SELECT fp.id, fp.wallet, fp.content, fp.created_at, u.username
            FROM feed_posts fp
            LEFT JOIN users u ON fp.wallet = u.wallet_address
            ORDER BY fp.created_at DESC LIMIT 100
        ''')
        rows = c.fetchall()
        conn.close()
        posts = []
        for r in rows:
            w = r[1] or ''
            posts.append({
                'id':      r[0],
                'wallet':  (w[:4] + '…' + w[-4:]) if len(w) >= 8 else w,
                'wallet_full': w,
                'content': r[2] or '',
                'ts':      (r[3] or '')[:16],
                'author':  r[4] or ((w[:6] + '…' + w[-4:]) if len(w) >= 10 else w),
            })
        return jsonify({'ok': True, 'posts': posts, 'total': len(posts)})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/revenue')
@csrf_exempt
@rate_limit(20, 60)
def admin_revenue():
    err = _require_role('admin', 'moderator', 'analyst')
    if err: return err
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        ok_f = "(status IS NULL OR status='ok') AND (fee_tx IS NULL OR fee_tx NOT LIKE 'FAILED:%')"
        c.execute(f'SELECT COALESCE(SUM(fee_amount),0) FROM fees WHERE {ok_f}')
        collected = round(float(c.fetchone()[0] or 0), 4)
        c.execute(f'SELECT COALESCE(SUM(fee_amount),0) FROM fees WHERE {ok_f} AND timestamp LIKE ?', (today + '%',))
        today_sol = round(float(c.fetchone()[0] or 0), 4)
        c.execute('SELECT COALESCE(SUM(fee_amount),0) FROM fees WHERE status="failed" OR fee_tx LIKE "FAILED:%"')
        failed = round(float(c.fetchone()[0] or 0), 4)
        c.execute('''SELECT COALESCE(SUM(t.pnl * 0.05), 0) FROM trades t
                     WHERE t.pnl > 0 AND (t.fee_paid IS NULL OR t.fee_paid = 0)''')
        pending = round(float(c.fetchone()[0] or 0), 4)
        c.execute('''SELECT user_wallet, token, gross_profit, fee_amount, fee_tx, timestamp, status
                     FROM fees ORDER BY timestamp DESC LIMIT 200''')
        txs = []
        for r in c.fetchall():
            w = r[0] or ''
            status = r[6] or ('failed' if str(r[4] or '').startswith('FAILED:') else 'ok')
            txs.append({
                'wallet': (w[:4] + '…' + w[-4:]) if len(w) >= 8 else w,
                'token':  r[1], 'gross': round(r[2] or 0, 4),
                'fee':    round(r[3] or 0, 4), 'tx': r[4],
                'ts':     (r[5] or '')[:16], 'status': status,
            })
        conn.close()
        return jsonify({
            'ok': True,
            'collected': collected, 'today': today_sol,
            'failed': failed, 'pending': pending,
            'transactions': txs,
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/settings/save', methods=['POST'])
@csrf_exempt
def admin_settings_save():
    err = _require_role('admin')
    if err: return err
    wallet = session.get('wallet', '')
    data = request.get_json(silent=True) or {}
    max_positions = data.get('max_positions')
    fee           = data.get('fee')
    min_deposit   = data.get('min_deposit')
    rate_limit_v  = data.get('rate_limit')
    # Store in a simple in-memory dict (extend to DB if persistence needed)
    if not hasattr(admin_settings_save, '_store'):
        admin_settings_save._store = {}
    store = admin_settings_save._store
    if max_positions is not None: store['max_positions'] = float(max_positions)
    if fee           is not None: store['fee']           = float(fee)
    if min_deposit   is not None: store['min_deposit']   = float(min_deposit)
    if rate_limit_v  is not None: store['rate_limit']    = int(rate_limit_v)
    print(f'[admin] settings saved by {wallet[:8]}… → {store}', flush=True)
    return jsonify({'ok': True, 'saved': store})


@app.route('/api/admin/features/toggle', methods=['POST'])
@csrf_exempt
def admin_features_toggle():
    wallet = session.get('wallet', '')
    if not wallet or not hmac.compare_digest(wallet.encode(), ADMIN_WALLET.encode()):
        return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
    data    = request.get_json(silent=True) or {}
    feature = str(data.get('feature', '')).strip()
    value   = bool(data.get('value', False))
    if not feature:
        return jsonify({'ok': False, 'msg': 'Missing feature'}), 400
    if not hasattr(admin_features_toggle, '_store'):
        admin_features_toggle._store = {}
    admin_features_toggle._store[feature] = value
    print(f'[admin] feature "{feature}" → {value} by {wallet[:8]}…', flush=True)
    return jsonify({'ok': True, 'feature': feature, 'value': value})


@app.route('/api/admin/whoami')
@csrf_exempt
def admin_whoami():
    wallet = session.get('wallet', '')
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not authenticated'}), 401
    role = get_user_role(wallet)
    if role == 'user':
        return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
    return jsonify({'ok': True, 'wallet': wallet, 'role': role})


@app.route('/api/admin/roles', methods=['GET'])
@csrf_exempt
def admin_roles_list():
    wallet = session.get('wallet', '')
    if not wallet or not hmac.compare_digest(wallet.encode(), ADMIN_WALLET.encode()):
        return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
    conn = sqlite3.connect(DB_FILE)
    try:
        rows = conn.execute(
            'SELECT wallet_address, role, invited_by, invited_at FROM admin_roles ORDER BY invited_at'
        ).fetchall()
        members = [{'wallet': r[0], 'role': r[1], 'invited_by': r[2], 'invited_at': (r[3] or '')[:10]}
                   for r in rows]
        # Always prepend the super-admin (owner) so they appear first
        owner = {'wallet': ADMIN_WALLET, 'role': 'Super-admin', 'invited_by': None, 'invited_at': ''}
        return jsonify({'ok': True, 'members': [owner] + members})
    finally:
        conn.close()


@app.route('/api/admin/invite', methods=['POST'])
@csrf_exempt
def admin_invite():
    err = _require_role('admin')
    if err: return err
    admin_wallet = session.get('wallet', '')
    data        = request.get_json(silent=True) or {}
    invite_addr = str(data.get('wallet', '')).strip()
    role        = str(data.get('role', 'Moderator')).strip()
    if not invite_addr or len(invite_addr) < 32:
        return jsonify({'ok': False, 'msg': 'Invalid wallet address'}), 400
    if invite_addr == ADMIN_WALLET:
        return jsonify({'ok': False, 'msg': 'Owner wallet cannot be re-invited'}), 400
    if role not in ('Moderator', 'Analyst'):
        role = 'Moderator'
    conn = sqlite3.connect(DB_FILE)
    try:
        # Supersede any existing pending invite for this wallet
        conn.execute(
            "UPDATE admin_invites SET status='superseded' WHERE wallet=? AND status='pending'",
            (invite_addr,)
        )
        # Create fresh pending invite (user sees modal on next login)
        conn.execute(
            'INSERT INTO admin_invites(wallet, role, invited_by) VALUES(?,?,?)',
            (invite_addr, role, admin_wallet)
        )
        conn.commit()
        print(f'[admin] invite queued {invite_addr[:8]}… as {role} by {admin_wallet[:8]}…', flush=True)
        return jsonify({
            'ok': True, 'wallet': invite_addr, 'role': role,
            'msg': 'Invite sent — user will see it when they log in',
        })
    finally:
        conn.close()


@app.route('/api/admin/invites')
@csrf_exempt
def admin_invites_pending():
    err = _require_role('admin', 'moderator')
    if err: return err
    conn = sqlite3.connect(DB_FILE)
    try:
        rows = conn.execute(
            "SELECT id, wallet, role, invited_by, created_at FROM admin_invites "
            "WHERE status='pending' ORDER BY created_at DESC"
        ).fetchall()
        invites = [{
            'id': r[0], 'wallet': r[1], 'role': r[2],
            'invited_by': r[3], 'created_at': (r[4] or '')[:10],
        } for r in rows]
        return jsonify({'ok': True, 'invites': invites})
    finally:
        conn.close()


@app.route('/api/invite/check')
@csrf_exempt
def invite_check():
    wallet = session.get('wallet', '')
    if not wallet:
        return jsonify({'ok': False, 'invite': None})
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute(
            "SELECT id, role, invited_by FROM admin_invites "
            "WHERE wallet=? AND status='pending' ORDER BY created_at DESC LIMIT 1",
            (wallet,)
        ).fetchone()
        if not row:
            return jsonify({'ok': True, 'invite': None})
        inv_by = row[2] or ''
        return jsonify({'ok': True, 'invite': {
            'id': row[0], 'role': row[1],
            'invited_by': (inv_by[:8] + '…') if len(inv_by) > 8 else inv_by,
        }})
    finally:
        conn.close()


@app.route('/api/invite/respond', methods=['POST'])
@csrf_exempt
def invite_respond():
    wallet = session.get('wallet', '')
    if not wallet:
        return jsonify({'ok': False, 'msg': 'Not authenticated'}), 401
    data      = request.get_json(silent=True) or {}
    action    = str(data.get('action', '')).strip()
    invite_id = data.get('invite_id')
    if action not in ('accept', 'decline'):
        return jsonify({'ok': False, 'msg': 'Invalid action'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        if invite_id:
            row = conn.execute(
                "SELECT id, role, invited_by FROM admin_invites "
                "WHERE id=? AND wallet=? AND status='pending'",
                (invite_id, wallet)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, role, invited_by FROM admin_invites "
                "WHERE wallet=? AND status='pending' ORDER BY created_at DESC LIMIT 1",
                (wallet,)
            ).fetchone()
        if not row:
            return jsonify({'ok': False, 'msg': 'No pending invite found'}), 404
        inv_id, role, invited_by = row
        if action == 'accept':
            conn.execute(
                "UPDATE users SET role=? WHERE wallet_address=?",
                (role.lower(), wallet)
            )
            conn.execute(
                'INSERT INTO admin_roles(wallet_address,role,invited_by) VALUES(?,?,?) '
                'ON CONFLICT(wallet_address) DO UPDATE SET role=excluded.role',
                (wallet, role, invited_by or '')
            )
            conn.execute("UPDATE admin_invites SET status='accepted' WHERE id=?", (inv_id,))
            conn.commit()
            print(f'[invite] {wallet[:8]}… accepted role {role}', flush=True)
            return jsonify({'ok': True, 'role': role, 'msg': f'You are now a {role}'})
        else:
            conn.execute("UPDATE admin_invites SET status='declined' WHERE id=?", (inv_id,))
            conn.commit()
            print(f'[invite] {wallet[:8]}… declined role {role}', flush=True)
            return jsonify({'ok': True, 'msg': 'Invite declined'})
    finally:
        conn.close()


@app.route('/api/admin/role/change', methods=['POST'])
@csrf_exempt
def admin_role_change():
    wallet = session.get('wallet', '')
    if not wallet or not hmac.compare_digest(wallet.encode(), ADMIN_WALLET.encode()):
        return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
    data        = request.get_json(silent=True) or {}
    target      = str(data.get('wallet', '')).strip()
    role        = str(data.get('role', '')).strip()
    if not target or len(target) < 32:
        return jsonify({'ok': False, 'msg': 'Invalid wallet'}), 400
    if target == ADMIN_WALLET:
        return jsonify({'ok': False, 'msg': 'Cannot change owner role'}), 400
    if role not in ('Moderator', 'Analyst'):
        return jsonify({'ok': False, 'msg': 'Invalid role'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute(
            'UPDATE admin_roles SET role=? WHERE wallet_address=?', (role, target)
        )
        conn.commit()
        print(f'[admin] role change {target[:8]}… → {role} by {wallet[:8]}…', flush=True)
        return jsonify({'ok': True, 'wallet': target, 'role': role})
    finally:
        conn.close()


@app.route('/api/admin/role/remove', methods=['POST'])
@csrf_exempt
def admin_role_remove():
    wallet = session.get('wallet', '')
    if not wallet or not hmac.compare_digest(wallet.encode(), ADMIN_WALLET.encode()):
        return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
    data   = request.get_json(silent=True) or {}
    target = str(data.get('wallet', '')).strip()
    if not target or len(target) < 32:
        return jsonify({'ok': False, 'msg': 'Invalid wallet'}), 400
    if target == ADMIN_WALLET:
        return jsonify({'ok': False, 'msg': 'Cannot remove owner'}), 400
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute('DELETE FROM admin_roles WHERE wallet_address=?', (target,))
        conn.commit()
        print(f'[admin] role removed {target[:8]}… by {wallet[:8]}…', flush=True)
        return jsonify({'ok': True})
    finally:
        conn.close()


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
def _autostart_bots():
    """Re-start bots for users who had bot_enabled=1 before the last deploy.
    Runs in a background thread so it doesn't block Flask startup."""
    time.sleep(5)  # let DB init and migrations finish
    try:
        _conn = sqlite3.connect(DB_FILE)
        _rows = _conn.execute(
            "SELECT wallet_address FROM users "
            "WHERE bot_enabled=1 AND encrypted_private_key != '' AND encrypted_private_key IS NOT NULL"
        ).fetchall()
        _n_total = _conn.execute(
            "SELECT COUNT(*) FROM users WHERE encrypted_private_key != '' AND encrypted_private_key IS NOT NULL"
        ).fetchone()[0]
        _conn.close()
    except Exception as _e:
        print(f'[startup] autostart query failed: {_e}', flush=True)
        return
    print(f'[startup] {len(_rows)} bot(s) set to auto-restart  '
          f'({_n_total} user{"s" if _n_total != 1 else ""} with trading key configured)', flush=True)
    for (_wal,) in _rows:
        try:
            us = get_user_state(_wal)
            if us.get('trader_running'):
                continue
            us['trader_stop']   = threading.Event()
            us['trader_thread'] = threading.Thread(
                target=user_trader_loop, args=(us['trader_stop'], {}, _wal), daemon=True)
            us['trader_thread'].start()
            us['trader_running'] = True
            _sh = (_wal[:6] + '...' + _wal[-4:]) if len(_wal) >= 10 else _wal
            print(f'[startup] auto-restarted bot for {_sh}', flush=True)
            add_user_log(_wal, f'[{_sh}] Bot auto-restarted after deploy')
        except Exception as _e2:
            print(f'[startup] failed to auto-restart {_wal[:8]}: {_e2}', flush=True)

threading.Thread(target=_autostart_bots, daemon=True).start()

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
