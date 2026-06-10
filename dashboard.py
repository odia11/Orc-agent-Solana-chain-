import threading, time, json, os, sys, subprocess, requests, logging, datetime, sqlite3
from flask import Flask, jsonify, request, send_from_directory, session
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
    """Returns the wallet address for the current session (per-user)."""
    return session.get('wallet', '') or state.get('wallet', '')

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
        }
    return user_states[wallet]

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
        # prefer m5 txns for recency, fall back to h1
        m5_buys   = int(txns.get('m5', {}).get('buys',  0) or 0)
        m5_sells  = int(txns.get('m5', {}).get('sells', 0) or 0)
        h1_buys   = int(txns.get('h1', {}).get('buys',  0) or 0)
        h1_sells  = int(txns.get('h1', {}).get('sells', 0) or 0)
        return {
            'symbol':    base.get('symbol', '') or '',
            'name':      base.get('name', '') or '',
            'price':     float(p.get('priceUsd', 0) or 0),
            'change5m':  float(p.get('priceChange', {}).get('m5', 0) or 0),
            'change1h':  float(p.get('priceChange', {}).get('h1', 0) or 0),
            'change24h': float(p.get('priceChange', {}).get('h24', 0) or 0),
            'liquidity': float(p.get('liquidity', {}).get('usd', 0) or 0),
            'volume5m':  float(p.get('volume', {}).get('m5', 0) or 0),
            'volume1h':  float(p.get('volume', {}).get('h1', 0) or 0),
            'volume24h': float(p.get('volume', {}).get('h24', 0) or 0),
            'fdv':       float(p.get('fdv', 0) or p.get('marketCap', 0) or 0),
            'txns_buys':  m5_buys  or h1_buys,
            'txns_sells': m5_sells or h1_sells,
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
    for _ in range(20):
        if state['tokens']: break
        time.sleep(30)
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
                if not data or data['price'] <= 0 or data['liquidity'] < 10000:
                    continue
                sc     = score_token(data)
                entry  = {
                    'mint':      mint,
                    'symbol':    data['symbol'] or mint[:8],
                    'name':      data['name'] or data['symbol'] or mint[:8],
                    'price':     data['price'],
                    'change5m':  data['change5m'],
                    'change1h':  data['change1h'],
                    'change24h': data['change24h'],
                    'volume5m':  data['volume5m'],
                    'volume1h':  data['volume1h'],
                    'volume24h': data['volume24h'],
                    'liquidity': data['liquidity'],
                    'fdv':       data['fdv'],
                    'score':     sc,
                }
                all_tokens.append(entry)
            # Sort by m5 % descending — biggest pumpers first
            display = sorted(all_tokens, key=lambda t: t['change5m'], reverse=True)
            if display:
                state['tokens'] = display
                pumping = sum(1 for t in display if t['change5m'] >= 20 or t['change1h'] >= 30)
                add_log('Market refresh: ' + str(len(display)) + ' tokens' +
                        (' (' + str(pumping) + ' pumping)' if pumping else ' (none pumping)'))
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
                        os.system('cd "' + BASE + '" && python orcagent_solana.py sell ' + mint + ' ' + str(pos['amount']) + ' &')
                        record_trade(label, pos['buy_price'], price, pos['amount'], pos['spend'])
                        positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'peak_price': 0.0, 'spend': 0.0}
                        open_pos -= 1
                        continue

                # ── Entry: score ≥ 7, still pumping ──
                if sc >= 7 and m5 >= 10 and usdc > 3 and open_pos < 3 and pos['amount'] == 0:
                    spend = round(min(usdc * config.get('trade_pct', 0.20), config.get('max_usdc', 12.5)), 2)
                    add_log('BUY ' + label + ' $' + str(spend) + ' score:' + str(sc) + ' m5:+' + str(round(m5, 1)) + '%')
                    os.system('cd "' + BASE + '" && python orcagent_solana.py buy ' + mint + ' ' + str(spend) + ' &')
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
    max_usdc         = float(row[2] or config.get('max_usdc', 12.5))
    daily_loss_limit = abs(float(row[3] or config.get('daily_loss_limit', 50.0)))

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

@app.route('/')
def index():
    return send_from_directory(BASE, 'dashboard.html')

# ── WALLET ──
@app.route('/api/wallet/set', methods=['POST'])
def set_wallet():
    address = (request.json or {}).get('address', '').strip()
    if address:
        session['wallet'] = address
        state['wallet']   = address
        try:
            get_or_create_user(address)
        except: pass
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
def save_settings():
    wallet = _current_wallet()
    if not wallet:
        return jsonify({'ok': False, 'msg': 'No wallet connected'})
    data             = request.json or {}
    private_key_raw  = data.get('private_key', '').strip()
    max_trade_size   = float(data.get('max_trade_size', 12.5))
    daily_loss_limit = float(data.get('daily_loss_limit', 50.0))

    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute('SELECT id, encrypted_private_key FROM users WHERE wallet_address=?', (wallet,))
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
        return jsonify({
            'trader_running': us.get('trader_running', False),
            'usdc': state['usdc'], 'sol': state['sol'],
            'positions': open_pos,
            'log_lines': state['log_lines'][:40],
            'tokens':    state['tokens'],
            'wallet':    wallet,
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
    wallet = _current_wallet()
    config = request.json or {}

    if wallet:
        us = get_user_state(wallet)
        if us['trader_running']:
            return jsonify({'ok': False, 'msg': 'Already running'})
        us['trader_stop']   = threading.Event()
        us['trader_thread'] = threading.Thread(target=user_trader_loop, args=(us['trader_stop'], config, wallet), daemon=True)
        us['trader_thread'].start()
        us['trader_running'] = True
        return jsonify({'ok': True})

    if state['trader_running']:
        return jsonify({'ok': False, 'msg': 'Already running'})
    trader_stop   = threading.Event()
    trader_thread = threading.Thread(target=trader_loop, args=(trader_stop, config), daemon=True)
    trader_thread.start()
    state['trader_running'] = True
    return jsonify({'ok': True})

@app.route('/api/trader/stop', methods=['POST'])
def stop_trader():
    global trader_stop
    wallet = _current_wallet()

    if wallet:
        us = get_user_state(wallet)
        if us.get('trader_stop'):
            us['trader_stop'].set()
        us['trader_running'] = False
        return jsonify({'ok': True})

    trader_stop.set()
    state['trader_running'] = False
    return jsonify({'ok': True})

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
def api_chart(mint):
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
                for i, t_ts in enumerate(ts_arr):
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
                    t_ts = c.get('time', c.get('t', 0))
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

        return jsonify({'candles': candles, 'pair_address': pair_address})
    except Exception as e:
        return jsonify({'candles': [], 'error': str(e)})

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
