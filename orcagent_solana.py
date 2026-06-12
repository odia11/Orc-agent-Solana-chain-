import sys, time, json, os, requests, base64, traceback
from dotenv import load_dotenv
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction
from solders.message import to_bytes_versioned
load_dotenv()

WALLET_ADDRESS = os.getenv('WALLET_ADDRESS', '')
PRIVATE_KEY    = os.getenv('WALLET_PRIVATE_KEY', '')
MAX_USDC       = float(os.getenv('MAX_USDC', 50))
STOP_LOSS      = float(os.getenv('STOP_LOSS', 0.05))
TAKE_PROFIT    = float(os.getenv('TAKE_PROFIT', 0.15))
TRAILING_STOP  = float(os.getenv('TRAILING_STOP', 0.03))
INTERVAL       = int(os.getenv('INTERVAL', 60))

SOLANA_RPC    = 'https://api.mainnet-beta.solana.com'
SOLANA_RPCS   = [
    'https://api.mainnet-beta.solana.com',
    'https://rpc.ankr.com/solana',
]
JUPITER_QUOTE = 'https://quote-api.jup.ag/v6/quote'
JUPITER_SWAP  = 'https://quote-api.jup.ag/v6/swap'
USDC_MINT     = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'


def _rpc_post(payload: dict, timeout: int = 30) -> dict:
    """Try each RPC endpoint in order; return first success or raise."""
    last_err: object = None
    for rpc in SOLANA_RPCS:
        try:
            result = requests.post(rpc, json=payload, timeout=timeout).json()
            # Retry on node-overload codes; return on any other response
            if 'error' not in result or result['error'].get('code') not in (-32005, -32009):
                return result
            last_err = result
        except Exception as e:
            last_err = e
    raise Exception(f'All RPC endpoints failed. Last: {last_err}')


def get_token_decimals(mint: str) -> int:
    """Fetch actual on-chain decimals via getTokenSupply; default 6 on error."""
    try:
        r = requests.post(SOLANA_RPC, json={
            'jsonrpc': '2.0', 'id': 1,
            'method': 'getTokenSupply',
            'params': [mint],
        }, timeout=8).json()
        return int(r['result']['value']['decimals'])
    except Exception:
        print(f'get_token_decimals failed for {mint[:8]}, defaulting to 6', flush=True)
        return 6


# ── SWAP EXECUTION ──────────────────────────────────────────────────────────

def execute_swap(input_mint: str, output_mint: str, amount_lamports: int,
                 wallet_address: str = '', private_key: str = '') -> str:
    """Execute a Jupiter v6 swap. Returns the transaction signature string.
    Logs every step so failures are immediately visible in Railway logs."""
    wallet_address = wallet_address or WALLET_ADDRESS
    private_key    = private_key    or PRIVATE_KEY
    if not wallet_address or not private_key:
        raise ValueError('WALLET_ADDRESS and WALLET_PRIVATE_KEY must be set')

    label     = output_mint[:8] if input_mint == USDC_MINT else input_mint[:8]
    direction = 'BUY' if input_mint == USDC_MINT else 'SELL'

    # ── Step 1: Jupiter quote ────────────────────────────────────────────────
    print(f'[TRADE] Step 1/6 — Requesting {direction} quote for {label} ({amount_lamports} lamports)', flush=True)
    try:
        r = requests.get(
            JUPITER_QUOTE,
            params={
                'inputMint':   input_mint,
                'outputMint':  output_mint,
                'amount':      int(amount_lamports),
                'slippageBps': 300,
            },
            timeout=15,
        )
        quote = r.json()
    except Exception:
        print('[TRADE] FAIL Step 1 (quote GET):\n' + traceback.format_exc(), flush=True)
        raise

    # ── Step 2: Validate quote ───────────────────────────────────────────────
    out_amount = quote.get('outAmount', '?')
    impact     = quote.get('priceImpactPct', '?')
    print(f'[TRADE] Step 2/6 — Quote OK: outAmount={out_amount}  priceImpact={impact}%', flush=True)
    if 'error' in quote:
        print(f'[TRADE] Jupiter quote error: {quote["error"]}', flush=True)
        raise Exception(f'Jupiter quote error: {quote["error"]}')
    if 'outAmount' not in quote:
        raise Exception(f'Unexpected quote response: {str(quote)[:300]}')

    # ── Step 3: Get swap transaction ─────────────────────────────────────────
    print('[TRADE] Step 3/6 — Getting swap transaction from Jupiter', flush=True)
    try:
        r2 = requests.post(
            JUPITER_SWAP,
            json={
                'quoteResponse':             quote,
                'userPublicKey':             wallet_address,
                'wrapAndUnwrapSol':          True,
                'dynamicComputeUnitLimit':   True,
                'prioritizationFeeLamports': 1000,
            },
            headers={'Content-Type': 'application/json'},
            timeout=20,
        )
        swap_resp = r2.json()
    except Exception:
        print('[TRADE] FAIL Step 3 (swap POST):\n' + traceback.format_exc(), flush=True)
        raise

    swap_tx_b64 = swap_resp.get('swapTransaction')
    print(f'[TRADE] Step 4/6 — Signing transaction (tx present={bool(swap_tx_b64)})', flush=True)
    if 'error' in swap_resp:
        print(f'[TRADE] Jupiter swap error: {swap_resp["error"]}', flush=True)
        raise Exception(f'Jupiter swap error: {swap_resp["error"]}')
    if not swap_tx_b64:
        raise Exception(f'No swapTransaction in response: {str(swap_resp)[:300]}')

    # ── Step 4: Decode + sign ────────────────────────────────────────────────
    try:
        tx_bytes  = base64.b64decode(swap_tx_b64)
        keypair   = Keypair.from_base58_string(private_key)
        vtx       = VersionedTransaction.from_bytes(tx_bytes)
        # VersionedTransaction(message, [keypair]) is the correct sign pattern;
        # mutating vtx.signatures[0] is silently ignored (immutable Rust binding).
        signed_tx = VersionedTransaction(vtx.message, [keypair])
        encoded   = base64.b64encode(bytes(signed_tx)).decode()
    except Exception:
        print('[TRADE] FAIL Step 4 (sign):\n' + traceback.format_exc(), flush=True)
        raise

    # ── Step 5: Send to RPC (with multi-RPC failover) ───────────────────────
    print('[TRADE] Step 5/6 — Sending transaction to Solana RPC', flush=True)
    try:
        rpc_resp = _rpc_post({
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'sendTransaction',
            'params': [
                encoded,
                {
                    'encoding':      'base64',
                    'skipPreflight': False,
                    'maxRetries':    3,
                },
            ],
        }, timeout=30)
    except Exception:
        print('[TRADE] FAIL Step 5 (sendTransaction):\n' + traceback.format_exc(), flush=True)
        raise

    # ── Step 6: Result ───────────────────────────────────────────────────────
    print(f'[TRADE] Step 6/6 — RPC response: {rpc_resp}', flush=True)
    if 'error' in rpc_resp:
        print(f'[TRADE] RPC ERROR: {rpc_resp["error"]}', flush=True)
        raise Exception(f'RPC sendTransaction error: {rpc_resp["error"]}')
    sig = rpc_resp.get('result')
    if sig:
        print(f'[TRADE] SUCCESS: https://solscan.io/tx/{sig}', flush=True)
        return sig
    raise Exception(f'No signature in RPC response: {rpc_resp}')


# ── SINGLE SWAP ENTRY POINT (called from dashboard subprocess) ───────────────

def execute_single_swap(action: str, mint: str, amount_str: str):
    """Called as: python orcagent_solana.py buy|sell MINT AMOUNT"""
    amount = float(amount_str)
    try:
        if action == 'buy':
            lamports = int(amount * 1_000_000)  # USDC has 6 decimals
            sig = execute_swap(USDC_MINT, mint, lamports)
            print(f'BUY {mint[:16]} ${round(amount,2)} TX:{sig}', flush=True)
        elif action == 'sell':
            decimals = get_token_decimals(mint)
            lamports = int(amount * (10 ** decimals))
            sig = execute_swap(mint, USDC_MINT, lamports)
            print(f'SELL {mint[:16]} amt:{round(amount,4)} TX:{sig}', flush=True)
        else:
            print(f'Unknown action: {action}', flush=True)
            sys.exit(1)
    except Exception:
        print(f'execute_single_swap FAILED [{action} {mint[:16]}]:\n' + traceback.format_exc(), flush=True)
        sys.exit(1)


# ── BALANCE HELPERS ──────────────────────────────────────────────────────────

def get_balance() -> float:
    r = requests.post(SOLANA_RPC, json={
        'jsonrpc': '2.0', 'id': 1,
        'method': 'getBalance',
        'params': [WALLET_ADDRESS],
    }, timeout=10)
    return r.json()['result']['value'] / 1e9

def get_usdc_balance() -> float:
    r = requests.post(SOLANA_RPC, json={
        'jsonrpc': '2.0', 'id': 1,
        'method': 'getTokenAccountsByOwner',
        'params': [WALLET_ADDRESS, {'mint': USDC_MINT}, {'encoding': 'jsonParsed'}],
    }, timeout=10)
    accounts = r.json().get('result', {}).get('value', [])
    if accounts:
        return float(accounts[0]['account']['data']['parsed']['info']['tokenAmount']['uiAmount'] or 0)
    return 0.0


# ── TOKEN DISCOVERY ──────────────────────────────────────────────────────────

def discover_tokens(limit=30):
    mints   = []
    trending = set()
    seen    = {USDC_MINT}
    _h = {'User-Agent': 'Mozilla/5.0 OrcAgent/1.0', 'Accept': 'application/json'}
    try:
        r = requests.get('https://api.dexscreener.com/token-boosts/top/v1', headers=_h, timeout=10)
        if r.status_code == 200:
            for item in r.json():
                if item.get('chainId') == 'solana':
                    m = item.get('tokenAddress', '')
                    if m and m not in seen:
                        seen.add(m); mints.append(m)
    except Exception: pass
    try:
        r = requests.get(
            'https://api.dexscreener.com/latest/dex/search?q=solana&rankBy=trendingScoreH6',
            headers=_h, timeout=10)
        if r.status_code == 200:
            data  = r.json()
            pairs = data.get('pairs', []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            for p in pairs:
                if p.get('chainId') == 'solana':
                    m = (p.get('baseToken') or {}).get('address', '')
                    if m:
                        trending.add(m)
                        if m not in seen:
                            seen.add(m); mints.append(m)
    except Exception: pass
    try:
        r = requests.get('https://api.dexscreener.com/token-profiles/latest/v1', headers=_h, timeout=10)
        if r.status_code == 200:
            items = r.json() if isinstance(r.json(), list) else []
            for item in items:
                if item.get('chainId') == 'solana':
                    m = item.get('tokenAddress', '')
                    if m and m not in seen:
                        seen.add(m); mints.append(m)
    except Exception: pass
    return [{'mint': m, 'label': m[:8]} for m in mints[:limit]], trending


def get_token_data(mint: str):
    try:
        r = requests.get(
            'https://api.dexscreener.com/latest/dex/tokens/' + mint,
            headers={'User-Agent': 'Mozilla/5.0 OrcAgent/1.0'},
            timeout=10)
        r.raise_for_status()
        pairs = r.json().get('pairs', [])
        if not pairs: return None
        p    = pairs[0]
        txns = p.get('txns', {})
        m5b  = int(txns.get('m5', {}).get('buys',  0) or 0)
        m5s  = int(txns.get('m5', {}).get('sells', 0) or 0)
        h1b  = int(txns.get('h1', {}).get('buys',  0) or 0)
        h1s  = int(txns.get('h1', {}).get('sells', 0) or 0)
        return {
            'price':      float(p.get('priceUsd', 0) or 0),
            'change5m':   float(p.get('priceChange', {}).get('m5',  0) or 0),
            'change15m':  float(p.get('priceChange', {}).get('m15', 0) or 0),
            'change1h':   float(p.get('priceChange', {}).get('h1',  0) or 0),
            'liquidity':  float(p.get('liquidity', {}).get('usd', 0) or 0),
            'volume5m':   float(p.get('volume', {}).get('m5', 0) or 0),
            'volume1h':   float(p.get('volume', {}).get('h1', 0) or 0),
            'txns_buys':  m5b or h1b,
            'txns_sells': m5s or h1s,
        }
    except Exception:
        return None


def score_token(data: dict) -> float:
    """Score 0–10. Momentum-focused: ≥4 = BUY signal."""
    if data.get('price', 0) <= 0: return 0
    score = 0.0
    m5    = data.get('change5m', 0)
    h1    = data.get('change1h', 0)
    vol5m = data.get('volume5m', 0)
    liq   = data.get('liquidity', 0)
    buys  = data.get('txns_buys', 0)
    sells = max(data.get('txns_sells', 1), 1)

    if   m5 >= 50: score += 4.0
    elif m5 >= 30: score += 3.0
    elif m5 >= 20: score += 2.5
    elif m5 >= 10: score += 1.5
    elif m5 >=  5: score += 0.5

    if   h1 >= 60: score += 2.0
    elif h1 >= 30: score += 1.5
    elif h1 >= 15: score += 1.0
    elif h1 >=  5: score += 0.5

    if   vol5m >= 50000: score += 2.0
    elif vol5m >= 20000: score += 1.5
    elif vol5m >=  5000: score += 1.0
    elif vol5m >=  1000: score += 0.5

    ratio = buys / sells
    if   ratio >= 4.0: score += 2.0
    elif ratio >= 2.5: score += 1.5
    elif ratio >= 1.5: score += 1.0
    elif ratio >= 1.0: score += 0.5

    if   liq < 5000:  score = max(0, score - 4.0)
    elif liq < 10000: score = max(0, score - 2.0)

    return min(10.0, max(0.0, round(score, 1)))


# ── STANDALONE TRADING LOOP ──────────────────────────────────────────────────

def run():
    """Standalone trading loop (not used by dashboard.py but available for CLI use)."""
    print('OrcAgent Solana — momentum scalper v6', flush=True)
    print(f'Wallet: {WALLET_ADDRESS}', flush=True)
    print(f'TP:{TAKE_PROFIT*100}% | SL:{STOP_LOSS*100}% | Interval:{INTERVAL}s', flush=True)
    positions = {}
    while True:
        try:
            tokens, trending_mints = discover_tokens()
            sol  = get_balance()
            usdc = get_usdc_balance()
            print(f'SOL:{round(sol,4)} USDC:{round(usdc,2)}', flush=True)

            candidates = []
            for t in tokens:
                mint = t['mint']
                data = get_token_data(mint)
                if not data or data['price'] <= 0 or data['liquidity'] < 15000: continue
                m5  = data['change5m']
                m15 = data.get('change15m', 0)
                is_tr = mint in trending_mints
                if (m5 >= 5 or m15 >= 10 or is_tr) and data['volume5m'] >= 5000:
                    sc = score_token(data)
                    candidates.append((sc, t, data, is_tr))
            candidates.sort(key=lambda x: x[0], reverse=True)

            for sc, token, data, is_tr in candidates:
                try:
                    mint  = token['mint']
                    label = token['label']
                    m5    = data['change5m']
                    if mint not in positions:
                        positions[mint] = {'amount': 0.0, 'buy_price': 0.0, 'peak_price': 0.0}
                    pos = positions[mint]

                    if pos['amount'] > 0 and pos['buy_price'] > 0:
                        if data['price'] > pos['peak_price']: pos['peak_price'] = data['price']
                        chg = (data['price'] - pos['buy_price']) / pos['buy_price']
                        _dec = pos.get('decimals', 6)
                        _raw = int(pos['amount'] * (10 ** _dec))
                        if chg >= TAKE_PROFIT:
                            sig = execute_swap(mint, USDC_MINT, _raw)
                            print(f'TAKE PROFIT {label} +{round(chg*100,1)}% TX:{sig}', flush=True)
                            pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                        elif chg <= -STOP_LOSS:
                            sig = execute_swap(mint, USDC_MINT, _raw)
                            print(f'STOP LOSS {label} {round(chg*100,1)}% TX:{sig}', flush=True)
                            pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                        elif m5 < 5:
                            sig = execute_swap(mint, USDC_MINT, _raw)
                            print(f'MOMENTUM DIED {label} m5={round(m5,1)}% TX:{sig}', flush=True)
                            pos['amount'] = pos['buy_price'] = pos['peak_price'] = 0.0
                        continue

                    if sc >= 4 and (m5 >= 5 or data.get('change15m', 0) >= 10 or is_tr) and usdc > 5:
                        spend = min(usdc * 0.20, MAX_USDC / 4)
                        sig   = execute_swap(USDC_MINT, mint, int(spend * 1e6))
                        print(f'BUY {label} ${round(spend,2)} score:{sc} m5:+{round(m5,1)}% TX:{sig}', flush=True)
                        _dec              = get_token_decimals(mint)
                        pos['amount']     = spend / data['price']
                        pos['decimals']   = _dec
                        pos['buy_price']  = data['price']
                        pos['peak_price'] = data['price']
                        usdc -= spend
                except Exception as e:
                    print(f'{token["label"]} error: {traceback.format_exc()}', flush=True)
        except Exception:
            print('run() loop error:\n' + traceback.format_exc(), flush=True)
        time.sleep(INTERVAL)


if __name__ == '__main__':
    if len(sys.argv) >= 4:
        execute_single_swap(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        run()
