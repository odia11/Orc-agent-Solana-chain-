import sys, time, json, os, requests, base64, traceback
from dotenv import load_dotenv
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction
from solders.message import to_bytes_versioned
load_dotenv()

WALLET_ADDRESS = os.getenv('WALLET_ADDRESS', '')
PRIVATE_KEY    = os.getenv('WALLET_PRIVATE_KEY', '')
MAX_SOL        = float(os.getenv('MAX_SOL', 0.5))
MIN_SOL        = float(os.getenv('MIN_SOL', 0.005))
STOP_LOSS      = float(os.getenv('STOP_LOSS', 0.03))
TAKE_PROFIT    = float(os.getenv('TAKE_PROFIT', 0.12))
INTERVAL       = int(os.getenv('INTERVAL', 30))

SOLANA_RPC    = 'https://api.mainnet-beta.solana.com'
SOLANA_RPCS   = [
    'https://api.mainnet-beta.solana.com',
    'https://rpc.ankr.com/solana',
]
USDC_MINT     = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
SOL_MINT      = 'So11111111111111111111111111111111111111112'

# Platform fee on the sell leg (token -> SOL), folded directly into the swap
# transaction via Jupiter's platformFeeBps/feeAccount so it's never a second,
# separately-visible SOL transfer out of the user's wallet. Set by
# dashboard.py's subprocess env for bot-driven sells only -- absent (empty/0)
# for buys and for manual Live Market instant-trades, which keep the swap
# exactly as before.
FEE_WALLET    = os.getenv('FEE_WALLET', '')
FEE_RATE_TXN  = float(os.getenv('FEE_RATE_TXN', '0') or 0)
TOKEN_PROGRAM       = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
ASSOC_TOKEN_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'

def _clean_rpc_error(err):
    if isinstance(err, dict):
        # Solana's real failure reason (e.g. 'AccountNotFound' -- a 0-SOL
        # wallet, since an empty account doesn't exist on-chain to simulate
        # against) lives in data.err, separate from the generic top-level
        # message ('Transaction simulation failed'). Previously a present
        # message short-circuited before data.err was ever checked, so
        # every simulation failure surfaced as that one generic phrase
        # with no actual reason attached.
        detail = None
        if isinstance(err.get('data'), dict) and err['data'].get('err'):
            detail = str(err['data']['err'])
        if err.get('message'):
            msg = str(err['message'])
            if detail and detail not in msg:
                msg = f'{msg}: {detail}'
            return msg[:200]
        if detail:
            return f'Transaction simulation failed: {detail}'[:200]
        return 'RPC error (see server logs for details)'
    return str(err)[:200]

# Optional proxy — set JUPITER_PROXY_URL in Railway Variables to route swap
# calls through the Cloudflare Workers proxy in proxy/worker.js.
# Proxy routes: /quote → api.jup.ag/swap/v1/quote, /swap → api.jup.ag/swap/v1/swap
_PROXY_BASE   = os.getenv('JUPITER_PROXY_URL', '').rstrip('/')
_PROXY_SECRET = os.getenv('JUPITER_PROXY_SECRET', '')

if _PROXY_BASE:
    JUPITER_QUOTE = _PROXY_BASE + '/quote'
    JUPITER_SWAP  = _PROXY_BASE + '/swap'
    print(f'[TRADE] Using Jupiter proxy: {_PROXY_BASE}', flush=True)
else:
    JUPITER_QUOTE = 'https://api.jup.ag/swap/v1/quote'
    JUPITER_SWAP  = 'https://api.jup.ag/swap/v1/swap'

# Required by Jupiter (and the proxy) — some endpoints reject requests without these
_JUP_HEADERS = {
    'Accept':       'application/json',
    'Content-Type': 'application/json',
    'User-Agent':   'Mozilla/5.0 OrcAgent/1.0',
}
if _PROXY_SECRET:
    _JUP_HEADERS['X-Proxy-Secret'] = _PROXY_SECRET


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


# ── PLATFORM FEE (sell leg, bundled into the swap tx) ────────────────────────

def _get_ata(owner: str, mint: str) -> str:
    """Standard Associated Token Account address derivation (a PDA) -- no
    on-chain lookup, just the deterministic address for (owner, mint)."""
    from solders.pubkey import Pubkey
    owner_pk = Pubkey.from_string(owner)
    mint_pk  = Pubkey.from_string(mint)
    ata, _bump = Pubkey.find_program_address(
        [bytes(owner_pk), bytes(Pubkey.from_string(TOKEN_PROGRAM)), bytes(mint_pk)],
        Pubkey.from_string(ASSOC_TOKEN_PROGRAM),
    )
    return str(ata)


def _ensure_fee_ata(payer_keypair, fee_wallet: str, mint: str) -> str:
    """Return the SPL token account FEE_WALLET uses to receive Jupiter's
    platform-fee cut of a sell's SOL output, creating it (funded by
    payer_keypair -- whichever wallet happens to run the first sell after
    this ships, a one-time ~0.002 SOL rent deposit) if it doesn't exist yet.
    Every sell after that reuses the same shared account, no further setup."""
    from solders.pubkey import Pubkey
    from solders.instruction import Instruction, AccountMeta
    from solders.transaction import Transaction
    from solders.hash import Hash as SolHash

    ata = _get_ata(fee_wallet, mint)
    info = requests.post(SOLANA_RPC, json={
        'jsonrpc': '2.0', 'id': 1, 'method': 'getAccountInfo',
        'params': [ata, {'encoding': 'base64'}],
    }, timeout=10).json()
    if (info.get('result') or {}).get('value') is not None:
        return ata  # already set up

    print(f'[fee] one-time setup: creating shared fee token account {ata[:8]}... '
          f'for mint {mint[:8]}...', flush=True)
    payer_pk = payer_keypair.pubkey()
    ix = Instruction(
        program_id=Pubkey.from_string(ASSOC_TOKEN_PROGRAM),
        accounts=[
            AccountMeta(payer_pk,                          is_signer=True,  is_writable=True),
            AccountMeta(Pubkey.from_string(ata),            is_signer=False, is_writable=True),
            AccountMeta(Pubkey.from_string(fee_wallet),     is_signer=False, is_writable=False),
            AccountMeta(Pubkey.from_string(mint),           is_signer=False, is_writable=False),
            AccountMeta(Pubkey.from_string('11111111111111111111111111111111'), is_signer=False, is_writable=False),
            AccountMeta(Pubkey.from_string(TOKEN_PROGRAM),  is_signer=False, is_writable=False),
        ],
        data=bytes(),
    )
    bh = requests.post(SOLANA_RPC, json={
        'jsonrpc': '2.0', 'id': 1, 'method': 'getLatestBlockhash', 'params': [],
    }, timeout=10).json()['result']['value']['blockhash']
    tx = Transaction.new_signed_with_payer([ix], payer_pk, [payer_keypair], SolHash.from_string(bh))
    res = requests.post(SOLANA_RPC, json={
        'jsonrpc': '2.0', 'id': 1, 'method': 'sendTransaction',
        'params': [base64.b64encode(bytes(tx)).decode(), {'encoding': 'base64', 'skipPreflight': False}],
    }, timeout=30).json()
    if 'error' in res:
        raise Exception('fee ATA creation failed: ' + str(res['error']))
    print(f'[fee] fee token account created  TX:{res.get("result","?")[:20]}...', flush=True)
    time.sleep(8)  # let it land before the swap tx references it
    return ata


# ── SWAP EXECUTION ──────────────────────────────────────────────────────────

def _execute_swap_inner(input_mint: str, output_mint: str, amount_lamports: int,
                 wallet_address: str = '', private_key: str = '',
                 fee_wallet: str = '', fee_bps: int = 0) -> tuple:
    """Execute a Jupiter v6 swap. Returns (signature, out_amount) where
    out_amount is the raw (undivided by decimals) quoted output amount as a
    string, so callers can report exactly how much of the output asset the
    swap actually produced.
    Logs every step so failures are immediately visible in Railway logs.
    Called through execute_swap() below, which adds a fee-specific safety net
    on top of this -- call that one, not this one, from outside this file."""
    wallet_address = wallet_address or WALLET_ADDRESS
    private_key    = private_key    or PRIVATE_KEY
    if not wallet_address or not private_key:
        raise ValueError('WALLET_ADDRESS and WALLET_PRIVATE_KEY must be set')

    label     = output_mint[:8] if input_mint == USDC_MINT else input_mint[:8]
    direction = 'BUY' if input_mint == USDC_MINT else 'SELL'

    # Keypair created here so pubkey is derived from the actual signing key
    # and can be passed to the swap body before signing in Step 4.
    try:
        keypair = Keypair.from_base58_string(private_key)
        pubkey  = str(keypair.pubkey())
    except Exception:
        # Do NOT log traceback here — solders may embed the raw key in its error message.
        print('[TRADE] FAIL — invalid private key (exception details withheld for security)', flush=True)
        raise

    # Fold the platform fee into this swap's own transaction (Jupiter's
    # platformFeeBps/feeAccount) instead of a separate, later, visible SOL
    # transfer -- best-effort: any failure here just proceeds without the fee
    # rather than blocking the trade, since a missed fee is a far smaller
    # problem than a real user's sell failing outright.
    fee_account = ''
    if fee_wallet and fee_bps > 0:
        try:
            fee_account = _ensure_fee_ata(keypair, fee_wallet, output_mint)
        except Exception as e:
            print(f'[fee] could not prepare platform-fee account, swap proceeds without it: {e}', flush=True)

    # ── Step 1: Jupiter quote ────────────────────────────────────────────────
    print(f'[TRADE] Step 1/6 — Requesting {direction} quote for {label} ({amount_lamports} lamports)'
          + (f'  (+{fee_bps}bps platform fee)' if fee_account else ''), flush=True)
    for _attempt in range(3):
        try:
            quote_params = {
                'inputMint':   input_mint,
                'outputMint':  output_mint,
                'amount':      int(amount_lamports),
                'slippageBps': 300,
            }
            if fee_account:
                quote_params['platformFeeBps'] = fee_bps
            r = requests.get(
                JUPITER_QUOTE,
                params=quote_params,
                headers=_JUP_HEADERS,
                timeout=15,
            )
            print(f'[TRADE] Step 1 — HTTP {r.status_code} from Jupiter quote endpoint', flush=True)
            if r.status_code == 429:
                wait = 2 ** _attempt
                print(f'[TRADE] Jupiter rate-limited (429) — retrying in {wait}s (attempt {_attempt+1}/3)', flush=True)
                time.sleep(wait)
                continue
            if r.status_code == 503:
                wait = 2 ** _attempt
                print(f'[TRADE] Jupiter unavailable (503) — retrying in {wait}s (attempt {_attempt+1}/3)', flush=True)
                time.sleep(wait)
                continue
            if r.status_code != 200:
                raise Exception(f'Jupiter quote HTTP {r.status_code}: {r.text[:300]}')
            quote = r.json()
            break
        except Exception:
            if _attempt == 2:
                print('[TRADE] FAIL Step 1 (quote GET):\n' + traceback.format_exc(), flush=True)
                raise
            time.sleep(2 ** _attempt)
    else:
        raise Exception('Jupiter quote failed after 3 attempts')

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
    for _attempt in range(3):
        try:
            swap_body = {
                'quoteResponse':             quote,
                'userPublicKey':             pubkey,
                'wrapAndUnwrapSol':          True,
                'dynamicComputeUnitLimit':   True,
                'prioritizationFeeLamports': 'auto',
            }
            if fee_account:
                swap_body['feeAccount'] = fee_account
            r2 = requests.post(
                JUPITER_SWAP,
                json=swap_body,
                headers=_JUP_HEADERS,
                timeout=20,
            )
            print(f'[TRADE] Step 3 — HTTP {r2.status_code} from Jupiter swap endpoint', flush=True)
            if r2.status_code == 429:
                wait = 2 ** _attempt
                print(f'[TRADE] Jupiter rate-limited (429) — retrying in {wait}s (attempt {_attempt+1}/3)', flush=True)
                time.sleep(wait)
                continue
            if r2.status_code == 503:
                wait = 2 ** _attempt
                print(f'[TRADE] Jupiter unavailable (503) — retrying in {wait}s (attempt {_attempt+1}/3)', flush=True)
                time.sleep(wait)
                continue
            if r2.status_code not in (200, 201):
                raise Exception(f'Jupiter swap HTTP {r2.status_code}: {r2.text[:300]}')
            swap_resp = r2.json()
            break
        except Exception:
            if _attempt == 2:
                print('[TRADE] FAIL Step 3 (swap POST):\n' + traceback.format_exc(), flush=True)
                raise
            time.sleep(2 ** _attempt)
    else:
        raise Exception('Jupiter swap failed after 3 attempts')

    swap_tx_b64 = swap_resp.get('swapTransaction')
    print(f'[TRADE] Step 4/6 — Signing transaction (tx present={bool(swap_tx_b64)})', flush=True)
    if 'error' in swap_resp:
        print(f'[TRADE] Jupiter swap error: {swap_resp["error"]}', flush=True)
        raise Exception(f'Jupiter swap error: {_clean_rpc_error(swap_resp["error"])}')
    if not swap_tx_b64:
        raise Exception(f'No swapTransaction in response: {str(swap_resp)[:300]}')

    # ── Step 4: Decode + sign ────────────────────────────────────────────────
    try:
        tx_bytes  = base64.b64decode(swap_tx_b64)
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
        raise Exception(f'RPC sendTransaction error: {_clean_rpc_error(rpc_resp["error"])}')
    sig = rpc_resp.get('result')
    if sig:
        print(f'[TRADE] SUCCESS: https://solscan.io/tx/{sig}', flush=True)
        return sig, out_amount
    raise Exception(f'No signature in RPC response: {rpc_resp}')


def execute_swap(input_mint: str, output_mint: str, amount_lamports: int,
                  wallet_address: str = '', private_key: str = '',
                  fee_wallet: str = '', fee_bps: int = 0) -> tuple:
    """Public entry point for a swap -- see _execute_swap_inner() for the real
    step-by-step logic. This just adds one safety net on top: if a platform
    fee was requested and ANYTHING about the swap fails (quote rejection, a
    bad/missing fee account, on-chain simulation, whatever), retry the exact
    same swap once with no fee attached at all, rather than letting a
    fee-related problem fail a real user's trade."""
    try:
        return _execute_swap_inner(input_mint, output_mint, amount_lamports,
                                    wallet_address, private_key, fee_wallet, fee_bps)
    except Exception as e:
        if fee_wallet and fee_bps > 0:
            print(f'[fee] swap with platform fee failed ({e}) — retrying once without it', flush=True)
            return _execute_swap_inner(input_mint, output_mint, amount_lamports,
                                        wallet_address, private_key, fee_wallet='', fee_bps=0)
        raise


# ── SINGLE SWAP ENTRY POINT (called from dashboard subprocess) ───────────────

def execute_single_swap(action: str, mint: str, amount_str: str):
    """Called as: python orcagent_solana.py buy|sell MINT AMOUNT"""
    amount = float(amount_str)
    try:
        if action == 'buy':
            lamports = int(amount * 1_000_000_000)  # SOL has 9 decimals
            sig, out_amount_raw = execute_swap(SOL_MINT, mint, lamports)
            try:
                decimals    = get_token_decimals(mint)
                got_amount  = int(out_amount_raw) / (10 ** decimals)
            except Exception:
                got_amount = 0
            print(f'BUY {mint[:16]} {round(amount,4)} SOL got:{round(got_amount,6)} TX:{sig}', flush=True)
        elif action == 'sell':
            decimals              = get_token_decimals(mint)
            actual_balance, raw_balance = get_token_balance_raw(mint)
            if actual_balance <= 0 or raw_balance <= 0:
                print(f'SELL {mint[:16]} — on-chain balance is 0, nothing to sell', flush=True)
                sys.exit(0)
            # amount<=0 means "sell everything held" (e.g. Live Market's "Sell
            # All" button, and every bot-driven full close: stop loss, take
            # profit, crash exit, rugpull exit, manual sell, stop-trading
            # liquidation) -- use the exact raw integer balance from the RPC
            # directly rather than reconstructing it from the decimal-divided
            # uiAmount float, which can undershoot by a unit or more to float
            # precision loss and leave a sliver of dust in the wallet even
            # though the intent was to close the position 100%.
            # A positive amount means sell exactly that much, clamped to the
            # actual on-chain balance so a stale/optimistic caller can never
            # oversell -- previously this branch ignored `amount` entirely and
            # always sold 100%, so a partial sell request (e.g. the wallet
            # Swap modal) silently liquidated the whole balance instead.
            if amount <= 0:
                lamports    = raw_balance
                sell_amount = actual_balance
            else:
                sell_amount = min(amount, actual_balance)
                lamports    = int(sell_amount * (10 ** decimals))
            if lamports <= 0:
                print(f'SELL {mint[:16]} — computed sell amount is 0, nothing to sell', flush=True)
                sys.exit(0)
            sig, out_amount_raw = execute_swap(
                mint, SOL_MINT, lamports,
                fee_wallet=FEE_WALLET, fee_bps=int(round(FEE_RATE_TXN * 10000)))
            try:
                sol_received = int(out_amount_raw) / 1_000_000_000  # SOL has 9 decimals
            except Exception:
                sol_received = 0
            requested = 'ALL' if amount <= 0 else round(amount, 6)
            print(f'SELL {mint[:16]} amt:{round(sell_amount,6)} sol:{round(sol_received,6)} '
                  f'(requested:{requested}, on-chain:{round(actual_balance,6)}) TX:{sig}', flush=True)
        else:
            print(f'Unknown action: {action}', flush=True)
            sys.exit(1)
    except Exception:
        print(f'execute_single_swap FAILED [{action} {mint[:16]}]:\n' + traceback.format_exc(), flush=True)
        sys.exit(1)


# ── BALANCE HELPERS ──────────────────────────────────────────────────────────

def get_balance() -> float:
    try:
        owner = str(Keypair.from_base58_string(PRIVATE_KEY).pubkey()) if PRIVATE_KEY else WALLET_ADDRESS
    except Exception:
        owner = WALLET_ADDRESS
    r = requests.post(SOLANA_RPC, json={
        'jsonrpc': '2.0', 'id': 1,
        'method': 'getBalance',
        'params': [owner],
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


def get_token_balance(mint: str) -> float:
    """Fetch actual on-chain token balance for the trading keypair.

    Jupiter uses keypair.pubkey() as userPublicKey — the ATA is created there,
    NOT on WALLET_ADDRESS (the Phantom session wallet). We must query the address
    derived from the private key, or sells will always see balance=0 and fail.
    """
    return get_token_balance_raw(mint)[0]

def get_token_balance_raw(mint: str) -> tuple:
    """Same lookup as get_token_balance(), but also returns the exact raw
    integer amount (as reported by the RPC, no float involved) alongside the
    decimal-divided uiAmount float. A full-balance sell must use the raw
    integer directly -- reconstructing it by multiplying uiAmount back up by
    10**decimals can undershoot the true on-chain amount by a unit or more
    (float precision loss), leaving a sliver of dust behind even when the
    caller asked to sell everything. Returns (ui_amount: float, raw_amount:
    int) -- (0.0, 0) if there's no token account or the lookup fails."""
    try:
        owner = str(Keypair.from_base58_string(PRIVATE_KEY).pubkey()) if PRIVATE_KEY else WALLET_ADDRESS
    except Exception:
        owner = WALLET_ADDRESS
    print(f'[get_token_balance] owner={owner[:8]}... mint={mint[:8]}...', flush=True)
    try:
        r = requests.post(SOLANA_RPC, json={
            'jsonrpc': '2.0', 'id': 1,
            'method': 'getTokenAccountsByOwner',
            'params': [owner, {'mint': mint}, {'encoding': 'jsonParsed'}],
        }, timeout=10)
        accounts = r.json().get('result', {}).get('value', [])
        if accounts:
            amt_info = accounts[0]['account']['data']['parsed']['info']['tokenAmount']
            ui  = float(amt_info.get('uiAmount', 0) or 0)
            raw = int(amt_info.get('amount', 0) or 0)
            print(f'[get_token_balance] balance={ui} raw={raw}', flush=True)
            return ui, raw
        print(f'[get_token_balance] no ATA found for {mint[:8]}... on {owner[:8]}...', flush=True)
    except Exception as e:
        print(f'[get_token_balance] ERROR {mint[:16]}: {e}', flush=True)
    return 0.0, 0


# ── TOKEN DISCOVERY ──────────────────────────────────────────────────────────

def discover_tokens(limit=30):
    mints   = []
    trending = set()
    seen    = {USDC_MINT, SOL_MINT}
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
    """Score 0–10. Momentum-focused: ≥4.5 = BUY signal."""
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
            print(f'SOL:{round(sol,4)}', flush=True)

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
                        positions[mint] = {'amount': 0.0, 'buy_price': 0.0}
                    pos = positions[mint]

                    if pos['amount'] > 0 and pos['buy_price'] > 0:
                        chg = (data['price'] - pos['buy_price']) / pos['buy_price']
                        _dec = pos.get('decimals', 6)
                        _raw = int(pos['amount'] * (10 ** _dec))
                        if chg <= -STOP_LOSS:
                            sig, _ = execute_swap(mint, SOL_MINT, _raw)
                            print(f'STOP LOSS {label} {round(chg*100,1)}% TX:{sig}', flush=True)
                            pos['amount'] = pos['buy_price'] = 0.0
                        elif chg >= TAKE_PROFIT:
                            sig, _ = execute_swap(mint, SOL_MINT, _raw)
                            print(f'TAKE PROFIT {label} +{round(chg*100,1)}% TX:{sig}', flush=True)
                            pos['amount'] = pos['buy_price'] = 0.0
                        continue

                    open_count = sum(1 for p in positions.values() if p.get('amount', 0) > 0)
                    if sc >= 4.5 and open_count < 3 and (m5 >= 5 or data.get('change15m', 0) >= 10 or is_tr) and sol > 0.05:
                        trade_pct = 0.60 if sc >= 7 else 0.40
                        spend = min(sol * trade_pct, MAX_SOL)
                        if spend < MIN_SOL:
                            continue
                        sig, _ = execute_swap(SOL_MINT, mint, int(spend * 1e9))
                        print(f'BUY {label} {round(spend,4)} SOL score:{sc} pct:{int(trade_pct*100)}% m5:+{round(m5,1)}% TX:{sig}', flush=True)
                        _dec              = get_token_decimals(mint)
                        pos['amount']    = spend
                        pos['decimals']  = _dec
                        pos['buy_price'] = data['price']
                        sol -= spend
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
