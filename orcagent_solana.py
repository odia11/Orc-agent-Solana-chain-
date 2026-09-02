import sys, time, json, os, requests, base64, traceback, struct
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
# Every swap in this file is BASE<->memecoin: one side is always one of these
# ("the base currency being spent/received"), the other the token being
# traded. Hardcoded rather than fetched on-chain -- both are fixed, well-known
# mints that never change decimals. Used to infer BUY/SELL generically (any
# base mint, not just SOL) and to convert a UI amount to raw base units for
# execute_single_swap()'s optional USDC leg.
BASE_MINT_DECIMALS = {SOL_MINT: 9, USDC_MINT: 6}
_BASE_MINTS = frozenset(BASE_MINT_DECIMALS)

# Platform fee, folded directly into the swap transaction itself so it's
# never a second, separately-visible SOL transfer out of the user's wallet.
# Sell (token -> SOL): Jupiter's own platformFeeBps/feeAccount handles it,
# since the swap's output is already SOL. Buy (SOL -> token): Jupiter's fee
# mechanism would take it out of the purchased TOKEN instead, so a buy
# splices our own SOL-transfer instruction into the swap's own transaction
# via /swap-instructions + MessageV0.try_compile() (see
# _execute_buy_with_bundled_fee()) -- more moving parts, but the fee stays in
# SOL either way. Set by dashboard.py's subprocess env; absent (empty/0)
# disables this entirely (e.g. manual Live Market instant-trades never had
# this fee and don't set these).
FEE_WALLET    = os.getenv('FEE_WALLET', '')
FEE_RATE_TXN  = float(os.getenv('FEE_RATE_TXN', '0') or 0)
TOKEN_PROGRAM       = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
ASSOC_TOKEN_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'
SYSTEM_PROGRAM      = '11111111111111111111111111111111'
# Deliberately NOT proxied through JUPITER_PROXY_URL (unlike JUPITER_QUOTE/
# JUPITER_SWAP above) -- there's no evidence the optional proxy has a route
# for this endpoint, and this path already has a full fallback to the normal
# (proxied) swap on any failure, so a wrong/missing proxy route here just
# means that one trade's fee doesn't get bundled, never a broken trade.
JUPITER_SWAP_INSTRUCTIONS = 'https://api.jup.ag/swap/v1/swap-instructions'

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
    """Try each RPC endpoint in order; return first success or raise. This is
    now the ONLY way this file talks to a Solana RPC (every getBalance/
    getAccountInfo/getLatestBlockhash/getTokenAccountsByOwner/getTokenSupply
    call below routes through here) -- previously only sendTransaction used
    this failover and everything else hit the single hardcoded SOLANA_RPC
    with no fallback, so a blip on the public mainnet-beta endpoint could
    fail an otherwise-healthy trade for no on-chain reason at all."""
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


# Solana's recent-blockhash validity window is ~150 blocks (~60-90s under
# normal conditions, longer under congestion). This MUST be at least that
# long: it's not just a "how long do we wait to feel good about it" number --
# it's the safety margin that makes a post-timeout retry safe. If we gave up
# and retried before the original transaction's blockhash could possibly have
# expired, the original could still land on-chain AFTER our retry's fresh
# transaction also lands, executing the same buy or sell twice. Waiting out
# the full window first guarantees that by the time we ever consider a retry,
# the original is either already confirmed (and reconciliation below will see
# it) or permanently dead (blockhash expired, can never confirm) -- there is
# no ambiguous middle state left for a second transaction to collide with.
CONFIRM_TIMEOUT_S = 90.0
CONFIRM_POLL_INTERVAL_S = 1.5


def _confirm_transaction(sig: str, timeout_s: float = CONFIRM_TIMEOUT_S) -> dict:
    """Poll getSignatureStatuses until the transaction is confirmed, fails
    on-chain, or the blockhash-validity window (see CONFIRM_TIMEOUT_S above)
    elapses with no answer. A signature coming back from sendTransaction only
    means an RPC node accepted and broadcast it -- it does NOT mean it landed.
    Returns {'confirmed': bool, 'err': str|None, 'status': str,
    'confirmation_time_s': float}. 'status' is one of: 'finalized',
    'confirmed', 'failed' (landed but reverted on-chain), or 'timeout'
    (genuinely unknown -- caller MUST fall back to balance reconciliation,
    never treat this as success on its own)."""
    start = time.time()
    while time.time() - start < timeout_s:
        try:
            r = _rpc_post({
                'jsonrpc': '2.0', 'id': 1, 'method': 'getSignatureStatuses',
                'params': [[sig], {'searchTransactionHistory': True}],
            }, timeout=10)
            statuses = (r.get('result') or {}).get('value') or [None]
            status = statuses[0]
            if status:
                if status.get('err'):
                    return {'confirmed': False, 'err': str(status['err']),
                            'status': 'failed', 'confirmation_time_s': round(time.time() - start, 2)}
                conf = status.get('confirmationStatus')
                if conf in ('confirmed', 'finalized'):
                    return {'confirmed': True, 'err': None,
                            'status': conf, 'confirmation_time_s': round(time.time() - start, 2)}
        except Exception as e:
            print(f'[confirm] status poll error for {sig[:12]}...: {e}', flush=True)
        time.sleep(CONFIRM_POLL_INTERVAL_S)
    return {'confirmed': False, 'err': 'confirmation timeout (blockhash validity window elapsed)',
            'status': 'timeout', 'confirmation_time_s': round(time.time() - start, 2)}


def _log_exec_meta(meta: dict) -> None:
    """Single structured line summarizing exactly one swap attempt --
    quote/tx latency, price impact, requested slippage, confirmation time,
    actual result, and failure reason when there is one. Printed on EVERY
    exit path of _execute_swap_inner() (success or any failure), so Railway
    logs always carry a grep-able 'EXEC_META:' line per attempt regardless
    of where it failed. dashboard.py can also parse this line (it's the last
    thing printed before a raise/return) if it ever needs these figures
    beyond what BUY/SELL's own summary line already carries."""
    try:
        print('EXEC_META:' + json.dumps(meta, default=str), flush=True)
    except Exception:
        pass


def get_token_decimals(mint: str) -> int:
    """Fetch actual on-chain decimals via getTokenSupply; default 6 on error."""
    try:
        r = _rpc_post({
            'jsonrpc': '2.0', 'id': 1,
            'method': 'getTokenSupply',
            'params': [mint],
        }, timeout=8)
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
    info = _rpc_post({
        'jsonrpc': '2.0', 'id': 1, 'method': 'getAccountInfo',
        'params': [ata, {'encoding': 'base64'}],
    }, timeout=10)
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
    bh = _rpc_post({
        'jsonrpc': '2.0', 'id': 1, 'method': 'getLatestBlockhash', 'params': [],
    }, timeout=10)['result']['value']['blockhash']
    tx = Transaction.new_signed_with_payer([ix], payer_pk, [payer_keypair], SolHash.from_string(bh))
    res = _rpc_post({
        'jsonrpc': '2.0', 'id': 1, 'method': 'sendTransaction',
        'params': [base64.b64encode(bytes(tx)).decode(), {'encoding': 'base64', 'skipPreflight': False}],
    }, timeout=30)
    if 'error' in res:
        raise Exception('fee ATA creation failed: ' + str(res['error']))
    _ata_sig = res.get('result', '?')
    print(f'[fee] fee token account tx sent  TX:{_ata_sig[:20]}... — confirming', flush=True)
    _ata_conf = _confirm_transaction(_ata_sig, timeout_s=CONFIRM_TIMEOUT_S)
    if not _ata_conf['confirmed']:
        raise Exception(f'fee ATA creation did not confirm ({_ata_conf["status"]}): {_ata_conf["err"]}')
    print(f'[fee] fee token account created and confirmed ({_ata_conf["status"]}, '
          f'{_ata_conf["confirmation_time_s"]}s)', flush=True)
    return ata


def _deser_ix(ix_json):
    """One Jupiter /swap-instructions JSON instruction -> a solders
    Instruction. Jupiter's instructions come as {programId, accounts:
    [{pubkey, isSigner, isWritable}], data (base64)} -- the same shape
    web3.js's own `TransactionInstruction` uses, just JSON instead of a
    class."""
    from solders.pubkey import Pubkey
    from solders.instruction import Instruction, AccountMeta
    program_id = Pubkey.from_string(ix_json['programId'])
    accounts = [
        AccountMeta(Pubkey.from_string(a['pubkey']), bool(a.get('isSigner')), bool(a.get('isWritable')))
        for a in (ix_json.get('accounts') or [])
    ]
    data = base64.b64decode(ix_json['data']) if ix_json.get('data') else b''
    return Instruction(program_id, data, accounts)


def _resolve_alts(addresses):
    """Fetch the on-chain data for each address-lookup-table address Jupiter's
    swap-instructions response references, and decode it into the
    AddressLookupTableAccount objects MessageV0.try_compile() needs to
    resolve the swap instruction's compressed account references.

    An ALT account's on-chain layout is a fixed 56-byte header (discriminator
    + deactivation_slot + last_extended_slot + last_extended_slot_start_index
    + Option<authority> + padding -- unchanged since lookup tables shipped,
    same LOOKUP_TABLE_META_SIZE constant @solana/web3.js's own
    AddressLookupTableAccount.deserialize() uses) followed by a flat array of
    32-byte addresses."""
    from solders.pubkey import Pubkey
    from solders.address_lookup_table_account import AddressLookupTableAccount
    ALT_HEADER_SIZE = 56
    out = []
    for addr in addresses:
        r = _rpc_post({
            'jsonrpc': '2.0', 'id': 1, 'method': 'getAccountInfo',
            'params': [addr, {'encoding': 'base64'}],
        }, timeout=10)
        val = (r.get('result') or {}).get('value')
        if not val or not val.get('data'):
            raise Exception(f'lookup table account not found: {addr[:8]}...')
        raw = base64.b64decode(val['data'][0])
        body = raw[ALT_HEADER_SIZE:]
        body = body[:len(body) - (len(body) % 32)]  # drop any trailing partial entry
        addr_list = [Pubkey(body[i:i + 32]) for i in range(0, len(body), 32)]
        out.append(AddressLookupTableAccount(key=Pubkey.from_string(addr), addresses=addr_list))
    return out


def _execute_buy_with_bundled_fee(mint: str, spend_lamports: int, fee_lamports: int,
                                   wallet_address: str, private_key: str, fee_wallet: str) -> tuple:
    """Buy `mint` with (spend_lamports - fee_lamports) SOL, with the
    fee_lamports transfer to fee_wallet spliced into the SAME transaction as
    the swap -- so the wallet still spends exactly spend_lamports total, but
    there's no second, separately-visible transfer afterward.

    Jupiter's own platformFeeBps/feeAccount (used for the sell leg) takes its
    cut from the swap's OUTPUT, which for a buy is the token being purchased,
    not SOL -- not what we want here. Instead this fetches the swap as raw,
    uncompiled instructions (/swap-instructions, not /swap) via a Jupiter
    quote for the REDUCED amount, adds one plain SystemProgram transfer
    instruction for fee_lamports, and compiles everything into one
    MessageV0/VersionedTransaction ourselves. Returns (signature, out_amount)
    like _execute_swap_inner(), and raises on any problem -- callers must
    catch and fall back to a normal (unbundled) swap for spend_lamports."""
    from solders.pubkey import Pubkey
    from solders.instruction import Instruction, AccountMeta
    from solders.message import MessageV0
    from solders.transaction import VersionedTransaction as _VTx
    from solders.hash import Hash as SolHash

    net_lamports = spend_lamports - fee_lamports
    if net_lamports <= 0:
        raise Exception('nothing left to swap after fee')

    keypair = Keypair.from_base58_string(private_key)
    payer   = keypair.pubkey()
    meta    = {
        'direction': 'BUY', 'mint': mint, 'amount_lamports': net_lamports,
        'requested_slippage_bps': 300, 'quote_latency_ms': None, 'price_impact_pct': None,
        'send_latency_ms': None, 'confirmation_time_s': None, 'confirmation_status': None,
        'reconciled': None, 'result': 'FAILED', 'failure_reason': None, 'signature': None,
        'bundled_fee': True,
    }
    try:
        _, baseline_raw = get_token_balance_raw(mint)
    except Exception:
        baseline_raw = 0

    print(f'[fee] buy: requesting quote for {net_lamports} lamports '
          f'({fee_lamports} lamports fee bundled into this tx)', flush=True)
    _quote_t0 = time.time()
    r = requests.get(
        JUPITER_QUOTE,
        params={'inputMint': SOL_MINT, 'outputMint': mint, 'amount': net_lamports, 'slippageBps': 300},
        headers=_JUP_HEADERS, timeout=15,
    )
    if r.status_code != 200:
        meta['failure_reason'] = f'quote HTTP {r.status_code}'
        _log_exec_meta(meta)
        raise Exception(f'quote HTTP {r.status_code}: {r.text[:200]}')
    quote = r.json()
    if 'error' in quote or 'outAmount' not in quote:
        meta['failure_reason'] = f'quote error: {quote.get("error", quote)}'
        _log_exec_meta(meta)
        raise Exception(f'quote error: {quote.get("error", quote)}')
    meta['quote_latency_ms'] = round((time.time() - _quote_t0) * 1000, 1)
    try:
        meta['price_impact_pct'] = float(quote.get('priceImpactPct', 0) or 0)
    except (TypeError, ValueError):
        pass
    out_amount = quote.get('outAmount', '0')

    r2 = requests.post(
        JUPITER_SWAP_INSTRUCTIONS,
        json={'quoteResponse': quote, 'userPublicKey': str(payer),
              'wrapAndUnwrapSol': True, 'dynamicComputeUnitLimit': True,
              'prioritizationFeeLamports': 'auto'},
        headers=_JUP_HEADERS, timeout=20,
    )
    if r2.status_code != 200:
        meta['failure_reason'] = f'swap-instructions HTTP {r2.status_code}'
        _log_exec_meta(meta)
        raise Exception(f'swap-instructions HTTP {r2.status_code}: {r2.text[:200]}')
    swi = r2.json()
    if 'error' in swi:
        meta['failure_reason'] = f'swap-instructions error: {swi["error"]}'
        _log_exec_meta(meta)
        raise Exception(f'swap-instructions error: {swi["error"]}')

    instructions = []
    for key in ('computeBudgetInstructions', 'setupInstructions'):
        for ix in (swi.get(key) or []):
            instructions.append(_deser_ix(ix))
    if swi.get('swapInstruction'):
        instructions.append(_deser_ix(swi['swapInstruction']))
    if swi.get('cleanupInstruction'):
        instructions.append(_deser_ix(swi['cleanupInstruction']))
    if not instructions:
        raise Exception('swap-instructions returned no instructions')

    # Our fee transfer -- plain System Program transfer, appended after the
    # swap itself so it doesn't interfere with the swap's own account setup.
    instructions.append(Instruction(
        program_id=Pubkey.from_string(SYSTEM_PROGRAM),
        accounts=[
            AccountMeta(payer, is_signer=True, is_writable=True),
            AccountMeta(Pubkey.from_string(fee_wallet), is_signer=False, is_writable=True),
        ],
        data=struct.pack('<IQ', 2, fee_lamports),
    ))

    alt_accounts = _resolve_alts(swi.get('addressLookupTableAddresses') or [])

    bh = _rpc_post({
        'jsonrpc': '2.0', 'id': 1, 'method': 'getLatestBlockhash', 'params': [],
    }, timeout=10)['result']['value']['blockhash']

    message   = MessageV0.try_compile(payer, instructions, alt_accounts, SolHash.from_string(bh))
    signed_tx = _VTx(message, [keypair])
    encoded   = base64.b64encode(bytes(signed_tx)).decode()

    _send_t0 = time.time()
    rpc_resp = _rpc_post({
        'jsonrpc': '2.0', 'id': 1, 'method': 'sendTransaction',
        'params': [encoded, {'encoding': 'base64', 'skipPreflight': False, 'maxRetries': 3}],
    }, timeout=30)
    meta['send_latency_ms'] = round((time.time() - _send_t0) * 1000, 1)
    if 'error' in rpc_resp:
        meta['failure_reason'] = f'sendTransaction error: {_clean_rpc_error(rpc_resp["error"])}'
        _log_exec_meta(meta)
        raise Exception(f'sendTransaction error: {_clean_rpc_error(rpc_resp["error"])}')
    sig = rpc_resp.get('result')
    if not sig:
        meta['failure_reason'] = 'no signature in sendTransaction response'
        _log_exec_meta(meta)
        raise Exception(f'no signature in RPC response: {rpc_resp}')
    meta['signature'] = sig
    print(f'[fee] buy with bundled fee submitted, confirming: https://solscan.io/tx/{sig}', flush=True)

    # Same confirm-then-reconcile discipline as _execute_swap_inner() -- a
    # signature is not success on its own here either.
    conf = _confirm_transaction(sig)
    meta['confirmation_time_s'] = conf['confirmation_time_s']
    meta['confirmation_status'] = conf['status']
    if conf['status'] == 'failed':
        meta['failure_reason'] = f'on-chain failure: {conf["err"]}'
        _log_exec_meta(meta)
        raise Exception(f'Bundled-fee buy failed on-chain: {conf["err"]}')

    post_raw, changed = _reconciled_token_balance(mint, 'increase', baseline_raw)
    meta['reconciled'] = changed
    if not changed:
        meta['failure_reason'] = f'balance did not increase (confirmation={conf["status"]})'
        _log_exec_meta(meta)
        raise Exception(f'Bundled-fee buy balance reconciliation failed '
                         f'({mint[:8]}... baseline={baseline_raw} now={post_raw})')

    actual_delta = abs(post_raw - baseline_raw)
    meta['result'] = 'SUCCESS'
    _log_exec_meta(meta)
    print(f'[fee] buy with bundled fee SUCCESS (confirmation={conf["status"]}, '
          f'confirm_time={conf["confirmation_time_s"]}s): https://solscan.io/tx/{sig}  '
          f'actual_delta={actual_delta} (quoted outAmount={out_amount})', flush=True)
    return sig, str(actual_delta)


# ── SWAP EXECUTION ──────────────────────────────────────────────────────────

def _get_sol_balance_raw(owner: str) -> int:
    """Raw lamports (not the UI-divided float get_balance() returns) for
    `owner` -- used only to report the actual SOL a SELL received (see
    _execute_swap_inner()'s Step 8), where a UI-float divide/remultiply
    round-trip would lose precision get_token_balance_raw() already avoids
    on the token side. Returns 0 on any failure -- callers must treat that
    as 'unmeasurable', not 'zero received'."""
    try:
        r = _rpc_post({'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [owner]}, timeout=10)
        return int(r['result']['value'])
    except Exception:
        return 0


def _reconciled_token_balance(mint: str, expect_change: str, baseline_raw: int,
                               attempts: int = 4, delay_s: float = 1.5) -> tuple:
    """Poll get_token_balance_raw(mint) until it reflects a change from
    baseline_raw in the expected direction ('increase' or 'decrease'), or
    give up after `attempts` reads. RPC reads can lag a couple seconds behind
    a just-confirmed transaction even on the node that confirmed it (and a
    failover read may hit a different, further-behind node entirely) -- a
    single immediate read risks a false "balance didn't change" verdict on a
    swap that actually succeeded. Returns (raw_balance, changed_as_expected)."""
    raw = baseline_raw
    for _i in range(attempts):
        _ui, raw = get_token_balance_raw(mint)
        if expect_change == 'increase' and raw > baseline_raw:
            return raw, True
        if expect_change == 'decrease' and raw < baseline_raw:
            return raw, True
        if _i < attempts - 1:
            time.sleep(delay_s)
    return raw, False


def _execute_swap_inner(input_mint: str, output_mint: str, amount_lamports: int,
                 wallet_address: str = '', private_key: str = '',
                 fee_wallet: str = '', fee_bps: int = 0) -> tuple:
    """Execute a Jupiter v6 swap: quote -> validate -> build -> sign -> send
    -> CONFIRM -> RECONCILE on-chain balance -> only then return success.
    Returns (signature, out_amount_raw) where out_amount_raw is the actual
    measured on-chain balance delta of the output asset (not just Jupiter's
    pre-execution quote) as a string of raw base units. Raises on ANY
    failure, including "sent but never confirmed" and "confirmed but the
    balance didn't move as expected" -- a signature coming back from
    sendTransaction is never, on its own, treated as a successful trade.
    Logs every step (including a final EXEC_META line -- see its own
    comment) so failures and timings are visible in Railway logs.
    Called through execute_swap() below, which adds a fee-specific safety net
    on top of this -- call that one, not this one, from outside this file."""
    wallet_address = wallet_address or WALLET_ADDRESS
    private_key    = private_key    or PRIVATE_KEY
    if not wallet_address or not private_key:
        raise ValueError('WALLET_ADDRESS and WALLET_PRIVATE_KEY must be set')

    # Generic across every base currency this file supports (SOL, USDC, any
    # future addition to _BASE_MINTS) -- whichever side is the base currency
    # tells you the direction, regardless of which one it is. (Previously
    # this only recognized USDC-as-input as a BUY, which meant a real
    # SOL-input buy fell into the 'else' branch and got mislabeled 'SELL'
    # whenever it reached this function -- harmless while direction was only
    # used for logging/EXEC_META, but Step 7/8's reconcile-and-report logic
    # below also branches on it, so a mislabeled swap silently reconciled and
    # reported the wrong side.)
    direction = 'BUY' if input_mint in _BASE_MINTS else 'SELL'
    label     = output_mint[:8] if direction == 'BUY' else input_mint[:8]
    t0        = time.time()
    meta      = {  # accumulated for the final EXEC_META log line -- see bottom
        'direction': direction, 'mint': (output_mint if direction == 'BUY' else input_mint),
        'amount_lamports': amount_lamports, 'requested_slippage_bps': 300,
        'quote_latency_ms': None, 'price_impact_pct': None, 'send_latency_ms': None,
        'confirmation_time_s': None, 'confirmation_status': None, 'reconciled': None,
        'result': 'FAILED', 'failure_reason': None, 'signature': None,
    }

    # Keypair created here so pubkey is derived from the actual signing key
    # and can be passed to the swap body before signing in Step 4.
    try:
        keypair = Keypair.from_base58_string(private_key)
        pubkey  = str(keypair.pubkey())
    except Exception:
        # Do NOT log traceback here — solders may embed the raw key in its error message.
        print('[TRADE] FAIL — invalid private key (exception details withheld for security)', flush=True)
        meta['failure_reason'] = 'invalid private key'
        _log_exec_meta(meta)
        raise

    # Baseline for the SUCCESS/FAILURE reconciliation check (Step 7 below).
    # BUY: reconcile the token we're receiving (clean, unambiguous signal).
    # SELL: reconcile the token we're GIVING UP decreasing, not the SOL we
    # receive -- SOL balance always drops a little on every transaction
    # regardless of outcome (network/priority fees), so it's a poor pass/
    # fail signal, but the token side is exact. The actual SOL received is
    # still measured and returned below (Step 8), just not used to decide
    # success. Reading this is best-effort: a lookup failure here just means
    # reconciliation later can't run (treated as its own failure there, not
    # swallowed silently).
    _recon_mint = output_mint if direction == 'BUY' else input_mint
    _recon_dir  = 'increase'  if direction == 'BUY' else 'decrease'
    try:
        _, baseline_raw = get_token_balance_raw(_recon_mint)
    except Exception:
        baseline_raw = 0
    # SELL only: baseline of the OUTPUT asset (whichever base currency this
    # swap converts into -- SOL or USDC) for reporting the actual amount
    # received in Step 8. Not used for the confirm/reconcile decision above
    # (that always reconciles the INPUT, the token being sold, decreasing).
    # Native SOL isn't an SPL token account, so it needs the separate
    # lamport-balance RPC call; any other output mint (USDC included) reuses
    # the same get_token_balance_raw() the BUY side already relies on.
    output_is_native_sol = (output_mint == SOL_MINT)
    out_baseline = None
    if direction == 'SELL':
        try:
            if output_is_native_sol:
                out_baseline = _get_sol_balance_raw(pubkey)
            else:
                _, out_baseline = get_token_balance_raw(output_mint)
        except Exception:
            out_baseline = None

    # Fold the platform fee into this swap's own transaction (Jupiter's
    # platformFeeBps/feeAccount) instead of a separate, later, visible SOL
    # transfer -- best-effort: any failure here just proceeds without the fee
    # rather than blocking the trade, since a missed fee is a far smaller
    # problem than a real user's sell failing outright.
    fee_account = ''
    if fee_wallet and fee_bps > 0 and direction == 'SELL':
        # Only ever correct for a SELL, where the output is a base currency
        # (SOL or USDC) -- Jupiter's platformFeeBps/feeAccount takes its cut
        # from the swap's OUTPUT, so for a BUY that output is the memecoin
        # being purchased, not a currency the fee should be taken in. A
        # SOL-input buy never reaches this branch anyway (execute_swap()
        # below routes it to _execute_buy_with_bundled_fee() instead); this
        # guard is what makes a USDC-input buy correctly skip platform-fee
        # collection here too, rather than incorrectly taxing the token.
        try:
            fee_account = _ensure_fee_ata(keypair, fee_wallet, output_mint)
        except Exception as e:
            print(f'[fee] could not prepare platform-fee account, swap proceeds without it: {e}', flush=True)

    # ── Step 1: Jupiter quote ────────────────────────────────────────────────
    print(f'[TRADE] Step 1/8 — Requesting {direction} quote for {label} ({amount_lamports} lamports)'
          + (f'  (+{fee_bps}bps platform fee)' if fee_account else ''), flush=True)
    _quote_t0 = time.time()
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
                meta['failure_reason'] = 'quote failed after retries'
                _log_exec_meta(meta)
                raise
            time.sleep(2 ** _attempt)
    else:
        meta['failure_reason'] = 'quote failed after retries'
        _log_exec_meta(meta)
        raise Exception('Jupiter quote failed after 3 attempts')
    meta['quote_latency_ms'] = round((time.time() - _quote_t0) * 1000, 1)

    # ── Step 2: Validate quote freshness + shape ────────────────────────────
    out_amount = quote.get('outAmount', '?')
    impact_raw = quote.get('priceImpactPct', 0)
    try:
        impact = float(impact_raw or 0)
    except (TypeError, ValueError):
        impact = None
    meta['price_impact_pct'] = impact
    print(f'[TRADE] Step 2/8 — Quote OK: outAmount={out_amount}  priceImpact={impact_raw}  '
          f'quote_latency={meta["quote_latency_ms"]}ms', flush=True)
    if 'error' in quote:
        print(f'[TRADE] Jupiter quote error: {quote["error"]}', flush=True)
        meta['failure_reason'] = f'quote error: {quote["error"]}'
        _log_exec_meta(meta)
        raise Exception(f'Jupiter quote error: {quote["error"]}')
    if 'outAmount' not in quote or int(quote.get('outAmount', 0) or 0) <= 0:
        meta['failure_reason'] = 'quote returned no usable route'
        _log_exec_meta(meta)
        raise Exception(f'Unexpected quote response: {str(quote)[:300]}')
    # A quote used more than ~10s after being fetched is stale enough that
    # on-chain prices may have moved meaningfully since -- everything from
    # here to Step 5 (send) should be fast local work (no further network
    # round-trips except the immediately-following /swap build), so this is
    # a freshness floor, not a real-world bottleneck.
    _quote_age_s = time.time() - _quote_t0
    if _quote_age_s > 10.0:
        meta['failure_reason'] = f'quote stale ({round(_quote_age_s,1)}s old)'
        _log_exec_meta(meta)
        raise Exception(f'Quote too stale to execute safely ({round(_quote_age_s,1)}s old)')

    # ── Step 3: Get swap transaction ─────────────────────────────────────────
    print('[TRADE] Step 3/8 — Getting swap transaction from Jupiter', flush=True)
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
                meta['failure_reason'] = 'swap build failed after retries'
                _log_exec_meta(meta)
                raise
            time.sleep(2 ** _attempt)
    else:
        meta['failure_reason'] = 'swap build failed after retries'
        _log_exec_meta(meta)
        raise Exception('Jupiter swap failed after 3 attempts')

    swap_tx_b64 = swap_resp.get('swapTransaction')
    print(f'[TRADE] Step 4/8 — Signing transaction (tx present={bool(swap_tx_b64)})', flush=True)
    if 'error' in swap_resp:
        print(f'[TRADE] Jupiter swap error: {swap_resp["error"]}', flush=True)
        meta['failure_reason'] = f'swap build error: {_clean_rpc_error(swap_resp["error"])}'
        _log_exec_meta(meta)
        raise Exception(f'Jupiter swap error: {_clean_rpc_error(swap_resp["error"])}')
    if not swap_tx_b64:
        meta['failure_reason'] = 'no swapTransaction in response'
        _log_exec_meta(meta)
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
        meta['failure_reason'] = 'signing failed'
        _log_exec_meta(meta)
        raise

    # ── Step 5: Send to RPC (with multi-RPC failover) ───────────────────────
    print('[TRADE] Step 5/8 — Sending transaction to Solana RPC', flush=True)
    _send_t0 = time.time()
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
        meta['failure_reason'] = 'sendTransaction request failed'
        _log_exec_meta(meta)
        raise
    meta['send_latency_ms'] = round((time.time() - _send_t0) * 1000, 1)

    print(f'[TRADE] Step 5 — RPC response: {rpc_resp}  (send_latency={meta["send_latency_ms"]}ms)', flush=True)
    if 'error' in rpc_resp:
        print(f'[TRADE] RPC ERROR: {rpc_resp["error"]}', flush=True)
        meta['failure_reason'] = f'sendTransaction error: {_clean_rpc_error(rpc_resp["error"])}'
        _log_exec_meta(meta)
        raise Exception(f'RPC sendTransaction error: {_clean_rpc_error(rpc_resp["error"])}')
    sig = rpc_resp.get('result')
    if not sig:
        meta['failure_reason'] = 'no signature in sendTransaction response'
        _log_exec_meta(meta)
        raise Exception(f'No signature in RPC response: {rpc_resp}')
    meta['signature'] = sig
    print(f'[TRADE] Step 5 — submitted, NOT yet confirmed: https://solscan.io/tx/{sig}', flush=True)

    # ── Step 6: Confirm on-chain ─────────────────────────────────────────────
    # A signature only proves an RPC node accepted and broadcast the
    # transaction -- it does NOT prove it landed. Everything below this line
    # is what actually decides success or failure; nothing above it does.
    print(f'[TRADE] Step 6/8 — Confirming transaction (up to {CONFIRM_TIMEOUT_S:.0f}s)...', flush=True)
    conf = _confirm_transaction(sig)
    meta['confirmation_time_s'] = conf['confirmation_time_s']
    meta['confirmation_status'] = conf['status']
    if conf['status'] == 'failed':
        # Landed on-chain but reverted (e.g. slippage tolerance exceeded) --
        # unambiguous failure. Only the network fee was spent; no swap
        # happened, so there is nothing to reconcile and no reason a caller
        # shouldn't retry with a fresh quote.
        print(f'[TRADE] Step 6 — transaction FAILED on-chain: {conf["err"]}', flush=True)
        meta['failure_reason'] = f'on-chain failure: {conf["err"]}'
        _log_exec_meta(meta)
        raise Exception(f'Transaction failed on-chain: {conf["err"]}')

    # ── Step 7/8: Reconcile the resulting balance ───────────────────────────
    # Required in BOTH the confirmed and the timeout ('status' == 'timeout',
    # genuinely unknown) cases: confirmation alone is not treated as proof
    # either -- the balance delta is the actual ground truth this function
    # reports success or failure on. A 'timeout' with a balance that DID move
    # as expected is treated as success (the transaction evidently landed,
    # we just couldn't observe status in time); a 'timeout' with no balance
    # movement is a genuine, safe-to-retry failure -- CONFIRM_TIMEOUT_S is
    # long enough that the original's blockhash is now guaranteed dead.
    print(f'[TRADE] Step 7/8 — Reconciling {_recon_mint[:8]}... balance '
          f'(expect {_recon_dir}, baseline_raw={baseline_raw})', flush=True)
    post_raw, changed = _reconciled_token_balance(_recon_mint, _recon_dir, baseline_raw)
    meta['reconciled'] = changed
    if not changed:
        _status_note = 'confirmed but' if conf['confirmed'] else 'never confirmed and'
        print(f'[TRADE] Step 7 — balance did NOT {_recon_dir} as expected '
              f'(baseline={baseline_raw}, now={post_raw}) — transaction {_status_note} did not deliver funds', flush=True)
        meta['failure_reason'] = f'balance did not {_recon_dir} (confirmation={conf["status"]})'
        _log_exec_meta(meta)
        raise Exception(f'Swap {_status_note} balance reconciliation failed '
                         f'({_recon_mint[:8]}... baseline={baseline_raw} now={post_raw})')

    # ── Step 8/8: Report the actual amount ──────────────────────────────────
    # BUY: the token delta just reconciled above IS the amount received --
    # report it directly. SELL: the reconciled side was the token decrease
    # (used only to confirm the swap happened); the amount to report is SOL
    # received, measured separately since SOL balance wasn't the confirm
    # signal. Falls back to Jupiter's pre-execution quote only if the SOL-side
    # read itself is unusable (e.g. RPC failure) -- a real sell nets far more
    # than network/priority fees, so a implausibly small or negative reading
    # means the read raced ahead of/behind reality, not that nothing was
    # received.
    if direction == 'BUY':
        actual_delta = abs(post_raw - baseline_raw)
    else:
        actual_delta = None
        if out_baseline is not None:
            try:
                if output_is_native_sol:
                    out_now   = _get_sol_balance_raw(pubkey)
                    out_delta = out_now - out_baseline
                    if out_delta > 1000:  # lamports -- floor well above any plausible fee-only noise (network/priority fees are always paid in SOL, even for a non-SOL output)
                        actual_delta = out_delta
                else:
                    _, out_now = get_token_balance_raw(output_mint)
                    out_delta  = out_now - out_baseline
                    if out_delta > 0:  # an SPL token balance (unlike native SOL) never drops from fees, so any positive delta is real
                        actual_delta = out_delta
            except Exception:
                pass
        if actual_delta is None:
            try:
                actual_delta = int(out_amount)
            except (TypeError, ValueError):
                actual_delta = 0
            print(f'[TRADE] Step 8 — could not measure actual amount received; '
                  f'reporting Jupiter\'s pre-execution quote instead ({actual_delta})', flush=True)

    print(f'[TRADE] Step 8/8 — SUCCESS (confirmation={conf["status"]}, '
          f'confirm_time={conf["confirmation_time_s"]}s): https://solscan.io/tx/{sig}  '
          f'reported_amount={actual_delta} (quoted outAmount={out_amount})', flush=True)
    meta['result'] = 'SUCCESS'
    _log_exec_meta(meta)
    return sig, str(actual_delta)


def execute_swap(input_mint: str, output_mint: str, amount_lamports: int,
                  wallet_address: str = '', private_key: str = '',
                  fee_wallet: str = '', fee_bps: int = 0) -> tuple:
    """Public entry point for a swap -- see _execute_swap_inner() for the real
    sell-side step-by-step logic, and _execute_buy_with_bundled_fee() for the
    buy-side one. Either way this adds one safety net on top: if a platform
    fee was requested and ANYTHING about the swap fails (quote rejection, a
    bad/missing fee account, on-chain simulation, whatever), retry the exact
    same swap once with no fee attached at all, rather than letting a
    fee-related problem fail a real user's trade."""
    if fee_wallet and fee_bps > 0 and input_mint == SOL_MINT:
        # Buy (SOL -> token): fee is spliced into the swap's own transaction
        # as a plain SOL transfer -- see _execute_buy_with_bundled_fee()'s
        # docstring for why this can't use Jupiter's platformFeeBps like the
        # sell leg does.
        wallet_address = wallet_address or WALLET_ADDRESS
        private_key    = private_key    or PRIVATE_KEY
        fee_lamports   = int(amount_lamports * fee_bps / 10000)
        try:
            return _execute_buy_with_bundled_fee(output_mint, amount_lamports, fee_lamports,
                                                  wallet_address, private_key, fee_wallet)
        except Exception as e:
            print(f'[fee] bundled buy fee failed ({e}) — retrying as a normal buy, no fee this time', flush=True)
            return _execute_swap_inner(input_mint, output_mint, amount_lamports, wallet_address, private_key)
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

def execute_single_swap(action: str, mint: str, amount_str: str, base: str = 'SOL'):
    """Called as: python orcagent_solana.py buy|sell MINT AMOUNT [BASE]
    BASE selects which currency AMOUNT is denominated in, and which currency
    is actually spent (buy) or received (sell): 'SOL' (default -- identical
    behavior to every existing caller, which omits this argument entirely)
    or 'USDC'. Both go through the same execute_swap() engine; a USDC buy
    carries no platform fee yet (see _execute_swap_inner's fee guard) -- a
    disclosed v1 limitation, not a bug, since bundling a fee into a USDC buy
    would need a new raw SPL-token-transfer instruction this file doesn't
    build yet."""
    amount = float(amount_str)
    base_mint     = USDC_MINT if base.upper() == 'USDC' else SOL_MINT
    base_decimals = BASE_MINT_DECIMALS[base_mint]
    base_label    = 'USDC' if base_mint == USDC_MINT else 'SOL'
    try:
        if action == 'buy':
            lamports = int(amount * (10 ** base_decimals))
            sig, out_amount_raw = execute_swap(
                base_mint, mint, lamports,
                fee_wallet=FEE_WALLET, fee_bps=int(round(FEE_RATE_TXN * 10000)))
            try:
                decimals    = get_token_decimals(mint)
                got_amount  = int(out_amount_raw) / (10 ** decimals)
            except Exception:
                got_amount = 0
            print(f'BUY {mint[:16]} {round(amount,4)} {base_label} got:{round(got_amount,6)} TX:{sig}', flush=True)
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
                mint, base_mint, lamports,
                fee_wallet=FEE_WALLET, fee_bps=int(round(FEE_RATE_TXN * 10000)))
            try:
                base_received = int(out_amount_raw) / (10 ** base_decimals)
            except Exception:
                base_received = 0
            requested = 'ALL' if amount <= 0 else round(amount, 6)
            # 'sol:' key kept literal even for a USDC sell -- dashboard.py's
            # stdout parser (_parse_swap_realized_amounts) matches on that
            # exact substring; a ' base:USDC' suffix (only added when it's
            # not the default) is additive and doesn't change what the
            # parser reads, so every existing SOL-default caller's output is
            # byte-for-byte unchanged.
            base_note = '' if base_label == 'SOL' else f' base:{base_label}'
            print(f'SELL {mint[:16]} amt:{round(sell_amount,6)} sol:{round(base_received,6)} '
                  f'(requested:{requested}, on-chain:{round(actual_balance,6)}){base_note} TX:{sig}', flush=True)
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
    r = _rpc_post({
        'jsonrpc': '2.0', 'id': 1,
        'method': 'getBalance',
        'params': [owner],
    }, timeout=10)
    return r['result']['value'] / 1e9

def get_usdc_balance() -> float:
    r = _rpc_post({
        'jsonrpc': '2.0', 'id': 1,
        'method': 'getTokenAccountsByOwner',
        'params': [WALLET_ADDRESS, {'mint': USDC_MINT}, {'encoding': 'jsonParsed'}],
    }, timeout=10)
    accounts = r.get('result', {}).get('value', [])
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
        r = _rpc_post({
            'jsonrpc': '2.0', 'id': 1,
            'method': 'getTokenAccountsByOwner',
            'params': [owner, {'mint': mint}, {'encoding': 'jsonParsed'}],
        }, timeout=10)
        accounts = r.get('result', {}).get('value', [])
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
        execute_single_swap(sys.argv[1], sys.argv[2], sys.argv[3],
                             sys.argv[4] if len(sys.argv) >= 5 else 'SOL')
    else:
        run()
