"""Periodic background safety net that keeps every user's EVM trading wallet
(BSC, Base, Arbitrum, Polygon, Robinhood Chain) topped up with native gas
(BNB/ETH/POL) -- so a wallet whose trading capital sits entirely in USDC
never gets stuck unable to broadcast a buy or sell for lack of a few cents
of gas, even between trades.

This module deliberately does NOT reimplement any swap, bridge, or key
decryption logic. dashboard.py's _ensure_evm_gas() -- already called right
before every EVM buy/sell -- is the one and only place that decides whether
a wallet needs gas and executes it:
  - a low-but-nonzero balance is topped up with a same-chain USDC -> native
    swap via the 0x API (_execute_evm_gas_topup)
  - a completely empty (0) balance is bootstrapped by bridging a small,
    fixed amount of the user's own SOL into native gas on that chain
    (_bootstrap_evm_gas_via_bridge), since a same-chain swap can't pay for
    its own broadcast from literal zero
Reusing that single function here means this sweep can never drift out of
sync with the per-trade path or apply a different threshold, and the
per-(wallet, chain) lock inside _ensure_evm_gas() itself (see dashboard.py)
keeps this background sweep and a live trade's own gas check from ever
firing two top-ups for the same wallet at once.

All this module adds is the SCHEDULE: walk every user with an EVM trading
key configured, across every chain they actually hold USDC on, on a timer --
so a dip in gas (network fee drift, an outgoing transfer, etc.) gets caught
proactively instead of only at the moment of a trade.

Deliberately skips a chain entirely when the user holds no USDC there and
has no open position on it: _ensure_evm_gas()'s zero-balance branch spends
the user's own SOL bootstrapping gas, and every chain starts at a native
balance of 0 for a wallet that's never touched it -- sweeping unconditionally
would silently spend SOL bootstrapping gas on chains the user never asked to
trade on. Gating on "do they have capital or a position there" keeps this
strictly a safety net for chains actually in use.

Never decrypts a private key just to check a balance: the EVM address is
already stored in plaintext (users.bsc_wallet_address -- see dashboard.py's
ensure_bsc_wallet()), so the balance/USDC pre-check below is two public RPC
reads with no key material touched at all. The key is only decrypted, via
dashboard's own _use_key() (same encryption scheme, same security logging,
same best-effort memory scrub), for the one wallet+chain pair this cycle
that actually needs a top-up.
"""
import logging
import os
import sqlite3
import threading
import time

import dashboard as _app

logger = logging.getLogger('gas_manager')
logger.setLevel(logging.INFO)
if not logger.handlers:
    # dashboard.py logs via plain print(..., flush=True) rather than the
    # logging module, so nothing upstream configures a root handler --
    # without this, logging.info()/error() calls here would be silently
    # dropped (root logger defaults to WARNING) instead of reaching
    # Railway's console like every other line in this app's logs.
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(_handler)
    logger.propagate = False

# How often the sweep runs. The existing pre-trade _ensure_evm_gas() call
# already covers "gas is guaranteed sufficient at the moment of a trade" --
# this timer is what additionally covers the gaps between trades. 15 minutes
# by default; override with GAS_MANAGER_INTERVAL_MINUTES if ever needed.
SWEEP_INTERVAL_SECONDS = int(os.environ.get('GAS_MANAGER_INTERVAL_MINUTES', '15')) * 60

# Below this much USDC on a chain, there's no real trading capital there to
# protect -- skip the chain rather than risk bootstrapping gas (spending the
# user's SOL) on a chain they don't actually use.
_MIN_USDC_TO_PROTECT = 1.0


def _users_with_evm_key():
    """Every (user_id, wallet_address, bsc_wallet_address, encrypted_private_key_bsc)
    row with an EVM trading key configured. One EVM key/address is shared
    across every chain in EVM_CHAINS -- see dashboard.py's own
    encrypted_private_key_bsc column comment."""
    conn = sqlite3.connect(_app.DB_FILE)
    try:
        return conn.execute(
            "SELECT id, wallet_address, bsc_wallet_address, encrypted_private_key_bsc FROM users "
            "WHERE encrypted_private_key_bsc IS NOT NULL AND encrypted_private_key_bsc != '' "
            "AND bsc_wallet_address IS NOT NULL AND bsc_wallet_address != ''"
        ).fetchall()
    finally:
        conn.close()


def _has_open_evm_position(user_id: int, chain: str) -> bool:
    conn = sqlite3.connect(_app.DB_FILE)
    try:
        row = conn.execute(
            "SELECT 1 FROM trades WHERE user_id=? AND chain=? AND (exit_price IS NULL OR exit_price=0) LIMIT 1",
            (user_id, chain)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def _needs_gas_precheck(evm_address: str, chain: str) -> bool:
    """Same threshold _ensure_evm_gas() itself checks (native balance vs. one
    worst-case tx's gas cost) -- but read-only, no private key involved, so
    every wallet that's already fine on gas costs this sweep nothing more
    than two public RPC calls."""
    w3 = _app._get_web3(chain)
    try:
        native_bal_wei = w3.eth.get_balance(w3.to_checksum_address(evm_address))
        needed_wei = w3.eth.gas_price * _app.GAS_TOPUP_TX_GAS_UNITS
    except Exception as e:
        logger.error('[gas-manager] %s RPC unreachable checking %s: %s', chain, evm_address[:10], e)
        return False
    return native_bal_wei < needed_wei


def _sweep_user_chain(user_id: int, wallet: str, evm_address: str, enc_blob: str, chain: str):
    try:
        usdc_bal = _app.get_evm_usdc_balance(evm_address, chain)
    except Exception as e:
        logger.error('[gas-manager] %s USDC balance check failed for %s...: %s', chain, wallet[:8], e)
        return
    if usdc_bal < _MIN_USDC_TO_PROTECT and not _has_open_evm_position(user_id, chain):
        return  # no capital and no open position on this chain -- nothing to protect, never bootstrap speculatively

    if not _needs_gas_precheck(evm_address, chain):
        return  # already fine -- no need to touch the private key at all

    logger.info('[gas-manager] %s wallet %s... is low on gas (USDC balance %.4f) -- rebalancing',
                chain, wallet[:8], usdc_bal)
    try:
        with _app._use_key(enc_blob, wallet) as pk:
            ok, msg, bridge_id = _app._ensure_evm_gas(user_id, wallet, pk, evm_address, chain)
    except Exception as e:
        logger.error('[gas-manager] %s rebalance for %s... raised: %s', chain, wallet[:8], e)
        return

    if ok:
        logger.info('[gas-manager] %s wallet %s... gas rebalanced successfully', chain, wallet[:8])
    elif bridge_id:
        logger.info('[gas-manager] %s wallet %s... gas bootstrap bridge in flight (row %s)', chain, wallet[:8], bridge_id)
    else:
        # _ensure_evm_gas() already surfaces genuine dead ends (e.g. "deposit
        # more SOL/USDC") to the user via add_user_log -- nothing more to do
        # here beyond the server-side record of why this cycle didn't fix it.
        logger.info('[gas-manager] %s wallet %s... not rebalanced this cycle: %s', chain, wallet[:8], msg)


def sweep_once():
    """One full pass over every user with an EVM key, across every chain in
    EVM_CHAINS. Safe to call directly (e.g. right after a trade) as well as
    from the periodic loop below -- _ensure_evm_gas()'s own per-(wallet,
    chain) lock keeps overlapping calls from ever double-topping-up."""
    users = _users_with_evm_key()
    if not users:
        return
    logger.info('[gas-manager] sweep starting -- %d user(s) with an EVM key configured', len(users))
    for user_id, wallet, evm_address, enc_blob in users:
        for chain in _app.EVM_CHAINS:
            try:
                _sweep_user_chain(user_id, wallet, evm_address, enc_blob, chain)
            except Exception as e:
                logger.error('[gas-manager] unexpected error sweeping %s for %s...: %s', chain, wallet[:8], e)
    logger.info('[gas-manager] sweep complete')


def gas_sweep_loop():
    """Background loop entry point -- start via
    threading.Thread(target=gas_manager.gas_sweep_loop, daemon=True).start()
    Never lets one bad cycle kill the loop."""
    logger.info('[gas-manager] background sweep loop started (every %d minutes)', SWEEP_INTERVAL_SECONDS // 60)
    while True:
        try:
            sweep_once()
        except Exception as e:
            logger.error('[gas-manager] sweep cycle failed: %s', e)
        time.sleep(SWEEP_INTERVAL_SECONDS)
