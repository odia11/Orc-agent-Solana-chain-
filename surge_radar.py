"""Watches every token the scanner already tracks and flags the ones whose
activity suddenly explodes -- the "$AMC on Robinhood Chain went from nothing
to enormous volume and a wall of buys inside a minute" case -- so the Live
Market page can pin them at the top while it is still happening.

HOW IT DETECTS, AND WHAT THAT HONESTLY MEANS
DexScreener's public API has no per-minute field: its finest bucket is a
rolling 5-minute one (volume.m5, txns.m5). So this does not read a "last
minute" number anywhere -- it SAMPLES those 5-minute buckets every
SAMPLE_INTERVAL seconds and compares the newest sample against the token's
own recent baseline. A token whose 5-minute volume jumps several times above
what it was doing minutes ago is, in practice, a token that just had a huge
minute. Detection therefore lags the real move by roughly a minute, and a
token has to be observed for MIN_HISTORY_SECONDS before it can be judged at
all -- there is no baseline to be several times above otherwise.

WHY TWO SIGNALS, NOT ONE
Volume alone is one whale buying. Transaction count alone is a bot spamming
dust. A real surge is both at once: money AND participants climbing together,
so both ratios must clear their thresholds. Absolute floors on top of that
stop a token going from $2 to $40 of volume -- a 20x ratio -- from
outranking one going from $40k to $200k.

Everything here is read-only market data. It never touches a wallet, never
places a trade, and is deliberately separate from the trading bot's own
entry logic: this ranks attention, which is not the same thing as a good
trade, and nothing here should be read as a recommendation to buy.
"""
import logging
import os
import statistics
import threading
import time
from collections import deque

import dashboard as _app

logger = logging.getLogger('surge_radar')
logger.setLevel(logging.INFO)
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(_h)
    logger.propagate = False

SAMPLE_INTERVAL      = int(os.environ.get('SURGE_SAMPLE_SECONDS', '30'))
MIN_HISTORY_SECONDS  = 90     # a token must be watched this long before it has a baseline worth comparing against
MAX_SAMPLES          = 24     # ~12 minutes of history per token at the default interval
SURGE_TTL            = 300    # how long a surge stays pinned after it stops accelerating

# Ratios -- how far above its OWN recent normal a token has to be.
VOL_RATIO_TRIGGER    = 3.0
TXN_RATIO_TRIGGER    = 2.0
# Absolute floors -- what "worth showing" means at all, so a tiny token's
# huge ratio can't outrank a real move.
MIN_VOLUME_5M        = 3000.0
MIN_TXNS_5M          = 25
MIN_LIQUIDITY        = 2000.0

_history: dict = {}        # mint -> deque[(ts, volume_5m, txns_5m, price_usd)]
_surges: dict = {}         # mint -> surge dict
_lock = threading.Lock()


def _baseline(samples, key_idx):
    """The token's own recent normal, excluding the newest sample (which is
    the candidate spike itself). Median rather than mean so one earlier spike
    in the window can't inflate the bar and mask a real one now."""
    prior = [s[key_idx] for s in list(samples)[:-1]]
    return statistics.median(prior) if prior else 0.0


def _evaluate(tok, samples, now):
    """Returns a surge dict when this token is accelerating hard enough to
    show, else None. Pure function of the samples -- no I/O, no state."""
    ts_first = samples[0][0]
    if now - ts_first < MIN_HISTORY_SECONDS or len(samples) < 3:
        return None

    _, vol_now, txns_now, price_now = samples[-1]
    if vol_now < MIN_VOLUME_5M or txns_now < MIN_TXNS_5M:
        return None
    if float(tok.get('liquidity_usd') or 0) < MIN_LIQUIDITY:
        return None

    vol_base  = _baseline(samples, 1)
    txn_base  = _baseline(samples, 2)
    # A token with a genuinely quiet baseline would divide by ~0 and score
    # infinity, so the floors double as the divisor's minimum: the ratio is
    # "how far above a meaningful baseline", never "how far above nothing".
    vol_ratio = vol_now / max(vol_base, MIN_VOLUME_5M / 3.0)
    txn_ratio = txns_now / max(txn_base, MIN_TXNS_5M / 3.0)
    if vol_ratio < VOL_RATIO_TRIGGER or txn_ratio < TXN_RATIO_TRIGGER:
        return None

    buys, sells = int(tok.get('buys_5m') or 0), int(tok.get('sells_5m') or 0)
    total = buys + sells
    return {
        'mint':          tok.get('mint'),
        'symbol':        tok.get('symbol') or '',
        'name':          tok.get('name') or '',
        'chain':         tok.get('chain') or 'solana',
        'image_url':     tok.get('image_url') or '',
        'pair_address':  tok.get('pair_address') or '',
        'price_usd':     price_now,
        'liquidity_usd': float(tok.get('liquidity_usd') or 0),
        'market_cap':    float(tok.get('market_cap') or 0),
        'volume_5m':     vol_now,
        'txns_5m':       txns_now,
        'buys_5m':       buys,
        'sells_5m':      sells,
        'buy_pct':       round(buys / total * 100, 1) if total else 0.0,
        'price_change_5m': float(tok.get('price_change_5m') or 0),
        'vol_ratio':     round(vol_ratio, 1),
        'txn_ratio':     round(txn_ratio, 1),
        'score':         round(vol_ratio * min(txn_ratio, 10.0), 2),
        'pair_created_at': tok.get('pair_created_at'),
        'twitter_url':   tok.get('twitter_url'),
    }


def _buzz_mints() -> dict:
    """Mints currently being talked about on X, across every chain the
    platform trades -- {mint: symbol}. Purely a badge: it never creates,
    ranks or blocks a surge, so the radar keeps working exactly the same
    when this is unavailable (no API key, no Anthropic credit, a bad
    response). Failing to a plain empty dict is what guarantees that."""
    try:
        return {c['mint']: c.get('symbol', '') for c in _app.get_multichain_x_buzz() if c.get('mint')}
    except Exception as e:
        logger.error('[surge-radar] X buzz unavailable, continuing without it: %s', e)
        return {}


def _sample_once():
    """One pass: read the scanner's current view of the market, append a
    sample per token, and re-evaluate. Reuses _get_scanner_cached() so this
    shares the scanner's own upstream response cache -- watching the market
    continuously costs no extra DexScreener traffic."""
    try:
        tokens = _app._get_scanner_cached()
    except Exception as e:
        logger.error('[surge-radar] could not read scanner candidates: %s', e)
        return
    now = time.time()
    fresh = []
    buzz = _buzz_mints()

    with _lock:
        seen = set()
        for tok in tokens or []:
            mint = tok.get('mint')
            if not mint:
                continue
            seen.add(mint)
            sample = (now,
                      float(tok.get('volume_5m') or 0),
                      int(tok.get('buys_5m') or 0) + int(tok.get('sells_5m') or 0),
                      float(tok.get('price_usd') or 0))
            hist = _history.setdefault(mint, deque(maxlen=MAX_SAMPLES))
            hist.append(sample)

            surge = _evaluate(tok, hist, now)
            if surge:
                surge['x_buzz'] = mint in buzz
                prev = _surges.get(mint)
                # Keep the peak of the episode, so a surge that is already
                # cooling still shows how big it actually got rather than
                # sliding down the list while it is still the story.
                if prev and prev.get('peak_score', 0) > surge['score']:
                    surge['peak_score'] = prev['peak_score']
                    surge['peak_vol_ratio'] = prev.get('peak_vol_ratio', surge['vol_ratio'])
                else:
                    surge['peak_score'] = surge['score']
                    surge['peak_vol_ratio'] = surge['vol_ratio']
                surge['first_seen'] = prev['first_seen'] if prev else now
                surge['last_seen'] = now
                _surges[mint] = surge
                if not prev:
                    fresh.append(surge)

        # Forget tokens the scanner no longer returns, and expire finished
        # surges, so neither dict grows without bound.
        for mint in [m for m in _history if m not in seen]:
            _history.pop(mint, None)
        for mint, s in list(_surges.items()):
            if now - s['last_seen'] > SURGE_TTL:
                _surges.pop(mint, None)

    for s in fresh:
        logger.info('[surge-radar] %s on %s — %sx volume, %sx transactions, $%s in 5m, %s%% buys',
                    s['symbol'], s['chain'], s['vol_ratio'], s['txn_ratio'],
                    round(s['volume_5m']), s['buy_pct'])


def current_surges(limit: int = 12) -> list:
    """The live surge list, hottest first. Safe to call from a request
    thread -- returns copies, never the live dicts."""
    with _lock:
        out = [dict(s) for s in _surges.values()]
    now = time.time()
    for s in out:
        s['age_seconds'] = int(now - s['first_seen'])
        s['cooling'] = (now - s['last_seen']) > SAMPLE_INTERVAL * 2
    out.sort(key=lambda s: (not s['cooling'], s['peak_score']), reverse=True)
    return out[:limit]


def stats() -> dict:
    with _lock:
        return {'watching': len(_history), 'active_surges': len(_surges),
                'sample_interval': SAMPLE_INTERVAL}


def surge_loop():
    """Background entry point -- never lets one bad cycle kill the loop."""
    logger.info('[surge-radar] started (sampling every %ds, needs %ds of history per token)',
                SAMPLE_INTERVAL, MIN_HISTORY_SECONDS)
    while True:
        try:
            _sample_once()
        except Exception as e:
            logger.error('[surge-radar] sample cycle failed: %s', e)
        time.sleep(SAMPLE_INTERVAL)
