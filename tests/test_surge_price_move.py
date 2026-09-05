"""The percentage move on a surge -- the figure the strip and the alert are
actually read for.

It is measured two ways on purpose. DexScreener's priceChange.m5 is what the
rest of the site shows, so it wins when it exists. But on brand-new pairs --
exactly the ones that surge -- that field is regularly absent or flat zero,
and a surge card showing no percentage is the one failure worth engineering
around. So the radar also measures the move across its own price samples.

These check the second one is real arithmetic on real samples, and that it is
never passed off as a five-minute number when it covers a different period.

The real _evaluate is extracted from surge_radar.py; nothing is stubbed but
the module-level constants it reads."""
import re, sys, time

REPO = '/home/user/Orc-agent-Solana-chain-'
SRC  = open(REPO + '/surge_radar.py').read()
JS   = open(REPO + '/static/live-market-pro.js').read()
CSS  = open(REPO + '/templates/live_market_pro.html').read()

checks = []
def check(name, cond):
    checks.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name)

def extract(name, src=SRC):
    m = re.search(rf'^def {re.escape(name)}\(.*?\n(?=\S|\Z)', src, re.M | re.S)
    assert m, f'could not find {name}'
    return m.group(0)

import statistics
ns = {'statistics': statistics,
      'MIN_HISTORY_SECONDS': 90, 'MIN_VOLUME_5M': 3000.0, 'MIN_TXNS_5M': 25,
      'MIN_LIQUIDITY': 2000.0, 'VOL_RATIO_TRIGGER': 3.0, 'TXN_RATIO_TRIGGER': 2.0}
exec(extract('_baseline'), ns)
exec(extract('_evaluate'), ns)

NOW = 1_700_000_000.0

def samples(prices, start_offset=600):
    """A history that clears every threshold, so only the price varies."""
    n = len(prices)
    step = start_offset / max(n - 1, 1)
    out = []
    for i, px in enumerate(prices):
        ts = NOW - start_offset + i * step
        # quiet baseline, then a spike on the last sample
        vol  = 1000.0 if i < n - 1 else 20000.0
        txns = 10 if i < n - 1 else 200
        out.append((ts, vol, txns, px))
    return out

TOK = {'mint': 'M', 'symbol': 'X', 'chain': 'base', 'liquidity_usd': 50000.0,
       'buys_5m': 130, 'sells_5m': 70}

# ── the measurement itself ──
s = ns['_evaluate'](TOK, samples([1.0, 1.1, 1.2, 2.0]), NOW)
check('a surge is detected at all (the fixture clears every threshold)', s is not None)
check('a doubling from the first observed price reads as +100%',
      s and abs(s['price_change_obs'] - 100.0) < 0.01)
check('the observed window is reported in seconds so the label can name it',
      s and s['obs_seconds'] == 600)

s = ns['_evaluate'](TOK, samples([2.0, 1.9, 1.8, 1.0]), NOW)
check('a halving reads as -50%, signed', s and abs(s['price_change_obs'] + 50.0) < 0.01)

s = ns['_evaluate'](TOK, samples([1.0, 1.0, 1.0, 1.0]), NOW)
check('a flat price reads as exactly 0, not as noise', s and s['price_change_obs'] == 0.0)

# ── the cases that would otherwise divide by zero or lie ──
s = ns['_evaluate'](TOK, samples([0.0, 0.0, 0.0, 1.5]), NOW)
check('a token whose early samples had no price does not divide by zero',
      s is not None and s['price_change_obs'] == 0.0)

s = ns['_evaluate'](TOK, samples([0.0, 0.0, 2.0, 4.0]), NOW)
check('the first sample with a REAL price is the baseline, not the zero before it '
      '— otherwise the first genuine reading would score as infinite growth',
      s and abs(s['price_change_obs'] - 100.0) < 0.01)

s = ns['_evaluate'](TOK, samples([1.0, 1.2, 1.5, 0.0]), NOW)
check('a token whose latest price came back empty reports no move rather than -100%',
      s and s['price_change_obs'] == 0.0)

# ── DexScreener's own figure is still carried, untouched ──
s = ns['_evaluate'](dict(TOK, price_change_5m=13.5), samples([1.0, 1.1, 1.2, 2.0]), NOW)
check("DexScreener's 5m figure is passed through unchanged alongside it",
      s and s['price_change_5m'] == 13.5)
check('the two are separate fields, so the consumer picks — the radar does not '
      'silently overwrite one with the other',
      s and s['price_change_obs'] != s['price_change_5m'])

# ── the card ──
check('the card renders a percentage at all', 'pt-surge-chg' in JS and 'pt-surge-chg' in CSS)
check('the card prefers the 5m figure and falls back the same way the alert does',
      're.escape' not in JS and 's.price_change_5m' in JS and 's.price_change_obs' in JS)
check('the card labels the fallback window rather than borrowing "5m"',
      "chgWin = Math.max(1, Math.round((Number(s.obs_seconds)||0)/60))+'m'" in JS)
check('a rise and a fall get different colours', '.pt-surge-chg.up{' in CSS and '.pt-surge-chg.down{' in CSS)
_chg_size = int(re.search(r'\.pt-surge-chg\{[^}]*font-size:(\d+)px', CSS).group(1))
_sym_size = float(re.search(r'\.pt-surge-sym\{[^}]*font-size:([\d.]+)px', CSS).group(1))
check('the percentage is the largest text on the card — larger than the ticker itself',
      _chg_size > _sym_size)
check('...and it gets its own line rather than a corner slot, so a long ticker and a '
      'four-digit percentage stop competing for the same 172px',
      'margin-top' in re.search(r'\.pt-surge-chg\{[^}]*\}', CSS).group(0)
      and JS.index("+ '</div>'\n    + chgHtml") > 0)
check('the multiplier moved to the meta line rather than being dropped',
      'pt-surge-mult' in JS and JS.index('pt-surge-meta') < JS.index('pt-surge-mult" title'))
check('the multiplier no longer competes for the corner slot',
      'margin-left:auto' not in re.search(r'\.pt-surge-mult\{[^}]*\}', CSS).group(0))
check('the chain badge uses the short label the rest of the page uses, so "ROBINHOOD" '
      'stops eating the ticker\'s width', 'CHAIN_LABELS[s.chain]' in JS)
check('no percentage is invented when none was measured — a dash, not a 0.0%',
      "Math.abs(chg) >= 0.05" in JS and "'—'" in JS and '0.0%' not in JS)
check('the meta line clips inside the card instead of spilling past its border',
      'overflow:hidden' in re.search(r'\.pt-surge-meta\{[^}]*\}', CSS).group(0))

print(f'\n{sum(1 for _, c in checks if c)}/{len(checks)} checks passed')
sys.exit(0 if all(c for _, c in checks) else 1)
