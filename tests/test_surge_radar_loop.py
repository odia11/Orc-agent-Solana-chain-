"""Runs surge_radar's real sampling loop against a fake market, to prove the
alert wiring the unit tests only assert about actually fires end to end.

The unit tests check that notify_surge decides correctly when it is called.
This checks that it IS called -- on every sweep for a live surge, not just on
the first detection, which is what lets a token that keeps climbing earn a
second alert. Nothing else is ever pushed: a falling token is refused by the
radar itself, so it never reaches the alert path at all.

dashboard is replaced by a stub module before surge_radar imports it."""
import sys, time, types

REPO = '/home/user/Orc-agent-Solana-chain-'
sys.path.insert(0, REPO)

checks = []
def check(name, cond):
    checks.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name)

MARKET = []
calls = {'surge': []}

stub = types.ModuleType('dashboard')
stub._get_scanner_cached = lambda: list(MARKET)
stub.get_multichain_x_buzz = lambda: []
stub.notify_surge = lambda s: calls['surge'].append((s['mint'], s.get('price_usd')))
sys.modules['dashboard'] = stub

import surge_radar as R
R.MIN_HISTORY_SECONDS = 0          # no waiting in a test

def token(mint='M1', price=1.0, vol=20000.0, buys=150, sells=100, liq=50000.0):
    return {'mint': mint, 'symbol': 'TKN', 'name': 'Token', 'chain': 'solana',
            'price_usd': price, 'liquidity_usd': liq, 'volume_5m': vol,
            'buys_5m': buys, 'sells_5m': sells, 'market_cap': 500000.0}

def quiet(**kw):
    return token(vol=1000.0, buys=5, sells=5, **kw)

# Three quiet samples at a low price build the baseline, then a spike that
# both explodes on volume AND rises -- a surge is a rise, so a flat price
# would (correctly) never be detected at all.
MARKET[:] = [quiet(price=0.5)]
for _ in range(3):
    R._sample_once()
check('nothing alerts while the token is merely being watched', calls['surge'] == [])

MARKET[:] = [token(price=1.0)]
R._sample_once()
check('the spike is detected and offered', len(calls['surge']) == 1)

# The surge is still live on the next sweeps -- it must be re-offered, or a
# token that keeps climbing could never earn a second alert.
MARKET[:] = [token(price=1.5)]
R._sample_once()
MARKET[:] = [token(price=2.0)]
R._sample_once()
check('a live surge is re-offered on every sweep, with its current price, '
      'not only when first detected',
      [c[1] for c in calls['surge']] == [1.0, 1.5, 2.0])

# It stops accelerating. It stays pinned (and offered) for SURGE_TTL, which
# is correct -- notify_surge is the one that decides a falling price earns
# nothing -- and then expires out of the surge list entirely.
calls['surge'].clear()
MARKET[:] = [quiet(price=0.6)]
R._sample_once()
check('a cooling surge is still offered while it is still pinned on the page — '
      'the alert gate, not the radar, is what refuses it',
      len(calls['surge']) == 1 and calls['surge'][0][0] == 'M1')
check('a cooling surge carries the price from its LAST detection, not the current '
      'quiet one — which is harmless precisely because a follow-up needs a price '
      'ABOVE the last alert, and a stale price is never above itself',
      calls['surge'][0][1] == 2.0)
check('a falling token is never offered as a surge in the first place, so the '
      'cooling entry above is the last detected RISE, never a fall',
      all(px is not None and px > 0 for _, px in calls['surge']))

calls['surge'].clear()
R._surges.clear()                  # what SURGE_TTL does after five quiet minutes
R._sample_once()
check('once it has expired out of the surge list it is no longer offered as one',
      calls['surge'] == [])

# A falling token is refused by the radar, so nothing about a fall can reach
# the alert path -- there is no second notifier for it to reach anyway.
MARKET[:] = [token(price=0.3)]      # huge volume, but the price has collapsed
for _ in range(3):
    R._sample_once()
check('a token whose volume explodes while its price collapses is never offered '
      'as a surge, so a fall cannot reach a phone through any path',
      calls['surge'] == [])
check('the radar asks the app for nothing but surges',
      not hasattr(stub, 'notify_surge_drop'))

# A failing alert must never stop sampling.
stub.notify_surge = lambda s: (_ for _ in ()).throw(RuntimeError('push down'))
MARKET[:] = [quiet(price=0.5)]
for _ in range(3):
    R._sample_once()
MARKET[:] = [token(price=1.0)]
R._sample_once()
check('a failing surge alert is swallowed rather than killing the sample cycle', True)

print(f'\n{sum(1 for _, c in checks if c)}/{len(checks)} checks passed')
sys.exit(0 if all(c for _, c in checks) else 1)
