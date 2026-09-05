"""Runs surge_radar's real sampling loop against a fake market, to prove the
alert wiring the unit tests only assert about actually fires end to end.

The unit tests check that notify_surge decides correctly when it is called.
This checks that it IS called -- for follow-ups on every sweep, not just on
the first detection, and for drops from the raw scanner list after a token
has already expired out of the surge list. That second one is the part no
string assertion can prove.

dashboard is replaced by a stub module before surge_radar imports it."""
import sys, time, types

REPO = '/home/user/Orc-agent-Solana-chain-'
sys.path.insert(0, REPO)

checks = []
def check(name, cond):
    checks.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name)

MARKET = []
calls = {'surge': [], 'drop': []}
TRACKED = set()

stub = types.ModuleType('dashboard')
stub._get_scanner_cached = lambda: list(MARKET)
stub.get_multichain_x_buzz = lambda: []
stub.notify_surge = lambda s: calls['surge'].append((s['mint'], s.get('price_usd')))
stub.notify_surge_drop = lambda t: calls['drop'].append((t['mint'], t.get('price_usd')))
stub.surge_alert_tracked_mints = lambda: set(TRACKED)
sys.modules['dashboard'] = stub

import surge_radar as R
R.MIN_HISTORY_SECONDS = 0          # no waiting in a test

def token(mint='M1', price=1.0, vol=20000.0, buys=150, sells=100, liq=50000.0):
    return {'mint': mint, 'symbol': 'TKN', 'name': 'Token', 'chain': 'solana',
            'price_usd': price, 'liquidity_usd': liq, 'volume_5m': vol,
            'buys_5m': buys, 'sells_5m': sells, 'market_cap': 500000.0}

def quiet(**kw):
    return token(vol=1000.0, buys=5, sells=5, **kw)

# Three quiet samples build a baseline, then a spike.
MARKET[:] = [quiet()]
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

calls['surge'].clear()
R._surges.clear()                  # what SURGE_TTL does after five quiet minutes
R._sample_once()
check('once it has expired out of the surge list it is no longer offered as one',
      calls['surge'] == [])
check('...and no drop is asked about a token nobody was alerted on', calls['drop'] == [])

# The app says it is still owed a drop notice -- the radar must keep feeding
# it prices from the raw scanner list, which is where it still appears.
TRACKED.add('M1')
MARKET[:] = [quiet(price=0.55)]
R._sample_once()
check('a token the app is still tracking keeps being fed prices AFTER it has '
      'left the surge list — which is exactly when a token gives its gains back',
      calls['drop'] == [('M1', 0.55)])

# A failing alert must never stop sampling.
calls['drop'].clear()
stub.notify_surge_drop = lambda t: (_ for _ in ()).throw(RuntimeError('push down'))
MARKET[:] = [quiet(price=0.5)]
R._sample_once()
check('a failing drop alert is swallowed rather than killing the sample cycle', True)

stub.surge_alert_tracked_mints = lambda: (_ for _ in ()).throw(RuntimeError('db down'))
R._sample_once()
check('an unreadable tracking list is swallowed too', True)

print(f'\n{sum(1 for _, c in checks if c)}/{len(checks)} checks passed')
sys.exit(0 if all(c for _, c in checks) else 1)
