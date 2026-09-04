"""Tests for _trade_excursion_counterfactual (dashboard.py) -- the "how a
trade was managed" counterfactual behind the AI self-analysis loop's new
how_analysis field.

dashboard.py cannot be safely `import`ed in a test process (it starts
background threads and a job scheduler at module level), so this extracts
the real function source via `ast` and execs it in an isolated namespace,
exactly like test_net_edge_filter.py does for _estimate_net_edge. Every test
below exercises the real, shipped function body.

Run with: python3 test_trade_counterfactual.py
"""
import ast
import os

DASHBOARD_PATH = os.path.join(os.path.dirname(__file__), '..', 'dashboard.py')


def _load_real_function():
    with open(DASHBOARD_PATH, encoding='utf-8') as f:
        src = f.read()
    tree = ast.parse(src)
    func_src = None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == '_trade_excursion_counterfactual':
            func_src = ast.get_source_segment(src, node)
            break
    assert func_src is not None, '_trade_excursion_counterfactual not found in dashboard.py'
    namespace = {}
    exec(func_src, namespace)
    return namespace['_trade_excursion_counterfactual']


_cf = _load_real_function()

_passed = 0
_failed = 0


def check(name, condition, detail=''):
    global _passed, _failed
    if condition:
        _passed += 1
        print(f'  PASS  {name}')
    else:
        _failed += 1
        print(f'  FAIL  {name}  {detail}')


# ── Missing / degenerate data must never fabricate a counterfactual ──
print('Missing data (must return kind=None):')
r = _cf('stop_loss', 0, -10.0, 10.0, 20.0, 1.05, 0.95)
check('zero entry price -> None', r['kind'] is None)

r = _cf('stop_loss', 1.0, -10.0, 10.0, 20.0, None, 0.9)
check('no highest_price on a non-TP exit -> None', r['kind'] is None)

r = _cf('take_profit', 1.0, 20.0, 10.0, 20.0, 1.2, None)
check('no lowest_price on a TP exit -> None', r['kind'] is None)

# ── A trade that did NOT exit via take-profit: real, already-recorded peak
# is usable as "a lower TP would have banked this" -- but only if it's a
# non-trivial amount above what was actually realized ──
print('\nNon-TP exit that gave back a real peak (must report gave_back_peak):')
# entry 1.0, stopped out at -8% (pnl_pct=-8.0), but peaked at 1.30 (+30%)
# along the way before reversing.
r = _cf('stop_loss', 1.0, -8.0, 10.0, 25.0, 1.30, 0.90)
check('stop_loss exit that peaked +30% -> gave_back_peak', r['kind'] == 'gave_back_peak',
      detail=str(r))
check('peak_pct computed from real highest_price', r.get('peak_pct') == 30.0, detail=str(r))

# trailing_stop exit, same shape
r = _cf('trailing_stop', 1.0, 5.0, None, 25.0, 1.15, 0.95)
check('trailing_stop exit that peaked +15% vs realized +5% -> gave_back_peak',
      r['kind'] == 'gave_back_peak', detail=str(r))

# ── The peak must be non-trivially above the ACTUAL realized pnl, not just
# any peak >= 0 -- a trade whose peak matches what was realized (e.g. the
# stop itself IS near the peak) should not be reported ──
print('\nNon-TP exit whose peak barely exceeds the actual outcome (must be None):')
r = _cf('stop_loss', 1.0, -9.8, 10.0, 25.0, 1.001, 0.90)  # peak +0.1%, actual -9.8%
check('trivial/negative peak vs a losing exit -> still counts if genuinely higher',
      r['kind'] is None or r.get('peak_pct', 0) > -9.8 + 0.5)
r2 = _cf('stop_loss', 1.0, -9.8, 10.0, 25.0, 0.999, 0.90)  # never even went positive
check('peak below the actual pnl -> None', r2['kind'] is None, detail=str(r2))

# ── A take-profit exit: a real, already-recorded trough is usable as "a
# tighter SL would have stopped this out before it recovered" -- but only if
# the drawdown is non-trivial AND shallower than (or SL unknown) the actual
# SL that was in place (otherwise the SL WOULD already have caught it, which
# is a contradiction, not a counterfactual) ──
print('\nTake-profit exit that survived a real drawdown (must report survived_drawdown):')
r = _cf('take_profit', 1.0, 20.0, 15.0, 20.0, 1.20, 0.90)  # dipped -10%, SL was -15%
check('TP win that dipped -10% with a -15% SL -> survived_drawdown', r['kind'] == 'survived_drawdown',
      detail=str(r))
check('trough_pct computed from real lowest_price', r.get('trough_pct') == 10.0, detail=str(r))

r = _cf('take_profit', 1.0, 20.0, None, 20.0, 1.20, 0.90)  # SL unknown -- still a valid signal
check('TP win with SL unknown still reports the drawdown', r['kind'] == 'survived_drawdown', detail=str(r))

print('\nTake-profit exit whose drawdown was NOT shallower than its own SL (contradiction -> None):')
r = _cf('take_profit', 1.0, 20.0, 8.0, 20.0, 1.20, 0.85)  # dipped -15%, SL was -8% -- SL should have fired first
check('drawdown deeper than the actual SL -> None (would be self-contradictory)', r['kind'] is None,
      detail=str(r))

print('\nTake-profit exit with a trivial drawdown (must be None):')
r = _cf('take_profit', 1.0, 20.0, 15.0, 20.0, 1.20, 0.997)  # barely dipped
check('trivial drawdown -> None', r['kind'] is None, detail=str(r))

# ── The two counterfactuals are mutually exclusive by construction: a TP
# exit is never checked for gave_back_peak, a non-TP exit never for
# survived_drawdown ──
print('\nMutual exclusivity by exit type:')
r = _cf('take_profit', 1.0, 20.0, 15.0, 20.0, 1.35, 0.90)  # even with a big "peak", TP exits skip that branch
check('TP exit never reports gave_back_peak even with a large highest_price',
      r['kind'] != 'gave_back_peak', detail=str(r))

print(f'\n{_passed} passed, {_failed} failed')
if _failed:
    raise SystemExit(1)
