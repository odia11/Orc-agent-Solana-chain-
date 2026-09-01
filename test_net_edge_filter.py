"""Tests for the Net Expected Edge Filter (_estimate_net_edge in dashboard.py).

dashboard.py cannot be safely `import`ed in a test process: it starts
background threads and a job scheduler (_start_backup_scheduler()) at
module level, unconditionally, not behind `if __name__ == '__main__':`.
Rather than reimplementing the filter's logic here (which would test a copy
that can silently drift from the real code), this extracts the actual
function source -- and the actual module-level constants it depends on --
directly out of dashboard.py via `ast`, and execs that source in an
isolated namespace. Every test below is exercising the real, shipped
function body.

Run with: python3 test_net_edge_filter.py
"""
import ast
import os

DASHBOARD_PATH = os.path.join(os.path.dirname(__file__), 'dashboard.py')


def _load_real_function():
    """Extracts _estimate_net_edge's source plus the three module-level
    constants it reads (FEE_RATE_TXN, PRIORITY_FEE_PCT_ASSUMPTION,
    MIN_EDGE_TO_COST_RATIO) from dashboard.py, execs them together in a
    fresh namespace, and returns the real function object."""
    with open(DASHBOARD_PATH, encoding='utf-8') as f:
        src = f.read()
    tree = ast.parse(src)

    wanted_consts = {'FEE_RATE_TXN', 'PRIORITY_FEE_PCT_ASSUMPTION', 'MIN_EDGE_TO_COST_RATIO'}
    const_srcs = []
    func_src = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id in wanted_consts:
            const_srcs.append(ast.get_source_segment(src, node))
        elif isinstance(node, ast.FunctionDef) and node.name == '_estimate_net_edge':
            func_src = ast.get_source_segment(src, node)

    missing = wanted_consts - {c.split('=')[0].strip() for c in const_srcs}
    assert not missing, f'Could not find constant(s) in dashboard.py: {missing}'
    assert func_src is not None, '_estimate_net_edge not found in dashboard.py'

    namespace = {}
    exec('\n'.join(const_srcs), namespace)
    exec(func_src, namespace)
    return namespace['_estimate_net_edge']


_estimate_net_edge = _load_real_function()

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


# ── Missing-data scenarios: must default to SKIP, never assume profitable ──
print('Missing/unreliable data (must always SKIP):')
r = _estimate_net_edge(None, 20.0)
check('missing price impact -> SKIP', r['decision'] == 'SKIP' and 'price impact' in r['reason'])

r = _estimate_net_edge(0.01, None)
check('missing take-profit -> SKIP', r['decision'] == 'SKIP' and 'take-profit' in r['reason'])

r = _estimate_net_edge(0.01, 0.0)
check('zero take-profit -> SKIP', r['decision'] == 'SKIP')

r = _estimate_net_edge(0.01, -5.0)
check('negative take-profit -> SKIP', r['decision'] == 'SKIP')

# ── Unprofitable scenario: a low take-profit target can't clear round-trip
# costs even before considering win probability at all ──
print('\nUnprofitable-edge scenarios (must SKIP):')
# TP=3%, impact=2% -> entry_cost=2.75%, exit_cost=2.75%, fees=0.1% -> total=5.6%
# gross move (3%) is nowhere near covering 5.6% of round-trip cost.
r = _estimate_net_edge(0.02, 3.0)
check('low TP vs high impact -> SKIP', r['decision'] == 'SKIP',
      detail=f'edge={r["expected_net_edge_pct"]} cost={r["estimated_total_cost_pct"]}')
check('cost fields populated even on SKIP', all(
    r[k] is not None for k in ('expected_gross_move_pct', 'estimated_entry_cost_pct',
                                'estimated_exit_cost_pct', 'estimated_fees_pct', 'estimated_total_cost_pct')))

# TP=5%, impact=5% (at the price-impact gate's own 5% ceiling) -> costs alone
# (2x(5%+0.75%)+0.1%) = 11.6%, nowhere near covered by a 5% target.
r = _estimate_net_edge(0.05, 5.0)
check('TP at ceiling-impact token -> SKIP', r['decision'] == 'SKIP')

# ── Profitable scenario: a wide take-profit target on a liquid pool (tiny
# price impact) comfortably clears round-trip costs with margin to spare ──
print('\nProfitable-edge scenarios (must PROCEED):')
# TP=30% (Aggressive preset), impact=0.2% -> entry_cost=0.95%, exit_cost=0.95%,
# fees=0.1% -> total=2.0%. net_edge = 28% >> 1x2.0% floor.
r = _estimate_net_edge(0.002, 30.0)
check('wide TP + deep liquidity -> PROCEED', r['decision'] == 'PROCEED',
      detail=f'edge={r["expected_net_edge_pct"]} cost={r["estimated_total_cost_pct"]}')
check('net edge arithmetic is internally consistent', abs(
    r['expected_gross_move_pct'] - r['estimated_total_cost_pct'] - r['expected_net_edge_pct']) < 1e-6)

# Balanced preset (TP=20%) on a reasonably liquid pool (impact=0.5%):
# entry/exit cost = 1.25% each, fees=0.1% -> total=2.6%, net_edge=17.4% -> PROCEED.
r = _estimate_net_edge(0.005, 20.0)
check('Balanced preset on liquid pool -> PROCEED', r['decision'] == 'PROCEED')

# ── Boundary: exactly at the MIN_EDGE_TO_COST_RATIO=1.0x floor must PROCEED
# (>=, not >) and one unit below it must SKIP ──
print('\nBoundary at MIN_EDGE_TO_COST_RATIO:')
# Solve for a take_profit that lands net_edge exactly == total_cost, given
# impact=0.01 (entry=exit=0.0175, fees=0.001, total=0.036):
# net_edge == total_cost  =>  gross_move == 2*total_cost  =>  tp_pct == 2*3.6 = 7.2
r = _estimate_net_edge(0.01, 7.2)
check('exactly at 1.0x floor -> PROCEED', r['decision'] == 'PROCEED',
      detail=f'edge={r["expected_net_edge_pct"]} cost={r["estimated_total_cost_pct"]}')
r = _estimate_net_edge(0.01, 7.1)
check('just below 1.0x floor -> SKIP', r['decision'] == 'SKIP')

print(f'\n{_passed} passed, {_failed} failed')
if _failed:
    raise SystemExit(1)
