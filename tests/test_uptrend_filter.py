"""Tests for the 'uptrend' sort mode in api_market_scanner() (dashboard.py):
tokens with +5% or more over 24h AND a $30K+ market cap.

dashboard.py cannot be safely `import`ed in a test process (it starts
background threads and a job scheduler at module level), so this extracts
the real function source via `ast` and execs it with lightweight fakes for
its Flask/DB dependencies (request, jsonify, sqlite3, _current_wallet,
_scanner_get_safety), same approach as the other test_*.py files in this
repo. _get_scanner_cached() is stubbed to return fixture tokens directly,
so this exercises the actual filter/sort/count logic inside the real,
shipped route function body.

Run with: python3 test_uptrend_filter.py
"""
import ast
import os
import time

DASHBOARD_PATH = os.path.join(os.path.dirname(__file__), '..', 'dashboard.py')
with open(DASHBOARD_PATH, encoding='utf-8') as f:
    _SRC = f.read()
_TREE = ast.parse(_SRC)

_func_src = None
_age_buckets_src = None
for node in _TREE.body:
    if isinstance(node, ast.FunctionDef) and node.name == 'api_market_scanner':
        _func_src = ast.get_source_segment(_SRC, node)
    elif isinstance(node, ast.Assign) and len(node.targets) == 1 \
            and isinstance(node.targets[0], ast.Name) and node.targets[0].id == '_AGE_BUCKET_SECONDS':
        _age_buckets_src = ast.get_source_segment(_SRC, node)

assert _func_src is not None, 'api_market_scanner not found in dashboard.py'
assert _age_buckets_src is not None, '_AGE_BUCKET_SECONDS not found in dashboard.py'


# ── fixtures ──
def tok(symbol, price_change_24h, market_cap, liquidity_usd=50000, volume_24h=10000,
        pair_created_at=None, mint=None):
    return {
        'mint': mint or symbol, 'symbol': symbol, 'price_change_24h': price_change_24h,
        'market_cap': market_cap, 'liquidity_usd': liquidity_usd, 'volume_24h': volume_24h,
        'pair_created_at': pair_created_at, 'buys_24h': 5, 'sells_24h': 2,
    }


FIXTURES = [
    tok('BIGWIN',   price_change_24h=8.0,  market_cap=50_000),   # qualifies: +8%, $50K MC
    tok('EXACTLY5', price_change_24h=5.0,  market_cap=30_000),   # boundary: exactly at both thresholds
    tok('TOOSMALL', price_change_24h=12.0, market_cap=29_999),   # fails: MC just under $30K
    tok('TOOFLAT',  price_change_24h=4.9,  market_cap=100_000),  # fails: % just under 5
    tok('DUMPING',  price_change_24h=-20.0, market_cap=1_000_000),  # fails: negative change
    tok('MEGA',     price_change_24h=25.0, market_cap=500_000),  # qualifies, highest %, should sort first
]


class _FakeArgs:
    def __init__(self, params):
        self._p = params
    def get(self, key, default=None):
        return self._p.get(key, default)


class _FakeRequest:
    def __init__(self, params):
        self.args = _FakeArgs(params)


def _fake_jsonify(payload):
    return payload  # inspect the dict directly instead of a real Flask Response


class _FakeSqlite3:
    class OperationalError(Exception):
        pass
    @staticmethod
    def connect(path):
        raise RuntimeError('no wallet in these tests -- should never be reached')


def _run_scanner(sort_mode='trending', **extra_params):
    params = {'sort': sort_mode}
    params.update(extra_params)
    namespace = {
        'request': _FakeRequest(params),
        'jsonify': _fake_jsonify,
        'time': time,
        'sqlite3': _FakeSqlite3,
        'DB_FILE': ':unused:',
        'ThreadPoolExecutor': __import__('concurrent.futures', fromlist=['ThreadPoolExecutor']).ThreadPoolExecutor,
        '_get_scanner_cached': lambda: list(FIXTURES),
        '_current_wallet': lambda: None,   # skips the friends-query sqlite path entirely
        '_scanner_get_safety': lambda mint: {'lp_locked_pct': 0, 'mint_authority_active': False, 'freeze_authority_active': False},
        '_scanner_score': lambda tok, safety: 3,
    }
    exec(_age_buckets_src, namespace)
    exec(_func_src, namespace)
    return namespace['api_market_scanner']()


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


print("'uptrend' sort mode:")
result = _run_scanner('uptrend')
symbols = [t['symbol'] for t in result['tokens']]
check('qualifying token BIGWIN present', 'BIGWIN' in symbols, detail=str(symbols))
check('boundary token EXACTLY5 present (>= is inclusive on both ends)', 'EXACTLY5' in symbols, detail=str(symbols))
check('MC just under $30K excluded (TOOSMALL)', 'TOOSMALL' not in symbols, detail=str(symbols))
check('% just under 5 excluded (TOOFLAT)', 'TOOFLAT' not in symbols, detail=str(symbols))
check('negative-change token excluded (DUMPING)', 'DUMPING' not in symbols, detail=str(symbols))
check('exactly 3 tokens qualify', len(symbols) == 3, detail=str(symbols))
check('sorted by price_change_24h descending (MEGA first)', symbols[0] == 'MEGA', detail=str(symbols))
check("'uptrend' count in counts dict matches", result['counts']['uptrend'] == 3, detail=str(result['counts']))

print('\nRegression -- other sort modes still behave as before:')
gainers = _run_scanner('gainers')
g_symbols = [t['symbol'] for t in gainers['tokens']]
check("'gainers' still includes ANY positive change (TOOFLAT, at +4.9%)", 'TOOFLAT' in g_symbols, detail=str(g_symbols))
check("'gainers' still excludes the negative-change token", 'DUMPING' not in g_symbols, detail=str(g_symbols))

trending = _run_scanner('trending')
t_symbols = [t['symbol'] for t in trending['tokens']]
check("'trending' (default) still returns every fixture token", len(t_symbols) == len(FIXTURES), detail=str(t_symbols))

volume = _run_scanner('volume')
check("'volume' sort mode untouched by this change", 'counts' in volume and 'volume' in volume['counts'])

print(f'\n{_passed} passed, {_failed} failed')
if _failed:
    raise SystemExit(1)
