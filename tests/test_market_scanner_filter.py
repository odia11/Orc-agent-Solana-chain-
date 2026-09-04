"""Tests for _is_market_major_or_impersonator and its effect on
_get_scanner_candidates()/_get_narrative_candidates() (dashboard.py) --
the filter that keeps major assets (SOL/USDC/USDT/...) and ticker
impersonators of them out of Live Market's story rail and the home feed's
market rail, and the volume-based sort that replaces upstream insertion
order.

dashboard.py cannot be safely `import`ed in a test process (it starts
background threads and a job scheduler at module level), so this extracts
the real function source via `ast` and execs it in an isolated namespace,
same approach as test_net_edge_filter.py / test_trade_counterfactual.py.
Network calls (_dex_get) are stubbed with a fake that serves canned
DexScreener-shaped responses built to reproduce the reported bug: several
different mint addresses all claiming ticker "SOL".

Run with: python3 test_market_scanner_filter.py
"""
import ast
import os
import threading
import time

DASHBOARD_PATH = os.path.join(os.path.dirname(__file__), '..', 'dashboard.py')

with open(DASHBOARD_PATH, encoding='utf-8') as f:
    _SRC = f.read()
_TREE = ast.parse(_SRC)

_WANTED_FUNCS = {
    '_is_market_major_or_impersonator',
    '_get_scanner_candidates',
    '_get_narrative_candidates',
}
_WANTED_CONSTS = {'_MARKET_MAJOR_ADDRESSES', '_MARKET_MAJOR_SYMBOLS', '_MARKET_LIVE_CHAINS'}

_func_src, _const_src = {}, {}
for node in _TREE.body:
    if isinstance(node, ast.FunctionDef) and node.name in _WANTED_FUNCS:
        _func_src[node.name] = ast.get_source_segment(_SRC, node)
    elif isinstance(node, ast.Assign) and len(node.targets) == 1 \
            and isinstance(node.targets[0], ast.Name) and node.targets[0].id in _WANTED_CONSTS:
        _const_src[node.targets[0].id] = ast.get_source_segment(_SRC, node)

assert set(_func_src) == _WANTED_FUNCS, f'missing functions: {_WANTED_FUNCS - set(_func_src)}'
assert set(_const_src) == _WANTED_CONSTS, f'missing constants: {_WANTED_CONSTS - set(_const_src)}'


class _FakeResp:
    def __init__(self, payload):
        self.status_code = 200
        self._payload = payload
    def json(self):
        return self._payload


def _pair(symbol, address, volume_h24=0.0, liquidity_usd=10000.0, chain='solana'):
    return {
        'chainId': chain,
        'baseToken': {'address': address, 'symbol': symbol, 'name': symbol},
        'info': {'imageUrl': ''},
        'priceUsd': '0.001',
        'marketCap': 100000,
        'liquidity': {'usd': liquidity_usd},
        'volume': {'h24': volume_h24},
        'txns': {'h24': {'buys': 10, 'sells': 5}},
        'priceChange': {'h24': 5.0},
        'pairCreatedAt': int(time.time() * 1000),
    }


# ── Scenario reproducing the reported screenshot: the trending search for
# "solana" returns the real SOL/USDC pair PLUS three impersonator tokens
# (different mint addresses, all lying about their ticker being "SOL"),
# alongside one genuine new token. ──
FAKE_TRENDING_SOLANA = [
    _pair('SOL', 'So11111111111111111111111111111111111111112', volume_h24=99_000_000, liquidity_usd=5_000_000),
    _pair('SOL', 'FAKE1111111111111111111111111111111111111', volume_h24=500, liquidity_usd=800),
    _pair('SOL', 'FAKE2222222222222222222222222222222222222', volume_h24=300, liquidity_usd=600),
    _pair('SOL', 'FAKE3333333333333333333333333333333333333', volume_h24=200, liquidity_usd=400),
    _pair('Pumpooor', 'REALTOKEN11111111111111111111111111111111', volume_h24=2_310_000, liquidity_usd=81_300),
    _pair('USDC', 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', volume_h24=50_000_000, liquidity_usd=9_000_000),
]


def _fake_dex_get(url, timeout=8):
    if 'token-boosts/top' in url:
        return _FakeResp([])
    if 'token-profiles/latest' in url:
        return _FakeResp([])
    if 'search?q=solana' in url:
        return _FakeResp({'pairs': FAKE_TRENDING_SOLANA})
    if 'search?q=bnb' in url:
        return _FakeResp({'pairs': []})
    if 'latest/dex/tokens/' in url:
        return _FakeResp({'pairs': []})
    return _FakeResp({'pairs': []})


namespace = {
    'time': time,
    'threading': threading,
    'ThreadPoolExecutor': __import__('concurrent.futures', fromlist=['ThreadPoolExecutor']).ThreadPoolExecutor,
    '_dex_get': _fake_dex_get,
}
exec(_const_src['_MARKET_LIVE_CHAINS'], namespace)
exec(_const_src['_MARKET_MAJOR_ADDRESSES'], namespace)
exec(_const_src['_MARKET_MAJOR_SYMBOLS'], namespace)
exec(_func_src['_is_market_major_or_impersonator'], namespace)
exec(_func_src['_get_scanner_candidates'], namespace)
exec(_func_src['_get_narrative_candidates'], namespace)

_is_major = namespace['_is_market_major_or_impersonator']
_get_scanner_candidates = namespace['_get_scanner_candidates']
_get_narrative_candidates = namespace['_get_narrative_candidates']

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


print('_is_market_major_or_impersonator unit behavior:')
check('real WSOL address flagged', _is_major('SOL', 'So11111111111111111111111111111111111111112'))
check('real USDC address flagged', _is_major('USDC', 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'))
check('ticker impersonator (fake address, symbol "SOL") flagged',
      _is_major('SOL', 'FAKE1111111111111111111111111111111111111'))
check('ticker impersonator is case/whitespace-insensitive',
      _is_major('  sol  ', 'SomeOtherAddress'))
check('a genuine new token is NOT flagged', not _is_major('Pumpooor', 'REALTOKEN11111111111111111111111111111111'))
check('a token merely containing "sol" as a substring is NOT flagged (exact match only)',
      not _is_major('SOLDIER', 'SomeAddress'))

print('\n_get_scanner_candidates() end-to-end against the reproduced bug scenario:')
scanner_out = _get_scanner_candidates()
symbols = [t['symbol'] for t in scanner_out]
check('no SOL-labeled entries survive (real or impersonator)', 'SOL' not in symbols, detail=str(symbols))
check('no USDC entry survives', 'USDC' not in symbols, detail=str(symbols))
check('the genuine new token IS present', 'Pumpooor' in symbols, detail=str(symbols))
check('exactly one candidate survives (the genuine token only)', len(scanner_out) == 1, detail=str(scanner_out))

print('\n_get_narrative_candidates() end-to-end (home feed market rail):')
narrative_out = _get_narrative_candidates()
n_symbols = [t['symbol'] for t in narrative_out]
check('no SOL-labeled entries survive', 'SOL' not in n_symbols, detail=str(n_symbols))
check('the genuine new token IS present', 'Pumpooor' in n_symbols, detail=str(n_symbols))

print('\nVolume-based ordering (no upstream sort should leak through):')
# Two genuine (non-major) tokens, deliberately returned LOW-volume-first by
# the fake trending search, must come back HIGH-volume-first.
FAKE_TRENDING_SOLANA_VOL_TEST = [
    _pair('LOWVOL', 'LOWVOL1111111111111111111111111111111111', volume_h24=1_000, liquidity_usd=5000),
    _pair('HIGHVOL', 'HIGHVOL111111111111111111111111111111111', volume_h24=9_000_000, liquidity_usd=200_000),
]
def _fake_dex_get_vol(url, timeout=8):
    if 'search?q=solana' in url:
        return _FakeResp({'pairs': FAKE_TRENDING_SOLANA_VOL_TEST})
    return _FakeResp({'pairs': []}) if 'search?q=bnb' not in url else _FakeResp({'pairs': []})
namespace2 = dict(namespace)
namespace2['_dex_get'] = _fake_dex_get_vol
exec(_func_src['_get_scanner_candidates'], namespace2)
vol_out = namespace2['_get_scanner_candidates']()
check('highest-volume token sorted first', vol_out and vol_out[0]['symbol'] == 'HIGHVOL', detail=str(vol_out))

print(f'\n{_passed} passed, {_failed} failed')
if _failed:
    raise SystemExit(1)
