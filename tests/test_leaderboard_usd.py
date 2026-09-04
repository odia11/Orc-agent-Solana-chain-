"""Tests for /api/leaderboard's total_pnl_usd field (dashboard.py) -- the
USD conversion of a trader's rolling-24h SOL PnL, computed from the live
_sol_price_usd, that Live Market's Top Traders spotlight displays.

dashboard.py cannot be safely `import`ed in a test process (it starts
background threads and a job scheduler at module level), so this extracts
the real function source via `ast` and execs it with a real temp-file
SQLite database and a fake jsonify, same approach as the other test_*.py
files in this repo.

Run with: python3 test_leaderboard_usd.py
"""
import ast
import os
import sqlite3
import tempfile
import time

DASHBOARD_PATH = os.path.join(os.path.dirname(__file__), '..', 'dashboard.py')
with open(DASHBOARD_PATH, encoding='utf-8') as f:
    _SRC = f.read()
_TREE = ast.parse(_SRC)

_func_src = None
for node in _TREE.body:
    if isinstance(node, ast.FunctionDef) and node.name == 'get_leaderboard':
        _func_src = ast.get_source_segment(_SRC, node)
        break
assert _func_src is not None, 'get_leaderboard not found in dashboard.py'


def _fake_jsonify(payload):
    return payload


def _run_leaderboard(sol_price_usd):
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT, wallet_address TEXT,
        avatar_url TEXT, badges TEXT, is_verified INTEGER)''')
    conn.execute('''CREATE TABLE trades (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, pnl REAL,
        timestamp TEXT, source TEXT, mint_address TEXT)''')
    conn.execute("INSERT INTO users VALUES (1,'winner','WalletWinner1111111111111111111111111111',"
                 "'', '', 0)")
    now = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())
    conn.execute("INSERT INTO trades (user_id, pnl, timestamp, source) VALUES (1, 2.5, ?, 'bot')", (now,))
    conn.execute("INSERT INTO trades (user_id, pnl, timestamp, source) VALUES (1, -0.5, ?, 'bot')", (now,))
    conn.commit()
    conn.close()

    namespace = {
        'sqlite3': sqlite3, 'DB_FILE': path, 'jsonify': _fake_jsonify,
        '_sol_price_usd': sol_price_usd,
    }
    exec(_func_src, namespace)
    result = namespace['get_leaderboard']()
    os.remove(path)
    return result


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


print('total_pnl_usd with a live SOL price:')
result = _run_leaderboard(sol_price_usd=200.0)
check('one trader in the result', len(result) == 1, detail=str(result))
row = result[0]
check('total_pnl is the raw SOL sum (2.5 - 0.5 = 2.0)', row['total_pnl'] == 2.0, detail=str(row))
check('total_pnl_usd = total_pnl * sol price (2.0 * 200 = 400.0)', row['total_pnl_usd'] == 400.0, detail=str(row))
check('win_rate present (1 of 2 trades non-negative = 50%)', row['win_rate'] == 50.0, detail=str(row))

print('\ntotal_pnl_usd when the price feed has not populated yet (_sol_price_usd == 0):')
result2 = _run_leaderboard(sol_price_usd=0.0)
row2 = result2[0]
check('total_pnl_usd is None, not a misleading $0.00', row2['total_pnl_usd'] is None, detail=str(row2))
check('total_pnl (SOL) is still correct so the frontend can fall back to it', row2['total_pnl'] == 2.0, detail=str(row2))

print(f'\n{_passed} passed, {_failed} failed')
if _failed:
    raise SystemExit(1)
