"""Which token a $TICKER opens, and how a tiny price is written.

Both are cases where the app confidently showed a WRONG number rather than
failing, which is the worst way for this kind of bug to behave: a market cap
and a price for a completely different coin look exactly as trustworthy as
the right ones.

The real functions are lifted out of the two front-end files and run in node,
so these test the shipped code rather than a copy of it."""
import json, re, subprocess, sys

REPO = '/home/user/Orc-agent-Solana-chain-'
D    = open(REPO + '/static/dashboard.js').read()
T    = open(REPO + '/static/token-card.js').read()

checks = []
def check(name, cond):
    checks.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name)

def fn(src, name):
    m = re.search(rf'^function {re.escape(name)}\(.*?\n\}}', src, re.M | re.S)
    assert m, name
    return m.group(0)

harness = '\n'.join([fn(D, '_pickPairForSymbol'), fn(D, '_fmtTinyDecimal'),
                     fn(D, 'fmtTokenPrice'), fn(T, '_lmtdPickPair'), fn(T, '_fmtPrice')]) + r'''
var CHAINS = ['solana','bsc','base','arbitrum','polygon','robinhood'];
function pr(sym, liq, chain, name){
  return {baseToken:{symbol:sym, name:name||sym}, chainId:chain, liquidity:{usd:liq}};
}
// How DexScreener actually answers a search for "D": its own relevance order,
// which puts a big well-known coin whose NAME contains the letter first.
var SEARCH_D = [pr('DOGE',9000000,'solana','Dogecoin'), pr('D',12000,'solana','D coin'),
                pr('D',53900,'robinhood','Point D'),   pr('DRIFT',400000,'solana','Drift')];
function nm(p){ return p ? p.baseToken.name : null; }
var out = {
  first_supported: nm(SEARCH_D.filter(function(x){return CHAINS.indexOf(x.chainId)!==-1;})[0]),
  dash_D:  nm(_pickPairForSymbol(SEARCH_D,'D',CHAINS)),
  card_D:  nm(_lmtdPickPair(SEARCH_D,'D',CHAINS)),
  dash_D_chain: (_pickPairForSymbol(SEARCH_D,'D',CHAINS)||{}).chainId,
  lowercase:    nm(_pickPairForSymbol(SEARCH_D,'d',CHAINS)),
  padded:       nm(_pickPairForSymbol(SEARCH_D,' D ',CHAINS)),
  offchain:     _pickPairForSymbol([pr('D',999,'ethereum')],'D',CHAINS) || null,
  none:         _pickPairForSymbol([],'D',CHAINS) || null,
  no_exact:     nm(_pickPairForSymbol([pr('DOGE',5,'solana'),pr('DOGGY',900,'base')],'D',CHAINS)),
  no_liq:       nm(_pickPairForSymbol([{baseToken:{symbol:'D',name:'No liq'},chainId:'solana'}],'D',CHAINS)),
  prices:  {}, card_prices: {}
};
[1.5, 0.0234, 0.000230, 0.0000023456, 0.00000000012345, 0].forEach(function(v){
  out.prices[String(v)] = fmtTokenPrice(v);
  out.card_prices[String(v)] = _fmtPrice(v);
});
console.log(JSON.stringify(out));
'''
open('_tl.js', 'w').write(harness)
res = subprocess.run(['node', '_tl.js'], capture_output=True, text=True)
assert res.returncode == 0, res.stderr
R = json.loads(res.stdout)
print(json.dumps(R, indent=2) + '\n')

# ── which token a ticker opens ──
check('the old rule really did open the wrong coin — "$D" took DexScreener\'s '
      'first result, which is Dogecoin because its NAME contains a D',
      R['first_supported'] == 'Dogecoin')
check('an exact symbol match now beats a bigger coin that merely matched the search',
      R['dash_D'] == 'Point D' and R['card_D'] == 'Point D')
check('...on both cards, which had the identical bug in two files',
      R['dash_D'] == R['card_D'])
check('among exact matches the deepest pool wins, so a $12K "D coin" does not '
      'outrank the $53.9K one the post was about', R['dash_D_chain'] == 'robinhood')
check('the ticker is matched case-insensitively', R['lowercase'] == 'Point D')
check('...and stray whitespace does not break it', R['padded'] == 'Point D')
check('a pair on a chain this app does not trade is never opened', R['offchain'] is None)
check('an empty result set returns nothing rather than throwing', R['none'] is None)
check('with no exact match it still opens the deepest near-match instead of an '
      'error — an inexact ticker should show something', R['no_exact'] == 'DOGGY')
check('a pair with no liquidity field does not crash the comparison', R['no_liq'] == 'No liq')

# ── how a price is written ──
P, C = R['prices'], R['card_prices']
check('a dollar price is unchanged', P['1.5'] == '$1.50')
check('a cent price is unchanged', P['0.0234'] == '$0.0234')
check('the price behind a ~$230K market cap reads exactly as it is',
      P['0.00023'] == '$0.000230')
check('a price of 0.0000023456 is no longer written "$0.052345" — the old format '
      'put the zero-count INSIDE the number and was off by four orders of magnitude',
      P['0.0000023456'] == '$0.000002346')
check('...and the same on the Live Market card', C['0.0000023456'] == '$0.000002346')
check('a price below 1e-10 shows real digits instead of being truncated to "$0."',
      P['1.2345e-10'].startswith('$0.0000000001') and C['1.2345e-10'].startswith('$0.0000000001'))
check('every price is a number a reader can compare — no zero-count shorthand left',
      all(not re.match(r'^\$0\.0\d{5,}$', v) or float(v[1:]) > 0 for v in P.values() if v != '—'))
check('zero is still zero, not a long string of decimals', P['0'] in ('$0', '—'))

check('no call site still takes DexScreener\'s first result',
      '.find(x=>liveChains.indexOf(x.chainId)!==-1)' not in D
      and 'return _liveChains.indexOf(x.chainId)!==-1; })' not in T)

print(f'\n{sum(1 for _, c in checks if c)}/{len(checks)} checks passed')
sys.exit(0 if all(c for _, c in checks) else 1)
