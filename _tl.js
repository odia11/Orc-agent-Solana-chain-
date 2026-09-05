function _pickPairForSymbol(pairs, symbol, liveChains){
  var wanted = String(symbol||'').trim().toUpperCase();
  var liq = function(x){ return parseFloat((x.liquidity||{}).usd || 0) || 0; };
  var ok = (pairs||[]).filter(function(x){ return liveChains.indexOf(x.chainId) !== -1; });
  var exact = ok.filter(function(x){ return String((x.baseToken||{}).symbol||'').toUpperCase() === wanted; });
  var pool = exact.length ? exact : ok;
  if(!pool.length) return undefined;
  return pool.reduce(function(best, x){ return liq(x) > liq(best) ? x : best; }, pool[0]);
}
function _fmtTinyDecimal(p){
  var m = p.toFixed(20).match(/^0\.(0*)/);
  var zeros = m ? m[1].length : 0;
  return p.toFixed(Math.min(zeros + 4, 18)).replace(/0+$/,'').replace(/\.$/,'');
}
function fmtTokenPrice(p){
  p=parseFloat(p);
  if(!p) return '$0';
  if(p>=1) return '$'+p.toFixed(2);
  if(p>=0.01) return '$'+p.toFixed(4);
  if(p>=0.0001) return '$'+p.toFixed(6);
  // Below that this used to return '$0.0'+zeroCount+digits -- the subscript
  // notation without the subscript. A price of 0.0000023456 came out as
  // "$0.052345", which reads as five cents and is off by four orders of
  // magnitude. Print the actual decimal instead, to four significant digits.
  return '$'+_fmtTinyDecimal(p);
}
function _lmtdPickPair(pairs, symbol, liveChains){
  // A ticker in a post or a ?token= URL carries no chain, so the search can
  // match many different coins. Require an exact symbol match (a search for
  // "D" also returns every token whose NAME contains a D) and among those
  // take the deepest pool -- the same rule the market data uses to choose a
  // pair. Deepest partial match as a fallback, so something still opens.
  var wanted = String(symbol||'').trim().toUpperCase();
  var liq = function(x){ return parseFloat((x.liquidity||{}).usd || 0) || 0; };
  var ok = (pairs||[]).filter(function(x){ return liveChains.indexOf(x.chainId) !== -1; });
  var exact = ok.filter(function(x){ return String((x.baseToken||{}).symbol||'').toUpperCase() === wanted; });
  var pool = exact.length ? exact : ok;
  if(!pool.length) return undefined;
  return pool.reduce(function(best, x){ return liq(x) > liq(best) ? x : best; }, pool[0]);
}
function _fmtPrice(p){
  if(!p) return '—';
  p = parseFloat(p);
  if(isNaN(p)||p<=0) return '—';
  if(p>=1) return '$'+p.toFixed(2);
  if(p>=0.0001) return '$'+p.toFixed(6);
  // Four significant digits of the REAL decimal. toFixed(10) silently
  // truncated anything smaller than 1e-10 to "$0." -- a price of zero.
  var m = p.toFixed(20).match(/^0\.(0*)/);
  var zeros = m ? m[1].length : 0;
  return '$'+p.toFixed(Math.min(zeros + 4, 18)).replace(/0+$/,'').replace(/\.$/,'');
}
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
