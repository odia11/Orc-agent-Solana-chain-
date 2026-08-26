// OrcAgent token detail card (chart + stats + buy/sell) -- shared between
// live_market.html (as a modal, wrapped in #lm-token-modal) and token.html
// (as the entire page, wrapped directly in .lm-modal-card, no overlay/close
// button). Both host pages must provide:
//   - a #lm-modal-body element for showTokenCard()/_lmtdRenderModal() to
//     render into
//   - <meta name="csrf-token"> and <meta name="client-secret"> tags for
//     executeTrade()/_doTrade()
// Extracted from live_market.html so bug fixes and improvements land in one
// place instead of drifting between two copies.

async function _doTrade(sym, pairAddr, side, amount, tokenAddr, chain){
  chain = chain || 'solana';
  try{
    var _cs   = _lmClientSecret||(document.querySelector('meta[name="client-secret"]')||{}).content||'';
    var _csrf = (document.querySelector('meta[name="csrf-token"]')||{}).content||_lmCsrf||'';
    var headers = Object.assign({
        'Content-Type':'application/json',
        'X-CSRF-Token':_csrf,
        'X-CSRFToken':_csrf,
        'X-Requested-With':'XMLHttpRequest'
      }, _cs ? {'X-API-Shared-Secret':_cs} : {});

    var url, body;
    if(chain === 'bsc'){
      // BSC uses two separate buy/sell routes (not one side-flagged endpoint
      // like Solana's /api/instant-trade), and trades are USDC-denominated,
      // not SOL-denominated -- see _execute_bsc_swap() on the backend.
      // /api/bsc/trade/buy reads amount_usdc specifically (not amount) --
      // /api/bsc/trade/sell ignores amount entirely and sells the full
      // tracked position server-side, so it's harmless to still send here.
      url = side === 'buy' ? '/api/bsc/trade/buy' : '/api/bsc/trade/sell';
      body = {token_address: tokenAddr, amount_usdc: amount, amount: amount};
    } else {
      url = '/api/instant-trade';
      body = {symbol:sym, pair_address:pairAddr, side:side, amount_sol:amount, token_address:tokenAddr};
    }

    var r = await fetch(url, {
      method:'POST',
      credentials:'include',
      headers: headers,
      body: JSON.stringify(body)
    });
    var d = await r.json();
    if(r.ok) return true;
    _toast((d.error||d.message||d.msg||'Trade failed'), false);
    return false;
  }catch(e){
    _toast('Network error — trade not sent', false);
    return false;
  }
}

/* ── token modal ── */
/* ── token detail modal: Focus / Terminal (see PROMPT.md spec) ── */
var _lmtdPair       = null;
var _lmtdSymbol     = '';
var _lmtdLayout     = 'focus';
var _lmtdTf         = '5m';
var _lmtdSide       = 'buy';
var _lmtdSolBalance = 0;
var _lmtdChart      = null;
var _lmtdSeries     = null;
var _lmtdVolSeries  = null;
var _lmtdChartStyle = 'candles'; // 'candles' or 'fomo' (live area chart)
var _lmtdFomoTimer  = null;      // live-refresh interval while the 'fomo' style is active
var _lmtdPriceLine  = null;      // the dashed current-price line + floating label on the fomo chart
var _lmtdChartFetch = null; // {mint, tf, promise} -- most recent chart-data fetch (pending or resolved) for
                             // the currently-open token, so the skeleton render, the post-metadata re-render,
                             // and layout switches all reuse the same request instead of re-fetching
var _lmtdActiveMint = ''; // mint the modal is CURRENTLY open on — lets a late-arriving stale fetch recognize itself as stale
var _lmtdChartGen   = 0;  // bumped every _lmtdInitChart() call -- showTokenCard() renders the modal twice (skeleton,
                           // then again once real metadata lands), and each render tears down and recreates
                           // _lmtdChart/_lmtdSeries. Without this, a chart-data fetch started against the skeleton's
                           // chart instance can still be in flight when the metadata render replaces it, and then
                           // resolve into a since-destroyed series -- intermittently (whichever render's fetch
                           // happens to land last "wins", so it's a coin flip, and lands more often as fetches get
                           // faster) showing "Chart unavailable" even though the data loaded fine.
var _LMTD_TF_MAP    = {'1m':'1m','5m':'5m','15m':'15m','1H':'1h','4H':'4h','1D':'D'};
var _LMTD_CHART_FETCH_TIMEOUT = 12000;
var _lmtdLastClose   = null; // most recent candle close -- "current price" for the Holders tab, independent of the priceUsd shown in the hero
var _lmtdHoldersTotal = null; // total from the last /holders fetch; null until loaded, reset per token in showTokenCard()

function _lmtdFetchBalance(){
  fetch('/api/wallet/balance', {credentials:'include'}).then(function(r){return r.json();}).then(function(d){
    if(d.ok) _lmtdSolBalance = d.sol;
  }).catch(function(){});
}

/* Raw chart-data fetch only — no DOM/chart-instance interaction, so it's
   safe to kick off before the chart container even exists (i.e. in parallel
   with the DexScreener pair-search below). Independent try/catch from that
   search: a failure here never blocks or breaks the pair-search, and vice
   versa (see _lmtdRenderChartData). Races the fetch against a 12s timeout so
   a hung request can't leave the loading state stuck forever. */
async function _lmtdFetchChartData(addr, tf, pairAddr){
  var tfParam = _LMTD_TF_MAP[tf] || '5m';
  var url = '/api/chart/'+encodeURIComponent(addr)+'?tf='+tfParam;
  // pairAddr (already known from the table row that was clicked) lets the
  // backend skip its own DexScreener round-trip to resolve it -- that's the
  // slow part of a cold chart load, so passing it through is what actually
  // makes the chart appear instantly instead of "a few seconds later".
  if(pairAddr) url += '&pair='+encodeURIComponent(pairAddr);
  var fetchPromise = fetch(url)
    .then(function(x){return x.json();})
    .catch(function(){return null;});
  var timeoutPromise = new Promise(function(resolve){
    setTimeout(function(){ resolve(null); }, _LMTD_CHART_FETCH_TIMEOUT);
  });
  return await Promise.race([fetchPromise, timeoutPromise]);
}

/* Starts (or reuses an already in-flight/just-finished) chart-data fetch for
   mint+tf. Called both by the skeleton render (as soon as the mint is known,
   before any metadata exists) and by the follow-up render once metadata
   arrives -- the second call reuses the same promise instead of firing a
   second network request, so switching from skeleton to full render never
   re-triggers (or re-delays) the chart. */
function _lmtdGetChartPromise(addr, tf, pairAddr){
  if(_lmtdChartFetch && _lmtdChartFetch.mint === addr && _lmtdChartFetch.tf === tf){
    return _lmtdChartFetch.promise;
  }
  var p = _lmtdFetchChartData(addr, tf, pairAddr);
  _lmtdChartFetch = {mint: addr, tf: tf, promise: p};
  return p;
}

/* Pair-metadata lookup by symbol — routed through the backend's cached,
   429-backoff-protected DexScreener proxy (/api/dexscreener/search, the
   same endpoint the global token search uses) instead of an unproxied,
   uncached, timeout-less direct browser call to DexScreener. Races against
   the same 12s cap as the chart fetch so a slow/hung upstream can't leave
   the modal stuck — returns null on timeout or network failure. */
async function _lmtdSearchPair(symbol){
  var fetchPromise = fetch('/api/dexscreener/search?q='+encodeURIComponent(symbol))
    .then(function(x){return x.json();})
    .catch(function(){return null;});
  var timeoutPromise = new Promise(function(resolve){
    setTimeout(function(){ resolve(null); }, _LMTD_CHART_FETCH_TIMEOUT);
  });
  return await Promise.race([fetchPromise, timeoutPromise]);
}

/* Direct mint lookup — used instead of _lmtdSearchPair whenever the mint
   address is already known (normal row click, or a global-search result).
   One exact match against /api/token/info/<mint> instead of a symbol
   search that can return multiple same-named tokens across chains/pools
   and needs post-filtering. Same cache/backoff (_dex_get) and 12s race as
   the other lookups here. */
async function _lmtdFetchTokenInfo(addr){
  var fetchPromise = fetch('/api/token/info/'+encodeURIComponent(addr))
    .then(function(x){return x.json();})
    .catch(function(){return null;});
  var timeoutPromise = new Promise(function(resolve){
    setTimeout(function(){ resolve(null); }, _LMTD_CHART_FETCH_TIMEOUT);
  });
  return await Promise.race([fetchPromise, timeoutPromise]);
}

/* Placeholder pair shape used to render the modal (chart + header) the
   instant a row is clicked, before any metadata fetch has resolved -- only
   needs a symbol + mint + (if already known from the table row) pair
   address. Everything else renders as '—' via the existing
   _fmtPrice/_fmtNum null-handling until the real pair data replaces it. */
function _lmtdSkeletonPair(symbol, addr, pairAddr){
  return {
    baseToken:   {symbol: symbol || '', name: symbol || '', address: addr || ''},
    info:        {imageUrl: ''},
    priceUsd:    null,
    priceChange: {},
    marketCap:   null,
    fdv:         null,
    volume:      {h24: null},
    liquidity:   {usd: null},
    txns:        {h24: null},
    pairAddress: pairAddr || '',
  };
}

/* Adapts /api/token/info/<mint>'s flat response into the DexScreener
   pair shape _lmtdRenderModal/_lmtdStatTilesHtml/_lmtdSidePanelHtml
   already expect, so the rest of the modal needs no changes. */
function _lmtdPairFromTokenInfo(d){
  return {
    baseToken:   {symbol: d.symbol || '', name: d.name || '', address: d.address || ''},
    info:        {imageUrl: d.image_url || ''},
    priceUsd:    d.price_usd,
    priceChange: d.price_change || {},
    marketCap:   d.market_cap,
    fdv:         d.fdv,
    volume:      {h24: d.volume_24h},
    liquidity:   {usd: d.liquidity_usd},
    txns:        {h24: {buys: d.buyers_24h, sells: d.sellers_24h}},
    pairAddress: d.pair_address || '',
  };
}

async function showTokenCard(symbol, knownAddr, knownPair){
  var modal = document.getElementById('lm-token-modal');
  var body  = document.getElementById('lm-modal-body');
  if(modal) modal.style.display = 'flex'; // no #lm-token-modal on the standalone /token page
  var card = document.querySelector('.lm-modal-card');
  if(card){ card.style.transition=''; card.style.transform=''; } // clear any leftover swipe-to-dismiss drag state
  _lmtdLayout = 'focus';
  _lmtdTf     = '5m';
  _lmtdSide   = 'buy';
  _lmtdHoldersTotal = null;
  _lmtdFetchBalance();
  _lmtdActiveMint = knownAddr || '';
  if(knownAddr) _lmtdLoadTokenSafety(knownAddr);
  if(knownAddr){
    // Mint already known from the table-row click — render the chart (and a
    // placeholder header/stats) immediately instead of waiting behind the
    // token-info fetch below. _lmtdRenderModal() starts the chart fetch via
    // _lmtdGetChartPromise(); the metadata fetch below runs fully in
    // parallel and, once it resolves, re-renders with real data — reusing
    // that same chart fetch/result instead of starting a second one.
    // knownPair (also already on the table row) lets that chart fetch skip
    // the backend's own pair-address lookup too — see _lmtdFetchChartData.
    _lmtdSymbol = symbol || '';
    _lmtdPair   = _lmtdSkeletonPair(symbol, knownAddr, knownPair);
    _lmtdRenderModal();
  } else {
    body.innerHTML = '<div style="text-align:center;padding:60px 0">'
      +'<div style="width:30px;height:30px;border:3px solid #16191f;border-top-color:#f7b955;border-radius:50%;margin:0 auto 14px;animation:tcSpin .8s linear infinite"></div>'
      +'<div style="color:#565d68;font-size:13px;font-family:\'JetBrains Mono\',monospace">Loading…</div>'
      +'</div>';
  }
  try{
    var p;
    if(knownAddr){
      // Mint already known — exact single-token lookup, no symbol-search ambiguity.
      var info = await _lmtdFetchTokenInfo(knownAddr);
      if(info === null){
        if(!_lmtdChart) body.innerHTML='<div style="text-align:center;padding:48px 20px;color:#ff4d6a;font-size:13px;font-family:\'JetBrains Mono\',monospace">Token lookup timed out — try again</div>';
        return;
      }
      if(!info.ok){
        if(!_lmtdChart) body.innerHTML='<div style="text-align:center;padding:48px 20px;color:#565d68;font-size:13px">No Solana pair found for $'+_esc(symbol)+'</div>';
        return;
      }
      p = _lmtdPairFromTokenInfo(info);
    } else {
      // No pre-known address (e.g. opened via ?token= URL param) — fall
      // back to the symbol search.
      var d = await _lmtdSearchPair(symbol);
      if(d === null){
        body.innerHTML='<div style="text-align:center;padding:48px 20px;color:#ff4d6a;font-size:13px;font-family:\'JetBrains Mono\',monospace">Token lookup timed out — try again</div>';
        return;
      }
      p = (d.pairs||[]).find(function(x){ return x.chainId==='solana'; });
      if(!p){
        body.innerHTML='<div style="text-align:center;padding:48px 20px;color:#565d68;font-size:13px">No Solana pair found for $'+_esc(symbol)+'</div>';
        return;
      }
    }
    _lmtdPair   = p;
    _lmtdSymbol = (p.baseToken&&p.baseToken.symbol)||symbol;
    // No pre-known address (e.g. opened via ?token= URL param, not a row
    // click) — _lmtdActiveMint is only set now; _lmtdRenderModal() below
    // starts the chart fetch itself since nothing was pre-started for it.
    if(!knownAddr){
      _lmtdActiveMint = (p.baseToken&&p.baseToken.address)||'';
      if(_lmtdActiveMint) _lmtdLoadTokenSafety(_lmtdActiveMint);
    }
    _lmtdRenderModal();
  }catch(e){
    if(!_lmtdChart) body.innerHTML='<div style="text-align:center;padding:48px 20px;color:#ff4d6a;font-size:13px;font-family:\'JetBrains Mono\',monospace">Failed to load token data</div>';
  }
}

function _lmtdCloseModal(){
  document.getElementById('lm-token-modal').style.display = 'none';
  if(_lmtdChart){ try{ _lmtdChart.remove(); }catch(e){} _lmtdChart=null; _lmtdSeries=null; _lmtdVolSeries=null; }
  if(_lmtdFomoTimer){ clearInterval(_lmtdFomoTimer); _lmtdFomoTimer=null; }
  _lmtdPriceLine = null;
  _lmtdActiveMint = ''; // any fetch still in flight for the closed token now reads as stale
}

/* ── SWIPE-TO-DISMISS (token detail modal) — same vanilla touchstart/
   touchmove/touchend pattern as _attachSwipeToDelete() (static/dashboard.js
   ~line 6272): dragging .lm-modal-card down moves it with the finger;
   releasing past DISMISS_DISTANCE, or with a fast enough downward flick
   (DISMISS_VELOCITY), closes it via _lmtdCloseModal() -- otherwise it
   springs back into place. Only wired up when #lm-token-modal exists: on
   the standalone /token page .lm-modal-card IS the page, there's no
   overlay to dismiss it into. ── */
(function(){
  var overlay = document.getElementById('lm-token-modal');
  var card    = document.querySelector('.lm-modal-card');
  if(!overlay || !card) return;
  var DISMISS_DISTANCE = 100;  // px
  var DISMISS_VELOCITY = 0.5;  // px/ms
  var startX=0, startY=0, lastY=0, lastT=0, lastDy=0, velocity=0;
  var dragging=false, verticalDown=null, moved=false;

  function setTranslate(y, animate){
    card.style.transition = animate ? 'transform .2s ease' : 'none';
    card.style.transform = 'translateY('+y+'px)';
  }

  card.addEventListener('touchstart', function(e){
    if(e.touches.length!==1) return;
    startX = e.touches[0].clientX;
    startY = lastY = e.touches[0].clientY;
    lastT = Date.now();
    velocity = 0; lastDy = 0;
    dragging = true; verticalDown = null; moved = false;
  }, {passive:true});

  card.addEventListener('touchmove', function(e){
    if(!dragging) return;
    var x = e.touches[0].clientX, y = e.touches[0].clientY;
    var dx = x-startX, dy = y-startY;
    if(verticalDown===null && (Math.abs(dx)>6||Math.abs(dy)>6)){
      // Only start the dismiss-drag if the modal's own scroll is already at
      // the top -- otherwise this is someone scrolling the modal content
      // down-then-up, not trying to dismiss it. scrollTop<=0 (not ===0)
      // to tolerate iOS Safari's negative scrollTop during rubber-banding.
      verticalDown = Math.abs(dy)>Math.abs(dx) && dy>0 && overlay.scrollTop<=0;
    }
    if(verticalDown){
      e.preventDefault(); // only suppress scroll/chart-pan once confirmed a downward drag
      moved = true;
      var now = Date.now(), dt = now-lastT;
      if(dt>0) velocity = (y-lastY)/dt;
      lastY = y; lastT = now; lastDy = dy;
      setTranslate(dy, false);
    }
  }, {passive:false});

  function endDrag(){
    if(!dragging) return;
    dragging = false;
    if(verticalDown && moved){
      if(lastDy>DISMISS_DISTANCE || velocity>DISMISS_VELOCITY) _lmtdCloseModal();
      else setTranslate(0,true);
    }
    verticalDown = null; moved = false;
  }
  card.addEventListener('touchend', endDrag, {passive:true});
  card.addEventListener('touchcancel', endDrag, {passive:true});
})();

function _lmtdRenderModal(){
  var p    = _lmtdPair;
  var body = document.getElementById('lm-modal-body');
  var sym  = (p.baseToken&&p.baseToken.symbol)||_lmtdSymbol;
  var name = (p.baseToken&&p.baseToken.name)||sym;
  var addr = (p.baseToken&&p.baseToken.address)||'';
  var imgUrl = p.info&&p.info.imageUrl?p.info.imageUrl:'';
  var logo = imgUrl
    ? '<img class="lmtd-logo" src="'+_esc(imgUrl)+'">'
    : '<div class="lmtd-logo-ph">'+_esc(sym.slice(0,2))+'</div>';

  var price    = _fmtPrice(p.priceUsd);
  var chg24    = p.priceChange&&p.priceChange.h24!=null?p.priceChange.h24:null;
  var chgColor = chg24!=null?(chg24>=0?'var(--green)':'var(--red)'):'var(--muted)';
  var chgStr   = chg24!=null?(chg24>=0?'+':'')+chg24.toFixed(2)+'%':'—';

  var tfHtml = ['1m','5m','15m','1H','4H','1D'].map(function(tf){
    return '<button class="lmtd-tf-btn'+(tf===_lmtdTf?' active':'')+'" onclick="_lmtdSetTf(\''+tf+'\')">'+tf+'</button>';
  }).join('');
  var styleToggleHtml = '<div class="lmtd-chart-style-toggle">'
    +'<button class="lmtd-style-btn'+(_lmtdChartStyle==='candles'?' active':'')+'" onclick="_lmtdSetChartStyle(\'candles\')" title="Candlestick chart">Candles</button>'
    +'<button class="lmtd-style-btn'+(_lmtdChartStyle==='fomo'?' active':'')+'" onclick="_lmtdSetChartStyle(\'fomo\')" title="Live step chart">Live</button>'
    +'</div>';

  var headerHtml =
    '<div class="lmtd-header">'
      +logo
      +'<div class="lmtd-title-wrap">'
        +'<div class="lmtd-name">'
          +'<span class="lmtd-name-text">'+_esc(name||sym)+'</span>'
          +'<span class="lmtd-chain-badge">SOLANA</span>'
          +'<span class="lmtd-live-dot-wrap"><span class="lmtd-live-dot"></span>LIVE</span>'
        +'</div>'
        +'<div class="lmtd-sym">$'+_esc(sym)+'</div>'
      +'</div>'
      +'<div class="lmtd-layout-toggle">'
        +'<button class="lmtd-layout-btn'+(_lmtdLayout==='focus'?' active':'')+'" onclick="_lmtdSetLayout(\'focus\')">Focus</button>'
        +'<button class="lmtd-layout-btn'+(_lmtdLayout==='terminal'?' active':'')+'" onclick="_lmtdSetLayout(\'terminal\')">Terminal</button>'
        +'<button class="lmtd-layout-btn'+(_lmtdLayout==='holders'?' active':'')+'" id="lmtd-holders-tab-btn" onclick="_lmtdSetLayout(\'holders\')">Holders'+(_lmtdHoldersTotal!=null?' ('+_lmtdHoldersTotal+')':'')+'</button>'
      +'</div>'
    +'</div>'
    +'<div class="lmtd-hero">'
      +'<div class="lmtd-hero-price">'+price+'</div>'
      +'<div class="lmtd-hero-chg" style="color:'+chgColor+'">'+chgStr+' (24h)</div>'
    +'</div>'
    +'<div class="lmtd-tf-tabs">'+tfHtml+styleToggleHtml+'</div>'
    +(addr ? (
      '<div class="lmtd-mint-row">'
        +'<span class="lmtd-mint-label">Mint</span>'
        +'<span class="lmtd-mint-addr" id="lmtd-mint-addr" data-full="'+_esc(addr)+'">'+_esc(addr.slice(0,4)+'...'+addr.slice(-4))+'</span>'
        +'<button class="lmtd-mint-copy" onclick="_lmtdCopyMint()">Copy</button>'
        +'<span class="lmtd-mint-msg" id="lmtd-mint-msg"></span>'
      +'</div>'
      +'<div class="lmtd-safety" id="lmtd-safety">'
        +'<span id="lmtd-safety-icon"></span>'
        +'<span id="lmtd-safety-text"></span>'
      +'</div>'
    ) : '');

  var chartHtml = '<div class="lmtd-chart-container" id="lmtd-chart-container">'
    +'<div class="lmtd-chart-loading" id="lmtd-chart-loading">Loading chart…</div>'
    +'</div>';

  var bodyHtml;
  if(_lmtdLayout === 'focus'){
    bodyHtml = headerHtml
      +'<div class="lmtd-chart-wrap">'+chartHtml+'</div>'
      +'<div class="lmtd-stats-focus">'+_lmtdStatTilesHtml(p)+'</div>'
      +'<div class="lmtd-trade-cta"><button class="lmtd-trade-cta-btn" onclick="_lmtdSetLayout(\'terminal\')">Trade</button></div>';
  } else if(_lmtdLayout === 'terminal'){
    bodyHtml = headerHtml
      +'<div class="lmtd-terminal">'
        +'<div class="lmtd-terminal-chart">'+chartHtml+'</div>'
        +'<div class="lmtd-terminal-side"><div id="lmtd-terminal-side-inner">'+_lmtdSidePanelHtml(p, sym, addr)+'</div></div>'
      +'</div>';
  } else { // holders
    bodyHtml = headerHtml
      +'<div class="lmtd-holders-wrap" id="lmtd-holders-wrap"><div class="lmtd-holders-loading">Loading holders…</div></div>';
  }
  body.innerHTML = bodyHtml;
  _lmtdRenderSafetyBadge(); // reapplies cached safety data if the fetch (fired once from showTokenCard) already resolved -- headerHtml, and the badge in it, gets rebuilt on every layout switch
  if(_lmtdLayout !== 'holders'){
    _lmtdInitChart();
    _lmtdLoadChartData(); // reuses an in-flight/cached fetch for this mint+tf if one already exists
    if(_lmtdChartStyle === 'fomo') _lmtdFomoLiveLoop(addr || _lmtdActiveMint);
  }
  if(_lmtdLayout === 'terminal') _lmtdWireSidePanel(sym, addr);
  if(_lmtdLayout === 'holders') _lmtdRenderHoldersTab(addr);
}

/* Safety badge -- fetched independently of the DexScreener pair lookup
   (fires immediately from showTokenCard(), not gated on that succeeding).
   Purely informational, never disables Buy/Sell. Same visual language and
   thresholds as the removed friends.html's token-detail safety badge
   (git 75ad403~1: _frLoadTokenSafety). Cached per-mint since headerHtml
   (and the badge DOM inside it) gets rebuilt on every layout switch. */
var _lmtdSafetyMint = '';
var _lmtdSafetyData = null;
function _lmtdRenderSafetyBadge(){
  var badge  = document.getElementById('lmtd-safety');
  var iconEl = document.getElementById('lmtd-safety-icon');
  var textEl = document.getElementById('lmtd-safety-text');
  if(!badge || !textEl) return;
  if(_lmtdSafetyMint !== _lmtdActiveMint || !_lmtdSafetyData){
    badge.style.display = 'none';
    return;
  }
  var d = _lmtdSafetyData;
  badge.classList.remove('risky', 'safe');
  if(d.is_risky){
    var reasons = [];
    if(d.mint_authority_active)   reasons.push('Mint authority active');
    if(d.freeze_authority_active) reasons.push('Freeze authority active');
    if(d.lp_locked_pct < 50)      reasons.push('Only '+d.lp_locked_pct.toFixed(0)+'% LP locked');
    badge.classList.add('risky');
    iconEl.textContent = '⚠️';
    textEl.textContent = reasons.join(' · ') || 'Risky token';
  } else {
    badge.classList.add('safe');
    iconEl.textContent = '✓';
    textEl.textContent = 'Mint revoked · '+d.lp_locked_pct.toFixed(0)+'% LP locked';
  }
  badge.style.display = 'flex';
}
async function _lmtdLoadTokenSafety(addr){
  _lmtdSafetyMint = '';
  _lmtdSafetyData = null;
  try{
    var r = await fetch('/api/token/'+encodeURIComponent(addr)+'/safety');
    var d = await r.json();
    if(_lmtdActiveMint !== addr || !d.ok) return;
    _lmtdSafetyMint = addr;
    _lmtdSafetyData = d;
    _lmtdRenderSafetyBadge();
  }catch(e){}
}

/* mint-adres kopiëren — zelfde clipboard+fallback-logica als
   templates/token.html's copyMint()/_fallbackCopy(), hernoemd naar het
   _lmtd-namespace van deze modal. Adres wordt verkort getoond
   (data-full bevat het volledige adres om te kopiëren). */
function _lmtdCopyMint(){
  var el  = document.getElementById('lmtd-mint-addr');
  var msg = document.getElementById('lmtd-mint-msg');
  if(!el) return;
  var addr = el.dataset.full || el.textContent;
  var done = function(){
    if(msg){ msg.textContent = '✓ Copied'; setTimeout(function(){ msg.textContent = ''; }, 2000); }
  };
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(addr).then(done).catch(function(){ _lmtdFallbackCopyMint(addr); done(); });
  } else {
    _lmtdFallbackCopyMint(addr); done();
  }
}
function _lmtdFallbackCopyMint(t){
  var ta = document.createElement('textarea');
  ta.value = t; ta.style.cssText = 'position:fixed;opacity:0';
  document.body.appendChild(ta); ta.select();
  try{ document.execCommand('copy'); }catch(e){}
  document.body.removeChild(ta);
}

/* 5-tile stat row (Focus layout): Volume 24h, Liquidity, Market Cap, Holders, Buys/Sells ratio.
   Holders has no data source anywhere in this codebase (checked dashboard.py + this file) —
   shown as "—" rather than fabricated. */
function _lmtdStatTilesHtml(p){
  var vol   = _fmtNum(p.volume&&p.volume.h24!=null?p.volume.h24:null);
  var liq   = _fmtNum(p.liquidity&&p.liquidity.usd!=null?p.liquidity.usd:null);
  var mcap  = _fmtNum(p.marketCap || p.fdv || null);
  var buys  = p.txns&&p.txns.h24 ? p.txns.h24.buys : 0;
  var sells = p.txns&&p.txns.h24 ? p.txns.h24.sells : 0;
  var total = buys+sells;
  var buyPct = total>0 ? Math.round(buys/total*100) : 50;
  var buysSellsVal = p.txns&&p.txns.h24
    ? buys+' / '+sells+'<div class="lmtd-ratio-bar"><div class="lmtd-ratio-buy" style="width:'+buyPct+'%"></div><div class="lmtd-ratio-sell" style="width:'+(100-buyPct)+'%"></div></div>'
    : '—';
  return [
    {l:'Volume 24h',  v:vol},
    {l:'Liquidity',   v:liq},
    {l:'Market Cap',  v:mcap},
    {l:'Holders',     v:'—'},
    {l:'Buys/Sells',  v:buysSellsVal}
  ].map(function(t){
    return '<div class="lmtd-stat-tile">'
      +'<div class="lmtd-stat-tile-label">'+t.l+'</div>'
      +'<div class="lmtd-stat-tile-value">'+t.v+'</div>'
      +'</div>';
  }).join('');
}

/* Terminal sidebar: Buy/Sell tab toggle, SOL input, quick-pct chips, action
   button, compact stats list. Sell only gets a MAX chip — /api/instant-trade
   always sells the full position server-side (amount is ignored for sell),
   so 25/50/75% sell buttons would be misleading. */
function _lmtdSidePanelHtml(p, sym, addr){
  var vol   = _fmtNum(p.volume&&p.volume.h24!=null?p.volume.h24:null);
  var liq   = _fmtNum(p.liquidity&&p.liquidity.usd!=null?p.liquidity.usd:null);
  var mcap  = _fmtNum(p.marketCap || p.fdv || null);
  var buys  = p.txns&&p.txns.h24 ? p.txns.h24.buys : 0;
  var sells = p.txns&&p.txns.h24 ? p.txns.h24.sells : 0;
  var pctChipsHtml = _lmtdSide === 'buy'
    ? [25,50,75,100].map(function(pct){
        return '<button class="lmtd-pct-btn" onclick="_lmtdSetPct('+pct+')">'+(pct===100?'MAX':pct+'%')+'</button>';
      }).join('')
    : '<button class="lmtd-pct-btn" onclick="_lmtdSetPct(100)">MAX</button>';
  return ''
    +'<div class="lmtd-side-tabs">'
      +'<button class="lmtd-side-tab buy'+(_lmtdSide==='buy'?' active':'')+'" onclick="_lmtdSetSide(\'buy\')">Buy</button>'
      +'<button class="lmtd-side-tab sell'+(_lmtdSide==='sell'?' active':'')+'" onclick="_lmtdSetSide(\'sell\')">Sell</button>'
    +'</div>'
    +'<div class="lmtd-sol-input-wrap">'
      +'<input class="lmtd-sol-input" id="lmtd-sol-input" type="number" min="0.001" step="0.1" value="0.1" onclick="event.stopPropagation()">'
      +'<span class="lmtd-sol-input-unit">SOL</span>'
    +'</div>'
    +'<div class="lmtd-pct-row">'+pctChipsHtml+'</div>'
    +'<button class="lmtd-action-btn '+_lmtdSide+'" id="lmtd-action-btn">'+(_lmtdSide==='buy'?'Buy':'Sell')+' $'+_esc(sym)+'</button>'
    +'<div class="lmtd-compact-stats">'
      +'<div class="lmtd-compact-stat-row"><span class="lmtd-compact-stat-label">Volume 24h</span><span class="lmtd-compact-stat-value">'+vol+'</span></div>'
      +'<div class="lmtd-compact-stat-row"><span class="lmtd-compact-stat-label">Liquidity</span><span class="lmtd-compact-stat-value">'+liq+'</span></div>'
      +'<div class="lmtd-compact-stat-row"><span class="lmtd-compact-stat-label">Market Cap</span><span class="lmtd-compact-stat-value">'+mcap+'</span></div>'
      +'<div class="lmtd-compact-stat-row"><span class="lmtd-compact-stat-label">Holders</span><span class="lmtd-compact-stat-value">—</span></div>'
      +'<div class="lmtd-compact-stat-row"><span class="lmtd-compact-stat-label">Buys/Sells</span><span class="lmtd-compact-stat-value">'+(p.txns&&p.txns.h24?buys+' / '+sells:'—')+'</span></div>'
    +'</div>';
}

function _lmtdWireSidePanel(sym, addr){
  var btn = document.getElementById('lmtd-action-btn');
  if(!btn) return;
  btn.addEventListener('click', function(){
    var input     = document.getElementById('lmtd-sol-input');
    var amount    = input ? input.value : '0.1';
    var pairAddr  = (_lmtdPair && _lmtdPair.pairAddress) || '';
    executeTrade(sym, pairAddr, _lmtdSide, amount, addr, btn);
  });
}

function _lmtdSetLayout(layout){
  _lmtdLayout = layout;
  _lmtdRenderModal(); // Focus/Terminal move the chart to a different container, so it re-inits
}

function _lmtdSetTf(tf){
  _lmtdTf = tf;
  document.querySelectorAll('.lmtd-tf-btn').forEach(function(b){
    b.classList.toggle('active', b.textContent===tf);
  });
  _lmtdLoadChartData(); // reuse the existing chart instance — just reload candles
}

function _lmtdSetChartStyle(style){
  if(style === _lmtdChartStyle) return;
  _lmtdChartStyle = style;
  document.querySelectorAll('.lmtd-style-btn').forEach(function(b){
    b.classList.toggle('active', b.getAttribute('onclick').indexOf("'"+style+"'") !== -1);
  });
  _lmtdInitChart();     // different series type — needs a fresh chart instance
  _lmtdLoadChartData();
  if(style === 'fomo'){
    _lmtdFomoLiveLoop((_lmtdPair && _lmtdPair.baseToken && _lmtdPair.baseToken.address) || _lmtdActiveMint);
  } else if(_lmtdFomoTimer){
    clearInterval(_lmtdFomoTimer); _lmtdFomoTimer = null;
  }
}

function _lmtdSetSide(side){
  var prevInput = document.getElementById('lmtd-sol-input');
  var prevVal   = prevInput ? prevInput.value : '0.1';
  _lmtdSide = side;
  var panel = document.getElementById('lmtd-terminal-side-inner');
  var p     = _lmtdPair;
  if(!panel || !p) return;
  var sym  = (p.baseToken&&p.baseToken.symbol)||_lmtdSymbol;
  var addr = (p.baseToken&&p.baseToken.address)||'';
  panel.innerHTML = _lmtdSidePanelHtml(p, sym, addr);
  document.getElementById('lmtd-sol-input').value = prevVal;
  _lmtdWireSidePanel(sym, addr);
}

function _lmtdSetPct(pct){
  var input = document.getElementById('lmtd-sol-input');
  if(!input) return;
  var bal = _lmtdSolBalance || 0;
  var amt = pct===100 ? Math.max(0, bal-0.01) : bal*pct/100;
  input.value = amt.toFixed(4);
}

/* ── holders tab ── */
function _lmtdFmtDuration(secs){
  if(secs==null) return '—';
  secs = Math.max(0, Math.floor(secs));
  var d = Math.floor(secs/86400);
  var h = Math.floor((secs%86400)/3600);
  var m = Math.floor((secs%3600)/60);
  if(d>0) return d+'d '+h+'h';
  if(h>0) return h+'h '+m+'m';
  if(m>0) return m+'m';
  return secs+'s';
}

function _lmtdUpdateHoldersTabLabel(){
  var btn = document.getElementById('lmtd-holders-tab-btn');
  if(btn) btn.textContent = 'Holders'+(_lmtdHoldersTotal!=null ? ' ('+_lmtdHoldersTotal+')' : '');
}

function _lmtdHolderRowHtml(h, curPrice){
  var avatar = h.avatar_url
    ? '<img class="lmtd-holder-avatar" src="'+_esc(h.avatar_url)+'">'
    : '<div class="lmtd-holder-avatar-ph">'+_esc((h.username||'?').slice(0,2))+'</div>';
  var verified = h.is_verified ? '<span class="lmtd-holder-verified">✓</span>' : '';
  var posValue = (curPrice>0 && h.amount!=null) ? _fmtNum(h.amount*curPrice) : '—';
  var pnlPct   = (curPrice>0 && h.buy_price>0) ? (curPrice-h.buy_price)/h.buy_price*100 : null;
  var pnlStr   = pnlPct==null ? '—' : (pnlPct>=0?'+':'')+pnlPct.toFixed(2)+'%';
  var pnlColor = pnlPct==null ? 'var(--muted)' : (pnlPct>=0?'var(--green)':'var(--red)');
  var postHtml = h.post
    ? '<div class="lmtd-holder-post">'+_esc(h.post.content)+' <span class="lmtd-holder-post-likes">♥ '+h.post.like_count+'</span></div>'
    : '';
  return '<div class="lmtd-holder-row">'
    +'<div class="lmtd-holder-left">'
      +avatar
      +'<div class="lmtd-holder-info">'
        +'<div class="lmtd-holder-name">'+_esc(h.username||'—')+verified+'</div>'
        +'<div class="lmtd-holder-duration">'+_lmtdFmtDuration(h.hold_duration)+'</div>'
        +postHtml
      +'</div>'
    +'</div>'
    +'<div class="lmtd-holder-right">'
      +'<div class="lmtd-holder-value">'+posValue+'</div>'
      +'<div class="lmtd-holder-pnl" style="color:'+pnlColor+'">'+pnlStr+'</div>'
    +'</div>'
  +'</div>';
}

/* Fetches /api/token/<mint>/holders and renders one row per holder -- also
   updates the "Holders (N)" tab label as soon as the total is known.
   curPrice comes from the chart's last candle close (_lmtdLastClose), not
   the DexScreener priceUsd used elsewhere in the modal, per spec. */
async function _lmtdHoldersHtml(addr){
  try{
    var r = await fetch('/api/token/'+encodeURIComponent(addr)+'/holders');
    var d = await r.json();
    if(!d.ok){
      _lmtdHoldersTotal = 0;
      _lmtdUpdateHoldersTabLabel();
      return '<div class="lmtd-holders-empty">Could not load holders</div>';
    }
    _lmtdHoldersTotal = d.total || 0;
    _lmtdUpdateHoldersTabLabel();
    if(!d.holders || !d.holders.length){
      return '<div class="lmtd-holders-empty">No holders found for this token yet</div>';
    }
    var curPrice = _lmtdLastClose || 0;
    return d.holders.map(function(h){ return _lmtdHolderRowHtml(h, curPrice); }).join('');
  }catch(e){
    _lmtdHoldersTotal = 0;
    _lmtdUpdateHoldersTabLabel();
    return '<div class="lmtd-holders-empty">Could not load holders</div>';
  }
}

/* Injects the holders list into the tab -- guards against the modal having
   moved to a different token or layout while the fetch was in flight (same
   staleness pattern as _lmtdRenderChartData). */
async function _lmtdRenderHoldersTab(addr){
  var html = await _lmtdHoldersHtml(addr);
  if(_lmtdLayout !== 'holders' || addr !== _lmtdActiveMint) return;
  var wrap = document.getElementById('lmtd-holders-wrap');
  if(wrap) wrap.innerHTML = html;
}

/* candlestick + volume chart — same LightweightCharts pattern as
   dashboard.html's _posChart, fed by the existing /api/chart/<mint> endpoint */
function _lmtdInitChart(){
  _lmtdChartGen++; // any chart-data fetch already in flight for the previous instance is now stale
  if(_lmtdChartStyle === 'fomo') return _lmtdInitFomoChart();
  return _lmtdInitCandleChart();
}

/* Shared LightweightCharts candlestick+volume chart constructor -- pulled
   out of _lmtdInitCandleChart() so both the modal below (unchanged
   behavior) and live_market.html's poster-card mini charts (see
   _lmtdInitEmbeddedChart() below, many simultaneous instances) build a
   chart the exact same way instead of two option-object copies drifting
   apart. Does no data fetching/rendering and keeps no global state of its
   own, so it's safe to call for any number of different containers at
   once. Returns null (instead of throwing) if the container doesn't exist
   or LightweightCharts hasn't loaded yet. */
function _lmtdCreateChart(containerId){
  var container = document.getElementById(containerId);
  if(!container || typeof LightweightCharts === 'undefined') return null;
  var chart = LightweightCharts.createChart(container, {
    width: container.clientWidth,
    height: container.clientHeight || 340,
    layout:{background:{type:'solid',color:'#16191f'},textColor:'#c7ccd4'},
    grid:{vertLines:{color:'#21252c'},horzLines:{color:'#21252c'}},
    crosshair:{mode:LightweightCharts.CrosshairMode.Normal},
    rightPriceScale:{borderColor:'#21252c',scaleMargins:{top:0.1,bottom:0.3}},
    timeScale:{borderColor:'#21252c',timeVisible:true,secondsVisible:false},
    handleScroll:true,handleScale:true
  });
  var series = chart.addCandlestickSeries({
    upColor:'#3ad29b',downColor:'#ff4d6a',borderVisible:false,
    wickUpColor:'#3ad29b',wickDownColor:'#ff4d6a'
  });
  var volSeries = chart.addHistogramSeries({priceFormat:{type:'volume'},priceScaleId:'lmtd-vol'});
  chart.priceScale('lmtd-vol').applyOptions({scaleMargins:{top:0.75,bottom:0}});
  var resizeObserver = new ResizeObserver(function(){
    if(container.clientWidth>0) chart.applyOptions({width:container.clientWidth,height:container.clientHeight});
  });
  resizeObserver.observe(container);
  return {chart:chart, series:series, volSeries:volSeries, resizeObserver:resizeObserver};
}

function _lmtdInitCandleChart(){
  if(_lmtdChart){ try{ _lmtdChart.remove(); }catch(e){} _lmtdChart=null; _lmtdSeries=null; _lmtdVolSeries=null; }
  var created = _lmtdCreateChart('lmtd-chart-container');
  if(!created) return;
  _lmtdChart    = created.chart;
  _lmtdSeries   = created.series;
  _lmtdVolSeries = created.volSeries;
  // created.resizeObserver is intentionally not kept -- _lmtdInitCandleChart()
  // never disconnected its ResizeObserver before this refactor either
  // (chart.remove() above tears down its DOM; a fresh observer was simply
  // created every call). Same behavior, unchanged.
}

/* Shared FOMO-style area chart constructor — same extraction pattern
   as _lmtdCreateChart() above, pulled out of _lmtdInitFomoChart() so both
   the modal (unchanged behavior) and _lmtdInitEmbeddedChart() below build
   this chart style identically. No volume series (the FOMO style never
   had one) and no global state. */
function _lmtdCreateFomoChart(containerId){
  var container = document.getElementById(containerId);
  if(!container || typeof LightweightCharts === 'undefined') return null;
  var chart = LightweightCharts.createChart(container, {
    width: container.clientWidth,
    height: container.clientHeight || 340,
    layout:{background:{type:'solid',color:'#0b0906'},textColor:'#e8dcc0'},
    grid:{vertLines:{color:'transparent'},horzLines:{color:'#1c1409'}},
    crosshair:{mode:LightweightCharts.CrosshairMode.Magnet},
    rightPriceScale:{borderColor:'#21252c',scaleMargins:{top:0.15,bottom:0.1}},
    timeScale:{borderColor:'#21252c',timeVisible:true,secondsVisible:false},
    handleScroll:true,handleScale:true
  });
  var series = chart.addAreaSeries({
    lineColor:'#f2b840', lineWidth:2, lineType: LightweightCharts.LineType.Curved,
    topColor:'rgba(242,184,64,.18)', bottomColor:'rgba(255,122,61,0)',
    priceLineVisible:false,
  });
  var resizeObserver = new ResizeObserver(function(){
    if(container.clientWidth>0) chart.applyOptions({width:container.clientWidth,height:container.clientHeight});
  });
  resizeObserver.observe(container);
  return {chart:chart, series:series, resizeObserver:resizeObserver};
}

/* "Live" area chart — same visual pattern popularized by apps like
   FOMO Family: a curved, gold-accented area series (Clean Editorial theme)
   with a gradient fill, plus a dashed price-line with a floating label
   pinned to the latest value. Built entirely with LightweightCharts features already
   in use elsewhere in this file (candlesticks, the PNL area chart) — no new
   library, just a different series type + createPriceLine(). Sourced from
   the same /api/chart/<mint> candle data, using each candle's close price
   as one point on the line (no separate backend endpoint needed). */
function _lmtdInitFomoChart(){
  if(_lmtdChart){ try{ _lmtdChart.remove(); }catch(e){} _lmtdChart=null; _lmtdSeries=null; _lmtdVolSeries=null; _lmtdPriceLine=null; }
  var created = _lmtdCreateFomoChart('lmtd-chart-container');
  if(!created) return;
  _lmtdChart  = created.chart;
  _lmtdSeries = created.series;
  // created.resizeObserver intentionally not kept -- same reasoning as
  // _lmtdInitCandleChart() above, unchanged from before this refactor.
}

/* Embedded, "live" mini chart for live_market.html's poster cards -- same
   FOMO-style area look + gradient fill + dashed price-line as the
   modal's Live chart style (_lmtdInitFomoChart() above), via the shared
   _lmtdCreateFomoChart() constructor, but owning its own series/timer
   state locally instead of the modal's globals, so many can run at once
   (one per visible poster card). Re-fetches and re-renders every 5s while
   mounted -- same cadence/approach as the modal's _lmtdFomoLiveLoop(), the
   closest a REST-polling setup gets to a true live tick feed -- and stops
   the moment destroy() is called. chain is accepted for parity with how
   every other mint-scoped call in this app threads chain through, even
   though /api/chart/<mint> is Solana-only today: a BSC poster card gets no
   chart at all (returns null) rather than a broken one. Returns
   {destroy()} for the caller to tear down (see live_market.html's
   IntersectionObserver), or null if the container/library/chain isn't
   available. */
function _lmtdInitEmbeddedChart(containerId, mint, chain, onResult){
  if(chain && chain !== 'solana') return null;
  var created = _lmtdCreateFomoChart(containerId);
  if(!created) return null;
  // Transparent background so the poster card's own banner art shows
  // through behind the chart -- applied here, after creation, rather than
  // changed in _lmtdCreateFomoChart() itself, so the modal's chart (which
  // wants its solid #16191f panel) is completely unaffected.
  try{ created.chart.applyOptions({layout:{background:{type:'solid', color:'transparent'}}}); }catch(e){}
  var destroyed      = false;
  var priceLine       = null;
  var timer           = null;
  var firstReported   = false;

  // onResult(r, isFirst) -- optional, lets the caller (live_market.html's
  // chart-init queue) know when this card's first fetch has settled, so it
  // can free up a concurrency slot for the next queued card, and show/hide
  // its own "not enough data yet" state. Called at most once with isFirst
  // true; guaranteed to fire even if destroy() happens before the first
  // fetch resolves, so a card scrolled away mid-fetch never leaves the
  // queue permanently short a slot.
  function reportFirst(r){
    if(firstReported) return;
    firstReported = true;
    if(typeof onResult === 'function') onResult(r || null, true);
  }

  function renderOnce(isFirst){
    _lmtdFetchChartData(mint, '5m', '').then(function(r){
      if(destroyed) return;
      if(isFirst) reportFirst(r);
      else if(typeof onResult === 'function') onResult(r, false);
      if(!r || !r.candles || !r.candles.length) return;
      try{
        var linePoints = r.candles.map(function(c){ return {time:c.t, value:c.c}; });
        created.series.setData(linePoints);
        var lastPoint = linePoints[linePoints.length-1];
        if(priceLine){ try{ created.series.removePriceLine(priceLine); }catch(e){} }
        priceLine = created.series.createPriceLine({
          price: lastPoint.value,
          color: '#ff7a3d',
          lineWidth: 1,
          lineStyle: LightweightCharts.LineStyle.Dashed,
          axisLabelVisible: true,
          title: _fmtPrice(lastPoint.value),
        });
        created.chart.timeScale().fitContent();
      }catch(e){}
    });
  }

  renderOnce(true);
  timer = setInterval(function(){
    if(destroyed){ clearInterval(timer); return; }
    renderOnce(false);
  }, 5000);

  return {
    destroy: function(){
      destroyed = true;
      reportFirst(null); // release a pending queue slot even if torn down before the first fetch resolved
      if(timer){ clearInterval(timer); timer=null; }
      try{ created.resizeObserver.disconnect(); }catch(e){}
      try{ created.chart.remove(); }catch(e){}
    }
  };
}

/* Restarts (or stops) the ~5s live-refresh loop that keeps the fomo chart's
   last point moving while that style + the modal are both still active —
   the closest a REST-polling setup gets to the true tick-by-tick feed a
   dedicated WebSocket would give, without standing up new infrastructure. */
function _lmtdFomoLiveLoop(mint){
  if(_lmtdFomoTimer){ clearInterval(_lmtdFomoTimer); _lmtdFomoTimer=null; }
  if(_lmtdChartStyle !== 'fomo') return;
  _lmtdFomoTimer = setInterval(function(){
    if(_lmtdChartStyle !== 'fomo' || mint !== _lmtdActiveMint || !_lmtdChart){
      clearInterval(_lmtdFomoTimer); _lmtdFomoTimer=null; return;
    }
    var pairAddr = (_lmtdPair && _lmtdPair.pairAddress) || '';
    _lmtdRenderChartData(_lmtdGetChartPromise(mint, _lmtdTf, pairAddr), mint);
  }, 5000);
}

/* Awaits a chart-data promise (already in flight — started in parallel with
   the pair-search — or freshly created) and renders it into the existing
   chart instance. Fully independent of the pair-search path: a failure here
   only ever affects the chart's own loading/unavailable state.
   forMint is the mint this fetch was started for — re-checked against
   _lmtdActiveMint once the data lands, so a slow/stale fetch from a token
   the user has since navigated away from (switched tokens, or closed the
   modal) is silently dropped instead of rendering into the wrong chart. */
async function _lmtdRenderChartData(dataPromise, forMint){
  var myGen = _lmtdChartGen; // snapshot -- if _lmtdInitChart() runs again before this resolves, our chart/series is gone
  var loadEl = document.getElementById('lmtd-chart-loading');
  if(loadEl){ loadEl.textContent='Loading chart…'; loadEl.style.display='flex'; }
  if(!_lmtdChart) return;
  var r = await dataPromise;
  if(forMint !== _lmtdActiveMint) return; // stale — modal has moved on since this fetch started
  if(myGen !== _lmtdChartGen) return; // stale — chart/series was torn down and recreated while we were awaiting
  if(r && r.candles && r.candles.length){
    try{
      if(_lmtdChartStyle === 'fomo'){
        var linePoints = r.candles.map(function(c){ return {time:c.t, value:c.c}; });
        _lmtdSeries.setData(linePoints);
        var lastPoint = linePoints[linePoints.length-1];
        _lmtdLastClose = lastPoint.value;
        if(_lmtdPriceLine){ try{ _lmtdSeries.removePriceLine(_lmtdPriceLine); }catch(e){} }
        _lmtdPriceLine = _lmtdSeries.createPriceLine({
          price: lastPoint.value,
          color: '#ff7a3d',
          lineWidth: 1,
          lineStyle: LightweightCharts.LineStyle.Dashed,
          axisLabelVisible: true,
          title: _fmtPrice(lastPoint.value),
        });
      } else {
        _lmtdSeries.setData(r.candles.map(function(c){ return {time:c.t, open:c.o, high:c.h, low:c.l, close:c.c}; }));
        _lmtdVolSeries.setData(r.candles.map(function(c){ return {time:c.t, value:c.v, color: c.c>=c.o ? 'rgba(58,210,155,.45)' : 'rgba(255,77,106,.45)'}; }));
        _lmtdLastClose = r.candles[r.candles.length-1].c;
      }
      _lmtdChart.timeScale().fitContent();
      if(loadEl) loadEl.style.display='none';
    }catch(e){
      console.error('[lmtd] chart.setData failed', e);
      if(loadEl){ loadEl.textContent='Chart unavailable for this token'; loadEl.style.display='flex'; }
    }
  } else if(loadEl){
    loadEl.textContent = 'Chart unavailable for this token';
    loadEl.style.display = 'flex';
  }
}

/* Loads candles for the active mint+tf into the chart -- reuses an
   in-flight/cached fetch via _lmtdGetChartPromise() when one already exists
   (skeleton render, layout switch), otherwise starts a fresh one (timeframe
   switch, or the no-pre-known-address path). */
function _lmtdLoadChartData(){
  var addr = (_lmtdPair && _lmtdPair.baseToken && _lmtdPair.baseToken.address) || '';
  if(!addr || !_lmtdChart) return;
  var pairAddr = (_lmtdPair && _lmtdPair.pairAddress) || '';
  _lmtdRenderChartData(_lmtdGetChartPromise(addr, _lmtdTf, pairAddr), addr);
}

/* ── toast ── */
function _toast(msg, ok){
  var t = document.createElement('div');
  t.textContent = msg;
  t.style.cssText = 'position:fixed;bottom:28px;left:50%;transform:translateX(-50%) translateY(20px);'
    +'background:#101216;color:#eef1f5;border:1px solid #16191f;'
    +'border-radius:12px;padding:11px 20px;font-size:13px;font-weight:700;'
    +'font-family:\'JetBrains Mono\',monospace;z-index:9999;pointer-events:none;'
    +'opacity:0;transition:opacity .2s,transform .2s;white-space:nowrap;box-shadow:0 4px 24px rgba(0,0,0,.5)';
  document.body.appendChild(t);
  requestAnimationFrame(function(){
    t.style.opacity='1'; t.style.transform='translateX(-50%) translateY(0)';
    setTimeout(function(){
      t.style.opacity='0'; t.style.transform='translateX(-50%) translateY(12px)';
      setTimeout(function(){ t.remove(); }, 250);
    }, 3000);
  });
}

/* ── trade execution (modal) ── */
async function executeTrade(symbol, pairAddress, side, amountStr, tokenAddress, btn){
  var amount = parseFloat(amountStr);
  if(!amount||amount<=0){ _toast('Enter a valid SOL amount', false); return; }
  var origHtml = btn ? btn.innerHTML : '';
  var origBg   = btn ? btn.style.background : '';
  var spinner  = '<span style="display:inline-block;width:12px;height:12px;border:2px solid rgba(0,0,0,.25);border-top-color:rgba(0,0,0,.6);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle"></span>';
  if(btn){ btn.innerHTML=spinner; btn.disabled=true; }
  var ok = await _doTrade(symbol, pairAddress, side, amount, tokenAddress);
  if(btn){ btn.innerHTML=origHtml; btn.disabled=false; btn.style.background=origBg; }
  if(ok) _toast(side==='buy' ? 'Buy order executed' : 'Sold', true);
}

/* ── helpers ── */
function _fmtPrice(p){
  if(!p) return '—';
  p = parseFloat(p);
  if(isNaN(p)||p<=0) return '—';
  if(p>=1) return '$'+p.toFixed(2);
  if(p>=0.0001) return '$'+p.toFixed(6);
  return '$'+p.toFixed(10).replace(/0+$/,'');
}
function _fmtNum(n){
  if(n==null||isNaN(n)) return '—';
  if(n>=1e9) return '$'+(n/1e9).toFixed(2)+'B';
  if(n>=1e6) return '$'+(n/1e6).toFixed(2)+'M';
  if(n>=1e3) return '$'+(n/1e3).toFixed(1)+'K';
  return '$'+n.toFixed(2);
}
function _esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ── auth headers ── */
var _lmCsrf         = (document.querySelector('meta[name="csrf-token"]')||{}).content||'';
var _lmClientSecret = (document.querySelector('meta[name="client-secret"]')||{}).content||'';
