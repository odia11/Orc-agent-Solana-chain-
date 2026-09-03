/* OrcAgent Live Market — "Pro terminal" desktop page controller.
   Talks to /api/market/scanner (server-side sort/filter), /api/market/tape
   (global buy/sell activity), and the existing token/wallet/trade/watchlist/
   copy-trade/leaderboard endpoints already used elsewhere in the app. */
(function(){
'use strict';

/* ── helpers ── */
function esc(s){
  return String(s==null?'':s).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function fmtUsd(n){
  n = Number(n)||0;
  if(!n) return '—';
  var sign = n<0?'-':''; n=Math.abs(n);
  if(n>=1e9) return sign+'$'+(n/1e9).toFixed(2)+'B';
  if(n>=1e6) return sign+'$'+(n/1e6).toFixed(2)+'M';
  if(n>=1e3) return sign+'$'+(n/1e3).toFixed(1)+'K';
  return sign+'$'+n.toFixed(0);
}
/* Trader PnL, in USD at the live SOL price -- t.total_pnl_usd is computed
   server-side from _sol_price_usd (null there means the price feed hasn't
   populated yet, not that PnL is zero), so this falls back to the raw SOL
   figure rather than ever showing a misleading "$0.00". */
function fmtTraderPnl(t){
  var usd = t.total_pnl_usd;
  if(usd != null){
    var sign = usd >= 0 ? '+' : '-';
    return sign + '$' + Math.abs(usd).toFixed(2);
  }
  var sol = Number(t.total_pnl||0);
  return (sol >= 0 ? '+' : '') + sol.toFixed(3) + ' SOL';
}
function fmtShort(n){
  n = Number(n)||0;
  if(n>=1000) return (n/1000)+'K';
  return String(n);
}
function fmtPrice(n){
  n = Number(n);
  if(n==null || isNaN(n)) return '—';
  if(n===0) return '$0.00';
  if(n>=1) return '$'+n.toFixed(2);
  if(n>=0.01) return '$'+n.toFixed(4);
  if(n>=0.0001) return '$'+n.toFixed(6);
  return '$'+n.toFixed(8);
}
function fmtPct(n){
  n = Number(n)||0;
  return (n>=0?'+':'')+n.toFixed(2)+'%';
}
function fmtAge(createdMs){
  if(!createdMs) return '?';
  var diff = Date.now()-createdMs;
  var h = diff/3600000;
  if(h<1) return Math.max(1,Math.round(diff/60000))+'m';
  if(h<24) return Math.round(h)+'h';
  return Math.round(h/24)+'d';
}
function fmtAgeSeconds(s){
  s = Math.max(0, Math.round(s||0));
  if(s<60) return s+'s';
  if(s<3600) return Math.round(s/60)+'m';
  if(s<86400) return Math.round(s/3600)+'h';
  return Math.round(s/86400)+'d';
}
function ratioStr(buys, sells){
  buys = buys||0; sells = sells||0;
  var total = buys+sells;
  if(!total) return '—';
  var bp = Math.round(buys/total*100);
  return bp+'% / '+(100-bp)+'%';
}
function authHeaders(){
  var csrf   = (document.querySelector('meta[name="csrf-token"]')||{}).content||'';
  var secret = (document.querySelector('meta[name="client-secret"]')||{}).content||'';
  var h = {'Content-Type':'application/json','X-CSRF-Token':csrf,'X-CSRFToken':csrf,'X-Requested-With':'XMLHttpRequest'};
  if(secret) h['X-API-Shared-Secret'] = secret;
  return h;
}
var _toastTimer = null;
function toast(msg){
  var el = document.getElementById('pt-toast');
  if(!el) return;
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(function(){ el.classList.remove('show'); }, 2600);
}
function showMsg(el, text, ok){
  if(!el) return;
  el.textContent = text;
  el.className = 'pt-buy-msg ' + (ok?'ok':'err');
  el.style.display = 'block';
}

/* ── mobile drawer/menu overlays (no-ops on desktop, where the classes
   toggled here have no matching CSS) ── */
function closeMobileOverlays(){
  // The nav drawer itself is now the shared navbar's (static/navbar.js) --
  // this only owns the filters drawer that's unique to this page.
  var left = document.getElementById('pt-left');
  var scrim = document.getElementById('pt-scrim');
  if(left) left.classList.remove('mobile-open');
  if(scrim) scrim.classList.remove('show');
}

/* ── state ── */
var ST = {
  sort: 'trending', minLiquidity: 25000, age: 'any',
  lpLocked: false, mintRevoked: false, hideHoneypots: false, verifiedSocials: false,
  tokens: [], counts: {}
};
var watchSet = new Set();
var _copyStatus = {copying:false, target:null};
var _wlEditMode = false;
var _sellArmed = {};
// Count of currently-open buy panels -- loadFeed() skips its poll while this
// is >0 (see loadFeed() below). Without this, the 15s auto-refresh replaces
// ST.tokens wholesale and rebuilds the entire card list from scratch
// (renderFeedList's el.innerHTML = ...), which both re-numbers every card's
// idx (breaking the open panel's own data-idx references) and can drop a
// card off the list entirely the moment its rank shifts out of the
// server's top-30 -- exactly the "I'm mid-purchase and the card vanishes"
// bug this fixes. A card that isn't in the middle of a purchase still
// refreshes normally.
var _openBuyPanelCount = 0;
var _feedInFlight = false;

var SORT_DEFS = [
  {key:'trending', label:'Trending'},
  {key:'gainers',  label:'Top gainers'},
  // +5% or more over 24h AND a $30K+ market cap -- server-computed in
  // api_market_scanner()'s uptrend_set, not just "gainers" re-labeled.
  {key:'uptrend',  label:'Uptrend (+5%, $30K+ MC)'},
  {key:'new',      label:'New pairs'},
  // Recently launched (any chain) but already past the riskiest early phase:
  // real 24h volume + real transaction activity -- server-computed in
  // api_market_scanner()'s graduated_set (GRADUATED_* constants).
  {key:'graduated', label:'Graduated'},
  {key:'volume',   label:'Volume leaders'},
  {key:'friends',  label:'Friends buying'}
];

/* ── chart (custom SVG: smooth cubic-bezier line, gradient fill, dotted
   current-price line, price pill, timeframe pills, time axis) ── */
var _chartTimers = {}; // idx -> {destroyed, mint, pair, tf, timer}

function buildSmoothPath(pts){
  if(pts.length<2) return '';
  var d = 'M'+pts[0].x.toFixed(2)+','+pts[0].y.toFixed(2);
  for(var i=0;i<pts.length-1;i++){
    var p0 = pts[i===0?0:i-1], p1 = pts[i], p2 = pts[i+1], p3 = pts[i+2]||p2;
    var c1x = p1.x+(p2.x-p0.x)/6, c1y = p1.y+(p2.y-p0.y)/6;
    var c2x = p2.x-(p3.x-p1.x)/6, c2y = p2.y-(p3.y-p1.y)/6;
    d += ' C'+c1x.toFixed(2)+','+c1y.toFixed(2)+' '+c2x.toFixed(2)+','+c2y.toFixed(2)+' '+p2.x.toFixed(2)+','+p2.y.toFixed(2);
  }
  return d;
}

function updateAxis(idx, candles){
  var axisEl = document.getElementById('pt-chart-axis-'+idx);
  if(!axisEl) return;
  if(!candles.length){ axisEl.innerHTML=''; return; }
  var n = candles.length;
  var picks = [0, Math.floor(n*0.25), Math.floor(n*0.5), Math.floor(n*0.75), n-1];
  var seen = {}, html = '';
  picks.forEach(function(i){
    if(seen[i]) return; seen[i]=true;
    var d = new Date(candles[i].t*1000);
    var hh = ('0'+d.getHours()).slice(-2);
    var mm = ('0'+d.getMinutes()).slice(-2);
    html += '<span>'+hh+':'+mm+'</span>';
  });
  axisEl.innerHTML = html;
}

function renderChartSvg(idx, candles, currentPrice){
  var svg  = document.getElementById('pt-chart-svg-'+idx);
  var wrap = document.getElementById('pt-chart-wrap-'+idx);
  if(!svg || !wrap) return;
  var w = wrap.clientWidth || 300;
  var h = 200;
  svg.setAttribute('viewBox', '0 0 '+w+' '+h);

  var oldPill = wrap.querySelector('.pt-price-pill');
  if(oldPill) oldPill.remove();

  if(!candles || candles.length<2){
    svg.innerHTML = '';
    if(!wrap.querySelector('.pt-chart-empty')){
      var emptyEl = document.createElement('div');
      emptyEl.className = 'pt-chart-empty';
      emptyEl.textContent = 'Not enough data yet';
      wrap.insertBefore(emptyEl, wrap.querySelector('.pt-chart-axis'));
    }
    updateAxis(idx, []);
    return;
  }
  var stale = wrap.querySelector('.pt-chart-empty');
  if(stale) stale.remove();

  var values = candles.map(function(c){ return c.c; });
  var min = Math.min.apply(null, values), max = Math.max.apply(null, values);
  if(min===max){ min = min*0.98; max = (max*1.02)||1; }
  var pad = (max-min)*0.12;
  min -= pad; max += pad;

  var n = candles.length;
  var pts = candles.map(function(c,i){
    var x = n===1 ? 0 : (i/(n-1))*w;
    var y = h - ((c.c-min)/(max-min))*h;
    return {x:x, y:y};
  });

  var linePath = buildSmoothPath(pts);
  var areaPath = linePath + ' L'+pts[pts.length-1].x.toFixed(2)+','+h+' L'+pts[0].x.toFixed(2)+','+h+' Z';

  var priceVal = (currentPrice!=null && currentPrice>0) ? currentPrice : values[values.length-1];
  var priceY = h - ((priceVal-min)/(max-min))*h;
  priceY = Math.max(2, Math.min(h-2, priceY));

  var gradId = 'pt-grad-'+idx;
  svg.innerHTML =
      '<defs><linearGradient id="'+gradId+'" x1="0" y1="0" x2="0" y2="1">'
    +   '<stop offset="0%" stop-color="#f7b955" stop-opacity="0.22"/>'
    +   '<stop offset="100%" stop-color="#f7b955" stop-opacity="0"/>'
    + '</linearGradient></defs>'
    + '<path d="'+areaPath+'" fill="url(#'+gradId+')" stroke="none"></path>'
    + '<line x1="0" y1="'+priceY.toFixed(2)+'" x2="'+w+'" y2="'+priceY.toFixed(2)+'" stroke="#f7b955" stroke-width="1" stroke-dasharray="3,4" opacity="0.55" vector-effect="non-scaling-stroke"></line>'
    + '<path d="'+linePath+'" fill="none" stroke="#f7b955" stroke-width="1.6" vector-effect="non-scaling-stroke" stroke-linecap="round"></path>';

  var pill = document.createElement('div');
  pill.className = 'pt-price-pill';
  pill.style.top = priceY+'px';
  pill.textContent = fmtPrice(priceVal);
  wrap.insertBefore(pill, wrap.querySelector('.pt-chart-axis'));

  updateAxis(idx, candles);
}

function fetchChart(mint, tf, pairAddr, chain){
  var url = '/api/chart/'+encodeURIComponent(mint)+'?tf='+encodeURIComponent(tf);
  if(pairAddr) url += '&pair='+encodeURIComponent(pairAddr);
  if(chain) url += '&chain='+encodeURIComponent(chain);
  return fetch(url).then(function(r){ return r.json(); }).catch(function(){ return null; });
}

function chartTick(idx){
  var st = _chartTimers[idx];
  if(!st || st.destroyed) return;
  fetchChart(st.mint, st.tf, st.pair, st.chain).then(function(r){
    if(!st || st.destroyed) return;
    if(r && r.candles) renderChartSvg(idx, r.candles, r.current_price);
  });
}

// `chain` defaults to 'solana' -- the API's own default -- so a caller that
// doesn't know/care about chain (there weren't any before this) still gets
// the exact prior behavior.
function mountChart(idx, mint, pairAddr, chain){
  if(_chartTimers[idx]) return;
  var st = {destroyed:false, mint:mint, pair:pairAddr, chain:(chain||'solana'), tf:'5m', timer:null};
  _chartTimers[idx] = st;
  chartTick(idx);
  st.timer = setInterval(function(){ chartTick(idx); }, 5000);
}
function unmountChart(idx){
  var st = _chartTimers[idx];
  if(!st) return;
  st.destroyed = true;
  if(st.timer) clearInterval(st.timer);
  delete _chartTimers[idx];
}
function setChartTf(idx, tf){
  var st = _chartTimers[idx];
  if(!st) return;
  st.tf = tf;
  chartTick(idx);
}

/* ── per-card lazy loading (safety badges, friends/holders footer) ── */
var _lazyDone = {};
var _cardObserver = null;

function fetchSafety(idx, mint){
  var el = document.getElementById('pt-safety-'+idx);
  fetch('/api/token/'+encodeURIComponent(mint)+'/safety', {credentials:'include'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(!el) return;
      if(!d || !d.ok){ el.innerHTML=''; return; }
      var lpOk = (d.lp_locked_pct||0) >= 50;
      var mintOk = !d.mint_authority_active && !d.freeze_authority_active;
      el.innerHTML = '<span class="pt-badge '+(lpOk?'ok':'bad')+'"><span class="ico">'+(lpOk?'✓':'✕')+'</span>LP</span>'
        + '<span class="pt-badge '+(mintOk?'ok':'bad')+'"><span class="ico">'+(mintOk?'✓':'✕')+'</span>Mint</span>';
    }).catch(function(){ if(el) el.innerHTML=''; });
}

function fetchFriends(idx, mint){
  var friendsEl = document.getElementById('pt-friends-'+idx);
  // Always shows something -- including "0 friends hold this" -- instead of
  // going blank when nobody you follow holds it, so the Friends section
  // reads as a real, always-there stat rather than something that only
  // appears sometimes.
  fetch('/api/token/'+encodeURIComponent(mint)+'/co-traders', {credentials:'include'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(!friendsEl) return;
      var users = (d && d.ok && d.users) || [];
      if(!users.length){
        friendsEl.innerHTML = '<span class="pt-friends-empty">👥 0 friends</span>';
        return;
      }
      var avs = users.slice(0,3).map(function(u){
        return u.avatar_url
          ? '<img src="'+esc(u.avatar_url)+'">'
          : '<div class="ph">'+esc((u.username||'?').slice(0,1).toUpperCase())+'</div>';
      }).join('');
      friendsEl.innerHTML = '<div class="pt-friend-avs">'+avs+'</div><span>'+users.length+' friend'+(users.length===1?'':'s')+'</span>';
    }).catch(function(){
      if(friendsEl) friendsEl.innerHTML = '<span class="pt-friends-empty">👥 0 friends</span>';
    });

  fetch('/api/token/'+encodeURIComponent(mint)+'/holders', {credentials:'include'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      var ftEl = document.getElementById('pt-ft-stats-'+idx);
      if(!ftEl || !d || !d.ok) return;
      var t = ST.tokens[Number(idx)];
      var txns = t ? (t.buys_24h+t.sells_24h) : 0;
      var txnsStr = txns >= 1000 ? (txns/1000).toFixed(1)+'K' : String(txns);
      var ratio = t ? ratioStr(t.buys_24h, t.sells_24h) : '—';
      // 'holders' here is a count of OrcAgent users with a position in this
      // token, NOT the real on-chain holder count (DexScreener's API, which
      // powers every other stat on this card, doesn't expose that) -- kept
      // as its own small chip, clearly scoped to "on OrcAgent" rather than
      // implying it's the token's total holder count.
      ftEl.innerHTML = '<span class="pt-ft-chip">👤 '+(d.platform_holders||0)+' on OrcAgent</span>'
        + '<span class="pt-ft-chip">'+txnsStr+' txns</span>'
        + '<span class="pt-ft-chip">'+ratio+'</span>';
    }).catch(function(){});
}

function activateCard(card){
  var idx = card.dataset.idx, mint = card.dataset.mint, pair = card.dataset.pair;
  var t = ST.tokens[Number(idx)];
  mountChart(idx, mint, pair, t ? t.chain : 'solana');
  var done = _lazyDone[idx] || (_lazyDone[idx] = {});
  if(!done.safety){ done.safety = true; fetchSafety(idx, mint); }
  if(!done.friends){ done.friends = true; fetchFriends(idx, mint); }
}

function observeCards(){
  var cards = document.querySelectorAll('.pt-card');
  if(_cardObserver) _cardObserver.disconnect();
  if(!('IntersectionObserver' in window)){
    cards.forEach(activateCard);
    return;
  }
  _cardObserver = new IntersectionObserver(function(entries){
    entries.forEach(function(entry){
      var idx = entry.target.dataset.idx;
      if(entry.isIntersecting) activateCard(entry.target);
      else unmountChart(idx);
    });
  }, {rootMargin:'250px 0px', threshold:0.01});
  cards.forEach(function(c){ _cardObserver.observe(c); });
}

function resetCardState(){
  Object.keys(_chartTimers).forEach(unmountChart);
  _lazyDone = {};
  _sellArmed = {};
}

/* ── markup builders ── */
function logoTile(imgUrl, symbol, cls, phCls){
  var initials = esc((symbol||'?').slice(0,2).toUpperCase());
  if(!imgUrl) return '<div class="'+phCls+'">'+initials+'</div>';
  return '<img class="'+cls+'" src="'+esc(imgUrl)+'" onerror="this.style.display=\'none\';this.nextElementSibling.style.display=\'flex\'">'
    + '<div class="'+phCls+'" style="display:none">'+initials+'</div>';
}
function statRow(lbl, val){
  return '<div class="pt-stat-row"><span class="pt-stat-lbl">'+lbl+'</span><span class="pt-stat-val mono">'+val+'</span></div>';
}
function starsHtml(score){
  var n = Math.max(0, Math.min(5, score||0));
  var cls = n>=4 ? 's-hi' : (n===3 ? 's-mid' : 's-lo');
  var str = '';
  for(var i=0;i<5;i++) str += i<n ? '★' : '☆';
  return '<span class="pt-stars '+cls+'">'+str+'</span>';
}
function tfPill(tf, label, active){
  return '<button class="pt-tf-pill'+(active?' active':'')+'" data-tf="'+tf+'">'+label+'</button>';
}
/* Which chain a token/trade lives on -- feeds a token's Buy/Sell routing
   (confirmBuy/handleSell below) as well as this badge, so a Solana token
   always spends SOL via /api/instant-trade, BSC always spends USDC via
   /api/bsc/trade/*, and Base/Arbitrum/Polygon/Robinhood Chain always spend
   their own chain's USD stablecoin via the generic /api/evm/trade/* (see
   EVM_TRADE_CHAINS below). Defaults to 'solana' for any candidate that
   omits it (every pre-multi-chain scanner response), so old cached
   responses never render as blank/unlabeled. */
var EVM_TRADE_CHAINS = {bsc:1, base:1, arbitrum:1, polygon:1, robinhood:1};
var CHAIN_LABELS = {bsc:'BSC', base:'BASE', arbitrum:'ARB', polygon:'POLY', robinhood:'HOOD'};
// Every EVM chain here trades against native USDC EXCEPT Robinhood Chain,
// whose own stablecoin is USDG (Global Dollar) -- USDC bridged there
// actually becomes USDG, there is no USDC on that chain at all. Getting
// this label wrong would tell a user they're spending a currency that
// doesn't exist on that chain.
var EVM_CURRENCY_LABELS = {robinhood:'USDG'};
function evmCurrencyLabel(chain){ return EVM_CURRENCY_LABELS[chain] || 'USDC'; }
function chainLabel(chain){ return CHAIN_LABELS[chain] || 'SOL'; }
function shortAddr(addr){
  addr = addr || '';
  return addr.length > 10 ? addr.slice(0, 4) + '…' + addr.slice(-4) : addr;
}
// Falls back to the legacy execCommand path when navigator.clipboard isn't
// available (older in-app webviews, non-HTTPS) rather than silently doing
// nothing -- copying the contract address is the entire point of this button.
function copyToClipboard(text){
  if(navigator.clipboard && navigator.clipboard.writeText){
    return navigator.clipboard.writeText(text);
  }
  return new Promise(function(resolve, reject){
    try{
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus(); ta.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      ok ? resolve() : reject(new Error('execCommand copy failed'));
    }catch(e){ reject(e); }
  });
}
function copyCA(mint, el){
  copyToClipboard(mint).then(function(){
    toast('Contract address copied');
    if(el){
      var textEl = el.querySelector('.pt-tok-ca-text');
      if(textEl){
        var orig = textEl.textContent;
        textEl.textContent = 'Copied!';
        setTimeout(function(){ textEl.textContent = orig; }, 1200);
      }
    }
  }).catch(function(){ toast('Could not copy — long-press the address instead'); });
}
function chainBadgeHtml(chain){
  var c = CHAIN_LABELS[chain] ? chain : 'solana';
  return '<span class="pt-chain-badge chain-'+c+'"><span class="pt-chain-dot"></span>'+chainLabel(c)+'</span>';
}

function storyHtml(t, idx){
  var down = (t.price_change_24h||0) < 0;
  return '<div class="pt-story" data-action="story" data-idx="'+idx+'">'
    + '<div class="pt-story-ring'+(down?' down':'')+'"><div class="pt-story-inner">'
    +   logoTile(t.image_url, t.symbol, 'pt-story-img', 'pt-story-img-ph')
    + '</div></div>'
    + '<div class="pt-story-name">$'+esc(t.symbol||'?')+'</div>'
    + '<div class="pt-story-chg mono '+(down?'down':'up')+'">'+fmtPct(t.price_change_24h)+'</div>'
    + '</div>';
}

function cardHtml(t, idx){
  var down = (t.price_change_24h||0) < 0;
  var isWatched = watchSet.has(t.mint);
  return '<div class="pt-card'+(t.score>=4?' hi':'')+'" id="pt-card-'+idx+'" data-mint="'+esc(t.mint)+'" data-idx="'+idx+'" data-pair="'+esc(t.pair_address||'')+'">'
    + '<div class="pt-card-hd">'
    +   logoTile(t.image_url, t.symbol, 'pt-tok-logo', 'pt-tok-logo-ph')
    +   '<div class="pt-tok-id"><div class="pt-tok-sym">$'+esc(t.symbol)+' '+starsHtml(t.score)+chainBadgeHtml(t.chain)+'</div>'
    +   '<div class="pt-tok-meta">'+esc(t.name||t.symbol)+' · '+fmtAge(t.pair_created_at)+' old</div>'
    +   '<div class="pt-tok-ca" data-action="copy-ca" data-mint="'+esc(t.mint)+'" title="'+esc(t.mint)+'">'
    +     '<span class="pt-tok-ca-text mono">'+esc(shortAddr(t.mint))+'</span>'
    +     '<span class="pt-tok-ca-icon">⧉</span>'
    +   '</div></div>'
    +   '<div class="pt-card-hd-right">'
    +     '<span id="pt-safety-'+idx+'"></span>'
    +     '<button class="pt-watch-btn'+(isWatched?' active':'')+'" data-action="watch" data-mint="'+esc(t.mint)+'" data-sym="'+esc(t.symbol)+'">'+(isWatched?'★':'☆')+'</button>'
    +   '</div>'
    + '</div>'
    + '<div class="pt-card-body">'
    +   '<div class="pt-card-stats">'
    +     '<div class="pt-price mono" id="pt-price-'+idx+'">'+fmtPrice(t.price_usd)+'</div>'
    +     '<div class="pt-chg mono '+(down?'down':'up')+'">'+fmtPct(t.price_change_24h)+' · 24h</div>'
    +     statRow('Liquidity', fmtUsd(t.liquidity_usd))
    +     statRow('Market cap', fmtUsd(t.market_cap))
    +     statRow('Volume 24h', fmtUsd(t.volume_24h))
    +     statRow('Buy / Sell', ratioStr(t.buys_24h, t.sells_24h))
    +     '<div class="pt-trade-btns">'
    +       '<button class="pt-buy-btn" data-action="buy-open" data-idx="'+idx+'">Buy</button>'
    +       '<button class="pt-sell-btn" data-action="sell" data-idx="'+idx+'">Sell</button>'
    +     '</div>'
    +     '<div class="pt-buy-panel" id="pt-buy-panel-'+idx+'" style="display:none"></div>'
    +   '</div>'
    +   '<div class="pt-chart-wrap" id="pt-chart-wrap-'+idx+'">'
    +     '<svg class="pt-chart-svg" id="pt-chart-svg-'+idx+'" preserveAspectRatio="none"></svg>'
    +     '<div class="pt-chart-live"><span class="pt-chart-live-dot"></span>LIVE</div>'
    +     '<div class="pt-chart-tfs" id="pt-chart-tfs-'+idx+'">'
    +       tfPill('1m','1M') + tfPill('5m','5M', true) + tfPill('1h','1H') + tfPill('D','1D')
    +     '</div>'
    +     '<div class="pt-chart-axis" id="pt-chart-axis-'+idx+'"></div>'
    +   '</div>'
    + '</div>'
    + '<div class="pt-card-ft">'
    +   '<div class="pt-friends" id="pt-friends-'+idx+'"></div>'
    +   '<div class="pt-card-ft-right mono" id="pt-ft-stats-'+idx+'">'+(t.buys_24h+t.sells_24h)+' txns · '+ratioStr(t.buys_24h,t.sells_24h)+'</div>'
    + '</div>'
    + '</div>';
}

/* ── left rail: sort / toggles / liquidity / age ── */
function renderSortList(){
  var el = document.getElementById('pt-sort-list');
  el.innerHTML = SORT_DEFS.map(function(s){
    var c = ST.counts[s.key]!=null ? ST.counts[s.key] : 0;
    return '<div class="pt-sort-row'+(ST.sort===s.key?' active':'')+'" data-sort="'+s.key+'">'
      + '<span>'+s.label+'</span><span class="pt-sort-count">'+c+'</span></div>';
  }).join('');
}
function setSort(s){ ST.sort = s; renderSortList(); loadFeed(); closeMobileOverlays(); }
function setAge(a){
  ST.age = a;
  document.querySelectorAll('.pt-age-chip').forEach(function(c){ c.classList.toggle('active', c.dataset.age===a); });
  loadFeed();
}
var _FILTER_KEYS = {lp_locked:'lpLocked', mint_revoked:'mintRevoked', hide_honeypots:'hideHoneypots', verified_socials:'verifiedSocials'};
function toggleFilter(btn){
  var stateKey = _FILTER_KEYS[btn.dataset.filter];
  ST[stateKey] = !ST[stateKey];
  btn.classList.toggle('on', ST[stateKey]);
  loadFeed();
}

/* ── feed loading ── */
function updateHeaderCounts(){
  var n = ST.tokens.length;
  var el;
  if((el=document.getElementById('pt-tok-count'))) el.textContent = n;
  if((el=document.getElementById('pt-bot-count'))) el.textContent = n;
  if((el=document.getElementById('pt-pulse-tokens'))) el.textContent = n;
}

function renderStoryRail(){
  var el = document.getElementById('pt-story-rail');
  var list = ST.tokens.slice(0, 14);
  el.innerHTML = list.map(function(t,i){ return storyHtml(t,i); }).join('');
}

function renderFeedList(){
  resetCardState();
  var el = document.getElementById('pt-feed-list');
  if(!ST.tokens.length){
    el.innerHTML = '<div class="pt-empty">No tokens match these filters</div>';
    return;
  }
  el.innerHTML = ST.tokens.map(function(t,i){ return cardHtml(t,i); }).join('');
  observeCards();
}

// isPoll=true only from the 15s auto-refresh interval below -- a user-
// initiated reload (changing sort/filters/liquidity) always goes through
// even while a buy panel is open, since that's an explicit action, not a
// background refresh that could yank the card out from under them.
function loadFeed(isPoll){
  if(isPoll && _openBuyPanelCount > 0) return;
  if(_feedInFlight) return;
  _feedInFlight = true;
  var qs = new URLSearchParams({
    sort: ST.sort,
    min_liquidity: ST.minLiquidity,
    age: ST.age,
    lp_locked: ST.lpLocked?1:0,
    mint_revoked: ST.mintRevoked?1:0,
    hide_honeypots: ST.hideHoneypots?1:0,
    verified_socials: ST.verifiedSocials?1:0
  });
  fetch('/api/market/scanner?'+qs.toString(), {credentials:'include'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(!d || !d.ok) return;
      ST.tokens = d.tokens || [];
      ST.counts = d.counts || {};
      renderSortList();
      renderStoryRail();
      renderFeedList();
      updateHeaderCounts();
    })
    .catch(function(){})
    .finally(function(){ _feedInFlight = false; });
}

/* ── trade actions ── */
// Shared close path so every way a buy panel can close (manual toggle, or
// auto-hide after a completed buy below) keeps _openBuyPanelCount accurate.
function closeBuyPanel(idx){
  var p = document.getElementById('pt-buy-panel-'+idx);
  if(p){ p.style.display = 'none'; p.innerHTML = ''; }
  _openBuyPanelCount = Math.max(0, _openBuyPanelCount - 1);
}

function openBuyPanel(idx){
  var panel = document.getElementById('pt-buy-panel-'+idx);
  if(!panel) return;
  if(panel.style.display === 'flex'){ closeBuyPanel(idx); return; }
  _openBuyPanelCount++;
  var t = ST.tokens[Number(idx)];
  var isEvm = t && !!EVM_TRADE_CHAINS[t.chain];
  panel.style.display = 'flex';
  panel.innerHTML = '<input class="pt-buy-input" id="pt-buy-amt-'+idx+'" type="number" min="0" step="any" placeholder="'+(isEvm?('Amount in '+evmCurrencyLabel(t.chain)):'Amount in SOL')+'">'
    + '<button class="pt-buy-confirm" data-action="confirm-buy" data-idx="'+idx+'">Confirm Buy</button>'
    + '<div class="pt-buy-msg" id="pt-buy-msg-'+idx+'" style="display:none"></div>';
}

function confirmBuy(idx){
  var t = ST.tokens[Number(idx)];
  if(!t) return;
  var input = document.getElementById('pt-buy-amt-'+idx);
  var amt = parseFloat(input ? input.value : '');
  var msgEl = document.getElementById('pt-buy-msg-'+idx);
  if(!amt || amt<=0){ showMsg(msgEl, 'Enter a valid amount', false); return; }
  var btn = document.querySelector('#pt-buy-panel-'+idx+' .pt-buy-confirm');
  if(btn){ btn.disabled = true; btn.textContent = '…'; }
  // Which chain this token lives on decides both the endpoint and the
  // currency the entered amount is denominated in: BSC keeps its own
  // dedicated route, Base/Arbitrum/Polygon share the generic /api/evm/*
  // route (chain passed in the body), and only a plain Solana token ever
  // spends SOL via /api/instant-trade -- the three EVM engines can never be
  // crossed with each other or with Solana here.
  var isBsc = t.chain === 'bsc';
  var isEvm = !!EVM_TRADE_CHAINS[t.chain];
  var url  = isBsc ? '/api/bsc/trade/buy' : (isEvm ? '/api/evm/trade/buy' : '/api/instant-trade');
  var body = isBsc ? {token_address:t.mint, amount_usdc:amt}
    : isEvm ? {chain:t.chain, token_address:t.mint, amount_usdc:amt}
    : {symbol:t.symbol, token_address:t.mint, pair_address:t.pair_address, side:'buy', amount_sol:amt};
  fetch(url, {
    method:'POST', credentials:'include', headers: authHeaders(),
    body: JSON.stringify(body)
  }).then(function(r){ return r.json(); }).then(function(d){
    // If this chain's own balance couldn't cover the trade, the server
    // already started an automatic top-up from whichever chain has enough
    // and attached this buy to it -- {ok:true, pending:true, bridge_id:...}.
    // Poll silently until the purchase actually happens; the user only ever
    // sees "Buying..." then a normal Bought/failed message, never bridge
    // terminology, matching every other buy on this page.
    if(d && d.ok && d.pending && d.bridge_id){
      showMsg(msgEl, 'Buying $'+t.symbol+'…', true);
      _pollAutoBuyBridge(d.bridge_id, idx, t, amt, msgEl, input);
      return;
    }
    // /api/instant-trade's real success shape is {success:true, tx:<sig>, ...};
    // /api/bsc/trade/buy's and /api/evm/trade/buy's is {ok:true, tx_hash:<sig>, ...}
    // -- checking every one of success/tx/ok/sig/tx_hash covers all of them
    // instead of assuming any single endpoint's exact shape (a prior version
    // of this only checked the Solana shape, so every successful BSC buy
    // showed "Buy failed" anyway).
    if(d && (d.success || d.tx || d.ok || d.sig || d.tx_hash)){
      showMsg(msgEl, 'Bought $'+t.symbol+' for '+amt+' '+(isEvm?evmCurrencyLabel(t.chain):'SOL'), true);
      if(input) input.value = '';
      setTimeout(function(){ closeBuyPanel(idx); }, 2200);
    } else {
      showMsg(msgEl, (d && (d.error||d.msg)) || 'Buy failed', false);
    }
    if(btn){ btn.disabled=false; btn.textContent='Confirm Buy'; }
  }).catch(function(){
    showMsg(msgEl, 'Network error — buy not sent', false);
    if(btn){ btn.disabled=false; btn.textContent='Confirm Buy'; }
  });
}

// Polls a background auto-bridge-then-buy through to completion, purely so
// confirmBuy() can show the same Bought/failed message it always would have
// -- the bridge itself (and the wait, up to a few minutes) is never
// surfaced to the user, per the "no friction from bridging" requirement.
// The button stays disabled/'…' for the whole wait, same as any other
// in-flight buy, rather than re-enabling and inviting a duplicate click.
function _pollAutoBuyBridge(bridgeId, idx, t, amt, msgEl, input){
  var attempts = 0;
  var maxAttempts = 150; // ~150 * 8s = 20 minutes outer ceiling, generous over the bridge's own 30-min timeout
  var btn = document.querySelector('#pt-buy-panel-'+idx+' .pt-buy-confirm');
  function tick(){
    attempts++;
    fetch('/api/bridge/status/'+bridgeId, {credentials:'include', headers: authHeaders()})
      .then(function(r){ return r.json(); })
      .then(function(d){
        if(!d || !d.ok){ return scheduleNext(); }
        if(d.auto_buy_status === 'done'){
          var res = d.auto_buy_result || {};
          showMsg(msgEl, 'Bought $'+(res.symbol||t.symbol)+' for '+(res.amount_usdc!=null?res.amount_usdc:amt)+' '+evmCurrencyLabel(t.chain), true);
          if(input) input.value = '';
          if(btn){ btn.disabled=false; btn.textContent='Confirm Buy'; }
          setTimeout(function(){ closeBuyPanel(idx); }, 2200);
          return;
        }
        if(d.auto_buy_status === 'failed'){
          var err = (d.auto_buy_result && d.auto_buy_result.error) || 'Buy failed after funds arrived — your balance is safe, try again';
          showMsg(msgEl, err, false);
          if(btn){ btn.disabled=false; btn.textContent='Confirm Buy'; }
          return;
        }
        if(d.status === 'bridge_failed' || d.status === 'origin_tx_reverted' || d.status === 'timed_out'){
          showMsg(msgEl, 'Buy failed — could not move funds to this chain', false);
          if(btn){ btn.disabled=false; btn.textContent='Confirm Buy'; }
          return;
        }
        scheduleNext();
      })
      .catch(scheduleNext);
  }
  function scheduleNext(){
    if(attempts >= maxAttempts){
      showMsg(msgEl, 'Still buying… check your Wallet page shortly', true);
      if(btn){ btn.disabled=false; btn.textContent='Confirm Buy'; }
      return;
    }
    setTimeout(tick, 8000);
  }
  tick();
}

function handleSell(idx, btn){
  var t = ST.tokens[Number(idx)];
  if(!t) return;
  if(!_sellArmed[idx]){
    _sellArmed[idx] = true;
    var orig = btn.textContent;
    btn.textContent = 'Confirm?';
    setTimeout(function(){ if(_sellArmed[idx]){ _sellArmed[idx]=false; btn.textContent = orig; } }, 3000);
    return;
  }
  _sellArmed[idx] = false;
  btn.disabled = true; btn.textContent = '…';
  // Same chain-based routing as confirmBuy() -- an EVM position can only ever
  // be closed through its own chain's endpoint (it sells the exact tracked
  // position server-side, same as the Solana endpoint does for amount_sol:0).
  var isBsc = t.chain === 'bsc';
  var isEvm = !!EVM_TRADE_CHAINS[t.chain];
  var url  = isBsc ? '/api/bsc/trade/sell' : (isEvm ? '/api/evm/trade/sell' : '/api/instant-trade');
  var body = isBsc ? {token_address:t.mint}
    : isEvm ? {chain:t.chain, token_address:t.mint}
    : {symbol:t.symbol, token_address:t.mint, pair_address:t.pair_address, side:'sell', amount_sol:0};
  fetch(url, {
    method:'POST', credentials:'include', headers: authHeaders(),
    body: JSON.stringify(body)
  }).then(function(r){ return r.json(); }).then(function(d){
    // /api/bsc/trade/sell and /api/evm/trade/sell both always answer HTTP 200
    // with ok:true (it means "the position was found and the sell was
    // attempted"), so their REAL success signal is sell_executed, not ok --
    // checking d.ok here like the Solana path does would show "Sold" even on
    // a swap that actually failed.
    var sold = isEvm ? !!(d && d.sell_executed) : !!(d && (d.success||d.tx||d.ok||d.sig));
    toast(sold ? ('Sold $'+t.symbol) : ((d && (d.error||d.msg)) || 'Sell failed'));
  }).catch(function(){ toast('Network error — sell not sent'); })
    .finally(function(){ btn.disabled=false; btn.textContent='Sell'; });
}

/* ── watchlist ── */
function loadWatchlistSet(){
  return fetch('/api/watchlist', {credentials:'include'}).then(function(r){ return r.json(); }).then(function(d){
    watchSet = new Set((d && d.ok ? d.tokens : []).map(function(t){ return t.token_address; }));
  }).catch(function(){});
}
function toggleWatch(mint, sym, btn){
  var active = watchSet.has(mint);
  fetch('/api/watchlist/'+encodeURIComponent(mint), {
    method: active?'DELETE':'POST', credentials:'include', headers: authHeaders(),
    body: active ? undefined : JSON.stringify({symbol:sym})
  }).then(function(r){ return r.json(); }).then(function(d){
    if(d && d.ok){
      if(active) watchSet.delete(mint); else watchSet.add(mint);
      if(btn){ btn.classList.toggle('active', !active); btn.textContent = !active?'★':'☆'; }
      loadWatchlist();
    } else {
      toast((d && d.msg) || 'Connect your wallet to use the watchlist');
    }
  }).catch(function(){ toast('Network error'); });
}
function toggleWlEdit(){
  _wlEditMode = !_wlEditMode;
  var btn = document.getElementById('pt-wl-edit-btn');
  if(btn) btn.textContent = _wlEditMode ? 'Done' : 'Edit';
  document.querySelectorAll('.pt-wl-remove').forEach(function(b){ b.classList.toggle('show', _wlEditMode); });
}
function removeWatchFromList(mint){
  fetch('/api/watchlist/'+encodeURIComponent(mint), {method:'DELETE', credentials:'include', headers:authHeaders()})
    .then(function(r){ return r.json(); }).then(function(d){
      if(d && d.ok){ watchSet.delete(mint); loadWatchlist(); renderFeedList(); }
    }).catch(function(){});
}
function loadWatchlist(){
  fetch('/api/watchlist', {credentials:'include'}).then(function(r){ return r.json(); }).then(function(d){
    var addrs = (d && d.ok ? d.tokens : []) || [];
    var el = document.getElementById('pt-wl-list');
    if(!addrs.length){ el.innerHTML = '<div class="pt-tape-empty">No tokens watched</div>'; return; }
    var joined = addrs.map(function(t){ return t.token_address; }).join(',');
    fetch('/api/dexscreener/tokens/'+joined).then(function(r){ return r.json(); }).then(function(pd){
      var byAddr = {};
      (pd.pairs||[]).forEach(function(p){
        var a = p.baseToken && p.baseToken.address;
        if(!a) return;
        var liq = (p.liquidity && p.liquidity.usd) || 0;
        var cur = byAddr[a];
        if(!cur || liq > ((cur.liquidity&&cur.liquidity.usd)||0)) byAddr[a] = p;
      });
      el.innerHTML = addrs.map(function(t){
        var p = byAddr[t.token_address];
        var price = p ? fmtPrice(p.priceUsd) : '—';
        var chg = p && p.priceChange ? p.priceChange.h24 : null;
        var img = p && p.info && p.info.imageUrl;
        return '<div class="pt-wl-row">'
          + logoTile(img, t.symbol, 'pt-trader-av', 'pt-trader-av-ph')
          + '<div class="pt-trader-mid"><div class="pt-trader-name">$'+esc(t.symbol||'?')+'</div></div>'
          + '<div class="pt-trader-right"><div class="mono" style="font-size:11.5px;font-weight:700">'+price+'</div>'
          + '<div class="mono '+((chg||0)>=0?'up':'down')+'" style="font-size:10px">'+(chg!=null?fmtPct(chg):'—')+'</div></div>'
          + '<button class="pt-wl-remove'+(_wlEditMode?' show':'')+'" data-mint="'+esc(t.token_address)+'">✕</button>'
          + '</div>';
      }).join('');
    }).catch(function(){ el.innerHTML = '<div class="pt-tape-empty">No tokens watched</div>'; });
  }).catch(function(){});
}

/* ── live trades tape ── */
function loadTape(){
  fetch('/api/market/tape').then(function(r){ return r.json(); }).then(function(d){
    var el = document.getElementById('pt-tape-list');
    var rows = (d && d.ok && d.trades) || [];
    if(!rows.length){ el.innerHTML = '<div class="pt-tape-empty">Waiting for trades…</div>'; return; }
    el.innerHTML = rows.slice(0,14).map(function(r){
      return '<div class="pt-tape-row">'
        + '<span class="pt-tape-pill '+r.side+'">'+r.side.toUpperCase()+'</span>'
        + '<span class="pt-tape-sym">$'+esc(r.symbol)+'</span>'
        + '<span class="pt-tape-amt">'+Number(r.sol_amount||0).toFixed(3)+' SOL</span>'
        + '<span class="pt-tape-age">'+fmtAgeSeconds(r.age_seconds)+'</span>'
        + '</div>';
    }).join('');
  }).catch(function(){});
}

/* ── top traders / copy trade ──
   /api/leaderboard is the real rolling-24h leaderboard (see its own
   docstring server-side) -- this used to call /api/leaderboard/full, the
   ALL-TIME ranking, while both the right-rail card and this rail's own
   heading say "24h". Fetched once and rendered into both the compact
   top-of-feed rail (renderTraderRail, mobile+desktop, above the fold) and
   the fuller right-rail list (desktop only, has the Copy-trade button). */
function loadTraders(){
  fetch('/api/leaderboard').then(function(r){ return r.json(); }).then(function(rows){
    rows = Array.isArray(rows) ? rows : [];
    renderTraderRail(rows);
    var el = document.getElementById('pt-traders-list');
    if(!el) return;
    if(!rows.length){ el.innerHTML = '<div class="pt-tape-empty">No traders yet</div>'; return; }
    el.innerHTML = rows.slice(0,8).map(function(t){
      var isCopying = _copyStatus.copying && _copyStatus.target === t.wallet_address;
      var pnl = Number(t.total_pnl||0);
      return '<div class="pt-trader-row">'
        + '<span class="pt-trader-rank">'+t.rank+'</span>'
        + '<span class="pt-trader-click" data-action="trader-profile" data-wallet="'+esc(t.wallet_address)+'">'
        +   logoTile(t.avatar_url, t.username, 'pt-trader-av', 'pt-trader-av-ph')
        +   '<div class="pt-trader-mid"><div class="pt-trader-name">'+esc(t.username)+'</div>'
        +     '<div class="pt-trader-sub">'+(t.win_rate||0)+'% win · '+(t.trade_count||0)+' trades</div></div>'
        + '</span>'
        + '<div class="pt-trader-right"><div class="pt-trader-pnl mono '+(pnl>=0?'up':'down')+'">'+fmtTraderPnl(t)+'</div>'
        +   '<button class="pt-copy-link'+(isCopying?' active':'')+'" data-action="copy" data-wallet="'+esc(t.wallet_address)+'">'+(isCopying?'Copying':'Copy')+'</button></div>'
        + '</div>';
    }).join('');
  }).catch(function(){});
}

/* Compact horizontal spotlight, same visual language as the token story
   rail directly above it (ring + circle avatar + name + a stat underneath)
   but for people instead of tokens -- sits inside the always-visible center
   feed so it doesn't need the desktop-only right rail to be seen, and
   answers exactly what was asked: which traders are actually up real money
   (shown in USD, see fmtTraderPnl()) today, one tap to their profile. */
function renderTraderRail(rows){
  var wrap = document.getElementById('pt-trader-rail-wrap');
  var el = document.getElementById('pt-trader-rail');
  if(!wrap || !el) return;
  var top = (rows||[]).filter(function(t){ return Number(t.total_pnl||0) > 0; }).slice(0, 10);
  if(!top.length){ wrap.style.display = 'none'; return; }
  wrap.style.display = '';
  el.innerHTML = top.map(function(t){
    var verified = t.badges && t.badges.indexOf('verified') !== -1;
    return '<div class="pt-story pt-trader-story" data-action="trader-profile" data-wallet="'+esc(t.wallet_address)+'">'
      + '<div class="pt-trader-rank-badge'+(t.rank===1?' gold':'')+'">'+esc(String(t.rank))+'</div>'
      + '<div class="pt-story-ring">'
      +   '<div class="pt-story-inner">'
      +     logoTile(t.avatar_url, t.username, 'pt-story-img', 'pt-story-img-ph')
      +   '</div>'
      + '</div>'
      + '<div class="pt-story-name">'+esc(t.username||'')+(verified?' ✓':'')+'</div>'
      + '<div class="pt-story-chg up">'+fmtTraderPnl(t)+'</div>'
      + '</div>';
  }).join('');
}
function toggleCopy(btn){
  var wallet = btn.dataset.wallet;
  var alreadyCopying = _copyStatus.copying && _copyStatus.target === wallet;
  fetch('/api/copy-trade/toggle', {
    method:'POST', credentials:'include', headers: authHeaders(),
    body: JSON.stringify({wallet: wallet, sol_amount: alreadyCopying ? 0 : 0.05})
  }).then(function(r){ return r.json(); }).then(function(d){
    if(d && d.ok){
      var copying = d.copying!=null ? d.copying : d.active;
      _copyStatus.copying = !!copying;
      _copyStatus.target  = copying ? wallet : null;
      loadTraders();
      toast(copying ? 'Copy-trading enabled' : 'Copy-trading stopped');
    } else {
      toast((d && d.msg) || 'Could not update copy-trade');
    }
  }).catch(function(){ toast('Network error'); });
}

/* ── market pulse ── */
function loadPulse(){
  fetch('/api/platform/stats').then(function(r){ return r.json(); }).then(function(d){
    if(!d || !d.ok) return;
    var tradesEl = document.getElementById('pt-pulse-trades');
    var netEl    = document.getElementById('pt-pulse-net');
    if(tradesEl) tradesEl.textContent = d.trades_today;
    if(netEl){
      var net = Number(d.net_pnl_today||0);
      netEl.textContent = (net>=0?'+':'')+net.toFixed(2);
      netEl.classList.toggle('green', net>=0);
      netEl.style.color = net<0 ? 'var(--red)' : '';
    }
  }).catch(function(){});
  fetch('/api/online-count').then(function(r){ return r.json(); }).then(function(d){
    var el = document.getElementById('pt-pulse-online');
    if(d && d.ok && el) el.textContent = d.online;
  }).catch(function(){});
}

/* ── deep-linked token (shared navbar's search redirects here as ?mint=) ── */
function scrollToCard(idx){
  var card = document.getElementById('pt-card-'+idx);
  if(!card) return;
  card.scrollIntoView({behavior:'smooth', block:'center'});
  var wasHi = card.classList.contains('hi');
  card.classList.add('hi');
  if(!wasHi) setTimeout(function(){ card.classList.remove('hi'); }, 1600);
}

function prependSearchedToken(mint, sym, pairAddr){
  fetch('/api/token/info/'+encodeURIComponent(mint)).then(function(r){ return r.json(); }).then(function(info){
    var tok;
    if(info && info.ok){
      var pc = info.price_change || {};
      tok = {
        mint: info.address||mint, symbol: info.symbol||sym, name: info.name||sym,
        chain: info.chain||'solana', pair_address: info.pair_address||pairAddr,
        image_url: info.image_url||'', price_usd: Number(info.price_usd||info.price||0),
        market_cap: Number(info.market_cap||info.mcap||0), liquidity_usd: Number(info.liquidity_usd||info.liquidity||0),
        volume_24h: Number(info.volume_24h||0), buys_24h: Number(info.buyers_24h||0), sells_24h: Number(info.sellers_24h||0),
        price_change_24h: Number(pc.h24||0), pair_created_at: null, verified_socials:false, score:3
      };
    } else {
      tok = {mint:mint, symbol:sym, name:sym, chain:'solana', pair_address:pairAddr, image_url:'',
        price_usd:0, market_cap:0, liquidity_usd:0, volume_24h:0, buys_24h:0, sells_24h:0,
        price_change_24h:0, pair_created_at:null, verified_socials:false, score:3};
    }
    ST.tokens = [tok].concat(ST.tokens.filter(function(t){ return t.mint !== tok.mint; }));
    renderStoryRail();
    renderFeedList();
    updateHeaderCounts();
    setTimeout(function(){ scrollToCard(0); }, 60);
  }).catch(function(){});
}

/* ── event wiring ── */
document.addEventListener('click', function(e){
  var el;
  if((el = e.target.closest('[data-action="story"]'))){ scrollToCard(el.dataset.idx); return; }
  if((el = e.target.closest('[data-action="watch"]'))){ toggleWatch(el.dataset.mint, el.dataset.sym, el); return; }
  if((el = e.target.closest('[data-action="buy-open"]'))){ openBuyPanel(el.dataset.idx); return; }
  if((el = e.target.closest('[data-action="confirm-buy"]'))){ confirmBuy(el.dataset.idx); return; }
  if((el = e.target.closest('[data-action="sell"]'))){ handleSell(el.dataset.idx, el); return; }
  if((el = e.target.closest('[data-action="copy"]'))){ toggleCopy(el); return; }
  if((el = e.target.closest('[data-action="copy-ca"]'))){ copyCA(el.dataset.mint, el); return; }
  if((el = e.target.closest('[data-action="trader-profile"]'))){
    if(el.dataset.wallet) location.href = '/profile/' + encodeURIComponent(el.dataset.wallet);
    return;
  }
  if((el = e.target.closest('.pt-tf-pill'))){
    var wrap = el.closest('.pt-chart-tfs');
    var idx = wrap.id.replace('pt-chart-tfs-','');
    wrap.querySelectorAll('.pt-tf-pill').forEach(function(b){ b.classList.toggle('active', b===el); });
    setChartTf(idx, el.dataset.tf);
    return;
  }
  if((el = e.target.closest('[data-sort]'))){ setSort(el.dataset.sort); return; }
  if((el = e.target.closest('.pt-age-chip'))){ setAge(el.dataset.age); return; }
  if((el = e.target.closest('.pt-switch'))){ toggleFilter(el); return; }
  if((el = e.target.closest('#pt-wl-edit-btn'))){ toggleWlEdit(); return; }
  if((el = e.target.closest('.pt-wl-remove'))){ removeWatchFromList(el.dataset.mint); return; }
});

/* ── init ── */
document.addEventListener('DOMContentLoaded', function(){
  var liqSlider  = document.getElementById('pt-liq-slider');
  var liqValueEl = document.getElementById('pt-liq-value');
  var _liqDebounce = null;
  liqSlider.addEventListener('input', function(){
    ST.minLiquidity = parseInt(liqSlider.value, 10);
    liqValueEl.textContent = '$'+fmtShort(ST.minLiquidity)+' of $500K';
    clearTimeout(_liqDebounce);
    _liqDebounce = setTimeout(loadFeed, 350);
  });

  /* mobile: left-rail filters drawer (the nav drawer is the shared navbar's
     own, see static/navbar.js) */
  var filtersBtn = document.getElementById('pt-mobile-filters-btn');
  var leftEl     = document.getElementById('pt-left');
  var scrimEl    = document.getElementById('pt-scrim');
  if(filtersBtn) filtersBtn.addEventListener('click', function(){
    var opening = !leftEl.classList.contains('mobile-open');
    closeMobileOverlays();
    if(opening){ leftEl.classList.add('mobile-open'); scrimEl.classList.add('show'); }
  });
  if(scrimEl) scrimEl.addEventListener('click', closeMobileOverlays);

  /* re-measure & redraw mounted charts on resize/rotation (e.g. desktop<->mobile
     breakpoint change) -- renderChartSvg() re-reads clientWidth each call, it
     just isn't re-triggered by a resize on its own between 5s poll ticks */
  var _resizeTimer = null;
  window.addEventListener('resize', function(){
    clearTimeout(_resizeTimer);
    _resizeTimer = setTimeout(function(){
      Object.keys(_chartTimers).forEach(function(idx){ chartTick(idx); });
    }, 200);
  });

  renderSortList();
  loadWatchlistSet().then(function(){ loadFeed(); });
  loadTape();
  loadTraders();
  loadWatchlist();
  loadPulse();
  fetch('/api/copy-trade/status', {credentials:'include'}).then(function(r){ return r.json(); }).then(function(d){
    if(d && d.ok){ _copyStatus.copying = d.copying; _copyStatus.target = d.target_wallet; loadTraders(); }
  }).catch(function(){});

  // A token opened via the shared navbar's search lands here as ?mint=<addr>
  // (a plain full-page navigation, since the navbar itself has no feed to
  // inject into on every other page) -- inject it once the first scanner
  // load has had a chance to populate ST.tokens, so it isn't immediately
  // overwritten by that response.
  var _qMint = new URLSearchParams(location.search).get('mint');
  if(_qMint){
    history.replaceState(null, '', location.pathname);
    setTimeout(function(){ prependSearchedToken(_qMint, '', ''); }, 900);
  }

  setInterval(function(){ loadFeed(true); }, 15000);
  setInterval(loadTape, 8000);
  setInterval(loadTraders, 30000);
  setInterval(loadPulse, 20000);
});

})();
