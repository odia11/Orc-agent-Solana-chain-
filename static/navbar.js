/* Shared OrcAgent top navbar controller. Pairs with the markup rendered by
   dashboard.py's _navbar_html() (used by every page via a Jinja global on
   render_template()-based pages, and spliced into dashboard.html's raw HTML
   the same way the modal partials are). Self-contained: does not assume any
   other script on the page has already run. */
(function(){
'use strict';

// Chains OrcAgent actually trades on -- mirrors dashboard.py's
// _MARKET_LIVE_CHAINS. Used to keep the navbar search from surfacing (or
// letting a user click into) a token on a chain this app has no trading
// route for at all.
var _NB_LIVE_CHAINS = ['solana', 'bsc', 'base', 'arbitrum', 'polygon', 'robinhood'];
var _NB_CHAIN_LABELS = {solana:'SOL', bsc:'BSC', base:'BASE', arbitrum:'ARB', polygon:'POLY', robinhood:'HOOD'};

// ── DEFAULT FETCH TIMEOUT ──
// After a phone sleeps or the app sits backgrounded for a while, network
// connections resumed on wake are often stale: the socket still looks open
// to the browser, but the other end is long gone, so a fetch() over it can
// hang far past any user's patience instead of failing fast so the page's
// own polling can retry. Almost none of this codebase's many fetch() call
// sites set a timeout themselves (a small handful already use their own
// AbortController), so a stuck fetch here read as exactly the reported bug:
// return to the app after being away, and it just sits there, frozen.
//
// This patches window.fetch ONCE, globally -- loaded on every page via the
// shared navbar -- so every call gets a bounded timeout unless it already
// supplies its own AbortSignal (never overrides a caller's own abort/timeout
// logic; several pages already wrap window.fetch this same way for CSRF
// headers etc., and compose fine since each wrapper just delegates to
// whatever window.fetch already was when it installed itself). FormData
// bodies (image/file uploads) get a much longer allowance -- a real upload
// on a slow connection legitimately needs more than a few seconds, and
// that's a different failure mode than a silently-dead polling request.
(function(){
  var DEFAULT_FETCH_TIMEOUT_MS = 15000;
  var UPLOAD_FETCH_TIMEOUT_MS  = 60000;
  var _origFetch = window.fetch.bind(window);
  window.fetch = function(input, init){
    if(init && init.signal) return _origFetch(input, init);
    var isUpload = !!(init && typeof FormData !== 'undefined' && init.body instanceof FormData);
    var ctl = new AbortController();
    var timer = setTimeout(function(){ ctl.abort(); }, isUpload ? UPLOAD_FETCH_TIMEOUT_MS : DEFAULT_FETCH_TIMEOUT_MS);
    var opts = Object.assign({}, init || {}, {signal: ctl.signal});
    return _origFetch(input, opts).finally(function(){ clearTimeout(timer); });
  };
})();

// ── RESUME REPAINT ──
// Standalone (home-screen) PWAs on iOS have a long-documented WebKit bug:
// after the app sits backgrounded for a while, coming back can show a black,
// unresponsive screen -- the page is alive underneath, WebKit just fails to
// recomposite its GPU layers on resume. Nudging document.documentElement's
// opacity by a hair and back forces a fresh composite pass -- one of the
// standard, low-risk workarounds for this bug class: it doesn't touch
// layout/scroll (unlike toggling display), so nothing about the page's
// state changes, and the change is imperceptibly small and reverted before
// the browser's next paint. Skipped for a brief tab-switch glance (under
// 3s hidden) so it only fires for a real "was away for a while" return,
// matching what was actually reported.
(function(){
  var _hiddenAt = null;
  function _forceRepaint(){
    var el = document.documentElement;
    var prev = el.style.opacity;
    el.style.opacity = '0.99999';
    requestAnimationFrame(function(){ el.style.opacity = prev; });
  }
  document.addEventListener('visibilitychange', function(){
    if(document.hidden){ _hiddenAt = Date.now(); return; }
    if(_hiddenAt && Date.now() - _hiddenAt > 3000) _forceRepaint();
    _hiddenAt = null;
  });
  window.addEventListener('pageshow', function(e){
    if(e.persisted) _forceRepaint();
  });
})();

function esc(s){
  return String(s==null?'':s).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
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
function logoTile(imgUrl, label, cls, phCls){
  var initials = esc((label||'?').slice(0,2).toUpperCase());
  if(!imgUrl) return '<div class="'+phCls+'">'+initials+'</div>';
  return '<img class="'+cls+'" src="'+esc(imgUrl)+'" onerror="this.style.display=\'none\';this.nextElementSibling.style.display=\'flex\'">'
    + '<div class="'+phCls+'" style="display:none">'+initials+'</div>';
}

function closeAllOverlays(){
  var nav = document.getElementById('pt-nb-nav');
  var more = document.getElementById('pt-nb-more-dd');
  var scrim = document.getElementById('pt-nb-scrim');
  var results = document.getElementById('pt-nb-search-results');
  if(nav) nav.classList.remove('mobile-open');
  if(more) more.classList.remove('open');
  if(scrim) scrim.classList.remove('show');
  if(results) results.classList.remove('open');
}

document.addEventListener('DOMContentLoaded', function(){
  var root = document.querySelector('.pt-nb-topbar');
  if(!root) return; // navbar not on this page

  var menuBtn    = document.getElementById('pt-nb-menu-btn');
  var navEl      = document.getElementById('pt-nb-nav');
  var moreBtn    = document.getElementById('pt-nb-more-btn');
  var moreDd     = document.getElementById('pt-nb-more-dd');
  var scrimEl    = document.getElementById('pt-nb-scrim');
  var searchIn   = document.getElementById('pt-nb-search-input');
  var searchRes  = document.getElementById('pt-nb-search-results');

  if(menuBtn) menuBtn.addEventListener('click', function(e){
    e.stopPropagation();
    var opening = !navEl.classList.contains('mobile-open');
    closeAllOverlays();
    if(opening){ navEl.classList.add('mobile-open'); if(scrimEl) scrimEl.classList.add('show'); }
  });
  if(moreBtn) moreBtn.addEventListener('click', function(e){
    e.stopPropagation();
    var opening = !moreDd.classList.contains('open');
    closeAllOverlays();
    if(opening) moreDd.classList.add('open');
  });
  if(scrimEl) scrimEl.addEventListener('click', closeAllOverlays);

  // Two copies exist (the desktop-only "More" popup, and the same list
  // folded into the mobile hamburger menu) so a visitor only ever sees one
  // merged menu on mobile instead of two competing ones -- wire up both.
  document.querySelectorAll('.pt-nb-disconnect-btn').forEach(function(disconnectBtn){
    disconnectBtn.addEventListener('click', function(){
      // dashboard.html defines a richer disconnectWallet() (disconnects the
      // wallet-adapter provider too, clears per-user caches) -- prefer it
      // when present; every other page just does the plain logout.
      if(typeof window.disconnectWallet === 'function'){ window.disconnectWallet(); return; }
      fetch('/api/logout', {method:'POST', credentials:'include'})
        .catch(function(){})
        .finally(function(){ window.location.href = '/'; });
    });
  });
  document.addEventListener('click', function(e){
    if(moreDd && moreDd.classList.contains('open') && !e.target.closest('.pt-nb-more-wrap')) moreDd.classList.remove('open');
    if(searchRes && searchRes.classList.contains('open') && !e.target.closest('.pt-nb-search-wrap')) searchRes.classList.remove('open');
  });

  /* ── search (tokens via DexScreener proxy, traders via /api/users/search) ── */
  var _searchTimer = null;
  if(searchIn){
    searchIn.addEventListener('input', function(){
      var q = searchIn.value.trim();
      clearTimeout(_searchTimer);
      if(q.length<2){ searchRes.classList.remove('open'); return; }
      _searchTimer = setTimeout(function(){ runSearch(q); }, 300);
    });
  }
  function runSearch(q){
    Promise.allSettled([
      fetch('/api/dexscreener/search?q='+encodeURIComponent(q)).then(function(r){ return r.json(); }),
      fetch('/api/users/search?q='+encodeURIComponent(q), {credentials:'include'}).then(function(r){ return r.json(); })
    ]).then(function(results){
      var tokRes  = results[0].status==='fulfilled' ? results[0].value : null;
      var userRes = results[1].status==='fulfilled' ? results[1].value : null;
      // Was Solana-only ({p.chainId==='solana'}) -- every other chain OrcAgent
      // trades on (BSC/Base/Arbitrum/Polygon/Robinhood) got silently thrown
      // away here even though /api/dexscreener/search itself already returns
      // every chain DexScreener knows about. Now keeps any chain this app
      // actually supports trading on.
      var pairs = ((tokRes && tokRes.pairs) || []).filter(function(p){ return _NB_LIVE_CHAINS.indexOf(p.chainId)!==-1; }).slice(0,6);
      var users = (userRes && userRes.ok && userRes.users) || [];
      var html = '';
      if(pairs.length){
        html += '<div class="pt-nb-sr-hd">Tokens</div>' + pairs.map(function(p){
          var sym = p.baseToken.symbol, addr = p.baseToken.address, img = p.info && p.info.imageUrl;
          var chainLbl = _NB_CHAIN_LABELS[p.chainId] || p.chainId;
          return '<div class="pt-nb-sr-row" data-action="tok" data-mint="'+esc(addr)+'" data-chain="'+esc(p.chainId)+'">'
            + logoTile(img, sym, 'pt-nb-sr-logo', 'pt-nb-sr-logo-ph')
            + '<div class="pt-nb-sr-name">$'+esc(sym)+' <span class="pt-nb-sr-chain">'+esc(chainLbl)+'</span></div><div class="pt-nb-sr-sub">'+fmtPrice(p.priceUsd)+'</div></div>';
        }).join('');
      }
      if(users.length){
        html += '<div class="pt-nb-sr-hd">Traders</div>' + users.slice(0,5).map(function(u){
          return '<div class="pt-nb-sr-row" data-action="trader" data-wallet="'+esc(u.wallet)+'">'
            + logoTile(u.avatar_url, u.username, 'pt-nb-sr-logo', 'pt-nb-sr-logo-ph')
            + '<div class="pt-nb-sr-name">'+esc(u.username||'')+'</div></div>';
        }).join('');
      }
      searchRes.innerHTML = html || '<div class="pt-nb-sr-empty">No results</div>';
      searchRes.classList.add('open');
    });
  }
  if(searchRes) searchRes.addEventListener('click', function(e){
    var tok = e.target.closest('[data-action="tok"]');
    if(tok){ window.location.href = '/live-market?mint='+encodeURIComponent(tok.dataset.mint); return; }
    var trader = e.target.closest('[data-action="trader"]');
    if(trader){ window.location.href = '/profile/'+encodeURIComponent(trader.dataset.wallet); return; }
  });

  /* ── current user: avatar, SOL balance, admin-only More items ── */
  fetch('/api/me', {credentials:'include'}).then(function(r){ return r.json(); }).then(function(d){
    if(!d || !d.ok) return;
    var balEl = document.getElementById('pt-nb-sol-balance');
    if(balEl) balEl.textContent = Number(d.balance||0).toFixed(2);
    if(d.avatar){
      var img = document.getElementById('pt-nb-avatar');
      var ph  = document.getElementById('pt-nb-avatar-ph');
      if(img){ img.src = d.avatar; img.style.display = 'block'; }
      if(ph) ph.style.display = 'none';
    }
    if(d.is_admin){
      document.querySelectorAll('.pt-nb-admin-link').forEach(function(adminItem){
        adminItem.style.display = 'flex';
      });
    }
  }).catch(function(){});

  /* ── unread badges (messages / notifications) ── */
  function refreshBadges(){
    fetch('/api/messages/unread_count', {credentials:'include'}).then(function(r){ return r.json(); }).then(function(d){
      var n = (d && d.count) || 0;
      ['pt-nb-msg-badge','pt-nb-more-msg-badge'].forEach(function(id){
        var el = document.getElementById(id);
        if(!el) return;
        el.textContent = n>99 ? '99+' : String(n);
        el.classList.toggle('show', n>0);
      });
    }).catch(function(){});
    fetch('/api/notifications/mine/unread_count', {credentials:'include'}).then(function(r){ return r.json(); }).then(function(d){
      var n = (d && d.ok && d.unread) || 0;
      ['pt-nb-notif-badge','pt-nb-more-notif-badge'].forEach(function(id){
        var el = document.getElementById(id);
        if(!el) return;
        el.textContent = n>99 ? '99+' : String(n);
        el.classList.toggle('show', n>0);
      });
    }).catch(function(){});
  }
  refreshBadges();
  setInterval(refreshBadges, 30000);
});

})();
