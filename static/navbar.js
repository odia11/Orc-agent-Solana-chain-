/* Shared OrcAgent top navbar controller. Pairs with the markup rendered by
   dashboard.py's _navbar_html() (used by every page via a Jinja global on
   render_template()-based pages, and spliced into dashboard.html's raw HTML
   the same way the modal partials are). Self-contained: does not assume any
   other script on the page has already run. */
(function(){
'use strict';

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

  var disconnectBtn = document.getElementById('pt-nb-disconnect');
  if(disconnectBtn) disconnectBtn.addEventListener('click', function(){
    fetch('/api/logout', {method:'POST', credentials:'include'})
      .catch(function(){})
      .finally(function(){ window.location.href = '/'; });
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
      var pairs = ((tokRes && tokRes.pairs) || []).filter(function(p){ return p.chainId==='solana'; }).slice(0,6);
      var users = (userRes && userRes.ok && userRes.users) || [];
      var html = '';
      if(pairs.length){
        html += '<div class="pt-nb-sr-hd">Tokens</div>' + pairs.map(function(p){
          var sym = p.baseToken.symbol, addr = p.baseToken.address, img = p.info && p.info.imageUrl;
          return '<div class="pt-nb-sr-row" data-action="tok" data-mint="'+esc(addr)+'">'
            + logoTile(img, sym, 'pt-nb-sr-logo', 'pt-nb-sr-logo-ph')
            + '<div class="pt-nb-sr-name">$'+esc(sym)+'</div><div class="pt-nb-sr-sub">'+fmtPrice(p.priceUsd)+'</div></div>';
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
      var adminItem = document.getElementById('pt-nb-more-admin');
      if(adminItem) adminItem.style.display = 'flex';
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
