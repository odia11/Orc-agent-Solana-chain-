// ── SAFE AUTO-REFRESH ───────────────────────────────────────────────────────
// Keeps the home feed from going stale during a long session by silently
// refetching it in place every REFRESH_INTERVAL_MS -- balances, positions,
// market data, and notifications already have their own periodic refetch
// (fetchState()/fetchMarketOnly()/_pollNotifCount() in dashboard.js and
// notif-poll.js) so this only needs to cover the one thing nothing else
// polls: new posts appearing in the social feed.
//
// This used to be a full window.location.reload(), which re-downloaded and
// re-parsed the whole ~350KB HTML + JS bundle every minute for every active
// tab -- the visible stutter this file now avoids. Swapping to loadHomeFeed()
// mirrors the pattern already used elsewhere in this codebase (see the
// "refetch + re-render in place instead of a full page reload" comment in
// dashboard.js) rather than introducing a new refresh strategy.
//
// Same skip conditions as before (typing, modal/drawer/dropdown open, request
// in flight, recent interaction, tab not visible), plus one new one: skip
// while the person is scrolled into the feed reading, so an in-place refresh
// never yanks their scroll position out from under them. Only refetch while
// they're at the top, same as a "new posts" indicator on other feeds would.
(function(){
  var REFRESH_INTERVAL_MS  = 60000;
  var IDLE_GRACE_MS        = 20000;
  var VISIBLE_GRACE_MS     = 5000;
  var SCROLL_TOP_THRESHOLD = 80; // px -- "near the top" tolerance
  var _lastInteraction = Date.now();
  var _lastVisible     = Date.now();
  ['mousedown', 'keydown', 'touchstart', 'scroll'].forEach(function(evt){
    document.addEventListener(evt, function(){ _lastInteraction = Date.now(); }, {passive: true});
  });
  document.addEventListener('visibilitychange', function(){
    if(!document.hidden) _lastVisible = Date.now();
  });

  function _isTypingOrFocused(){
    var el = document.activeElement;
    if(!el) return false;
    var tag = el.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable === true;
  }

  // Every modal/drawer/dropdown/panel/popup in this codebase toggles a shared
  // `.open` class (confirm-modal.js, alert-modal.js, delete-convo-modal.js,
  // low-balance-modal.js, and dashboard.js's tos/settings/withdraw/deposit/
  // incinerator/pos-chart modals, side panels, and dropdowns all use it) --
  // that's a far more complete signal than the couple of overlays that also
  // happen to lock body scroll, so check both.
  function _modalOpen(){
    return document.body.style.overflow === 'hidden' || document.querySelector('.open') !== null;
  }

  // Track in-flight fetch() calls so a refresh never lands mid-request (e.g.
  // a trade submit) with no chance for the success/error toast to show.
  // Wraps whatever window.fetch currently is, so it composes with any
  // page-specific wrapper (e.g. dashboard.js's CSRF-header injector) that
  // ran before this script, rather than replacing it.
  var _pendingFetches = 0;
  var _prevFetch = window.fetch;
  window.fetch = function(){
    _pendingFetches++;
    return _prevFetch.apply(this, arguments).finally(function(){ _pendingFetches--; });
  };

  function _scrolledIntoFeed(){
    return (window.scrollY || document.documentElement.scrollTop || 0) > SCROLL_TOP_THRESHOLD;
  }

  setInterval(function(){
    if(document.hidden) return;
    if(_isTypingOrFocused()) return;
    if(_modalOpen()) return;
    if(_pendingFetches > 0) return;
    if(Date.now() - _lastInteraction < IDLE_GRACE_MS) return;
    if(Date.now() - _lastVisible < VISIBLE_GRACE_MS) return;
    if(_scrolledIntoFeed()) return;
    if(typeof loadHomeFeed === 'function') loadHomeFeed();
  }, REFRESH_INTERVAL_MS);
})();
