// ── SAFE AUTO-REFRESH ───────────────────────────────────────────────────────
// Reloads the page every 60s so balances, positions, and feeds don't go stale
// during a long session. Skipped while the person is actively typing, has any
// modal/drawer/dropdown/panel open, has a request in flight, interacted in
// the last 20s, or the tab isn't visible.
(function(){
  var REFRESH_INTERVAL_MS = 60000;
  var IDLE_GRACE_MS       = 20000;
  var _lastInteraction = Date.now();
  ['mousedown', 'keydown', 'touchstart', 'scroll'].forEach(function(evt){
    document.addEventListener(evt, function(){ _lastInteraction = Date.now(); }, {passive: true});
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

  // Track in-flight fetch() calls so a reload never lands mid-request (e.g.
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

  setInterval(function(){
    if(document.hidden) return;
    if(_isTypingOrFocused()) return;
    if(_modalOpen()) return;
    if(_pendingFetches > 0) return;
    if(Date.now() - _lastInteraction < IDLE_GRACE_MS) return;
    window.location.reload();
  }, REFRESH_INTERVAL_MS);
})();
