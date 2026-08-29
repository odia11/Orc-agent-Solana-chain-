// ── PULL-TO-REFRESH (shared, mobile touch only) ──────────────────────────
// Same gesture/indicator as the home feed's own pull-to-refresh (see
// dashboard.js) generalized into one reusable module for every other page:
// only arms when the page is already scrolled to the top, tracks a downward
// drag as a growing spinner, and fires a refresh once the drag clears
// PTR_THRESHOLD. Call initPullToRefresh() once per page; pass onRefresh to
// reuse that page's own data-loading functions instead of a full reload
// where one's easy to hook in, otherwise the default just reloads the page --
// still a correct "pull to refresh", just not an in-place refetch.
(function(){
  var _styleInjected = false;
  function _injectStyle(){
    if(_styleInjected) return;
    _styleInjected = true;
    var s = document.createElement('style');
    s.textContent = '@keyframes ptrSpin{to{transform:rotate(360deg)}}'
      + '.ptr-indicator-spin{width:20px;height:20px;border-radius:50%;'
      + 'border:2px solid rgba(255,255,255,.15);border-top-color:#f7b955;'
      + 'animation:ptrSpin .7s linear infinite;display:inline-block}';
    document.head.appendChild(s);
  }

  window.initPullToRefresh = function(opts){
    opts = opts || {};
    var PTR_THRESHOLD = 70;
    var touchTarget = _resolve(opts.touchTarget) || document.body;
    var scrollEl    = _resolve(opts.scrollEl); // null => window/document scroll
    var anchorEl    = _resolve(opts.anchorEl) || document.body.firstElementChild;
    var onRefresh   = opts.onRefresh || function(){ location.reload(); };
    if(!touchTarget || !anchorEl) return;
    _injectStyle();

    function _resolve(v){
      if(!v) return null;
      return typeof v === 'string' ? document.querySelector(v) : v;
    }
    function scrollTop(){
      if(scrollEl) return scrollEl.scrollTop;
      return window.scrollY || document.documentElement.scrollTop || document.body.scrollTop || 0;
    }

    var _startY = 0, _active = false, _pulling = false, _indicator = null;

    function ensureIndicator(){
      if(_indicator) return _indicator;
      var wrap = document.createElement('div');
      wrap.className = 'ptr-indicator';
      wrap.style.cssText = 'display:flex;align-items:center;justify-content:center;height:0;overflow:hidden;transition:height .15s ease';
      var spin = document.createElement('span');
      spin.className = 'ptr-indicator-spin';
      wrap.appendChild(spin);
      anchorEl.parentNode.insertBefore(wrap, anchorEl);
      _indicator = wrap;
      return wrap;
    }

    touchTarget.addEventListener('touchstart', function(e){
      if(opts.ignoreTarget && e.target.closest(opts.ignoreTarget)){ _active = false; return; }
      if(scrollTop() !== 0){ _active = false; return; }
      _startY = e.touches[0].clientY;
      _active = true;
      _pulling = false;
    }, {passive: true});

    touchTarget.addEventListener('touchmove', function(e){
      if(!_active) return;
      var dy = e.touches[0].clientY - _startY;
      if(dy <= 0 || scrollTop() !== 0){ _active = false; return; }
      _pulling = true;
      e.preventDefault(); // suppress native overscroll bounce while our indicator is dragging
      ensureIndicator().style.height = Math.min(dy, PTR_THRESHOLD) + 'px';
    }, {passive: false});

    touchTarget.addEventListener('touchend', async function(){
      if(!_active) return;
      _active = false;
      if(_pulling && _indicator){
        var pulled = parseInt(_indicator.style.height, 10) || 0;
        if(pulled >= PTR_THRESHOLD){
          _indicator.style.height = PTR_THRESHOLD + 'px'; // hold open, spinner keeps spinning
          try{ await onRefresh(); }catch(e){}
        }
        _indicator.style.height = '0px';
      }
      _pulling = false;
    }, {passive: true});
  };
})();
