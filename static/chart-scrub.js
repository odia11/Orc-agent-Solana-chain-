/* Shared touch/hover price-scrubbing for every LightweightCharts instance in
   this app ("Live Family" style: dragging or hovering over a chart finds the
   nearest data point to the pointer's x-position and shows a crosshair +
   floating "price · time" tooltip there, instead of a touch drag being read
   as a pan/scroll gesture -- the default with handleScroll:true, which is
   what made this not work at all on every chart before its own fix).

   Originally built inside token-card.js for its two charts (candles + the
   "Live" area chart), then copied into dashboard.js for its two more
   (position detail, PNL summary) -- pulled out here after that second copy,
   so there's exactly one implementation instead of drifting duplicates.
   Depends only on the DOM and the chart/series objects passed in; callers
   supply their own price formatter (_fmtPrice/fmtPrice, both already exist
   per-page under one of those two names) via formatTip.

   getPrice(pt) returns the y-value to pass to chart.setCrosshairPosition()
   for a data point: a plain {time,value} point's value for an area/line
   series, a candle's close for a candlestick series. formatTip(pt) returns
   the tooltip text for that point -- see chartScrubFmtTip() below for the
   "$price · HH:MM" format every current caller uses.

   containerId keys a small registry so re-creating a chart in the same
   container (switching timeframe/style, reopening a modal for a different
   token) tears down the previous listeners/tooltip first -- without this,
   they'd stack up on every re-init since the container div itself persists
   across chart instances. */
var _chartScrubByContainer = {};
function attachChartScrub(containerId, container, chart, series, dataRef, getPrice, formatTip){
  var stale = _chartScrubByContainer[containerId];
  if(stale){ stale.teardown(); delete _chartScrubByContainer[containerId]; }

  var tip = document.createElement('div');
  tip.className = 'lmtd-chart-scrub-tip';
  tip.style.display = 'none';
  if(getComputedStyle(container).position === 'static') container.style.position = 'relative';
  container.appendChild(tip);

  function nearestPoint(time){
    var pts = dataRef.current;
    if(!pts.length) return null;
    // pts is time-ascending (chart data always is) -- a linear scan is fine
    // at the point counts these timeframes return (a few hundred at most).
    var best = pts[0], bestDiff = Math.abs(pts[0].time - time);
    for(var i = 1; i < pts.length; i++){
      var diff = Math.abs(pts[i].time - time);
      if(diff < bestDiff){ best = pts[i]; bestDiff = diff; }
      else if(pts[i].time > time) break; // ascending + already past time -- best won't improve further
    }
    return best;
  }

  function scrubToX(clientX){
    var pts = dataRef.current;
    if(!pts.length) return;
    var rect = container.getBoundingClientRect();
    var localX = Math.max(0, Math.min(rect.width, clientX - rect.left));
    var time = chart.timeScale().coordinateToTime(localX);
    var pt = time == null ? pts[pts.length - 1] : nearestPoint(time);
    if(!pt) return;
    chart.setCrosshairPosition(getPrice(pt), pt.time, series);
    tip.textContent = formatTip(pt);
    tip.style.display = 'block';
    var tipX = Math.max(6, Math.min(rect.width - tip.offsetWidth - 6, localX - tip.offsetWidth / 2));
    tip.style.left = tipX + 'px';
  }

  function clearScrub(){
    chart.clearCrosshairPosition();
    tip.style.display = 'none';
  }

  function onTouchStart(e){ if(e.touches[0]) scrubToX(e.touches[0].clientX); }
  function onTouchMove(e){ if(e.touches[0]){ e.preventDefault(); scrubToX(e.touches[0].clientX); } }
  function onMouseMove(e){ scrubToX(e.clientX); }
  container.addEventListener('touchstart', onTouchStart, {passive: true});
  container.addEventListener('touchmove', onTouchMove, {passive: false});
  container.addEventListener('touchend', clearScrub, {passive: true});
  container.addEventListener('touchcancel', clearScrub, {passive: true});
  container.addEventListener('mousemove', onMouseMove);
  container.addEventListener('mouseleave', clearScrub);
  function teardown(){
    container.removeEventListener('touchstart', onTouchStart);
    container.removeEventListener('touchmove', onTouchMove);
    container.removeEventListener('touchend', clearScrub);
    container.removeEventListener('touchcancel', clearScrub);
    container.removeEventListener('mousemove', onMouseMove);
    container.removeEventListener('mouseleave', clearScrub);
    if(tip.parentNode) tip.parentNode.removeChild(tip);
  }
  _chartScrubByContainer[containerId] = {teardown: teardown};
  return tip;
}

/* "$price · HH:MM" -- the format every current caller's tooltip uses.
   fmtPriceFn is the caller's own price formatter (pages in this app define
   either _fmtPrice or fmtPrice; passed in explicitly rather than assumed by
   name so this file has no naming dependency on either). */
function chartScrubFmtTip(fmtPriceFn, price, time){
  var d = new Date(time * 1000);
  var hh = String(d.getHours()).padStart(2, '0'), mm = String(d.getMinutes()).padStart(2, '0');
  return fmtPriceFn(price) + '  ·  ' + hh + ':' + mm;
}
