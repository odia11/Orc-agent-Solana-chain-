(function(){
  var b=document.createElement('div');
  b.id='pgl-bar';
  b.style.cssText='position:fixed;top:0;left:0;height:2px;width:0;background:#f7b955;z-index:99999;transition:width .2s,opacity .3s;box-shadow:0 0 8px rgba(247,185,85,.6)';
  document.documentElement.appendChild(b);
  var p=0,t;
  function start(){p=0;b.style.opacity='1';clearInterval(t);t=setInterval(function(){p+=(85-p)*.1;b.style.width=p+'%'},120)}
  function finish(){clearInterval(t);b.style.width='100%';b.style.opacity='0'}
  addEventListener('beforeunload',start);
  addEventListener('pageshow',finish);
})();
