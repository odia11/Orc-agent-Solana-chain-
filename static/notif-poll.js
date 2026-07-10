function _pushNotif(title, body){
  if(!document.hidden) return;
  if(Notification.permission !== 'granted') return;
  try{ new Notification(title, {body, icon:'/favicon.ico'}); }catch(e){}
}

function _setNotifBadge(n){
  [document.getElementById('sb-notif-badge'),
   document.getElementById('mn-notif-badge')].forEach(el=>{
    if(!el) return;
    el.textContent=n>99?'99+':n||'';
    el.style.display=n>0?'inline-block':'none';
  });
}

var _prevNotifCount=-1;
async function _pollNotifCount(){
  try{
    var r=await fetch('/api/notifications/mine/unread_count').then(function(x){return x.json();}).catch(function(){return null;});
    if(!r||!r.ok) return;
    var n=r.unread||0;
    _setNotifBadge(n);
    if(_prevNotifCount>=0 && n>_prevNotifCount){
      var nr=await fetch('/api/notifications/mine').then(function(x){return x.json();}).catch(function(){return null;});
      if(nr&&nr.ok&&nr.notifications&&nr.notifications.length){
        var notif=nr.notifications[0];
        var sep=notif.content.indexOf(': ');
        var title=sep>-1?notif.content.slice(0,sep):notif.content;
        var body=sep>-1?notif.content.slice(sep+2):'';
        _pushNotif(title,body);
      }
    }
    _prevNotifCount=n;
  }catch(_){}
}

if('Notification' in window) Notification.requestPermission();
setInterval(_pollNotifCount,15000);
async function _silentPushResubscribeCheck(){
  if(!('serviceWorker' in navigator) || !('PushManager' in window)) return;
  if(!('Notification' in window) || Notification.permission !== 'granted') return;
  try{
    var reg = await navigator.serviceWorker.getRegistration('/sw.js');
    if(!reg) reg = await navigator.serviceWorker.register('/sw.js');
    await navigator.serviceWorker.ready;
    var sub = await reg.pushManager.getSubscription();
    if(sub) return;
  }catch(e){}
}
