// OrcAgent push notification subscription flow.
// Call _enablePushNotifications() from a button click (must be a real user
// gesture — browsers block permission prompts triggered automatically).
function _urlBase64ToUint8Array(base64String) {
  var padding = '='.repeat((4 - base64String.length % 4) % 4);
  var base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  var rawData = window.atob(base64);
  var outputArray = new Uint8Array(rawData.length);
  for (var i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}
async function _enablePushNotifications() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    alert('Push notifications are not supported on this browser.');
    return { ok: false, msg: 'Not supported' };
  }
  try {
    var perm = await Notification.requestPermission();
    if (perm !== 'granted') {
      return { ok: false, msg: 'Permission denied' };
    }
    var reg = await navigator.serviceWorker.register('/static/sw.js');
    await navigator.serviceWorker.ready;
    var keyRes = await fetch('/api/push/vapid-public-key').then(function(r) { return r.json(); });
    var appServerKey = _urlBase64ToUint8Array(keyRes.key);
    var sub = await reg.pushManager.getSubscription();
    if (!sub) {
      sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: appServerKey
      });
    }
  } catch (e) {
    console.error('[push] subscribe failed', e);
    return { ok: false, msg: String(e) };
  }
}
