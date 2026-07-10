// OrcAgent service worker — receives Web Push events and shows notifications
// even when the site itself is closed.
self.addEventListener('install', function(event) {
  self.skipWaiting();
});
self.addEventListener('activate', function(event) {
  event.waitUntil(self.clients.claim());
});
self.addEventListener('push', function(event) {
  var data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) {}
  var title = data.title || 'OrcAgent';
  var body  = data.body  || '';
  var url   = data.url   || '/';
  event.waitUntil(
    self.registration.showNotification(title, {
      body: body,
      icon: '/favicon.svg',
      badge: '/favicon.svg',
      data: { url: url }
    })
  );
});
