// OrcAgent service worker — receives Web Push events and shows notifications
// even when the site itself is closed.
self.addEventListener('install', function(event) {
  self.skipWaiting();
});
self.addEventListener('activate', function(event) {
  event.waitUntil(self.clients.claim());
});
