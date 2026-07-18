// ── SHARED GENERIC ALERT MODAL ──────────────────────────────────────────────
// Replaces native alert() popups with a house-style modal (same visual
// language as the delete-conversation and insufficient-balance modals).
// Pairs with templates/_alert_modal.html. Fire-and-forget by default, but
// returns a Promise that resolves on dismiss for callers that want to await it:
//   openAlertModal({text: 'Could not delete this notification.'});
let _amResolve = null;

function openAlertModal(opts) {
  opts = opts || {};
  const titleEl = document.getElementById('am-title');
  const textEl  = document.getElementById('am-text');
  titleEl.textContent = opts.title || opts.text || '';
  textEl.textContent  = opts.title ? (opts.text || '') : '';
  textEl.style.display = textEl.textContent ? 'block' : 'none';
  document.getElementById('alert-modal').classList.add('open');
  return new Promise(function(resolve) { _amResolve = resolve; });
}

function closeAlertModal() {
  document.getElementById('alert-modal').classList.remove('open');
  const resolve = _amResolve;
  _amResolve = null;
  if (resolve) resolve();
}
