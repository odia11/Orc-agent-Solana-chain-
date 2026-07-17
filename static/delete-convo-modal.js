// ── SHARED DELETE-CONFIRM MODAL ─────────────────────────────────────────────
// Originally built for messages.html (swipe-to-delete + desktop hover-icon
// flow) and dashboard.js (embedded DM panel) — replaces the native confirm()
// dialog with a house-style modal. Also reused by notifications.html for
// deleting a single notification, via the optional title/text override.
// Pairs with templates/_delete_convo_modal.html.
// Generic callback design: each caller passes its own delete function since
// callers track their own state (_conversations / _dmConvos / _personal)
// with separate delete implementations.
let _dcmOnConfirm = null;
const _DCM_DEFAULT_TITLE = 'Delete this conversation?';
const _DCM_DEFAULT_TEXT  = 'This only removes it from your inbox — the other person keeps their copy.';

function openDeleteConvoModal(onConfirm, opts) {
  opts = opts || {};
  const titleEl = document.getElementById('dcm-title');
  const textEl  = document.getElementById('dcm-text');
  if (titleEl) titleEl.textContent = opts.title || _DCM_DEFAULT_TITLE;
  if (textEl)  textEl.textContent  = opts.text  || _DCM_DEFAULT_TEXT;
  _dcmOnConfirm = onConfirm;
  document.getElementById('delete-convo-modal').classList.add('open');
}

function closeDeleteConvoModal() {
  document.getElementById('delete-convo-modal').classList.remove('open');
  _dcmOnConfirm = null;
}

function _dcmConfirm() {
  const fn = _dcmOnConfirm;
  closeDeleteConvoModal();
  if (fn) fn();
}
