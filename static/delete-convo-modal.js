// ── DELETE CONVERSATION CONFIRM MODAL ───────────────────────────────────────
// Shared by messages.html (swipe-to-delete + desktop hover-icon flow) and
// dashboard.js (embedded DM panel) — replaces the native confirm() dialog
// with a house-style modal. Pairs with templates/_delete_convo_modal.html.
// Generic callback design: each caller passes its own delete function since
// messages.html and dashboard.js track conversations in separate state
// (_conversations vs _dmConvos) with separate delete implementations.
let _dcmOnConfirm = null;

function openDeleteConvoModal(onConfirm) {
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
