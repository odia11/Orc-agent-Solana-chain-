// ── SHARED GENERIC CONFIRM MODAL ────────────────────────────────────────────
// Replaces native confirm() dialogs with a house-style modal (same visual
// language as the delete-conversation and insufficient-balance modals).
// Pairs with templates/_confirm_modal.html. Promise-based so call sites can
// keep their original guard-clause shape:
//   if (!(await openConfirmModal({text: 'Delete this message?'}))) return;
// Pass {danger:true} for destructive actions (red Confirm button); omit it
// (or pass false) for neutral confirmations (amber accent Confirm button).
let _cmResolve = null;

function openConfirmModal(opts) {
  opts = opts || {};
  const titleEl   = document.getElementById('cm-title');
  const textEl    = document.getElementById('cm-text');
  const confirmBtn = document.getElementById('cm-confirm-btn');
  titleEl.textContent = opts.title || opts.text || 'Are you sure?';
  textEl.textContent  = opts.title ? (opts.text || '') : '';
  textEl.style.display = textEl.textContent ? 'block' : 'none';
  confirmBtn.textContent = opts.confirmLabel || 'Confirm';
  if (opts.danger) {
    confirmBtn.style.background = '#ff3b3b';
    confirmBtn.style.color = '#fff';
  } else {
    confirmBtn.style.background = 'var(--accent)';
    confirmBtn.style.color = '#0a0b0e';
  }
  document.getElementById('confirm-modal').classList.add('open');
  return new Promise(function(resolve) { _cmResolve = resolve; });
}

function closeConfirmModal(result) {
  document.getElementById('confirm-modal').classList.remove('open');
  const resolve = _cmResolve;
  _cmResolve = null;
  if (resolve) resolve(!!result);
}
