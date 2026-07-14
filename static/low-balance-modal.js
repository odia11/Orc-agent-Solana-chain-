// ── INSUFFICIENT SOL BALANCE MODAL ──────────────────────────────────────────
// Shared by dashboard.html (bot start) and messages.html (copy trade) — pairs
// with templates/_low_balance_modal.html. Keep this the single implementation
// so desktop and mobile never drift into separate variants.
let _lbDepositAddr = null;

function showLowBalanceModal(data){
  _lbDepositAddr = data.trading_wallet || null;
  document.getElementById('lb-current').textContent  = (typeof data.current_sol  === 'number' ? data.current_sol.toFixed(4)  : '—') + ' SOL';
  document.getElementById('lb-required').textContent  = (typeof data.required_sol === 'number' ? data.required_sol.toFixed(4) : '—') + ' SOL';
  document.getElementById('lb-addr-text').textContent = _lbDepositAddr || '—';
  document.getElementById('lb-copy-msg').textContent  = '';
  document.getElementById('lb-copy-btn').textContent  = '📋';
  document.getElementById('low-balance-modal').classList.add('open');
}

function closeLowBalanceModal(){
  document.getElementById('low-balance-modal').classList.remove('open');
}

function copyLowBalanceAddr(){
  if (!_lbDepositAddr) return;
  const copyFallback = () => {
    const ta = document.createElement('textarea');
    ta.value = _lbDepositAddr;
    ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch(_) {}
    document.body.removeChild(ta);
  };
  const done = () => {
    document.getElementById('lb-copy-msg').textContent = '✓ Copied to clipboard';
    document.getElementById('lb-copy-btn').textContent = '✓';
    setTimeout(() => {
      document.getElementById('lb-copy-msg').textContent = '';
      document.getElementById('lb-copy-btn').textContent = '📋';
    }, 2000);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(_lbDepositAddr).then(done).catch(() => { copyFallback(); done(); });
  } else {
    copyFallback(); done();
  }
}
