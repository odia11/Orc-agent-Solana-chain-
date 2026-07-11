let traderOn=false, phantomKey=null, walletType=null, currentStep=0, _isAdmin=false, _copySource=null;
var _isReadonly = false;
let guestMode = false;
/* ── Pre-populate navbar from server session (eliminates "not connected" flash) ── */
(function(){
  var sw=window.__SESSION_WALLET||'', ss=window.__SESSION_SHORT||'';
  if(!sw) return;
  phantomKey=sw;
  var pill=document.getElementById('wallet-pill');
  var sh=document.getElementById('wallet-short');
  var ini=document.getElementById('nav-avatar-ini');
  if(pill) pill.style.display='flex';
  if(sh)   sh.textContent=ss;
  if(ini){ ini.style.display='flex'; ini.textContent=sw.slice(0,2).toUpperCase(); }
  // Early admin visibility — avoids waiting for async launchApp()
  if(sw.startsWith('HC5ahspSox3XRm')){
    var _al=document.getElementById('sb-admin-link');
    var _ab=document.getElementById('admin-btn');
    if(_al) _al.style.display='flex';
    if(_ab) _ab.style.display='';
  }
})();

/* ── CONNECT SCREEN HELPERS ── */
function _toggleManual(){
  var sec=document.getElementById('ob-manual-section');
  if(!sec) return;
  var open=sec.classList.toggle('open');
  var btn=document.getElementById('ob-manual-toggle');
  if(btn) btn.textContent=open?'▲ Enter wallet address':'📋 Enter wallet address';
  if(open) setTimeout(function(){ var inp=document.getElementById('ob-manual-addr'); if(inp) inp.focus(); },100);
}

async function connectReadonlyAddress(){
  var inp=document.getElementById('ob-manual-addr');
  var errEl=document.getElementById('ob-manual-err');
  var btn=document.getElementById('ob-manual-connect');
  var addr=inp?inp.value.trim():'';
  if(errEl) errEl.textContent='';
  if(!addr){ if(errEl) errEl.textContent='Please paste a Solana wallet address.'; return; }
  if(btn){ btn.disabled=true; btn.textContent='Connecting…'; }
  try{
    var r=await fetch('/api/wallet/connect-readonly',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({address:addr})
    }).then(function(x){ return x.json(); });
    if(r.ok){
      phantomKey=r.wallet; walletType='readonly'; _isReadonly=true;
      if(r.csrf_token) _csrfToken=r.csrf_token;
      launchApp();
    } else {
      if(errEl) errEl.textContent=r.msg||'Invalid address.';
    }
  }catch(e){ if(errEl) errEl.textContent='Connection failed — please try again.'; }
  finally{ if(btn){ btn.disabled=false; btn.textContent='CONNECT (read-only) →'; } }
}

async function _webAuthnLogin(){
  var errEl=document.getElementById('ob-bio-err');
  var btn=document.getElementById('ob-bio-btn');
  var label=document.getElementById('ob-bio-label');
  if(errEl) errEl.textContent='';
  if(!window.PublicKeyCredential){
    if(errEl) errEl.textContent='WebAuthn not supported on this device.';
    _showWalletOptions(); return;
  }
  if(btn) btn.disabled=true;
  if(label) label.textContent='Authenticating…';
  var failed=false;
  try{
    var storedId=localStorage.getItem('orca_credential_id');
    var allowCreds=[];
    if(storedId){
      try{ allowCreds=[{type:'public-key',id:Uint8Array.from(atob(storedId),function(c){return c.charCodeAt(0);})}]; }catch(e){}
    }
    var ch=new Uint8Array(32); crypto.getRandomValues(ch);
    var cred=await navigator.credentials.get({
      publicKey:{rpId:'orcagent.fun',challenge:ch,timeout:60000,userVerification:'required',allowCredentials:allowCreds}
    });
    if(!cred){ if(errEl) errEl.textContent='Face ID failed.'; failed=true; return; }
    var rawIdB64=btoa(String.fromCharCode(...new Uint8Array(cred.rawId)));
    var r=await fetch('/api/auth/webauthn/login',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({credential_id:rawIdB64})
    }).then(res=>res.json()).catch(()=>null);
    if(r&&r.success){
      location.reload();
    } else {
      if(errEl) errEl.textContent=(r&&r.msg)||'Face ID failed — try connecting wallet instead.';
      failed=true;
    }
  }catch(e){
    var em=e.name==='NotAllowedError'?'Face ID failed — try connecting wallet instead.':
           e.name==='SecurityError'?'Domain mismatch — passkey not valid for this site.':
           'Auth failed: '+(e.message||e.name);
    if(errEl) errEl.textContent=em;
    failed=true;
  }finally{
    if(btn) btn.disabled=false;
    if(label) label.textContent='Login with Face ID';
    if(failed) _showWalletOptions();
  }
}

async function _loginWithPassword(){
  var userEl=document.getElementById('ob-pwd-user');
  var passEl=document.getElementById('ob-pwd-pass');
  var errEl=document.getElementById('ob-pwd-err');
  var btn=document.getElementById('ob-pwd-btn');
  if(errEl) errEl.textContent='';
  var username=(userEl&&userEl.value||'').trim();
  var password=passEl&&passEl.value||'';
  if(!username||!password){ if(errEl) errEl.textContent='Please enter your username and password.'; return; }
  if(btn){ btn.disabled=true; btn.textContent='Logging in…'; }
  try{
    var r=await fetch('/api/login_password',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:username,password:password})
    }).then(res=>res.json()).catch(()=>null);
    if(r&&r.success){
      if(r.csrf_token) _csrfToken=r.csrf_token;
      window.location.href='/dashboard';
    } else {
      if(errEl) errEl.textContent=(r&&r.error)||'Login failed — check your credentials.';
    }
  }catch(e){
    if(errEl) errEl.textContent='Login failed — please try again.';
  }finally{
    if(btn){ btn.disabled=false; btn.textContent='Login & Trade'; }
  }
}

function _showWalletOptions(){
  /* Reveal wallet buttons after Face ID failure or "connect a wallet instead" tap */
  var nullEl={style:{},innerHTML:'',textContent:''};
  var wbtns=document.getElementById('ob-wallet-btns');
  var phantomBtn=document.getElementById('phantom-ob-btn');
  var solflareBtn=document.getElementById('solflare-ob-btn');
  var phantomNote=document.getElementById('ob-phantom-note');
  var skipBtn=document.getElementById('ob-skip-btn');
  if(wbtns)       wbtns.style.display='block';
  if(phantomBtn)  phantomBtn.style.display='flex';
  if(solflareBtn) solflareBtn.style.display='flex';
  if(phantomNote) phantomNote.style.display='';
  if(skipBtn)     skipBtn.style.display='flex';
  _applyPhantomDetection(phantomBtn, phantomNote||nullEl);
  _applySolflareDetection(solflareBtn, nullEl);
}

async function _setupFaceID(){
  var wallet=phantomKey;
  var btn=document.getElementById('s-faceid-prompt-btn');
  var msg=document.getElementById('s-faceid-prompt-msg');
  function _show(text,ok){
    if(!msg) return;
    msg.style.color=ok?'var(--green)':'var(--red)';
    msg.textContent=text;
  }
  if(!wallet){ _show('Connect a wallet first.',false); return; }
  if(!window.PublicKeyCredential){ _show('WebAuthn not supported on this device.',false); return; }
  if(btn){ btn.disabled=true; btn.textContent='Setting up…'; }
  if(msg){ msg.style.color='var(--muted)'; msg.textContent=''; }
  try{
    var ch=new Uint8Array(32); crypto.getRandomValues(ch);
    var uid=new Uint8Array(32);
    new TextEncoder().encode(wallet).slice(0,32).forEach(function(b,i){ uid[i]=b; });
    var cred=await navigator.credentials.create({
      publicKey:{
        rp:{id:'orcagent.fun',name:'OrcAgent'},
        user:{id:uid,name:wallet,displayName:wallet},
        challenge:ch,
        pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
        timeout:60000,
        authenticatorSelection:{
          authenticatorAttachment:'platform',
          userVerification:'preferred',
          residentKey:'preferred'
        },
        attestation:'none'
      }
    });
    if(!cred){ _show('Registration failed — please try again.',false); return; }
    var rawIdB64=btoa(String.fromCharCode(...new Uint8Array(cred.rawId)));
    var attObjB64=btoa(String.fromCharCode(...new Uint8Array(cred.response.attestationObject)));
    var r=await fetch('/api/auth/webauthn/register',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({credential_id:rawIdB64,public_key:attObjB64})
    }).then(res=>res.json()).catch(()=>null);
    if(r&&r.success){
      localStorage.setItem('orca_credential_id',rawIdB64);
      _show('✓ Face ID saved!',true);
      _updateFaceIdStatus();
      setTimeout(function(){ var p=document.getElementById('s-faceid-prompt'); if(p) p.style.display='none'; },2500);
    } else {
      _show('Registration failed: '+((r&&r.msg)||'unknown error'),false);
    }
  }catch(e){
    _show(e.name==='NotAllowedError'?'Setup cancelled.':
          e.name==='InvalidStateError'?'Passkey already exists — try logging in.':
          'Setup failed: '+(e.message||e.name), false);
  }finally{
    if(btn){ btn.disabled=false; btn.textContent='Setup Face ID'; }
  }
}

async function _setupFaceId(){
  var wallet=phantomKey;
  if(!wallet){ alert('Connect a wallet first.'); return; }
  if(!window.PublicKeyCredential){ alert('WebAuthn not supported on this device.'); return; }
  var btn=document.getElementById('s-faceid-btn');
  var msg=document.getElementById('s-faceid-msg');
  if(btn){ btn.disabled=true; btn.textContent='Setting up…'; }
  if(msg){ msg.style.color='var(--muted)'; msg.textContent=''; }
  try{
    var ch=new Uint8Array(32); crypto.getRandomValues(ch);
    var uid=new Uint8Array(32);
    var wb=new TextEncoder().encode(wallet); uid.set(wb.slice(0,32));
    var cred=await navigator.credentials.create({
      publicKey:{
        rp:{id:'orcagent.fun',name:'OrcAgent'},
        user:{id:uid,name:wallet,displayName:wallet},
        challenge:ch,
        pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
        timeout:60000,
        authenticatorSelection:{userVerification:'preferred',residentKey:'preferred'},
        attestation:'none'
      }
    });
    if(!cred){
      if(msg){ msg.style.color='var(--red)'; msg.textContent='Registration failed — please try again.'; } return;
    }
    var rawIdB64=btoa(String.fromCharCode(...new Uint8Array(cred.rawId)));
    var attObjB64=btoa(String.fromCharCode(...new Uint8Array(cred.response.attestationObject)));
    var r=await fetch('/api/auth/webauthn/register',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({credential_id:rawIdB64,public_key:attObjB64,wallet_address:wallet})
    }).then(res=>res.json()).catch(()=>null);
    if(r && r.success){
      localStorage.setItem('orca_credential_id',rawIdB64);
      if(msg){ msg.style.color='var(--green)'; msg.textContent='Face ID saved! Use it to login next time.'; }
      _updateFaceIdStatus();
    } else {
      if(msg){ msg.style.color='var(--red)'; msg.textContent='Registration failed: '+((r&&r.msg)||'unknown error'); }
    }
  }catch(e){
    var em=e.name==='NotAllowedError'?'Setup cancelled.':
           e.name==='InvalidStateError'?'A passkey already exists for this device — try logging in.':
           'Setup failed: '+(e.message||e.name);
    if(msg){ msg.style.color='var(--red)'; msg.textContent=em; }
  }finally{
    if(btn) btn.disabled=false;
    _updateFaceIdStatus();
  }
}

function _removeFaceId(){
  if(!confirm('Remove saved Face ID login from this device?')) return;
  localStorage.removeItem('orca_credential_id');
  var msg=document.getElementById('s-faceid-msg');
  if(msg){ msg.style.color='var(--muted)'; msg.textContent='Face ID removed.'; }
  _updateFaceIdStatus();
}

function _updateFaceIdStatus(){
  var has=!!localStorage.getItem('orca_credential_id');
  var status=document.getElementById('s-faceid-status');
  var btn=document.getElementById('s-faceid-btn');
  var removeBtn=document.getElementById('s-faceid-remove-btn');
  var bioBtn=document.getElementById('ob-bio-btn');
  if(status) status.textContent=has?'Face ID is set up on this device.':'Not set up.';
  if(btn) btn.textContent=has?'Update Face ID':'Setup Face ID login';
  if(removeBtn) removeBtn.style.display=has?'':'none';
  if(bioBtn) bioBtn.style.display=has?'':'none';
}

/* Called by the post-key-save Face ID prompt in Settings */
async function _settingsFaceIdSetup(){
  var promptBtn=document.getElementById('s-faceid-prompt-btn');
  var promptMsg=document.getElementById('s-faceid-prompt-msg');
  if(promptBtn){ promptBtn.disabled=true; promptBtn.textContent='Setting up…'; }
  if(promptMsg){ promptMsg.style.color='var(--muted)'; promptMsg.textContent=''; }
  await _setupFaceId();
  if(promptBtn){ promptBtn.disabled=false; promptBtn.textContent='Setup Face ID'; }
  if(localStorage.getItem('orca_credential_id')){
    if(promptMsg){ promptMsg.style.color='var(--green)'; promptMsg.textContent='✓ Face ID saved! Next time login with just your face.'; }
    setTimeout(function(){ var p=document.getElementById('s-faceid-prompt'); if(p) p.style.display='none'; },2800);
  } else {
    /* _setupFaceId already wrote an error to s-faceid-msg — copy it to the prompt area */
    var faceMsg=document.getElementById('s-faceid-msg');
    if(promptMsg && faceMsg && faceMsg.textContent){
      promptMsg.style.color='var(--red)'; promptMsg.textContent=faceMsg.textContent;
    }
  }
}

/* Mobile deep-link constants — used by wallet detection below */
const isMobile=/iPhone|iPad|Android/i.test(navigator.userAgent);
const phantomDeepLink='https://phantom.app/ul/browse/'+encodeURIComponent('https://orcagent.fun');
const solflareDeepLink='https://solflare.com/ul/v1/browse/'+encodeURIComponent('https://orcagent.fun');

// Minimal base58 encoder for Phantom v1/connect deep link keypair
var _b58enc=(function(){
  var A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  return function(buf){
    var d=[],s='';
    for(var i=0;i<buf.length;i++){
      var c=buf[i];
      for(var j=0;j<d.length;j++){c+=d[j]<<8;d[j]=c%58;c=c/58|0;}
      while(c>0){d.push(c%58);c=c/58|0;}
    }
    for(var k=0;buf[k]===0&&k<buf.length-1;k++) s+='1';
    return s+d.reverse().map(function(x){return A[x];}).join('');
  };
})();

async function _connectWalletSigned(provider, address){
  async function _attempt(){
    // 1. Fetch nonce
    var nr = await fetch('/api/auth/nonce').then(function(r){return r.json();}).catch(function(){return null;});
    if(!nr || !nr.ok) return {ok:false, msg:'Failed to get nonce'};

    // 2. Sign — catch user rejection separately so it doesn't fall to outer catch
    var result;
    try{
      result = await provider.signMessage(new TextEncoder().encode(nr.message), 'utf8');
    }catch(e){
      return {ok:false, msg:'Signature rejected'};
    }

    // 3. Normalise: Phantom → {signature:Uint8Array}, Solflare → Uint8Array directly
    var sigBytes = (result instanceof Uint8Array)
      ? result
      : (result && result.signature instanceof Uint8Array ? result.signature : null);
    if(!sigBytes) return {ok:false, msg:'Signature rejected'};

    // 4. Base58-encode signature bytes
    var sigB58 = _b58enc(sigBytes);

    // 5. POST /api/wallet/set with proof
    var r = await fetch('/api/wallet/set',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({address:address, signature:sigB58, nonce:nr.nonce})
    }).then(function(x){return x.json();}).catch(function(){return null;});

    return r || {ok:false, msg:'Network error'};
  }

  var r = await _attempt();
  // Nonce expired (e.g. user took >5 min in Phantom app on mobile) — retry once with a fresh nonce
  if(r && !r.ok && r.msg === 'Nonce expired, try again'){
    r = await _attempt();
  }
  return r;
}

function _phantomMobileV1Connect(){
  localStorage.removeItem('orca_manual_disconnect');
  var msgEl=document.getElementById('wallet-install-msg');
  var noteEl=document.getElementById('ob-phantom-note');
  function _setNote(txt,col){
    if(noteEl){noteEl.textContent=txt;if(col)noteEl.style.color=col;}
    if(msgEl&&msgEl!==noteEl){msgEl.textContent=txt;msgEl.style.display='block';}
  }
  _setNote('Initialising connection…','var(--muted)');
  // Server generates the NaCl keypair — no browser storage needed
  fetch('/api/phantom/init',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:'{}'})
  .then(function(r){return r.json();})
  .then(function(d){
    if(!d.ok||!d.dapp_pk||!d.token){
      _setNote('Connection init failed — please try again.','var(--red)');
      return;
    }
    var _cbUrl='https://orcagent.fun/phantom-callback?token='+encodeURIComponent(d.token)+'&_cb='+Date.now();
    console.log('[phantom] server-side init ok, token=',d.token.slice(0,8)+'…');
    var params=new URLSearchParams({
      app_url:'https://orcagent.fun',
      dapp_encryption_public_key:d.dapp_pk,
      redirect_link:_cbUrl,
      cluster:'mainnet-beta'
    });
    window.location.href='https://phantom.app/ul/v1/connect?'+params.toString();
  })
  .catch(function(e){
    _setNote('Network error — please try again.','var(--red)');
    console.error('[phantom] init fetch failed:',e);
  });
}

function _applyPhantomDetection(phantomBtn, phantomNote){
  if(!phantomBtn||!phantomNote) return;
  if(window.solana&&window.solana.isPhantom) return; // extension present — nothing to do
  if(isMobile){
    /* Mobile: use Phantom v1/connect Universal Link */
    phantomBtn.onclick=function(){ _phantomMobileV1Connect(); };
    var lbl=document.getElementById('phantom-ob-label');
    if(lbl) lbl.textContent='Connect Phantom →';
    if(phantomNote){ phantomNote.textContent='Opens Phantom to approve connection'; phantomNote.style.color='var(--muted)'; }
  } else {
    /* Desktop: not installed — change button to install link */
    var _pLbl=document.getElementById('phantom-ob-label');
    if(_pLbl) _pLbl.textContent='Install Phantom ↗';
    phantomBtn.onclick=function(){ window.open('https://phantom.app','_blank','noopener'); };
    if(phantomNote) phantomNote.innerHTML='';
  }
}

function _applySolflareDetection(solflareBtn, solflareNote){
  if(!solflareBtn||!solflareNote) return;
  if(window.solflare) return;
  // Solflare injects window.solflare asynchronously on some browsers — wait before applying fallback
  setTimeout(function(){
    if(window.solflare) return;
    if(isMobile){
      solflareBtn.onclick=function(){ window.location.href=solflareDeepLink; };
      var lbl=solflareBtn.querySelector('span')||solflareBtn;
      if(lbl.tagName==='SPAN') lbl.textContent='Open in Solflare →';
      else solflareBtn.textContent='Open in Solflare →';
      solflareNote.textContent='Opens OrcAgent inside your wallet\'s browser';
      solflareNote.style.color='var(--muted)';
    } else {
      var _sfSvg=solflareBtn.querySelector('svg');
      solflareBtn.innerHTML=(_sfSvg?_sfSvg.outerHTML:'')+' Install Solflare ↗';
      solflareBtn.onclick=function(){ window.open('https://solflare.com','_blank','noopener'); };
    }
  }, 400);
}

/* On load: switch connect screen between Face ID / password / Phantom modes */
document.addEventListener('DOMContentLoaded',function(){
  var hasFaceId=!!localStorage.getItem('orca_credential_id');
  var bioBtn    =document.getElementById('ob-bio-btn');
  var altLink   =document.getElementById('ob-alt-link');
  var pwdForm   =document.getElementById('ob-pwd-form');
  var wbtns     =document.getElementById('ob-wallet-btns');
  var phantomBtn=document.getElementById('phantom-ob-btn');
  var phantomNote=document.getElementById('ob-phantom-note');
  var solflareBtn=document.getElementById('solflare-ob-btn');
  var skipBtn   =document.getElementById('ob-skip-btn');
  var nullEl    ={style:{},innerHTML:'',textContent:''};

  if(hasFaceId){
    /* Face ID mode: show Face ID button + "or connect differently" link; hide wallet buttons */
    if(bioBtn)   bioBtn.style.display='flex';
    if(altLink)  altLink.style.display='';
    if(pwdForm)  pwdForm.style.display='none';
    if(wbtns)    wbtns.style.display='none';
  } else {
    /* No Face ID: show both wallet connect buttons */
    if(pwdForm)     pwdForm.style.display='none';
    if(bioBtn)      bioBtn.style.display='none';
    if(altLink)     altLink.style.display='none';
    if(wbtns)       wbtns.style.display='block';
    if(phantomBtn)  phantomBtn.style.display='flex';
    if(solflareBtn) solflareBtn.style.display='flex';
    _applyPhantomDetection(phantomBtn, phantomNote||nullEl);
    _applySolflareDetection(solflareBtn, nullEl);
  }
});

// ── CSRF TOKEN ──
let _csrfToken = '';

// Shared client secret, injected server-side at page-serve time (see index() in
// dashboard.py). Empty string when API_SHARED_SECRET isn't configured on the server.
const _CLIENT_SECRET = window.__API_SHARED_SECRET||'';

// Override fetch globally: inject X-CSRF-Token and X-API-Shared-Secret into all mutating
// requests. The override is installed synchronously so it covers every fetch call below.
// _csrfToken is populated asynchronously by _initCsrf(); it's empty until then
// but the server only requires it for authenticated sessions, so the race is safe.
(function(){
  const _origFetch = window.fetch.bind(window);
  window.fetch = function(url, opts) {
    opts = Object.assign({}, opts || {});
    const method = ((opts.method || 'GET') + '').toUpperCase();
    if (['POST','PUT','PATCH','DELETE'].includes(method)) {
      const extra = {};
      if (_csrfToken) extra['X-CSRF-Token'] = _csrfToken;
      if (_CLIENT_SECRET) extra['X-API-Shared-Secret'] = _CLIENT_SECRET;
      opts.headers = Object.assign({}, opts.headers || {}, extra);
    }
    return _origFetch(url, opts);
  };
})();

async function _initCsrf(){
  try {
    const r = await window.fetch('/api/csrf-token').then(r=>r.json()).catch(()=>null);
    if(r && r.token) _csrfToken = r.token;
  } catch(e) {}
}

// Fetch CSRF token immediately on page load (before any user interaction)
_initCsrf();

// ── INACTIVITY TIMEOUT ──
const INACT_WARN_MS   = 8 * 60 * 1000;  // warn at 8 min
const INACT_LIMIT_MS  = 10 * 60 * 1000; // logout at 10 min
let _lastActivity     = Date.now();
let _warnShown        = false;
let _warnTick         = null;

function _resetActivity(){
  _lastActivity = Date.now();
  if(_warnShown) _hideInactWarning();
}

function _hideInactWarning(){
  _warnShown = false;
  document.getElementById('inact-overlay').style.display = 'none';
  if(_warnTick){ clearInterval(_warnTick); _warnTick = null; }
}

function stayConnected(){ _resetActivity(); }

function _showInactWarning(){
  if(_warnShown || !phantomKey) return;
  _warnShown = true;
  document.getElementById('inact-overlay').style.display = 'flex';
  if(_warnTick) clearInterval(_warnTick);
  _warnTick = setInterval(()=>{
    const rem = Math.max(0, INACT_LIMIT_MS - (Date.now() - _lastActivity));
    const secs = Math.ceil(rem / 1000);
    const el = document.getElementById('inact-countdown');
    if(el) el.textContent = secs;
    if(rem <= 0){ clearInterval(_warnTick); _warnTick = null; }
  }, 500);
}

function _checkInactivity(){
  if(!phantomKey) return;
  if(traderOn){ _hideInactWarning(); return; } // never log out while bot is running
  const idle = Date.now() - _lastActivity;
  if(idle >= INACT_LIMIT_MS){
    _hideInactWarning();
    doLogout();
  } else if(idle >= INACT_WARN_MS && !_warnShown){
    _showInactWarning();
  }
}

// User activity resets the timer
['mousemove','mousedown','keydown','scroll','touchstart','click'].forEach(evt=>{
  document.addEventListener(evt, _resetActivity, {passive:true});
});

// ── LOGOUT ──
function doLogout(){
  _hideInactWarning();
  phantomKey=null; walletType=null; _isAdmin=false;
  updateAuthBtns();
  fetch('/api/wallet/set',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:''})}).catch(()=>{});
  document.getElementById('wallet-pill').style.display='none';
  document.getElementById('deposit-sol-btn').style.display='none';
  document.getElementById('withdraw-sol-btn').style.display='none';
  document.getElementById('perf-share-btns').style.display='none';
  _resetBadges();
  _resetMyProfile();
  _copySource=null; _updateCopyPill();
  document.getElementById('app').style.display='none';
  document.getElementById('onboard').classList.remove('hide');
  document.getElementById('s-sol').innerHTML='<span class="stat-placeholder">——</span>';
  _solCounterDone=false;
  currentStep=0; showStep(0);
}

// ── ONBOARDING ──
function showStep(n){
  document.querySelectorAll('.ob-step').forEach((s,i)=>s.classList.toggle('active',i===n));
  document.querySelectorAll('.ob-dot').forEach((d,i)=>{d.classList.toggle('done',i<n);d.classList.toggle('active',i===n);});
}
function nextStep(n){currentStep=n+1;showStep(currentStep);}
function gotoSetupGuide(){currentStep=1;showStep(1);}

async function connectWalletOnboard(type){
  localStorage.removeItem('orca_manual_disconnect');
  const isPhantom=type==='phantom';
  const provider=isPhantom?window.solana:window.solflare;
  const name=isPhantom?'Phantom':'Solflare';
  const installUrl=isPhantom?'https://phantom.app':'https://solflare.com';
  const check=isPhantom?provider?.isPhantom:!!provider;
  const msgEl=document.getElementById('wallet-install-msg');

  if(!check){
    /* On mobile without the extension, use deep link */
    if(isMobile){ if(isPhantom){ _phantomMobileV1Connect(); return; } window.location.href=solflareDeepLink; return; }
    const other=isPhantom?'Solflare':'Phantom';
    const otherUrl=isPhantom?'https://solflare.com':'https://phantom.app';
    msgEl.innerHTML=name+' wallet not detected. <a href="'+installUrl+'" target="_blank" style="color:var(--blue);text-decoration:underline">Install '+name+'</a> or try <a href="'+otherUrl+'" target="_blank" style="color:var(--blue);text-decoration:underline">'+other+'</a>.';
    msgEl.style.display='block';
    return;
  }
  msgEl.style.display='none';
  try{
    const resp=await provider.connect();
    const pubkey=provider.publicKey||resp?.publicKey;
    if(!pubkey){
      msgEl.textContent='Could not get wallet address — please try again.';
      msgEl.style.display='block';
      return;
    }
    phantomKey=pubkey.toString();
    walletType=name;
    document.getElementById('wallet-type-label').textContent=name+' wallet connected';
    document.getElementById('wallet-addr').textContent=phantomKey;
    document.getElementById('wallet-connected').style.display='flex';
    var _wbtns=document.getElementById('ob-wallet-btns');
    if(_wbtns) _wbtns.style.display='none';
    document.getElementById('phantom-ob-btn').style.display='none';
    document.getElementById('solflare-ob-btn').style.display='none';
    const cb=document.getElementById('step1-continue-btn');
    cb.disabled=false; cb.style.cssText='';
    document.getElementById('wallet-back-btn').style.display='flex';
    const r=await _connectWalletSigned(provider, phantomKey);
    if(!r?.ok && (r?.msg==='Signature rejected'||(r?.msg||'').startsWith('Nonce expired'))){
      msgEl.textContent='Onderteken het verzoek in je wallet om in te loggen — probeer opnieuw';
      msgEl.style.display='block'; return;
    }
    if(r?.csrf_token) _csrfToken=r.csrf_token;
    settingsHasKey=r?.has_trading_key||false; _isAdmin=r?.is_admin||false; _updateKeyStatus();
    if(r?.success){
      if(r.status==='new_user'){ gotoSetupGuide(); return; }
      await launchApp(); return;
    }
  }catch(e){
    msgEl.textContent='Connection rejected or failed — please try again.';
    msgEl.style.display='block';
    console.error(e);
  }
}

function resetWallet(){
  phantomKey=null; walletType=null;
  fetch('/api/wallet/set',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:''})}).catch(()=>{});
  document.getElementById('wallet-install-msg').style.display='none';
  document.getElementById('wallet-connected').style.display='none';
  var _wbtns=document.getElementById('ob-wallet-btns');
  if(_wbtns) _wbtns.style.display='block';
  document.getElementById('phantom-ob-btn').style.display='flex';
  document.getElementById('solflare-ob-btn').style.display='flex';
  const cb=document.getElementById('step1-continue-btn');
  cb.disabled=true; cb.style.display='none';
  document.getElementById('wallet-back-btn').style.display='none';
}

// ── ONBOARDING: key entry step ──
async function _obSaveKey(){
  const ta=document.getElementById('ob-privkey');
  const errEl=document.getElementById('ob-key-err');
  const btn=document.getElementById('ob-save-key-btn');
  const key=(ta?ta.value:'').trim();
  if(!key){ if(errEl) errEl.textContent='Please paste your private key.'; return; }
  if(errEl) errEl.textContent='';
  const origText=btn.textContent; btn.textContent='Saving…'; btn.disabled=true;
  try{
    const r=await fetch('/api/wallet/set-key',{
      method:'POST',
      credentials:'include',
      headers:{'Content-Type':'application/json','X-CSRF-Token':_csrfToken},
      body:JSON.stringify({private_key:key})
    }).then(x=>x.json()).catch(()=>null);
    if(r?.ok){
      settingsHasKey=true; _updateKeyStatus();
      await launchApp();
    } else {
      if(errEl) errEl.textContent=r?.msg||'Invalid key — check format and try again.';
      btn.textContent=origText; btn.disabled=false;
    }
  }catch(e){
    if(errEl) errEl.textContent='Network error — please try again.';
    btn.textContent=origText; btn.disabled=false;
  }
}

function disconnectWallet(){
  var _wp=walletType==='Phantom'?window.solana:(walletType==='Solflare'?window.solflare:(window.solana||window.solflare));
  var _doLogout=function(){
    fetch('/api/logout',{method:'POST',credentials:'include'}).finally(function(){
      phantomKey=null; walletType=null; guestMode=false;
      localStorage.removeItem('orca_credential_id');
      localStorage.setItem('orca_manual_disconnect','1');
      window.location.reload();
    });
  };
  if(_wp&&_wp.disconnect){ _wp.disconnect().then(_doLogout).catch(_doLogout); }
  else { _doLogout(); }
}
function _obSkipKey(){
  launchApp();
  setTimeout(function(){ _checkWelcomeBanner(); }, 400);
}

function skipToApp(){
  guestMode = true;
  phantomKey=null; walletType=null;
  launchApp();
}
function enterGuestMode(){ skipToApp(); }
function _showGuestBanner(){
  var gb=document.getElementById('guest-banner');
  if(!gb) return;
  gb.style.display='flex';
  document.getElementById('app').style.paddingTop=gb.offsetHeight+'px';
}
function _minimizeGuestBanner(){
  var gb=document.getElementById('guest-banner');
  if(gb) gb.style.display='none';
  var app=document.getElementById('app');
  if(app) app.style.paddingTop='';
}
function _guestConnect(){
  _minimizeGuestBanner();
  var app=document.getElementById('app');
  if(app) app.style.display='none';
  var ob=document.getElementById('onboard');
  if(ob) ob.classList.remove('hide');
  currentStep=0; showStep(0);
}
function checkGuest(){
  if(!guestMode) return false;
  _showGuestWall();
  return true;
}
function _showGuestWall(){
  var m=document.getElementById('guest-wall-modal');
  if(m) m.style.display='flex';
}
function _closeGuestWall(){
  var m=document.getElementById('guest-wall-modal');
  if(m) m.style.display='none';
}
function _guestWallConnect(){
  _closeGuestWall();
  _guestConnect();
}

// ── ADMIN INVITE ──
var _pendingInviteId = null;
async function _checkAdminInvite(){
  if(!phantomKey) return;
  var r = await fetch('/api/invite/check',{credentials:'include'}).then(r=>r.json()).catch(()=>null);
  if(!r?.invite) return;
  _pendingInviteId = r.invite.id;
  document.getElementById('aim-role').textContent = r.invite.role;
  document.getElementById('admin-invite-modal').style.display = 'flex';
}
async function _inviteRespond(action){
  var btn = document.getElementById('aim-accept-btn');
  if(btn) btn.disabled = true;
  var r = await fetch('/api/invite/respond',{
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action: action, invite_id: _pendingInviteId})
  }).then(r=>r.json()).catch(()=>null);
  document.getElementById('admin-invite-modal').style.display = 'none';
  if(btn) btn.disabled = false;
  if(r?.ok){
    if(action==='accept'){
      // Small toast + show admin link if now visible
      var _sb=document.getElementById('sb-admin-link');
      if(_sb) _sb.style.display='flex';
      var _hdr=document.getElementById('admin-btn');
      if(_hdr) _hdr.style.display='';
    }
  }
}

async function launchApp(){
  // ── 1. Verify / silently restore server-side session ────────────
  if(phantomKey){
    try{
      const sr = await fetch('/api/state').then(r=>r.json()).catch(()=>null);
      if(!sr || !sr.wallet){
        // Session expired — re-register before showing the dashboard
        const _wp=walletType==='Phantom'?window.solana:window.solflare;
        const wr = await _connectWalletSigned(_wp, phantomKey);
        if(!wr?.ok && (wr?.msg==='Signature rejected'||(wr?.msg||'').startsWith('Nonce expired'))){
          showLfToast('🔑','Onderteken het verzoek in je wallet om in te loggen — probeer opnieuw','warn');
        } else if(wr){ settingsHasKey=wr.has_trading_key||false; _isAdmin=wr.is_admin||false; _updateKeyStatus(); if(wr.csrf_token) _csrfToken=wr.csrf_token; }
      } else {
        // Pick up any server-side flag changes (key uploaded from another tab, etc.)
        if(typeof sr.is_admin==='boolean') _isAdmin=sr.is_admin;
        if(typeof sr.has_trading_key==='boolean'){ settingsHasKey=sr.has_trading_key; _updateKeyStatus(); }
      }
    }catch(e){}
  }

  // ── 2. Show dashboard ──────────────────────────────────────────
  if(phantomKey) guestMode = false;
  document.getElementById('onboard').classList.add('hide');
  document.getElementById('app').style.display='block';
  const _spos=document.getElementById('s-pos'); if(_spos) _spos.textContent='0/5';
  if(phantomKey){
    const short=phantomKey.slice(0,4)+'...'+phantomKey.slice(-4);
    document.getElementById('wallet-pill').style.display='flex';
    const _dsb=document.getElementById('deposit-sol-btn'); if(_dsb) _dsb.style.display='';
    const _wsb=document.getElementById('withdraw-sol-btn'); if(_wsb) _wsb.style.display='';
    const _psb=document.getElementById('perf-share-btns'); if(_psb) _psb.style.display='flex';
    document.getElementById('btn-solscan').onclick=()=>window.open('https://solscan.io/account/'+phantomKey,'_blank');
    fetch('/api/username').then(r=>r.json()).then(r=>{
      _displayName=r?.ok&&r.username?r.username:null;
      _updateNavPill();
    }).catch(()=>{ _updateNavPill(); });
    fetchBalance();
    _updateDashProfileBar();
    fetch('/api/settings').then(r=>r.json()).then(r=>{
      if(r?.ok){
        settingsHasKey=r.has_trading_key||false;
        document.getElementById('s-minusdc').value=r.min_trade_size??1;
        document.getElementById('s-maxusdc').value=r.max_trade_size||10;
        document.getElementById('s-losslimit').value=r.daily_loss_limit||50;
        _updateKeyStatus();
        if(r.avatar_url){ _avatarUrl=r.avatar_url||null; _updateNavPill(); }
        _prefSoundAlerts = r.pref_sound_alerts||false;
      }
    }).catch(()=>{});
  }
  updateAuthBtns();
  checkOwnerPanel(); _syncAdminNavLink();
  _lastActivity = Date.now();
  /* guest mode banner */
  if(guestMode) _showGuestBanner();
  /* apply read-only restrictions */
  if(_isReadonly){
    const roBanner=document.getElementById('readonly-banner');
    if(roBanner) roBanner.style.display='flex';
    ['feed-trade-btn','sb-start-btn','trade-btn'].forEach(function(id){
      const el=document.getElementById(id); if(el) el.style.display='none';
    });
    const buyBtn=document.getElementById('tdp-buy-btn');
    const sellBtn=document.getElementById('tdp-sell-btn');
    if(buyBtn) buyBtn.style.display='none';
    if(sellBtn) sellBtn.style.display='none';
  }
  if('Notification' in window) Notification.requestPermission();
  await fetchState();
  fetchTrades();
  fetchPnlChart();
  fetchLeaderboard();
  fetchBadges();
  fetchCopyStatus();
  fetchMyProfile();
  dmFetchUnread();
  fetch('/api/heartbeat', {method:'POST', headers:{'X-CSRF-Token': _csrfToken}}).catch(function(){});
  if (!window._heartbeatTimer) {
    window._heartbeatTimer = setInterval(function(){
      fetch('/api/heartbeat', {method:'POST', headers:{'X-CSRF-Token': _csrfToken}}).catch(function(){});
    }, 45000);
  }
  fetchPumpScanner();
  loadHomeFeed();
  _loadRightRail();
  _checkAdminInvite();
  const _pendingProfile = sessionStorage.getItem('openProfile');
  if(_pendingProfile){
    sessionStorage.removeItem('openProfile');
    const _pid = parseInt(_pendingProfile, 10);
    if(_pid) setTimeout(() => openProfileCard(_pid), 400);
  }
}

// ── RIGHT DISCOVERY RAIL ────────────────────────────────────────────────────
const _RR_COLORS = ['#35d4c4','#7c8cff','#f7b955','#3ad29b','#f76b62','#2b6cff'];
function _rrColor(str){ var n=0; for(var i=0;i<(str||'').length;i++) n=(n*31+str.charCodeAt(i))>>>0; return _RR_COLORS[n%_RR_COLORS.length]; }
function _rrPrice(p){ if(!p) return '—'; var n=parseFloat(p); if(isNaN(n)) return '—'; return n<0.001?'$'+n.toFixed(8).replace(/\.?0+$/,''):n<1?'$'+n.toFixed(6):'$'+n.toFixed(4); }

async function _loadRightRail(){
  _loadRrMarket();
  _loadRrTraders();
  _loadRrStats();
  setInterval(_loadRrMarket, 30000);
  setInterval(_loadRrStats,  60000);
}

async function _loadRrMarket(){
  var el=document.getElementById('rr-market-list'); if(!el) return;
  try{
    var d=await fetch('/api/market/top').then(function(r){return r.json();}).catch(function(){return null;});
    var toks=(d&&d.tokens)||[];
    if(!toks.length){ el.innerHTML='<div class="rr-empty">No market data</div>'; return; }
    el.innerHTML=toks.slice(0,5).map(function(t){
      var chg=parseFloat(t.price_change_24h||0);
      var col=chg>=0?'#3ad29b':'#f76b62';
      var tick=(t.symbol||t.ticker||'?').toUpperCase().slice(0,5);
      var bg=_rrColor(tick);
      var pr=_rrPrice(t.price||t.price_usd);
      return '<div class="rr-market-row" onclick="window.location=\'/live-market\'">'
        +'<div class="rr-tok-chip" style="background:'+bg+'">'+tick.slice(0,3)+'</div>'
        +'<div class="rr-tok-info"><div class="rr-tok-name">'+esc(t.name||tick)+'</div>'
        +'<div class="rr-tok-pair">'+tick+' / SOL</div></div>'
        +'<div class="rr-tok-right"><div class="rr-tok-price">'+pr+'</div>'
        +'<div class="rr-tok-chg" style="color:'+col+'">'+(chg>=0?'+':'')+chg.toFixed(1)+'%</div></div>'
        +'</div>';
    }).join('');
  }catch(e){ el.innerHTML='<div class="rr-empty">—</div>'; }
}

async function _loadRrTraders(){
  var el=document.getElementById('rr-traders-list'); if(!el) return;
  try{
    var d=await fetch('/api/leaderboard').then(function(r){return r.json();}).catch(function(){return null;});
    if(!d||!d.length){ el.innerHTML='<div class="rr-empty">No data yet today</div>'; return; }
    el.innerHTML=d.slice(0,4).map(function(t){
      var ini=(t.username||t.wallet_address||'?')[0].toUpperCase();
      var bg=_rrColor(t.username||t.wallet_address||'?');
      var pnl=(t.total_pnl>=0?'+':'')+t.total_pnl.toFixed(3)+' SOL';
      var badge=t.badges&&t.badges.includes('verified')?'<span class="rr-verified">✓</span>':'';
      return '<div class="rr-trader-row" onclick="openProfileCard('+t.user_id+')">'
        +'<span class="rr-trader-rank">'+t.rank+'</span>'
        +'<div class="rr-trader-av" style="background:'+bg+'">'+ini+'</div>'
        +'<div class="rr-trader-info">'
        +'<div class="rr-trader-name">'+esc(t.username||ini)+badge+'</div>'
        +'<div class="rr-trader-handle">@'+(t.username||t.wallet_address.slice(0,6))+'</div>'
        +'</div>'
        +'<div class="rr-trader-pnl">'+pnl+'</div>'
        +'</div>';
    }).join('');
  }catch(e){ el.innerHTML='<div class="rr-empty">—</div>'; }
}

async function _loadRrStats(){
  try{
    var d=await fetch('/api/platform/stats').then(function(r){return r.json();}).catch(function(){return null;});
    if(!d||!d.ok) return;
    var t=document.getElementById('rr-stat-trades'); if(t) t.textContent=(d.trades_today||0).toLocaleString();
    var p=document.getElementById('rr-stat-pnl');
    if(p){ var pv=d.net_pnl_today||0; p.textContent=(pv>=0?'+':'')+pv.toFixed(1); p.className='rr-stat-val'+(pv>=0?' pos':' neg'); }
    var o=document.getElementById('rr-stat-online'); if(o) o.textContent=(d.active_traders||0).toLocaleString();
  }catch(e){}
}

function _rrSearch(q){
  if(!q||q.length<2) return;
  window.location='/live-market?q='+encodeURIComponent(q);
}

function _rrSetVisible(show){
  var rr=document.getElementById('right-rail');
  if(rr) rr.style.display=show?'flex':'none';
}
var loadRightRail=_loadRightRail;

// ── LAUNCH WITH 5s TIMEOUT (prevents button getting stuck) ─────────────────
async function _launchWithTimeout(){
  if(!phantomKey) return;
  const btn=document.getElementById('ob-launch-btn');
  if(btn._launching) return;
  btn._launching=true;
  const origText=btn.textContent;
  const origCss=btn.style.cssText;
  btn.textContent='Launching…';
  btn.style.opacity='.7';
  try{
    await Promise.race([launchApp(), new Promise(r=>setTimeout(r,5000))]);
  }catch(e){}
  btn._launching=false;
  // If app is now showing, button is gone — nothing to restore
  const ob=document.getElementById('onboard');
  if(ob && ob.classList.contains('hide')) return;
  // Timeout or failure before app showed — re-enable so user can retry
  btn.textContent=origText; btn.style.cssText=origCss; btn.disabled=false;
}

// ── AUTO-RECONNECT ON TAB FOCUS ────────────────────────────────────────────
document.addEventListener('visibilitychange', async function(){
  if(document.visibilityState!=='visible'||!phantomKey) return;
  try{
    const sr=await fetch('/api/state').then(r=>r.json()).catch(()=>null);
    if(sr && !sr.wallet){
      const _wp=walletType==='Phantom'?window.solana:window.solflare;
      const wr=await _connectWalletSigned(_wp, phantomKey);
      if(!wr?.ok && (wr?.msg==='Signature rejected'||(wr?.msg||'').startsWith('Nonce expired'))){
        showLfToast('🔑','Onderteken het verzoek in je wallet om in te loggen — probeer opnieuw','warn');
      } else if(wr){ settingsHasKey=wr.has_trading_key||false; _isAdmin=wr.is_admin||false; _updateKeyStatus(); checkOwnerPanel(); _syncAdminNavLink(); if(wr.csrf_token) _csrfToken=wr.csrf_token; }
    }
  }catch(e){}
});

// ── BALANCE REFRESH ──
let _solUsdPrice=0;
async function _fetchSolPrice(){
  try{
    const r=await fetch('https://api.binance.com/api/v3/ticker/price?symbol=SOLUSDT').then(r=>r.json());
    const p=parseFloat(r?.price||0);
    if(p>1) _solUsdPrice=p;
  }catch(e){}
}
_fetchSolPrice();
setInterval(_fetchSolPrice,30000);

function _updateSolUsdc(sol){
  const el=document.getElementById('s-sol-usdc');
  if(!el) return;
  if(_solUsdPrice>0) el.textContent='≈ $'+(sol*_solUsdPrice).toFixed(2)+' USDC';
  else el.textContent='';
}

let _solCounterDone=false;
function _animateSolCounter(target){
  const el=document.getElementById('s-sol');
  if(!el) return;
  if(_solCounterDone||target===0){el.textContent=target.toFixed(4);_solCounterDone=true;return;}
  _solCounterDone=true;
  const dur=700,t0=performance.now();
  function step(now){
    const p=Math.min(1,(now-t0)/dur);
    const ease=1-Math.pow(1-p,3);
    el.textContent=(target*ease).toFixed(4);
    if(p<1) requestAnimationFrame(step);
    else el.textContent=target.toFixed(4);
  }
  requestAnimationFrame(step);
}

async function fetchBalance(){
  if(!phantomKey||!appVisible()) return;
  const r=await fetch('/api/balance').then(r=>r.json()).catch(()=>null);
  if(r?.ok){
    const sol=+r.sol||0;
    _animateSolCounter(sol);
    _updateSolUsdc(sol);
  }
}

function updateAuthBtns(){
  const authed=!!phantomKey;
  document.getElementById('connect-btn').style.display=authed?'none':'';
}

// ── ORC DANCE ──
function showOrcDance(text,detail){
  const o=document.getElementById('orc-overlay');
  document.getElementById('orc-trade-text').textContent=text;
  document.getElementById('orc-trade-detail').textContent=detail||'';
  o.classList.add('show');
  const c=document.getElementById('orc-coins');c.innerHTML='';
  const em=['💰','💎','🚀','✨','💸','🤑','⚡'];
  for(let i=0;i<12;i++){
    const d=document.createElement('div');d.className='coin';
    d.textContent=em[Math.floor(Math.random()*em.length)];
    d.style.cssText='left:'+(Math.random()*200)+'px;top:'+(80+Math.random()*100)+'px;animation-delay:'+(Math.random()*.6)+'s';
    c.appendChild(d);
  }
  setTimeout(()=>o.classList.remove('show'),3500);
}

// ── STATE ──
let lastLogCount=0;
function appVisible(){ return document.getElementById('app').style.display!=='none'; }

async function fetchState(){
  if(!document.getElementById('sol-balance-display')&&!document.getElementById('state-sol')) return
  if(!appVisible()) return;
  const r=await fetch('/api/state').then(r=>r.json()).catch(()=>null);
  if(!r) return;
  if(typeof r.is_admin==='boolean' && r.is_admin!==_isAdmin){
    _isAdmin=r.is_admin;
    checkOwnerPanel(); _syncAdminNavLink();
  }
  if(typeof r.has_trading_key==='boolean' && r.has_trading_key!==settingsHasKey){
    settingsHasKey=r.has_trading_key;
    _updateKeyStatus();
  }
  const _sposEl=document.getElementById('s-pos'); if(_sposEl) _sposEl.textContent=(r.positions??0)+'/5';
  if(phantomKey){
    if(r.sol!=null){
      const _sv=+r.sol;
      if(!_solCounterDone) _animateSolCounter(_sv);
      else { const _ssolEl=document.getElementById('s-sol'); if(_ssolEl) _ssolEl.textContent=_sv.toFixed(4); }
      const sbSol=document.getElementById('sb-sol');
      if(sbSol) sbSol.textContent=_sv.toFixed(4);
      _updateSolUsdc(_sv);
      const uw=document.getElementById('usdc-warn');
      if(uw) uw.style.display=(+r.sol<0.02)?'block':'none';
    }
  }
  traderOn=r.trader_running;
  updateBtns();
  if(r.log_lines){checkForTrades(r.log_lines);renderLog(r.log_lines);}
  renderMarket(r.tokens||[]);

  _checkClosedPositions(r.positions_detail||[]);
  renderPositions(r.positions_detail||[]);
  if(r.sol_price) _solPrice=r.sol_price;
  _lfBuildMintMap(r.tokens||[]);
  _lfCheckNewBuys(r.positions_detail||[]);
  _lfPositions=r.positions_detail||[];
  renderLiveFeed();
}

async function fetchMarketOnly(){
  if(!appVisible()) return;
  const r=await fetch('/api/market/live').then(r=>r.json()).catch(()=>null);
  if(r?.tokens?.length) renderLiveMarket(r.tokens);
}

function renderLiveMarket(tokens){
  if(!tokens?.length) return;
  const count=document.getElementById('token-count');
  if(count) count.textContent=tokens.length+' live';
  const fmtChg=v=>{const n=parseFloat(v??0);return (n>=0?'+':'')+n.toFixed(1)+'%';};
  const chgCls=v=>parseFloat(v??0)>=0?'up':'dn';

  // Update ticker bar
  const ticker=document.getElementById('ticker-track');
  if(ticker){
    const th=tokens.map(t=>{
      const chg=parseFloat(t.price_change_24h??t.price_change_1h??0);
      const col=chg>=0?'var(--green)':'var(--red)';
      return `<span class="tick-item"><span class="tick-sym">${esc(t.symbol||'?')}</span><span>${fmtPrice(t.price)}</span><span style="color:${col}">${chg>=0?'+':''}${chg.toFixed(2)}%</span></span><span class="tick-div">·</span>`;
    }).join('');
    ticker.innerHTML=th+th;
  }

  // Desktop table
  const tbody=document.getElementById('lm-tbody');
  if(tbody){
    tbody.innerHTML=tokens.map((t,i)=>{
      const addr=safeMint(t.address||'');
      const sym=esc(t.symbol||'?');
      const nm=esc(t.name||t.symbol||'');
      const logo=t.image_url
        ?`<img src="${esc(t.image_url)}" alt="" style="width:24px;height:24px;border-radius:50%;object-fit:cover;margin-right:7px;vertical-align:middle;background:var(--bg3)" onerror="this.style.display='none'">`
        :`<span style="display:inline-block;width:24px;height:24px;border-radius:50%;background:var(--bg3);margin-right:7px;vertical-align:middle"></span>`;
      const rowClick=addr?`onclick="if(event.target.tagName!=='BUTTON')window.openTokenPanel&&window.openTokenPanel('${addr}')"`:' ';
      return `<tr ${rowClick}>
        <td style="color:var(--muted)">${i+1}</td>
        <td style="min-width:140px">${logo}<span style="font-weight:700">${sym}</span><span style="color:var(--muted);margin-left:6px;font-size:11px">${nm}</span></td>
        <td>${fmtPrice(t.price)}</td>
        <td><span class="lm-pct ${chgCls(t.price_change_5m)}">${fmtChg(t.price_change_5m)}</span></td>
        <td><span class="lm-pct ${chgCls(t.price_change_1h)}">${fmtChg(t.price_change_1h)}</span></td>
        <td><span class="lm-pct ${chgCls(t.price_change_6h)}">${fmtChg(t.price_change_6h)}</span></td>
        <td><span class="lm-pct ${chgCls(t.price_change_24h)}">${fmtChg(t.price_change_24h)}</span></td>
        <td>${fmtNum(t.volume_24h)}</td>
        <td>${fmtNum(t.liquidity)}</td>
        <td>${fmtInt(t.txns_24h)}</td>
        <td>${addr?`<button class="lm-buy-btn" onclick="event.stopPropagation();_lmBuy('${addr}','${sym}',this)">BUY</button>`:''}</td>
      </tr>`;
    }).join('');
  }

  // Mobile cards
  const cards=document.getElementById('lm-cards');
  if(cards){
    cards.innerHTML=tokens.map(t=>{
      const addr=safeMint(t.address||'');
      const sym=esc(t.symbol||'?');
      const nm=esc(t.name||t.symbol||'');
      const chg24=parseFloat(t.price_change_24h??0);
      const logo=t.image_url
        ?`<img src="${esc(t.image_url)}" alt="" class="lm-card-logo" onerror="this.style.display='none'">`
        :`<span class="lm-card-logo"></span>`;
      return `<div class="lm-card"${addr?` onclick="if(!event.target.closest('button'))window.openTokenPanel&&window.openTokenPanel('${addr}')"`:''}>
        ${logo}
        <div class="lm-card-info"><div class="lm-card-sym">${sym}</div><div class="lm-card-name">${nm}</div></div>
        <div class="lm-card-right">
          <div class="lm-card-price">${fmtPrice(t.price)}</div>
          <div class="lm-pct ${chgCls(chg24)}" style="font-size:11px">${fmtChg(t.price_change_24h)}</div>
          ${addr?`<button class="lm-card-buy-btn" onclick="event.stopPropagation();_lmBuy('${addr}','${sym}',this)">BUY</button>`:''}
        </div>
      </div>`;
    }).join('');
  }
}

async function _lmBuy(addr,sym,btn){
  if(!addr) return;
  const orig=btn.textContent;
  btn.disabled=true; btn.textContent='…';
  try{
    const r=await fetch('/api/trade/buy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token_address:addr,token_symbol:sym})}).then(r=>r.json());
    btn.textContent=r.ok?'✓':'✗';
    btn.style.background=r.ok?'#00e676':'#ff1744';
    btn.style.color=r.ok?'#000':'#fff';
  }catch(e){ btn.textContent='✗'; btn.style.background='#ff1744'; btn.style.color='#fff'; }
  setTimeout(()=>{ btn.textContent=orig; btn.disabled=false; btn.style.background=''; btn.style.color=''; },2500);
}

function checkForTrades(lines){
  if(!lines.length||lastLogCount===0){lastLogCount=lines.length;return;}
  const m=lines[0]?.msg||'';
  if(m.startsWith('BUY ')&&!m.includes('FAILED'))showOrcDance('BUY EXECUTED! 🚀',m.substring(0,50));
  else if(m.includes('TAKE PROFIT'))showOrcDance('TAKE PROFIT! 💎',m.substring(0,50));
  if(m.includes('bot paused for 1 hour to protect gains')||m.includes('60% profit')){
    _pushNotif('🔒 Bot paused','60% profit target reached — bot paused for 1 hour to protect gains.');
  }
  lastLogCount=lines.length;
}

function renderLog(lines){
  const el=document.getElementById('log-body');
  el.innerHTML=lines.map(l=>{
    let cls='c-info';const m=l.msg||'';
    if(m.startsWith('BUY ')&&!m.includes('FAILED'))cls='c-buy';
    else if(m.includes('SELL')||m.includes('STOP LOSS')||m.includes('TRAILING'))cls='c-sell';
    else if(m.includes('error')||m.includes('FAILED'))cls='c-error';
    else if(m.includes('SKIP')||m.includes('[skip]'))cls='c-skip';
    return '<div class="log-line"><span class="lt">'+esc(l.t)+'</span><span class="'+cls+'">'+esc(m)+'</span></div>';
  }).join('');
}

// ── SECURITY HELPERS ──
function esc(s){
  // HTML-encode external data before injecting into innerHTML
  return String(s==null?'':s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
}
function safeMint(m){
  // Solana addresses are base58: 32–44 chars from a restricted alphabet
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(String(m||''))?String(m):'';
}

// ── FORMATTING ──
function fmtPrice(p){
  if(!p) return '—';
  p=parseFloat(p);
  if(p>=1) return '$'+p.toFixed(2);
  if(p>=0.01) return '$'+p.toFixed(4);
  const s=p.toFixed(10);
  const m=s.match(/0\.(0*)/);
  const zeros=m?m[1].length:0;
  return '$0.0'+(zeros>0?zeros.toString().sub():'')+p.toFixed(zeros+4).slice(2+zeros);
}
function fmtNum(n){
  if(!n||n===0) return '—';
  if(n>=1e9) return '$'+(n/1e9).toFixed(2)+'B';
  if(n>=1e6) return '$'+(n/1e6).toFixed(1)+'M';
  if(n>=1e3) return '$'+(n/1e3).toFixed(1)+'K';
  return '$'+Math.round(n);
}
function fmtInt(n){
  if(!n||n===0) return '—';
  return Math.round(n).toLocaleString();
}

// ── MARKET RENDER ──
function renderMarket(tokens){
  if(tokens?.length) _marketTokens=tokens;
  const grid=document.getElementById('market-grid');
  if(!grid) return; // replaced by live market table
  const ticker=document.getElementById('ticker-track');
  const count=document.getElementById('token-count');

  if(!tokens?.length){
    // Only replace if not already showing a token grid (avoids flicker on slow re-scan)
    if(!_marketTokens.length)
      grid.innerHTML='<div style="color:var(--muted);font-size:11px;grid-column:1/-1;padding:24px 0;text-align:center;letter-spacing:.08em">SCANNING LIVE MARKET...</div>';
    else
      grid.innerHTML='<div style="color:var(--muted);font-size:11px;grid-column:1/-1;padding:24px 0;text-align:center;letter-spacing:.08em">NO QUALIFYING TOKENS RIGHT NOW — RESCANNING...</div>';
    if(count) count.textContent='';
    return;
  }

  if(count) count.textContent=tokens.length+' trending';

  const fmtChg=v=>(v>=0?'+':'')+((v??0).toFixed(1))+'%';
  const chgCls=v=>(v??0)>=0?'up':'dn';
  const fmtTxns=n=>n>0?n.toLocaleString():'—';

  const makeCard=t=>{
    const hot=t.score>=7,cold=t.score<=2;
    const baseCls='mkt-card'+(hot?' hot':cold?' cold':'');
    const barPct=Math.min(100,Math.max(0,(t.score??0)/10*100)).toFixed(1);
    const barColor=hot?'var(--green)':cold?'var(--red)':'var(--yellow)';
    const scoreCol=hot?'var(--green)':cold?'var(--red)':'var(--muted)';
    const m5=t.change5m??0,h1=t.change1h??0,h6=t.change6h??0,h24=t.change24h??0;
    const pumping=h1>=50;
    // Sanitize all external data before injecting into innerHTML
    const sym=esc(t.symbol||'???');
    const name=esc(t.name||t.symbol||'Unknown');
    const mint=safeMint(t.mint);
    const clickAttr=mint?`onclick="location.href='/token/${mint}'"`:'';
    return `<div class="${baseCls}" style="display:flex;flex-direction:column${mint?';cursor:pointer':''}" ${clickAttr}>
  <div class="mkt-top">
    <div class="mkt-id">
      <div class="mkt-sym">${sym}</div>
      <div class="mkt-name">${name}</div>
    </div>
  </div>
  ${pumping?'<div class="pump-badge">🚀 PUMPING</div>':''}
  <span class="mkt-price">${fmtPrice(t.price)}</span>
  <div class="chg-grid">
    <div class="chg-cell"><div class="chg-period">5M</div><div class="chg-pct ${chgCls(m5)}">${fmtChg(m5)}</div></div>
    <div class="chg-cell"><div class="chg-period">1H</div><div class="chg-pct ${chgCls(h1)}">${fmtChg(h1)}</div></div>
    <div class="chg-cell"><div class="chg-period">6H</div><div class="chg-pct ${chgCls(h6)}">${fmtChg(h6)}</div></div>
    <div class="chg-cell"><div class="chg-period">24H</div><div class="chg-pct ${chgCls(h24)}">${fmtChg(h24)}</div></div>
  </div>
  <div class="mkt-divider"></div>
  <div class="mkt-meta-row">
    <div class="mkt-meta-cell"><div class="mkt-stat-lbl">Txns 24H</div><div class="mkt-stat-val">${fmtTxns(t.txns24h??0)}</div></div>
    <div class="mkt-meta-cell"><div class="mkt-stat-lbl">Makers</div><div class="mkt-stat-val">${fmtTxns(t.makers24h??0)}</div></div>
    <div class="mkt-meta-cell"><div class="mkt-stat-lbl">Vol 24H</div><div class="mkt-stat-val">${fmtNum(t.volume24h||0)}</div></div>
    <div class="mkt-meta-cell"><div class="mkt-stat-lbl">Liq</div><div class="mkt-stat-val">${fmtNum(t.liquidity||0)}</div></div>
  </div>
  <div class="mkt-meta-row">
    <div class="mkt-meta-cell"><div class="mkt-stat-lbl">MCap</div><div class="mkt-stat-val">${fmtNum(t.fdv||0)}</div></div>
    <div class="mkt-meta-cell"><div class="mkt-stat-lbl">Buys</div><div class="mkt-stat-val" style="color:var(--green)">${fmtTxns(t.txns24h_buys??0)}</div></div>
    <div class="mkt-meta-cell"><div class="mkt-stat-lbl">Sells</div><div class="mkt-stat-val" style="color:var(--red)">${fmtTxns(t.txns24h_sells??0)}</div></div>
    <div class="mkt-meta-cell"><div class="mkt-stat-lbl">Vol 5M</div><div class="mkt-stat-val">${fmtNum(t.volume5m||0)}</div></div>
  </div>
  <div class="mkt-score-row" style="margin-top:8px">
    <div class="mkt-score-track"><div class="mkt-score-fill" style="width:${barPct}%;background:${barColor}"></div></div>
    <span class="mkt-score-label" style="color:${scoreCol}">${t.score}/10</span>
  </div>
  ${mint?`<div style="display:flex;gap:6px;margin-top:auto;padding-top:10px;width:100%">
    <button style="flex:1;padding:6px;background:#00e676;color:#000000;font-weight:700;border:none;border-radius:6px;cursor:pointer;font-size:12px;letter-spacing:.03em" onclick="event.stopPropagation();manualBuy('${mint}','${sym}',this)">BUY</button>
    <button style="flex:1;padding:6px;background:#ff1744;color:#fff;font-weight:700;border:none;border-radius:6px;cursor:pointer;font-size:12px;letter-spacing:.03em" onclick="event.stopPropagation();manualSell('${mint}','${sym}',this)">SELL</button>
  </div>`:''}
</div>`;
  };
  grid.innerHTML=tokens.map(makeCard).join('')||
    '<div style="color:var(--muted);font-size:11px;grid-column:1/-1;padding:24px 0;text-align:center;letter-spacing:.08em">NO TRENDING TOKENS RIGHT NOW</div>';
  if(typeof window._swipeReset==='function') window._swipeReset();

  // ticker bar
  const tickHtml=tokens.map(t=>{
    const chg=t.change24h??t.change1h??0;
    const col=chg>=0?'var(--green)':'var(--red)';
    return `<span class="tick-item"><span class="tick-sym">${esc(t.symbol)}</span><span>${fmtPrice(t.price)}</span><span style="color:${col}">${chg>=0?'+':''}${chg.toFixed(2)}%</span></span><span class="tick-div">·</span>`;
  }).join('');
  ticker.innerHTML=tickHtml+tickHtml;
}

// ── LOW SOL BALANCE MODAL ──
function openLowSolModal(addr){
  document.getElementById('low-sol-addr').textContent=addr||'(unable to determine trading wallet)';
  document.getElementById('low-sol-modal').classList.add('open');
}
function closeLowSolModal(){
  document.getElementById('low-sol-modal').classList.remove('open');
}
function copyLowSolAddr(){
  const addr=document.getElementById('low-sol-addr').textContent;
  if(!addr) return;
  navigator.clipboard.writeText(addr);
  const btn=document.querySelector('.low-sol-copy-btn');
  if(btn){ const orig=btn.textContent; btn.textContent='✓ Copied!'; setTimeout(()=>btn.textContent=orig,2000); }
}

// ── INLINE ADMIN PANEL ──
let _iadminSelWallet='';

function _iadminSetVisible(show){
  const el=document.getElementById('iadmin-panel');
  if(el) el.style.display=show?'':'none';
}

async function iadminRefresh(){
  await Promise.all([iadminFetchStats(),iadminFetchFeeStats(),iadminFetchUsers(),iadminFetchBackups(),iadminFetchRateStats()]);
}

async function iadminFetchRateStats(){
  const r=await fetch('/api/admin/rate-stats').then(r=>r.json()).catch(()=>null);
  const s=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v;};
  if(!r?.ok){
    return;
  }
  s('ia-rl-api', r.api_calls_today??'—');
  s('ia-rl-jup', r.jupiter_calls_today??'—');
  s('ia-rl-dex', r.dexscreener_calls_today??'—');
  const eps=r.endpoints||[];
  const tb=document.getElementById('ia-rl-tbody');
  if(!tb) return;
  if(!eps.length){
    tb.innerHTML='<tr><td colspan="3" style="text-align:center;padding:10px;color:var(--muted)">No rate-limit activity yet</td></tr>';
    return;
  }
  tb.innerHTML=eps.map(e=>{
    const blocked=e.blocked_1h>0;
    const rowStyle=blocked?'background:rgba(255,77,106,.06)':'';
    const blockedStyle=blocked?'color:var(--red);font-weight:700':'color:var(--muted)';
    return `<tr style="${rowStyle}">
      <td style="font-family:'Share Tech Mono',monospace;color:var(--dim)">${esc(e.endpoint)}</td>
      <td style="text-align:right">${e.requests_1h}</td>
      <td style="text-align:right;${blockedStyle}">${blocked?'⚠ '+e.blocked_1h:e.blocked_1h}</td>
    </tr>`;
  }).join('');
}

function _fmtBytes(b){
  if(b>=1048576) return (b/1048576).toFixed(1)+' MB';
  if(b>=1024)    return (b/1024).toFixed(0)+' KB';
  return b+' B';
}

async function iadminFetchBackups(){
  const r=await fetch('/api/admin/backups').then(r=>r.json()).catch(()=>null);
  if(!r?.ok) return;
  const bkps=r.backups||[];
  const s=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v;};
  s('ia-bkp-count', bkps.length||'0');
  const totalBytes=bkps.reduce((a,b)=>a+b.size,0);
  s('ia-bkp-size',  bkps.length?_fmtBytes(totalBytes):'—');
  s('ia-bkp-last',  bkps.length?bkps[0].date:'Never');
  const listEl=document.getElementById('ia-bkp-list');
  if(listEl){
    listEl.innerHTML=bkps.map(b=>
      `<span style="color:var(--dim)">${esc(b.filename)}</span>&nbsp;·&nbsp;${_fmtBytes(b.size)}&nbsp;·&nbsp;${esc(b.date)}`
    ).join('<br>')||'<span style="color:var(--muted)">No backups yet — first backup runs 60 s after startup</span>';
  }
}

async function iadminFetchStats(){
  const r=await fetch('/api/admin/stats').then(r=>r.json()).catch(()=>null);
  if(!r?.ok) return;
  const s=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v;};
  s('ia-users',  r.users??'—');
  s('ia-trades', r.trades??'—');
  s('ia-volume', r.volume_sol!=null?r.volume_sol.toFixed(2)+' SOL':'—');
  s('ia-bots',   r.active_bots??'—');
}

async function iadminFetchFeeStats(){
  const r=await fetch('/api/admin/fee-stats').then(r=>r.json()).catch(()=>null);
  if(!r?.ok) return;
  const s=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v;};
  s('ia-fee-total',   r.collected!=null?r.collected.toFixed(4)+' SOL':'—');
  s('ia-fee-pending', r.pending!=null?r.pending.toFixed(4)+' SOL':'—');
  s('ia-fee-today',   r.today!=null?r.today.toFixed(4)+' SOL':'—');
}

async function iadminFetchUsers(){
  const r=await fetch('/api/admin/users').then(r=>r.json()).catch(()=>null);
  const tbody=document.getElementById('ia-users-tbody');
  if(!tbody) return;
  const users=r?.users||[];
  if(!users.length){
    tbody.innerHTML='<tr><td colspan="6" style="text-align:center;padding:12px;color:var(--muted)">No users</td></tr>';
    return;
  }
  tbody.innerHTML=users.map(u=>{
    const pnl=u.pnl_today!=null?((u.pnl_today>=0?'+':'')+u.pnl_today.toFixed(3)):'—';
    const pnlClr=u.pnl_today>0?'var(--green)':u.pnl_today<0?'var(--red)':'';
    const botClr=u.trading?'var(--green)':'var(--muted)';
    const isSel=_iadminSelWallet&&_iadminSelWallet===(u.wallet_full||'');
    return `<tr class="${isSel?'ia-sel':''}" onclick="iadminSelectUser(${JSON.stringify(u.wallet_full||'')},${JSON.stringify(u.wallet||'')})">
      <td title="${esc(u.wallet_full||u.wallet||'')}">${esc(u.wallet||'')}</td>
      <td style="color:${botClr}">${u.trading?'ON':'OFF'}</td>
      <td>${u.positions??0}</td>
      <td>${u.total_trades??0}</td>
      <td style="color:${pnlClr}">${pnl}</td>
      <td style="color:var(--muted)">${esc(u.last_seen||'—')}</td>
    </tr>`;
  }).join('');
}

function iadminSelectUser(walletFull,walletShort){
  _iadminSelWallet=walletFull;
  const lbl=document.getElementById('ia-sel-lbl');
  if(lbl) lbl.textContent=walletShort||(walletFull.slice(0,6)+'...'+walletFull.slice(-4));
  ['ia-btn-pause','ia-btn-resume','ia-btn-closeall'].forEach(id=>{
    const el=document.getElementById(id);
    if(el) el.disabled=!walletFull;
  });
  document.querySelectorAll('#ia-users-tbody tr').forEach(tr=>{
    tr.classList.toggle('ia-sel',tr.onclick&&tr.onclick.toString().includes(JSON.stringify(walletFull)));
  });
}

async function iadminCollectFees(){
  const btn=document.getElementById('ia-collect-btn');
  if(btn){btn.disabled=true;btn.textContent='Collecting…';}
  const r=await fetch('/api/admin/collect-fees',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(r=>r.json()).catch(()=>null);
  if(btn){btn.disabled=false;btn.textContent='💰 Collect All';}
  if(r?.ok){
    showLfToast('💰',r.msg||(r.total_sol!=null?'Collected '+r.total_sol.toFixed(4)+' SOL':'Done'),'pos');
    iadminFetchFeeStats();
  }else{
    showLfToast('⚠️',r?.error||'Collection failed','neg');
  }
}

async function iadminForce(action){
  if(!_iadminSelWallet){showLfToast('⚠️','No user selected','neg');return;}
  const btnId=action==='pause'?'ia-btn-pause':action==='resume'?'ia-btn-resume':'ia-btn-closeall';
  const btn=document.getElementById(btnId);
  if(btn) btn.disabled=true;
  const r=await fetch('/api/admin/force-'+action,{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({wallet:_iadminSelWallet})
  }).then(r=>r.json()).catch(()=>null);
  if(btn) btn.disabled=false;
  if(r?.ok){
    showLfToast('👑',r.msg||'Done','pos');
    setTimeout(iadminFetchUsers,800);
  }else{
    showLfToast('⚠️',r?.error||'Action failed','neg');
  }
}

// ── TOKEN OF THE DAY + LIVE CHART ──
let _marketTokens=[];  // used by renderMarket for grid fallback
let _openMints=new Set(); // mints with open positions — drives SELL button visibility



// ── PUMP SCANNER ──
async function fetchPumpScanner(){
  if(!phantomKey){ document.getElementById('ps-panel').style.display='none'; return; }
  const r=await fetch('/api/pump-scanner').then(r=>r.json()).catch(()=>null);
  if(r?.ok) renderPumpScanner(r.tokens||[]);
}

function renderPumpScanner(tokens){
  const panel=document.getElementById('ps-panel');
  const grid=document.getElementById('ps-grid');
  const count=document.getElementById('ps-count');
  if(!panel||!grid) return;
  if(!phantomKey||!tokens.length){ panel.style.display='none'; return; }
  panel.style.display='block';
  if(count) count.textContent=tokens.length+' pumping';
  const fmtChg=v=>(v>=0?'+':'')+((v??0).toFixed(1))+'%';
  const chgCls=v=>(v??0)>=0?'up':'dn';
  const _psCards=tokens.map(t=>{
    const sym=esc(t.symbol||'???');
    const name=esc(t.name||t.symbol||'Unknown');
    const mint=safeMint(t.mint);
    if(!mint) return '';
    const m5=t.change5m??0,h1=t.change1h??0;
    const hasSell=_openMints.has(mint);
    return `<div class="ps-card" onclick="location.href='/token/${mint}'" style="cursor:pointer">
  <div class="ps-card-top">
    <div><div class="ps-sym">${sym}</div><div class="ps-name">${name}</div></div>
    <div class="ps-price">${fmtPrice(t.price)}</div>
  </div>
  <div class="ps-chg-row">
    <span class="ps-chg ${chgCls(m5)}">5M ${fmtChg(m5)}</span>
    <span class="ps-chg ${chgCls(h1)}">1H ${fmtChg(h1)}</span>
  </div>
  <div style="display:flex;gap:6px;margin-top:10px;width:100%">
    <button class="ps-buy-btn" onclick="event.stopPropagation();manualBuy('${mint}','${sym}',this)">BUY</button>
    <button class="ps-sell-btn" style="display:${hasSell?'block':'none'}" onclick="event.stopPropagation();manualSell('${mint}','${sym}',this)">SELL</button>
  </div>
</div>`;
  });
  grid.innerHTML=_psCards.join('');
}

async function manualBuy(mint,symbol,btn){
  if(!btn) return;
  const solBal=parseFloat(document.getElementById('s-sol').textContent)||0;
  if(solBal<0.01){
    showLfToast('⚠️','Insufficient SOL balance — deposit SOL to trade','warn');
    const depBtn=document.getElementById('deposit-sol-btn');
    if(depBtn){depBtn.classList.add('dep-btn-pulse');setTimeout(()=>depBtn.classList.remove('dep-btn-pulse'),2000);}
    return;
  }
  btn.disabled=true; btn.textContent='BUYING'; btn.classList.add('ps-btn-loading');
  try{
    const r=await fetch('/api/manual_buy',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({mint_address:mint,symbol})
    }).then(r=>r.json()).catch(()=>null);
    btn.classList.remove('ps-btn-loading');
    if(r?.ok){
      showLfToast('🟢',r.msg||'Bought '+symbol,'pos');
      btn.textContent='✓ BOUGHT';
      setTimeout(()=>{if(btn){btn.disabled=false;btn.textContent='BUY';}},3000);
      await fetchState();
      fetchPumpScanner();
    } else {
      showLfToast('🔴',r?.msg||'Buy failed','neg');
      btn.disabled=false; btn.textContent='BUY';
    }
  }catch(e){
    btn.classList.remove('ps-btn-loading');
    showLfToast('🔴','Network error','neg');
    btn.disabled=false; btn.textContent='BUY';
  }
}

async function manualSell(mint,symbol,btn){
  if(!btn) return;
  btn.disabled=true; btn.textContent='SELLING'; btn.classList.add('ps-btn-loading');
  try{
    const r=await fetch('/api/manual_sell',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({mint_address:mint})
    }).then(r=>r.json()).catch(()=>null);
    btn.classList.remove('ps-btn-loading');
    if(r?.ok){
      showLfToast('🟢',(r.symbol||symbol)+' sold','pos');
      if(btn) btn.style.display='none';
      await fetchState();
      fetchPumpScanner();
    } else {
      showLfToast('🔴',r?.msg||'Sell failed','neg');
      btn.disabled=false; btn.textContent='SELL';
    }
  }catch(e){
    btn.classList.remove('ps-btn-loading');
    showLfToast('🔴','Network error','neg');
    btn.disabled=false; btn.textContent='SELL';
  }
}

// ── BADGE SYSTEM ──
const BADGE_META = {
  '🔥 Hot Streak':    { desc:'5+ consecutive winning trades',      color:'rgba(255,107,53,.45)' },
  '💎 Diamond Hands': { desc:'Held a position for 30+ minutes',    color:'rgba(185,242,255,.38)' },
  '🐋 Whale':         { desc:'Single trade volume over 1 SOL',     color:'rgba(136,136,136,.45)' },
  '⚡ Speed Trader':  { desc:'10+ trades in a single day',         color:'rgba(255,215,0,.42)' },
  '🎯 Sharp Shooter': { desc:'Win rate over 70% with 20+ trades',  color:'rgba(0,0,0,.42)' },
  '🏆 Top Earner':    { desc:'All-time PnL over 5 SOL',            color:'rgba(118,118,118,.45)' },
};
const ALL_BADGES = Object.keys(BADGE_META);

function _badgePillHtml(name, earned, compact=false){
  const meta = BADGE_META[name];
  if(!meta) return '';
  const sz = compact ? 'style="font-size:9px;padding:2px 7px"' : '';
  if(earned){
    return `<span class="badge-pill earned" style="--bp-color:${meta.color}" title="${meta.desc}" ${sz}>${name}</span>`;
  }
  const label = name.replace(/^\S+\s/,'');
  return `<span class="badge-pill locked" title="${meta.desc}" ${sz}>🔒 ${label}</span>`;
}

function _badgeRowHtml(earnedList, showLocked=true, compact=false){
  const earned = new Set(earnedList);
  return ALL_BADGES.map(b => (earned.has(b)||showLocked) ? _badgePillHtml(b, earned.has(b), compact) : '').join('');
}

async function fetchBadges(){
  if(!phantomKey){ _resetBadges(); return; }
  const r = await fetch('/api/badges/'+phantomKey).then(r=>r.json()).catch(()=>null);
  if(!r?.ok){ _resetBadges(); return; }
  const row = document.getElementById('badges-row');
  if(!row) return;
  row.innerHTML = _badgeRowHtml(r.badges||[], true);
  row.style.display = 'flex';
}

function _resetBadges(){
  const row = document.getElementById('badges-row');
  if(row){ row.innerHTML=''; row.style.display='none'; }
}

// ── MY PROFILE ──
let _myProfileId=null, _myProfileData=null;

async function fetchMyProfile(){
  if(!phantomKey) return;
  try{
    const r=await fetch('/api/profile/me').then(r=>r.json()).catch(()=>null);
    if(!r?.ok) return;
    _myProfileId=r.user_id;
    _dmMyId=r.user_id;
    _myProfileData=r;
    _updateMyProfileBtn();
    _updateTvMeCard();
    _updateDashProfileBar();
    _sbUpdateUser(r);
  }catch(e){}
}

function _updateMyProfileBtn(){ /* wallet-pill is always visible when logged in; profile opens on click */ }

function _updateTvMeCard(){
  const card=document.getElementById('tv-me-card');
  if(!card||!_myProfileData||!phantomKey){ if(card) card.style.display='none'; return; }
  const p=_myProfileData;
  const bg=_tvAvatarColor(p.username||'?');
  const ini=esc((p.username||'?')[0].toUpperCase());
  const avHtml=p.avatar_url
    ?`<div class="tv-me-avatar" style="background:${bg}"><img src="${p.avatar_url}" alt="" onerror="this.style.display='none'"><span style="position:relative;z-index:1">${ini}</span></div>`
    :`<div class="tv-me-avatar" style="background:${bg}">${ini}</div>`;
  const todayPnl=p.today_pnl??0;
  const todayPos=todayPnl>=0;
  const pnlColor=todayPos?'var(--green)':'var(--red)';
  const pnlStr=(todayPos?'+':'')+todayPnl.toFixed(4)+' SOL';
  card.innerHTML=`
    <div class="tv-me-badge">Your Profile</div>
    <div class="tv-me-row">
      ${avHtml}
      <div class="tv-me-info">
        <div class="tv-me-name">${esc(p.username||p.wallet)}</div>
        <div class="tv-me-chips">
          <span class="tv-me-chip"><strong>${p.follower_count??0}</strong> Followers</span>
          <span class="tv-me-chip"><strong>${p.following_count??0}</strong> Following</span>
          <span class="tv-me-chip" style="color:${pnlColor}"><strong style="color:inherit">${esc(pnlStr)}</strong> today</span>
        </div>
      </div>
      <button class="tv-me-profile-btn" onclick="if(_myProfileId)openProfileCard(_myProfileId)">View Full Profile</button>
    </div>`;
  card.style.display='flex';
}

function _updateDashProfileBar(){
  const bar=document.getElementById('dash-profile-bar');
  if(!bar||!phantomKey){ if(bar) bar.style.display='none'; return; }
  const p=_myProfileData||{};
  const shortWallet=phantomKey.slice(0,4)+'…'+phantomKey.slice(-4);
  const displayName=p.username||shortWallet;
  const bg=_tvAvatarColor(displayName);
  const ini=esc(displayName[0].toUpperCase());
  const avDiv=document.getElementById('dpb-avatar');
  const nameEl=document.getElementById('dpb-name');
  const chipsEl=document.getElementById('dpb-chips');
  if(avDiv){
    avDiv.style.background=bg;
    avDiv.style.color='#fff';
    avDiv.innerHTML=p.avatar_url
      ?`<img src="${esc(p.avatar_url)}" alt="" style="position:absolute;inset:0;width:100%;height:100%;object-fit:cover;border-radius:50%" onerror="this.style.display='none'"><span style="position:relative;z-index:1">${ini}</span>`
      :ini;
  }
  if(nameEl) nameEl.textContent=displayName;
  const todayPnl=+(p.today_pnl??0);
  const todayPos=todayPnl>=0;
  const pnlColor=todayPos?'var(--green)':'var(--red)';
  const pnlStr=(todayPos?'+':'')+todayPnl.toFixed(4)+' SOL';
  if(chipsEl) chipsEl.innerHTML=`
    <span class="dpb-chip"><strong>${p.follower_count??0}</strong> Followers</span>
    <span class="dpb-chip"><strong>${p.following_count??0}</strong> Following</span>
    <span class="dpb-chip" style="color:${pnlColor}"><strong style="color:inherit">${esc(pnlStr)}</strong> today</span>`;
  bar.style.display='flex';
}

function _resetMyProfile(){
  _myProfileId=null; _myProfileData=null;
  const card=document.getElementById('tv-me-card');
  if(card){ card.innerHTML=''; card.style.display='none'; }
  const bar=document.getElementById('dash-profile-bar');
  if(bar) bar.style.display='none';
}

// ── COPY TRADING ──
async function fetchCopyStatus(){
  if(!phantomKey) return;
  try{
    const r=await fetch('/api/copy-trade/status').then(r=>r.json()).catch(()=>null);
    if(r?.ok){ _copySource=r.copying?r.target_wallet:null; }
  }catch(e){}
  _updateCopyPill();
}

function _updateCopyPill(){
  const pill=document.getElementById('copy-source-pill');
  const lbl=document.getElementById('copy-source-label');
  if(!pill||!lbl) return;
  if(_copySource){
    const short=_copySource.slice(0,6)+'...'+_copySource.slice(-4);
    lbl.textContent='Copying: '+short;
    pill.style.display='';
  } else {
    pill.style.display='none';
  }
}

function _stopCopyingConfirm(){
  if(!confirm('Stop copying this trader?')) return;
  fetch('/api/copy-trade/stop',{method:'POST'})
    .then(r=>r.json())
    .then(r=>{ if(r?.ok){ _copySource=null; _updateCopyPill(); showLfToast('🟢','Stopped copying','pos'); } })
    .catch(()=>{});
}

async function _tpcStartCopy(wallet, username){
  if(checkGuest()) return;
  const r=await fetch('/api/copy-trade',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target_wallet:wallet})}).then(r=>r.json()).catch(()=>null);
  if(r?.ok){
    _copySource=wallet;
    _updateCopyPill();
    const btn=document.getElementById('tpc-copy-btn');
    if(btn){ btn.className='tpc-stop-copy-btn'; btn.textContent='Stop Copying'; btn.onclick=()=>_tpcStopCopy(); }
    showLfToast('🟢','Now copying '+username,'pos');
  }
}

async function _tpcStopCopy(){
  const r=await fetch('/api/copy-trade/stop',{method:'POST'}).then(r=>r.json()).catch(()=>null);
  if(r?.ok){
    const prevWallet=_tpcCurrentFullWallet;
    _copySource=null;
    _updateCopyPill();
    const btn=document.getElementById('tpc-copy-btn');
    const username=document.querySelector('.tvp-username')?.textContent||'trader';
    if(btn){ btn.className='tpc-copy-btn'; btn.textContent='Copy Trader'; btn.onclick=()=>_tpcStartCopy(prevWallet,username); }
    showLfToast('🟢','Stopped copying','pos');
  }
}

// ── PERFORMANCE PANEL ──
async function fetchTrades(){
  if(!appVisible()) return;
  const r=await fetch('/api/trades').then(r=>r.json()).catch(()=>null);
  console.log('[api_trades] response:', JSON.stringify(r));
  if(!r) return;
  renderPerfPanel(r);
  if(r.recent){
    _lfCheckNewTrades(r.recent);
    _lfHistory=r.recent.slice().reverse();
    renderLiveFeed();
  }
  _lfStartCountdown();
}

// ── OWNER ADMIN PANEL ──
let _adminTimer=null, _adminView=false, _adminTabLoaded={};

async function _syncAdminNavLink(){
  var sbAdminLink=document.getElementById('sb-admin-link');
  var mnAdminLink=document.getElementById('mn-admin-link');
  if(!phantomKey){ if(sbAdminLink)sbAdminLink.style.display='none'; if(mnAdminLink)mnAdminLink.style.display='none'; return; }
  try{
    var r=await fetch('/api/admin/whoami',{credentials:'include'}).then(function(x){return x.json();});
    var show=!!(r&&r.ok&&r.role&&r.role!=='user');
    if(sbAdminLink) sbAdminLink.style.display=show?'flex':'none';
    if(mnAdminLink) mnAdminLink.style.display=show?'flex':'none';
  }catch(e){}
}

function checkOwnerPanel(){
  const ADMIN_WALLET='HC5ahspSox3XRmDbzXjXVoAASuY89RCmGUKwp87FRJS5';
  const adminBtn=document.getElementById('admin-btn');
  const healthBtn=document.getElementById('health-btn');
  const sbAdminLink=document.getElementById('sb-admin-link');
  const mnAdminLink=document.getElementById('mn-admin-link');
  const isAdminWallet=!!(phantomKey&&(phantomKey===ADMIN_WALLET||phantomKey.startsWith('HC5ahspSox3XRm')));
  if(isAdminWallet){
    if(adminBtn) adminBtn.style.display='';
    if(healthBtn) healthBtn.style.display='';
    _iadminSetVisible(true);
    iadminRefresh();
    fetchAudit();
    if(!_adminTimer) _adminTimer=setInterval(()=>{ if(_adminView) fetchAdminOverview(); else iadminRefresh(); },60000);
  } else {
    if(adminBtn) adminBtn.style.display='none';
    if(healthBtn) healthBtn.style.display='none';
    _iadminSetVisible(false);
    if(_adminView) toggleAdminView();
    closeHealthPanel();
    if(_adminTimer){clearInterval(_adminTimer);_adminTimer=null;}
  }
}

function toggleAdminView(){
  _adminView=!_adminView;
  document.getElementById('dash-main').style.display=_adminView?'none':'';
  document.getElementById('dash-admin').style.display=_adminView?'':'none';
  const btn=document.getElementById('admin-btn');
  if(btn){
    btn.textContent=_adminView?'← Dashboard':'👑 Admin';
    btn.style.background=_adminView?'rgba(118,118,118,.15)':'';
  }
  if(_adminView){
    _adminTabLoaded={};
    fetchAdminOverview();
    showAdminTab('users');
  }
}

function showAdminTab(tab){
  const tabs=['users','fees','tokens','health','security','test'];
  tabs.forEach(t=>{
    const btn=document.getElementById('adtab-'+t);
    const pane=document.getElementById('adpane-'+t);
    if(btn) btn.classList.toggle('active',t===tab);
    if(pane) pane.style.display=t===tab?'':'none';
  });
  if(!_adminTabLoaded[tab]){
    _adminTabLoaded[tab]=true;
    if(tab==='users')    fetchAdminUsers();
    else if(tab==='fees')     fetchAdminFees();
    else if(tab==='tokens')   fetchAdminTokens();
    else if(tab==='health')   fetchAdminHealth();
    else if(tab==='security') fetchAdminSecurity();
  }
}

async function fetchAdminOverview(){
  const r=await fetch('/api/admin').then(r=>r.json()).catch(()=>null);
  if(!r||r.error) return;
  document.getElementById('ad-users').textContent=r.total_users??0;
  document.getElementById('ad-trading').textContent=r.users_trading??0;
  document.getElementById('ad-trades-today').textContent=r.trades_today??0;
  document.getElementById('ad-fees-today').textContent='$'+(r.fees_today||0).toFixed(4);
}

async function fetchAdminUsers(){
  const tbody=document.getElementById('ad-users-tbody');
  const r=await fetch('/api/admin/users').then(r=>r.json()).catch(()=>null);
  if(!r||r.error){return;}
  const users=r.users||[];
  if(!users.length){tbody.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:16px">No users yet</td></tr>';return;}
  tbody.innerHTML=users.map(u=>`<tr>
    <td style="font-family:monospace">${esc(u.wallet)}</td>
    <td><span style="color:${u.has_key?'var(--green)':'var(--muted)'}">${u.has_key?'✓ Yes':'✗ No'}</span></td>
    <td><span style="color:${u.trading?'var(--green)':'var(--muted)'}">${u.trading?'● Active':'○ Idle'}</span></td>
    <td style="text-align:center">${u.positions}</td>
    <td>$${(u.max_trade||0).toFixed(2)}</td>
    <td style="color:var(--muted);font-size:10px">${esc(u.created)}</td>
  </tr>`).join('');
}

async function fetchAdminFees(){
  const tbody=document.getElementById('ad-fees-tbody');
  const r=await fetch('/api/admin/fees').then(r=>r.json()).catch(()=>null);
  if(!r||r.error){return;}
  const txs=r.transactions||[];
  if(!txs.length){tbody.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:16px">No fees collected yet</td></tr>';return;}
  tbody.innerHTML=txs.map(f=>{
    const tx=f.tx||'';
    const sol=tx?`<a href="https://solscan.io/tx/${esc(tx)}" target="_blank" style="color:var(--blue)">${esc(tx.slice(0,10))}…</a>`:'-';
    return `<tr>
      <td style="font-size:10px">${esc(f.ts||'')}</td>
      <td style="font-family:monospace">${esc(f.wallet||'')}</td>
      <td>${esc(f.token||'')}</td>
      <td class="td-pos">+$${(f.gross||0).toFixed(4)}</td>
      <td class="td-neg">-$${(f.fee||0).toFixed(4)}</td>
      <td>${sol}</td>
    </tr>`;
  }).join('');
}

async function fetchAdminTokens(){
  const tbody=document.getElementById('ad-tokens-tbody');
  const r=await fetch('/api/admin/tokens').then(r=>r.json()).catch(()=>null);
  if(!r||r.error){return;}
  const tokens=r.tokens||[];
  if(!tokens.length){tbody.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:16px">No trades yet</td></tr>';return;}
  tbody.innerHTML=tokens.map(t=>{
    const tp=t.total_pnl||0,ap=t.avg_pnl||0;
    return `<tr>
      <td style="font-weight:600">${esc(t.token||'')}</td>
      <td style="text-align:center">${t.trades}</td>
      <td style="text-align:center">${t.win_rate}%</td>
      <td class="${tp>=0?'td-pos':'td-neg'}">${tp>=0?'+':'-'}$${Math.abs(tp).toFixed(4)}</td>
      <td class="${ap>=0?'td-pos':'td-neg'}">${ap>=0?'+':'-'}$${Math.abs(ap).toFixed(4)}</td>
      <td class="td-pos">+$${(t.best_pnl||0).toFixed(4)}</td>
    </tr>`;
  }).join('');
}

async function fetchAdminHealth(){
  const grid=document.getElementById('ad-health-grid');
  const r=await fetch('/api/admin/health').then(r=>r.json()).catch(()=>null);
  if(!r||r.error){return;}
  const items=[
    ['Tokens Tracked', r.tokens_tracked, ''],
    ['Active Traders', r.active_traders, ''],
    ['Total Sessions', r.total_sessions, ''],
    ['Total Users', r.total_users, ''],
    ['DB Size', r.db_size_kb+' KB', ''],
    ['AI Cache', r.ai_cache_size+' entries', ''],
    ['AI Key', r.ai_disabled?'⏸ Disabled (1h backoff)':(r.anthropic_key?'✓ Set':'✗ Not set'), r.ai_disabled?'warn':(r.anthropic_key?'ok':'warn')],
    ['DexScreener', r.dex_rate_limited?'⚠ Rate Limited':'✓ OK', r.dex_rate_limited?'warn':'ok'],
    ['Jupiter Proxy', r.jupiter_proxy?'✓ Configured':'— Direct', r.jupiter_proxy?'ok':''],
    ['Owner Wallet', r.owner_configured?'✓ Set':'✗ Not set', r.owner_configured?'ok':'bad'],
    ['Sec Events (1h)', r.sec_events_1h, r.sec_events_1h>5?'warn':''],
  ];
  grid.innerHTML=items.map(([k,v,c])=>`
    <div class="adash-health-item">
      <span class="adash-health-key">${esc(String(k))}</span>
      <span class="adash-health-val ${c==='ok'?'adash-ok':c==='warn'?'adash-warn':c==='bad'?'adash-bad':''}">${esc(String(v))}</span>
    </div>`).join('');
}

async function testAIKey(){
  const btn=document.getElementById('test-ai-btn');
  const out=document.getElementById('test-ai-result');
  if(btn){btn.disabled=true;btn.textContent='Testing…';}
  out.textContent='';
  try{
    const r=await fetch('/api/admin/test',{method:'POST',headers:{'Content-Type':'application/json'}}).then(r=>r.json()).catch(()=>null);
    if(!r){out.style.color='var(--red)';out.textContent='Request failed';return;}
    const ai=r.ai||{};
    out.style.color=ai.ok?'var(--green)':'var(--red)';
    out.textContent=ai.msg||'No response';
    if(ai.ok) _adminTabLoaded['health']=false; // refresh health grid to clear backoff status
  }finally{
    if(btn){btn.disabled=false;btn.textContent='⚡ Test AI Key';}
  }
}

async function runFeeRecovery(){
  const btn=document.getElementById('recover-fees-btn');
  const out=document.getElementById('recover-fees-result');
  btn.disabled=true; btn.textContent='⏳ Recovering…';
  out.innerHTML='<span style="color:var(--muted)">Scanning trades and sending fees…</span>';
  try{
    const r=await fetch('/api/admin/recover-fees',{method:'POST',headers:{'Content-Type':'application/json'}});
    const d=await r.json();
    if(d.error){out.innerHTML=`<span style="color:var(--red)">Error: ${d.error}</span>`;}
    else if(!d.ok){out.innerHTML=`<span style="color:var(--red)">${d.error||'Recovery failed'}</span>`;}
    else{
      const lines=[];
      lines.push(`<b style="color:#4ade80">Total recovered: ${(d.total_sol||0).toFixed(5)} SOL</b>`);
      lines.push(`Wallets processed: ${d.wallets||0}`);
      (d.results||[]).forEach(res=>{
        const icon=res.status==='sent'?'✓':res.status==='skipped_dust'?'—':'✗';
        const col=res.status==='sent'?'#4ade80':res.status==='skipped_dust'?'var(--muted)':'var(--red)';
        const detail=res.status==='sent'
          ?`${res.fee?.toFixed(5)} SOL  TX:${(res.tx||'').slice(0,14)}…  (${res.trades} trade(s))`
          :res.status==='skipped_dust'?`${res.fee?.toFixed(6)} SOL — dust`
          :`FAILED: ${res.error||'unknown'}`;
        lines.push(`<span style="color:${col}">${icon} ${res.wallet}  ${detail}</span>`);
      });
      if(!d.results?.length) lines.push('<span style="color:var(--muted)">No unpaid fees found</span>');
      out.innerHTML=lines.join('<br>');
      if(typeof loadAdminFees==='function') loadAdminFees();
    }
  }catch(e){out.innerHTML=`<span style="color:var(--red)">Request failed: ${e.message}</span>`;}
  finally{btn.disabled=false; btn.textContent='💰 RECOVER FEES NOW';}
}

async function testFeeTransfer(){
  const btn=document.getElementById('test-fee-btn');
  const out=document.getElementById('test-fee-result');
  if(btn){btn.disabled=true;btn.textContent='Running…';}
  out.innerHTML='<span style="color:var(--muted)">Checking…</span>';
  try{
    const r=await fetch('/api/admin/test_fee',{method:'POST',headers:{'Content-Type':'application/json'}}).then(x=>x.json()).catch(()=>null);
    if(!r){out.innerHTML='<span style="color:var(--red)">✗ Request failed — check network</span>';return;}
    let html='';
    // render step-by-step checklist
    if(Array.isArray(r.steps)&&r.steps.length){
      html+=r.steps.map(s=>{
        const icon=s.ok?'<span style="color:var(--green)">✓</span>':'<span style="color:var(--red)">✗</span>';
        const detail=s.detail?` <span style="color:var(--muted)">${esc(s.detail)}</span>`:'';
        return `${icon} ${esc(s.msg)}${detail}`;
      }).join('<br>');
      html+='<br>';
    }
    if(r.ok){
      html+=`<span style="color:var(--green)">${esc(r.msg||'OK')}</span>`;
      if(r.solscan_url) html+=` &nbsp;<a href="${esc(r.solscan_url)}" target="_blank" style="color:var(--blue)">View on Solscan ↗</a>`;
    } else {
      html+=`<span style="color:var(--red)">✗ ${esc(r.error||'Failed')}</span>`;
      if(r.traceback){
        html+=`<details style="margin-top:6px"><summary style="cursor:pointer;color:var(--muted);font-size:10px">Traceback</summary>`+
          `<pre style="font-size:9px;color:var(--muted);white-space:pre-wrap;margin:4px 0 0">${esc(r.traceback)}</pre></details>`;
      }
    }
    out.innerHTML=html;
  }finally{
    if(btn){btn.disabled=false;btn.textContent='🧪 Test Fee Transfer ($0.01)';}
  }
}

async function fetchAdminSecurity(){
  const tbody=document.getElementById('ad-sec-tbody');
  const r=await fetch('/api/admin').then(r=>r.json()).catch(()=>null);
  if(!r||r.error){return;}
  const log=r.security_log||[];
  if(!log.length){tbody.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:12px">No security events yet</td></tr>';return;}
  const ec={key_saved:'var(--green)',key_deleted:'var(--yellow)',key_access:'var(--blue)',key_leak_blocked:'#ff1744',key_rotation:'#ff9500'};
  tbody.innerHTML=log.map(e=>{
    const w=e.wallet||'';
    const ws=w.length>=8?w.slice(0,4)+'...'+w.slice(-4):w;
    return `<tr>
      <td style="font-size:10px">${esc(e.ts||'')}</td>
      <td><span style="color:${ec[e.event]||'var(--muted)'};font-weight:600">${esc(e.event||'')}</span></td>
      <td style="font-family:monospace">${esc(ws)}</td>
      <td style="font-size:10px">${esc(e.ip||'')}</td>
      <td style="font-size:10px">${esc(e.details||'')}</td>
    </tr>`;
  }).join('');
  fetchAdminBans();
}

async function fetchAdminBans(){
  const el=document.getElementById('ad-bans-list');
  const r=await fetch('/api/admin/bans').then(x=>x.json()).catch(()=>null);
  if(!r){return;}
  el.style.color='var(--muted)';
  if(!r.bans||!r.bans.length){
    el.textContent=`No active bans  •  ${r.rl_bucket_count||0} rate-limit bucket(s) in memory`;
    return;
  }
  el.innerHTML=r.bans.map(b=>`<div style="display:flex;align-items:center;gap:12px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.04)">
    <span style="color:var(--red);min-width:130px">${esc(b.ip)}</span>
    <span style="color:var(--muted)">expires in ${b.mins_left} min</span>
    <button onclick="unbanIP('${esc(b.ip)}')" style="margin-left:auto;background:rgba(255,77,106,.1);border:1px solid rgba(255,77,106,.3);border-radius:5px;padding:2px 10px;color:#ef4444;font-size:10px;font-family:'Share Tech Mono',monospace;cursor:pointer">Unban</button>
  </div>`).join('')+
  `<div style="margin-top:6px;color:var(--muted)">${r.bans.length} ban(s) active  •  ${r.rl_bucket_count||0} rate-limit bucket(s) in memory</div>`;
}

async function unbanIP(ip){
  const r=await fetch('/api/admin/clear_ratelimit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})}).then(x=>x.json()).catch(()=>null);
  if(r?.ok) fetchAdminBans();
  else alert('Failed to unban: '+(r?.error||'unknown error'));
}

async function clearAllBans(){
  if(!confirm('Clear all IP bans and rate-limit counters?')) return;
  const r=await fetch('/api/admin/clear_ratelimit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})}).then(x=>x.json()).catch(()=>null);
  const el=document.getElementById('ad-bans-list');
  if(r?.ok){el.style.color='var(--green)';el.textContent='✓ '+r.msg;setTimeout(fetchAdminBans,1500);}
  else{el.style.color='var(--red)';el.textContent='✗ '+(r?.error||'Failed');}
}

async function runTestTrade(){
  const mint=(document.getElementById('test-trade-mint').value||'').trim();
  const out=document.getElementById('test-trade-result');
  if(!mint){out.style.display='block';out.textContent='⚠ Enter a token mint address first.';return;}
  out.style.display='block';
  out.textContent='⏳ Submitting $1 test buy… (may take up to 60s)';
  const btn=document.getElementById('test-trade-btn');
  if(btn){btn.disabled=true;btn.textContent='Running…';}
  try{
    const r=await fetch('/api/admin/test_trade',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({token_address:mint}),
    }).then(r=>r.json()).catch(e=>({error:String(e)}));
    if(r.error){out.textContent='ERROR: '+r.error;return;}
    let txt='';
    if(r.ok){txt+='✅ SUCCESS\n';}else{txt+='❌ FAILED (returncode='+r.returncode+')\n';}
    if(r.solscan_url){txt+='🔗 '+r.solscan_url+'\n';}
    txt+='⏱ '+r.elapsed_s+'s\n\n';
    if(r.stdout){txt+='── STDOUT ──\n'+r.stdout+'\n';}
    if(r.stderr){txt+='\n── STDERR ──\n'+r.stderr+'\n';}
    out.textContent=txt;
    if(r.solscan_url){
      const a=document.createElement('a');
      a.href=r.solscan_url;a.target='_blank';
      a.style='display:block;color:#ffffff;margin-top:6px;font-size:11px;word-break:break-all';
      a.textContent='Open on Solscan ↗';
      out.appendChild(a);
    }
  }finally{
    if(btn){btn.disabled=false;btn.textContent='⚡ Test Trade ($1)';}
  }
}


function renderPerfPanel(r){
  if(!document.getElementById('perf-pnl')) return
  const d=r.daily||{};
  const pnl=d.total_pnl??0;
  const pct=d.total_pnl_pct??0;
  const trades=d.trades??0;
  const wins=d.wins??0;

  const pnlEl=document.getElementById('p-pnl');
  pnlEl.textContent=(pnl>=0?'+':'-')+fmtSolToUsdc(Math.abs(pnl));
  pnlEl.className='perf-stat-val '+(pnl>=0?'td-pos':'td-neg');

  const pctEl=document.getElementById('p-pct');
  pctEl.textContent=(pct>=0?'+':'')+pct.toFixed(2)+'%';
  pctEl.className='perf-stat-val '+(pct>=0?'td-pos':'td-neg');

  document.getElementById('p-trades').textContent=trades;
  const wrStr=trades>0?Math.round(wins/trades*100)+'%':'—';
  document.getElementById('p-wr').textContent=wrStr;
  const sbWr=document.getElementById('sb-wr');
  if(sbWr) sbWr.textContent=wrStr;
  const sbPnl=document.getElementById('sb-allpnl');
  if(sbPnl){
    sbPnl.textContent=(pnl>=0?'+':'')+pnl.toFixed(4)+' SOL';
    sbPnl.className='statsbar-val '+(pnl>=0?'pos':'neg');
  }
  document.getElementById('p-best').textContent=d.best!=null?'+'+d.best.toFixed(1)+'%':'—';
  document.getElementById('p-worst').textContent=d.worst!=null?d.worst.toFixed(1)+'%':'—';
  const _now=new Date();
  document.getElementById('perf-date').textContent=_now.toLocaleDateString(navigator.language,{weekday:'short',month:'short',day:'numeric'});
  const _tzOff=-_now.getTimezoneOffset(),_tzH=Math.floor(Math.abs(_tzOff)/60),_tzM=Math.abs(_tzOff)%60;
  document.getElementById('perf-tz').textContent='UTC'+(_tzOff>=0?'+':'-')+_tzH+(_tzM?':'+String(_tzM).padStart(2,'0'):'');

  renderPnlChart(d.curve||[]);

  const tbody=document.getElementById('trade-tbody');
  const hist=(r.history||[]).slice().reverse();
  if(!hist.length){
    tbody.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:16px">No trades today</td></tr>';
    return;
  }
  tbody.innerHTML=hist.map(t=>{
    const p=t.pnl??0, pp=t.pnl_pct??0;
    const cls=p>=0?'td-pos':'td-neg';
    const sign=p>=0?'+':'';
    const avoidBtn=t.mint?`<button class="avoid-btn" onclick="avoidToken('${esc(t.mint)}','${esc(t.symbol||'???')}')" title="Avoid — bot will skip this token">🚫</button>`:'';
    return `<tr>
      <td>${t.ts?new Date(t.ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}):(t.time||'—')}</td>
      <td class="td-sym">${esc(t.symbol||'???')}</td>
      <td>${fmtPrice(t.entry||0)}</td>
      <td>${fmtPrice(t.exit||0)}</td>
      <td class="${cls}">${sign}${fmtSolToUsdc(Math.abs(p))} <span style="opacity:.6;font-size:9px">(${sign}${pp.toFixed(1)}%)</span></td>
      <td>${avoidBtn}</td>
    </tr>`;
  }).join('');
}

function renderPnlChart(curve){
  const svg=document.getElementById('pnl-chart');
  const emptyEl=document.getElementById('perf-chart-empty');
  const W=600,H=120,PAD=14,XPAD=36,BPAD=18;
  if(!curve.length){
    svg.innerHTML='';
    if(emptyEl) emptyEl.style.display='flex';
    return;
  }
  if(emptyEl) emptyEl.style.display='none';
  const pts=[{t:'00:00',v:0},...curve];
  const vals=pts.map(p=>p.v);
  const minV=Math.min(0,...vals), maxV=Math.max(0,...vals);
  const range=Math.max(maxV-minV,0.001);
  const chartH=H-PAD-BPAD;
  const mX=i=>XPAD+(i/Math.max(pts.length-1,1))*(W-XPAD-PAD);
  const mY=v=>PAD+(1-(v-minV)/range)*(chartH-PAD);
  const zY=mY(0);
  const lastV=pts[pts.length-1].v;
  const pos=lastV>=0;
  const col=pos?'#000000':'#ff1744';
  const lineStr=pts.map((p,i)=>mX(i)+','+mY(p.v)).join(' ');
  const areaStr=mX(0)+','+zY+' '+lineStr+' '+mX(pts.length-1)+','+zY;
  const zeroLine=(minV<0&&maxV>0)?`<line x1="${XPAD}" y1="${zY}" x2="${W-PAD}" y2="${zY}" stroke="var(--border2)" stroke-width="1" stroke-dasharray="4,3"/>`:'' ;
  // Y-axis label (last value)
  const yLabel=(lastV>=0?'+':'')+lastV.toFixed(4)+' ◎';
  // X-axis time labels: first, middle, last
  const labelIdxs=[0,Math.floor((pts.length-1)/2),pts.length-1];
  const xLabels=labelIdxs.map(i=>{
    const t=pts[i]?.t||'';
    return `<text x="${mX(i)}" y="${H-3}" text-anchor="middle" fill="#4a7095" font-size="8" font-family="Share Tech Mono,monospace">${t}</text>`;
  }).join('');
  svg.innerHTML=`
    <defs>
      <linearGradient id="cg" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="${col}" stop-opacity="0.18"/>
        <stop offset="100%" stop-color="${col}" stop-opacity="0.01"/>
      </linearGradient>
    </defs>
    <polygon points="${areaStr}" fill="url(#cg)"/>
    <polyline points="${lineStr}" fill="none" stroke="${col}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
    ${zeroLine}
    <circle cx="${mX(pts.length-1)}" cy="${mY(lastV)}" r="3.5" fill="${col}"/>
    <text x="${XPAD-2}" y="${mY(lastV)+4}" text-anchor="end" fill="${col}" font-size="8" font-family="Share Tech Mono,monospace">${yLabel}</text>
    ${xLabels}
  `;
}

function renderPositions(detail){
  _openMints=new Set((detail||[]).map(p=>p.mint).filter(Boolean));
  const emptyEl=document.getElementById('top-pos-empty');
  const listEl=document.getElementById('top-pos-list');
  if(!detail||!detail.length){
    if(emptyEl) emptyEl.style.display='block';
    if(listEl) listEl.style.display='none';
    return;
  }
  if(emptyEl) emptyEl.style.display='none';
  if(listEl) listEl.style.display='block';
  const posCount=document.getElementById('pos-count');
  if(posCount) posCount.textContent=detail.length+'/5';
  listEl.innerHTML=detail.map(p=>{
    const isPos=p.pnl>=0;
    const cls=isPos?'td-pos':'td-neg';
    const sign=isPos?'+':'-';
    const pnlStr=sign+fmtSolToUsdc(Math.abs(p.pnl||0));
    const pctStr=(isPos?'+':'-')+Math.abs(p.pnl_pct||0).toFixed(1)+'%';
    const sym=p.mint?`<a href="/token/${esc(p.mint)}" style="color:inherit;text-decoration:none">${esc(p.symbol||'???')}</a>`:esc(p.symbol||'???');
    return `<div class="pos-mini-card" id="pos-row-${esc(p.mint||'')}">
      <div class="pos-mini-sym">${sym}</div>
      <div style="display:flex;align-items:center;gap:6px">
        <div class="${cls} pos-mini-pnl">${pnlStr} <span style="font-size:9px;opacity:.7">${pctStr}</span></div>
        <div id="pos-act-${esc(p.mint||'')}" style="display:flex;gap:3px">
          <button class="pos-chart-btn" style="padding:2px 7px;font-size:9px" onclick="openPosChart('${esc(p.mint||'')}','${esc(p.symbol||'???')}',${p.current||0})">📈</button>
          <button class="pos-sell-btn" style="padding:2px 7px;font-size:9px" onclick="_posStartSell('${esc(p.mint||'')}','${esc(p.symbol||'???')}')">✕</button>
          ${p.mint?`<button class="avoid-btn" style="padding:2px 5px;font-size:9px" onclick="avoidToken('${esc(p.mint)}','${esc(p.symbol||'???')}')" title="Avoid">🚫</button>`:''}
        </div>
      </div>
    </div>`;
  }).join('');
}

// ── POSITION SELL ──
function _posStartSell(mint, symbol) {
  const wrap = document.getElementById('pos-act-' + mint);
  if (!wrap) return;
  wrap.dataset.origHtml = wrap.innerHTML;
  wrap.innerHTML = `<div class="pos-sell-conf">
    <span class="pos-sell-conf-label">Sell ${esc(symbol)}?</span>
    <button class="pos-sell-confirm-btn" onclick="_posConfirmSell('${esc(mint)}','${esc(symbol)}')">Confirm Sell</button>
    <button class="pos-sell-cancel-btn" onclick="_posCancelSell('${esc(mint)}')">Cancel</button>
  </div>`;
}

function _posCancelSell(mint) {
  const wrap = document.getElementById('pos-act-' + mint);
  if (!wrap || !wrap.dataset.origHtml) return;
  wrap.innerHTML = wrap.dataset.origHtml;
  delete wrap.dataset.origHtml;
}

async function _posConfirmSell(mint, symbol) {
  const wrap = document.getElementById('pos-act-' + mint);
  if (!wrap) return;
  const confirmBtn = wrap.querySelector('.pos-sell-confirm-btn');
  const cancelBtn  = wrap.querySelector('.pos-sell-cancel-btn');
  if (confirmBtn) { confirmBtn.disabled = true; confirmBtn.textContent = 'Selling…'; }
  if (cancelBtn)  { cancelBtn.disabled = true; }
  try {
    const resp = await fetch('/api/sell', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({mint})
    });
    const data = await resp.json();
    if (data.ok) {
      const row = document.getElementById('pos-row-' + mint);
      if (row) row.remove();
      showLfToast('✓', (data.symbol || symbol) + ' sold', 'pos');
    } else {
      wrap.innerHTML = `<div class="pos-sell-conf">
        <span class="pos-sell-err">✗ ${esc(data.msg || 'Sell failed')}</span>
        <button class="pos-sell-cancel-btn" onclick="_posCancelSell('${esc(mint)}')">Dismiss</button>
      </div>`;
    }
  } catch(e) {
    wrap.innerHTML = `<div class="pos-sell-conf">
      <span class="pos-sell-err">✗ Network error</span>
      <button class="pos-sell-cancel-btn" onclick="_posCancelSell('${esc(mint)}')">Dismiss</button>
    </div>`;
  }
}

// ── POSITION CHART MODAL ──
let _posChart=null,_posSeries=null,_posVolSeries=null,_posPriceLine=null;
let _posCurrentMint='',_posCurrentTf='5m';

async function openPosChart(mint,symbol,currentPrice){
  if(!mint) return;
  _posCurrentMint=mint;
  _posCurrentTf='5m';
  document.getElementById('pos-chart-title').textContent=(symbol||mint.slice(0,8))+' — 5m';
  document.querySelectorAll('#pos-chart-tf-bar .chart-tf-btn').forEach(b=>b.classList.toggle('active',b.textContent==='5m'));
  document.getElementById('pos-chart-modal').classList.add('open');
  document.body.style.overflow='hidden';
  _initPosChart(currentPrice);
  await _loadPosChartData();
}

function closePosChart(){
  document.getElementById('pos-chart-modal').classList.remove('open');
  document.body.style.overflow='';
}

async function setPosChartTf(tf,btn){
  _posCurrentTf=tf;
  document.querySelectorAll('#pos-chart-tf-bar .chart-tf-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  const titleEl=document.getElementById('pos-chart-title');
  titleEl.textContent=titleEl.textContent.replace(/— .+$/,'— '+tf);
  await _loadPosChartData();
}

function _initPosChart(currentPrice){
  const container=document.getElementById('pos-chart-container');
  if(_posChart){
    // Chart already exists — just refresh the price line
    try{if(_posPriceLine) _posSeries.removePriceLine(_posPriceLine);}catch(e){}
    if(currentPrice>0) _posPriceLine=_posSeries.createPriceLine({price:currentPrice,color:'#ffc13a',lineWidth:1,lineStyle:2,axisLabelVisible:true,title:'now'});
    return;
  }
  _posChart=LightweightCharts.createChart(container,{
    width:container.clientWidth,
    height:container.clientHeight||400,
    layout:{background:{type:'solid',color:'#0d0d0d'},textColor:'#d1d4dc'},
    grid:{vertLines:{color:'#1e222d'},horzLines:{color:'#1e222d'}},
    crosshair:{mode:LightweightCharts.CrosshairMode.Normal},
    rightPriceScale:{borderColor:'#2a2e39'},
    timeScale:{borderColor:'#2a2e39',timeVisible:true,secondsVisible:false},
    handleScroll:true,handleScale:true,
  });
  _posSeries=_posChart.addCandlestickSeries({
    upColor:'#26a69a',downColor:'#ef5350',
    borderVisible:false,
    wickUpColor:'#26a69a',wickDownColor:'#ef5350',
  });
  _posVolSeries=_posChart.addHistogramSeries({
    priceFormat:{type:'volume'},priceScaleId:'pos-vol',
  });
  _posChart.priceScale('pos-vol').applyOptions({scaleMargins:{top:0.70,bottom:0}});
  if(currentPrice>0) _posPriceLine=_posSeries.createPriceLine({price:currentPrice,color:'#ffc13a',lineWidth:1,lineStyle:2,axisLabelVisible:true,title:'now'});
  new ResizeObserver(()=>{
    if(container.clientWidth>0) _posChart.applyOptions({width:container.clientWidth,height:container.clientHeight});
  }).observe(container);
}

async function _loadPosChartData(){
  const loadEl=document.getElementById('pos-chart-loading');
  if(loadEl){loadEl.textContent='Loading chart…';loadEl.style.display='flex';}
  const r=await fetch('/api/chart/'+encodeURIComponent(_posCurrentMint)+'?tf='+_posCurrentTf).then(r=>r.json()).catch(()=>null);
  if(r?.candles?.length){
    _posSeries.setData(r.candles.map(c=>({time:c.t,open:c.o,high:c.h,low:c.l,close:c.c})));
    _posVolSeries.setData(r.candles.map(c=>({time:c.t,value:c.v,color:c.c>=c.o?'rgba(38,166,154,.45)':'rgba(239,83,80,.45)'})));
    _posChart.timeScale().fitContent();
    if(loadEl) loadEl.style.display='none';
  }else{
    if(loadEl){loadEl.textContent='Chart unavailable for this token';loadEl.style.display='flex';}
  }
}

document.addEventListener('keydown',e=>{if(e.key==='Escape') closePosChart();});

// ── LIVE ACTIVITY FEED ──
let _lfHistory=[], _lfPositions=[], _lfMintMap={}, _lfLastSeenTs=0;
let _lfPositionMints=new Set(), _lfCountdownVal=10, _lfCountdownTimer=null;
let _solPrice=0;
function fmtSolToUsdc(sol){return '$'+(sol*_solPrice).toFixed(2);}

function _lfBuildMintMap(tokens){
  if(!tokens?.length) return;
  for(const t of tokens) if(t.mint&&t.symbol) _lfMintMap[String(t.symbol).toUpperCase()]=t.mint;
}

function _lfResolveMint(symbol, mintDirect){
  if(mintDirect) return safeMint(mintDirect);
  return safeMint(_lfMintMap[String(symbol||'').toUpperCase()]||'');
}

function _lfLogoHtml(sym, mint){
  const initial=esc(String(sym||'?')[0].toUpperCase());
  if(mint){
    const url=esc('https://dd.dexscreener.com/ds-data/tokens/solana/'+mint+'.png');
    return `<div class="lf-logo"><img src="${url}" alt="" loading="lazy" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"><span style="display:none;width:100%;height:100%;align-items:center;justify-content:center">${initial}</span></div>`;
  }
  return `<div class="lf-logo">${initial}</div>`;
}

function renderLiveFeed(){
  const list=document.getElementById('lf-list');
  const countEl=document.getElementById('lf-count');
  if(!list) return;
  const feed=[];
  for(const pos of _lfPositions){
    feed.push({type:'buy',symbol:pos.symbol,entry:pos.entry,exit:pos.current,pnl:pos.pnl,pnl_pct:pos.pnl_pct,ts:pos.opened_at||0,mint:pos.mint||'',spend:pos.spend||0,exit_reason:''});
  }
  for(const t of _lfHistory){
    feed.push({type:'sell',symbol:t.symbol,entry:t.entry,exit:t.exit,pnl:t.pnl,pnl_pct:t.pnl_pct,ts:t.ts||0,time:t.time,mint:t.mint||'',spend:t.spend||0,exit_reason:t.exit_reason||''});
  }
  feed.sort((a,b)=>b.ts-a.ts);
  const items=feed.slice(0,20);
  if(countEl) countEl.textContent=items.length?items.length+' recent':'';
  if(!items.length){list.innerHTML='<div class="lf-empty">No recent trades yet</div>';return;}
  list.innerHTML=items.map(item=>{
    const isBuy=item.type==='buy';
    const mint=_lfResolveMint(item.symbol,item.mint);
    const logoHtml=_lfLogoHtml(item.symbol,mint);
    const pnlPos=(item.pnl||0)>=0;
    const pnlCls=pnlPos?'td-pos':'td-neg';
    const sign=pnlPos?'+':'-';
    const itemCls='lf-item '+(isBuy?'lf-item-buy':(pnlPos?'lf-item-sell-pos':'lf-item-sell-neg'));
    const reason=(item.exit_reason||'').toUpperCase();
    const isTp=!isBuy&&reason.includes('TAKE PROFIT');
    const isSl=!isBuy&&reason.includes('STOP LOSS');
    const badge=isBuy
      ?'<span class="lf-badge lf-badge-buy">BUY</span>'
      :isTp?'<span class="lf-badge lf-badge-tp">TAKE PROFIT</span>'
      :isSl?'<span class="lf-badge lf-badge-sl">STOP LOSS</span>'
      :'<span class="lf-badge lf-badge-sell">SELL</span>';
    const priceLabel=isBuy?'Current':'Exit';
    const priceHtml=`Entry: <span>${fmtPrice(item.entry||0)}</span>&nbsp;→&nbsp;${priceLabel}: <span>${fmtPrice(item.exit||0)}</span>`;
    const spendSol=item.spend||0;
    const amtHtml=spendSol>0
      ?`<div class="lf-amt">◎${spendSol.toFixed(4)} <span style="color:var(--dim)">/ $${(spendSol*_solPrice).toFixed(2)}</span></div>`
      :'';
    const timeStr=item.ts?new Date(item.ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}):(item.time||'—');
    const txHtml=mint?`<a href="https://solscan.io/token/${mint}" target="_blank" rel="noopener" class="lf-tx">View ↗</a>`:'';
    return `<div class="${itemCls}">
      ${logoHtml}
      <div class="lf-main">
        <div class="lf-top-row">${badge}${mint?`<a href="/token/${esc(mint)}" class="lf-sym" style="color:inherit;text-decoration:none" onmouseover="this.style.color='var(--green)'" onmouseout="this.style.color='inherit'">${esc(item.symbol||'???')}</a>`:`<span class="lf-sym">${esc(item.symbol||'???')}</span>`}</div>
        <div class="lf-prices">${priceHtml}</div>
        ${amtHtml}
      </div>
      <div class="lf-right">
        <span class="${pnlCls} lf-pnl-sol">${sign}${fmtSolToUsdc(Math.abs(item.pnl||0))}</span>
        <span class="${pnlCls} lf-pnl-pct">${sign}${Math.abs(item.pnl_pct||0).toFixed(1)}%</span>
        <span class="lf-time">${esc(timeStr)}</span>
        ${txHtml}
      </div>
    </div>`;
  }).join('');
}

function _lfCheckNewTrades(recent){
  if(!recent?.length) return;
  if(_lfLastSeenTs===0){_lfLastSeenTs=Math.max(...recent.map(t=>t.ts||0));return;}
  const newTrades=recent.filter(t=>(t.ts||0)>_lfLastSeenTs);
  for(const t of newTrades){
    const sym=String(t.symbol||'???').toUpperCase();
    const pnlPos=(t.pnl||0)>=0;
    const icon=pnlPos?'🟢':'🔴';
    const msg=`SOLD ${sym} at ${fmtPrice(t.exit||0)} (${pnlPos?'+':''}${(t.pnl_pct||0).toFixed(1)}%)`;
    showLfToast(icon,msg,pnlPos?'pos':'neg');
  }
  if(newTrades.length) _lfLastSeenTs=Math.max(...recent.map(t=>t.ts||0));
}

// ── PUSH NOTIFICATIONS ───────────────────────────────────────────────────────
let _prevPosMap = null; // null = not yet seeded; Map<mint, posObj> after first poll
let _prefSoundAlerts = false;

function _checkClosedPositions(currentPositions){
  if(_prevPosMap === null){
    // First poll after load: seed the map without firing notifications
    _prevPosMap = new Map((currentPositions||[]).map(p=>[p.mint, p]));
    return;
  }
  const currentMints = new Set((currentPositions||[]).map(p=>p.mint).filter(Boolean));
  for(const [mint, pos] of _prevPosMap){
    if(!currentMints.has(mint)){
      const sym  = String(pos.symbol||mint.slice(0,6)).toUpperCase();
      const pnl  = pos.pnl||0;
      const sol  = Math.abs(pnl).toFixed(4);
      if(pnl >= 0){
        _pushNotif('✅ '+sym+' sold — WIN', '+'+sol+' SOL profit!');
        if(_prefSoundAlerts) _playTradeSound(true);
      } else {
        _pushNotif('❌ '+sym+' sold — LOSS', '-'+sol+' SOL loss');
        if(_prefSoundAlerts) _playTradeSound(false);
      }
    }
  }
  _prevPosMap = new Map((currentPositions||[]).map(p=>[p.mint, p]));
}

function _playTradeSound(win){
  try{
    var ctx=new (window.AudioContext||window.webkitAudioContext)();
    var osc=ctx.createOscillator();
    var gain=ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.type='sine';
    if(win){
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      osc.frequency.setValueAtTime(1100, ctx.currentTime+0.12);
    } else {
      osc.frequency.setValueAtTime(440, ctx.currentTime);
      osc.frequency.setValueAtTime(330, ctx.currentTime+0.12);
    }
    gain.gain.setValueAtTime(0.3, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime+0.35);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime+0.35);
    osc.onended=function(){ ctx.close(); };
  }catch(e){}
}

function _lfCheckNewBuys(positions){
  const newMints=new Set((positions||[]).map(p=>p.mint).filter(Boolean));
  if(_lfPositionMints.size>0){
    for(const pos of (positions||[])){
      if(pos.mint&&!_lfPositionMints.has(pos.mint)){
        const sym=String(pos.symbol||'???').toUpperCase();
        showLfToast('🟢',`BOUGHT ${sym} at ${fmtPrice(pos.entry||0)}`,'pos');
      }
    }
  }
  _lfPositionMints=newMints;
}

function showLfToast(icon,msg,type){
  const wrap=document.getElementById('lf-toast-wrap');
  if(!wrap) return;
  const toast=document.createElement('div');
  toast.className='lf-toast';
  if(type==='warn'){
    toast.style.borderLeft='3px solid #ffc107';
    toast.style.background='rgba(255,193,7,0.08)';
  } else {
    toast.style.borderLeft='3px solid '+(type==='pos'?'var(--green)':'var(--red)');
  }
  const iconSpan=document.createElement('span');
  iconSpan.className='lf-toast-icon';
  iconSpan.textContent=icon;
  const textSpan=document.createElement('span');
  textSpan.textContent=msg;
  toast.appendChild(iconSpan);
  toast.appendChild(textSpan);
  wrap.appendChild(toast);
  setTimeout(()=>{
    toast.classList.add('lf-toast-removing');
    toast.addEventListener('animationend',()=>toast.remove(),{once:true});
  },type==='warn'?4000:4500);
}

function _lfStartCountdown(){
  if(_lfCountdownTimer) clearInterval(_lfCountdownTimer);
  _lfCountdownVal=10;
  const el=document.getElementById('lf-countdown');
  if(el) el.textContent='↻ '+_lfCountdownVal+'s';
  _lfCountdownTimer=setInterval(()=>{
    _lfCountdownVal=Math.max(0,_lfCountdownVal-1);
    if(el) el.textContent=_lfCountdownVal>0?'↻ '+_lfCountdownVal+'s':'refreshing…';
    if(_lfCountdownVal===0) _lfCountdownVal=10;
  },1000);
}


function _refreshTradeBtnState(){
  const tb=document.getElementById('trade-btn');
  if(!tb) return;
  if(traderOn){ tb.disabled=false; tb.title=''; tb.style.opacity=''; return; }
  if(!phantomKey){
    tb.disabled=true; tb.title='Connect a wallet to enable trading'; tb.style.opacity='.45';
  } else {
    tb.disabled=false; tb.title=''; tb.style.opacity='';
  }
}


function updateBtns(){
  if(!document.getElementById('start-btn')&&!document.getElementById('ob-start-btn')) return
  const tb=document.getElementById('trade-btn');
  const tbadge=document.getElementById('trade-badge');
  const tc=document.getElementById('trade-card');
  const scanText=document.getElementById('bot-scan-text');
  if(traderOn){
    tb.textContent='■ STOP';
    tb.className='botbar-btn botbar-btn-stop';
    tbadge.textContent='RUNNING';tbadge.className='badge badge-run';
    tc.className='botbar botbar-running';
    if(scanText) scanText.style.display='';
  } else {
    tb.textContent='▶ START';
    tb.className='botbar-btn botbar-btn-start';
    tbadge.textContent='IDLE';tbadge.className='badge badge-idle';
    tc.className='botbar';
    if(scanText) scanText.style.display='none';
  }
  _refreshTradeBtnState();
  _updateBotIdleBanner();
  const sbDot=document.getElementById('sb-bot-dot');
  const sbText=document.getElementById('sb-bot-text');
  if(sbDot){ sbDot.className='sb-bot-dot '+(traderOn?'running':'idle'); }
  if(sbText){ sbText.textContent='Bot: '+(traderOn?'RUNNING':'IDLE'); }
  const sbStartBtn=document.getElementById('sb-start-btn');
  if(sbStartBtn){
    if(traderOn){
      sbStartBtn.textContent='⏹ Stop Trading';
      sbStartBtn.style.background='var(--red)';
      sbStartBtn.style.color='#fff';
    } else {
      sbStartBtn.textContent='▶ Start Trading';
      sbStartBtn.style.background='';
      sbStartBtn.style.color='';
    }
  }
  /* ── feed bot card ── */
  const feedDot=document.getElementById('feed-bot-dot');
  const feedStatus=document.getElementById('feed-bot-status-text');
  const feedBtn=document.getElementById('feed-trade-btn');
  if(feedDot) feedDot.classList.toggle('running',traderOn);
  if(feedStatus) feedStatus.textContent=traderOn?'Your bot is running':'Your bot is idle';
  if(feedBtn){
    if(traderOn){ feedBtn.textContent='⏹ Stop Trading'; feedBtn.classList.add('stop'); }
    else { feedBtn.textContent='▶ Start Trading'; feedBtn.classList.remove('stop'); }
    feedBtn.disabled=!phantomKey;
    feedBtn.title=phantomKey?'':'Connect a wallet to enable trading';
  }
}

function _updateBotIdleBanner(){
  const b=document.getElementById('bot-idle-banner');
  if(!b) return;
  // Show only when: wallet connected, key saved, not already running
  const show = !!(phantomKey && settingsHasKey && !traderOn);
  b.classList.toggle('hide', !show);
}

async function toggleTrader(){
  if(!traderOn && !settingsHasKey){
    showTradeWarn('⚠️ Add your trading wallet private key in Settings first');
    openSettings();
    return;
  }
  if(!traderOn){
    const sol=parseFloat(document.getElementById('s-sol').textContent)||0;
    if(sol < 0.02){
      showTradeWarn('⚠️ Low SOL balance — you need at least 0.02 SOL to trade');
      return;
    }
  }
  hideTradeWarn();
  const starting=!traderOn;
  const tb=document.getElementById('trade-btn');
  tb.disabled=true; tb.style.opacity='.6';
  // Watchdog: re-enable after 5 s regardless, so a hung request never leaves the button stuck
  const watchdog=setTimeout(()=>{ _refreshTradeBtnState(); },5000);
  try{
    const res=await fetch(starting?'/api/trader/start':'/api/trader/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({interval:300,trade_pct:0.20,max_usdc:1.0})});
    const rj=await res.json().catch(()=>null);
    if(rj&&rj.ok){
      traderOn=starting;   // optimistic update — don't wait for fetchState()
      updateBtns();
    } else if(rj&&!rj.ok&&rj.msg){
      showTradeWarn('⚠️ '+rj.msg);
    }
    await fetchState();    // authoritative sync
  }catch(e){ console.error('toggleTrader',e); }
  finally{ clearTimeout(watchdog); _refreshTradeBtnState(); }
}

// ── MOBILE DETECTION & ONBOARD SETUP ──
function _isMobile(){ return /Android|iPhone|iPad|iPod|IEMobile|Opera Mini/i.test(navigator.userAgent); }
function _inDappBrowser(){ return !!(window.solana||window.solflare); }
(function _setupOnboard(){
  // On a mobile regular browser (no injected wallet), swap connect buttons for deep links.
  // Inside Phantom/Solflare's built-in browser, or on desktop, keep the existing flow.
  if(_isMobile()&&!_inDappBrowser()){
    var _mds=document.getElementById('mobile-deeplink-section'); if(_mds) _mds.style.display='none';
    var _dcs=document.getElementById('dapp-connect-section'); if(_dcs) _dcs.style.display='none';
    var _scb=document.getElementById('step1-continue-btn'); if(_scb) _scb.style.display='none';
    // Hide Phantom connect on mobile regular browsers — deep-link flow is unreliable
    var _pb=document.getElementById('phantom-ob-btn');
    var _pn=document.getElementById('ob-phantom-note');
    if(_pb) _pb.style.display='none';
    if(_pn) _pn.style.display='none';
  }
})();

// ── STARTUP: restore session ──
(async function initApp(){
  if(localStorage.getItem('orca_manual_disconnect') && !phantomKey){ return; }
  if(phantomKey){ localStorage.removeItem('orca_manual_disconnect'); }
  // Check extension wallet before using session wallet
  const phantomReady  = window.solana?.isPhantom   && window.solana?.isConnected && window.solana?.publicKey;
  const solflareReady = window.solflare?.isSolflare && window.solflare?.isConnected && window.solflare?.publicKey;
  const _p = phantomReady ? window.solana : solflareReady ? window.solflare : null;
  const _n = phantomReady ? 'Phantom'    : solflareReady ? 'Solflare'      : null;

  // If session wallet exists but doesn't match the connected extension wallet → clear session & reload
  if(phantomKey && _p){
    const _extPk = _p.publicKey.toString();
    if(_extPk !== phantomKey){
      await fetch('/api/logout',{method:'POST',credentials:'include'}).catch(()=>{});
      window.location.reload();
      return;
    }
  }

  // If Flask session pre-populated phantomKey, go straight to launchApp — no extension
  // re-detection needed, and avoids a redundant /api/wallet/set round-trip.
  if(phantomKey){ await launchApp(); return; }

  // Extension already connected with no session wallet — register it
  if(_p && _n){
    const _pk=_p.publicKey.toString();
    phantomKey=_pk; walletType=_n;
    const r=await _connectWalletSigned(_p, _pk);
    if(!r?.ok && (r?.msg==='Signature rejected'||(r?.msg||'').startsWith('Nonce expired'))){
      const _m=document.getElementById('wallet-install-msg');
      if(_m){ _m.textContent='Onderteken het verzoek in je wallet om in te loggen — probeer opnieuw'; _m.style.display='block'; }
      return;
    }
    if(r?.csrf_token) _csrfToken=r.csrf_token;
    settingsHasKey=r?.has_trading_key||false; _isAdmin=r?.is_admin||false; _updateKeyStatus();
    if(r?.success){
      if(r.status==='new_user'){ gotoSetupGuide(); return; }
      await launchApp();
      return;
    }
    await launchApp();
    return;
  }

  // No wallet detected — leave onboarding visible so user can connect
  // (skipToApp() is still available for browse-without-connecting)
})();

window.addEventListener('pageshow', function(event) {
  if (event.persisted) {
    launchApp();
  }
});

// ── SETTINGS MODAL ──
let settingsHasKey=false;
let _displayName=null;
let _avatarUrl=null;
let _pendingAvatarData=null;

function _getInitials(){
  if(_displayName) return _displayName.slice(0,2).toUpperCase();
  if(phantomKey)   return phantomKey.slice(0,2).toUpperCase();
  return '?';
}

function _updateNavPill(){
  if(!phantomKey) return;
  const short=phantomKey.slice(0,4)+'...'+phantomKey.slice(-4);
  document.getElementById('wallet-short').textContent=_displayName||short;
  const img=document.getElementById('nav-avatar-img');
  const ini=document.getElementById('nav-avatar-ini');
  if(_avatarUrl){
    img.src=_avatarUrl; img.style.display='block'; ini.style.display='none';
  } else {
    img.style.display='none'; ini.style.display='block'; ini.textContent=_getInitials();
  }
}


function _previewAvatar(url){
  const img=document.getElementById('s-avatar-img');
  const ini=document.getElementById('s-avatar-ini');
  if(url){
    img.src=url; img.style.display='block'; ini.style.display='none';
  } else {
    img.style.display='none'; ini.style.display='block'; ini.textContent=_getInitials();
  }
}

function _syncSettingsAvatar(){
  _pendingAvatarData=null;
  _previewAvatar(_avatarUrl||'');
  const m=document.getElementById('s-avatar-msg'); m.className='s-msg'; m.textContent='';
  const fi=document.getElementById('s-avatar-file'); if(fi) fi.value='';
}

function toggleHowTo(btn){
  const body=btn.nextElementSibling;
  const open=body.classList.toggle('open');
  btn.setAttribute('aria-expanded',open);
  btn.querySelector('.how-to-arrow').style.transform=open?'rotate(180deg)':'rotate(0deg)';
}

function _checkWelcomeBanner(){
  const banner=document.getElementById('welcome-banner');
  if(!banner) return;
  const dismissed=localStorage.getItem('orca_welcome_dismissed');
  if(!dismissed && phantomKey && !settingsHasKey){
    banner.classList.remove('hide');
  } else {
    banner.classList.add('hide');
  }
  _checkSetupWizard();
}
function dismissWelcome(){
  localStorage.setItem('orca_welcome_dismissed','1');
  document.getElementById('welcome-banner').classList.add('hide');
}

// ── SETUP WIZARD ──────────────────────────────────────────────────────────────
let _wizardStep=0;

function _wizardStepHtml(step){
  if(step===1) return `
    <div class="swiz-step-icon">⬡</div>
    <div class="swiz-step-h">Connect your wallet</div>
    <div class="swiz-step-p">Link your Phantom or Solflare wallet so OrcAgent knows who you are.</div>
    <span class="swiz-check">✓ Wallet connected</span>`;
  if(step===2) return `
    <div class="swiz-step-icon">🔑</div>
    <div class="swiz-step-h">Add your trading key</div>
    <div class="swiz-step-p">OrcAgent needs your trading wallet private key to execute trades on your behalf. It is encrypted and never exposed.</div>
    <button class="swiz-action-btn" onclick="openSettings()">⚙ Open Settings</button>`;
  const addr=phantomKey||'—';
  return `
    <div class="swiz-step-icon">◎</div>
    <div class="swiz-step-h">Fund your trading wallet</div>
    <div class="swiz-step-p">Send SOL to your trading wallet so the bot can buy tokens.</div>
    <div class="swiz-addr-box">
      <span>${addr}</span>
      <button class="swiz-copy-btn" onclick="_wizardCopyAddr()" title="Copy">⧉</button>
    </div>
    <div class="swiz-qr"><span style="font-size:26px">▦</span><span>QR placeholder</span></div>`;
}

function _checkSetupWizard(){
  if(localStorage.getItem('orca_wizard_dismissed')||!phantomKey){
    if(_wizardStep>0) _hideSetupWizard();
    return;
  }
  if(settingsHasKey&&_wizardStep===0) return; // already set up before wizard ran
  if(settingsHasKey&&_wizardStep===2){ _showSetupWizard(3); return; } // key just saved
  if(!settingsHasKey&&_wizardStep===0) _showSetupWizard(1);
}

function _showSetupWizard(step){
  _wizardStep=step;
  const el=document.getElementById('setup-wizard');
  if(!el) return;
  el.classList.remove('hide');
  document.getElementById('swiz-prog-bar').style.width=Math.round(step/3*100)+'%';
  document.getElementById('swiz-step-lbl').textContent='Step '+step+' of 3';
  document.getElementById('swiz-body').innerHTML=_wizardStepHtml(step);
  document.getElementById('swiz-next-btn').textContent=step===3?'Done ✓':'Next →';
}

function _hideSetupWizard(){
  _wizardStep=0;
  const el=document.getElementById('setup-wizard');
  if(el) el.classList.add('hide');
}

function _wizardNext(){
  if(_wizardStep>=3){ _wizardSkip(); return; }
  _showSetupWizard(_wizardStep+1);
}

function _wizardSkip(){
  localStorage.setItem('orca_wizard_dismissed','1');
  _hideSetupWizard();
}

function _wizardCopyAddr(){
  if(!phantomKey) return;
  navigator.clipboard.writeText(phantomKey).then(()=>showLfToast('◎','Address copied!','pos')).catch(()=>{});
}

function showTradeWarn(msg){
  const el=document.getElementById('trade-warn');
  if(!el) return;
  el.textContent=msg;
  el.classList.add('show');
  setTimeout(()=>el.classList.remove('show'),8000);
}
function hideTradeWarn(){
  const el=document.getElementById('trade-warn');
  if(el) el.classList.remove('show');
}

function updateKeyIndicator(){
  const btn=document.getElementById('settings-btn');
  if(!btn) return;
  if(settingsHasKey){
    btn.textContent='⚙ Settings ✓';
    btn.style.color='var(--green)';
    btn.style.borderColor='var(--green)';
  } else {
    btn.textContent='⚙ Settings ⚠';
    btn.style.color='#ff9500';
    btn.style.borderColor='#ff9500';
  }
}
function _updateKeyStatus(){
  updateKeyIndicator();
  const saved=document.getElementById('s-key-saved');
  const inp=document.getElementById('s-privkey');
  const hint=document.getElementById('s-key-hint');
  if(saved) saved.style.display=settingsHasKey?'flex':'none';
  if(inp) inp.placeholder=settingsHasKey?'Enter new key to replace existing':'Paste private key (base58)';
  if(hint) hint.textContent='';
  _checkWelcomeBanner();
  _updateBotIdleBanner();
}
async function removeKey(){
  if(!confirm('Remove your saved trading key?')) return;
  const r=await fetch('/api/settings/key',{method:'DELETE'}).then(r=>r.json()).catch(()=>null);
  if(r?.ok){
    settingsHasKey=false;
    _updateKeyStatus();
    const msgEl=document.getElementById('s-msg');
    if(msgEl){ msgEl.className='s-msg ok'; msgEl.textContent='✓ Trading key removed.'; }
  }
}
// ── TOKEN BLACKLIST ──
async function avoidToken(mint, symbol){
  if(!mint) return;
  try{
    const r=await fetch('/api/blacklist/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mint,symbol})});
    const j=await r.json();
    if(j.ok){
      showLfToast('🚫','Token avoided — bot will skip '+(symbol||mint.slice(0,8)),'pos');
      const sModal=document.getElementById('settings-modal');
      if(sModal&&sModal.classList.contains('open')) loadBlacklist();
    }
  }catch(e){}
}

async function removeBlacklistToken(mint){
  try{
    await fetch('/api/blacklist/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mint})});
    loadBlacklist();
    showLfToast('✓','Token unbanned','pos');
  }catch(e){}
}

function openBlacklistModal(){
  document.getElementById('blacklist-modal').style.display='flex';
  _blMgrFetch();
}
function closeBlacklistModal(){
  document.getElementById('blacklist-modal').style.display='none';
}
async function _blMgrFetch(){
  const loading=document.getElementById('bl-mgr-loading');
  const body=document.getElementById('bl-mgr-body');
  const empty=document.getElementById('bl-mgr-empty');
  const tbody=document.getElementById('bl-mgr-tbody');
  if(loading){loading.style.display='block';loading.textContent='Loading…';loading.style.color='var(--muted)';}
  if(body) body.style.display='none';
  if(empty) empty.style.display='none';
  try{
    const r=await fetch('/api/blacklist').then(r=>r.json());
    const tokens=r.tokens||[];
    if(loading) loading.style.display='none';
    if(!tokens.length){if(empty) empty.style.display='block';return;}
    if(body) body.style.display='block';
    tbody.innerHTML=tokens.map(t=>`<tr>
      <td><span class="bl-mgr-sym">${_esc(t.symbol||t.mint.slice(0,8))}</span></td>
      <td style="font-size:9px;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${_esc(t.mint)}">${_esc(t.mint)}</td>
      <td>${_esc(t.blacklisted_at||'—')}</td>
      <td><span class="bl-status-label">🚫 Blocked</span></td>
      <td><button class="bl-unban-btn" onclick="event.stopPropagation();_blMgrUnban(this,'${_esc(t.mint)}')">Unban</button></td>
    </tr>`).join('');
  }catch(e){
    if(loading){loading.textContent='Failed to load.';loading.style.color='var(--red)';loading.style.display='block';}
  }
}
async function _blMgrUnban(btn,mint){
  if(btn) btn.disabled=true;
  await fetch('/api/blacklist/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mint})}).catch(()=>null);
  showLfToast('✓','Token unbanned','pos');
  _blMgrFetch();
}

async function loadBlacklist(){
  try{
    const r=await fetch('/api/blacklist');
    const j=await r.json();
    _renderBlacklist(j.tokens||[]);
  }catch(e){}
}

function _renderBlacklist(tokens){
  const wrap=document.getElementById('bl-list-wrap');
  if(!wrap) return;
  if(!tokens.length){
    wrap.innerHTML='<div style="font-size:10px;color:var(--muted);padding:6px 0">No avoided tokens — use 🚫 Avoid on any token</div>';
    return;
  }
  wrap.innerHTML='<div class="bl-list">'+tokens.map(t=>`
    <div class="bl-item">
      <span class="bl-item-sym">🚫 ${esc(t.symbol||t.mint.slice(0,8))}</span>
      <span class="bl-item-mint">${esc(t.mint)}</span>
      <button class="bl-remove-btn" onclick="removeBlacklistToken('${esc(t.mint)}')">✕ Remove</button>
    </div>`).join('')+'</div>';
}

// ── NAV MENU ──
let _logExpanded=false;
function _toggleLog(){
  _logExpanded=!_logExpanded;
  const el=document.getElementById('log-body');
  const btn=document.getElementById('log-toggle-btn');
  if(el) el.style.maxHeight=_logExpanded?'400px':'100px';
  if(btn) btn.textContent=_logExpanded?'▲ Collapse':'▼ Expand';
}

function _toggleNavMenu(){
  const d=document.getElementById('nav-menu-dropdown');
  if(d) d.classList.toggle('open');
}
function _closeNavMenu(){
  const d=document.getElementById('nav-menu-dropdown');
  if(d) d.classList.remove('open');
}
function _toggleAvatarMenu(){
  const m=document.getElementById('hdr-avatar-menu');
  if(m) m.classList.toggle('open');
}
function _closeAvatarMenu(){
  const m=document.getElementById('hdr-avatar-menu');
  if(m) m.classList.remove('open');
}
function _toggleSidebar(){
  const sb=document.getElementById('sidebar');
  const ov=document.getElementById('sidebar-overlay');
  if(!sb) return;
  const isOpen=sb.classList.contains('open');
  if(isOpen){
    sb.classList.remove('open');
    if(ov) ov.classList.remove('visible');
  } else {
    sb.classList.add('open');
    if(ov) ov.classList.add('visible');
  }
}
function _closeSidebar(){
  const sb=document.getElementById('sidebar');
  const ov=document.getElementById('sidebar-overlay');
  if(sb) sb.classList.remove('open');
  if(ov) ov.classList.remove('visible');
}
var _wltInterval=null;
async function loadWalletTokens(){
  const list=document.getElementById('wallet-token-list');
  if(!list) return;
  // show wallet address
  const wallet=phantomKey||currentWallet||'';
  const addrEl=document.getElementById('wlt-address');
  if(addrEl&&wallet) addrEl.textContent=wallet.slice(0,6)+'…'+wallet.slice(-4);
  list.innerHTML='<div style="padding:20px;color:#555;text-align:center">Loading...</div>';
  try{
    // fetch totals and tokens in parallel
    const [totRes, tokRes]=await Promise.all([
      fetch('/api/wallet/total').then(r=>r.json()).catch(()=>null),
      fetch('/api/wallet/tokens').then(r=>r.json()),
    ]);
    // update header from /api/wallet/total
    if(totRes&&totRes.ok){
      document.getElementById('wlt-total-usd').textContent='$'+Number(totRes.total_usd).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
      document.getElementById('wlt-total-sol').textContent='◎ '+Number(totRes.total_sol).toFixed(4);
    }
    if(!tokRes.ok) throw new Error(tokRes.msg||'Failed to load wallet');
    if(!tokRes.tokens||tokRes.tokens.length===0){
      list.innerHTML='<div style="padding:20px;color:#555;text-align:center">No tokens found</div>';
      return;
    }
    list.innerHTML=tokRes.tokens.map(function(t){
      const chg=Number(t.price_change_24h||0);
      const chgColor=chg>0?'#00e676':chg<0?'#ff1744':'#aaa';
      const chgStr=(chg>0?'+':'')+chg.toFixed(2)+'%';
      const valStr=t.value_usd>=0.01?'$'+Number(t.value_usd).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2}):'<$0.01';
      const amtStr=Number(t.amount>=0.0001?t.amount:0).toLocaleString('en-US',{maximumFractionDigits:4})+' '+(t.symbol||'');
      const logoHtml=t.logo_url
        ?`<img src="${t.logo_url}" onerror="this.style.display='none';this.nextSibling.style.display='flex'" style="width:36px;height:36px;border-radius:50%;object-fit:cover;flex-shrink:0" alt=""><div style="display:none;width:36px;height:36px;border-radius:50%;background:#2e2e2e;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff;flex-shrink:0">${(t.symbol||'?')[0].toUpperCase()}</div>`
        :`<div style="width:36px;height:36px;border-radius:50%;background:#2e2e2e;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff;flex-shrink:0">${(t.symbol||'?')[0].toUpperCase()}</div>`;
      return `<div onclick="window.openTokenPanel&&window.openTokenPanel('${t.mint}')" style="display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid #2e2e2e;cursor:pointer;transition:background .12s" onmouseover="this.style.background='#1c1c1c'" onmouseout="this.style.background=\'\'">${logoHtml}<div style="flex:1;min-width:0"><div style="font-size:13px;font-weight:700;color:#fff">${t.symbol||'?'}</div><div style="font-size:11px;color:#aaa;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${t.name||''}</div><div style="font-size:11px;color:#aaa;margin-top:1px">${amtStr}</div></div><div style="text-align:right;flex-shrink:0"><div style="font-size:13px;font-weight:700;color:#fff">${valStr}</div><div style="font-size:11px;color:${chgColor};margin-top:2px">${chgStr}</div></div></div>`;
    }).join('');
  }catch(e){
    list.innerHTML='<div style="padding:20px;color:#ff1744;text-align:center">'+e.message+'</div>';
  }
}
function _startWalletRefresh(){
  _stopWalletRefresh();
  _wltInterval=setInterval(loadWalletTokens,30000);
}
function _stopWalletRefresh(){
  if(_wltInterval){clearInterval(_wltInterval);_wltInterval=null;}
}
function _sbSetActive(id){
  document.querySelectorAll('#sidebar .sb-nav-item').forEach(el=>el.classList.remove('active'));
  const el=document.getElementById(id);
  if(el) el.classList.add('active');
  if(window.innerWidth<=768) _closeSidebar();
}
// ── bot status sidebar card ───────────────────────────────
var _botRunning=false
var _botPollTimer=null

async function _botFetchStatus(){
  if(!phantomKey) return;
  try{
    var r=await fetch('/api/bot/status')
    var d=await r.json()
    if(!d.ok) return
    _botRunning=!!d.running
    // dot + label
    var dot=document.getElementById('bot-dot')
    var lbl=document.getElementById('bot-label')
    if(dot) dot.style.background=_botRunning?'#3ad29b':'#f7b955'
    if(lbl) lbl.textContent=_botRunning?'Bot running':'Bot is idle'
    // stats line
    var statsEl=document.getElementById('bot-stats')
    if(statsEl){
      var sol=parseFloat(d.sol_ready||0).toFixed(2)
      var open=parseInt(d.open_positions||0)
      var wr=parseFloat(d.win_rate||0).toFixed(0)
      statsEl.textContent=sol+' SOL ready · '+open+'/5 open · '+wr+'% win rate'
    }
    // button state
    var btn=document.getElementById('bot-toggle-btn')
    if(btn){
      if(_botRunning){
        btn.textContent='⏹ Stop Trading'
        btn.classList.add('running')
      } else {
        btn.textContent='▶ Start Trading'
        btn.classList.remove('running')
      }
    }
  }catch(e){}
}

async function _botToggle(){
  var btn=document.getElementById('bot-toggle-btn')
  if(btn){btn.disabled=true;btn.textContent=_botRunning?'Stopping…':'Starting…'}
  try{
    var url=_botRunning?'/api/bot/stop':'/api/bot/start'
    var r=await fetch(url,{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:'{}'})
    var d=await r.json()
    if(d.ok||d.success){
      await _botFetchStatus()
    } else {
      if(btn){btn.disabled=false;btn.textContent=_botRunning?'⏹ Stop Trading':'▶ Start Trading'}
      alert(d.msg||'Failed')
    }
  }catch(e){
    if(btn){btn.disabled=false;btn.textContent=_botRunning?'⏹ Stop Trading':'▶ Start Trading'}
  }
  if(btn) btn.disabled=false
}

// Initial fetch + 30s poll
_botFetchStatus()
_botPollTimer=setInterval(_botFetchStatus,30000)

// ── bot PNL panel ──────────────────────────────────────
async function _botLoadPositions(){
  if(!phantomKey) return;
  var listEl=document.getElementById('bot-pnl-list')
  var totalEl=document.getElementById('bot-pnl-total')
  try{
    var d=await fetch('/api/bot/positions').then(function(r){return r.json()})
    if(!d.ok||!d.positions){return}
    var pos=d.positions
    var tot=parseFloat(d.total_pnl_sol||0)
    if(totalEl){
      totalEl.textContent=(tot>=0?'+':'')+tot.toFixed(4)+' SOL'
      totalEl.style.color=tot>0?'#3ad29b':tot<0?'#f76b62':'#565d68'
    }
    if(!listEl) return
    if(!pos.length){listEl.innerHTML='<div class="sb-pnl-empty">No open positions</div>';return}
    var html=''
    pos.forEach(function(p){
      var initials=(p.symbol||'?').replace(/[^A-Za-z0-9]/g,'').slice(0,3).toUpperCase()
      var pct=parseFloat(p.pnl_pct||0)
      var sol=parseFloat(p.pnl_sol||0)
      var col=pct>0?'#3ad29b':pct<0?'#f76b62':'#565d68'
      var pctStr=(pct>=0?'+':'')+pct.toFixed(2)+'%'
      var solStr=(sol>=0?'+':'')+sol.toFixed(4)+' SOL'
      var tpPct=5
      var statusStr='TP +'+tpPct+'% · open'
      html+='<div class="sb-pnl-pos">'
        +'<div class="sb-pnl-circ">'+initials+'</div>'
        +'<div class="sb-pnl-mid">'
          +'<div class="sb-pnl-sym">$'+p.symbol+'</div>'
          +'<div class="sb-pnl-sub">'+statusStr+'</div>'
        +'</div>'
        +'<div class="sb-pnl-right">'
          +'<div class="sb-pnl-pct" style="color:'+col+'">'+pctStr+'</div>'
          +'<div class="sb-pnl-sol" style="color:'+col+'">'+solStr+'</div>'
        +'</div>'
        +'</div>'
    })
    listEl.innerHTML=html
  }catch(e){}
}
_botLoadPositions()
setInterval(_botLoadPositions,10000)

function _sbNav(section){
  if(section!=='wallet') _stopWalletRefresh();
  if(section==='dashboard'){
    if(_dmOpen) closeMessagesView();
    else if(_tradersView) closeTradersView();
    else if(_gcOpen) closeCommunityView();
    // always ensure main content is visible (guards against edge-case blanks)
    const _mc=document.getElementById('main-content');
    if(_mc) _mc.style.display='';
    const _dm=document.getElementById('dash-main');
    if(_dm) _dm.style.display='';
    _sbSetActive('sbn-dashboard');
    loadHomeFeed();
    const _rrD=document.getElementById('right-rail');if(_rrD){_rrD.style.display='flex';loadRightRail();}loadInlineSidebar();
  } else if(section==='market'){
    if(_dmOpen) closeMessagesView();
    if(_tradersView) closeTradersView();
    const _mc=document.getElementById('main-content');
    if(_mc) _mc.style.display='';
    const _dm=document.getElementById('dash-main');
    if(_dm) _dm.style.display='';
    _sbSetActive('sbn-market');
    const mp=document.getElementById('market-panel');
    if(mp) setTimeout(()=>mp.scrollIntoView({behavior:'smooth',block:'start'}),50);
  } else if(section==='wallet'){
    if(_dmOpen) closeMessagesView();
    if(_tradersView) closeTradersView();
    if(_gcOpen) closeCommunityView();
    // hide main content and all dash sections
    const _mc=document.getElementById('main-content');
    if(_mc) _mc.style.display='none';
    document.querySelectorAll('.dash-section').forEach(function(s){ s.style.display='none'; });
    const wlt=document.getElementById('dash-wallet');
    if(wlt){
      wlt.style.display='block';
      wlt.scrollTop=0;
    }
    _sbSetActive('sbn-wallet');
    loadWalletTokens();
    _startWalletRefresh();
  } else if(section==='traders'){
    openTradersView();
  } else if(section==='messages'){
    openMessagesView();
  } else if(section==='community'){
    openCommunityView();
  } else if(section==='leaderboard'){
    window.location.href='/leaderboard';
  } else if(section==='notifications'){
    if(_dmOpen) closeMessagesView();
    if(_tradersView) closeTradersView();
    if(_gcOpen) closeCommunityView();
    const _mc=document.getElementById('main-content');
    if(_mc) _mc.style.display='';
    document.querySelectorAll('.dash-section').forEach(function(s){ s.style.display='none'; });
    const _notif=document.getElementById('dash-notifications');
    if(_notif) _notif.style.display='block';
    _sbSetActive('sbn-notifications');
  }
}

/* unified nav alias — maps external section names to _sbNav keys */
function showSection(name){
  var map={'live-market':'market','home':'dashboard'};
  _sbNav(map[name]||name);
}

function _wltSend(){ openWithdrawModal(); }
function _wltReceive(){ openDepositModal(); }
// ── SWAP MODAL ──────────────────────────────────────────────────────────────
var _swapTokens = [];   // [{symbol,name,mint,amount,value_usd,logo_url,price_usd}]
var _swapFrom   = {symbol:'SOL',  name:'Solana',       mint:'So11111111111111111111111111111111111111112', amount:0, value_usd:0, price_usd:0, logo_url:''};
var _swapTo     = {symbol:'USDC', name:'USD Coin',      mint:'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', amount:0, value_usd:0, price_usd:0, logo_url:''};
var _swapPickerSide = 'pay'; // 'pay' | 'recv'

var _QUICK_PICKS = ['SOL','USDC','WIF','POP'];
var _TOK_COLORS  = {SOL:'#9945ff',USDC:'#2775ca',WIF:'#f7b955',POP:'#f76b62',DEFAULT:'#3ad29b'};

function _tokColor(sym){ return _TOK_COLORS[sym] || _TOK_COLORS.DEFAULT; }
function _tokAvatar(tok, size){
  size = size||38;
  if(tok.logo_url){
    return '<img src="'+tok.logo_url+'" style="width:'+size+'px;height:'+size+'px;border-radius:50%;object-fit:cover;flex-shrink:0" onerror="this.style.display=\'none\'" alt="">';
  }
  return '<div class="sp-tok-chip" style="width:'+size+'px;height:'+size+'px;background:'+_tokColor(tok.symbol)+'">'+((tok.symbol||'?')[0].toUpperCase())+'</div>';
}

function _wltSwap(){
  document.getElementById('swap-overlay').style.display='flex';
  _swapRenderForm();
  if(!_swapTokens.length) _swapLoadTokens();
}
function _swapClose(){
  document.getElementById('swap-overlay').style.display='none';
  document.getElementById('swap-form-state').style.display='';
  document.getElementById('swap-picker-state').style.display='none';
}

async function _swapLoadTokens(){
  try{
    var r = await fetch('/api/wallet/tokens');
    var d = await r.json();
    if(d.ok && d.tokens && d.tokens.length){
      _swapTokens = d.tokens.map(function(t){
        return {
          symbol:    t.symbol||'?',
          name:      t.name||t.symbol||'',
          mint:      t.mint||'',
          amount:    Number(t.amount||0),
          value_usd: Number(t.value_usd||0),
          price_usd: t.amount > 0 ? Number(t.value_usd||0)/Number(t.amount) : 0,
          logo_url:  t.logo_url||''
        };
      });
      // update balances shown on form panels
      var fromTok = _swapTokens.find(function(t){ return t.symbol === _swapFrom.symbol; });
      if(fromTok){ _swapFrom.amount=fromTok.amount; _swapFrom.price_usd=fromTok.price_usd; _swapFrom.logo_url=fromTok.logo_url; }
      var toTok = _swapTokens.find(function(t){ return t.symbol === _swapTo.symbol; });
      if(toTok){ _swapTo.amount=toTok.amount; _swapTo.price_usd=toTok.price_usd; _swapTo.logo_url=toTok.logo_url; }
      _swapRenderForm();
    }
  }catch(e){}
}

function _swapRenderForm(){
  var el = function(id){ return document.getElementById(id); };
  el('swap-pay-tok-lbl').textContent  = _swapFrom.symbol;
  el('swap-recv-tok-lbl').textContent = _swapTo.symbol;
  el('swap-pay-bal').textContent  = _swapFrom.amount > 0 ? 'Balance: '+_swapFrom.amount.toFixed(4)+' '+_swapFrom.symbol : '';
  el('swap-recv-bal').textContent = _swapTo.amount   > 0 ? 'Balance: '+_swapTo.amount.toFixed(4)+' '+_swapTo.symbol     : '';
  _swapUpdateRate();
}

function _swapUpdateRate(){
  var amt  = parseFloat(document.getElementById('swap-pay-amt').value||'0')||0;
  var payUsd  = amt * (_swapFrom.price_usd||0);
  var recvAmt = (_swapTo.price_usd > 0 && _swapFrom.price_usd > 0) ? (amt * _swapFrom.price_usd / _swapTo.price_usd) : 0;
  document.getElementById('swap-pay-usd').textContent  = '≈ $'+payUsd.toFixed(2);
  document.getElementById('swap-recv-amt').textContent = recvAmt > 0 ? recvAmt.toFixed(6) : '0';
  document.getElementById('swap-recv-usd').textContent = '≈ $'+(recvAmt*(_swapTo.price_usd||0)).toFixed(2);
  if(amt > 0 && _swapFrom.price_usd > 0 && _swapTo.price_usd > 0){
    document.getElementById('swap-rate').textContent =
      '1 '+_swapFrom.symbol+' ≈ '+((_swapFrom.price_usd/_swapTo.price_usd).toFixed(4))+' '+_swapTo.symbol+
      ' · Slippage 0.5% · Fee 0.25%';
  } else {
    document.getElementById('swap-rate').textContent = 'Enter an amount to see rate';
  }
}

function _swapSwitch(){
  var tmp = _swapFrom; _swapFrom = _swapTo; _swapTo = tmp;
  document.getElementById('swap-pay-amt').value = '';
  _swapRenderForm();
}

function _swapReview(){
  var amt = parseFloat(document.getElementById('swap-pay-amt').value||'0')||0;
  if(!amt){ document.getElementById('swap-pay-amt').focus(); return; }
  var url = 'https://jup.ag/swap/'+_swapFrom.symbol+'-'+_swapTo.symbol;
  window.open(url,'_blank','noopener');
}

function _swapOpenPicker(side){
  _swapPickerSide = side;
  document.getElementById('swap-form-state').style.display   = 'none';
  document.getElementById('swap-picker-state').style.display = '';
  document.getElementById('swap-hdr-title').textContent = 'Select token';
  document.getElementById('sp-search').value = '';
  _swapRenderPicker('');
}
function _swapClosePicker(){
  document.getElementById('swap-form-state').style.display   = '';
  document.getElementById('swap-picker-state').style.display = 'none';
  document.getElementById('swap-hdr-title').textContent = 'Swap';
}
function _swapPickerSearch(val){
  _swapRenderPicker(val.trim().toLowerCase());
}

function _swapRenderPicker(query){
  // Quick pick chips
  var selectedSym = (_swapPickerSide === 'pay' ? _swapFrom : _swapTo).symbol;
  var qc = document.getElementById('sp-quick-chips');
  qc.innerHTML = _QUICK_PICKS.map(function(sym){
    var tok = _swapTokens.find(function(t){ return t.symbol===sym; }) || {symbol:sym,name:sym,logo_url:''};
    var active = sym === selectedSym ? ' active' : '';
    return '<button class="sp-quick-chip'+active+'" onclick="_swapSelectToken(\''+sym+'\')">'+
      '<div style="width:20px;height:20px;border-radius:50%;background:'+_tokColor(sym)+';display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;color:#0a0b0e">'+sym[0]+'</div>'+
      sym+'</button>';
  }).join('');

  // Token list
  var tokens = _swapTokens.length ? _swapTokens : [_swapFrom, _swapTo];
  if(query){
    tokens = tokens.filter(function(t){
      return t.symbol.toLowerCase().includes(query) ||
             t.name.toLowerCase().includes(query)   ||
             t.mint.toLowerCase().includes(query);
    });
  }
  var list = document.getElementById('sp-token-list');
  if(!tokens.length){
    list.innerHTML = '<div style="padding:20px;text-align:center;color:var(--muted);font-size:13px">No tokens found</div>';
    return;
  }
  list.innerHTML = tokens.map(function(tok){
    var active = tok.symbol === selectedSym ? ' active' : '';
    var balStr = tok.amount > 0 ? tok.amount.toFixed(4)+' '+tok.symbol : '0 '+tok.symbol;
    var usdStr = tok.value_usd > 0 ? '$'+tok.value_usd.toFixed(2) : '';
    var chip = tok.logo_url
      ? '<img src="'+tok.logo_url+'" class="sp-tok-chip" style="object-fit:cover" onerror="this.style.display=\'none\'" alt="">'
      : '<div class="sp-tok-chip" style="background:'+_tokColor(tok.symbol)+'">'+((tok.symbol||'?')[0].toUpperCase())+'</div>';
    return '<div class="sp-token-row'+active+'" onclick="_swapSelectToken(\''+tok.symbol.replace(/'/g,"\\'")+'\')">'
      +chip
      +'<div class="sp-tok-info"><div class="sp-tok-sym">'+tok.symbol+'</div><div class="sp-tok-name">'+tok.name+'</div></div>'
      +'<div class="sp-tok-right"><div class="sp-tok-bal">'+balStr+'</div>'+(usdStr?'<div class="sp-tok-usd">'+usdStr+'</div>':'')+'</div>'
      +'</div>';
  }).join('');
}

function _swapSelectToken(sym){
  var tok = _swapTokens.find(function(t){ return t.symbol===sym; })
         || {symbol:sym, name:sym, mint:'', amount:0, value_usd:0, price_usd:0, logo_url:''};
  if(_swapPickerSide === 'pay'){
    if(sym === _swapTo.symbol){ var tmp=_swapFrom; _swapFrom=_swapTo; _swapTo=tmp; }
    else { _swapFrom = tok; }
  } else {
    if(sym === _swapFrom.symbol){ var tmp=_swapFrom; _swapFrom=_swapTo; _swapTo=tmp; }
    else { _swapTo = tok; }
  }
  document.getElementById('swap-pay-amt').value = '';
  _swapClosePicker();
  _swapRenderForm();
}
function _sbUpdateUser(profileData){
  const nameEl  =document.getElementById('sb-user-name');
  const handleEl=document.getElementById('sb-handle');
  const dotEl   =document.getElementById('sb-online-dot');
  const iniEl   =document.getElementById('sb-avatar-ini');
  const imgEl   =document.getElementById('sb-avatar-img');
  if(!profileData){ if(nameEl) nameEl.textContent='You'; return; }
  const uname=profileData.username||profileData.display_name||'';
  if(nameEl)   nameEl.textContent=uname||'You';
  if(handleEl) handleEl.textContent=uname?('@'+uname):(phantomKey?('@'+(phantomKey.slice(0,4)+'…'+phantomKey.slice(-4))):'@—');
  if(dotEl) dotEl.style.display='';
  if(profileData.avatar_url && imgEl){
    imgEl.src=profileData.avatar_url;
    imgEl.style.display='';
  } else if(iniEl){
    iniEl.textContent=((uname||phantomKey||'?')[0]||'?').toUpperCase();
  }
  var _ca=document.getElementById('feed-composer-avatar');
  if(_ca){
    _ca.innerHTML='';
    _ca.removeAttribute('style');
    if(profileData.avatar_url){
      var _ci=document.createElement('img');
      _ci.src=profileData.avatar_url;
      _ci.style.cssText='position:absolute;inset:0;width:100%;height:100%;object-fit:cover;border-radius:50%';
      _ci.onerror=function(){this.remove();};
      _ca.appendChild(_ci);
    } else {
      var _ini=((uname||phantomKey||'?')[0]||'?').toUpperCase();
      _ca.textContent=_ini;
      _ca.style.cssText='width:44px;height:44px;border-radius:50%;background:#f7b955;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:700;color:#0a0b0e;flex-shrink:0';
    }
  }
  const pnlEl=document.getElementById('sb-pnl');
  if(pnlEl && profileData.today_pnl!=null){
    const v=profileData.today_pnl;
    pnlEl.textContent=(v>=0?'+':'')+v.toFixed(4)+' SOL today';
    pnlEl.className='sb-pnl '+(v>0?'pos':v<0?'neg':'neu');
  }
}
document.addEventListener('click',function(e){
  const btn=document.getElementById('nav-menu-btn');
  const dd=document.getElementById('nav-menu-dropdown');
  if(dd&&dd.classList.contains('open')&&!dd.contains(e.target)&&(!btn||!btn.contains(e.target)))
    dd.classList.remove('open');
  const avatarWrap=document.getElementById('wallet-pill');
  const avatarMenu=document.getElementById('hdr-avatar-menu');
  if(avatarMenu&&avatarMenu.classList.contains('open')&&avatarWrap&&!avatarWrap.contains(e.target))
    avatarMenu.classList.remove('open');
  // Close DM search dropdown when clicking outside it
  const wrap=document.getElementById('dm-search-wrap');
  const drop=document.getElementById('dm-search-results');
  if(drop&&drop.style.display!=='none'&&wrap&&!wrap.contains(e.target)){
    drop.style.display='none';
  }
});

async function openSettings(){
  const modal=document.getElementById('settings-modal');
  modal.classList.add('open');
  const msgEl=document.getElementById('s-msg');
  msgEl.className='s-msg'; msgEl.textContent='';
  const saveBtn=document.getElementById('s-save-btn');
  if(phantomKey){
    const short=phantomKey.slice(0,4)+'...'+phantomKey.slice(-4);
    document.getElementById('s-user-label').textContent='Settings for '+(_displayName||short);
    saveBtn.disabled=false; saveBtn.style.opacity='1';
    const r=await fetch('/api/settings').then(r=>r.json()).catch(()=>null);
    if(r?.ok){
      document.getElementById('s-minusdc').value=r.min_trade_size??1;
      document.getElementById('s-maxusdc').value=r.max_trade_size||10;
      document.getElementById('s-losslimit').value=r.daily_loss_limit||50;
      settingsHasKey=r.has_trading_key||false;
      _updateKeyStatus();
      if(r.avatar_url!==undefined){ _avatarUrl=r.avatar_url||null; _updateNavPill(); }
    }
    loadBlacklist();
  } else {
    document.getElementById('s-user-label').textContent='Connect a wallet to save settings';
    saveBtn.disabled=true; saveBtn.style.opacity='.45';
    settingsHasKey=false;
    _updateKeyStatus();
  }
  _updateFaceIdStatus();
}

function closeSettings(){
  document.getElementById('settings-modal').classList.remove('open');
}

async function _setPassword(){
  var inp=document.getElementById('s-pwd-input');
  var msg=document.getElementById('s-pwd-msg');
  var btn=document.getElementById('s-pwd-btn');
  if(msg){ msg.className='s-msg'; msg.textContent=''; }
  var password=(inp&&inp.value)||'';
  if(password.length<8){
    if(msg){ msg.className='s-msg err'; msg.textContent='Password must be at least 8 characters.'; }
    return;
  }
  if(btn){ btn.disabled=true; btn.textContent='Saving…'; }
  try{
    var r=await fetch('/api/set_password',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:password})
    }).then(res=>res.json()).catch(()=>null);
    if(r&&r.success){
      if(msg){ msg.className='s-msg ok'; msg.textContent='✓ Password saved — you can now login on mobile without Phantom.'; }
      if(inp) inp.value='';
    } else {
      if(msg){ msg.className='s-msg err'; msg.textContent=(r&&r.error)||'Failed to save password.'; }
    }
  }catch(e){
    if(msg){ msg.className='s-msg err'; msg.textContent='Failed to save password.'; }
  }finally{
    if(btn){ btn.disabled=false; btn.textContent='Set Password'; }
  }
}

async function saveUsername(){
  if(!phantomKey){alert('Connect a wallet first.');return;}
  const val=document.getElementById('s-username').value.trim();
  const msgEl=document.getElementById('s-username-msg');
  const btn=document.getElementById('s-username-btn');
  msgEl.className='s-msg'; msgEl.textContent='';
  btn.textContent='Saving...'; btn.disabled=true;
  const r=await fetch('/api/username',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:val})
  }).then(r=>r.json()).catch(()=>null);
  btn.textContent='Save'; btn.disabled=false;
  if(r?.ok){
    msgEl.className='s-msg ok';
    msgEl.textContent='✓ Username saved!';
    _displayName=r.username||null;
    _updateNavPill();
  } else {
    msgEl.className='s-msg err';
    msgEl.textContent='✗ '+(r?.msg||'Save failed');
  }
}

function _onAvatarFile(input){
  const file=input.files[0];
  if(!file) return;
  const msgEl=document.getElementById('s-avatar-msg');
  msgEl.className='s-msg'; msgEl.textContent='';
  if(file.size>2*1024*1024){
    msgEl.className='s-msg err'; msgEl.textContent='✗ Image too large (max 2 MB)'; input.value=''; return;
  }
  const reader=new FileReader();
  reader.onload=function(e){
    _pendingAvatarData=e.target.result;
    _previewAvatar(_pendingAvatarData);
    saveAvatar();
  };
  reader.readAsDataURL(file);
}

async function saveAvatar(){
  if(!phantomKey){alert('Connect a wallet first.');return;}
  if(!_pendingAvatarData){return;}
  const msgEl=document.getElementById('s-avatar-msg');
  const btn=document.getElementById('s-avatar-btn');
  msgEl.className='s-msg'; msgEl.textContent='';
  btn.textContent='Uploading...'; btn.disabled=true;
  const r=await fetch('/api/avatar',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({avatar_data:_pendingAvatarData})
  }).then(r=>r.json()).catch(()=>null);
  btn.textContent='📷 Choose Photo'; btn.disabled=false;
  if(r?.ok){
    msgEl.className='s-msg ok';
    msgEl.textContent='✓ Profile picture saved!';
    _avatarUrl=r.avatar_url||null;
    _pendingAvatarData=null;
    _updateNavPill();
  } else {
    msgEl.className='s-msg err';
    msgEl.textContent='✗ '+(r?.msg||'Save failed');
  }
}

function togglePrivVis(){
  const inp=document.getElementById('s-privkey');
  const btn=document.getElementById('s-vis-btn');
  inp.type=inp.type==='password'?'text':'password';
  btn.textContent=inp.type==='password'?'👁':'🙈';
}

async function saveSettings(){
  if(!phantomKey){alert('Connect a wallet first.');return;}
  const minUsdc  =parseFloat(document.getElementById('s-minusdc').value)||0.01;
  const maxUsdc  =parseFloat(document.getElementById('s-maxusdc').value)||0.5;
  const lossLimit=parseFloat(document.getElementById('s-losslimit').value)||10;
  const msgEl    =document.getElementById('s-msg');
  const saveBtn  =document.getElementById('s-save-btn');

  saveBtn.textContent='SAVING...'; saveBtn.disabled=true;
  const r=await fetch('/api/settings',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({min_trade_size:minUsdc,max_trade_size:maxUsdc,daily_loss_limit:lossLimit})
  }).then(r=>r.json()).catch(()=>null);
  saveBtn.textContent='SAVE SETTINGS'; saveBtn.disabled=false;

  if(r?.ok){
    msgEl.className='s-msg ok';
    msgEl.textContent='✓ Bot settings updated.';
  } else {
    msgEl.className='s-msg err';
    msgEl.textContent='✗ '+(r?.msg||'Save failed. Check server logs.');
  }
}

// ── TRADERS VIEW ──
let _tradersView=false, _tvCountdownTimer=null, _tvCountdownVal=15, _tvFollowed=new Set(), _tvFeedCache=[], _tvFeedFilter='all';

function _tvStartCountdown(){
  if(_tvCountdownTimer) clearInterval(_tvCountdownTimer);
  _tvCountdownVal=15;
  const el=document.getElementById('tv-countdown');
  if(el) el.textContent='↻ '+_tvCountdownVal+'s';
  _tvCountdownTimer=setInterval(()=>{
    _tvCountdownVal=Math.max(0,_tvCountdownVal-1);
    if(el) el.textContent=_tvCountdownVal>0?'↻ '+_tvCountdownVal+'s':'refreshing…';
    if(_tvCountdownVal===0) _tvCountdownVal=15;
  },1000);
}

function _tvTimeAgo(ts){
  if(!ts) return '';
  const sec=Math.floor(Date.now()/1000)-ts;
  if(sec<60)   return sec+'s ago';
  if(sec<3600) return Math.floor(sec/60)+'m ago';
  if(sec<86400)return Math.floor(sec/3600)+'h ago';
  return Math.floor(sec/86400)+'d ago';
}

function _tvTimeAgoStr(isoStr){
  if(!isoStr) return '';
  try{ var _fixed = isoStr.endsWith('Z') ? isoStr : isoStr + 'Z'; return _tvTimeAgo(Math.floor(new Date(_fixed).getTime()/1000)); }catch(e){ return ''; }
}

const _TV_AVATAR_COLORS=['#1a5276','#0e4d3a','#2d3561','#4a235a','#5b2333','#1b4332','#154360','#3d1a00'];
function _tvAvatarColor(name){
  let h=0; for(let i=0;i<(name||'').length;i++) h=(h*31+name.charCodeAt(i))>>>0;
  return _TV_AVATAR_COLORS[h%_TV_AVATAR_COLORS.length];
}

function _tvAvatarHtml(e){
  const name=e.username||'?';
  const ini=esc(name[0].toUpperCase());
  const bg=_tvAvatarColor(name);
  if(e.avatar_url){
    return `<div class="tv-avatar" style="background:${bg}"><img src="${e.avatar_url}" alt="" onerror="this.style.display='none'">${ini}</div>`;
  }
  return `<div class="tv-avatar" style="background:${bg}">${ini}</div>`;
}

async function _tvFollowToggle(btn, key, userId, username){
  if(checkGuest()) return;
  const wasFollowing=_tvFollowed.has(key);
  if(wasFollowing){
    _tvFollowed.delete(key);
    btn.classList.remove('followed','is-following');
    btn.textContent='Follow';
  } else {
    _tvFollowed.add(key);
    btn.classList.add('followed','is-following');
    btn.textContent='✓ Following';
  }
  if(username) showLfToast(wasFollowing?'👋':'👥', wasFollowing?`Unfollowed ${username}`:`Now following ${username}`, wasFollowing?'neg':'pos');
  if(userId){
    const r=await fetch('/api/follow/'+userId,{method:'POST',headers:{'Content-Type':'application/json'}}).then(r=>r.json()).catch(()=>null);
    if(r?.ok){
      if(r.following){_tvFollowed.add(key);btn.classList.add('followed','is-following');btn.textContent='✓ Following';}
      else{_tvFollowed.delete(key);btn.classList.remove('followed','is-following');btn.textContent='Follow';}
    }
  }
}


function _tvTopAvatar(e){
  const bg=_lbAvatarColor(e.username||e.wallet||'?');
  const ini=(e.username||e.wallet||'?')[0].toUpperCase();
  const img=e.avatar_url?`<img src="${esc(e.avatar_url)}" alt="" loading="lazy" onerror="this.style.display='none'">`:'';
  return `<div class="tv-top-avtr" style="background:${bg}">${img}<span style="${e.avatar_url?'opacity:0;position:absolute':''}">  ${ini}</span></div>`;
}

function renderTopTraders(entries){
  const el=document.getElementById('tv-top-traders'); if(!el) return;
  if(!entries||!entries.length){el.innerHTML='<div class="tv-empty" style="padding:16px 0">No trades yet today.</div>';return;}
  const top=entries.slice(0,5);
  const rankColors=['#FFD700','#C0C0C0','#CD7F32','var(--dim)','var(--dim)'];
  el.innerHTML=top.map((e,i)=>{
    const pnl=e.total_pnl||0;
    const pos=pnl>=0;
    const pnlStr=(pos?'+':'')+pnl.toFixed(4)+' SOL';
    const pnlCls=pos?'tv-top-pnl-pos':'tv-top-pnl-neg';
    const uid=e.user_id||0;
    return `<div class="tv-top-row" onclick="openProfileCard(${uid})">
      <span class="tv-top-rank" style="color:${rankColors[i]}">${i+1}</span>
      ${_tvTopAvatar(e)}
      <span class="tv-top-name">${esc(e.username||e.wallet||'Trader')}</span>
      <span class="${pnlCls}">${esc(pnlStr)}</span>
    </div>`;
  }).join('');
}

function renderPlatformStats(s){
  const tv=document.getElementById('tv-pstat-trades');
  const pv=document.getElementById('tv-pstat-pnl');
  const av=document.getElementById('tv-pstat-active');
  if(tv) tv.textContent=s.trades_today??'—';
  if(pv){
    const n=s.net_pnl_today??null;
    if(n!=null){
      const pos=n>=0;
      pv.textContent=(pos?'+':'')+Number(n).toFixed(4);
      pv.style.color=pos?'var(--green)':'var(--red)';
    } else {pv.textContent='—';}
  }
  if(av) av.textContent=s.active_traders??'—';
  const badge=document.getElementById('tv-active-badge');
  if(badge&&s.active_traders!=null){
    badge.innerHTML=`<b>${s.active_traders}</b> active`;
    badge.style.display='';
  }
}

async function fetchTradersFeed(){
  if(!_tradersView) return;
  const [lb, stats]=await Promise.all([
    fetch('/api/leaderboard').then(r=>r.json()).catch(()=>null),
    fetch('/api/platform/stats').then(r=>r.json()).catch(()=>null),
  ]);
  if(Array.isArray(lb)) renderTopTraders(lb);
  if(stats&&stats.ok) renderPlatformStats(stats);
  _tvStartCountdown();
}

function _navLogoClick(){
  if(_dmOpen){ closeMessagesView(); return; }
  if(_gcOpen){ closeCommunityView(); return; }
  if(_tradersView){
    if(_tvProfileOpen){ closeTraderProfile(); return; }
    closeTradersView(); return;
  }
  window.scrollTo({top:0,behavior:'smooth'});
}

function _fadeIn(el){
  if(!el) return;
  el.classList.remove('fade-in');
  void el.offsetWidth;
  el.classList.add('fade-in');
}

function openTradersView(){
  if(_tradersView) return;
  _tradersView=true;
  document.getElementById('dash-main').style.display='none';
  const _rrT=document.getElementById('right-rail');if(_rrT) _rrT.style.display='none';
  if(!document.getElementById('dash-admin').style.display||document.getElementById('dash-admin').style.display!=='none'){
    document.getElementById('dash-admin').style.display='none';
  }
  const _dtEl=document.getElementById('dash-traders');
  _dtEl.style.display='';
  _fadeIn(_dtEl);
  _sbSetActive('sbn-traders');
  const btn=document.getElementById('traders-btn');
  if(btn){btn.style.borderColor='var(--green)';btn.style.color='var(--green)';btn.style.background='rgba(0,0,0,.08)';}
  if(_myProfileData) _updateTvMeCard();
  fetchTradersFeed();
}

function closeTradersView(){
  if(!_tradersView) return;
  _tradersView=false;
  // If a profile is open, reset it so re-opening traders view shows the feed
  if(typeof _tvProfileOpen!=='undefined'&&_tvProfileOpen){
    _tvProfileOpen=false;
    _tpcCurrentFullWallet='';
    const pv=document.getElementById('tv-profile-view');
    if(pv) pv.style.display='none';
    const tl=document.getElementById('tv-layout');
    if(tl) tl.style.display='';
  }
  document.getElementById('dash-traders').style.display='none';
  const _dmEl=document.getElementById('dash-main');
  _dmEl.style.display='';
  _fadeIn(_dmEl);
  const _rrC=document.getElementById('right-rail');if(_rrC){_rrC.style.display='flex';loadRightRail();}loadInlineSidebar();
  _sbSetActive('sbn-dashboard');
  if(_tvCountdownTimer){clearInterval(_tvCountdownTimer);_tvCountdownTimer=null;}
  const el=document.getElementById('tv-countdown'); if(el) el.textContent='';
  const btn=document.getElementById('traders-btn');
  if(btn){btn.style.borderColor='';btn.style.color='';btn.style.background='';}
  const meCard=document.getElementById('tv-me-card');
  if(meCard) meCard.style.display='none';
}

// ── TRADER PROFILE CARD ──
function _tvFormatHold(secs){
  if(!secs||secs<=0) return '—';
  const h=Math.floor(secs/3600), m=Math.floor((secs%3600)/60);
  if(h>0) return h+'h'+(m>0?' '+m+'m':'');
  if(m>0) return m+'m';
  return Math.round(secs)+'s';
}

function _tvFormatJoined(iso){
  if(!iso) return '—';
  try{ return new Date(iso.slice(0,10)).toLocaleDateString('en-US',{month:'short',year:'numeric',timeZone:'UTC'}); }
  catch(e){ return '—'; }
}

function closeProfileCard(){
  document.getElementById('tv-profile-overlay').classList.add('hidden');
  _tpcCurrentFullWallet='';
}

function _tpcAvatarHtml(p, botActive=false){
  const name=p.username||'?';
  const ini=esc(name[0].toUpperCase());
  const bg=_tvAvatarColor(name);
  const cls='tvp-avatar'+(botActive?' tvp-avatar-active':'');
  if(p.avatar_url){
    return `<div class="${cls}" style="background:${bg}"><img src="${p.avatar_url}" alt="" onerror="this.style.display='none'">${ini}</div>`;
  }
  return `<div class="${cls}" style="background:${bg}">${ini}</div>`;
}

function _tpcRecentHtml(userId){
  const open  =_tvFeedCache.filter(e=>e.user_id===userId&&e.type==='open');
  const trades=_tvFeedCache.filter(e=>e.user_id===userId&&e.type==='trade');
  const items =[...open,...trades].slice(0,5);
  if(!items.length) return '<div style="font-size:11px;color:var(--muted);padding:10px 0;text-align:center">No recent activity</div>';
  return items.map(e=>{
    if(e.type==='open'){
      const pct=e.current_pnl_pct;
      const pctStr=pct!=null?(pct>=0?'+':'')+pct.toFixed(1)+'%':'in trade';
      return `<div class="tpc-trade-row">
        <span class="tpc-trade-badge" style="background:rgba(0,0,0,.15);color:var(--green);border:1px solid rgba(0,0,0,.4)">LIVE</span>
        <span class="tpc-trade-token">${esc(e.token)}</span>
        <span class="tpc-trade-pnl" style="color:var(--green)">📈 ${esc(pctStr)}</span>
        <span class="tpc-trade-time">${_tvTimeAgo(e.opened_at)}</span>
      </div>`;
    }
    const pos=e.pnl>=0;
    return `<div class="tpc-trade-row">
      <span class="tpc-trade-badge" style="${pos?'background:rgba(0,0,0,.1);color:var(--green);border:1px solid rgba(0,0,0,.25)':'background:rgba(255,77,106,.1);color:var(--red);border:1px solid rgba(255,77,106,.3)'}">${pos?'WIN':'LOSS'}</span>
      <span class="tpc-trade-token">${esc(e.token)}</span>
      <span class="tpc-trade-pnl" style="color:${pos?'var(--green)':'var(--red)'}">${esc((pos?'+':'')+e.pnl.toFixed(4)+' SOL')}</span>
      <span class="tpc-trade-time">${_tvTimeAgoStr(e.timestamp)}</span>
    </div>`;
  }).join('');
}

// ── SEND SOL ──
let _tpcCurrentFullWallet = '';

async function _waitForSolanaWeb3(timeout=10000){
  const start=Date.now();
  while(!window.solanaWeb3){
    if(Date.now()-start>timeout) throw new Error('solana/web3.js load timeout');
    await new Promise(r=>setTimeout(r,100));
  }
  return window.solanaWeb3;
}

function _tpcOpenSolForm(){
  const form=document.getElementById('tpc-sol-form');
  const recip=document.getElementById('tpc-sol-recip');
  const msg=document.getElementById('tpc-sol-msg');
  const inp=document.getElementById('tpc-sol-amount');
  const btn=document.getElementById('tpc-sol-send-btn');
  if(!form) return;
  const w=_tpcCurrentFullWallet;
  if(recip) recip.textContent=w?(w.slice(0,6)+'...'+w.slice(-4)):'—';
  if(msg){msg.className='tpc-sol-msg';msg.textContent='';}
  if(inp) inp.value='';
  if(btn){btn.disabled=false;btn.textContent='Send';}
  form.classList.toggle('open');
}

function _tpcCloseSolForm(){
  const form=document.getElementById('tpc-sol-form');
  if(form) form.classList.remove('open');
}

async function _tpcSendSol(amountSol, recipientFullWallet) {
  const provider = window.solana || window.solflare;
  if (!provider || !provider.publicKey) throw new Error('No wallet connected');
  const lamports = Math.floor(parseFloat(amountSol) * 1e9);
  const resp = await fetch('/api/solana/build_transfer', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({from_wallet: provider.publicKey.toString(), to_wallet: recipientFullWallet, lamports})
  });
  const data = await resp.json();
  if (!data.ok) throw new Error(data.msg);
  const result = await provider.signAndSendTransaction({
    serialize: () => Uint8Array.from(atob(data.tx_b64), c => c.charCodeAt(0))
  });
  return result.signature || result;
}

async function _tpcToggleFollow(userId, followKey){
  if(checkGuest()) return;
  const btn=document.getElementById('tpc-follow-btn');
  if(!btn||btn.disabled) return;

  const wasFollowing=_tvFollowed.has(followKey);
  const username=followKey.split('|')[0];

  // Optimistic update — apply immediately before the API round-trip
  if(wasFollowing){
    _tvFollowed.delete(followKey);
    btn.className='tpc-follow-btn btn-follow';
    btn.textContent='Follow';
  } else {
    _tvFollowed.add(followKey);
    btn.className='tpc-follow-btn btn-follow following is-following';
    btn.textContent='✓ Following';
  }

  btn.disabled=true;
  const r=await fetch('/api/follow/'+userId,{method:'POST',headers:{'Content-Type':'application/json'}}).then(res=>res.json()).catch(()=>null);
  btn.disabled=false;

  if(!r?.ok){
    // Revert optimistic update on failure
    if(wasFollowing){
      _tvFollowed.add(followKey);
      btn.className='tpc-follow-btn btn-follow following is-following';
      btn.textContent='✓ Following';
    } else {
      _tvFollowed.delete(followKey);
      btn.className='tpc-follow-btn btn-follow';
      btn.textContent='Follow';
    }
    showLfToast('🔴','Could not update follow status — try again','neg');
    return;
  }

  // Sync to authoritative server state (handles any edge cases)
  if(r.following){
    _tvFollowed.add(followKey);
    btn.className='tpc-follow-btn btn-follow following is-following';
    btn.textContent='✓ Following';
    showLfToast('👥',`Now following ${username}`,'pos');
  } else {
    _tvFollowed.delete(followKey);
    btn.className='tpc-follow-btn btn-follow';
    btn.textContent='Follow';
    showLfToast('👋',`Unfollowed ${username}`,'neg');
  }
  const fc=document.getElementById('tpc-follower-count');
  if(fc) fc.textContent=r.follower_count;
}

let _tvProfileOpen = false;

function closeTraderProfile(){
  _tvProfileOpen = false;
  _tpcCurrentFullWallet = '';
  _tvpCurrentProfileId = 0;
  _tvpCurrentProfileUsername = '';
  _tvpPrevProfile = null;
  document.getElementById('tv-profile-view').style.display = 'none';
  document.getElementById('tv-follow-view').style.display = 'none';
  document.getElementById('tv-layout').style.display = '';
  _updateTvMeCard();
}

// ── FOLLOW FULL-PAGE VIEW ──
let _tvFollowViewUserId = 0;
let _tvFollowViewUsername = '';
let _tvFollowViewType = 'followers';

function closeFollowView(){
  document.getElementById('tv-follow-view').style.display = 'none';
  if(_tvpCurrentProfileId){
    document.getElementById('tv-profile-view').style.display = '';
  } else {
    document.getElementById('tv-layout').style.display = '';
    _updateTvMeCard();
  }
}

async function openFollowView(userId, username, type){
  if(!userId) return;
  _tvFollowViewUserId = userId;
  _tvFollowViewUsername = username || '';
  _tvFollowViewType = type;
  const view = document.getElementById('tv-follow-view');
  document.getElementById('tv-profile-view').style.display = 'none';
  document.getElementById('tv-layout').style.display = 'none';
  const meCard = document.getElementById('tv-me-card');
  if(meCard) meCard.style.display = 'none';
  view.style.display = '';
  const title = type === 'followers'
    ? `${esc(username)}'s Followers`
    : `${esc(username)} is Following`;
  view.innerHTML = `
    <div class="tvp-back-bar">
      <button class="tvp-back-btn" onclick="closeFollowView()">← Back</button>
      <span style="color:var(--muted);font-size:11px">${esc(username)}</span>
    </div>
    <div class="tvfl-title">${title}</div>
    <div class="tvfl-list" id="tvfl-list"><div class="tvfl-loading">Loading…</div></div>`;
  const r = await fetch(`/api/profile/${userId}/${type}`).then(r=>r.json()).catch(()=>null);
  const listEl = document.getElementById('tvfl-list');
  if(!listEl) return;
  if(!r?.ok || !r.users?.length){
    listEl.innerHTML = `<div class="tvfl-empty">No ${type} yet.</div>`;
    return;
  }
  listEl.innerHTML = r.users.map(u=>{
    const bg = _tvAvatarColor(u.username||'?');
    const ini = esc((u.username||'?')[0].toUpperCase());
    const avImg = u.avatar_url ? `<img src="${u.avatar_url}" alt="" onerror="this.style.display='none'">` : '';
    const pnl = u.pnl_today ?? 0;
    const pnlPos = pnl >= 0;
    const pnlStr = (pnlPos?'+':'') + pnl.toFixed(4);
    const pnlColor = pnlPos ? 'var(--green)' : 'var(--red)';
    const rawKey = u.username+'|'+(u.wallet_address||'');
    const followKey = esc(rawKey);
    // Seed _tvFollowed from server's authoritative is_following field
    if(u.is_following) _tvFollowed.add(rawKey); else _tvFollowed.delete(rawKey);
    const isFollowed = _tvFollowed.has(rawKey);
    const fBtnHtml = (u.user_id && phantomKey && u.wallet_address !== phantomKey)
      ? `<button class="tv-follow-btn${isFollowed?' followed is-following':''}" onclick="event.stopPropagation();_tvFollowToggle(this,'${followKey}',${u.user_id},'${esc(u.username).replace(/'/g,"\\'")}')">Follow</button>`
      : '';
    const rowCls = (type==='following' && isFollowed) ? 'tvfl-row is-following' : 'tvfl-row';
    const nameBadge = type==='followers'
      ? (isFollowed ? '<span class="fstate-mutual">Mutual</span>' : '<span class="fstate-follows-you">Follows you</span>')
      : '';
    return `<div class="${rowCls}" onclick="openProfileCard(${u.user_id||0})">
      <div class="tvfl-avatar" style="background:${bg}">${avImg}${ini}</div>
      <div class="tvfl-info">
        <div class="tvfl-name">${esc(u.username||u.wallet)}${nameBadge}</div>
        <div class="tvfl-wallet">${esc(u.wallet)}</div>
      </div>
      <div class="tvfl-pnl" style="color:${pnlColor}">${esc(pnlStr)}</div>
      ${fBtnHtml}
    </div>`;
  }).join('');
}

// ── FOLLOWERS / FOLLOWING PANEL (inline in profile view) ──
let _tvpFollowPanelWallet = '';
let _tvpFollowPanelTab = 'followers';

async function _loadFollowPanel(wallet, tab){
  if(!wallet) return;
  _tvpFollowPanelWallet = wallet;
  _tvpFollowPanelTab = tab;
  const listEl = document.getElementById('tvp-fp-list');
  if(!listEl) return;
  listEl.innerHTML = '<div class="tvp-fp-loading">Loading…</div>';
  const r = await fetch(`/api/profile/${encodeURIComponent(wallet)}/${tab}`).then(r=>r.json()).catch(()=>null);
  console.log('[followPanel] tab:', tab, 'response:', r);
  if(!listEl.isConnected) return;
  if(!r?.ok || !r.users?.length){
    const empty = tab==='followers' ? 'No followers yet' : 'Not following anyone';
    listEl.innerHTML = `<div class="tvp-fp-empty">${empty}</div>`;
    return;
  }
  listEl.innerHTML = r.users.map(u=>{
    const bg = _tvAvatarColor(u.username||'?');
    const ini = esc((u.username||'?')[0].toUpperCase());
    const avImg = u.avatar_url ? `<img src="${u.avatar_url}" alt="" onerror="this.style.display='none'">` : '';
    const pnl = u.pnl_today ?? 0;
    const pnlPos = pnl >= 0;
    const pnlStr = (pnlPos?'+':'') + pnl.toFixed(4);
    const pnlColor = pnlPos ? 'var(--green)' : 'var(--red)';
    const rawKey = u.username+'|'+(u.wallet_address||'');
    const followKey = esc(rawKey);
    // Seed _tvFollowed from server's authoritative is_following field
    if(u.is_following) _tvFollowed.add(rawKey); else _tvFollowed.delete(rawKey);
    const isFollowed = _tvFollowed.has(rawKey);
    // stopPropagation is on the button directly — not a wrapper div — so clicking
    // elsewhere on the row still fires the row onclick
    const fBtnHtml = (u.user_id && phantomKey && u.wallet_address !== phantomKey)
      ? `<button class="tv-follow-btn${isFollowed?' followed is-following':''}" onclick="event.stopPropagation();_tvpFollowAndRefresh(this,'${followKey}',${u.user_id},'${esc(u.username).replace(/'/g,"\\'")}')">Follow</button>`
      : '';
    const rowCls = (tab==='following' && isFollowed) ? 'tvp-fp-row is-following' : 'tvp-fp-row';
    const nameBadge = tab==='followers'
      ? (isFollowed ? '<span class="fstate-mutual">Mutual</span>' : '<span class="fstate-follows-you">Follows you</span>')
      : '';
    return `<div class="${rowCls}" onclick="openProfileCard(${u.user_id||0})">
      <div class="tvp-fp-avatar" style="background:${bg}">${avImg}${ini}</div>
      <div class="tvp-fp-info">
        <div class="tvp-fp-name">${esc(u.username||u.wallet)}${nameBadge}</div>
        <div class="tvp-fp-wallet">${esc(u.wallet)}</div>
      </div>
      <div class="tvp-fp-pnl" style="color:${pnlColor}">${esc(pnlStr)}</div>
      ${fBtnHtml}
    </div>`;
  }).join('');
}

function _switchFollowTab(tab){
  _tvpFollowPanelTab = tab;
  document.getElementById('tvp-tab-followers')?.classList.toggle('active', tab==='followers');
  document.getElementById('tvp-tab-following')?.classList.toggle('active', tab==='following');
  _loadFollowPanel(_tvpFollowPanelWallet, tab);
}

async function _tvpFollowAndRefresh(btn, key, userId, username){
  await _tvFollowToggle(btn, key, userId, username);
  _loadFollowPanel(_tvpFollowPanelWallet, _tvpFollowPanelTab);
}

// ── PROFILE NAVIGATION HISTORY ──
let _tvpCurrentProfileId = 0;
let _tvpCurrentProfileUsername = '';
let _tvpPrevProfile = null; // {userId, wallet, tab, username}

async function _tvpGoBack(){
  const prev = _tvpPrevProfile;
  _tvpPrevProfile = null;
  await openProfileCard(prev.userId);
  if(prev.tab !== 'followers') _switchFollowTab(prev.tab);
}

function _tvpTradesHtml(trades){
  if(!trades?.length) return '<div class="tvp-empty">No trades today</div>';
  return `<table class="tvp-table">
    <thead><tr>
      <th>Token</th><th>Entry</th><th>Exit</th><th>PnL</th><th>Time</th>
    </tr></thead>
    <tbody>${trades.map(t=>{
      const pos=t.pnl>=0;
      const pnlStr=(pos?'+':'')+t.pnl.toFixed(4)+' SOL';
      const pnlColor=pos?'var(--green)':'var(--red)';
      return `<tr>
        <td style="font-weight:700;color:var(--text)">${esc(t.token)}</td>
        <td style="color:var(--muted)">${fmtPrice(t.entry)}</td>
        <td style="color:var(--muted)">${fmtPrice(t.exit)}</td>
        <td style="color:${pnlColor};font-weight:700">${esc(pnlStr)}</td>
        <td style="color:var(--dim)">${esc(_tvTimeAgoStr(t.timestamp))}</td>
      </tr>`;
    }).join('')}</tbody>
  </table>`;
}

function _tvpPositionsHtml(positions){
  if(!positions?.length) return '';
  return `<table class="tvp-table">
    <thead><tr>
      <th>Token</th><th>Entry</th><th>Current</th><th>PnL%</th><th>PnL SOL</th><th>Open</th>
    </tr></thead>
    <tbody>${positions.map(p=>{
      const pct=p.pnl_pct;
      const sol=p.pnl_sol;
      const pctStr=pct!=null?(pct>=0?'+':'')+pct.toFixed(1)+'%':'—';
      const solStr=sol!=null?(sol>=0?'+':'')+sol.toFixed(4):'—';
      const pnlColor=(pct!=null&&pct<0)?'var(--red)':'var(--green)';
      const openStr=p.opened_at?_tvTimeAgo(p.opened_at):'—';
      return `<tr>
        <td style="font-weight:700;color:var(--text)">${esc(p.token)}</td>
        <td style="color:var(--muted)">${fmtPrice(p.entry)}</td>
        <td style="color:var(--muted)">${p.current!=null?fmtPrice(p.current):'—'}</td>
        <td style="color:${pnlColor};font-weight:700">${esc(pctStr)}</td>
        <td style="color:${pnlColor};font-weight:700">${esc(solStr)}</td>
        <td style="color:var(--dim)">${esc(openStr)}</td>
      </tr>`;
    }).join('')}</tbody>
  </table>`;
}

async function openProfileCard(userId){
  if(!userId) return;
  if(!_tradersView) openTradersView();
  _tvProfileOpen = true;
  _tvpCurrentProfileId = userId;
  const view = document.getElementById('tv-profile-view');
  document.getElementById('tv-layout').style.display = 'none';
  document.getElementById('tv-follow-view').style.display = 'none';
  const meCard = document.getElementById('tv-me-card');
  if(meCard) meCard.style.display = 'none';
  view.style.display = '';
  view.innerHTML = '<div class="tvp-loading">Loading profile…</div>';

  const [p, td, copyStatus] = await Promise.all([
    fetch('/api/profile/'+userId).then(r=>r.json()).catch(()=>null),
    fetch('/api/profile/'+userId+'/trades').then(r=>r.json()).catch(()=>null),
    phantomKey ? fetch('/api/copy-trade/status').then(r=>r.json()).catch(()=>null) : Promise.resolve(null),
  ]);

  if(!p?.ok){
    view.innerHTML = '<div class="tvp-back-bar"><button class="tvp-back-btn" onclick="closeTraderProfile()">← Traders Feed</button></div><div class="tvp-loading" style="color:var(--red)">Failed to load profile.</div>';
    return;
  }

  _tpcCurrentFullWallet = p.wallet_address || '';
  _tvpCurrentProfileUsername = p.username || '';
  console.log('wallet set:', _tpcCurrentFullWallet);
  const followKey = p.username+'|'+p.wallet;
  // Seed _tvFollowed from server's authoritative response so the button is
  // correct on first load even if this trader was followed in a previous session.
  if(p.is_following){ _tvFollowed.add(followKey); }
  else               { _tvFollowed.delete(followKey); }
  const isFollowing = _tvFollowed.has(followKey);
  const followCls = 'tpc-follow-btn btn-follow'+(isFollowing?' following is-following':'');
  const _isSelf = !!(_myProfileId && userId && _myProfileId === userId);
  const isCopyingThis = !_isSelf && copyStatus?.ok && copyStatus.copying && copyStatus.target_wallet === _tpcCurrentFullWallet;
  const followBtnHtml = _isSelf
    ? `<button class="tpc-follow-btn" style="border-color:rgba(0,0,0,.4);color:var(--green);background:rgba(0,0,0,.06)" onclick="closeTraderProfile();openSettings()">✏ Edit Profile</button>`
    : `<button class="${followCls}" id="tpc-follow-btn" onclick="_tpcToggleFollow(${userId},'${followKey.replace(/'/g,"\\'")}')">Follow</button>`;
  const copyBtnHtml = (!_isSelf && phantomKey)
    ? (isCopyingThis
        ? `<button class="tpc-stop-copy-btn" id="tpc-copy-btn" onclick="_tpcStopCopy()">Stop Copying</button>`
        : `<button class="tpc-copy-btn" id="tpc-copy-btn" onclick="_tpcStartCopy('${_tpcCurrentFullWallet.replace(/'/g,"\\'")}','${esc(p.username).replace(/'/g,"\\'")}')">Copy Trader</button>`)
    : '';
  const msgBtnHtml = (!_isSelf && phantomKey)
    ? `<button class="tpc-msg-btn" onclick="openDMWith(${userId},'${_tpcCurrentFullWallet.replace(/'/g,"\\'")}','${(p.username||'').replace(/'/g,"\\'")}')">💬 Message</button>`
    : '';
  const tradesHtml = _tvpTradesHtml(td?.trades);
  const posHtml = _tvpPositionsHtml(td?.positions);

  const solBal    = p.sol_balance??td?.sol_balance??0;
  const openCnt   = p.open_trades??td?.open_count??0;
  const closedCnt = p.closed_trades??td?.total_closed??p.trade_count??0;
  const allPnl    = p.total_pnl??td?.total_pnl??0;
  const winRate   = p.win_rate??0;
  const allPnlPos = allPnl>=0;
  const allPnlStr = (allPnlPos?'+':'')+allPnl.toFixed(4)+' SOL';
  const winRateColor = winRate>=50?'var(--green)':'var(--muted)';
  const prevBackBtn = _tvpPrevProfile
    ? `<button class="tvp-back-btn" onclick="_tvpGoBack()">← ${esc(_tvpPrevProfile.username)}'s ${_tvpPrevProfile.tab}</button>`
    : '';

  view.innerHTML = `
    <div class="tvp-back-bar">
      <button class="tvp-back-btn" onclick="closeTraderProfile()">← Traders Feed</button>
      ${prevBackBtn}
    </div>

    <div class="tvp-card">
      <div class="tvp-top">
        ${_tpcAvatarHtml(p, p.bot_active)}
        <div class="tvp-meta">
          <div class="tvp-username">${esc(p.username)}</div>
          <div class="tvp-wallet">${esc(p.wallet)}</div>
          ${p.bio?`<div class="tpc-bio" style="margin-bottom:8px">${esc(p.bio)}</div>`:''}
          ${(p.badges&&p.badges.length)?`<div class="badges-row" style="margin-bottom:8px">${p.badges.map(b=>_badgePillHtml(b,true)).join('')}</div>`:''}
          <div class="tvp-social-row">
            <span class="tvp-social-item clickable" onclick="openFollowView(${userId},_tvpCurrentProfileUsername,'followers')" title="View followers"><span class="tvp-social-icon">👥</span><strong id="tpc-follower-count">${p.follower_count}</strong>&nbsp;Followers</span>
            <span class="tvp-social-item clickable" onclick="openFollowView(${userId},_tvpCurrentProfileUsername,'following')" title="View following"><span class="tvp-social-icon">➜</span><strong>${p.following_count}</strong>&nbsp;Following</span>
            ${p.avg_hold_seconds?`<span class="tvp-social-item"><span class="tvp-social-icon">⏱</span>&nbsp;${esc(_tvFormatHold(p.avg_hold_seconds))}</span>`:''}
            <span class="tvp-social-item"><span class="tvp-social-icon">📅</span>&nbsp;${esc(_tvFormatJoined(p.joined_at))}</span>
          </div>
        </div>
        <div class="tvp-actions">
          ${followBtnHtml}
          ${copyBtnHtml}
          ${msgBtnHtml}
          <button class="tpc-sol-btn" onclick="_tpcOpenSolForm()">◎ Send SOL</button>
        </div>
      </div>
      <div class="tpc-sol-form" id="tpc-sol-form" style="margin-top:14px">
        <div class="tpc-sol-row">
          <span class="tpc-sol-lbl">Amount (SOL)</span>
          <input type="number" class="tpc-sol-amount" id="tpc-sol-amount" placeholder="0.01" min="0.001" max="10" step="0.001">
        </div>
        <div class="tpc-sol-row">
          <span class="tpc-sol-lbl">To</span>
          <span class="tpc-sol-recip" id="tpc-sol-recip">—</span>
        </div>
        <div class="tpc-sol-btns">
          <button class="tpc-sol-send" id="tpc-sol-send-btn" onclick="(async()=>{const sendBtn=this,amountInput=document.getElementById('tpc-sol-amount'),msgEl=document.getElementById('tpc-sol-msg');sendBtn.disabled=true;sendBtn.textContent='Sending...';msgEl.textContent='';console.log('Send clicked', amountInput.value, _tpcCurrentFullWallet);try{const sig=await _tpcSendSol(parseFloat(amountInput.value),_tpcCurrentFullWallet);msgEl.className='tpc-sol-msg ok';msgEl.textContent='✓ Sent! '+sig.slice(0,8)+'...';sendBtn.textContent='✓ Sent';setTimeout(()=>{sendBtn.disabled=false;sendBtn.textContent='Send';},3000);}catch(e){msgEl.className='tpc-sol-msg err';msgEl.textContent='✗ '+(e.message||'Transaction failed');sendBtn.disabled=false;sendBtn.textContent='Send';}})()">Send</button>
          <button class="tpc-sol-cancel" onclick="_tpcCloseSolForm()">Cancel</button>
        </div>
        <div class="tpc-sol-msg" id="tpc-sol-msg"></div>
      </div>
    </div>

    <div class="tvp-stats5">
      <div class="tvp-stat5">
        <div class="tvp-stat5-val">◎ ${solBal.toFixed(4)}</div>
        <div class="tvp-stat5-lbl">SOL Balance</div>
      </div>
      <div class="tvp-stat5">
        <div class="tvp-stat5-val">${openCnt}</div>
        <div class="tvp-stat5-lbl">Open Trades</div>
      </div>
      <div class="tvp-stat5">
        <div class="tvp-stat5-val">${closedCnt}</div>
        <div class="tvp-stat5-lbl">Closed Trades</div>
      </div>
      <div class="tvp-stat5">
        <div class="tvp-stat5-val" style="color:${winRateColor}">${winRate.toFixed(1)}%</div>
        <div class="tvp-stat5-lbl">Win Rate</div>
      </div>
      <div class="tvp-stat5">
        <div class="tvp-stat5-val" style="color:${allPnlPos?'var(--green)':'var(--red)'}">${esc(allPnlStr)}</div>
        <div class="tvp-stat5-lbl">All-Time PnL</div>
      </div>
    </div>

    <div class="tvp-follow-panel">
      <div class="tvp-fp-tabs">
        <button class="tvp-fp-tab active" id="tvp-tab-followers" onclick="_switchFollowTab('followers')">👥 Followers</button>
        <button class="tvp-fp-tab" id="tvp-tab-following" onclick="_switchFollowTab('following')">➜ Following</button>
      </div>
      <div class="tvp-fp-list" id="tvp-fp-list"><div class="tvp-fp-loading">Loading…</div></div>
    </div>

    ${posHtml?`<div class="tvp-section"><div class="tvp-section-hdr">Open Positions</div>${posHtml}</div>`:''}

    <div class="tvp-section">
      <div class="tvp-section-hdr">Today's Trades</div>
      ${tradesHtml}
    </div>
    <div id="tvp-comments-section" class="tvp-comments"></div>
  `;
  _loadFollowPanel(_tpcCurrentFullWallet, 'followers');
  _tvcLoadComments(userId, isFollowing, _isSelf);
}

// ── DAILY LEADERBOARD ──
let _lbCountdownTimer=null,_lbCountdownVal=30;


function _lbStartCountdown(){
  if(_lbCountdownTimer) clearInterval(_lbCountdownTimer);
  _lbCountdownVal=30;
  const el=document.getElementById('lb-countdown');
  if(el) el.textContent='↻ '+_lbCountdownVal+'s';
  _lbCountdownTimer=setInterval(()=>{
    _lbCountdownVal=Math.max(0,_lbCountdownVal-1);
    if(el) el.textContent=_lbCountdownVal>0?'↻ '+_lbCountdownVal+'s':'refreshing…';
    if(_lbCountdownVal===0) _lbCountdownVal=30;
  },1000);
}

const _LB_AVATAR_COLORS=['#1a5276','#0e4d3a','#2d3561','#4a235a','#5b2333','#1b4332','#154360','#3d1a00'];
function _lbAvatarColor(name){
  let h=0; for(let i=0;i<(name||'').length;i++) h=(h*31+name.charCodeAt(i))>>>0;
  return _LB_AVATAR_COLORS[h%_LB_AVATAR_COLORS.length];
}

function _lbAvatarHtml(e, uid){
  const name=e.username||'?';
  const ini=esc(name[0].toUpperCase());
  const bg=_lbAvatarColor(name);
  const clickAttr=uid?`onclick="event.stopPropagation();openProfileCard(${uid})" style="cursor:pointer;background:${bg}"`:`style="background:${bg}"`;
  if(e.avatar_url){
    return `<div class="lb-avatar" ${clickAttr}><img src="${e.avatar_url}" alt="" onerror="this.style.display='none'">${ini}</div>`;
  }
  return `<div class="lb-avatar" ${clickAttr}>${ini}</div>`;
}

function _lbRankHtml(rank){
  const colors=['#FFD700','#C0C0C0','#CD7F32'];
  const color=rank<=3?colors[rank-1]:'var(--muted)';
  return `<div class="lb-rank" style="color:${color}">#${rank}</div>`;
}

function renderLeaderboard(entries){
  const list=document.getElementById('lb-list');
  if(!list) return;
  if(!entries||!entries.length){
    list.innerHTML='<div class="lb-empty">No trades today yet — be the first!</div>';
    return;
  }
  if(entries[0]) console.log('[leaderboard] first entry:', JSON.stringify(entries[0]));
  list.innerHTML=entries.map(e=>{
    const isMe=!!(phantomKey&&e.wallet_address===phantomKey);
    const pnlPos=e.total_pnl>=0;
    const pnlColor=pnlPos?'var(--green)':'var(--red)';
    const pnlStr=(pnlPos?'+':'')+e.total_pnl.toFixed(4)+' SOL';
    const bestStr=(e.best_trade>=0?'+':'')+e.best_trade.toFixed(4);
    const uid=e.user_id||0;
    const earnedBadges=(e.badges||[]);
    const badgeHtml=earnedBadges.length ? `<div class="badges-row" style="margin-top:3px;gap:3px">${earnedBadges.slice(0,3).map(b=>_badgePillHtml(b,true,true)).join('')}</div>` : '';
    const lbFollowKey=esc(e.username+'|'+(e.wallet_address||''));
    const lbFollowed=uid&&!isMe&&_tvFollowed.has(e.username+'|'+(e.wallet_address||''));
    const lbFollowBtn=uid&&!isMe?`<button class="tv-follow-btn${lbFollowed?' followed':''}" onclick="event.stopPropagation();_tvFollowToggle(this,'${lbFollowKey}',${uid},'${esc(e.username).replace(/'/g,"\\'")}')"> ${lbFollowed?'✓ Following':'Follow'}</button>`:'';
    return `<div class="lb-row${isMe?' lb-me':''}" style="cursor:pointer" onclick="openProfileCard(${uid})">
      ${_lbRankHtml(e.rank)}
      ${_lbAvatarHtml(e,uid)}
      <div class="lb-info">
        <div class="lb-name">${esc(e.username)}</div>
        <div class="lb-meta">(${e.trade_count} trade${e.trade_count===1?'':'s'}) &nbsp;·&nbsp; best: ${esc(bestStr)}</div>
        ${badgeHtml}
      </div>
      <div class="lb-pnl" style="color:${pnlColor}">${esc(pnlStr)}</div>
      ${lbFollowBtn}
    </div>`;
  }).join('');
}

async function fetchLeaderboard(){
  if(!appVisible()) return;
  const [r,ps]=await Promise.all([
    fetch('/api/leaderboard').then(r=>r.json()).catch(()=>null),
    fetch('/api/platform/stats').then(r=>r.json()).catch(()=>null)
  ]);
  if(Array.isArray(r)) renderLeaderboard(r);
  const _foc=document.getElementById('feed-online-count');
  if(_foc&&ps&&ps.ok) _foc.textContent=ps.active_traders??'—';
  _lbStartCountdown();
}

// ── PNL PERFORMANCE CHART (LightweightCharts) ──────────────────────────────
let _pnlcChart=null,_pnlcSeries=null,_pnlcRange='1d';

async function fetchPnlChart(){
  if(!appVisible()) return;
  try{
    const r=await fetch('/api/pnl_chart?range='+_pnlcRange).then(r=>r.json());
    console.log('[pnl_chart] range='+_pnlcRange+' response:', JSON.stringify(r));
    _renderPnlcChart(r.data||[]);
  }catch(e){console.error('[pnl_chart] fetch error:',e);}
}

function _renderPnlcChart(pts){
  const container=document.getElementById('pnlc-container');
  const emptyEl=document.getElementById('pnlc-empty');
  const valEl=document.getElementById('pnlc-val');
  if(!container) return;

  if(!pts||!pts.length){
    if(emptyEl){emptyEl.style.display='flex';}
    if(valEl){valEl.textContent='';valEl.style.color='';}
    return;
  }
  if(emptyEl) emptyEl.style.display='none';

  const lastVal=pts[pts.length-1].value;
  const isPos=lastVal>=0;
  const lineClr=isPos?'#000000':'#ff1744';
  const topClr=isPos?'rgba(0,0,0,0.25)':'rgba(255,68,68,0.25)';
  const botClr=isPos?'rgba(0,0,0,0)':'rgba(255,68,68,0)';

  if(valEl){
    valEl.textContent=(isPos?'+':'')+lastVal.toFixed(4)+' SOL';
    valEl.style.color=lineClr;
  }

  if(!_pnlcChart){
    _pnlcChart=LightweightCharts.createChart(container,{
      width:container.clientWidth,height:200,
      layout:{background:{type:'solid',color:'#0a0e1a'},textColor:'#6e8faf'},
      grid:{vertLines:{visible:false},horzLines:{visible:false}},
      crosshair:{mode:LightweightCharts.CrosshairMode.Magnet},
      rightPriceScale:{borderColor:'#2a4060',scaleMargins:{top:0.1,bottom:0.1}},
      timeScale:{borderColor:'#2a4060',timeVisible:_pnlcRange==='1d',secondsVisible:false},
      handleScroll:false,handleScale:false,
    });
    _pnlcSeries=_pnlcChart.addAreaSeries({lineColor:lineClr,topColor:topClr,bottomColor:botClr,lineWidth:2});
    new ResizeObserver(()=>{
      if(container.clientWidth>0) _pnlcChart.applyOptions({width:container.clientWidth});
    }).observe(container);
  }else{
    _pnlcChart.applyOptions({timeScale:{timeVisible:_pnlcRange==='1d'}});
    _pnlcSeries.applyOptions({lineColor:lineClr,topColor:topClr,bottomColor:botClr});
  }
  _pnlcSeries.setData(pts);
  _pnlcChart.timeScale().fitContent();
}

function _pnlSetRange(range,btn){
  _pnlcRange=range;
  document.querySelectorAll('.pnlc-btn').forEach(b=>b.classList.remove('active'));
  if(btn) btn.classList.add('active');
  fetchPnlChart();
}

setInterval(fetchState,10000);
setInterval(fetchMarketOnly,15000);
setInterval(fetchTrades,30000);
setInterval(fetchPnlChart,30000);
setInterval(fetchLeaderboard,30000);
setInterval(fetchTradersFeed,15000);
setInterval(_refreshVisibleReactions,12000);
setInterval(fetchPumpScanner,30000);

// ── VERSION POLLING ──
let _pageVersion=null;
(async()=>{
  const r=await fetch('/api/version').then(r=>r.json()).catch(()=>null);
  if(r?.version) _pageVersion=r.version;
})();
setInterval(async()=>{
  if(!_pageVersion) return;
  const r=await fetch('/api/version').then(r=>r.json()).catch(()=>null);
  if(r?.version && r.version!==_pageVersion){
    document.getElementById('update-banner').style.display='block';
  }
},30000);

// ── TOKEN INCINERATOR ──
let _incTokens=[], _incScanAll=false;

function _incRenderRow(t, i){
  const shortMint=t.mint?(t.mint.slice(0,6)+'…'+t.mint.slice(-4)):'—';
  const label=t.symbol?t.symbol:shortMint;
  const solscanUrl='https://solscan.io/token/'+(t.mint||'');
  const solRent='+'+(t.sol_rent||0.00203928).toFixed(6)+' SOL';

  let badge='', preChecked=t.can_close;
  if(t.reason==='empty')        badge='<span class="inc-badge inc-badge-empty">EMPTY</span>';
  else if(t.reason==='dust')    badge='<span class="inc-badge inc-badge-dust">DUST</span>';
  else if(t.reason==='unknown') badge='<span class="inc-badge inc-badge-unknown">UNVERIFIED</span>';
  else{badge='<span class="inc-badge inc-badge-value">HAS VALUE</span>';preChecked=false;}

  // Sub-line: balance and USD value
  let sub='';
  if(t.reason==='empty'){
    sub='No balance — rent only';
  } else if(t.value_usd!=null){
    const v=t.value_usd;
    const vStr=v<0.000001?v.toExponential(2):v<0.01?v.toFixed(6):v.toFixed(4);
    sub=(t.balance||'0')+' tokens &nbsp;·&nbsp; $'+vStr;
  } else {
    sub=(t.balance||'0')+' tokens';
  }

  const disAttr=t.can_close?'':'disabled';
  const rowCls='inc-token-row'+(t.can_close?'':' inc-row-disabled');
  const solCls='inc-token-sol'+(t.can_close?'':' inc-token-sol-dim');
  const solLabel=t.can_close?solRent:'No key';

  return `<label class="${rowCls}">
    <input type="checkbox" class="inc-checkbox" data-idx="${i}" data-account="${t.pubkey||''}" data-sol="${t.sol_rent||0.00203928}" ${preChecked?'checked':''} ${disAttr} onchange="_incUpdateSummary()">
    <div class="inc-token-info">
      <div style="display:flex;align-items:center;gap:5px;flex-wrap:wrap">
        <a class="inc-token-mint" href="${solscanUrl}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="${t.mint||''}">${esc(label)}</a>
        ${badge}
      </div>
      <span class="inc-value">${sub}</span>
    </div>
    <span class="${solCls}">${solLabel}</span>
  </label>`;
}

async function _incLoad(scanAll){
  _incScanAll=scanAll;
  document.getElementById('inc-loading').style.display='block';
  document.getElementById('inc-body').style.display='none';
  document.getElementById('inc-empty').style.display='none';
  const st=document.getElementById('inc-status');
  st.style.display='none'; st.className='s-msg';

  const url='/api/get-tokens'+(scanAll?'?scan_all=1':'');
  const r=await fetch(url).then(r=>r.json()).catch(()=>null);
  document.getElementById('inc-loading').style.display='none';

  if(!r||!r.ok){
    st.textContent=r?.msg||'Failed to scan wallet. Try again.';
    st.className='s-msg err'; st.style.display='block';
    return;
  }

  _incTokens=r.tokens||[];
  const stats=r.stats||{};

  // Update mode UI
  const pill=document.getElementById('inc-mode-pill');
  const saBtn=document.getElementById('inc-scan-all-btn');
  const ssBtn=document.getElementById('inc-scan-smart-btn');
  const warn=document.getElementById('inc-scan-warn');
  if(scanAll){
    pill.textContent='All Tokens'; pill.className='inc-scan-pill all';
    saBtn.style.display='none'; ssBtn.style.display='';
    warn.classList.add('show');
  } else {
    pill.textContent='Smart Scan'; pill.className='inc-scan-pill smart';
    saBtn.style.display=''; ssBtn.style.display='none';
    warn.classList.remove('show');
  }

  if(!_incTokens.length){
    document.getElementById('inc-empty').style.display='block';
    return;
  }

  const recSol=stats.recoverable_sol!=null?stats.recoverable_sol.toFixed(6):null;
  let foundParts=[_incTokens.length+' account'+(_incTokens.length!==1?'s':'')];
  if(stats.empty) foundParts.push(stats.empty+' empty');
  if(stats.dust)  foundParts.push(stats.dust+' dust');
  if(recSol)      foundParts.push('~'+recSol+' SOL recoverable');
  document.getElementById('inc-found-count').textContent=foundParts.join(' · ');
  document.getElementById('inc-token-list').innerHTML=_incTokens.map(_incRenderRow).join('');
  _incUpdateSummary();
  document.getElementById('inc-body').style.display='block';
}

async function openIncinerator(){
  if(!phantomKey) return;
  document.getElementById('incinerator-modal').classList.add('open');
  await _incLoad(false);
}

async function _incSetMode(all){
  await _incLoad(all);
}

function _incUpdateSummary(){
  const cbs=document.querySelectorAll('.inc-checkbox:checked');
  const count=cbs.length;
  let sol=0;
  cbs.forEach(cb=>sol+=parseFloat(cb.dataset.sol||0));
  document.getElementById('inc-summary-text').textContent=count+' account'+(count!==1?'s':'')+' selected';
  document.getElementById('inc-sol-est').textContent='~'+sol.toFixed(4)+' SOL';
  document.getElementById('inc-burn-btn').disabled=count===0;
}

function _incSelectAll(all){
  // In select-all, only select accounts we can actually close
  document.querySelectorAll('.inc-checkbox:not(:disabled)').forEach(cb=>cb.checked=all);
  _incUpdateSummary();
}

function closeIncinerator(){
  document.getElementById('incinerator-modal').classList.remove('open');
}

async function burnSelected(){
  const cbs=document.querySelectorAll('.inc-checkbox:checked');
  if(!cbs.length) return;
  // Read account address from data-account (on-chain token account, not mint)
  const accounts=Array.from(cbs).map(cb=>cb.dataset.account).filter(Boolean);
  if(!accounts.length){
    const st=document.getElementById('inc-status');
    st.textContent='✗ No valid account addresses found — try rescanning.';
    st.className='s-msg err'; st.style.display='block';
    return;
  }
  const btn=document.getElementById('inc-burn-btn');
  const st=document.getElementById('inc-status');
  btn.disabled=true; btn.textContent='Burning…';
  st.style.display='none';
  try{
    const r=await fetch('/api/burn-tokens',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({accounts})
    }).then(res=>res.json()).catch(()=>null);
    st.style.display='block';
    if(r?.success){
      const sol=typeof r.recovered_sol==='number'?r.recovered_sol.toFixed(6):'?';
      st.textContent='✓ Claimed '+sol+' SOL'+(r.closed?' ('+r.closed+' account'+(r.closed!==1?'s':'')+' closed)':'');
      st.className='s-msg ok';
      setTimeout(fetchBalance,1500);
      btn.disabled=false; btn.textContent='🔥 Burn & Claim SOL';
      setTimeout(closeIncinerator,4000);
    } else {
      const errMsg=r?.error||r?.msg||'Transaction failed — check logs.';
      st.textContent='✗ '+errMsg;
      st.className='s-msg err';
      btn.disabled=false; btn.textContent='🔥 Burn & Claim SOL';
    }
  } catch(e){
    st.textContent='✗ Network error: '+e.message;
    st.className='s-msg err'; st.style.display='block';
    btn.disabled=false; btn.textContent='🔥 Burn & Claim SOL';
  }
}

// ── SWIPE GESTURES — market grid (mobile) ──
(function(){
  const outer=document.getElementById('market-grid-outer');
  const grid=document.getElementById('market-grid');
  if(!outer||!grid) return;

  let _idx=0, _startX=0, _startY=0, _active=false;

  function _cards(){ return Array.from(grid.querySelectorAll('.mkt-card')); }

  function _snapTo(n){
    const cards=_cards();
    if(!cards.length) return;
    _idx=Math.max(0,Math.min(n,cards.length-1));
    const cardW=cards[0].offsetWidth+12; // card width + 12px gap
    grid.style.transform='translateX(-'+(  _idx*cardW)+'px)';
  }

  // Called by renderMarket when new tokens load
  window._swipeReset=function(){ _idx=0; grid.style.transform=''; };

  outer.addEventListener('touchstart',function(e){
    _startX=e.touches[0].clientX;
    _startY=e.touches[0].clientY;
    _active=true;
  },{passive:true});

  outer.addEventListener('touchmove',function(e){
    if(!_active) return;
    const dx=e.touches[0].clientX-_startX;
    const dy=e.touches[0].clientY-_startY;
    if(Math.abs(dx)>Math.abs(dy)) e.preventDefault();
  },{passive:false});

  outer.addEventListener('touchend',function(e){
    if(!_active) return;
    _active=false;
    const dx=e.changedTouches[0].clientX-_startX;
    const dy=e.changedTouches[0].clientY-_startY;
    if(Math.abs(dx)<50||Math.abs(dy)>Math.abs(dx)) return;
    _snapTo(dx<0?_idx+1:_idx-1);
  },{passive:true});
})();


setInterval(fetchBalance,30000);
setInterval(_checkInactivity,10000);

// ── HEALTH / AUDIT (owner-only) ──
let _auditLastTs=0;
function isOwner(){ return _isAdmin; }

async function fetchAudit(){
  if(!isOwner()) return;
  const r=await fetch('/api/audit').then(r=>r.json()).catch(()=>null);
  if(r&&!r.error) renderAudit(r);
}

function renderAudit(r){
  _auditLastTs=r.ran_at_ts||0;
  // Update header dot
  const dot=document.getElementById('health-dot');
  if(dot){ dot.className='health-dot '+(r.status||'unknown'); }
  // If panel is open, refresh its contents
  const overlay=document.getElementById('audit-overlay');
  if(overlay?.classList.contains('open')) _renderAuditPanel(r);
}

function _renderAuditPanel(r){
  // Badge
  const badge=document.getElementById('audit-badge');
  const statusLabel={'pass':'ALL PASS','warn':'WARNING','fail':'ISSUES FOUND','unknown':'PENDING'}[r.status]||r.status;
  if(badge){ badge.textContent=statusLabel; badge.className='audit-status-badge '+(r.status||'unknown'); }
  // Ran-at
  const ra=document.getElementById('audit-ran-at');
  if(ra) ra.textContent=r.ran_at?'Last run: '+r.ran_at:'Not yet run — first check runs 15 s after startup';
  // Checks
  const ICON={'pass':'✓','warn':'⚠','fail':'✕'};
  const checks=document.getElementById('audit-checks');
  if(checks){
    if(!r.checks||!r.checks.length){
      checks.innerHTML='<div style="color:var(--muted);font-size:10px;text-align:center;padding:20px">Awaiting first audit run…</div>';
    } else {
      checks.innerHTML=r.checks.map(c=>`
        <div class="audit-row ${esc(c.status)}">
          <span class="audit-icon">${ICON[c.status]||'?'}</span>
          <div>
            <div class="audit-name">${esc(c.name)}</div>
            <div class="audit-msg">${esc(c.msg)}</div>
          </div>
        </div>`).join('');
    }
  }
  // Next run countdown
  const next=document.getElementById('audit-next');
  if(next&&_auditLastTs){
    const secsLeft=Math.max(0,300-Math.round((Date.now()/1000)-_auditLastTs));
    next.textContent=secsLeft>0?'Next auto-run in '+secsLeft+'s':'Refreshing…';
  }
}

function toggleHealthPanel(){
  if(!isOwner()) return;
  const o=document.getElementById('audit-overlay');
  if(!o) return;
  if(o.classList.contains('open')){ closeHealthPanel(); return; }
  o.classList.add('open');
  // Show last cached data immediately, then fetch fresh
  const cached={status:document.getElementById('health-dot')?.classList[1]||'unknown',checks:[],ran_at:null,ran_at_ts:_auditLastTs};
  _renderAuditPanel(cached);
  fetchAudit();
}

function closeHealthPanel(){
  document.getElementById('audit-overlay')?.classList.remove('open');
}

async function triggerAudit(){
  if(!isOwner()) return;
  const btn=document.getElementById('audit-run-btn');
  if(btn){ btn.disabled=true; btn.textContent='Running…'; }
  const r=await fetch('/api/audit/run',{method:'POST'}).then(r=>r.json()).catch(()=>null);
  if(btn){ btn.disabled=false; btn.textContent='↻ Run Now'; }
  if(r&&!r.error) renderAudit(r);
}

// No beforeunload handler — localStorage is intentionally preserved across page
// refreshes, tab switches, and browser restarts. The only way to clear the saved
// session is an explicit "Disconnect" button click, which calls doLogout().

// ── PNL SHARE CARD ─────────────────────────────────────────────────────────
function openPnlCard() {
  if (!phantomKey) return;
  window.open('/card/' + phantomKey, '_blank', 'noopener,noreferrer');
}

function copyPnlCardLink() {
  if (!phantomKey) return;
  const url = 'https://orcagent.fun/card/' + phantomKey;
  const btn = document.getElementById('perf-copy-link-btn');
  const origText = btn ? btn.textContent : '';
  const done = () => {
    if (btn) { btn.textContent = '✓ Copied!'; setTimeout(() => { btn.textContent = origText; }, 2000); }
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url).then(done).catch(() => { _clipFallback(url); done(); });
  } else {
    _clipFallback(url); done();
  }
}

function _clipFallback(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } catch(_) {}
  document.body.removeChild(ta);
}

// ── WITHDRAW SOL MODAL ─────────────────────────────────────────────────────
let _wdCurrentBalance = 0;

function openWithdrawModal() {
  if (!phantomKey) return;
  const modal = document.getElementById('withdraw-modal');
  document.getElementById('wd-to-addr').value = '';
  document.getElementById('wd-amount').value = '';
  document.getElementById('wd-addr-err').style.display = 'none';
  document.getElementById('wd-amt-err').style.display = 'none';
  document.getElementById('wd-result').style.display = 'none';
  const btn = document.getElementById('wd-confirm-btn');
  btn.disabled = false; btn.textContent = 'CONFIRM WITHDRAW';
  // Populate balance hint from cached state
  const solEl = document.getElementById('s-sol');
  const solText = solEl ? solEl.innerText.replace(/[^\d.]/g, '') : '';
  _wdCurrentBalance = parseFloat(solText) || 0;
  const available = Math.max(0, _wdCurrentBalance - 0.001);
  document.getElementById('wd-balance-hint').textContent =
    'Balance: ' + _wdCurrentBalance.toFixed(4) + ' SOL · Max sendable: ' + available.toFixed(6) + ' SOL';
  modal.classList.add('open');
}

function closeWithdrawModal() {
  document.getElementById('withdraw-modal').classList.remove('open');
}

function setMaxWithdraw() {
  const available = Math.max(0, _wdCurrentBalance - 0.001);
  if (available <= 0) return;
  document.getElementById('wd-amount').value = available.toFixed(6);
  document.getElementById('wd-amt-err').style.display = 'none';
}

async function confirmWithdraw() {
  const toAddr   = (document.getElementById('wd-to-addr').value || '').trim();
  const amountRaw = (document.getElementById('wd-amount').value || '').trim();
  const amount   = parseFloat(amountRaw);

  let hasErr = false;
  if (!toAddr || toAddr.length < 32) {
    const el = document.getElementById('wd-addr-err');
    el.textContent = 'Enter a valid Solana address'; el.style.display = 'block';
    hasErr = true;
  }
  if (!amountRaw || isNaN(amount) || amount <= 0) {
    const el = document.getElementById('wd-amt-err');
    el.textContent = 'Enter a valid amount'; el.style.display = 'block';
    hasErr = true;
  }
  if (hasErr) return;

  const btn = document.getElementById('wd-confirm-btn');
  btn.disabled = true; btn.textContent = 'Sending…';
  document.getElementById('wd-result').style.display = 'none';

  try {
    const resp = await fetch('/api/withdraw', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({to_address: toAddr, amount_sol: amount})
    });
    const data = await resp.json();
    const resultEl = document.getElementById('wd-result');
    if (data.ok) {
      const sig = data.signature || '';
      const explorer = sig ? `https://solscan.io/tx/${sig}` : '';
      resultEl.style.cssText = 'display:block;margin-bottom:14px;padding:10px 14px;border-radius:8px;font-size:11px;line-height:1.7;word-break:break-all;background:rgba(0,0,0,.07);border:1px solid rgba(0,0,0,.28);color:var(--green)';
      resultEl.innerHTML = `✓ Sent ${amount} SOL successfully!` +
        (explorer ? `<br><a href="${explorer}" target="_blank" rel="noopener noreferrer" style="color:var(--blue);font-size:10px;text-decoration:underline">View on Solscan ↗</a>` : '') +
        (sig ? `<br><span style="color:var(--muted);font-size:9px;word-break:break-all">TX: ${esc(sig)}</span>` : '');
      btn.style.display = 'none';
      showLfToast('◎',`Sent ${amount} SOL`,'pos');
      fetchBalance();
    } else {
      resultEl.style.cssText = 'display:block;margin-bottom:14px;padding:10px 14px;border-radius:8px;font-size:11px;line-height:1.6;background:rgba(255,77,106,.07);border:1px solid rgba(255,77,106,.28);color:var(--red)';
      resultEl.textContent = '✗ ' + (data.error || 'Withdrawal failed');
      btn.disabled = false; btn.textContent = 'CONFIRM WITHDRAW';
    }
  } catch(e) {
    const resultEl = document.getElementById('wd-result');
    resultEl.style.cssText = 'display:block;margin-bottom:14px;padding:10px 14px;border-radius:8px;font-size:11px;line-height:1.6;background:rgba(255,77,106,.07);border:1px solid rgba(255,77,106,.28);color:var(--red)';
    resultEl.textContent = '✗ Network error — please try again';
    btn.disabled = false; btn.textContent = 'CONFIRM WITHDRAW';
  }
}

// ── DEPOSIT SOL MODAL ──────────────────────────────────────────────────────
let _depQrWallet = null;

function openDepositModal() {
  if (!phantomKey) return;
  document.getElementById('deposit-modal').classList.add('open');
  document.getElementById('dep-addr-text').textContent = phantomKey;
  document.getElementById('dep-copy-msg').textContent = '';
  document.getElementById('dep-copy-btn').textContent = '📋';
  const qrEl = document.getElementById('dep-qr');
  qrEl.innerHTML = '<img src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=' + encodeURIComponent(phantomKey) + '" style="width:180px;height:180px;border-radius:4px" alt="QR code" onerror="this.parentElement.innerHTML=\'<p style=\\\'color:var(--muted);font-size:10px\\\'>QR unavailable</p>\'">';
}

function closeDepositModal() {
  document.getElementById('deposit-modal').classList.remove('open');
}

function copyDepositAddr() {
  if (!phantomKey) return;
  const copyFallback = () => {
    const ta = document.createElement('textarea');
    ta.value = phantomKey;
    ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch(_) {}
    document.body.removeChild(ta);
  };
  const done = () => {
    document.getElementById('dep-copy-msg').textContent = '✓ Copied to clipboard';
    document.getElementById('dep-copy-btn').textContent = '✓';
    setTimeout(() => {
      document.getElementById('dep-copy-msg').textContent = '';
      document.getElementById('dep-copy-btn').textContent = '📋';
    }, 2000);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(phantomKey).then(done).catch(() => { copyFallback(); done(); });
  } else {
    copyFallback(); done();
  }
}

// ── TIPS MODAL ───────────────────────────────────────────────────────────────
const _TIPS_DATA=[
  {icon:'🔄',color:'#9b6bff',title:'Two Ways to Trade',
   items:['🤖 <b>Auto Mode</b> — bot scans and trades automatically 24/7',
          '🖐️ <b>Manual Mode</b> — pick tokens from Live Market and buy/sell yourself'],
   note:'<span style="color:#ffffff;font-weight:700">Or use both at the same time!</span>'},
  {icon:'🤖',color:'#000000',title:'Auto Trading',
   items:['Bot scans 75+ tokens every 30 seconds',
          'Buys on momentum + volume + liquidity signals',
          'Sells at Take Profit or Stop Loss automatically']},
  {icon:'🖐️',color:'#00bfff',title:'Manual Trading',
   items:['Go to Live Solana Market on dashboard',
          'Press BUY on any token to instantly buy',
          'Press SELL to exit your position']},
  {icon:'⚙️',color:'#767676',title:'Bot Strategy (Auto)',
   items:['Bot strategy: TP +12% / SL -3% — 100% exit on both',
          'No configuration needed — strategy is fixed',
          'SL check runs before TP for capital preservation']},
  {icon:'💰',color:'#00d2b4',title:'Deposit SOL',
   items:['Minimum 0.05 SOL to trade',
          'Max 5 concurrent positions']},
  {icon:'🔒',color:'#ff1744',title:'Stay Safe',
   items:['Never share your private key',
          'Start with small trade sizes']},
];
let _tipsStep=0;

function openTipsModal(){
  _tipsStep=0;
  _renderTipsSlide();
  document.getElementById('tips-modal').classList.add('open');
}
function closeTipsModal(){
  localStorage.setItem('orcagent_tips_seen','1');
  document.getElementById('tips-modal').classList.remove('open');
}
function _renderTipsSlide(){
  const tip=_TIPS_DATA[_tipsStep];
  const total=_TIPS_DATA.length;
  const isLast=_tipsStep===total-1;
  document.getElementById('tips-counter').textContent=(_tipsStep+1)+' / '+total;
  document.getElementById('tips-dots').innerHTML=_TIPS_DATA.map((_,i)=>{
    let c='tips-dot'+(i<_tipsStep?' done':i===_tipsStep?' active':'');
    return '<div class="'+c+'" onclick="_tipJump('+i+')" title="Tip '+(i+1)+'"></div>';
  }).join('');
  const items=tip.items.map(t=>'<li class="tips-item">'+t+'</li>').join('');
  const note=tip.note?'<div class="tips-note">'+tip.note+'</div>':'';
  document.getElementById('tips-content').innerHTML=
    '<div class="tips-slide-icon">'+tip.icon+'</div>'+
    '<div class="tips-slide-title" style="color:'+tip.color+'">'+tip.title.toUpperCase()+'</div>'+
    '<ul class="tips-items">'+items+'</ul>'+note;
  document.getElementById('tips-prev-btn').disabled=_tipsStep===0;
  document.getElementById('tips-next-btn').textContent=isLast?'Start Trading! ▶':'Next →';
}
function _tipJump(i){_tipsStep=i;_renderTipsSlide();}
function tipsPrev(){if(_tipsStep>0){_tipsStep--;_renderTipsSlide();}}
function tipsNext(){
  if(_tipsStep<_TIPS_DATA.length-1){_tipsStep++;_renderTipsSlide();}
  else{closeTipsModal();}
}
(function _checkTipsOnLoad(){
  if(!localStorage.getItem('orcagent_tips_seen')) setTimeout(openTipsModal,600);
}());

// ── DIRECT MESSAGES ──
let _dmOpen=false, _dmPeerId=null, _dmPeerWallet='', _dmPeerUsername='',
    _dmRefreshTimer=null, _dmMyId=null, _dmConvos=[];

function _dmShort(w){ return w?w.slice(0,4)+'…'+w.slice(-4):''; }
function _dmInitials(name){ return name?name.slice(0,2).toUpperCase():'??'; }
function _dmRelTime(ts){
  if(!ts) return '';
  const d=new Date(ts+'Z'), now=Date.now(), diff=Math.round((now-d.getTime())/1000);
  if(diff<60) return diff+'s';
  if(diff<3600) return Math.floor(diff/60)+'m';
  if(diff<86400) return Math.floor(diff/3600)+'h';
  return Math.floor(diff/86400)+'d';
}

function _dmAvatarEl(container, wallet, username){
  const ini=_dmInitials(username||_dmShort(wallet));
  container.textContent=ini;
}

let _dmSearchTimer=null;
function _dmSearch(q){
  const drop=document.getElementById('dm-search-results');
  clearTimeout(_dmSearchTimer);
  if(!q.trim()){drop.style.display='none';drop.innerHTML='';return;}
  _dmSearchTimer=setTimeout(async()=>{
    try{
      const r=await fetch('/api/users/search?q='+encodeURIComponent(q.trim())).then(x=>x.json());
      if(!r.ok||!r.users.length){drop.style.display='none';drop.innerHTML='';return;}
      drop.innerHTML='';
      r.users.forEach(u=>{
        const ini=(u.username||u.wallet||'?').slice(0,2).toUpperCase();
        const short=u.wallet?u.wallet.slice(0,4)+'…'+u.wallet.slice(-4):'';
        const row=document.createElement('div');
        row.className='dm-search-row';
        row.innerHTML=`
          <div class="dm-search-av">${u.avatar_url?`<img src="${_esc(u.avatar_url)}" onerror="this.style.display='none';this.nextSibling.style.display=''"><span style="display:none">${_esc(ini)}</span>`:`<span>${_esc(ini)}</span>`}</div>
          <div class="dm-search-info">
            <div class="dm-search-name">${_esc(u.username||short)}</div>
            <div class="dm-search-wallet">${_esc(short)}</div>
          </div>`;
        row.onclick=()=>{
          document.getElementById('dm-search-input').value='';
          drop.style.display='none';drop.innerHTML='';
          openDMWith(u.user_id, u.wallet, u.username);
        };
        drop.appendChild(row);
      });
      drop.style.display='block';
    }catch(e){drop.style.display='none';}
  },220);
}

function openDMWith(peerId, peerWallet, peerUsername){
  if(!phantomKey){showLfToast('🔴','Connect wallet to use messages','neg');return;}
  closeTraderProfile();
  openMessagesView();
  dmOpenConvo(peerId, peerWallet, peerUsername||_dmShort(peerWallet));
}

function openMessagesView(){
  if(_dmOpen) return;
  _dmOpen=true;
  // Close any sub-view that may be active inside .wrap
  if(_tradersView) closeTradersView();
  // Hide .wrap entirely; messages lives outside it as a sibling
  const wrap=document.getElementById('main-content');
  if(wrap) wrap.style.display='none';
  const bn=document.getElementById('mob-bottom-nav');
  if(bn) bn.style.display='none';
  const _dmMsgEl=document.getElementById('dash-messages');
  _dmMsgEl.style.display='flex';
  _fadeIn(_dmMsgEl);
  _sbSetActive('sbn-messages');
  const btn=document.getElementById('messages-btn');
  if(btn){btn.style.borderColor='var(--green)';btn.style.color='var(--green)';btn.style.background='rgba(0,0,0,.08)';}
  _rrSetVisible(false);
  _dmSetUnreadBadge(0);
  dmLoadConversations();
  _dmRefreshTimer=setInterval(_dmAutoRefresh,5000);
}

function closeMessagesView(){
  if(!_dmOpen) return;
  _dmOpen=false;
  _dmPeerId=null;
  clearInterval(_dmRefreshTimer); _dmRefreshTimer=null;
  document.getElementById('dm-chat-placeholder').style.display='';
  document.getElementById('dm-chat-active').style.display='none';
  document.getElementById('dm-layout').classList.remove('convo-open');
  document.getElementById('dash-messages').style.display='none';
  const bn=document.getElementById('mob-bottom-nav');
  if(bn) bn.style.display='';
  // Restore .wrap and ensure only dash-main is visible
  const wrap=document.getElementById('main-content');
  if(wrap) wrap.style.display='';
  const _cmEl=document.getElementById('dash-main');
  _cmEl.style.display='';
  _fadeIn(_cmEl);
  document.getElementById('dash-traders').style.display='none';
  document.getElementById('dash-admin').style.display='none';
  _sbSetActive('sbn-dashboard');
  const btn=document.getElementById('messages-btn');
  if(btn){btn.style.borderColor='';btn.style.color='';btn.style.background='';}
  const si=document.getElementById('dm-search-input');
  const sd=document.getElementById('dm-search-results');
  if(si) si.value='';
  if(sd){sd.style.display='none';sd.innerHTML='';}
  _rrSetVisible(true);
}

function _hideAllViews(){
  document.getElementById('dash-main').style.display='none';
  document.getElementById('dash-traders').style.display='none';
  document.getElementById('dash-admin').style.display='none';
}

/* ── COMMUNITY CHAT ── */
let _gcOpen=false,_gcTimer=null,_gcMyId=null,_gcLastId=0,_gcPendingFile=null,_gcSendCooldown=false;

function openCommunityView(){
  if(_gcOpen) return;
  _gcOpen=true;
  if(_dmOpen) closeMessagesView();
  if(_tradersView) closeTradersView();
  const wrap=document.getElementById('main-content');
  if(wrap) wrap.style.display='none';
  const bn=document.getElementById('mob-bottom-nav');
  if(bn) bn.style.display='none';
  const _gcCommEl=document.getElementById('dash-community');
  _gcCommEl.style.display='flex';
  _fadeIn(_gcCommEl);
  _sbSetActive('sbn-community');
  _rrSetVisible(false);
  gcFetch(true);
  _gcTimer=setInterval(gcFetch,3000);
}

function closeCommunityView(){
  if(!_gcOpen) return;
  _gcOpen=false;
  clearInterval(_gcTimer); _gcTimer=null;
  gcCancelPreview();
  document.getElementById('dash-community').style.display='none';
  const bn=document.getElementById('mob-bottom-nav');
  if(bn) bn.style.display='';
  const wrap=document.getElementById('main-content');
  if(wrap) wrap.style.display='';
  const _ccMainEl=document.getElementById('dash-main');
  _ccMainEl.style.display='';
  _fadeIn(_ccMainEl);
  document.getElementById('dash-traders').style.display='none';
  document.getElementById('dash-admin').style.display='none';
  _sbSetActive('sbn-dashboard');
  _rrSetVisible(true);
}

function _gcRelTime(ts){
  if(!ts) return '';
  const d=new Date(ts.includes('T')?ts:ts+'Z');
  const diff=Math.round((Date.now()-d.getTime())/1000);
  if(diff<30) return 'just now';
  if(diff<3600) return Math.floor(diff/60)+'m ago';
  if(diff<86400) return Math.floor(diff/3600)+'h ago';
  return Math.floor(diff/86400)+'d ago';
}

function _gcUserColor(userId){
  const h=(userId*37)%360;
  return 'hsl('+h+',70%,60%)';
}

function _gcInitials(name){
  if(!name) return '?';
  return name.trim().split(/\s+/).map(w=>w[0]).join('').toUpperCase().slice(0,2)||'?';
}

async function gcFetch(reset){
  try{
    const r=await fetch('/api/chat').then(x=>x.json());
    if(!r.ok) return;
    const msgs=r.messages||[];
    if(msgs.length&&_gcMyId==null){
      const mine=msgs.find(m=>m.is_mine);
      if(mine) _gcMyId=mine.user_id;
    }
    const container=document.getElementById('gc-messages');
    const empty=document.getElementById('gc-empty');
    if(!msgs.length){
      if(empty) empty.style.display='flex';
      return;
    }
    if(empty) empty.style.display='none';
    const lastId=msgs[msgs.length-1].id;
    if(!reset&&lastId===_gcLastId) return;
    let newMsgs=[];
    if(reset||_gcLastId===0){
      container.innerHTML='';
      msgs.forEach(m=>container.appendChild(_gcBuildMsg(m)));
    } else {
      newMsgs=msgs.filter(m=>m.id>_gcLastId);
      newMsgs.forEach(m=>container.appendChild(_gcBuildMsg(m)));
    }
    _gcLastId=lastId;
    const unique=new Set(msgs.map(m=>m.user_id)).size;
    const oc=document.getElementById('gc-online-count');
    if(oc) oc.textContent=unique;
    const atBottom=container.scrollHeight-container.scrollTop-container.clientHeight<120;
    const newBtn=document.getElementById('gc-new-btn');
    if(atBottom||reset){
      container.scrollTop=container.scrollHeight;
      if(newBtn) newBtn.style.display='none';
    } else if(newMsgs.length>0){
      if(newBtn) newBtn.style.display='';
    }
  }catch(e){}
}

function _gcBuildMsg(m){
  const mine=!!m.is_mine;
  const wrap=document.createElement('div');
  wrap.className='gc-msg'+(mine?' mine':'');
  wrap.dataset.id=m.id;

  const av=document.createElement('div');
  av.className='gc-avatar';
  if(m.avatar_url){
    const img=document.createElement('img');
    img.src=m.avatar_url; img.alt='';
    img.onerror=()=>{ img.style.display='none'; };
    av.appendChild(img);
  } else {
    av.textContent=_gcInitials(m.username||m.wallet_address);
  }
  wrap.appendChild(av);

  const body=document.createElement('div');
  body.className='gc-body';

  const meta=document.createElement('div');
  meta.className='gc-meta';
  const uname=document.createElement('span');
  uname.className='gc-username';
  uname.textContent=m.username||(m.wallet_address?m.wallet_address.slice(0,8)+'…':'Unknown');
  uname.style.color=_gcUserColor(m.user_id);
  const ts=document.createElement('span');
  ts.className='gc-time';
  ts.textContent=_gcRelTime(m.created_at);
  meta.appendChild(uname);
  meta.appendChild(ts);
  body.appendChild(meta);

  if(m.message_type==='image'&&m.image_url&&m.image_url.startsWith('/static/chat_images/')){
    const img=document.createElement('img');
    img.className='gc-img'; img.src=m.image_url; img.alt='image';
    img.onclick=()=>window.open(m.image_url,'_blank');
    body.appendChild(img);
  } else if(m.message){
    const txt=document.createElement('div');
    txt.className='gc-text';
    txt.textContent=m.message;
    body.appendChild(txt);
  }
  wrap.appendChild(body);

  if(mine){
    const del=document.createElement('button');
    del.className='gc-del-btn'; del.title='Delete'; del.textContent='🗑';
    del.onclick=()=>gcDelete(m.id,wrap);
    wrap.appendChild(del);
  }
  return wrap;
}

function gcScrollToBottom(){
  const container=document.getElementById('gc-messages');
  if(container) container.scrollTop=container.scrollHeight;
  const newBtn=document.getElementById('gc-new-btn');
  if(newBtn) newBtn.style.display='none';
}

async function gcSend(){
  if(_gcSendCooldown) return;
  if(_gcPendingFile){ await _gcUploadAndSendImage(); return; }
  const inp=document.getElementById('gc-input');
  const text=(inp&&inp.value.trim())||'';
  if(!text) return;
  const btn=document.getElementById('gc-send-btn');
  if(btn) btn.disabled=true;
  _gcSendCooldown=true;
  try{
    const r=await fetch('/api/chat',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({message:text})
    }).then(x=>x.json());
    if(r.ok){
      inp.value=''; inp.style.height='';
      if(_gcMyId==null) _gcMyId=r.user_id;
      const container=document.getElementById('gc-messages');
      const empty=document.getElementById('gc-empty');
      if(empty) empty.style.display='none';
      container.appendChild(_gcBuildMsg(r));
      _gcLastId=r.id;
      gcScrollToBottom();
    } else {
      showTradeWarn('⚠️ '+(r.msg||'Send failed'));
    }
  }catch(e){ showTradeWarn('⚠️ Send failed'); }
  setTimeout(()=>{ _gcSendCooldown=false; if(btn) btn.disabled=false; if(inp) inp.focus(); },2000);
}

async function _gcUploadAndSendImage(){
  const file=_gcPendingFile;
  if(!file) return;
  const btn=document.getElementById('gc-send-btn');
  const imgBtn=document.getElementById('gc-img-btn');
  if(btn) btn.disabled=true;
  if(imgBtn){ imgBtn.innerHTML='<span class="dm-img-spinner"></span>'; imgBtn.classList.add('loading'); }
  _gcSendCooldown=true;
  try{
    const fd=new FormData();
    fd.append('image',file);
    const up=await fetch('/api/chat/upload-image',{method:'POST',body:fd}).then(x=>x.json());
    if(!up.ok){ showTradeWarn('⚠️ '+(up.msg||'Upload failed')); return; }
    const r=await fetch('/api/chat',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({message_type:'image',image_url:up.url})
    }).then(x=>x.json());
    if(r.ok){
      if(_gcMyId==null) _gcMyId=r.user_id;
      const container=document.getElementById('gc-messages');
      const empty=document.getElementById('gc-empty');
      if(empty) empty.style.display='none';
      container.appendChild(_gcBuildMsg(r));
      _gcLastId=r.id;
      gcScrollToBottom();
    } else {
      showTradeWarn('⚠️ '+(r.msg||'Failed to send image'));
    }
  }catch(e){ showTradeWarn('⚠️ Image send failed'); }
  finally{
    gcCancelPreview();
    if(imgBtn){ imgBtn.innerHTML='📷'; imgBtn.classList.remove('loading'); }
    setTimeout(()=>{ _gcSendCooldown=false; if(btn) btn.disabled=false; },2000);
  }
}

function gcPickImage(){
  const inp=document.getElementById('gc-img-input');
  if(inp){ inp.value=''; inp.click(); }
}

function gcSendImagePicked(file){
  if(!file) return;
  _gcPendingFile=file;
  const preview=document.getElementById('gc-img-preview');
  const thumb=document.getElementById('gc-img-preview-thumb');
  const name=document.getElementById('gc-img-preview-name');
  if(preview&&thumb&&name){
    thumb.src=URL.createObjectURL(file);
    name.textContent=file.name||'Image';
    preview.style.display='';
  }
  const inp=document.getElementById('gc-input');
  if(inp){ inp.disabled=true; inp.placeholder='Click SEND to send image…'; }
}

function gcCancelPreview(){
  _gcPendingFile=null;
  const preview=document.getElementById('gc-img-preview');
  if(preview) preview.style.display='none';
  const thumb=document.getElementById('gc-img-preview-thumb');
  if(thumb) thumb.src='';
  const inp=document.getElementById('gc-input');
  if(inp){ inp.disabled=false; inp.placeholder='Message the community…'; }
  const fileInp=document.getElementById('gc-img-input');
  if(fileInp) fileInp.value='';
}

async function gcDelete(msgId,el){
  try{
    const r=await fetch('/api/chat/'+msgId,{method:'DELETE'}).then(x=>x.json());
    if(r.ok){
      el.remove();
      const container=document.getElementById('gc-messages');
      if(container&&!container.querySelector('.gc-msg')){
        const empty=document.getElementById('gc-empty');
        if(empty) empty.style.display='flex';
      }
    }
  }catch(_){}
}

async function dmLoadConversations(){
  try{
    const r=await fetch('/api/messages').then(x=>x.json());
    if(!r.ok) return;
    _dmConvos=r.conversations||[];
    _dmRenderConvoList();
  }catch(e){}
}

function _dmRenderConvoList(){
  const list=document.getElementById('dm-convo-list');
  let empty=document.getElementById('dm-convo-empty');
  if(!empty){
    empty=document.createElement('div');
    empty.id='dm-convo-empty';
    empty.className='dm-empty-convo';
    empty.innerHTML='No conversations yet.<br>Message someone from their trader profile.';
  }
  if(!_dmConvos.length){
    list.innerHTML='';
    list.appendChild(empty);
    return;
  }
  // Detach empty before clearing innerHTML so getElementById finds it next time
  if(empty.parentNode) empty.parentNode.removeChild(empty);
  list.innerHTML='';
  _dmConvos.forEach(c=>{
    const div=document.createElement('div');
    div.className='dm-convo'+(c.peer_id===_dmPeerId?' active':'');
    div.dataset.peerId=c.peer_id;
    const name=c.peer_username||_dmShort(c.peer_wallet||'');
    div.innerHTML=`
      <div class="dm-convo-av" id="dm-cav-${c.peer_id}">${_dmInitials(name)}</div>
      <div class="dm-convo-info">
        <div class="dm-convo-name">${_esc(name)}</div>
        <div class="dm-convo-preview">${_esc((c.last_msg||'').slice(0,60))}</div>
      </div>
      <div class="dm-convo-meta">
        <div class="dm-convo-time">${_dmRelTime(c.last_ts)}</div>
        ${c.unread>0?`<div class="dm-unread-dot">${c.unread}</div>`:''}
      </div>`;
    div.onclick=()=>dmOpenConvo(c.peer_id, c.peer_wallet||'', c.peer_username||'');
    list.appendChild(div);
  });
}

async function dmOpenConvo(peerId, peerWallet, peerUsername){
  _dmPeerId=peerId;
  _dmPeerWallet=peerWallet;
  _dmPeerUsername=peerUsername||_dmShort(peerWallet);
  // Update active state on sidebar
  document.querySelectorAll('.dm-convo').forEach(el=>{
    el.classList.toggle('active', parseInt(el.dataset.peerId)===peerId);
  });
  // Show chat panel, hide placeholder
  document.getElementById('dm-chat-placeholder').style.display='none';
  const active=document.getElementById('dm-chat-active');
  active.style.display='flex';
  // Set header
  document.getElementById('dm-hdr-name').textContent=_dmPeerUsername;
  document.getElementById('dm-hdr-wallet').textContent=peerWallet;
  _dmAvatarEl(document.getElementById('dm-hdr-av'), peerWallet, _dmPeerUsername);
  // Mobile: show chat, hide sidebar
  document.getElementById('dm-layout').classList.add('convo-open');
  // Load messages
  await _dmFetchMessages();
}

function _esc(str){
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function _dmFetchMessages(){
  if(!_dmPeerId) return;
  const container=document.getElementById('dm-messages-area');
  let resp, rawText='';
  try{
    resp=await fetch('/api/messages/'+_dmPeerId);
    rawText=await resp.text();
    console.log('GET /api/messages/'+_dmPeerId+' status:',resp.status,'body:',rawText);
    let r;
    try{ r=JSON.parse(rawText); }
    catch(parseErr){
      console.error('JSON parse error:',parseErr,'raw:',rawText);
      container.innerHTML=`<div class="dm-chat-empty">Server error (${resp.status}) — check console</div>`;
      return;
    }
    if(!r.ok){
      console.error('GET /api/messages/'+_dmPeerId+' not ok — status:',resp.status,'body:',r);
      container.innerHTML=`<div class="dm-chat-empty">${_esc(r.msg||'Could not load messages ('+resp.status+')')}</div>`;
      return;
    }
    _dmRenderMessages(r.messages||[]);
    const convo=_dmConvos.find(c=>c.peer_id===_dmPeerId);
    if(convo) convo.unread=0;
    _dmRenderConvoList();
    _dmUpdateUnreadBadge();
  }catch(e){
    console.error('_dmFetchMessages exception:',e,'status:',(resp&&resp.status),'raw:',rawText);
    container.innerHTML=`<div class="dm-chat-empty">Could not load messages — ${_esc(String(e))}</div>`;
  }
}

function _dmBuildMessageEl(m, myId){
  const mine=myId!=null&&m.sender_id===myId;
  const isTradeShare=m.message_type==='trade_share'||
    (m.message&&m.message.startsWith('{"type":"trade_share"'));
  const div=document.createElement('div');
  if(isTradeShare){
    div.className='dm-msg '+(mine?'mine':'theirs')+' trade-share';
    let td={};
    try{ td=JSON.parse(m.message); }catch(_){}
    const sym=_esc(td.token_symbol||'???');
    const addr=td.token_address||'';
    const entry=td.entry_price!=null?('$'+Number(td.entry_price).toFixed(8)):'—';
    const amtSol=td.amount_sol!=null?(Number(td.amount_sol).toFixed(4)+' SOL'):'—';
    const pnl=td.pnl_pct!=null?td.pnl_pct:null;
    const closed=!!(td.exit_reason);
    const pnlHtml=pnl!=null
      ?`<span class="dm-trade-card-val ${pnl>=0?'pos':'neg'}">${pnl>=0?'+':''}${pnl.toFixed(2)}%</span>`
      :`<span class="dm-trade-card-val">—</span>`;
    const btnId='cp-btn-'+m.id+'_'+Date.now();
    const errId='cp-err-'+m.id+'_'+Date.now();
    div.innerHTML=`
      <div class="dm-trade-card${closed?' closed':''}">
        <div class="dm-trade-card-header">
          <span class="dm-trade-card-symbol">🟢 ${sym}</span>
          ${closed?'<span class="dm-trade-card-closed-badge">Trade Closed</span>':''}
        </div>
        <div class="dm-trade-card-rows">
          <div class="dm-trade-card-row">
            <span class="dm-trade-card-lbl">Entry</span>
            <span class="dm-trade-card-val">${entry}</span>
          </div>
          <div class="dm-trade-card-row">
            <span class="dm-trade-card-lbl">PnL</span>
            ${pnlHtml}
          </div>
          <div class="dm-trade-card-row">
            <span class="dm-trade-card-lbl">Size</span>
            <span class="dm-trade-card-val">${amtSol}</span>
          </div>
        </div>
        <button class="dm-copy-btn" id="${btnId}" ${closed||mine?'disabled':''} onclick="_dmCopyTrade(this,'${btnId}','${errId}',${JSON.stringify(addr)},${JSON.stringify(td.entry_price||0)},${JSON.stringify(td.amount_sol||0)})">
          ${closed?'Trade Closed':mine?'Your Trade':'⚡ Copy Trade'}
        </button>
        <div class="dm-copy-err" id="${errId}" style="display:none"></div>
      </div>
      <div class="dm-msg-time">${_dmRelTime(m.created_at)}</div>`;
  } else if(m.message_type==='image' && m.message && m.message.startsWith('/static/dm_images/')){
    div.className='dm-msg '+(mine?'mine':'theirs');
    const img=document.createElement('img');
    img.src=m.message;
    img.alt='Image';
    img.onclick=()=>window.open(m.message,'_blank');
    const bubble=document.createElement('div');
    bubble.className='dm-bubble dm-bubble-img';
    bubble.appendChild(img);
    const timeEl=document.createElement('div');
    timeEl.className='dm-msg-time';
    timeEl.textContent=_dmRelTime(m.created_at);
    div.appendChild(bubble);
    div.appendChild(timeEl);
  } else {
    div.className='dm-msg '+(mine?'mine':'theirs');
    div.innerHTML=`<div class="dm-bubble" id="dm-bubble-${m.id}">${_esc(m.message)}</div><div class="dm-msg-time">${_dmRelTime(m.created_at)}${m.edited_at?'<span class="dm-edited">(edited)</span>':''}</div>`;
  }
  if(mine && m.id){
    if(m.message_type==='text'||!m.message_type){
      const editBtn=document.createElement('button');
      editBtn.className='dm-edit-btn';
      editBtn.title='Edit message';
      editBtn.textContent='✏';
      editBtn.onclick=()=>_dmEditMsg(m.id, div);
      div.appendChild(editBtn);
    }
    const delBtn=document.createElement('button');
    delBtn.className='dm-del-btn';
    delBtn.title='Delete message';
    delBtn.textContent='🗑';
    delBtn.onclick=()=>_dmDeleteMsg(m.id, div);
    div.appendChild(delBtn);
  }
  return div;
}

async function _dmDeleteMsg(msgId, msgEl){
  try{
    const resp=await fetch('/api/messages/'+msgId,{method:'DELETE'});
    const r=await resp.json();
    if(r.ok) msgEl.remove();
  }catch(_){}
}

async function _dmEditMsg(msgId, msgEl){
  const bubble=document.getElementById('dm-bubble-'+msgId);
  if(!bubble) return;
  const orig=bubble.textContent;
  const inp=document.createElement('input');
  inp.type='text';
  inp.value=orig;
  inp.style.cssText='width:100%;background:transparent;border:none;outline:none;color:inherit;font:inherit;padding:0';
  bubble.innerHTML='';
  bubble.appendChild(inp);
  inp.focus(); inp.select();
  let saved=false;
  async function save(){
    if(saved) return; saved=true;
    const newText=inp.value.trim();
    if(!newText||newText===orig){ bubble.innerHTML=_esc(orig); return; }
    try{
      const r=await fetch('/api/messages/'+msgId,{
        method:'PUT',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({message:newText})
      }).then(r=>r.json());
      if(r.ok){
        bubble.textContent=r.message;
        const timeEl=msgEl.querySelector('.dm-msg-time');
        if(timeEl&&!timeEl.querySelector('.dm-edited')){
          const ed=document.createElement('span');
          ed.className='dm-edited'; ed.textContent='(edited)';
          timeEl.appendChild(ed);
        }
      } else { bubble.innerHTML=_esc(orig); }
    }catch(_){ bubble.innerHTML=_esc(orig); }
  }
  inp.addEventListener('keydown',e=>{
    if(e.key==='Enter'){e.preventDefault();inp.blur();}
    if(e.key==='Escape'){saved=true;bubble.innerHTML=_esc(orig);}
  });
  inp.addEventListener('blur',save);
}

const _EMOJI_PALETTE_EMOJIS=['😀','😂','😍','🥰','😢','😮','😎','🤔','😤','🔥','❤️','💯','👍','👎','🚀','💰','📈','📉','⚡','🎯','💎','🏆','🌙','💀','🤝','👀','🙏','✅','❌','⚠️'];
function _emojiPickerToggle(e, palId, inputId){
  e.stopPropagation();
  var pal=typeof palId==='string'?document.getElementById(palId):palId;
  var inp=typeof inputId==='string'?document.getElementById(inputId):inputId;
  if(!pal) return;
  var wasOpen=pal.style.display==='grid';
  document.querySelectorAll('.ep-palette,.fc-react-palette').forEach(function(p){ p.style.display='none'; });
  if(wasOpen) return;
  if(!pal.childElementCount){
    _EMOJI_PALETTE_EMOJIS.forEach(function(emoji){
      var b=document.createElement('button');
      b.textContent=emoji;
      b.onclick=function(ev){
        ev.stopPropagation();
        if(inp){
          var s=inp.selectionStart,en=inp.selectionEnd,v=inp.value;
          inp.value=v.slice(0,s)+emoji+v.slice(en);
          var pos=s+[...emoji].length;
          inp.setSelectionRange(pos,pos);
          inp.focus();
        }
      };
      pal.appendChild(b);
    });
  }
  // Escape overflow:hidden clipping by reparenting to body and using position:fixed
  var btn=e.currentTarget||e.target;
  var rect=btn.getBoundingClientRect();
  document.body.appendChild(pal);
  pal.style.position='fixed';
  pal.style.right='auto';
  pal.style.bottom='auto';
  pal.style.visibility='hidden';
  pal.style.display='grid';
  var pw=pal.offsetWidth, ph=pal.offsetHeight;
  var left=Math.max(4,Math.min(rect.left+rect.width/2-pw/2, window.innerWidth-pw-4));
  var top=rect.top-ph-8;
  if(top<4) top=rect.bottom+8;
  pal.style.left=left+'px';
  pal.style.top=top+'px';
  pal.style.visibility='';
}
document.addEventListener('click',function(){
  document.querySelectorAll('.ep-palette,.fc-react-palette').forEach(function(p){ p.style.display='none'; });
});

async function _dmCopyTrade(btn, btnId, errId, tokenAddr, entryPrice, amtSol){
  const errEl=document.getElementById(errId);
  btn.disabled=true;
  btn.textContent='Entering trade...';
  if(errEl){ errEl.style.display='none'; errEl.textContent=''; }
  try{
    const resp=await fetch('/api/trades/copy-from-message',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({token_address:tokenAddr,entry_price:entryPrice,amount_sol:amtSol})
    });
    const r=await resp.json();
    if(r.ok){
      btn.textContent='✓ In Trade!';
      btn.classList.add('success');
    } else {
      btn.textContent='⚡ Copy Trade';
      btn.disabled=false;
      if(errEl){ errEl.textContent=r.msg||'Copy failed'; errEl.style.display='block'; }
    }
  }catch(e){
    btn.textContent='⚡ Copy Trade';
    btn.disabled=false;
    if(errEl){ errEl.textContent='Request failed — try again'; errEl.style.display='block'; }
  }
}

function _dmRenderMessages(msgs){
  const container=document.getElementById('dm-messages-area');
  if(!msgs.length){
    container.innerHTML='<div class="dm-chat-empty"><div style="font-size:28px">💬</div><div>No messages yet — say hello!</div></div>';
    return;
  }
  const myId=_dmMyId;
  container.innerHTML='';
  msgs.forEach(m=>container.appendChild(_dmBuildMessageEl(m, myId)));
  container.scrollTop=container.scrollHeight;
}

function _dmAppendMessage(m){
  const container=document.getElementById('dm-messages-area');
  const empty=container.querySelector('.dm-chat-empty');
  if(empty) container.removeChild(empty);
  container.appendChild(_dmBuildMessageEl(m, _dmMyId));
  container.scrollTop=container.scrollHeight;
}

async function dmSend(){
  const input=document.getElementById('dm-input');
  const text=input.value.trim();
  if(!text||!_dmPeerId) return;
  const btn=document.getElementById('dm-send-btn');
  btn.disabled=true; btn.textContent='…';
  try{
    const resp=await fetch('/api/messages/'+_dmPeerId,{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({message:text})
    });
    const r=await resp.json();
    if(r.ok){
      input.value='';
      input.style.height='';
      _dmAppendMessage({sender_id:_dmMyId, message:text, created_at:r.created_at||new Date().toISOString()});
      _dmFetchMessages();
      showLfToast('💬','Message sent','pos');
    } else {
      console.error('POST /api/messages/'+_dmPeerId+' failed — status:',resp.status,'body:',r);
      showTradeWarn('⚠️ '+(r.msg||'Failed to send'));
    }
  }catch(e){
    console.error('dmSend exception:',e);
    showTradeWarn('⚠️ Send failed');
  }
  btn.disabled=false; btn.textContent='SEND';
  input.focus();
}

function dmPickImage(){
  if(!_dmPeerId) return;
  const inp=document.getElementById('dm-img-input');
  if(inp){ inp.value=''; inp.click(); }
}

async function dmSendImage(file){
  if(!file||!_dmPeerId) return;
  const btn=document.getElementById('dm-img-btn');
  if(btn){ btn.innerHTML='<span class="dm-img-spinner"></span>'; btn.classList.add('loading'); }
  try{
    const fd=new FormData();
    fd.append('image', file);
    const upResp=await fetch('/api/messages/upload-image',{method:'POST',body:fd});
    const upData=await upResp.json();
    if(!upData.ok){
      showTradeWarn('⚠️ '+(upData.msg||'Upload failed'));
      return;
    }
    const url=upData.url;
    const sendResp=await fetch('/api/messages/'+_dmPeerId,{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({message:url, message_type:'image'})
    });
    const r=await sendResp.json();
    if(r.ok){
      _dmAppendMessage({sender_id:_dmMyId, message:url, message_type:'image',
                        id:r.message_id, created_at:r.created_at||new Date().toISOString()});
      _dmFetchMessages();
    } else {
      showTradeWarn('⚠️ '+(r.msg||'Failed to send image'));
    }
  }catch(e){
    showTradeWarn('⚠️ Image send failed');
  }finally{
    if(btn){ btn.innerHTML='📷'; btn.classList.remove('loading'); }
    const inp=document.getElementById('dm-img-input');
    if(inp) inp.value='';
  }
}

function _dmBackToList(){
  _dmPeerId=null;
  document.getElementById('dm-layout').classList.remove('convo-open');
  document.getElementById('dm-chat-placeholder').style.display='';
  document.getElementById('dm-chat-active').style.display='none';
}

async function _dmAutoRefresh(){
  if(!_dmOpen) return;
  // Refresh unread count always
  await dmFetchUnread();
  // Refresh active conversation messages
  if(_dmPeerId) await _dmFetchMessages();
  else await dmLoadConversations();
}

async function dmFetchUnread(){
  if(!phantomKey) return;
  try{
    const [r1,r2]=await Promise.all([
      fetch('/api/messages/unread').then(x=>x.json()).catch(()=>({ok:false,unread:0})),
      fetch('/api/messages/unread_count').then(x=>x.json()).catch(()=>({count:0}))
    ]);
    _dmSetUnreadBadge((r1.ok?r1.unread||0:0)+(r2.count||0));
  }catch(e){}
}

function _dmSetUnreadBadge(n){
  [document.getElementById('nav-msg-badge'),
   document.getElementById('sb-msg-badge'),
   document.getElementById('mn-msg-badge')].forEach(el=>{
    if(!el) return;
    el.textContent=n>99?'99+':n||'';
    el.style.display=n>0?'inline-block':'none';
  });
}

function _dmUpdateUnreadBadge(){
  const total=_dmConvos.reduce((s,c)=>s+(c.unread||0),0);
  _dmSetUnreadBadge(total);
}

// Poll unread count on every page, even outside messages view
setInterval(dmFetchUnread, 30000);

// ── PROFILE COMMENTS ──
let _tvcCurrentUserId=null, _tvcCanComment=false, _tvcIsSelf=false;

async function _tvcLoadComments(profileUserId, canComment, isSelf){
  _tvcCurrentUserId=profileUserId;
  _tvcCanComment=!!canComment;
  _tvcIsSelf=!!isSelf;
  const sec=document.getElementById('tvp-comments-section');
  if(!sec) return;
  sec.innerHTML='<div class="tvp-comments-hdr">💬 Comments</div><div class="tvp-comments-empty">Loading…</div>';
  try{
    const r=await fetch('/api/comments/'+profileUserId).then(x=>x.json());
    if(!r.ok) throw new Error(r.msg||'failed');
    _tvcRender(r.comments||[], profileUserId, canComment, isSelf);
  }catch(e){
    sec.innerHTML='<div class="tvp-comments-hdr">💬 Comments</div><div class="tvp-comments-empty">Could not load comments.</div>';
  }
}

function _tvcRender(comments, profileUserId, canComment, isSelf){
  const sec=document.getElementById('tvp-comments-section');
  if(!sec) return;
  const myId=_myProfileId;
  const countStr=comments.length?'('+comments.length+')':'';
  let h=`<div class="tvp-comments-hdr">💬 Comments <span style="font-size:9px;color:var(--muted);font-family:'Share Tech Mono',monospace;font-weight:400">${countStr}</span></div>`;
  if(canComment){
    h+=`<div class="tvp-comment-input-row">
      <textarea class="tvp-comment-input" id="tvp-comment-input" placeholder="Write a comment… (max 280 chars)" rows="2" maxlength="280"
        onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();_tvcPost(${profileUserId})}"></textarea>
      <button class="tvp-comment-post-btn" id="tvp-comment-post-btn" onclick="_tvcPost(${profileUserId})">POST</button>
    </div>`;
  }
  h+='<div class="tvp-comments-list">';
  if(!comments.length){
    h+='<div class="tvp-comments-empty">No comments yet'+(canComment?' — be the first!':'')+'</div>';
  } else {
    comments.forEach(c=>{
      const name=c.author_username||_dmShort(c.author_wallet||'');
      const ini=_dmInitials(name);
      const canDel=myId&&(c.author_id===myId||isSelf);
      const delBtn=canDel?`<button class="tvp-comment-del" onclick="_tvcDelete(${c.id})" title="Delete">🗑</button>`:'';
      h+=`<div class="tvp-comment-card" id="tvpc-${c.id}">
        <div class="tvp-comment-av">${esc(ini)}</div>
        <div class="tvp-comment-body">
          <div class="tvp-comment-meta">
            <span class="tvp-comment-author">${esc(name)}</span>
            <span class="tvp-comment-time">${_dmRelTime(c.created_at)}</span>
            ${delBtn}
          </div>
          <div class="tvp-comment-text">${esc(c.message)}</div>
        </div>
      </div>`;
    });
  }
  h+='</div>';
  sec.innerHTML=h;
}

async function _tvcPost(profileUserId){
  const input=document.getElementById('tvp-comment-input');
  const btn=document.getElementById('tvp-comment-post-btn');
  if(!input) return;
  const text=input.value.trim();
  if(!text) return;
  btn.disabled=true;
  try{
    const r=await fetch('/api/comments/'+profileUserId,{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({message:text})
    }).then(x=>x.json());
    if(r.ok){
      input.value='';
      await _tvcLoadComments(profileUserId, _tvcCanComment, _tvcIsSelf);
    } else {
      let errEl=document.getElementById('tvp-comment-err');
      if(!errEl){errEl=document.createElement('div');errEl.id='tvp-comment-err';errEl.className='tvp-comment-err';input.parentNode.after(errEl);}
      errEl.textContent=r.msg||'Failed to post';
      setTimeout(()=>errEl.remove(),3000);
    }
  }catch(e){}
  if(btn) btn.disabled=false;
}

async function _tvcDelete(commentId){
  const card=document.getElementById('tvpc-'+commentId);
  if(card) card.style.opacity='.35';
  try{
    const r=await fetch('/api/comments/'+commentId,{method:'DELETE'}).then(x=>x.json());
    if(r.ok){
      if(card) card.remove();
      const list=document.querySelector('#tvp-comments-section .tvp-comments-list');
      if(list&&!list.querySelector('.tvp-comment-card')){
        list.innerHTML='<div class="tvp-comments-empty">No comments yet'+(phantomKey?' — be the first!':'')+'</div>';
      }
    } else {
      if(card) card.style.opacity='';
    }
  }catch(e){ if(card) card.style.opacity=''; }
}

// ── TOKEN DETAIL PANEL ──
document.addEventListener('DOMContentLoaded', function(){
  const panel   = document.getElementById('token-detail-panel');
  const overlay = document.getElementById('tdp-overlay');
  if(!panel) return;

  let _tdpAddr = '', _tdpSym = '';

  function _fmt(n){
    if(n==null||isNaN(n)) return '—';
    if(n>=1e9)  return '$'+(n/1e9).toFixed(2)+'B';
    if(n>=1e6)  return '$'+(n/1e6).toFixed(2)+'M';
    if(n>=1e3)  return '$'+(n/1e3).toFixed(1)+'K';
    return '$'+n.toFixed(2);
  }
  function _price(p){
    if(p==null||isNaN(p)) return '—';
    if(p<0.000001) return '$'+p.toExponential(3);
    if(p<0.01)     return '$'+p.toFixed(8);
    if(p<1)        return '$'+p.toFixed(4);
    return '$'+p.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
  }
  function _badge(val, lbl){
    const cls = val>0?'pos':val<0?'neg':'flat';
    const sign = val>0?'+':'';
    return `<span class="tdp-badge ${cls}"><span class="tdp-badge-lbl">${lbl}</span>${sign}${Number(val).toFixed(2)}%</span>`;
  }

  window.openTokenPanel = async function(addr){
    if(!panel) return;
    _tdpAddr = addr; _tdpSym = '';
    // reset loading state
    document.getElementById('tdp-name').textContent     = addr.slice(0,8)+'…';
    document.getElementById('tdp-symbol-lbl').textContent = '';
    document.getElementById('tdp-loading').style.display = '';
    document.getElementById('tdp-error').style.display   = 'none';
    document.getElementById('tdp-content').style.display = 'none';
    document.getElementById('tdp-trade-error').style.display = 'none';
    document.getElementById('tdp-position-info').classList.remove('visible');
    document.getElementById('tdp-sell-btn').style.display = 'none';
    const buyBtn = document.getElementById('tdp-buy-btn');
    buyBtn.disabled = false; buyBtn.textContent = 'BUY';
    // reset hero visuals
    const bannerBg = document.getElementById('tdp-banner-bg');
    if(bannerBg) bannerBg.style.backgroundImage = '';
    const logo = document.getElementById('tdp-logo');
    logo.classList.remove('loaded'); logo.src = '';
    const logoFb = document.getElementById('tdp-logo-fallback');
    if(logoFb){ logoFb.textContent='?'; logoFb.classList.remove('hidden'); }
    const twBtn = document.getElementById('tdp-twitter-btn');
    if(twBtn) twBtn.classList.remove('visible');
    const dexBadge = document.getElementById('tdp-dex-badge');
    if(dexBadge){ dexBadge.textContent=''; dexBadge.classList.remove('visible'); }
    document.getElementById('tdp-dex-btn').href = 'https://dexscreener.com/solana/'+addr;
    panel.classList.add('open');
    if(overlay) overlay.classList.add('open');
    document.body.style.overflow = 'hidden';
    try{
      const res  = await fetch('/api/token/info/'+encodeURIComponent(addr));
      const data = await res.json();
      if(!data.ok) throw new Error(data.msg||'Not found');
      _tdpSym = data.symbol || '';
      // hero: name + symbol + chain/dex badges
      document.getElementById('tdp-name').textContent       = data.name || _tdpSym || addr.slice(0,10);
      document.getElementById('tdp-symbol-lbl').textContent = _tdpSym;
      if(data.dex_name && dexBadge){
        dexBadge.textContent = data.dex_name;
        dexBadge.classList.add('visible');
      }
      // banner
      if(data.banner_url && bannerBg)
        bannerBg.style.backgroundImage = 'url('+JSON.stringify(data.banner_url)+')';
      // logo / fallback letter
      const imgUrl = data.logo_url || data.image_url;
      if(imgUrl){
        logo.onload  = ()=>{ logo.classList.add('loaded'); if(logoFb) logoFb.classList.add('hidden'); };
        logo.onerror = ()=>{ logo.src=''; if(logoFb){ logoFb.textContent=(_tdpSym||'?')[0].toUpperCase(); logoFb.classList.remove('hidden'); } };
        if(logoFb) logoFb.classList.add('hidden');
        logo.src = imgUrl;
      } else {
        if(logoFb){ logoFb.textContent=(_tdpSym||'?')[0].toUpperCase(); }
      }
      // twitter
      if(data.twitter_url && twBtn){
        twBtn.href = data.twitter_url;
        twBtn.classList.add('visible');
      }
      // price
      document.getElementById('tdp-price').textContent = _price(data.price_usd ?? data.price);
      const pSol = data.price_sol;
      document.getElementById('tdp-price-sol').textContent =
        pSol ? '◎ '+Number(pSol).toFixed(pSol<0.0001?8:pSol<0.01?6:4) : '';
      // % changes
      const pc = data.price_change || {};
      const chg = (v,l) => {
        const n=Number(v??0), cls=n>0?'pos':n<0?'neg':'flat', sign=n>0?'+':'';
        return `<div class="tdp-chg-cell"><div class="tdp-chg-lbl">${l}</div><div class="tdp-chg-val ${cls}">${sign}${n.toFixed(2)}%</div></div>`;
      };
      document.getElementById('tdp-changes').innerHTML =
        chg(pc.m5,'5M')+chg(pc.h1,'1H')+chg(pc.h6,'6H')+chg(pc.h24,'24H');
      // market stats
      const stat = (l,v) => `<div class="tdp-stat"><div class="tdp-stat-lbl">${l}</div><div class="tdp-stat-val">${v}</div></div>`;
      document.getElementById('tdp-stats').innerHTML =
        stat('Mkt Cap', _fmt(data.market_cap))+
        stat('FDV',     _fmt(data.fdv))+
        stat('Liquidity',_fmt(data.liquidity_usd));
      // activity
      const n = v => v!=null?Number(v).toLocaleString():'—';
      const act = (l,v,cls='') => `<div class="tdp-act"><div class="tdp-act-lbl">${l}</div><div class="tdp-act-val${cls?' '+cls:''}">${v}</div></div>`;
      const b5=data.txns_5m_buys, s5=data.txns_5m_sells;
      const b1=data.txns_1h_buys, s1=data.txns_1h_sells;
      const txns24=data.txns_24h, buyers=data.buyers_24h, sellers=data.sellers_24h;
      document.getElementById('tdp-activity').innerHTML =
        act('Txns 24h',  n(txns24))+
        act('Buys 24h',  n(buyers),'buy')+
        act('Sells 24h', n(sellers),'sell')+
        act('Vol 24h',   _fmt(data.volume_24h))+
        act('Vol 1h',    _fmt(data.volume_1h))+
        act('Vol 5m',    _fmt(data.volume_5m))+
        act('Buys 1h',   n(b1),'buy')+
        act('Sells 1h',  n(s1),'sell')+
        act('B/S 5m',    b5!=null&&s5!=null?n(b5)+'/'+n(s5):'—');
      if(data.dexscreener_url)
        document.getElementById('tdp-dex-btn').href = data.dexscreener_url;
      document.getElementById('tdp-loading').style.display = 'none';
      document.getElementById('tdp-content').style.display = '';
      window._tdpRefreshPosition();
    } catch(err){
      document.getElementById('tdp-loading').style.display = 'none';
      const el = document.getElementById('tdp-error');
      el.textContent = 'Failed to load: '+err.message;
      el.style.display = '';
    }
  };

  window._tdpRefreshPosition = async function(){
    const addr = _tdpAddr;
    if(!addr) return;
    const posInfo = document.getElementById('tdp-position-info');
    const sellBtn = document.getElementById('tdp-sell-btn');
    try{
      const res  = await fetch('/api/trade/position/'+encodeURIComponent(addr));
      const data = await res.json();
      if(data.ok && data.has_position){
        const amt  = Number(data.amount||0);
        const ep   = Number(data.entry_price||0);
        const pnl  = data.current_pnl!=null ? Number(data.current_pnl) : null;
        const pct  = (pnl!=null && ep>0 && amt>0) ? (pnl/(ep*amt)*100) : null;
        const pnlHtml = pct!=null
          ? ` | PnL: <strong style="color:${pct>=0?'#00e676':'#ff1744'}">${pct>=0?'+':''}${pct.toFixed(2)}%</strong>`
          : '';
        posInfo.innerHTML = `Position: <strong style="color:#fff">${amt.toFixed(4)} tokens</strong>`+
          ` | Entry: <strong style="color:#fff">$${ep<0.01?ep.toFixed(8):ep.toFixed(4)}</strong>`+pnlHtml;
        posInfo.classList.add('visible');
        sellBtn.style.display = '';
      } else {
        posInfo.innerHTML = '';
        posInfo.classList.remove('visible');
        sellBtn.style.display = 'none';
      }
    } catch(e){}
  };

  window._tdpBuy = async function(){
    const addr = _tdpAddr, sym = _tdpSym;
    if(!addr) return;
    const btn   = document.getElementById('tdp-buy-btn');
    const errEl = document.getElementById('tdp-trade-error');
    btn.disabled = true; btn.textContent = 'Buying…';
    errEl.style.display = 'none';
    try{
      const res  = await fetch('/api/trade/buy',{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({token_address:addr,token_symbol:sym})
      });
      const data = await res.json();
      if(!data.ok) throw new Error(data.msg||'Buy failed');
      btn.textContent = '✓ Bought!';
      await window._tdpRefreshPosition();
      setTimeout(()=>{ btn.disabled=false; btn.textContent='BUY'; }, 2500);
    } catch(e){
      errEl.textContent = e.message; errEl.style.display = '';
      btn.disabled = false; btn.textContent = 'BUY';
    }
  };

  window._tdpSell = async function(){
    const addr = _tdpAddr, sym = _tdpSym;
    if(!addr) return;
    const btn   = document.getElementById('tdp-sell-btn');
    const errEl = document.getElementById('tdp-trade-error');
    btn.disabled = true; btn.textContent = 'Selling…';
    errEl.style.display = 'none';
    try{
      const res  = await fetch('/api/trade/sell',{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({token_address:addr,token_symbol:sym})
      });
      const data = await res.json();
      if(!data.ok) throw new Error(data.msg||'Sell failed');
      btn.textContent = '✓ Sold!';
      await window._tdpRefreshPosition();
      setTimeout(()=>{ btn.disabled=false; btn.textContent='SELL'; }, 2500);
    } catch(e){
      errEl.textContent = e.message; errEl.style.display = '';
      btn.disabled = false; btn.textContent = 'SELL';
    }
  };

  window.closeTokenPanel = function(){
    if(!panel) return;
    panel.classList.remove('open');
    if(overlay) overlay.classList.remove('open');
    document.body.style.overflow='';
  };

  document.addEventListener('keydown', function(e){
    if(e.key==='Escape' && panel.classList.contains('open')) window.closeTokenPanel();
  });
});

// ── HEADER SEARCH ──
(function(){
  const inp = document.getElementById('hdr-search-input');
  const dd  = document.getElementById('hdr-search-dropdown');
  if(!inp || !dd) return;

  let _st = null;

  function _e(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
  function _short(a){ return a.length>14 ? a.slice(0,5)+'…'+a.slice(-4) : a; }
  function _avHtml(u){
    const ini=_e((u.username||'?')[0].toUpperCase());
    if(u.avatar_url)
      return `<div class="hdr-sd-avatar"><img src="${_e(u.avatar_url)}" onerror="this.style.display='none';this.nextSibling.style.cssText='display:flex;width:100%;height:100%;align-items:center;justify-content:center'"><span style="display:none">${ini}</span></div>`;
    return `<div class="hdr-sd-avatar">${ini}</div>`;
  }
  function closeDD(){ dd.classList.remove('open'); dd.innerHTML=''; }
  window._hdrCloseDD = closeDD;

  async function doSearch(q){
    // Parallel fetch traders + tokens
    const [trRes, tkRes] = await Promise.allSettled([
      fetch('/api/users/search?q='+encodeURIComponent(q)).then(x=>x.json()),
      fetch('/api/tokens/search?q='+encodeURIComponent(q)).then(x=>x.json()),
    ]);

    let traders = (trRes.status==='fulfilled' && trRes.value?.ok) ? (trRes.value.users||[]).slice(0,5) : [];
    let tokens  = (tkRes.status==='fulfilled' && tkRes.value?.ok) ? (tkRes.value.tokens||[]).slice(0,5) : [];

    // Contract address fallback if token search returned nothing
    if(!tokens.length && q.length>20 && /^[1-9A-HJ-NP-Za-km-z]+$/.test(q))
      tokens.push({address:q, symbol:'CONTRACT', name:q, price:null});

    if(!traders.length && !tokens.length){
      dd.innerHTML=`<div class="hdr-sd-empty">No results for "${_e(q)}"</div>`;
      dd.classList.add('open');
      return;
    }

    let html='';
    if(traders.length){
      html+='<div class="hdr-sd-section"><div class="hdr-sd-label">Traders</div>';
      for(const u of traders)
        html+=`<a class="hdr-sd-item" href="/trader/${_e(u.user_id)}">${_avHtml(u)}<div style="min-width:0;flex:1"><div class="hdr-sd-name">${_e(u.username||'Unknown')}</div><div class="hdr-sd-sub">${_e(_short(u.wallet||''))}</div></div></a>`;
      html+='</div>';
    }
    if(traders.length && tokens.length) html+='<div class="hdr-sd-sep"></div>';
    if(tokens.length){
      html+='<div class="hdr-sd-section"><div class="hdr-sd-label">Tokens</div>';
      for(const t of tokens){
        const addr=t.address||t.mint||'';
        const pVal=t.price!=null?Number(t.price):null;
        const priceStr=pVal!=null?(pVal<0.01?pVal.toFixed(8):pVal<1?pVal.toFixed(4):pVal.toFixed(2)):'';
        const chg=t.price_change_24h!=null?Number(t.price_change_24h):null;
        const chgHtml=chg!=null?`<span style="color:${chg>=0?'#00e676':'#ff1744'};font-size:10px">${chg>=0?'+':''}${chg.toFixed(1)}%</span>`:'';
        html+=`<div class="hdr-sd-item" onclick="window.openTokenPanel&&window.openTokenPanel('${addr}');if(window._hdrCloseDD)window._hdrCloseDD();" style="cursor:pointer">
          <div style="min-width:0;flex:1">
            <div class="hdr-sd-name"><strong>${_e(t.symbol||'?')}</strong>${t.name&&t.name!==t.symbol?` <span style="color:#555555;font-size:11px;font-weight:400">${_e(t.name)}</span>`:''}${priceStr?` <span style="color:#00e676;font-size:11px">$${_e(priceStr)}</span>`:''}</div>
            <div class="hdr-sd-sub" style="display:flex;justify-content:space-between;align-items:center">${_e(_short(addr))}${chgHtml}</div>
          </div></div>`;
      }
      html+='</div>';
    }
    dd.innerHTML=html;
    dd.classList.add('open');
  }

  inp.addEventListener('keyup', function(e){
    if(e.key==='Escape'){ closeDD(); inp.blur(); return; }
    if(e.key==='Enter'){
      const q=inp.value.trim();
      if(!q) return;
      if(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(q)){ closeDD(); openTokenPanel(q); return; }
      const m=(_marketTokens||[]).find(t=>(t.symbol||'').toLowerCase()===q.toLowerCase());
      if(m?.mint){ closeDD(); openTokenPanel(m.mint); return; }
      return;
    }
    const q=inp.value.trim();
    if(q.length<2){ closeDD(); return; }
    clearTimeout(_st);
    _st=setTimeout(()=>doSearch(q), 220);
  });

  document.addEventListener('click', function(e){
    if(!inp.closest('.hdr-search-wrap').contains(e.target)) closeDD();
  });
})();

/* ── FEED TAB SWITCHER ── */
var _tokenSearchBound=false
function tagToken(){
  document.getElementById('tokenModal').style.display='flex'
  const inp=document.getElementById('tokenSearch')
  if(inp){
    inp.value=''
    document.getElementById('tokenResults').innerHTML=''
    inp.focus()
    if(!_tokenSearchBound){
      _tokenSearchBound=true
      inp.addEventListener('input',function(){
        const q=this.value
        console.log('searching:',q)
        if(q.length<1) return
        fetch('/api/market/tokens?q='+encodeURIComponent(q))
        .then(r=>r.json())
        .then(d=>{
          console.log('results:',d)
          const el=document.getElementById('tokenResults')
          el.innerHTML=d.length?d.map(t=>`
          <div onclick="selectToken('${t.symbol}')" style="padding:10px;border-radius:8px;cursor:pointer;color:#eef1f5;background:#0a0b0e;margin-top:4px">
            <span style="color:#f7b955;font-weight:700">$${t.symbol}</span>
          </div>`).join(''):'<div style="color:#565d68;padding:10px">No tokens found</div>'
        })
      })
    }
  }
}

function searchToken(q){
  if(q.length<1) return
  fetch('/api/market/tokens?q='+encodeURIComponent(q))
  .then(r=>r.json()).then(d=>{
    document.getElementById('tokenResults').innerHTML=d.length?
    d.map(t=>`<div onclick="selectToken('${t.symbol}','${t.mint}')" style="padding:10px;cursor:pointer;border-bottom:1px solid #16191f">
      <div style="color:#f7b955;font-weight:700">$${t.symbol}</div>
      <div style="color:#565d68;font-size:11px;font-family:monospace">${t.mint}</div>
    </div>`).join('')
    :'<div style="color:#565d68;padding:10px">No tokens found</div>'
  })
}

function selectToken(symbol, mint){
  const ta=document.getElementById('postText')
  if(ta) ta.value+=' $'+symbol+(mint&&mint!='undefined'?' ('+mint+')':'')
  document.getElementById('tokenModal').style.display='none'
}

var _mentionTarget = null;
var _mentionAtPos = -1;
function _mentionHide(){
  var box = document.getElementById('mention-suggest');
  if(box) box.style.display='none';
  _mentionTarget = null;
}
function tagUser(){
  document.getElementById('userTagModal').style.display='flex'
  const inp=document.getElementById('userTagSearch')
  if(inp){ inp.value=''; document.getElementById('userTagResults').innerHTML=''; inp.focus() }
}
function searchUserTag(q){
  if(q.length<1){ document.getElementById('userTagResults').innerHTML=''; return }
  fetch('/api/users/search?q='+encodeURIComponent(q))
  .then(r=>r.json()).then(d=>{
    const users=(d&&d.users)||[]
    document.getElementById('userTagResults').innerHTML=users.length?
    users.map(u=>`<div onclick="selectUserTag('${u.username.replace(/'/g,"\\'")}')" style="padding:10px;cursor:pointer;border-bottom:1px solid #16191f;color:#eef1f5">
      <span style="color:#f7b955;font-weight:700">@${u.username}</span>
    </div>`).join('')
    :'<div style="color:#565d68;padding:10px">No users found</div>'
  })
}
function selectUserTag(username){
  const ta=document.getElementById('postText')
  if(ta) ta.value+=' @'+username+' '
  document.getElementById('userTagModal').style.display='none'
}
function _toggleFeedEmojiPanel(e){
  if(e) e.stopPropagation()
  document.getElementById('feed-emoji-panel').classList.toggle('open')
}
document.addEventListener('click', function(e){
  var panel = document.getElementById('feed-emoji-panel')
  if(panel && panel.classList.contains('open') && !e.target.closest('.feed-emoji-wrap')) panel.classList.remove('open')
})
document.addEventListener('click', function(e){
  var btn = e.target.closest('#feed-emoji-panel button')
  if(!btn) return
  var ta = document.getElementById('postText')
  if(!ta) return
  var start = ta.selectionStart || ta.value.length
  var end = ta.selectionEnd || ta.value.length
  ta.value = ta.value.slice(0,start) + btn.textContent + ta.value.slice(end)
  var pos = start + btn.textContent.length
  ta.focus()
  ta.setSelectionRange(pos,pos)
  document.getElementById('feed-emoji-panel').classList.remove('open')
})
async function submitPost(){
  const t=document.getElementById('postText')
  var text = t.value.trim()
  if(!text && !_composerChart && !_composerTrade) return
  var content = text
  if(_composerTrade) content = (content ? content+'\n' : '') + '__TRADE__'+JSON.stringify(_composerTrade)
  if(_composerChart) content = (content ? content+'\n' : '') + '__CHART__'+JSON.stringify(_composerChart)
  const r=await fetch('/api/feed/post',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:content})})
  const d=await r.json()
  if(r.ok){
    t.value=''
    _composerChart=null; _composerTrade=null
    var prev=document.getElementById('composer-chart-preview')
    if(prev) prev.style.display='none'
    var tprev=document.getElementById('composer-trade-preview')
    if(tprev) tprev.style.display='none'
    var bar=document.getElementById('composer-chart-search')
    if(bar) bar.style.display='none'
    var tdd=document.getElementById('composer-trade-dropdown')
    if(tdd) tdd.style.display='none'
    window.location.reload()
  } else alert('Error: '+JSON.stringify(d))
}

var _deletePostId=null
var _deletePostType=null
var _fcPendingDelete=null   // set by the "…" menu delete path

function deletePost(id,type){
  _deletePostId=id
  _deletePostType=type||'text'
  document.getElementById('deleteModal').style.display='flex'
}
async function confirmDelete(){
  document.getElementById('deleteModal').style.display='none'
  // "…" menu path — uses POST /api/post/<id>/delete (admin-aware)
  if(_fcPendingDelete){
    const {id,type}=_fcPendingDelete; _fcPendingDelete=null;
    const url=type==='trade'?'/api/trades/'+id:'/api/post/'+id+'/delete';
    const meth=type==='trade'?'DELETE':'POST';
    const r=await fetch(url,{method:meth});
    if(r.ok) window.location.reload();
    return;
  }
  // legacy path (existing trash-icon flow kept for other callers)
  if(!_deletePostId) return
  const url=_deletePostType==='trade'
    ? '/api/trades/'+_deletePostId
    : '/api/feed/post/'+_deletePostId
  const r=await fetch(url,{method:'DELETE'})
  _deletePostId=null
  _deletePostType=null
  if(r.ok) window.location.reload()
}

/* ── Feed post menu ── */
var _fcActiveMenuId=null;
function _fcMenuToggle(postId){
  var dd=document.getElementById('fc-menu-'+postId);
  if(!dd) return;
  var closing=(_fcActiveMenuId===postId && dd.style.display!=='none');
  _fcMenuClose();
  if(!closing){ dd.style.display='block'; _fcActiveMenuId=postId; }
}
function _fcMenuClose(){
  if(_fcActiveMenuId){
    var dd=document.getElementById('fc-menu-'+_fcActiveMenuId);
    if(dd) dd.style.display='none';
    _fcActiveMenuId=null;
  }
}
document.addEventListener('click',function(ev){
  if(_fcActiveMenuId && !ev.target.closest('.fc-menu-wrap')) _fcMenuClose();
},true);

function _fcMenuDelete(id,type){
  _fcMenuClose();
  _fcPendingDelete={id:id,type:type||'text'};
  document.getElementById('deleteModal').style.display='flex';
}

/* ── Inline edit ── */
function _fcEditStart(postId){
  _fcMenuClose();
  var card=document.getElementById('fc-card-'+postId);
  var raw=(card&&card.getAttribute('data-post-content'))||'';
  // strip embedded chart/trade blobs — edit the text portion only
  var text=raw.replace(/__TRADE__[\s\S]*/,'').replace(/__CHART__[\s\S]*/,'').trim();
  var textEl=document.getElementById('fc-text-'+postId);
  var editEl=document.getElementById('fc-edit-'+postId);
  var ta=document.getElementById('fc-edit-ta-'+postId);
  if(!textEl||!editEl||!ta) return;
  ta.value=text;
  ta.style.height='auto'; ta.style.height=ta.scrollHeight+'px';
  textEl.style.display='none';
  editEl.style.display='block';
  ta.focus();
}
function _fcEditCancel(postId){
  var textEl=document.getElementById('fc-text-'+postId);
  var editEl=document.getElementById('fc-edit-'+postId);
  if(textEl) textEl.style.display='';
  if(editEl) editEl.style.display='none';
}
async function _fcEditSave(postId,dbId){
  var ta=document.getElementById('fc-edit-ta-'+postId);
  var saveBtn=document.getElementById('fc-edit-save-'+postId);
  if(!ta) return;
  var text=ta.value.trim();
  if(!text){ ta.focus(); return; }
  if(saveBtn) saveBtn.disabled=true;
  try{
    var r=await fetch('/api/post/'+dbId+'/edit',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({content:text})
    });
    var d=await r.json().catch(()=>({}));
    if(r.ok&&d.ok){
      // persist raw content on card so re-edit reads updated text
      var card=document.getElementById('fc-card-'+postId);
      if(card) card.setAttribute('data-post-content',text);
      // update the visible text div with escaped + $TOKEN-linked content
      var textEl=document.getElementById('fc-text-'+postId);
      if(textEl){
        var safe=esc(text).replace(/\$([^\s<]+)/g,'<span class="token-tag" onclick="event.stopPropagation();showTokenCard(\'$1\')">$$$1</span>');
        safe = safe.replace(/@([a-zA-Z0-9_]+)/g,'<a href="/profile/$1" onclick="event.stopPropagation()" style="color:#f7b955;font-weight:600;text-decoration:none">@$1</a>');
        textEl.innerHTML='<div style="font-size:14.5px;line-height:1.55;color:#c7ccd4;margin:6px 0 10px">'+safe+'</div>';
      }
      _fcEditCancel(postId);
    } else {
      alert(d.msg||'Edit failed');
      if(saveBtn) saveBtn.disabled=false;
    }
  } catch(ex){
    alert('Network error — please retry');
    if(saveBtn) saveBtn.disabled=false;
  }
}

function copyTrade(id){ alert('Copy trade coming soon') }
async function likePost(id,btn){
  await fetch('/api/feed/like/'+id,{method:'POST'})
  const span=btn.querySelector('span')
  span.textContent=parseInt(span.textContent)+1
  btn.style.color='#f76b62'
}
async function replyPost(id){
  const text=prompt('Reply:')
  if(!text) return
  await fetch('/api/feed/reply/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:text})})
  window.location.reload()
}

function _feedComposerPost(){
  var inp = document.getElementById('postText');
  if(!inp) return;
  var text = inp.value.trim();
  if(!text) return;
  var btn = document.querySelector('.feed-composer-post');
  if(btn){ btn.disabled=true; btn.textContent='Posting…'; }
  fetch('/api/chat',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({message: text})
  }).then(function(r){ return r.json(); }).then(function(d){
    if(d.ok){
      inp.value='';
      _homeFeedData.unshift({
        type:'text', user_id:d.user_id, username:d.username,
        wallet:d.wallet_address, avatar_url:d.avatar_url,
        content:d.message, timestamp:d.created_at
      });
      renderHomeFeed();
    } else { alert(d.msg||'Could not post'); }
  }).catch(function(e){ console.error('[composer]',e); }).finally(function(){
    if(btn){ btn.disabled=false; btn.textContent='POST'; }
  });
}

var _composerChart = null;
var _composerTrade = null;

function _renderTradeTerminalCard(t){
  if(!t) return '';
  // If passed a raw feed item (has content field), normalize to trade field names
  if(t.content != null){
    t = {
      symbol:       t.symbol      || '',
      side:         t.side        || 'BUY',
      pct:          t.pnl_pct     || 0,
      pnl_pct:      t.pnl_pct     || 0,
      entry:        t.entry_price || 0,
      entry_price:  t.entry_price || 0,
      exit:         t.exit_price  || 0,
      exit_price:   t.exit_price  || 0,
      pnl_sol:      t.pnl_sol     || 0,
      amount:       t.amount      || 0,
      duration:     t.duration    || '',
      token_address:t.token_address || '',
    };
  }
  console.log('[trade]', t);
  var isBuy   = (t.side||'BUY').toUpperCase() !== 'SELL';
  var sideCol = isBuy ? '#00d084' : '#ff4757';
  var entryN  = parseFloat(t.entry_price || t.entry || 0);
  var exitN   = parseFloat(t.exit_price  || t.exit  || 0);
  var pct     = parseFloat(t.pnl_pct || t.pct || 0);
  var pctCol  = pct >= 0 ? '#00d084' : '#ff4757';
  var pctStr  = (pct >= 0 ? '+' : '') + pct.toFixed(2) + '%';
  var sol     = parseFloat(t.pnl_sol != null ? t.pnl_sol : (t.sol_profit || 0));
  var solStr  = (sol >= 0 ? '+' : '') + sol.toFixed(4) + ' SOL';
  var _fp = function(n){ n=parseFloat(n||0); return n ? (n<0.001 ? '$'+n.toFixed(8).replace(/\.?0+$/,'') : '$'+n.toFixed(6)) : '—'; };
  var entry  = _fp(entryN);
  var exit_p = _fp(exitN);
  var dur    = t.duration ? '<span style="color:#565d68;font-size:11px"> · '+esc(t.duration)+'</span>' : '';
  var sym    = esc(t.symbol||'');
  var amtStr = '';
  if(t.amount && parseFloat(t.amount) > 0){
    var _amt = parseFloat(t.amount);
    amtStr = '<div style="color:#565d68;font-size:11px;margin-top:3px">'+(_amt>=1000?_amt.toLocaleString('en-US',{maximumFractionDigits:0}):_amt.toFixed(4))+' tokens</div>';
  }
  return '<div style="background:#0d1117;border:1px solid #1a1f2e;border-radius:10px;padding:14px 16px;margin:8px 0 10px;font-family:\'JetBrains Mono\',monospace;cursor:pointer" onclick="event.stopPropagation();showTokenCard(\''+sym+'\')">'
    +'<div style="display:flex;justify-content:space-between;align-items:flex-start">'
    +'<div style="flex:1;min-width:0">'
    +'<div style="display:flex;align-items:center;gap:8px;margin-bottom:7px">'
    +'<span style="color:'+sideCol+';font-weight:700;font-size:11px;border:1px solid '+sideCol+'33;border-radius:4px;padding:1px 5px">'+(isBuy?'BUY':'SELL')+'</span>'
    +'<span style="color:#eef1f5;font-weight:700;font-size:15px">$'+sym+'</span>'
    +dur
    +'</div>'
    +'<div style="color:#8a919c;font-size:11px;margin-bottom:5px">$'+esc(String(t.entry_price||entryN||'—'))+' → $'+esc(String(t.exit_price||exitN||'—'))+'</div>'
    +'<div style="color:#f7b955;font-size:12px;font-weight:600">'+solStr+'</div>'
    +amtStr
    +'</div>'
    +'<div style="font-size:26px;font-weight:700;color:'+pctCol+';line-height:1;text-align:right;padding-left:14px;align-self:center">'+pctStr+'</div>'
    +'</div>'
    +'</div>';
}

function _feedComposerTrade(){
  var dd = document.getElementById('composer-trade-dropdown');
  if(!dd) return;
  var isOpen = dd.style.display !== 'none';
  // close chart search if open
  var cbar = document.getElementById('composer-chart-search');
  if(cbar) cbar.style.display = 'none';
  document.getElementById('chart-pill-btn').style.background = '';
  if(isOpen){
    dd.style.display = 'none';
    document.getElementById('trade-pill-btn').style.background = '';
  } else {
    dd.style.display = 'block';
    document.getElementById('trade-pill-btn').style.background = '#21252c';
    _loadMyTrades();
  }
}

function _loadMyTrades(){
  var list = document.getElementById('composer-trade-list');
  if(!list) return;
  list.innerHTML = '<div style="padding:12px 14px;color:#565d68;font-size:12px">Loading…</div>';
  fetch('/api/my-trades', {credentials:'include'})
  .then(function(r){ return r.json(); })
  .then(function(d){
    var trades = (d.trades || (Array.isArray(d) ? d : [])).slice(0,5);
    if(!trades.length){
      list.innerHTML = '<div style="padding:14px;color:#565d68;font-size:12px;text-align:center">No closed trades yet</div>';
      return;
    }
    list.innerHTML = trades.map(function(t, i){
      var sym  = t.symbol || t.token || '?';
      var pct  = t.pnl_pct != null ? parseFloat(t.pnl_pct)
                 : (t.entry_price && t.exit_price ? (t.exit_price - t.entry_price) / t.entry_price * 100 : 0);
      var col  = pct >= 0 ? '#00d084' : '#ff4757';
      var pstr = (pct >= 0 ? '+' : '') + pct.toFixed(1) + '%';
      return '<div onclick="_attachTradeEmbed('+i+')" style="padding:10px 14px;cursor:pointer;border-bottom:1px solid #16191f;display:flex;align-items:center;justify-content:space-between;transition:background .1s;font-family:\'JetBrains Mono\',monospace;font-size:12px" onmouseover="this.style.background=\'#16191f\'" onmouseout="this.style.background=\'\'">'
        +'<span style="color:#eef1f5;font-weight:700">$'+esc(sym)+'</span>'
        +'<span style="color:'+col+';font-weight:600">'+pstr+'</span>'
        +'</div>';
    }).join('');
    window._myTrades = trades;
  })
  .catch(function(){
    list.innerHTML = '<div style="padding:12px 14px;color:#f76b62;font-size:12px">Failed to load trades</div>';
  });
}

function _attachTradeEmbed(idx){
  var t = window._myTrades && window._myTrades[idx];
  if(!t) return;
  var sym   = t.symbol || t.token || '?';
  var side  = (t.side || 'BUY').toUpperCase();
  var entry = parseFloat(t.entry_price || t.entry || 0);
  var exit  = parseFloat(t.exit_price  || t.exit  || 0);
  var pct   = t.pnl_pct != null ? parseFloat(t.pnl_pct) : (entry>0 ? (exit-entry)/entry*100 : 0);
  var sol   = parseFloat(t.pnl_sol || t.profit_sol || t.sol_profit || 0);
  var dur   = t.duration || '';
  if(!dur && t.opened_at && (t.closed_at || t.timestamp)){
    var ms = new Date(t.closed_at||t.timestamp) - new Date(t.opened_at);
    var h  = Math.floor(ms/3600000), m = Math.floor((ms%3600000)/60000);
    dur = (h>0 ? h+'h ' : '') + m + 'm';
  }
  var amount = parseFloat(t.amount || 0);
  _composerTrade = {symbol:sym, side:side, entry_price:entry, exit_price:exit, pnl_pct:pct, pnl_sol:sol, amount:amount, duration:dur, token_address:t.token_address||''};
  document.getElementById('composer-trade-dropdown').style.display = 'none';
  document.getElementById('trade-pill-btn').style.background = '#00d08422';
  _renderComposerTradePreview();
}

function _renderComposerTradePreview(){
  var prev = document.getElementById('composer-trade-preview');
  var card = document.getElementById('composer-trade-card');
  if(!prev || !card || !_composerTrade) return;
  prev.style.display = 'block';
  card.innerHTML = _renderTradeTerminalCard(_composerTrade);
}

function _clearComposerTrade(){
  _composerTrade = null;
  var prev = document.getElementById('composer-trade-preview');
  if(prev) prev.style.display = 'none';
  var btn  = document.getElementById('trade-pill-btn');
  if(btn)  btn.style.background = '';
}


function _feedComposerChart(){
  var bar = document.getElementById('composer-chart-search');
  if(!bar) return;
  var isOpen = bar.style.display !== 'none';
  if(isOpen){
    bar.style.display = 'none';
    document.getElementById('chart-pill-btn').style.background = '';
  } else {
    bar.style.display = 'block';
    document.getElementById('chart-pill-btn').style.background = '#21252c';
    var inp = document.getElementById('composer-chart-input');
    if(inp){ inp.value=''; inp.focus(); }
    document.getElementById('composer-chart-results').style.display = 'none';
  }
}

var _chartSearchTimer = null;
function _chartSearch(q){
  clearTimeout(_chartSearchTimer);
  var res = document.getElementById('composer-chart-results');
  if(!q || q.length < 1){ res.style.display='none'; return; }
  res.style.display = 'block';
  res.innerHTML = '<div style="padding:10px;color:#565d68;font-size:13px">Searching…</div>';
  _chartSearchTimer = setTimeout(function(){
    fetch('https://api.dexscreener.com/latest/dex/search?q='+encodeURIComponent(q))
    .then(function(r){ return r.json(); })
    .then(function(d){
      var pairs = (d.pairs||[]).filter(function(p){ return p.chainId==='solana'; }).slice(0,5);
      if(!pairs.length){ res.innerHTML='<div style="padding:10px;color:#565d68;font-size:13px">No Solana tokens found</div>'; return; }
      res.innerHTML = pairs.map(function(p,i){
        var chg = p.priceChange && p.priceChange.h24 != null ? p.priceChange.h24 : null;
        var chgStr = chg != null ? (chg>=0?'<span style="color:#3ad29b">+'+chg.toFixed(2)+'%</span>':'<span style="color:#f76b62">'+chg.toFixed(2)+'%</span>') : '';
        var price = p.priceUsd ? '$'+parseFloat(p.priceUsd).toLocaleString(undefined,{maximumSignificantDigits:6}) : '—';
        var sym = (p.baseToken&&p.baseToken.symbol)||'?';
        var name = (p.baseToken&&p.baseToken.name)||'';
        var safeIdx = i;
        return '<div onclick="_attachChartEmbed('+i+')" data-pair-idx="'+i+'" style="padding:11px 14px;cursor:pointer;border-bottom:1px solid #16191f;display:flex;align-items:center;justify-content:space-between;transition:background .1s" onmouseover="this.style.background=\'#16191f\'" onmouseout="this.style.background=\'\'"><div><div style="font-weight:700;color:#eef1f5;font-size:13px">'+sym+'</div><div style="color:#565d68;font-size:11px">'+name+'</div></div><div style="text-align:right"><div style="font-family:\'JetBrains Mono\',monospace;font-size:12px;color:#eef1f5">'+price+'</div><div style="font-size:11px">'+chgStr+'</div></div></div>';
      }).join('');
      window._chartSearchPairs = pairs;
    })
    .catch(function(){ res.innerHTML='<div style="padding:10px;color:#f76b62;font-size:13px">Search failed</div>'; });
  }, 300);
}

function _attachChartEmbed(idx){
  var pairs = window._chartSearchPairs;
  if(!pairs || !pairs[idx]) return;
  var p = pairs[idx];
  _composerChart = {
    symbol:  (p.baseToken&&p.baseToken.symbol)||'?',
    name:    (p.baseToken&&p.baseToken.name)||'',
    price:   p.priceUsd||null,
    chg5m:   p.priceChange&&p.priceChange.m5!=null  ? p.priceChange.m5  : null,
    chg1h:   p.priceChange&&p.priceChange.h1!=null  ? p.priceChange.h1  : null,
    chg6h:   p.priceChange&&p.priceChange.h6!=null  ? p.priceChange.h6  : null,
    chg24h:  p.priceChange&&p.priceChange.h24!=null ? p.priceChange.h24 : null,
    vol24h:  p.volume&&p.volume.h24!=null ? p.volume.h24 : null,
    liq:     p.liquidity&&p.liquidity.usd!=null ? p.liquidity.usd : null,
    buys:        p.txns&&p.txns.h24 ? p.txns.h24.buys  : null,
    sells:       p.txns&&p.txns.h24 ? p.txns.h24.sells : null,
    mint:        (p.baseToken&&p.baseToken.address)||'',
    pairAddress: p.pairAddress||''
  };
  document.getElementById('composer-chart-search').style.display = 'none';
  document.getElementById('chart-pill-btn').style.background = '#f7b95522';
  _renderComposerChartPreview();
}

function _renderComposerChartPreview(){
  if(!_composerChart) return;
  var c = _composerChart;
  var chg24 = c.chg24h;
  var chgColor = chg24!=null ? (chg24>=0?'#3ad29b':'#f76b62') : '#565d68';
  var chgStr  = chg24!=null ? (chg24>=0?'+':'')+chg24.toFixed(2)+'%' : '—';
  var price   = c.price ? '$'+parseFloat(c.price).toLocaleString(undefined,{maximumSignificantDigits:6}) : '—';
  var fmt = function(n){ if(n==null) return '—'; if(n>=1e9) return '$'+(n/1e9).toFixed(2)+'B'; if(n>=1e6) return '$'+(n/1e6).toFixed(2)+'M'; if(n>=1e3) return '$'+(n/1e3).toFixed(1)+'K'; return '$'+n.toFixed(2); };

  /* mini bar chart from timeframe changes */
  var tfs = [
    {label:'5m',  val:c.chg5m},
    {label:'1h',  val:c.chg1h},
    {label:'6h',  val:c.chg6h},
    {label:'24h', val:c.chg24h}
  ];
  var maxAbs = 0.01;
  tfs.forEach(function(tf){ if(tf.val!=null && Math.abs(tf.val)>maxAbs) maxAbs=Math.abs(tf.val); });
  var bars = tfs.map(function(tf){
    var h = tf.val!=null ? Math.max(4, Math.round(Math.abs(tf.val)/maxAbs*36)) : 4;
    var col = tf.val!=null ? (tf.val>=0?'#3ad29b':'#f76b62') : '#21252c';
    return '<div style="display:flex;flex-direction:column;align-items:center;gap:3px"><div style="width:10px;height:'+h+'px;background:'+col+';border-radius:3px 3px 0 0"></div><div style="font-size:9px;color:#565d68;font-family:\'JetBrains Mono\',monospace">'+tf.label+'</div></div>';
  }).join('');

  var html = '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">'
    +'<div><div style="font-size:15px;font-weight:700;color:#eef1f5">$'+c.symbol+'</div>'
    +'<div style="font-size:11px;color:#565d68">'+c.name+'</div></div>'
    +'<div style="text-align:right"><div style="font-family:\'JetBrains Mono\',monospace;font-size:14px;font-weight:700;color:#eef1f5">'+price+'</div>'
    +'<div style="font-size:12px;color:'+chgColor+';font-weight:600">'+chgStr+'</div></div>'
    +'</div>'
    +'<div style="display:flex;align-items:flex-end;gap:6px;height:52px;margin-bottom:10px">'+bars+'</div>'
    +'<div style="display:flex;gap:10px">'
    +'<div style="flex:1;background:#0a0b0e;border-radius:8px;padding:8px"><div style="font-size:10px;color:#565d68;margin-bottom:2px">VOL 24H</div><div style="font-size:12px;font-weight:600;color:#eef1f5">'+fmt(c.vol24h)+'</div></div>'
    +'<div style="flex:1;background:#0a0b0e;border-radius:8px;padding:8px"><div style="font-size:10px;color:#565d68;margin-bottom:2px">LIQUIDITY</div><div style="font-size:12px;font-weight:600;color:#eef1f5">'+fmt(c.liq)+'</div></div>'
    +(c.buys!=null?'<div style="flex:1;background:#0a0b0e;border-radius:8px;padding:8px"><div style="font-size:10px;color:#565d68;margin-bottom:2px">BUYS/SELLS</div><div style="font-size:12px;font-weight:600;color:#eef1f5">'+c.buys+'/'+c.sells+'</div></div>':'')
    +'</div>';

  document.getElementById('composer-chart-card').innerHTML = html;
  document.getElementById('composer-chart-preview').style.display = 'block';
}

function _clearComposerChart(){
  _composerChart = null;
  document.getElementById('composer-chart-preview').style.display = 'none';
  document.getElementById('chart-pill-btn').style.background = '';
}

function _feedComposerTag(){
  var s=document.getElementById('hdr-search-input');
  if(s){ s.focus(); s.select(); }
}

function _feedTab(btn, tab){
  document.querySelectorAll('.feed-tab').forEach(function(t){ t.classList.remove('active'); });
  btn.classList.add('active');
  _homeFeedFilter = tab;
  if(tab === 'following' && _homeFeedData.length){
    renderHomeFeed();
    loadHomeFeed();
  } else {
    renderHomeFeed();
    loadHomeFeed();
  }
}

/* ── HOME FEED ── */
var _homeFeedFilter = 'foryou';
var _homeFeedData   = [];

function _showAvatarLightbox(url){
  var lb = document.getElementById('avatar-lightbox');
  var img = document.getElementById('avatar-lightbox-img');
  if(!lb || !img) return;
  img.src = url;
  lb.classList.add('open');
}
function _closeAvatarLightbox(){
  var lb = document.getElementById('avatar-lightbox');
  if(lb) lb.classList.remove('open');
}

async function loadHomeFeed(){
  const filter = _homeFeedFilter === 'following' ? 'following' : 'all';
  const el = document.getElementById('center-feed');
  if(el && !_homeFeedData.length) el.innerHTML = '<div class="fc-loading">Loading…</div>';
  try{
    const _ctl = new AbortController();
    const _tid = setTimeout(()=>_ctl.abort(), 12000);
    const r = await fetch('/api/social/feed?filter=' + filter, {signal:_ctl.signal});
    clearTimeout(_tid);
    console.log('[feed] status:', r.status);
    if(!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    console.log('[feed] items:', Array.isArray(data) ? data.length : data);
    if(Array.isArray(data)){
      console.log('[feed] first item:', JSON.stringify(data[0]));
      _homeFeedData = data;
      try{
        renderHomeFeed();
      }catch(e){
        console.error('[feed] render error:', e);
        if(el) el.innerHTML='<div class="fc-loading" style="color:#f76b62">Feed render error: '+e.message+'</div>';
      }
    } else {
      console.warn('[feed] unexpected response format:', data);
      if(el) el.innerHTML='<div class="fc-loading" style="color:#f76b62">Feed error: unexpected response</div>';
    }
  }catch(e){
    console.error('[feed] load error (silent, keeping last known feed):', e);
    if(!_homeFeedData.length && el) el.innerHTML='<div class="fc-loading">Loading…</div>';
    setTimeout(loadHomeFeed, 5000);
  }
}

async function loadRightRail(){
  const [mkt, lb] = await Promise.all([
    fetch('/api/market/live').then(r=>r.json()).catch(()=>null),
    fetch('/api/leaderboard').then(r=>r.json()).catch(()=>null),
  ]);

  /* ── Live Market ── */
  const mEl=document.getElementById('rs-movers');
  if(mEl){
    const tokens=mkt&&mkt.ok&&Array.isArray(mkt.tokens)?mkt.tokens:[];
    const top5=tokens.filter(t=>t.price_change_24h!=null).sort((a,b)=>Math.abs(b.price_change_24h)-Math.abs(a.price_change_24h)).slice(0,5);
    if(top5.length){
      mEl.innerHTML=top5.map(function(t){
        const pct=t.price_change_24h||0, isPos=pct>=0;
        const pctStr=(isPos?'+':'')+pct.toFixed(1)+'%';
        const p=t.price||0;
        const pStr=p<0.0001?'$'+p.toExponential(2):p<1?'$'+p.toFixed(6):'$'+p.toFixed(4);
        const sym=t.symbol||'?';
        const pair=(t.pair||sym+'/SOL');
        const bg=(typeof _lbAvatarColor==='function')?_lbAvatarColor(sym):'#21252c';
        return '<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid #16191f">'
          +'<div style="width:34px;height:34px;border-radius:50%;background:'+bg+';display:flex;align-items:center;justify-content:center;font-weight:700;font-size:11px;color:#fff;flex-shrink:0">'+esc(sym.slice(0,3))+'</div>'
          +'<div style="flex:1;min-width:0"><div style="font-weight:600;font-size:13px">'+esc(sym)+'</div><div style="font-size:11px;color:#565d68">'+esc(pair)+'</div></div>'
          +'<div style="text-align:right;flex-shrink:0"><div style="font-size:12px;font-family:monospace">'+esc(pStr)+'</div>'
          +'<div style="font-size:11px;font-weight:700;color:'+(isPos?'#3ad29b':'#f76b62')+'">'+esc(pctStr)+'</div></div>'
          +'</div>';
      }).join('');
    } else {
      mEl.innerHTML='<div style="padding:8px 0;font-size:12px;color:#565d68">No market data.</div>';
    }
  }

  /* ── Top Traders Today ── */
  const lEl=document.getElementById('rs-leaderboard');
  if(lEl){
    const traders=Array.isArray(lb)?lb.slice(0,4):[];
    if(traders.length){
      lEl.innerHTML=traders.map(function(e,i){
        const bg=(typeof _lbAvatarColor==='function')?_lbAvatarColor(e.username||e.wallet_address||'?'):'#21252c';
        const ini=((e.username||e.wallet_address||'?')[0]||'?').toUpperCase();
        const imgHtml=e.avatar_url?'<img src="'+esc(e.avatar_url)+'" alt="" style="position:absolute;inset:0;width:100%;height:100%;object-fit:cover;border-radius:50%" onerror="this.style.display=\'none\'">':'';
        const pnl=e.total_pnl||0, isPos=pnl>=0;
        const pnlStr=(isPos?'+':'')+pnl.toFixed(2)+' SOL';
        const handle='@'+(e.username||((e.wallet_address||'').slice(0,6)+'…'));
        const rankColors=['#f7b955','#8a919c','#cd7f32','#565d68'];
        return '<div style="display:flex;align-items:center;gap:9px;padding:8px 0;border-bottom:1px solid #16191f;cursor:pointer" onclick="typeof openProfileCard===\'function\'&&openProfileCard('+(e.user_id||0)+')">'
          +'<span style="font-size:12px;font-weight:700;color:'+rankColors[i]+';width:16px;flex-shrink:0">#'+(e.rank||i+1)+'</span>'
          +'<div style="width:32px;height:32px;border-radius:50%;background:'+bg+';flex-shrink:0;position:relative;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:12px;color:#fff">'+imgHtml+ini+'</div>'
          +'<div style="flex:1;min-width:0"><div style="font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(e.username||'Trader')+'</div>'
          +'<div style="font-size:11px;color:#565d68">'+esc(handle)+'</div></div>'
          +'<div style="font-size:12px;font-weight:700;color:'+(isPos?'#3ad29b':'#f76b62')+';flex-shrink:0">'+esc(pnlStr)+'</div>'
          +'</div>';
      }).join('');
    } else {
      lEl.innerHTML='<div style="padding:8px 0;font-size:12px;color:#565d68">No traders yet.</div>';
    }
  }
}

function loadInlineSidebar(){
  fetch('/api/market/top').then(r=>r.json()).then(d=>{
    const el=document.getElementById('sidebar-market');
    if(!el) return;
    el.innerHTML=d.slice(0,5).map(t=>`
    <div style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #16191f">
      <div style="width:36px;height:36px;border-radius:10px;background:#21252c;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:11px">${t.symbol?.slice(0,3)}</div>
      <div style="flex:1"><div style="font-weight:600;font-size:13px">${t.name||t.symbol}</div>
      <div style="color:#565d68;font-size:11px">${t.symbol}/SOL</div></div>
      <div style="text-align:right"><div style="font-size:13px;font-weight:600">$${t.price_usd?.toFixed(4)||'--'}</div>
      <div style="font-size:12px;color:${(t.change||0)>=0?'#3ad29b':'#f76b62'}">${(t.change||0)>=0?'+':''}${(t.change||0).toFixed(1)}%</div></div>
    </div>`).join('')
  }).catch(()=>{});

  fetch('/api/leaderboard').then(r=>r.json()).then(d=>{
    const el=document.getElementById('sidebar-traders');
    if(!el) return;
    el.innerHTML=d.slice(0,4).map((t,i)=>`
    <div style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #16191f">
      <span style="color:#565d68;font-size:13px;width:16px">${i+1}</span>
      <div style="width:36px;height:36px;border-radius:50%;background:#f7b955;color:#0a0b0e;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:12px">${(t.username||t.wallet||'?').slice(0,2).toUpperCase()}</div>
      <div style="flex:1"><div style="font-weight:600;font-size:13px">${t.username||t.wallet?.slice(0,8)}</div>
      <div style="color:#565d68;font-size:11px">@${t.username||t.wallet?.slice(0,8)}</div></div>
      <div style="color:#3ad29b;font-family:monospace;font-size:13px;font-weight:700">+${(t.total_pnl_sol||0).toFixed(1)} SOL</div>
    </div>`).join('')
  }).catch(()=>{});
}

/* ── Live chart cards ── */
var _liveChartTimers  = {};  /* cardEl.id -> intervalId */
var _liveChartHistory = {};  /* cardEl.id -> [price, ...] */

function _ccFmt(n){ if(n==null||isNaN(n)) return '—'; if(n>=1e9) return '$'+(n/1e9).toFixed(2)+'B'; if(n>=1e6) return '$'+(n/1e6).toFixed(2)+'M'; if(n>=1e3) return '$'+(n/1e3).toFixed(1)+'K'; return '$'+n.toFixed(2); }
function _ccFmtPrice(p){ if(!p) return '—'; var n=parseFloat(p); if(isNaN(n)||n<=0) return '—'; return n<0.001 ? '$'+n.toFixed(8).replace(/\.?0+$/,'') : '$'+n.toFixed(6); }

function _ccSeedHistory(pair){
  var now = parseFloat(pair.priceUsd||0);
  if(!now) return [];
  var pc = pair.priceChange||{};
  function back(pct){ return (pct!=null && pct>-100) ? now/(1+pct/100) : now; }
  /* reconstruct 4 historical points: -24h, -6h, -1h, -5m, now */
  return [back(pc.h24), back(pc.h6), back(pc.h1), back(pc.m5), now];
}

function _ccSnapHistory(cardEl){
  /* build 4-point history from the priceChange values stored as data attrs at embed time */
  var price = parseFloat(cardEl.getAttribute('data-chart-price')||0);
  if(!price) return [];
  var g = function(a){ var v=parseFloat(cardEl.getAttribute(a)); return isNaN(v)?null:v; };
  var pc = {h24:g('data-chart-chg24h'), h6:g('data-chart-chg6h'), h1:g('data-chart-chg1h'), m5:g('data-chart-chg5m')};
  function back(pct){ return (pct!=null && pct>-100) ? price/(1+pct/100) : price; }
  return [back(pc.h24), back(pc.h6), back(pc.h1), back(pc.m5), price];
}

function _ccDrawSparkline(lineEl, pts){
  if(!lineEl||!pts||pts.length<2) return;
  var mn = Math.min.apply(null,pts), mx = Math.max.apply(null,pts);
  var range = (mx-mn)||mn*0.01||1e-9;
  var W=220, H=44, PAD=3;
  var points = pts.map(function(v,i){
    var x = (i/(pts.length-1))*W;
    var y = PAD + (1-(v-mn)/range)*(H-PAD*2);
    return x.toFixed(1)+','+y.toFixed(1);
  }).join(' ');
  lineEl.setAttribute('points', points);
  lineEl.setAttribute('stroke', pts[pts.length-1] >= pts[0] ? '#f7b955' : '#f76b62');
}

async function _liveChartPoll(cardEl, pairAddress, symbol){
  /* stop if card left DOM */
  if(!document.contains(cardEl)){
    clearInterval(_liveChartTimers[cardEl.id]);
    delete _liveChartTimers[cardEl.id];
    delete _liveChartHistory[cardEl.id];
    return;
  }
  try{
    var url = pairAddress
      ? 'https://api.dexscreener.com/latest/dex/pairs/solana/'+encodeURIComponent(pairAddress)
      : 'https://api.dexscreener.com/latest/dex/search?q='+encodeURIComponent(symbol);
    var r = await fetch(url);
    var d = await r.json();
    var p = pairAddress
      ? (d.pair || (d.pairs&&d.pairs[0]) || null)
      : ((d.pairs||[]).find(function(x){ return x.chainId==='solana'; }) || null);
    if(!p) return;

    var key = cardEl.id;
    var price = parseFloat(p.priceUsd||0);
    if(!_liveChartHistory[key]||!_liveChartHistory[key].length){
      /* prefer live seed; fall back to stored embed values */
      _liveChartHistory[key] = price ? _ccSeedHistory(p) : _ccSnapHistory(cardEl);
    }
    if(price){ _liveChartHistory[key].push(price); }
    if(_liveChartHistory[key].length > 120) _liveChartHistory[key].shift();

    var chg24 = p.priceChange&&p.priceChange.h24!=null ? p.priceChange.h24 : null;

    var priceEl   = cardEl.querySelector('[data-cc="price"]');
    var chgEl     = cardEl.querySelector('[data-cc="chg"]');
    var volEl     = cardEl.querySelector('[data-cc="vol"]');
    var liqEl     = cardEl.querySelector('[data-cc="liq"]');
    var buysEl    = cardEl.querySelector('[data-cc="buys"]');
    var sellsEl   = cardEl.querySelector('[data-cc="sells"]');
    var buysBarEl = cardEl.querySelector('[data-cc="buysbar"]');
    var bannerEl  = cardEl.querySelector('[data-cc="banner"]');
    var logoEl    = cardEl.querySelector('[data-cc="logo"]');

    if(priceEl) priceEl.textContent = _ccFmtPrice(p.priceUsd);
    if(chgEl){
      chgEl.textContent = chg24!=null ? (chg24>=0?'+':'')+chg24.toFixed(2)+'%' : '—';
      chgEl.style.color = chg24!=null ? (chg24>=0?'#3ad29b':'#f76b62') : '#565d68';
    }
    if(volEl) volEl.textContent = _ccFmt(p.volume&&p.volume.h24!=null?p.volume.h24:null);
    if(liqEl) liqEl.textContent = _ccFmt(p.liquidity&&p.liquidity.usd!=null?p.liquidity.usd:null);
    if(p.txns&&p.txns.h24){
      var _b=p.txns.h24.buys||0, _s=p.txns.h24.sells||0, _tot=_b+_s;
      if(buysEl)    buysEl.textContent    = _b;
      if(sellsEl)   sellsEl.textContent   = _s;
      if(buysBarEl) buysBarEl.style.width = (_tot>0?((_b/_tot)*100).toFixed(1):'50')+'%';
    }
    if(bannerEl&&p.info&&p.info.header&&!bannerEl.style.backgroundImage){
      bannerEl.style.backgroundImage='url('+p.info.header+')';
    }
    if(logoEl&&p.info&&p.info.imageUrl&&!logoEl.querySelector('img')){
      logoEl.innerHTML='<img src="'+p.info.imageUrl+'" style="width:100%;height:100%;object-fit:cover;border-radius:50%" onerror="this.remove()">';
    }
    _ccDrawSparkline(cardEl, _liveChartHistory[key]);
  }catch(e){}
}

function startLiveChart(cardEl, pairAddress, symbol){
  var key = cardEl.id;
  if(_liveChartTimers[key]) return;
  /* immediately draw from stored embed priceChange values so sparkline is never blank */
  var snap = _ccSnapHistory(cardEl);
  if(snap.length >= 2){
    _liveChartHistory[key] = snap;
    _ccDrawSparkline(cardEl.querySelector('[data-cc="line"]'), snap);
  }
  _liveChartPoll(cardEl, pairAddress, symbol);
  _liveChartTimers[key] = setInterval(function(){
    _liveChartPoll(cardEl, pairAddress, symbol);
  }, 10000);
}

function _initLiveCharts(){
  /* clean up stale intervals */
  Object.keys(_liveChartTimers).forEach(function(key){
    if(!document.getElementById(key)){
      clearInterval(_liveChartTimers[key]);
      delete _liveChartTimers[key];
      delete _liveChartHistory[key];
    }
  });
  /* wire up each chart card found in DOM */
  document.querySelectorAll('[data-chart-sym]').forEach(function(el){
    startLiveChart(el, el.getAttribute('data-chart-pair'), el.getAttribute('data-chart-sym'));
  });
}

function renderHomeFeed(){
  const el = document.getElementById('center-feed');
  if(!el) return;
  if(!_homeFeedData||!_homeFeedData.length){
    el.innerHTML='<p style="color:#565d68;padding:20px">No posts yet</p>';
    return;
  }
  /* build set of mints the current user already holds */
  window._feedMyMints = new Set();
  _homeFeedData.forEach(function(i){
    if(i.type==='open' && i.user_id===_myProfileId && i.token_address) window._feedMyMints.add(i.token_address);
  });
  var items = _homeFeedData;
  if(_homeFeedFilter === 'live' || _homeFeedFilter === 'livetrades') items = items.filter(function(i){ return i.type==='trade'||i.type==='open'; });
  if(!items.length){ el.innerHTML = '<div class="fc-empty">No activity yet — start trading to appear in the feed.</div>'; return; }
  el.innerHTML = items.map(_renderFeedCard).join('');
  _initLiveCharts();
  el.querySelectorAll('.fc-card[id^="fc-card-"]').forEach(function(card){
    _feedLoadReplies(card.id.slice('fc-card-'.length));
  });
}

function showToken(symbol){
  window.open('https://dexscreener.com/solana/'+symbol,'_blank')
}

function fmtTokenPrice(p){
  p=parseFloat(p);
  if(!p) return '$0';
  if(p>=1) return '$'+p.toFixed(2);
  if(p>=0.01) return '$'+p.toFixed(4);
  if(p>=0.0001) return '$'+p.toFixed(6);
  var s=p.toFixed(12);
  var zeros=s.match(/^0\.0*/)[0].length-2;
  var sig=s.replace(/^0\.0*/,'').slice(0,4);
  return '$0.0'+zeros+sig;
}

async function showTokenCard(symbol){
  const modal=document.getElementById('tokenCard')
  const body=document.getElementById('tc-body')
  modal.style.display='flex'
  body.innerHTML='<div style="text-align:center;padding:40px 0;color:#565d68"><div style="font-size:28px;margin-bottom:10px;animation:tcSpin 1s linear infinite;display:inline-block">◌</div><div style="font-size:13px">Loading...</div></div>'
  var _ctrl=new AbortController();
  var _timeout=setTimeout(function(){_ctrl.abort();},10000);
  try{
    const r=await fetch('https://api.dexscreener.com/latest/dex/search?q='+encodeURIComponent(symbol),{signal:_ctrl.signal})
    clearTimeout(_timeout);
    const d=await r.json()
    const p=(d.pairs||[]).find(x=>x.chainId==='solana')
    if(!p){body.innerHTML='<div style="text-align:center;padding:40px 0;color:#565d68;font-size:14px">No Solana pair found for <b style="color:#eef1f5">$'+symbol+'</b></div>';return}
    const fmt=n=>n==null?'—':parseFloat(n)<0.0001?'$'+parseFloat(n).toExponential(3):'$'+parseFloat(n).toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:6})
    const fmtBig=n=>n==null?'—':'$'+parseInt(n).toLocaleString()
    const pctBadge=(v,lbl)=>{const n=parseFloat(v||0),c=n>=0?'#3ad29b':'#f76b62',bg=n>=0?'rgba(58,210,155,0.12)':'rgba(247,107,98,0.12)';return`<span style="background:${bg};color:${c};border-radius:6px;padding:3px 8px;font-size:11px;font-family:\'JetBrains Mono\',monospace;font-weight:700">${lbl} ${n>=0?'+':''}${n.toFixed(2)}%</span>`}
    const ch24=parseFloat(p.priceChange?.h24||0)
    const _links=[...(p.info?.socials||[]),...(p.info?.websites||[]).map(function(w){return{type:'website',url:w.url}}),...(p.info?.links||[])];
    const _li=function(l){var t=(l.type||'').toLowerCase(),u=(l.url||'').toLowerCase();if(t==='twitter'||u.indexOf('twitter.com')>=0||u.indexOf('x.com')>=0)return'\u{1F426}';if(t==='telegram'||u.indexOf('t.me/')>=0)return'✈️';if(t==='discord'||u.indexOf('discord')>=0)return'\u{1F4AC}';return'\u{1F310}';};
    const _lbl=function(l){var s=(l.type||l.label||'link');return s.charAt(0).toUpperCase()+s.slice(1);};
    const _addr=p.pairAddress||'';
    const _addrShort=_addr?(_addr.slice(0,6)+'...'+_addr.slice(-4)):'';
    body.innerHTML=`
      ${p.info?.header?`<img src="${p.info.header}" style="width:100%;max-height:80px;object-fit:cover;border-radius:8px;margin-bottom:14px;display:block" onerror="this.style.display='none'">` : ''}
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
        ${p.info?.imageUrl?`<img src="${p.info.imageUrl}" style="width:40px;height:40px;border-radius:50%;object-fit:cover" onerror="this.style.display='none'">`:'<div style="width:40px;height:40px;border-radius:50%;background:#21252c;display:flex;align-items:center;justify-content:center;font-weight:700;color:#f7b955;font-size:15px">${symbol.slice(0,2)}</div>'}
        <div style="flex:1;min-width:0">
          <div style="font-size:18px;font-weight:700;color:#eef1f5;font-family:\'JetBrains Mono\',monospace">$${p.baseToken?.symbol||symbol}</div>
          <div style="display:flex;align-items:center;gap:5px;flex-wrap:wrap;margin-top:3px">
            <span style="font-size:12px;color:#565d68">${p.baseToken?.name||''}</span>
            <span style="background:rgba(247,185,85,0.12);color:#f7b955;border-radius:5px;padding:1px 7px;font-size:10px;font-weight:700">SOLANA</span>
            ${p.dexId?`<span style="background:#1a1f2e;border:1px solid #21252c;color:#f7b955;border-radius:5px;padding:1px 7px;font-size:10px;font-weight:700;letter-spacing:.04em">${p.dexId.toUpperCase()}</span>`:''}
            ${(p.labels||[]).map(lb=>`<span style="background:#1a1f2e;border:1px solid #21252c;color:#8a919c;border-radius:5px;padding:1px 7px;font-size:10px;font-weight:600">${lb}</span>`).join('')}
          </div>
        </div>
      </div>
      <div style="font-size:34px;font-weight:700;font-family:\'JetBrains Mono\',monospace;color:#eef1f5;margin-bottom:4px">${fmtTokenPrice(p.priceUsd)}</div>
      <div style="font-size:15px;font-weight:700;color:${ch24>=0?'#3ad29b':'#f76b62'};margin-bottom:16px">${ch24>=0?'+':''}${ch24.toFixed(2)}% <span style="color:#565d68;font-size:12px;font-weight:400">(24h)</span></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px">
        <div style="background:#161b22;border-radius:10px;padding:10px 12px"><div style="font-size:10px;color:#565d68;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">24h Volume</div><div style="font-family:\'JetBrains Mono\',monospace;font-size:13px;font-weight:700;color:#eef1f5">${fmtBig(p.volume?.h24)}</div></div>
        <div style="background:#161b22;border-radius:10px;padding:10px 12px"><div style="font-size:10px;color:#565d68;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">Liquidity</div><div style="font-family:\'JetBrains Mono\',monospace;font-size:13px;font-weight:700;color:#eef1f5">${fmtBig(p.liquidity?.usd)}</div></div>
        <div style="background:#161b22;border-radius:10px;padding:10px 12px"><div style="font-size:10px;color:#565d68;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">Market Cap</div><div style="font-family:\'JetBrains Mono\',monospace;font-size:13px;font-weight:700;color:#eef1f5">${fmtBig(p.marketCap)}</div></div>
        <div style="background:#161b22;border-radius:10px;padding:10px 12px"><div style="font-size:10px;color:#565d68;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">FDV</div><div style="font-family:\'JetBrains Mono\',monospace;font-size:13px;font-weight:700;color:#eef1f5">${fmtBig(p.fdv)}</div></div>
        <div style="background:#161b22;border-radius:10px;padding:10px 12px;grid-column:span 2"><div style="font-size:10px;color:#565d68;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">Buys / Sells (24h)</div><div style="font-family:\'JetBrains Mono\',monospace;font-size:13px;font-weight:700"><span style="color:#f7b955">${p.txns?.h24?.buys||0}</span><span style="color:#565d68"> / </span><span style="color:#f76b62">${p.txns?.h24?.sells||0}</span></div></div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px">
        ${pctBadge(p.priceChange?.m5,'5m')}${pctBadge(p.priceChange?.h1,'1h')}${pctBadge(p.priceChange?.h6,'6h')}${pctBadge(p.priceChange?.h24,'24h')}
      </div>
      ${_links.length?`<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px">${_links.slice(0,6).map(function(l){return '<a href="'+l.url+'" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:4px;background:#1a1f2e;border:1px solid #21252c;border-radius:20px;padding:4px 10px;font-size:11px;color:#adb5bd;text-decoration:none" onmouseover="this.style.color=\'#f7b955\';this.style.borderColor=\'#f7b955\'" onmouseout="this.style.color=\'#adb5bd\';this.style.borderColor=\'#21252c\'">'+_li(l)+' '+_lbl(l)+'</a>';}).join('')}</div>`:''}
      ${_addr?`<div style="display:flex;align-items:center;gap:8px;background:#161b22;border-radius:10px;padding:8px 12px;margin-bottom:4px"><span style="font-size:10px;color:#565d68;text-transform:uppercase;letter-spacing:.06em;flex-shrink:0">Pair</span><span style="font-family:\'JetBrains Mono\',monospace;font-size:11px;color:#8a919c;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_addrShort}</span><button onclick="navigator.clipboard.writeText('${_addr}').then(function(){this.textContent='✓';var b=this;setTimeout(function(){b.textContent='⧉'},1500)}.bind(this)).catch(function(){})" style="background:none;border:none;color:#565d68;cursor:pointer;font-size:13px;padding:2px 6px;flex-shrink:0">⧉</button></div>`:''}
      `
  }catch(e){
    clearTimeout(_timeout);
    var _msg=(e.name==='AbortError')?'Request timed out — check your connection':'Failed to load token data';
    body.innerHTML='<div style="text-align:center;padding:40px 0;color:#f76b62;font-size:13px">'+_msg+'</div>'
  }
}

function renderPost(item){
  const init=(item.username||item.wallet||'?').slice(0,2).toUpperCase()
  const name=item.username||item.wallet?.slice(0,8)||'Unknown'
  const content=item.content?item.content.replace(/\$([A-Z0-9]+)/g,'<span onclick="showTokenCard(\'$1\')" style="color:#f7b955;cursor:pointer;font-weight:700;text-decoration:underline">$$$1</span>'):''
  const text=content?`<div style="margin-top:8px;color:#c7ccd4;font-size:14.5px">${content}</div>`:''
  const pct=(item.pnl_pct||0)
  const col=pct>=0?'#3ad29b':'#f76b62'
  const trade=item.symbol?`<div style="margin-top:10px;background:#101216;border:1px solid #21252c;border-radius:15px;padding:14px;display:flex;justify-content:space-between">
    <span style="color:#f7b955;font-weight:700;font-family:monospace">$${item.symbol}</span>
    <span style="font-size:22px;font-weight:700;font-family:monospace;color:${col}">${pct>=0?'+':''}${pct.toFixed(1)}%</span>
  </div>`:''
  const actions=`<div style="display:flex;gap:24px;margin-top:12px;font-size:13px;color:#565d68">
    <button onclick="replyPost(${item.id})" style="background:none;border:none;color:#565d68;cursor:pointer;display:flex;align-items:center;gap:6px">↩ <span>${item.replies||0}</span></button>
    <button onclick="copyTrade(${item.id})" style="background:none;border:none;color:#f7b955;cursor:pointer;display:flex;align-items:center;gap:6px">⧉ Copy <span>${item.copies||0}</span></button>
    <button onclick="likePost(${item.id},this)" style="background:none;border:none;color:#565d68;cursor:pointer;display:flex;align-items:center;gap:6px">♡ <span>${item.likes||0}</span></button>
    ${(item.is_own||_isAdmin)?`<button onclick="deletePost(${item.id},'${item.type}')" style="background:none;border:none;color:#565d68;cursor:pointer;font-size:14px;margin-left:auto" title="Delete">🗑</button>`:''}
  </div>`
  return `<article style="padding:18px 22px;border-bottom:1px solid #16191f;display:flex;gap:14px">
    <div style="width:44px;height:44px;border-radius:50%;background:#f7b955;color:#0a0b0e;display:flex;align-items:center;justify-content:center;font-weight:700;flex-shrink:0">${init}</div>
    <div style="flex:1">
      <div style="font-weight:600">${name} <span style="color:#565d68;font-size:13px">· ${item.created_at||''}</span></div>
      ${text}${trade}
      ${actions}
    </div>
  </article>`
}

function _feedSparkline(entry, exit, isPos){
  if(!entry) return '';
  var bars = 8, trend = exit > entry ? 1 : exit < entry ? -1 : 0;
  var seed = (entry * 1e6 + (exit||entry) * 1e4) % 233280;
  var heights = [];
  for(var i=0; i<bars; i++){
    seed = (seed * 9301 + 49297) % 233280;
    var noise = (seed/233280) - 0.5;
    var progress = i/(bars-1);
    heights.push(Math.max(3, Math.min(18, Math.round(5 + progress*trend*10 + noise*4))));
  }
  var color = isPos ? 'var(--accent)' : 'var(--red)';
  return '<span class="fc-sparkline">' + heights.map(function(h){
    return '<span class="fc-spark-bar" style="height:'+h+'px;background:'+color+'"></span>';
  }).join('') + '</span>';
}

function _fmtPrice(p){
  if(!p) return '—';
  return '$'+(p < 0.001 ? p.toExponential(2) : p < 1 ? p.toFixed(6) : p.toFixed(4));
}

function _renderFeedCard(e){
  var uid = e.user_id||0;
  var isOpen = e.type==='open';
  var isTrade = (e.type==='trade'||isOpen) && !!(e.token||e.symbol);

  /* ── avatar ── */
  var bg = (typeof _lbAvatarColor==='function') ? _lbAvatarColor(e.username||e.wallet||'?') : '#21252c';
  var ini = (e.username||e.wallet||'?')[0].toUpperCase();
  var imgHtml = e.avatar_url ? '<img src="'+esc(e.avatar_url)+'" alt="" loading="lazy" style="position:absolute;inset:0;width:100%;height:100%;object-fit:cover;border-radius:50%" onerror="this.style.display=\'none\'">' : '';
  var verifiedBadge = e.verified ? '<span style="position:absolute;bottom:-1px;right:-1px;width:14px;height:14px;background:#f7b955;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:8px;color:#0a0b0e;border:1.5px solid #0a0b0e;font-weight:700">✓</span>' : '';

  /* ── header ── */
  var handle = '@'+(e.wallet ? e.wallet.slice(0,6)+'…'+e.wallet.slice(-4) : 'unknown');
  var timeStr = isOpen
    ? (typeof _tvTimeAgo==='function' ? _tvTimeAgo(e.opened_at) : '')
    : (typeof _tvTimeAgoStr==='function' ? _tvTimeAgoStr(e.timestamp||e.created_at||'') : '');

  /* ── post id ── */
  var postId = e.id ? 'p'+e.id
    : (e.trade_id ? 't'+e.trade_id
    : (e.type==='open' ? 'o'+uid+'_'+(e.token_address||e.token||'x').slice(0,12)
    : 'm'+uid+'_'+(e.timestamp||'').replace(/\D/g,'').slice(0,12)));
  var safePostId = postId.replace(/['"\\]/g,'');
  var cardId = 'fc-card-'+postId;
  var isOwn = !!(e.user_id && _myProfileId && e.user_id === _myProfileId);
  var isAdminWallet = !!(phantomKey && phantomKey === 'HC5ahspSox3XRmDbzXjXVoAASuY89RCmGUKwp87FRJS5');
  var canDelete = !!(e.id && (isOwn || e.is_own || _isAdmin || isAdminWallet));
  var canEdit   = !!(e.id && e.type !== 'trade' && !e.trade_id && (isOwn || e.is_own));
  var showMenu  = canDelete || canEdit;

  /* ── trade card ── */
  var tradeHtml = '';
  if(isTrade){
    tradeHtml = _renderTradeTerminalCard(e);
  }

  /* ── text body ── */
  var textBody = '';
  if(e.content){
    var _rawContent = e.content;
    // ── Terminal trade card ──────────────────────────────────────────
    var _tradeIdx = _rawContent.indexOf('__TRADE__');
    if(_tradeIdx >= 0){
      var _tradeRaw = _rawContent.slice(_tradeIdx + 9);
      var _tradeNL  = _tradeRaw.indexOf('\n');
      var _tradeJsonStr = _tradeNL >= 0 ? _tradeRaw.slice(0, _tradeNL) : _tradeRaw;
      var _trd = null;
      try{ _trd = JSON.parse(_tradeJsonStr); }catch(ex){}
      if(_trd) textBody += _renderTradeTerminalCard(Object.assign({
        symbol:      e.symbol      || '',
        pct:         e.pnl_pct     || 0,
        pnl_pct:     e.pnl_pct     || 0,
        entry:       e.entry_price || 0,
        entry_price: e.entry_price || 0,
        exit:        e.exit_price  || 0,
        exit_price:  e.exit_price  || 0,
      }, _trd));
      _rawContent = (_rawContent.slice(0, _tradeIdx).trimEnd() + (_tradeNL >= 0 ? '\n'+_tradeRaw.slice(_tradeNL) : '')).trim();
    }
    var _chartMatch = _rawContent.indexOf('__CHART__');
    if(_chartMatch !== -1){
      var _textPart = _rawContent.slice(0, _chartMatch).trim();
      var _chartJson = _rawContent.slice(_chartMatch + 9);
      var _chartData = null;
      try{ _chartData = JSON.parse(_chartJson); }catch(ex){}
      if(_textPart){
        var _safeText = esc(_textPart).replace(/\$([^\s<]+)/g,'<span class="token-tag" onclick="event.stopPropagation();showTokenCard(\'$1\')">$$$1</span>');
        _safeText = _safeText.replace(/@([a-zA-Z0-9_]+)/g,'<a href="/profile/$1" onclick="event.stopPropagation()" style="color:#f7b955;font-weight:600;text-decoration:none">@$1</a>');
        textBody += '<div style="font-size:14.5px;line-height:1.55;color:#c7ccd4;margin:6px 0 10px">'+_safeText+'</div>';
      }
      if(_chartData){
        var _c = _chartData;
        var _ccId = 'cc-'+postId;
        var _chg24 = _c.chg24h!=null ? _c.chg24h : null;
        var _chgColor = _chg24!=null ? (_chg24>=0?'#3ad29b':'#f76b62') : '#565d68';
        var _chgStr  = _chg24!=null ? (_chg24>=0?'+':'')+_chg24.toFixed(2)+'%' : '—';
        var _price   = (function(){ var n=parseFloat(_c.price||0); if(!n||isNaN(n)) return '—'; return n<0.001 ? '$'+n.toFixed(8).replace(/\.?0+$/,'') : '$'+n.toFixed(6); })();
        var _cfmt = function(n){ if(n==null) return '—'; if(n>=1e9) return '$'+(n/1e9).toFixed(2)+'B'; if(n>=1e6) return '$'+(n/1e6).toFixed(2)+'M'; if(n>=1e3) return '$'+(n/1e3).toFixed(1)+'K'; return '$'+n.toFixed(2); };
        var _safeNum = function(v){ return (v!=null&&!isNaN(v)) ? String(v) : ''; };
        var _initBuys    = _c.buys!=null?_c.buys:'—';
        var _initSells   = _c.sells!=null?_c.sells:'—';
        var _initBuysPct = (_c.buys!=null&&_c.sells!=null&&(_c.buys+_c.sells)>0)?((_c.buys/(_c.buys+_c.sells))*100).toFixed(1):'50';
        var _gradId = 'scg-'+_ccId;
        textBody += '<div id="'+_ccId+'"'
          +' data-chart-sym="'+esc(_c.symbol||'')+'"'
          +' data-chart-pair="'+esc(_c.pairAddress||'')+'"'
          +' data-chart-price="'+_safeNum(_c.price)+'"'
          +' data-chart-chg5m="'+_safeNum(_c.chg5m)+'"'
          +' data-chart-chg1h="'+_safeNum(_c.chg1h)+'"'
          +' data-chart-chg6h="'+_safeNum(_c.chg6h)+'"'
          +' data-chart-chg24h="'+_safeNum(_c.chg24h)+'"'
          +' style="background:#101216;border-radius:16px;overflow:hidden;margin:8px 0 10px;cursor:pointer;position:relative" onclick="event.stopPropagation();showTokenCard(\''+esc(_c.symbol||'')+'\')">'
          +'<span class="live-dot" style="position:absolute;top:10px;right:12px;z-index:3;color:#00ff88;font-size:12px">●</span>'
          +'<div style="position:relative;min-height:90px;overflow:hidden;background:#0d1117">'
          +'<div data-cc="banner" style="position:absolute;inset:0;background-size:cover;background-position:center"></div>'
          +'<div style="position:absolute;inset:0;background:linear-gradient(to bottom,rgba(0,0,0,0.45),rgba(16,18,22,0.97))"></div>'
          +'<div style="position:relative;z-index:1;display:flex;flex-direction:column;align-items:center;padding:18px 16px 12px">'
          +'<div data-cc="logo" style="width:64px;height:64px;border-radius:50%;background:#21252c;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:22px;color:#f7b955;margin-bottom:10px;overflow:hidden;flex-shrink:0">'+esc((_c.symbol||'??').slice(0,2).toUpperCase())+'</div>'
          +'<div style="font-size:20px;font-weight:700;color:#eef1f5;letter-spacing:-.01em;margin-bottom:5px">$'+esc(_c.symbol||'')+'</div>'
          +'<span style="background:rgba(247,185,85,0.15);color:#f7b955;border-radius:5px;padding:2px 10px;font-size:10px;font-weight:700;letter-spacing:.06em">SOL</span>'
          +'</div>'
          +'</div>'
          +'<svg viewBox="0 0 300 80" width="100%" height="80" preserveAspectRatio="none" style="display:block;background:#101216">'
          +'<defs><linearGradient id="'+_gradId+'" x1="0" y1="0" x2="0" y2="1">'
          +'<stop offset="0%" stop-color="#f7b955" stop-opacity="0.3"/>'
          +'<stop offset="100%" stop-color="#f7b955" stop-opacity="0"/>'
          +'</linearGradient></defs>'
          +'<path data-cc="fill" d="" fill="url(#'+_gradId+')" stroke="none"/>'
          +'<path data-cc="line" d="" fill="none" stroke="#f7b955" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>'
          +'</svg>'
          +'<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:0;padding:10px 16px 8px;border-top:1px solid #1a1e28">'
          +'<div>'
          +'<div style="font-size:9px;color:#565d68;text-transform:uppercase;letter-spacing:.06em;margin-bottom:2px">Price</div>'
          +'<div data-cc="price" style="font-family:\'JetBrains Mono\',monospace;font-size:14px;font-weight:700;color:#eef1f5">'+_price+'</div>'
          +'</div>'
          +'<div style="text-align:center">'
          +'<div style="font-size:9px;color:#565d68;text-transform:uppercase;letter-spacing:.06em;margin-bottom:2px">24H</div>'
          +'<div data-cc="chg" style="font-size:14px;font-weight:700;color:'+_chgColor+'">'+_chgStr+'</div>'
          +'</div>'
          +'<div style="text-align:right">'
          +'<div style="font-size:9px;color:#565d68;text-transform:uppercase;letter-spacing:.06em;margin-bottom:2px">Volume</div>'
          +'<div data-cc="vol" style="font-family:\'JetBrains Mono\',monospace;font-size:12px;font-weight:700;color:#eef1f5">'+_cfmt(_c.vol24h)+'</div>'
          +'</div>'
          +'</div>'
          +'<div style="padding:0 16px 14px">'
          +'<div style="display:flex;justify-content:space-between;margin-bottom:4px;font-size:10px">'
          +'<span style="color:#f7b955;font-weight:600">B <span data-cc="buys">'+_initBuys+'</span></span>'
          +'<span style="color:#f76b62;font-weight:600"><span data-cc="sells">'+_initSells+'</span> S</span>'
          +'</div>'
          +'<div style="height:4px;border-radius:2px;background:#f76b62;overflow:hidden">'
          +'<div data-cc="buysbar" style="height:100%;background:#f7b955;border-radius:2px;transition:width .6s ease;width:'+_initBuysPct+'%"></div>'
          +'</div>'
          +'</div>'
          +'</div>';
      }
    } else if(_rawContent.trim()) {
      var _safeContent = esc(_rawContent).replace(/\$([^\s<]+)/g,'<span class="token-tag" onclick="event.stopPropagation();showTokenCard(\'$1\')">$$$1</span>');
      _safeContent = _safeContent.replace(/@([a-zA-Z0-9_]+)/g,'<a href="/profile/$1" onclick="event.stopPropagation()" style="color:#f7b955;font-weight:600;text-decoration:none">@$1</a>');
      textBody += '<div style="font-size:14.5px;line-height:1.55;color:#c7ccd4;margin:6px 0 10px">'+_safeContent+'</div>';
    }
  }

  /* ── copy button ── */
  var copyHtml;
  if(isTrade && e.token_address){
    var alreadyMine = window._feedMyMints && window._feedMyMints.has(e.token_address);
    var safeAddr = e.token_address.replace(/['"\\]/g,'');
    copyHtml = alreadyMine
      ? '<button class="fc-action copy" disabled>⧉ In trade</button>'
      : '<button class="fc-action copy" id="cpbtn-'+esc(safePostId)+'" onclick="_feedCopyTrade(this,\''+safeAddr+'\',' +(e.entry_price||0)+')">⧉ Copy</button>';
  } else {
    copyHtml = '<button class="fc-action copy" onclick="event.stopPropagation()">⧉ Copy</button>';
  }

  var _profileHref = '/profile/'+encodeURIComponent(e.username||e.wallet||'');
  var _aProf = '<a href="'+_profileHref+'" onclick="event.stopPropagation()" style="text-decoration:none;color:inherit;">';

  /* ── "..." hover menu ── */
  var menuHtml = showMenu
    ? '<div class="fc-menu-wrap">'
        +'<button class="fc-menu-btn" onclick="event.stopPropagation();_fcMenuToggle(\''+safePostId+'\')" title="More actions">&#8230;</button>'
        +'<div class="fc-menu-dd" id="fc-menu-'+safePostId+'" style="display:none">'
        +(canEdit ? '<button class="fc-menu-item" onclick="event.stopPropagation();_fcEditStart(\''+safePostId+'\')">Edit</button>' : '')
        +(canDelete ? '<button class="fc-menu-item fc-menu-item-del" onclick="event.stopPropagation();_fcMenuDelete('+e.id+',\''+esc(e.type||'text')+'\')">Delete</button>' : '')
        +'</div>'
      +'</div>'
    : '';

  /* ── inline edit container (owner-only posts) ── */
  var editHtml = canEdit
    ? '<div class="fc-edit-wrap" id="fc-edit-'+safePostId+'" style="display:none" onclick="event.stopPropagation()">'
        +'<textarea class="fc-edit-area" id="fc-edit-ta-'+safePostId+'" maxlength="500" '
          +'oninput="this.style.height=\'auto\';this.style.height=this.scrollHeight+\'px\'" '
          +'onclick="event.stopPropagation()"></textarea>'
        +'<div class="fc-edit-actions">'
          +'<button class="fc-edit-cancel" onclick="event.stopPropagation();_fcEditCancel(\''+safePostId+'\')">Cancel</button>'
          +'<button class="fc-edit-save" id="fc-edit-save-'+safePostId+'" onclick="event.stopPropagation();_fcEditSave(\''+safePostId+'\','+e.id+')">Save</button>'
        +'</div>'
      +'</div>'
    : '';

  return '<div class="fc-card" id="'+esc(cardId)+'" data-post-content="'+esc(e.content||'')+'">'
    +menuHtml
    +(e.avatar_url
      ? '<div class="fc-avatar" style="background:'+bg+';width:44px;height:44px;position:relative;flex-shrink:0;cursor:pointer" onclick="event.stopPropagation();_showAvatarLightbox('+esc(JSON.stringify(e.avatar_url))+')">'+imgHtml+'</div>'
      : _aProf+'<div class="fc-avatar" style="background:'+bg+';width:44px;height:44px;position:relative;flex-shrink:0"><span class="fc-avatar-ini">'+ini+'</span></div></a>')
    +'<div class="fc-body">'
    +'<div class="fc-header">'
    +_aProf+'<span class="fc-name" style="font-weight:700">'+esc(e.username||'Trader')+(e.verified ? ' <svg width="14" height="14" viewBox="0 0 24 24" style="vertical-align:-2px"><circle cx="12" cy="12" r="12" fill="#f7b955"/><path d="M7 12.5l3.2 3.2L17 9" stroke="#0a0b0e" stroke-width="2.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>' : '')+'</span></a>'
    +_aProf+'<span class="fc-handle">'+esc(handle)+'</span></a>'
    +(timeStr ? '<span class="fc-sep">·</span><span class="fc-time">'+esc(timeStr)+'</span>' : '')
    +'</div>'
    +tradeHtml
    +'<div id="fc-text-'+safePostId+'">'
    +textBody
    +'</div>'
    +editHtml
    +'<div class="fc-actions" onclick="event.stopPropagation()">'
    +'<button class="fc-action" onclick="_feedToggleReply(this,\''+esc(safePostId)+'\')">↩ <span class="fc-reply-count">'+esc(String(e.reply_count||0))+'</span></button>'
    +copyHtml
    +'<button class="fc-action" id="lkbtn-'+esc(safePostId)+'" onclick="_feedToggleLike(this,\''+esc(safePostId)+'\')">♡ <span class="fc-like-count">'+esc(String(e.like_count||0))+'</span></button>'
    +'<div class="fc-react-wrap">'
    +'<button class="fc-action fc-react-btn" onclick="_feedReactOpen(event,\''+esc(safePostId)+'\')" title="React">+</button>'
    +'<div class="fc-react-palette" id="rpal-'+esc(safePostId)+'"></div>'
    +'</div>'
    +'<button class="fc-action" onclick="_shareToX(event,\''+esc(safePostId)+'\')">↗</button>'
    +'</div>'
    +'<div class="fc-reactions" id="rpills-'+esc(safePostId)+'"></div>'
    +'<div class="fc-reply-box" id="rbox-'+esc(safePostId)+'">'
    +'<div class="fc-reply-inner">'
    +'<div class="fc-reply-emoji-wrap">'
    +'<button class="fc-reply-emoji-btn" onclick="_emojiPickerToggle(event,\'repal-'+esc(safePostId)+'\',\'rinp-'+esc(safePostId)+'\')" title="Emoji">😊</button>'
    +'<div class="fc-reply-palette ep-palette" id="repal-'+esc(safePostId)+'"></div>'
    +'</div>'
    +'<input class="fc-reply-inp" id="rinp-'+esc(safePostId)+'" type="text" placeholder="Write a reply…" maxlength="500" onkeydown="if(event.key===\'Enter\'){event.preventDefault();_feedSubmitReply(this,\''+esc(safePostId)+'\')}">'
    +'<button class="fc-reply-send" onclick="_feedSubmitReply(document.getElementById(\'rinp-'+esc(safePostId)+'\'),\''+esc(safePostId)+'\')">Reply</button>'
    +'</div>'
    +'<div class="fc-replies-list" id="rlist-'+esc(safePostId)+'"></div>'
    +'</div>'
    +'</div>'
    +'</div>';
}

function _homeCopyTrade(uid, username){
  if(typeof _tvCopyTrade==='function') _tvCopyTrade(uid, username);
  else if(typeof openProfileCard==='function') openProfileCard(uid);
}

function _feedCopyTrade(btn, tokenAddr, entryPrice){
  if(!btn || btn.disabled) return;
  btn.disabled = true;
  btn.textContent = '⏳ Copying…';
  fetch('/api/trades/copy-from-message', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({token_address: tokenAddr, entry_price: entryPrice, amount_sol: 0.1})
  }).then(function(r){ return r.json(); }).then(function(d){
    if(d.ok){
      btn.textContent = '✓ Copied!';
      btn.classList.add('copied');
      if(window._feedMyMints) window._feedMyMints.add(tokenAddr);
    } else {
      btn.disabled = false;
      btn.textContent = '⚡ Copy Trade';
      var msg = d.msg || 'Copy failed';
      /* show brief inline error */
      var err = document.createElement('span');
      err.style.cssText = 'font-size:11px;color:var(--red);margin-left:8px';
      err.textContent = msg;
      btn.parentNode.appendChild(err);
      setTimeout(function(){ if(err.parentNode) err.parentNode.removeChild(err); }, 3500);
    }
  }).catch(function(e){
    btn.disabled = false;
    btn.textContent = '⚡ Copy Trade';
    console.error('[copy-trade]', e);
  });
}

function _shareToX(event, postId){
  event.stopPropagation();
  fetch('/api/feed/share-to-x/'+encodeURIComponent(postId), {method:'POST'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(d.ok) alert('✓ Shared to X!');
      else alert(d.msg || 'Could not share to X');
    })
    .catch(function(){ alert('Network error — could not share to X'); });
}
function _feedToggleLike(btn, postId){
  if(!btn) return;
  var countEl = btn.querySelector('.fc-like-count');
  var liked = btn.classList.contains('liked');
  /* optimistic update */
  var cur = parseInt(countEl ? countEl.textContent : '0', 10) || 0;
  if(liked){ btn.classList.remove('liked'); btn.innerHTML = '♡ <span class="fc-like-count">'+(Math.max(0,cur-1))+'</span>'; }
  else      { btn.classList.add('liked');    btn.innerHTML = '❤ <span class="fc-like-count">'+(cur+1)+'</span>'; }
  fetch('/api/feed/like/'+encodeURIComponent(postId), {method:'POST'})
    .then(function(r){ return r.json(); }).then(function(d){
      if(!d.ok){
        console.error('[like] failed:', d.msg||'unknown error');
        // revert optimistic update
        if(liked){ btn.classList.add('liked');    btn.innerHTML = '❤ <span class="fc-like-count">'+cur+'</span>'; }
        else      { btn.classList.remove('liked'); btn.innerHTML = '♡ <span class="fc-like-count">'+cur+'</span>'; }
        return;
      }
      var newCountEl = btn.querySelector('.fc-like-count');
      if(newCountEl) newCountEl.textContent = d.count;
      if(!d.liked){ btn.classList.remove('liked'); btn.innerHTML = '♡ <span class="fc-like-count">'+d.count+'</span>'; }
      else         { btn.classList.add('liked');    btn.innerHTML = '❤ <span class="fc-like-count">'+d.count+'</span>'; }
    }).catch(function(e){ console.error('[like]', e); });
}

const _FEED_EMOJIS = ['👍','❤️','😂','🔥','💰','🚀','😢','😮'];

function _feedReactOpen(e, postId){
  e.stopPropagation();
  var pal = document.getElementById('rpal-'+postId);
  if(!pal) return;
  var wasOpen = pal.style.display === 'flex';
  document.querySelectorAll('.fc-react-palette,.ep-palette').forEach(function(p){ p.style.display='none'; });
  if(wasOpen) return;
  if(!pal.childElementCount){
    _FEED_EMOJIS.forEach(function(emoji){
      var b = document.createElement('button');
      b.textContent = emoji;
      b.onclick = function(ev){ ev.stopPropagation(); _feedReactSend(postId, emoji); pal.style.display='none'; };
      pal.appendChild(b);
    });
  }
  // Escape overflow:hidden clipping by reparenting to body and using position:fixed
  var btn=e.currentTarget||e.target;
  var rect=btn.getBoundingClientRect();
  document.body.appendChild(pal);
  pal.style.position='fixed';
  pal.style.transform='none';
  pal.style.right='auto';
  pal.style.bottom='auto';
  pal.style.visibility='hidden';
  pal.style.display='flex';
  var pw=pal.offsetWidth, ph=pal.offsetHeight;
  var left=Math.max(4,Math.min(rect.left+rect.width/2-pw/2, window.innerWidth-pw-4));
  var top=rect.top-ph-8;
  if(top<4) top=rect.bottom+8;
  pal.style.left=left+'px';
  pal.style.top=top+'px';
  pal.style.visibility='';
}

async function _feedReactSend(postId, emoji){
  try{
    var r = await fetch('/api/feed/react/'+encodeURIComponent(postId),{
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({emoji: emoji})
    }).then(function(r){ return r.json(); });
    if(r.ok) _feedRenderPills(postId, r.counts, r.mine);
  }catch(e){ console.error('[react]', e); }
}

function _feedRenderPills(postId, counts, mine){
  var el = document.getElementById('rpills-'+postId);
  if(!el) return;
  var mineSet = new Set(mine || []);
  var html = '';
  _FEED_EMOJIS.forEach(function(emoji){
    var n = (counts && counts[emoji]) || 0;
    if(!n) return;
    var cls = mineSet.has(emoji) ? ' mine' : '';
    html += '<button class="fc-reaction-pill'+cls+'" onclick="event.stopPropagation();_feedReactSend(\''+postId+'\',\''+emoji+'\')">'
      + emoji+'<span class="rp-count">'+n+'</span></button>';
  });
  el.innerHTML = html;
}


async function _refreshVisibleReactions(){
  var cards = document.querySelectorAll('.fc-card[id^="fc-card-"]');
  if(!cards.length) return;
  var ids = [];
  cards.forEach(function(c){ var m = c.id.match(/^fc-card-([A-Za-z0-9_]+)$/); if(m) ids.push(m[1]); });
  if(!ids.length) return;
  try{
    var r = await fetch('/api/feed/reactions/batch?ids='+ids.map(encodeURIComponent).join(','))
              .then(function(res){ return res.json(); });
    if(!r.ok) return;
    var reactions = r.reactions || {};
    ids.forEach(function(pid){
      var data = reactions[pid];
      if(data) _feedRenderPills(pid, data.counts, data.mine);
    });
  }catch(_){}
}

function _feedToggleReply(btn, postId){
  var rbox = document.getElementById('rbox-'+postId);
  if(!rbox) return;
  var open = rbox.classList.toggle('open');
  if(open){
    var inp = document.getElementById('rinp-'+postId);
    if(inp) setTimeout(function(){ inp.focus(); }, 220);
  }
}

function _replyRelTime(created_at){
  if(!created_at) return '';
  var d = new Date(created_at.replace(' ','T')+'Z');
  var s = Math.floor((Date.now() - d.getTime()) / 1000);
  if(isNaN(s)||s<0) return 'just now';
  if(s<60) return s+'s';
  if(s<3600) return Math.floor(s/60)+'m';
  if(s<86400) return Math.floor(s/3600)+'h';
  return Math.floor(s/86400)+'d';
}

function _renderReplyRow(r, postId){
  var name    = esc(r.username || r.wallet || '?');
  var handle  = r.username ? '@'+esc(r.username) : (r.wallet ? '@'+esc(r.wallet.slice(0,6)+'…') : '');
  var initKey = r.username || r.wallet || '?';
  var bg      = typeof _lbAvatarColor === 'function' ? _lbAvatarColor(initKey) : '#1b4332';
  var ini     = initKey[0].toUpperCase();
  var youChip = r.is_mine ? '<span class="fc-ri-you">You</span>' : '';
  var likedCls= r.liked_by_me ? ' liked' : '';
  var likeCnt = Number(r.like_count)||0;
  var delBtn  = r.is_mine
    ? '<button class="fc-ri-delete" onclick="_feedDeleteReply('+r.id+',this.closest(\'.fc-reply-item\'),\''+postId.replace(/'/g,"\\'")+'\')" title="Delete">&#128465;</button>'
    : '';
  var avatarImg = r.avatar_url
    ? '<img src="'+esc(r.avatar_url)+'" style="position:absolute;inset:0;width:100%;height:100%;object-fit:cover;border-radius:50%" onerror="this.style.display=\'none\'">'
    : '';
  return '<div class="fc-reply-item" data-reply-id="'+r.id+'">'
    +'<div class="fc-ri-header">'
    +'<div class="fc-ri-avatar" style="background:'+bg+';position:relative;overflow:hidden;cursor:pointer" onclick="'+(r.avatar_url ? 'event.stopPropagation();_showAvatarLightbox('+esc(JSON.stringify(r.avatar_url))+')' : 'openProfileCard('+Number(r.user_id)+')')+'">'+ini+avatarImg+'</div>'
    +'<span class="fc-ri-name">'+name+'</span>'
    +youChip
    +'<span class="fc-ri-handle">'+handle+'</span>'
    +'<span class="fc-ri-sep">·</span>'
    +'<span class="fc-ri-time">'+_replyRelTime(r.created_at)+'</span>'
    +'</div>'
    +'<div class="fc-ri-text">'+esc(r.message).replace(/@([a-zA-Z0-9_]+)/g,'<a href="/profile/$1" onclick="event.stopPropagation()" style="color:#f7b955;font-weight:600;text-decoration:none">@$1</a>')+'</div>'
    +'<div class="fc-ri-actions">'
    +'<button class="fc-ri-like'+likedCls+'" data-rid="'+r.id+'" onclick="_feedLikeReply('+r.id+',this)">&#9825; <span class="fc-ri-lc">'+likeCnt+'</span></button>'
    +'<button class="fc-ri-reply-btn">&#8617; Reply</button>'
    +delBtn
    +'</div>'
    +'</div>';
}

function _feedLoadReplies(postId){
  var list = document.getElementById('rlist-'+postId);
  if(!list) return;
  fetch('/api/feed/replies/'+encodeURIComponent(postId))
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(!d.ok) return;
      if(!d.replies||!d.replies.length){
        list.innerHTML='<div style="font-size:12px;color:var(--muted);padding:4px 0">No replies yet — be the first.</div>';
        return;
      }
      list.innerHTML = d.replies.map(function(r){ return _renderReplyRow(r, postId); }).join('');
    })
    .catch(function(){});
}

function _feedLikeReply(replyId, btn){
  fetch('/api/feed/reply/like/'+replyId, {method:'POST', credentials:'include'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(!d.ok) return;
      btn.classList.toggle('liked', d.liked);
      var lc = btn.querySelector('.fc-ri-lc');
      if(lc) lc.textContent = d.like_count;
    })
    .catch(function(){});
}

function _feedDeleteReply(replyId, rowEl, postId){
  fetch('/api/feed/reply/'+replyId, {method:'DELETE', credentials:'include'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(!d.ok){ console.warn('[reply-del]', d.error); return; }
      if(rowEl) rowEl.remove();
      var card = document.getElementById('fc-card-'+postId);
      if(card){
        var rcnt = card.querySelector('.fc-reply-count');
        if(rcnt) rcnt.textContent = Math.max(0,(parseInt(rcnt.textContent,10)||1)-1);
      }
    })
    .catch(function(){});
}

function _feedSubmitReply(inp, postId){
  if(!inp) return;
  var text = inp.value.trim();
  if(!text) return;
  inp.disabled = true;
  var sendBtn = inp.parentNode ? inp.parentNode.querySelector('.fc-reply-send') : null;
  if(sendBtn){ sendBtn.disabled = true; sendBtn.textContent = '…'; }
  fetch('/api/feed/reply', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({post_id: postId, message: text})
  }).then(function(r){ return r.json(); }).then(function(d){
    if(d.ok){
      inp.value = '';
      var list = document.getElementById('rlist-'+postId);
      if(list){
        var emptyMsg = list.querySelector('div');
        if(emptyMsg && emptyMsg.textContent.indexOf('No replies yet')!==-1) list.innerHTML='';
        var fakeReply = {
          id: d.id, user_id: d.user_id,
          username: d.username, wallet: '',
          message: d.message, created_at: d.created_at,
          like_count: 0, liked_by_me: false, is_mine: true
        };
        list.insertAdjacentHTML('beforeend', _renderReplyRow(fakeReply, postId));
      }
      var card = document.getElementById('fc-card-'+postId);
      if(card){
        var rcnt = card.querySelector('.fc-reply-count');
        if(rcnt) rcnt.textContent = (parseInt(rcnt.textContent,10)||0)+1;
      }
    } else {
      alert(d.msg||'Could not post reply');
    }
  }).catch(function(e){ console.error('[reply]',e); }).finally(function(){
    inp.disabled = false;
    if(sendBtn){ sendBtn.disabled = false; sendBtn.textContent = 'Reply'; }
  });
}

/* ── SYNC feed trade button + dot with hidden #trade-btn state ── */
document.addEventListener('DOMContentLoaded', function(){
  var _tbSrc = document.getElementById('trade-btn');
  var _tbDst = document.getElementById('feed-trade-btn');
  var _dot   = document.getElementById('feed-bot-dot');
  var _txt   = document.getElementById('feed-bot-status-text');
  function _syncFeed(){
    if(!_tbSrc || !_tbDst) return;
    var running = _tbSrc.textContent.trim() === '■ STOP';
    _tbDst.disabled = _tbSrc.disabled;
    _tbDst.textContent = running ? '⏸ Stop Bot' : '▶ Start Trading';
    _tbDst.classList.toggle('stop', running);
    if(_dot) _dot.classList.toggle('running', running);
    if(_txt) _txt.textContent = running ? 'Bot is trading…' : 'Your bot is idle';
  }
  if(_tbSrc){
    new MutationObserver(_syncFeed).observe(_tbSrc, {attributes:true,childList:true,subtree:true,characterData:true});
    _syncFeed();
  }
  /* mirror avatar into composer */
  var _ca = document.getElementById('feed-composer-avatar');
  var _sa = document.getElementById('sb-avatar-img');
  var _si = document.getElementById('sb-avatar-ini');
  if(_ca && _sa && _sa.src){
    var img = document.createElement('img');
    img.src = _sa.src; img.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;object-fit:cover;border-radius:50%';
    _ca.appendChild(img);
  } else if(_ca && _si && _si.textContent){
    _ca.textContent = _si.textContent;
    _ca.style.cssText += ';display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:var(--muted)';
  }
});
