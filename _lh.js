function esc(s){
  // HTML-encode external data before injecting into innerHTML
  return String(s==null?'':s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
}
function _fcTagText(t){
  if(!t) return '';
  // A ticker starts with a LETTER. /\$([^\s<]+)/ matched anything after a
  // dollar sign, so "$500 profit" and "$0.000002346" became clickable token
  // tags that resolve to nothing -- any post quoting a price or an amount
  // got them. Bounded length too: a ticker is not forty characters long.
  var out = esc(t).replace(/\$([A-Za-z][A-Za-z0-9_]{0,19})\b/g,'<span class="token-tag" data-sym="$1" onclick="event.stopPropagation();showTokenCard(this.dataset.sym)">$$$1</span>');
  // The @ has to START a word. Without that guard "me@example.com" renders as
  // "me" followed by a link to /profile/example -- the same class of bug the
  // URL split above exists to prevent, one character earlier.
  return out.replace(/(^|[^A-Za-z0-9_])@([a-zA-Z0-9_]+)/g,'$1<a href="/profile/$2" onclick="event.stopPropagation()" style="color:#f7b955;font-weight:600;text-decoration:none">@$2</a>');
}
function _fcLinkHtml(url){
  // Trailing punctuation is almost always the sentence's, not the URL's:
  // "see https://a.com/x." should not link the full stop. Unmatched closers
  // go back too, so "(see https://a.com/x)" keeps its bracket.
  var trail = '';
  var m = url.match(/[.,!?;:'"\)\]]+$/);
  if(m){
    var cut = m[0];
    // ...unless the URL genuinely contains the bracket, e.g. a wiki link.
    while(cut && cut[0] === ')' && (url.slice(0, url.length - cut.length).split('(').length >
                                    url.slice(0, url.length - cut.length).split(')').length)){
      cut = cut.slice(1);
    }
    if(cut){ trail = cut; url = url.slice(0, url.length - cut.length); }
  }
  if(!url) return esc(trail);
  var href = /^https?:\/\//i.test(url) ? url : 'https://' + url;
  // A long URL wraps to three lines and buries the post. Show the host and
  // enough path to recognise it, exactly as the platforms people came from do.
  var label = url.replace(/^https?:\/\//i,'').replace(/\/$/,'');
  if(label.length > 42) label = label.slice(0, 41) + '…';
  return '<a href="'+esc(href)+'" target="_blank" rel="noopener noreferrer nofollow" '
       + 'onclick="event.stopPropagation()" '
       + 'style="color:#f7b955;text-decoration:none;word-break:break-word">'+esc(label)+'</a>'
       + esc(trail);
}
function _fcRichText(raw){
  var s = String(raw == null ? '' : raw), out = '', last = 0, m;
  var re = /\b(?:https?:\/\/|www\.)[^\s<>"'`]+/gi;
  while((m = re.exec(s)) !== null){
    out += _fcTagText(s.slice(last, m.index)) + _fcLinkHtml(m[0]);
    last = m.index + m[0].length;
  }
  return out + _fcTagText(s.slice(last));
}
var out = [];
var CASES = ["https://openbell.market/", "check this https://openbell.market/ out", "www.openbell.market", "see https://a.com/x.", "(see https://a.com/x)", "https://en.wikipedia.org/wiki/Foo_(bar)", "https://x.com/@someone", "mail me at me@example.com", "$OPENBELL is at 200k https://openbell.market/", "@degentrader1990 look https://a.com", "javascript:alert(1)", "https://a.com/?a=1&b=2", "https://a.com/\" onmouseover=\"alert(1)", "<script>alert(1)</script>", "https://averyveryverylongdomainname.example.com/with/a/very/long/path/that/goes/on", "plain text, no link", "$OPENBELL is up but I only made $500 profit", "price is $0.000002346 not $0.052345", "$verylongtickernamethatisnotarealticker", ""];

CASES.forEach(function(c){ out.push(_fcRichText(c)); });
console.log(JSON.stringify(out));
