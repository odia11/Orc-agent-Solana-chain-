"""URLs in a post become links -- without becoming an injection hole.

A post is text a stranger typed. Turning any of it into HTML is the moment
that matters, so most of these are about what must NOT come out: no
javascript: link, no tag that survives escaping, and no @mention rule running
inside an href, which would rewrite the middle of a URL into a link of its
own.

The real functions are lifted out of static/dashboard.js and run in node."""
import json, re, subprocess, sys

REPO = '/home/user/Orc-agent-Solana-chain-'
JS   = open(REPO + '/static/dashboard.js').read()

checks = []
def check(name, cond):
    checks.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name)

def fn(name):
    m = re.search(rf'^function {re.escape(name)}\(.*?\n\}}', JS, re.M | re.S)
    assert m, name
    return m.group(0)

CASES = [
    'https://openbell.market/',
    'check this https://openbell.market/ out',
    'www.openbell.market',
    'see https://a.com/x.',
    '(see https://a.com/x)',
    'https://en.wikipedia.org/wiki/Foo_(bar)',
    'https://x.com/@someone',
    'mail me at me@example.com',
    '$OPENBELL is at 200k https://openbell.market/',
    '@degentrader1990 look https://a.com',
    'javascript:alert(1)',
    'https://a.com/?a=1&b=2',
    'https://a.com/" onmouseover="alert(1)',
    '<script>alert(1)</script>',
    'https://averyveryverylongdomainname.example.com/with/a/very/long/path/that/goes/on',
    'plain text, no link',
    '',
]

harness = fn('esc') + '\n' + fn('_fcTagText') + '\n' + fn('_fcLinkHtml') + '\n' + fn('_fcRichText') + '''
var out = [];
''' + 'var CASES = ' + json.dumps(CASES) + ';\n' + '''
CASES.forEach(function(c){ out.push(_fcRichText(c)); });
console.log(JSON.stringify(out));
'''
open('_lh.js', 'w').write(harness)
res = subprocess.run(['node', '_lh.js'], capture_output=True, text=True)
assert res.returncode == 0, res.stderr
R = dict(zip(CASES, json.loads(res.stdout)))
for c in CASES:
    print(f'   {c!r}\n     -> {R[c]}')
print()

check('a bare URL becomes a link',
      '<a href="https://openbell.market/"' in R['https://openbell.market/'])
check('it opens in a new tab and cannot reach back into this page',
      'target="_blank"' in R['https://openbell.market/']
      and 'rel="noopener noreferrer nofollow"' in R['https://openbell.market/'])
check('clicking the link does not also open the post it sits in',
      'event.stopPropagation()' in R['https://openbell.market/'])
check('the surrounding words survive intact',
      R['check this https://openbell.market/ out'].startswith('check this ')
      and R['check this https://openbell.market/ out'].endswith(' out'))
check('a scheme-less www. link still works, and gets https',
      'href="https://www.openbell.market"' in R['www.openbell.market'])

check('a trailing full stop is the sentence\'s, not the URL\'s',
      R['see https://a.com/x.'].endswith('</a>.')
      and 'href="https://a.com/x"' in R['see https://a.com/x.'])
check('a closing bracket that opened outside the URL goes back to the text',
      R['(see https://a.com/x)'].endswith('</a>)'))
check('...but a bracket the URL genuinely contains stays in the link',
      'href="https://en.wikipedia.org/wiki/Foo_(bar)"' in R['https://en.wikipedia.org/wiki/Foo_(bar)'])

# ── the ordering bugs this function exists to prevent ──
check('the @mention rule never runs inside a URL — /@([a-zA-Z0-9_]+)/ would '
      'otherwise rewrite the middle of an href into a link of its own',
      '/profile/someone' not in R['https://x.com/@someone']
      and 'href="https://x.com/@someone"' in R['https://x.com/@someone'])
check('a cashtag next to a URL still becomes a token tag, and the URL still a link',
      'token-tag' in R['$OPENBELL is at 200k https://openbell.market/']
      and '<a href="https://openbell.market/"' in R['$OPENBELL is at 200k https://openbell.market/'])
check('a mention next to a URL still becomes a profile link',
      '/profile/degentrader1990' in R['@degentrader1990 look https://a.com'])

# ── what must never come out ──
check('javascript: is not a link, at any point',
      '<a' not in R['javascript:alert(1)'] and 'javascript:' not in R['javascript:alert(1)'].lower().replace('javascript:alert(1)', ''))
check('...and its text is still shown, escaped, rather than silently dropped',
      'javascript:alert(1)' in R['javascript:alert(1)'])
check('a quote inside a URL cannot break out of the href attribute',
      'onmouseover=' not in R['https://a.com/" onmouseover="alert(1)']
      or '&quot;' in R['https://a.com/" onmouseover="alert(1)'])
check('a script tag in a post is escaped, not executed',
      '<script>' not in R['<script>alert(1)</script>']
      and '&lt;script&gt;' in R['<script>alert(1)</script>'])
check('an ampersand in a query string is escaped in the href but the link still '
      'points at the real URL',
      'href="https://a.com/?a=1&amp;b=2"' in R['https://a.com/?a=1&b=2'])

check('a very long URL is shortened for display but linked in full',
      len(re.search(r'>([^<]*)</a>', R[CASES[14]]).group(1)) <= 42
      and 'with/a/very/long/path/that/goes/on"' in R[CASES[14]])
check('an email address is not mangled into a profile link — an @ has to start a '
      'word, or "me@example.com" renders as "me" plus a link to /profile/example',
      R['mail me at me@example.com'] == 'mail me at me@example.com')
check('text with no URL is unchanged apart from escaping',
      R['plain text, no link'] == 'plain text, no link')
check('empty content produces nothing rather than an error', R[''] == '')

# ── every place a post is rendered uses it ──
check('the feed post, the post-with-chart, the inline edit and the replies all '
      'go through the one function, so none of them can drift',
      JS.count('_fcRichText(') - 1 == 4)   # minus its own definition
check('no call site still does the old inline escape+replace',
      "esc(_rawContent).replace(/\\$(" not in JS and "esc(r.message).replace(/@(" not in JS)

print(f'\n{sum(1 for _, c in checks if c)}/{len(checks)} checks passed')
sys.exit(0 if all(c for _, c in checks) else 1)
