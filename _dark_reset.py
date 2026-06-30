import re

with open('dashboard.html', 'r', encoding='utf-8') as f:
    content = f.read()

# ── 1. Meta theme-color
content = content.replace('content="#ffffff"', 'content="#0f0f0f"')

# ── 2. Root variables (single-line block in file)
OLD_ROOT = ('--bg:#ffffff;--bg2:#ffffff;--bg3:#f8f8f8;--bg4:#f0f0f0;'
            '--green:#000000;--green2:#000000;--red:#ff0000;--yellow:#767676;--blue:#767676;--purple:#767676;'
            '--text:#000000;--muted:#767676;--dim:#767676;--border:#e5e5e5;--border2:#e5e5e5;'
            '--shadow-card:0 1px 3px rgba(0,0,0,.08);--card-radius:10px;'
            '--glass-border:#e5e5e5;--green-glow:transparent;')
NEW_ROOT = ('--bg:#0f0f0f;--bg2:#141414;--bg3:#1c1c1c;--bg4:#242424;'
            '--green:#00e676;--green2:#00e676;--red:#ff1744;--yellow:#f5a623;--blue:#4fc3f7;--purple:#ce93d8;'
            '--text:#ffffff;--muted:#aaaaaa;--dim:#aaaaaa;--border:#2e2e2e;--border2:#2e2e2e;'
            '--shadow-card:0 2px 8px rgba(0,0,0,.4);--card-radius:10px;'
            '--glass-border:#2e2e2e;--green-glow:rgba(0,230,118,.15);')
content = content.replace(OLD_ROOT, NEW_ROOT)

# ── 3. Isolate <style> section
style_start = content.index('<style>') + len('<style>')
style_end   = content.index('</style>')
before_css  = content[:style_start]
css         = content[style_start:style_end]
after_style = content[style_end:]   # starts with </style>

# ── 4. CSS bulk replacements

# Backgrounds (light → dark)
for old, new in [
    ('background:#ffffff',  'background:#1c1c1c'),
    ('background:#f8f8f8',  'background:#1c1c1c'),
    ('background:#fff8f8',  'background:#1c1c1c'),
    ('background:#f0f0f0',  'background:#242424'),
    ('background:#000000',  'background:#141414'),
    ('background:#1a1a1a',  'background:#1c1c1c'),
]:
    css = css.replace(old, new)
css = re.sub(r'background:#fff(?=[;}\s,])', 'background:#1c1c1c', css)

# Text colors (dark/grey → light)
for old, new in [
    ('color:#000000',  'color:#ffffff'),
    ('color:#767676',  'color:#aaaaaa'),
    ('color:#888888',  'color:#aaaaaa'),
    ('color:#666666',  'color:#aaaaaa'),
    ('color:#444444',  'color:#aaaaaa'),
    ('color:#b5b5b5',  'color:#555555'),
]:
    css = css.replace(old, new)
css = re.sub(r'color:#000(?=[;}\s])', 'color:#ffffff', css)

# Borders (light → dark, explicit blacks → subtle)
for old, new in [
    ('#e5e5e5',                          '#2e2e2e'),
    ('#dddddd',                          '#2e2e2e'),
    ('#333333',                          '#2e2e2e'),
    ('solid #1a1a1a',                    'solid #2e2e2e'),
    ('border:1px solid #000000',         'border:1px solid #2e2e2e'),
    ('border-color:#000000',             'border-color:#2e2e2e'),
    ('border-bottom:1px solid #000000',  'border-bottom:1px solid #2e2e2e'),
    ('border-left:2px solid #000000',    'border-left:2px solid #2e2e2e'),
]:
    css = css.replace(old, new)
css = re.sub(r'border:1px solid #000(?=[;}\s])', 'border:1px solid #2e2e2e', css)

# Old red → new red
css = css.replace('#ff0000', '#ff1744')

# ── 5. Targeted post-bulk CSS fixes

# Header bg: #000000 → #141414 by bulk, need #0f0f0f
css = css.replace(
    'background:#141414;border-bottom:none;height:48px;gap:12px;flex-shrink:0}',
    'background:#0f0f0f;border-bottom:none;height:48px;gap:12px;flex-shrink:0}')

# sb-nav-item base: bulk made it #ffffff, but spec says #aaaaaa
css = css.replace(
    'gap:10px;padding:8px 16px;font-size:13px;color:#ffffff;cursor:pointer',
    'gap:10px;padding:8px 16px;font-size:13px;color:#aaaaaa;cursor:pointer')

# sb-sol: green
css = css.replace(
    '.sb-sol{font-size:13px;font-weight:700;color:#ffffff;margin-bottom:3px}',
    '.sb-sol{font-size:13px;font-weight:700;color:#00e676;margin-bottom:3px}')

# sb-pnl.pos: green
css = css.replace('.sb-pnl.pos{color:#ffffff;font-weight:700}',
                  '.sb-pnl.pos{color:#00e676;font-weight:700}')

# statsbar-val.pos: green
css = css.replace('.statsbar-val.pos{color:#ffffff;font-weight:900}',
                  '.statsbar-val.pos{color:#00e676;font-weight:900}')

# botbar-btn-start → green bg, black text
css = css.replace('.botbar-btn-start{background:#141414;color:#ffffff}',
                  '.botbar-btn-start{background:#00e676;color:#000000}')

# trade-btn → green
css = css.replace('.trade-btn{background:#141414;color:#fff;font-weight:700;border-radius:8px}',
                  '.trade-btn{background:#00e676;color:#000000;font-weight:700;border-radius:8px}')

# badge-run → green
css = css.replace(
    'background:#767676;color:#ffffff;border:1px solid #767676;animation:badge-pulse',
    'background:#00e676;color:#000000;border:1px solid #00e676;animation:badge-pulse')
css = css.replace(
    'rgba(118,118,118,.5)}70%{box-shadow:0 0 0 6px rgba(118,118,118,0)}}',
    'rgba(0,230,118,.5)}70%{box-shadow:0 0 0 6px rgba(0,230,118,0)}}')

# badge-idle: bulk made color #ffffff, should be #aaaaaa
css = css.replace('.badge-idle{background:transparent;color:#ffffff;border:1px solid #2e2e2e}',
                  '.badge-idle{background:transparent;color:#aaaaaa;border:1px solid #2e2e2e}')

# Online / running dots → green (bulk changed #000000 → #141414)
css = css.replace(
    '.sb-online-dot{width:7px;height:7px;border-radius:50%;background:#141414;flex-shrink:0;animation:blink 2s infinite}',
    '.sb-online-dot{width:7px;height:7px;border-radius:50%;background:#00e676;flex-shrink:0;animation:blink 2s infinite}')
css = css.replace(
    '.dot-green{width:6px;height:6px;border-radius:50%;background:#141414;animation:blink 2s infinite;flex-shrink:0}',
    '.dot-green{width:6px;height:6px;border-radius:50%;background:#00e676;animation:blink 2s infinite;flex-shrink:0}')
css = css.replace(
    '.sb-bot-dot.running{background:#141414;animation:blink 2s infinite}',
    '.sb-bot-dot.running{background:#00e676;animation:blink 2s infinite}')
css = css.replace('background:#141414;animation:pulse-dot', 'background:#00e676;animation:pulse-dot')
css = css.replace(
    'rgba(0,0,0,.55)}60%{opacity:.55;box-shadow:0 0 0 6px rgba(0,0,0,0)}}',
    'rgba(0,230,118,.55)}60%{opacity:.55;box-shadow:0 0 0 6px rgba(0,230,118,0)}}')

# panel-hdr accent bar: was background:#000000 → #141414, should be #ffffff
css = css.replace(
    ".panel-hdr::before{content:'';width:2px;height:11px;background:#141414;border-radius:2px}",
    ".panel-hdr::before{content:'';width:2px;height:11px;background:#ffffff;border-radius:2px}")

# Hover backgrounds that became same shade as base (needs to be slightly lighter)
css = css.replace('#dash-profile-bar:hover{background:#1c1c1c}',
                  '#dash-profile-bar:hover{background:#242424}')
css = css.replace('.hdr-avatar-menu-item:hover{background:rgba(0,0,0,.03);color:#ffffff}',
                  '.hdr-avatar-menu-item:hover{background:rgba(255,255,255,.06);color:#ffffff}')
css = css.replace('.nav-menu-item:hover{background:rgba(0,0,0,.03);color:var(--text)}',
                  '.nav-menu-item:hover{background:rgba(255,255,255,.06);color:var(--text)}')

# dpb-view-btn hover: rgba(0,0,0,.08) → rgba(255,255,255,.06)
css = css.replace('.dpb-view-btn:hover{background:rgba(0,0,0,.08)}',
                  '.dpb-view-btn:hover{background:rgba(255,255,255,.06)}')
css = css.replace('.tv-me-profile-btn:hover{background:rgba(0,0,0,.08)}',
                  '.tv-me-profile-btn:hover{background:rgba(255,255,255,.06)}')

# ── 6. HTML/JS section replacements
html_js = after_style

# BUY / SELL inline buttons in JS template literals
html_js = html_js.replace(
    'background:#000000;color:#ffffff;font-weight:700;border:none;border-radius:6px;cursor:pointer;font-size:12px;letter-spacing:.03em" onclick="event.stopPropagation();manualBuy',
    'background:#00e676;color:#000000;font-weight:700;border:none;border-radius:6px;cursor:pointer;font-size:12px;letter-spacing:.03em" onclick="event.stopPropagation();manualBuy')
html_js = html_js.replace('background:#ef4444;color:#fff', 'background:#ff1744;color:#fff')

# General inline style color fixes
html_js = html_js.replace('color:#000000', 'color:#ffffff')
html_js = re.sub(r'(?<=color:)#000(?=[;"\s])', '#ffffff', html_js)
html_js = html_js.replace('background:#ffffff', 'background:#1c1c1c')
html_js = html_js.replace('background:#f8f8f8', 'background:#1c1c1c')
html_js = html_js.replace('background:#000000', 'background:#141414')
html_js = html_js.replace('#e5e5e5', '#2e2e2e')
html_js = html_js.replace('#ff0000', '#ff1744')

# ── 7. Write output
content_final = before_css + css + html_js

with open('dashboard.html', 'w', encoding='utf-8') as f:
    f.write(content_final)

print('Done — dark theme color reset complete.')
