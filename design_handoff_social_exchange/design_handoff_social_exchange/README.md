# Handoff: OrcAgent — Social Exchange Redesign

## Overview
A complete redesign of the OrcAgent home screen, reframing the Solana meme-coin auto-trading
terminal as an **exclusive, invite-only crypto-social platform**. Instead of a static dashboard,
the home view is a three-column social feed: people-style activity (traders posting their bot's
executed trades + commentary), with persistent navigation on the left and live-market / top-trader
discovery rails on the right.

The goal: make trading activity feel social and community-driven — every trade the bot executes is a
shareable, copy-tradeable post — while keeping the dark "trading terminal" credibility of the original.

## About the Design Files
The files in this bundle are **design references created in HTML** — a prototype that demonstrates the
intended look, layout, and behavior. They are **not** production code to copy verbatim. The HTML uses a
lightweight in-house templating runtime (the `<x-dc>` / `<sc-for>` / `{{ }}` syntax) purely so the
mockup could be authored quickly; **ignore that runtime entirely** when implementing.

Your task is to **recreate this design in OrcAgent's real codebase**, using its existing framework,
component library, state layer, and data sources. If the app is React, build it as React components;
if no front-end environment exists yet, choose the most appropriate modern framework (React + Tailwind
or CSS Modules is a fine default) and implement the design there. Wire the placeholder data shown here
to the real wallet / bot / market APIs the live app already uses.

`current-app-reference.png` is a screenshot of the **current** production dashboard, included so you can
see the existing data model, terminology (SOL balance, open positions, win rate, all-time PnL, TP +12% /
SL -3%, achievement badges), and the real Solana-green brand accent.

## Fidelity
**High-fidelity (hifi).** Final colors, typography, spacing, and interaction states are all specified
below and should be matched closely. Recreate the UI pixel-accurately using the codebase's existing
primitives. The placeholder feed/market/trader *content* is illustrative — replace with live data — but
the visual treatment is intentional and final.

> Note on accent color: the prototype ships with a teal accent (`#35d4c4`) as the default and exposes it
> as a tweakable token. The **real OrcAgent brand accent is Solana green (`#16c784` / `#3ad29b`)** as seen
> in `current-app-reference.png`. Use the green as the production accent unless the team decides otherwise —
> the design is accent-agnostic and every accent usage is listed under Design Tokens.

---

## Layout (Home screen)

A centered, fixed-max-width app shell: `max-width: 1320px`, three columns, full viewport height.

```
┌────────────┬───────────────────────────┬──────────────────┐
│ LEFT RAIL  │       CENTER FEED          │   RIGHT RAIL     │
│  260px     │   flex:1, max 640px        │   340px          │
│  sticky    │   (the scrolling column)   │   sticky         │
└────────────┴───────────────────────────┴──────────────────┘
```

- Root: `display:flex; justify-content:center; background:#0a0b0e; color:#eef1f5; min-height:100vh`.
- Inner container: `display:flex; width:100%; max-width:1320px`.
- Left and right rails are `position:sticky; top:0; height:100vh`. The center column is the natural
  page scroller; its header is itself `sticky top:0` with a blurred translucent background.
- Column dividers are `1px solid #16191f` (left rail `border-right`, center `border-right`).

### Column 1 — Left navigation rail (`width:260px`, flex column)
- Padding `18px 14px 16px`.
- **Logo lockup** (top): a `36×36`, `border-radius:11px` accent-filled square containing a small dark
  upward CSS triangle (the "orca dorsal fin": `border-left/right:7px solid transparent;
  border-bottom:13px solid #0a0b0e`), followed by wordmark **"OrcAgent"** at `18px / 700 / -0.02em`.
- **Invite badge**: pill, `font-size:10px; weight:600; letter-spacing:0.14em`, accent text on
  `accentSoft` background with `accentBorder`, `border-radius:7px; padding:5px 9px`, leading 5px accent
  dot. Text: `INVITE-ONLY · BETA`.
- **Nav list** (`display:flex; flex-direction:column; gap:2px`). Each item: `padding:11px 12px;
  border-radius:11px; font-size:15px`.
  - Active item ("Home"): `font-weight:600; color:#eef1f5; background:accentSoft`, with a trailing 6px
    accent dot.
  - Inactive items: `font-weight:500; color:#8a919c`; hover → `background:#14171c; color:#eef1f5`.
  - Items in order: **Home** (active by default), **Live Market**, **Leaderboard**, **Traders**,
    **Messages** (trailing count pill "3"), **Notifications** (count pill "5"), **Wallet**, **Profile**,
    **Settings**.
  - **Home** and **Wallet** are the two implemented views and switch the center column in place (see
    "View switching" below). The active one gets the `accentSoft` background + a trailing 6px accent dot;
    clicking the bottom profile chip also opens Wallet.
  - Count pill: mono `11px / 700`, dark text on accent fill, `border-radius:999px; padding:1px 7px`.
- **Primary CTA** ("▶  Start Trading"): full width, accent fill, dark text (`#08120f`),
  `border-radius:13px; padding:13px; font-size:15px; weight:700`; hover `filter:brightness(1.08)`.
- **Bot PnL panel** (below the CTA): a compact card (`#101216; border:1px solid #16191f;
  border-radius:14px`) showing **only the trading bot's active positions** and their PnL — distinct from
  the full Wallet holdings. Header row: "BOT PNL" caption with a status dot (green when in profit) +
  a mono **total PnL** ("+0.32 SOL", green/red). Then one row per open bot position: [24px token chip]
  [mono $TICKER + tiny status line e.g. "TP +12% · open" / "SL -3% · open"] [right: mono % PnL + mono
  SOL delta, colored green/red]. Footer link "View all positions →" in accent. Wire to the bot's live
  open-position list; rows appear/update as the scanner opens and closes trades.
- The left rail is `overflow-y:auto` so the Bot PnL panel + profile chip stay reachable on short
  viewports.
- **Profile chip** (pinned to bottom via `margin-top:auto`): bordered (`1px solid #16191f`)
  `border-radius:14px; padding:10px`, row of [avatar 40px circle] [name "You" + "@you" muted]
  [right-aligned mono SOL balance "2.41" + "SOL" label]. Hover → `background:#101216`.

### Column 2 — Center feed (`flex:1; min-width:0; max-width:640px`)
Top-to-bottom:
1. **Sticky header** (`sticky top:0; z-index:20; background:rgba(10,11,14,0.82);
   backdrop-filter:blur(14px); border-bottom:1px solid #16191f; padding:15px 22px 0`):
   - Left: title **"Home"** (`20px / 600`) + subtitle `347 traders online · scanner running`
     (`12px; color:#565d68`).
   - Right: **LIVE** indicator — `11px / 600; letter-spacing:0.1em; color:#3ad29b` with a 7px green dot
     that blinks (`orcaBlink` keyframe, opacity 1→.35, 1.6s infinite).
   - **Tab row** (`display:flex; gap:30px; margin-top:16px`): **For You** (default active), **Following**,
     **Live Trades**. Each tab is a button `font-size:14px; padding-bottom:13px`. Active: `color:#eef1f5;
     weight:600; border-bottom:2px solid <accent>`. Inactive: `color:#565d68; weight:500; transparent
     border`.
2. **"Your bot" status card** (`margin:16px 22px; border:1px solid #21252c; border-radius:16px;
   padding:15px 17px; background:#101216`): left = 9px amber dot (`#f7b955` with
   `box-shadow:0 0 0 4px rgba(247,185,85,0.14)`) + "Your bot is idle" (`14px/600`) + mono sub
   `2.41 SOL ready · 0/5 open · 68% win rate` (`12px; #565d68`). Right = small accent "▶ Start Trading"
   button (`border-radius:11px; padding:10px 16px; 13px/700`).
3. **Composer** (`padding:15px 22px; border-bottom:1px solid #16191f; display:flex; gap:14px`):
   44px avatar + faux input "Share your last trade, @you…" (`17px; #565d68`) + action row:
   two outlined chips ("＋ Chart", "＄ Tag token" — `12px; #8a919c; border:1px solid #21252c;
   border-radius:9px; padding:6px 11px`), spacer, accent **Post** button.
4. **Feed** — list of post `<article>`s, each `padding:18px 22px; border-bottom:1px solid #16191f;
   display:flex; gap:14px`, hover `background:#0d0f12`. See "Post component" below.
5. **Footer**: centered muted line "You've reached the top of the feed · scanner refreshes every 30s".

### Column 3 — Right discovery rail (`width:340px; sticky; overflow-y:auto; padding:16px 18px 40px`)
1. **Search input**: full width, `background:#101216; border:1px solid #21252c; border-radius:13px;
   padding:11px 15px`, placeholder "Search traders, tokens…" (`#565d68`).
2. **Live Market card** (`background:#101216; border:1px solid #16191f; border-radius:18px`):
   header "Live Market" (`16px/600`) + green **PUMPING** indicator (blinking dot). Then rows: each row
   = [36px `border-radius:10px` token chip with mono ticker initials on token color] [name + mono
   "TICK / SOL" pair] [right: mono price + mono % change colored green/red]. Footer link
   "Show all markets →" in accent.
3. **Top Traders · Today card**: header (`16px/600`). Rows: [mono rank] [34px avatar circle]
   [name + optional verified check + "@handle"] [right mono green PnL "+NN.N SOL"]. Footer
   "View leaderboard →" in accent.
4. **Platform · 24h card**: three inline stat blocks — `1,284 Trades`, `+612 Net SOL` (green),
   `347 Online`. Numbers mono `19px/700`, labels `11px; #565d68`.
5. **Footer**: wrapped muted links (About · Docs · Fees · Security · Terms) + fine print
   "OrcAgent is invite-only. Trade with a dedicated wallet. Crypto trading carries risk."

---

## Post component (the core repeating unit)
Two variants share the same header + text + action row; the trade variant adds a trade card.

- **Header row** (`14px`): bold name `#eef1f5`, optional **verified badge** (15px accent circle, dark
  "✓", `9px/700`), then muted `@handle`, a `·` separator (`#3a4049`), and relative time (`#565d68`).
- **Trade card** (only when the post is a trade) — `margin-top:12px; border:1px solid #21252c;
  border-radius:15px; padding:14px 15px; background:#101216; display:flex; justify-content:space-between;
  align-items:center; gap:16px`:
  - Left block: action label (e.g. "Closed" / "Opened", `13px; #565d68`) + mono **$TOKEN** ticker
    (`15px/700`, colored per token) + a small outlined **side** chip (e.g. "LONG", "LONG · OPEN",
    "STOP-LOSS" — `10px/600; border:1px solid #21252c; border-radius:5px; padding:2px 6px`).
    Below: mono entry/exit line ("Entry $1.62  →  Exit $1.92", `12px; #565d68`).
    Below that: a **bar sparkline** — `display:flex; align-items:flex-end; gap:2px; height:34px;
    width:160px`, ~22 thin bars (`flex:1; height:<n>%; background:currentColor; border-radius:1px;
    opacity:0.82`), the container `color` set to green (`#3ad29b`) for wins / red (`#f76b62`) for losses.
  - Right block (right-aligned): big mono **PnL %** (`23px/700`, green or red) + mono sub line
    ("+0.42 SOL", "unrealized", "-0.08 SOL") in the same color.
- **Body text**: `margin-top:12px; font-size:14.5px; line-height:1.55; color:#c7ccd4`.
- **Action row** (`display:flex; gap:24px; margin-top:14px; font-size:13px; color:#565d68`):
  `↩ <replies>` (hover `#8a919c`), `⧉ Copy · <copies>` (always accent-colored — the headline social
  action), `♡ <likes>` (hover red `#f76b62`), `↗` share (hover `#8a919c`).

Text-only posts skip the trade card and just show header → text → actions.

---

## Messages / Direct Messages (sidebar → "Messages")
A two-pane DM experience, opened from the left-rail **Messages** item (which carries an unread count
badge and is present on every sidebar view, so DMs are reachable everywhere). It replaces the
feed+right-rail area while keeping the sidebar.

- **Conversation list** (`width:330px; border-right:1px solid #16191f; full height`):
  - Header: "Messages" title + an accent **✎ compose** button (new message), then a search field
    ("Search messages", `#101216; border:1px solid #21252c; border-radius:11px`).
  - Conversation rows (hover `#101216`; the active row has an accent left-border + `#101216` bg):
    [46px avatar with a green online dot when online] [name + verified ✓ + right-aligned time] over
    [last-message preview + optional unread count pill]. Preview is `#c7ccd4` when unread, else `#565d68`.
    "you: …" prefixes outgoing previews. Clicking a row sets the active conversation.
- **Chat thread** (`flex:1; full height; column`):
  - **Header**: avatar (+online dot), name + verified ✓, "Online · @handle" in green, and on the right an
    accent **⧉ Copy trades** button (mirror this trader's positions) + a `⋯` overflow button.
  - **Message area** (scrolls): a centered "Today" divider, then bubbles. Incoming bubbles are `#16191f`
    left-aligned (`radius 15px 15px 15px 4px`); outgoing are accent-filled with dark text, right-aligned
    (`radius 15px 15px 4px 15px`). A **shared-trade card** can appear inline (bordered `#101216` panel:
    action + $TOKEN, entry sub, and big colored PnL) — trades are shareable into a DM. Each bubble has a
    small muted timestamp beneath.
  - **Composer**: rounded bar (`#101216; border:1px solid #21252c; border-radius:14px`) with a ＋
    attach, the text input ("Message <name>…"), an emoji ☺, and an accent circular **➤ send** button.
- Data shapes: conversation `{ handle, name, initials, color, verified, online, time, preview, unread }`;
  message `{ kind:'text'|'trade', from:'me'|'them', text|trade fields, time }`. Active conversation is
  selected state (`convo`). Wire to the real DM/inbox service; unread badge sums across conversations.

---

## Center column — Wallet view
The center column renders **one of two views** depending on the active left-nav item: the **feed**
(Home, described above) or the **Wallet**. Same column shell, max-width 640px, sticky blurred header.
The right rail is unchanged across both.

Wallet view, top to bottom:
1. **Sticky header**: title **"Wallet"** (`20px/600`) + subtitle "Your dedicated trading wallet". Right:
   a network pill **"SOLANA · MAINNET"** — accent text on `accentSoft` with `accentBorder`, leading
   accent dot (`11px/600; letter-spacing:0.08em; border-radius:8px; padding:6px 10px`).
2. **Balance hero** (`margin:18px 22px 0; border:1px solid #21252c; border-radius:18px; padding:20px;
   background:linear-gradient(160deg,#11151a,#0e1013)`):
   - Label "TOTAL BALANCE" (`11px; letter-spacing:0.12em; #565d68`).
   - Big mono balance `4.87` + small `SOL` suffix (`40px/700`, suffix `18px; #565d68`), with inline
     green `+5.2% today` (`13px` mono).
   - Mono USD sub `≈ $834.70 USD` (`14px; #8a919c`).
   - **Action row** (4 equal-width buttons, `gap:9px`): **↓ Deposit** (accent fill, dark text) +
     **↑ Withdraw**, **↗ Send**, **⇄ Swap** (outlined: `background:#0a0b0e; border:1px solid #2c313a`,
     hover `#14171c`). All `border-radius:12px; padding:12px; 13px`.
   - **Available / In-positions split**: two cells joined by a 1px seam (`#21252c`), each `#0d0f12`,
     `border-radius:12px`: "Available" `2.41 SOL` and "In open positions" `2.46 SOL` (the second value
     in accent). Numbers mono `16px/700`.
3. **Deposit address card** (`#101216; border:1px solid #16191f; border-radius:18px; padding:17px`):
   label "DEPOSIT ADDRESS", then a row of [**QR placeholder** — 74px, `border-radius:12px`, light
   `#eef1f5` tile with a 6px grid pattern; replace with a real generated QR] + [mono wrapped address
   (`13px; #c7ccd4; word-break:break-all`) with two buttons: **⧉ Copy address** (accent-soft) and
   **View on Solscan ↗** (outlined)]. A hairline-topped fine-print note: "Send only SOL and SPL tokens…".
4. **Holdings**: section header "Holdings" + accent "Hide small balances" link, then a card listing each
   asset — [38px circular token chip, mono ticker on token color] [name + mono "<amount> <TICK>"]
   [right: mono USD value + mono % change colored green / muted / red]. Rows divided by `#16191f`.
5. **Recent activity**: section header + accent "View all →", then a card of transaction rows — each
   [38px `border-radius:11px` icon tile (arrow glyph) tinted green / neutral / red] [type + sub
   (e.g. "Sold $WIF" / "Auto · take-profit +18.4%")] [right: mono signed amount colored + relative time].
   Types shown: Deposit, auto Sell (TP), auto Buy, Withdraw, auto Sell (SL). Last row has no divider.
6. **Footer**: centered muted "Balances update every block · OrcAgent never holds custody of your keys".

### Swap modal + token picker (opened from the Wallet "⇄ Swap" button)
A centered overlay (`rgba(6,7,9,0.72)` + `blur(6px)` scrim; card `width:420px; background:#0e1116;
border:1px solid #21252c; border-radius:22px; shadow:0 24px 70px rgba(0,0,0,.6)`). Header "Swap" + gear
+ close ✕. Two states inside the same card:

- **Swap state** (default): a **You pay** panel and **You receive** panel (`#0a0b0e; border:1px solid
  #21252c; border-radius:16px`), each with a label row (caption + mono "Balance N"), a large mono amount
  (27px/700 — an editable input on the pay side), a USD sub, and a **token pill** on the right (rounded
  999px; the receive pill is accent-tinted). A circular **↓ switch** button straddles the seam between
  them (`34px; border-radius:11px; accent glyph`). Below: a mono rate line ("1 SOL ≈ 89.04 WIF") +
  "Slippage 0.5% · Fee 0.25%", then a full-width accent **Review swap** button.
- **Token-picker state** (the redesign of the ugly default dropdown — replaces a bare SOL / address /
  name list): tapping either token pill swaps the card body to the picker. It has a back ← arrow + a
  **search field** ("Search name or paste address", with ⌕ icon), a row of **quick-pick chips**
  (rounded token pills for SOL / USDC / WIF / POP), a "YOUR TOKENS" caption, and a scrollable
  (`max-height:280px`) list of token rows: [38px circular token chip] [ticker + verified ✓ + full
  name] [right: mono balance + mono USD value], each row `border-radius:13px`, hover `#14171c`.
  Selecting a token returns to the swap state. This is the intended production pattern for any
  token-selection dropdown in the app — never a raw unstyled `<select>`/list.

---

## Interactions & Behavior
- **Swap modal**: the Wallet "⇄ Swap" action opens the modal; clicking the scrim or ✕ closes it. Either
  token pill opens the **token picker**; ← or selecting a token returns to the swap form. Wire amounts,
  rate, balances, and the token universe to the real swap/route API; the "Review swap" CTA proceeds to
  confirm. Use the redesigned picker (search + quick chips + rich rows) wherever a token must be chosen.
- **View switching**: the **Home** and **Wallet** left-nav items (and the bottom profile chip → Wallet)
  swap the center column between the feed and the wallet. The active nav item shows the `accentSoft`
  highlight + accent dot. Map to real routes in production.
- **Wallet actions**: Deposit / Withdraw / Send / Swap and Copy-address are CTAs — wire to the existing
  deposit-address, transfer, and swap flows. The QR tile is a placeholder; generate a real QR for the
  deposit address.
- **Feed tabs** filter the visible feed:
  - **For You** → all posts.
  - **Following** → only posts from verified/followed traders.
  - **Live Trades** → only posts that are trades (open or closed).
  - Active tab updates the underline + text color. In production, these would map to real feed queries.
- **Hover states** (all specified inline above): nav items, profile chip, post rows, market/trader rows,
  action icons, and all buttons (`filter:brightness(1.08)` on accent buttons).
- **LIVE / PUMPING dots** pulse via a 1.6s `opacity` keyframe — purely decorative "is-live" affordance.
- **Copy Trade** (`⧉ Copy`) is the platform's signature action and is always rendered in the accent color
  to stand out; clicking it should initiate a copy-trade flow (mirror that trader's position with the
  user's bot). Wire to the real copy-trade endpoint.
- **Start Trading / Start Bot / Post** buttons are CTAs; hook to the existing bot-start and post-compose
  flows.
- Everything else (search, nav links, footer links) navigates to the corresponding existing routes.

## State Management
State needed in the real implementation:
- `activeView`: `'home' | 'wallet'` — which view the center column renders. The left-nav Home/Wallet
  items and the profile chip set it. In production this maps to routes (e.g. `/home`, `/wallet`).
- `activeFeedTab`: `'For You' | 'Following' | 'Live Trades'` — drives the feed query/filter.
- `feed`: list of post objects (see shape below), paginated/streamed from the activity API; new trades
  the bot executes should append/prepend in real time.
- `wallet` / `bot`: SOL balance, bot status (idle/running), open positions, win rate — for the status
  card and profile chip (already exist in the current app).
- `liveMarket`: top pumping tokens (ticker, name, price, % change) — already polled by the current
  "Live Market" page; reuse that source (scanner refreshes ~every 30s).
- `topTraders`: today's leaderboard slice.
- `platformStats`: 24h trades / net SOL / online count.
- `walletPortfolio`: total balance (SOL + USD), 24h change, available vs. in-positions split, deposit
  address, `holdings[]` (ticker, name, amount, USD value, % change), and `transactions[]` (type, sub,
  signed amount, direction → icon/color, time). For the Wallet view; wire to the real on-chain wallet
  balances and the bot's trade/transfer history.
- Tweakable presentation flags (optional, see Design Tokens): `accentColor`, `showSparklines`,
  `verifiedOnly`.

### Post object shape (illustrative)
```ts
type Post = {
  id: string;
  name: string; handle: string; initials: string; color: string; // avatar
  verified: boolean; time: string;          // relative ("2m")
  isTrade: boolean;
  text: string;
  // trade-only:
  action?: 'Closed' | 'Opened';
  token?: string; tokenColor?: string;
  side?: string;                            // "LONG" | "LONG · OPEN" | "STOP-LOSS"
  entryLine?: string;                       // "Entry $1.62  →  Exit $1.92"
  bars?: number[];                          // ~22 values 0–100 for the sparkline
  pnl?: string; sub?: string; pnlColor?: string; barColor?: string;
  // engagement:
  replies: number; copies: number; likes: number;
};
```

## Design Tokens

### Colors
| Role | Hex |
|---|---|
| App background | `#0a0b0e` |
| Surface / card | `#101216` |
| Surface (raised border on cards) | `#21252c` |
| Hairline divider | `#16191f` |
| Row hover | `#14171c` |
| Post hover | `#0d0f12` |
| Text primary | `#eef1f5` |
| Text body | `#c7ccd4` |
| Text secondary | `#8a919c` |
| Text muted | `#565d68` |
| Text faint | `#3a4049` |
| **Accent (prototype default)** | `#35d4c4` (teal) |
| **Accent (production / brand)** | `#16c784` ≈ `#3ad29b` (Solana green) |
| Accent soft (fill) | accent @ 10% alpha |
| Accent border | accent @ 30% alpha |
| Positive / up | `#3ad29b` |
| Negative / down | `#f76b62` |
| Warn / idle | `#f7b955` |
| Avatar palette | `#35d4c4`, `#7c8cff`, `#f7b955`, `#3ad29b`, `#f76b62`, `#2b6cff` |

Accent is a single token threaded through: logo square, invite badge, active nav highlight + dot,
nav count pills, all primary buttons, active feed-tab underline, the "Copy" action, verified badges,
PnL chart CTA, and the rail "Show all / View" links. Swapping it to brand green is a one-token change.

### Typography
- **UI / display**: `Geist` (weights 400/500/600/700). Substitute the codebase's grotesque/sans if Geist
  isn't available (Geist is on Google Fonts).
- **Numbers / tickers / addresses / code-ish data**: `JetBrains Mono` (400/500/700). All prices, %,
  balances, PnL, ranks, pairs, and the wallet handle use mono — this is a deliberate "terminal" cue.
- Scale used: hero/section titles 18–23px; nav/body 14–17px; meta/labels 10–13px; letter-spacing
  `-0.02em` on the wordmark, `0.06–0.14em` on uppercase labels/badges.

### Radius
Buttons/inputs `10–13px`; cards/rails `15–18px`; chips `5–9px`; avatars `50%`; logo/token chips `10–11px`;
count pills `999px`.

### Spacing
8px-ish rhythm. Rail padding `16–18px`; feed item padding `18px 22px`; card padding `14–17px`; nav item
`11px 12px`; gaps `2px` (nav), `9–14px` (rows/composer), `24–30px` (action row / tabs).

### Effects
- Sticky header blur: `backdrop-filter:blur(14px)` over `rgba(10,11,14,0.82)`.
- Idle dot glow: `box-shadow:0 0 0 4px rgba(247,185,85,0.14)`.
- Live dot: `@keyframes orcaBlink { 0%,100%{opacity:1} 50%{opacity:.35} }`, 1.6s infinite.
- No drop shadows on cards — depth comes from `#16191f`/`#21252c` hairlines on the near-black ground.

## Assets
- **No raster/vector image assets.** All avatars and token icons are CSS — colored circles/rounded
  squares with initials. Replace with real trader avatars / token logos in production where available,
  falling back to the initial-on-color treatment.
- The **orca logo mark** is pure CSS (accent rounded square + a dark CSS-border triangle). If the team
  has an official OrcAgent logo, drop it in here.
- Fonts loaded from Google Fonts (`Geist`, `JetBrains Mono`).
- `current-app-reference.png` — screenshot of the existing production dashboard for data/terminology
  reference and the real brand green.

## Trade History page (full-width, top-nav layout)
Unlike Home/Wallet (which use the left sidebar shell), **Trade History is a standalone full-width view**
that mirrors the real OrcAgent dashboard chrome: the left sidebar is hidden and replaced by a **top
navbar**. This is the layout to use for the dashboard-family pages (Dashboard, History, Leaderboard).

- **Top navbar** (`sticky top:0; blur; border-bottom:1px solid #16191f; padding:14px 30px`):
  - Left: a `38px` rounded accent-tinted logo tile (🐳) + **"ORCAGENT"** wordmark in accent
    (`18px/700; letter-spacing:0.04em`) over the muted tagline **"SOLANA SMART SCALPER V4"**
    (`10px; letter-spacing:0.14em`).
  - Right: a mono wallet pill ("● Cdn8…eAM9") then three nav buttons — **⊞ Dashboard**, **🕑 History**,
    **🏆 Leaderboard** (`13px/600; border-radius:10px; padding:8px 14px`). The active one (History) is an
    accent fill with dark text; the others are `#101216` with `#21252c` border.
- **Body** is centered at `max-width:1180px`. Title row: 📋 + "Trade History" (`26px/700`).
- **Filters bar** (`#101216; border:1px solid #16191f; border-radius:16px; padding:18px 20px; flex`):
  labeled fields TOKEN (text input), RESULT (select), FROM / TO (date inputs, mono placeholder
  "mm/dd/yyyy" with a calendar glyph), spacer, and a red outlined **✕ Clear** button. Each field label is
  `10px; letter-spacing:0.1em; #565d68; weight:600`; inputs are `#0a0b0e; border:1px solid #2c313a;
  border-radius:10px`.
- **Stat tiles** — a 5-up grid (`gap:14px`): TOTAL TRADES `23`, WIN RATE `43.5%` (red — it's <50%),
  TOTAL PNL `-0.1172 SOL` (red), BEST TRADE `+0.0600 SOL` (green), WORST TRADE `-0.1284 SOL` (red). Each
  tile (`#101216; border:1px solid #16191f; border-radius:16px; padding:16px 17px`): a 30px rounded
  tinted icon chip + caption on top, then the big mono value (`24px/700`) colored by sign.
- **Trades table** (`#101216; border:1px solid #16191f; border-radius:16px`): a "Showing N of N trades"
  line above it. Columns (CSS grid `130px 1fr 120px 120px 110px 100px 110px 90px`, `gap:12px`,
  `padding:15px 20px`, row divider `#16191f`, hover `#14171c`):
  **DATE / TIME** (mono, two lines) · **TOKEN** (bold, subtly underlined) · **BUY PRICE** · **SELL PRICE**
  (mono `#c7ccd4`) · **PNL (SOL)** · **PNL (%)** (mono bold, green/red by sign) · **DURATION** (mono
  muted) · **RESULT** — a **WIN**/**LOSS** pill (`10px/700; border-radius:7px`; green-tinted for WIN,
  red-tinted for LOSS). Header row is `10px; letter-spacing:0.08em; #565d68; weight:600`.
- Trade row shape: `{ date, time, token, buy, sell, pnlSol, pnlPct, duration, win:boolean }` →
  `result`/colors/badge styles derive from `win`.

---

## Files
- **Navigation & routing model**: the whole app is one shell driven by a single `view` state set by the
  left-sidebar nav (every nav item is clickable and highlights when active). All views are connected —
  cross-links work (profile chip → Wallet, "Edit profile" → Settings, History top-nav → Dashboard, etc.).
  In production map each `view` to a real route. The sidebar shows on every view **except** Trade History
  (which uses its own top-nav full-width chrome). The views:
  - **Home** — social feed (+ right rail) · **Wallet** — balances/holdings/activity (+ swap modal)
  - **Live Market** — scanner token table (rank, token, price, 24h %, volume, market cap, sparkline,
    Trade button) with Trending/Gainers/New/Volume filters + search.
  - **Leaderboard** — top-3 podium cards (gold/silver/bronze, lifted) + ranked table (rank, trader,
    win rate, trades, PnL, Copy button) with 24H/7D/30D range toggle.
  - **Traders** — 3-up directory of trader cards (avatar+online dot, verified, bio, 30D PnL / win /
    copiers split, Copy trades + Follow buttons) with search.
  - **Notifications** — All/Trades/Social tabs + activity rows (tinted icon by type, optional mono
    detail chip, time, unread dot; unread rows subtly tinted) + "Mark all read".
  - **Profile** — gradient cover, avatar + verified, bio, following/followers/copiers counts, 4 stat
    tiles, achievement badges, recent-trades list. "Edit profile" routes to Settings.
  - **Settings** — Trading Strategy (breakout/TP/SL/max positions value fields), Preferences (working
    **toggle switches** — animated, state-backed), Account & Wallet (manage/export key), and a red
    danger "Emergency stop" card.
  - **Messages** — two-pane DM (documented above) · **Trade History** — top-nav table (documented below)
- All views live in the single HTML file below and share the design tokens in this doc.

## Files (assets)
- The design covers a sidebar **app shell** (Home feed + Wallet) **and** a separate full-width
  **top-nav dashboard layout** (Trade History; the pattern for Dashboard/Leaderboard). All in one HTML
  file below.
- The design covers **two center-column views** behind one shell: the social **feed** (Home) and the
  **Wallet** (balance, deposit address, holdings, activity). Both are in the single HTML file below.
- `OrcAgent Social Exchange.dc.html` — the high-fidelity design prototype (open in a browser to view;
  the templating runtime is incidental — read it for structure, colors, and copy only).
- `current-app-reference.png` — current production dashboard screenshot.
- `README.md` — this document.
