# Paste-into-Claude-Code prompt

Copy everything in the box below into Claude Code (run it from the root of your OrcAgent repo, with
this whole `design_handoff_social_exchange/` folder available so Claude can read the files).

---

You are implementing a redesign of the OrcAgent web app (a Solana meme-coin auto-trading terminal,
reframed as an invite-only crypto-social platform). I've given you a design handoff folder. Build it
into THIS codebase — match the existing framework, component library, state layer and data sources.

## Read first
- `design_handoff_social_exchange/README.md` — the full design spec: navigation/routing model, every
  screen described in detail, design tokens (colors, type, radius, spacing, effects), data shapes, and
  interaction/state notes. Treat this as the source of truth.
- `design_handoff_social_exchange/OrcAgent Social Exchange.dc.html` — the high-fidelity reference
  prototype. Open it in a browser to see the intended look and behavior. IGNORE its templating runtime
  (the `<x-dc>` / `<sc-for>` / `{{ }}` syntax) — that's just how the mockup was authored. Read it only
  for structure, exact styling, copy, and layout. Do NOT copy that runtime into the app.
- `design_handoff_social_exchange/current-app-reference.png` — the current production dashboard, for the
  real data model, terminology, and brand color.

## What to build
One app shell driven by a single active-view/route, with a left sidebar (clickable nav, active state).
Implement every view and wire them together so navigation and cross-links actually work:
- **Home** — social feed of traders' bot trades + posts, with composer, "your bot" status card, feed
  tabs (For You / Following / Live Trades), and a right rail (Live Market, Top Traders, Platform stats).
- **Live Market** — scanner token table (rank, token, price, 24h %, volume, market cap, sparkline, Trade
  button) with Trending/Gainers/New/Volume filters + search. (Table has a min-width with horizontal
  scroll on narrow screens — keep that.)
- **Leaderboard** — top-3 podium + ranked table with Copy buttons and a 24H/7D/30D range toggle.
- **Traders** — directory of trader cards (avatar+online dot, verified, bio, 30D PnL / win / copiers,
  Copy trades + Follow).
- **Messages** — two-pane DMs (conversation list + chat thread with text bubbles and shareable trade
  cards, composer). Reachable from the sidebar everywhere; unread badge sums across conversations.
- **Notifications** — All/Trades/Social tabs + activity rows (typed icons, optional detail chip, unread
  state) + Mark all read.
- **Wallet** — total balance, deposit address + QR, holdings, recent activity, and a Swap modal whose
  token picker uses search + quick-pick chips + rich rows (not a bare dropdown).
- **History** — full-width top-nav layout (sidebar hidden): filters, 5 stat tiles, trades table with
  WIN/LOSS badges.
- **Profile** — cover, avatar, bio, follower/copier counts, stat tiles, achievement badges, recent
  trades. "Edit profile" routes to Settings.
- **Settings** — Trading Strategy (breakout/TP/SL/max positions), Preferences (working toggle switches),
  Account & Wallet (manage/export key), and a red Emergency-stop danger card.

## How to build it
- Reproduce the visuals pixel-accurately using the design tokens in the README. Dark, near-black ground
  (`#0a0b0e`), `#101216` surfaces, `#16191f`/`#21252c` hairlines, mono (JetBrains Mono) for all numbers,
  Geist (or the repo's grotesque sans) for UI. **Production accent = Solana green** (`#16e08e` / `#16c784`).
- Everything must be functional and connected: clicking nav changes the route; the bot status, balances,
  market, leaderboard, traders, notifications, DMs, and trade history all bind to the app's real
  data/services (replace the prototype's placeholder content). Copy-trade, Start bot, Swap, and Settings
  toggles call the real endpoints.
- Use the codebase's existing components and patterns where they exist; only add new ones where needed.
- Keep accessibility sane (focus states, hit targets ≥44px, semantic markup).

Start by proposing a short implementation plan (file structure, routing, shared components, and how each
view maps to existing data) before writing code. Then implement view by view, verifying each renders and
links correctly.

---

After Claude proposes its plan, tell it which data sources/endpoints each view should use (it can't know
your backend), then let it implement.
