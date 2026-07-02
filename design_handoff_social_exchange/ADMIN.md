# Admin Console (separate app — `OrcAgent Admin.dc.html`)

A distinct **admin** persona, kept as its own file/app (not part of the user-facing shell). Same OrcAgent
design tokens (near-black ground, `#101216` surfaces, `#16191f`/`#21252c` hairlines, JetBrains Mono for
numbers, Solana-green accent). Left sidebar labeled "ADMIN CONSOLE" + a single `view` state; a sticky
header with search + 24H/7D/30D range toggle. Restrict this whole app behind an admin role in production.

## Views
- **Overview** — 4 KPI cards (total users, active bots now, trades 24h, fees 24h, each with an icon tile
  and colored delta); a **Platform revenue** bar chart (14-day fees, last bar accent) beside a
  **Fee breakdown** (auto/copy/swaps/withdrawals with progress bars); a **Live bot activity** table
  (user wallet, BUY/SELL action pill, token, size, PnL — streaming) beside an **Alerts** feed (typed,
  tinted icons: latency spikes, flagged wallets, fee milestones, signups).
- **Users** — 4 stat tiles (registered / active 24h / running bots / banned); filter chips
  (All/Active/Idle/Flagged) + Export CSV; a **users table** (avatar+name+wallet, status pill
  RUNNING/IDLE/FLAGGED, balance, trades, all-time PnL, joined, View/Ban actions). Table has a min-width
  with horizontal scroll; the user cell truncates.
- **Trades** — 4 stat tiles (trades 24h / open now / win rate / volume); a LIVE indicator + filter chips
  (All/Open/Closed/Stop-loss/Flagged) + Export; a full **trades table** (time, user wallet, token,
  BUY/SELL side pill, entry, exit, size, PnL colored by result; open trades show muted "open"). Min-width
  + horizontal scroll.
- **Revenue** — 4 KPI cards (fees 30d, treasury balance, avg fee/day, pending payouts); a **14-day fee
  bar chart** beside **Revenue by source** (progress bars); a **Treasury flow** table (time, description,
  wallet, signed amount, SETTLED/PENDING status pill).
- **System** — 6 **service cards** (Scanner, RPC nodes, Trade engine, Fee collector, a DEGRADED region,
  Notification queue) each with a HEALTHY/DEGRADED status pill, a big metric, and a sparkline; plus an
  **event log** (mono rows: time, colored level INFO/TRADE/WARN/FLAG, message).
- **Moderation** — 4 stat tiles (open cases / flagged wallets / banned 30d / auto-flags 24h); an **Open
  cases** list (avatar, wallet, HIGH/MEDIUM severity pill, reason, Review + Ban actions) beside a
  **Review queue** (auto-flags & reports with typed icons). Sidebar item carries a red count badge.
- **Settings** — **Platform limits** (max positions, platform fee, min deposit, rate limit — value
  fields), **Feature flags** (working toggle switches; Maintenance mode toggles red), and **Admin
  access** (role list + Invite). Toggles are state-backed.

The sidebar count badges (System `2`, Moderation `3`) reflect items needing attention.

## Data shapes (illustrative)
- KPI `{ icon, value, label, delta }`
- live trade `{ user, action:'BUY'|'SELL', token, size, pnl, open:boolean }`
- user `{ initials, color, name, wallet, status:'RUNNING'|'IDLE'|'FLAGGED', balance, trades, pnl, joined }`
- service `{ name, status:'HEALTHY'|'DEGRADED', metric, metricLabel, series:number[] }`
- log `{ time, level:'INFO'|'TRADE'|'WARN'|'FLAG', msg }`

Wire everything to real admin/analytics endpoints; the live activity table and event log should stream.
Bans, CSV export, and range toggles call real actions.
