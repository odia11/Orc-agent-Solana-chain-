"""
OrcAgent uptime monitor — runs as a sidecar process alongside gunicorn.

Reads /data/heartbeat.txt every 30 seconds.
- If the heartbeat is older than 3 minutes, sends a Telegram DOWN alert.
- When the heartbeat recovers, sends an UP alert.

Required environment variables:
  TELEGRAM_BOT_TOKEN  — bot token from @BotFather
  TELEGRAM_CHAT_ID    — chat / channel ID to send alerts to

Optional:
  HEARTBEAT_FILE      — override path (default: /data/heartbeat.txt)
  HEARTBEAT_TIMEOUT   — seconds before declaring down (default: 180)
  MONITOR_INTERVAL    — check frequency in seconds (default: 30)
"""

import os
import sys
import time
import datetime

import requests

# ── Configuration ──────────────────────────────────────────────────────────
TELEGRAM_TOKEN   = os.environ.get('TELEGRAM_BOT_TOKEN', '').strip()
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '').strip()
HEARTBEAT_FILE   = os.environ.get('HEARTBEAT_FILE', '/data/heartbeat.txt')
HEARTBEAT_TIMEOUT = int(os.environ.get('HEARTBEAT_TIMEOUT', '180'))   # 3 minutes
MONITOR_INTERVAL  = int(os.environ.get('MONITOR_INTERVAL', '30'))

TELEGRAM_API = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'

# ── Telegram helper ────────────────────────────────────────────────────────
def _send(text: str) -> bool:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print(f'[monitor] Telegram not configured — skipping alert: {text}', flush=True)
        return False
    try:
        resp = requests.post(
            TELEGRAM_API,
            json={'chat_id': TELEGRAM_CHAT_ID, 'text': text, 'parse_mode': 'HTML'},
            timeout=10,
        )
        ok = resp.status_code == 200
        if not ok:
            print(f'[monitor] Telegram error {resp.status_code}: {resp.text[:200]}', flush=True)
        return ok
    except Exception as e:
        print(f'[monitor] Telegram request failed: {e}', flush=True)
        return False

# ── Heartbeat reader ───────────────────────────────────────────────────────
def _read_heartbeat() -> datetime.datetime | None:
    """Return the timestamp from the heartbeat file, or None if unreadable."""
    try:
        with open(HEARTBEAT_FILE) as f:
            raw = f.read().strip()
        return datetime.datetime.strptime(raw, '%Y-%m-%dT%H:%M:%SZ').replace(
            tzinfo=datetime.timezone.utc
        )
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f'[monitor] heartbeat read error: {e}', flush=True)
        return None

# ── Main loop ──────────────────────────────────────────────────────────────
def main():
    print(
        f'[monitor] started — checking {HEARTBEAT_FILE} every {MONITOR_INTERVAL}s '
        f'(timeout={HEARTBEAT_TIMEOUT}s)',
        flush=True,
    )
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print(
            '[monitor] WARNING: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set — '
            'alerts will be logged but not sent',
            flush=True,
        )

    is_down     = False   # True while we believe the app is down
    alert_sent  = False   # True after we sent the DOWN alert (prevents spam)

    while True:
        now = datetime.datetime.now(datetime.timezone.utc)
        hb  = _read_heartbeat()

        if hb is None:
            age_seconds = HEARTBEAT_TIMEOUT + 1   # treat missing file as stale
            hb_display  = 'unknown (file missing)'
        else:
            age_seconds = (now - hb).total_seconds()
            hb_display  = hb.strftime('%Y-%m-%d %H:%M:%S UTC')

        if age_seconds > HEARTBEAT_TIMEOUT:
            if not is_down:
                is_down    = True
                alert_sent = False
                print(f'[monitor] ⚠ heartbeat stale ({age_seconds:.0f}s) — app may be down', flush=True)

            if not alert_sent:
                msg = (
                    f'🔴 <b>OrcAgent is DOWN</b>\n'
                    f'Last heartbeat: {hb_display}\n'
                    f'Stale for: {int(age_seconds)}s'
                )
                if _send(msg):
                    alert_sent = True
                    print(f'[monitor] DOWN alert sent', flush=True)
        else:
            if is_down:
                # Recovery
                is_down    = False
                alert_sent = False
                msg = (
                    f'🟢 <b>OrcAgent is back UP</b>\n'
                    f'Heartbeat recovered: {hb_display}'
                )
                _send(msg)
                print(f'[monitor] UP alert sent — heartbeat recovered', flush=True)

        time.sleep(MONITOR_INTERVAL)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('[monitor] stopped', flush=True)
        sys.exit(0)
