import sqlite3, os

DB_FILE = os.getenv('DB_FILE', '/data/orcagent.db' if os.path.exists('/data') else 'orcagent.db')
conn = sqlite3.connect(DB_FILE)
c = conn.cursor()

trade_ids = [f"t{row[0]}" for row in c.execute("SELECT id FROM trades").fetchall()]
print(f"Found {len(trade_ids)} trades to delete.")

if trade_ids:
    ph = ','.join('?' * len(trade_ids))
    c.execute(f"DELETE FROM post_likes WHERE post_id IN ({ph})", trade_ids)
    c.execute(f"DELETE FROM post_reactions WHERE post_id IN ({ph})", trade_ids)

c.execute("DELETE FROM trades")
c.execute("UPDATE users SET badges = ''")
c.execute("DELETE FROM notifications")
c.execute("DELETE FROM copy_relationships")
conn.commit()
conn.close()
print("Done. Trades, badges, notifications, and copy-relationships reset.")
