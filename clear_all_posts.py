import sqlite3, os
DB_FILE = os.getenv('DB_FILE', '/data/orcagent.db' if os.path.exists('/data') else 'orcagent.db')
conn = sqlite3.connect(DB_FILE)
c = conn.cursor()
post_ids = [f"p{row[0]}" for row in c.execute("SELECT id FROM feed_posts").fetchall()]
print(f"Found {len(post_ids)} posts to delete.")
if post_ids:
    ph = ','.join('?' * len(post_ids))
    reply_ids = [row[0] for row in c.execute(f"SELECT id FROM feed_replies WHERE post_id IN ({ph})", post_ids).fetchall()]
    if reply_ids:
        rph = ','.join('?' * len(reply_ids))
        c.execute(f"DELETE FROM feed_reply_likes WHERE reply_id IN ({rph})", reply_ids)
    c.execute(f"DELETE FROM feed_replies WHERE post_id IN ({ph})", post_ids)
    c.execute(f"DELETE FROM post_likes WHERE post_id IN ({ph})", post_ids)
    c.execute(f"DELETE FROM post_reactions WHERE post_id IN ({ph})", post_ids)
c.execute("DELETE FROM feed_posts")
conn.commit()
conn.close()
print("Done. All posts and related replies/likes/reactions removed.")
