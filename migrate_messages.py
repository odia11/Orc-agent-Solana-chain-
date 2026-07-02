"""
One-time migration: copy rows from legacy `messages` table
(sender_wallet / receiver_wallet / content) into `direct_messages`
(sender_id / receiver_id / message / created_at / is_read / message_type).

Run once via Railway Console:
    python migrate_messages.py
"""

import os
import sqlite3

BASE     = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = '/data' if os.path.exists('/data') else BASE
DB_FILE  = os.path.join(DATA_DIR, 'orcagent.db')


def _get_uid(conn, wallet: str):
    row = conn.execute(
        'SELECT id FROM users WHERE wallet_address=?', (wallet,)
    ).fetchone()
    return row[0] if row else None


def migrate():
    conn = sqlite3.connect(DB_FILE)
    try:
        rows = conn.execute(
            'SELECT sender_wallet, receiver_wallet, content, created_at, is_read FROM messages ORDER BY id'
        ).fetchall()
    except Exception as e:
        print(f'[migrate] Could not read messages table: {e}')
        conn.close()
        return

    total    = len(rows)
    migrated = 0
    skipped  = 0

    for sender_wallet, receiver_wallet, content, created_at, is_read in rows:
        sender_id   = _get_uid(conn, sender_wallet)
        receiver_id = _get_uid(conn, receiver_wallet)

        if sender_id is None:
            print(f'[skip] sender wallet not found: {sender_wallet!r}')
            skipped += 1
            continue

        if receiver_id is None:
            print(f'[skip] receiver wallet not found: {receiver_wallet!r}')
            skipped += 1
            continue

        try:
            conn.execute(
                '''INSERT INTO direct_messages
                   (sender_id, receiver_id, message, created_at, is_read, message_type)
                   VALUES (?, ?, ?, ?, ?, 'text')''',
                (sender_id, receiver_id, content, created_at, is_read or 0)
            )
            migrated += 1
        except Exception as e:
            print(f'[skip] insert error for {sender_wallet!r} → {receiver_wallet!r}: {e}')
            skipped += 1

    conn.commit()
    conn.close()
    print(f'\n[migrate] done — {migrated} of {total} migrated, {skipped} skipped')


if __name__ == '__main__':
    migrate()
