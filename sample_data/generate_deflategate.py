import sqlite3
import time
import os

DB_NAME = "sms.db"

def create_synthetic_database():
    for f in [DB_NAME, f"{DB_NAME}-wal", f"{DB_NAME}-shm"]:
        if os.path.exists(f):
            os.remove(f)

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('PRAGMA journal_mode=WAL;')
    
    cursor.execute('''
        CREATE TABLE handle (
            ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT,
            service TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE message (
            ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT,
            handle_id INTEGER,
            date INTEGER,
            is_from_me INTEGER
        )
    ''')

    cursor.execute("INSERT INTO handle (id, service) VALUES ('Jim McNally', 'iMessage')")
    mcnally_id = cursor.lastrowid
    cursor.execute("INSERT INTO handle (id, service) VALUES ('Tom Brady', 'iMessage')")
    brady_id = cursor.lastrowid

    messages = [
        ("Tom sucks... im going make that next ball a f***ing balloon", mcnally_id, 1400000000, 1),
        ("Talked to him last night. He actually brought you up and said you must have a lot of stress trying to get them done...", brady_id, 1400000500, 0),
        ("You working?", mcnally_id, 1400001000, 1),
        ("Yup", brady_id, 1400001500, 0),
        ("I have a few items for you. Autographed shoes.", brady_id, 1400002000, 0),
        ("Nice. You are the best. I am not going to espn........yet.", mcnally_id, 1400002500, 1)
    ]
    
    for msg in messages:
        cursor.execute("INSERT INTO message (text, handle_id, date, is_from_me) VALUES (?, ?, ?, ?)", msg)
    conn.commit()
    print("[+] Database created and populated with Deflategate timeline.")

    print("[!] Suspect is attempting to delete evidence...")
    time.sleep(1)
    
    cursor.execute("DELETE FROM message WHERE ROWID = 1")
    cursor.execute("DELETE FROM message WHERE ROWID = 6")
    conn.commit()
    
    print("[+] Evidence deleted.")
    print("[+] Synthetic sms.db and sms.db-wal successfully generated for SQLite-Ghost testing.")
    conn.close()

if __name__ == "__main__":
    create_synthetic_database()
