import sqlite3
import time
import os
import random
import struct

DB_NAME = "large_forensic_dataset.db"

def create_large_dataset():
    for f in [DB_NAME, f"{DB_NAME}-wal", f"{DB_NAME}-shm"]:
        if os.path.exists(f):
            os.remove(f)

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('PRAGMA journal_mode=WAL;')
    
    # 1. Complex Schema
    cursor.execute('CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT, phone TEXT)')
    cursor.execute('CREATE TABLE calls (id INTEGER PRIMARY KEY, contact_id INTEGER, duration INTEGER, timestamp INTEGER)')
    cursor.execute('CREATE TABLE messages (id INTEGER PRIMARY KEY, contact_id INTEGER, text TEXT, is_sent INTEGER, timestamp INTEGER)')
    
    current_time = int(time.time())
    
    # 2. Populate Contacts
    contacts = [("Alice", "555-0101"), ("Bob", "555-0102"), ("Charlie", "555-0103"), ("Diana", "555-0104")]
    for c in contacts:
        cursor.execute("INSERT INTO contacts (name, phone) VALUES (?, ?)", c)
    
    # 3. Populate Hundreds of Messages and Calls to fill multiple pages
    print("[+] Generating 500 records to force multi-page B-Tree structures...")
    for i in range(1, 501):
        c_id = random.randint(1, 4)
        is_sent = random.choice([0, 1])
        ts = current_time - random.randint(1000, 100000)
        
        # Insert varied messages
        msg_text = f"Routine conversation message #{i} with varied payload lengths padding out the cell size to test the parser..." * random.randint(1, 3)
        cursor.execute("INSERT INTO messages (contact_id, text, is_sent, timestamp) VALUES (?, ?, ?, ?)", (c_id, msg_text, is_sent, ts))
        
        if i % 5 == 0:
            cursor.execute("INSERT INTO calls (contact_id, duration, timestamp) VALUES (?, ?, ?)", (c_id, random.randint(10, 300), ts))
            
    conn.commit()

    # 4. Anti-Forensics: Delete chunks of data to create freelists and slack space
    print("[+] Simulating suspect deleting evidence...")
    cursor.execute("DELETE FROM messages WHERE id BETWEEN 50 AND 100")
    cursor.execute("DELETE FROM messages WHERE id = 499")
    cursor.execute("DELETE FROM calls WHERE duration > 200")
    conn.commit()
    
    # 5. Insert Future Timestamp (Anomaly)
    print("[+] Injecting Future Timestamp Anomaly...")
    future_time = current_time + 50000000 # Way in the future
    cursor.execute("INSERT INTO messages (contact_id, text, is_sent, timestamp) VALUES (?, ?, ?, ?)", (1, "This message is from the FUTURE", 1, future_time))
    
    # 6. Uncommitted WAL transaction (Phantom Record)
    cursor.execute("INSERT INTO messages (contact_id, text, is_sent, timestamp) VALUES (?, ?, ?, ?)", (2, "This is a phantom record that only exists in the WAL file!", 1, current_time))
    
    conn.commit()
    conn.close()

    # 7. Binary Tampering (RowID swap & Corrupted Pointer)
    print("[+] Injecting Binary Structural Anomalies (RowID Tampering & Corrupt Pointers)...")
    with open(DB_NAME, 'rb+') as f:
        db_data = bytearray(f.read())
        
        # B-Tree Page 2 (Offset 4096) is usually the first leaf page for the messages table.
        # Header is 8 bytes. Pointers start at 4096 + 8 = 4104
        # We will intentionally swap the first two pointers to trigger a RowID Anomaly
        ptr1 = struct.unpack_from('>H', db_data, 4104)[0]
        ptr2 = struct.unpack_from('>H', db_data, 4106)[0]
        
        struct.pack_into('>H', db_data, 4104, ptr2)
        struct.pack_into('>H', db_data, 4106, ptr1)
        
        # Intentionally corrupt a pointer on Page 3 (Offset 8192) to point out of bounds
        struct.pack_into('>H', db_data, 8192 + 8, 9999)
        
        f.seek(0)
        f.write(db_data)

    print("[+] Large dataset generation complete! Ready for SQLite-Ghost analysis.")

if __name__ == "__main__":
    create_large_dataset()
