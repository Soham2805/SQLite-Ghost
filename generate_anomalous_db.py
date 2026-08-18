import sqlite3
import time
import os
import struct

def generate_anomalous_db():
    db_path = 'anomalous_data.db'
    
    # Cleanup
    for f in [db_path, db_path+'-wal', db_path+'-shm']:
        if os.path.exists(f):
            os.remove(f)
            
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE employees (
            id INTEGER PRIMARY KEY,
            name TEXT,
            role TEXT,
            salary INTEGER,
            hired_timestamp INTEGER
        )
    ''')

    current_time = int(time.time())
    
    # 1. Timestamp Contradiction (Future date: year 2030)
    future_time = 1893456000 
    
    employees = [
        ("Alice", "Engineer", 90000, current_time - 100000),
        ("Bob", "Time Traveler", 120000, future_time) # This will trigger the future timestamp anomaly
    ]
    
    for emp in employees:
        cursor.execute(
            'INSERT INTO employees (name, role, salary, hired_timestamp) VALUES (?, ?, ?, ?)', 
            emp
        )
    conn.commit()
    conn.close() # Close to flush to disk

    # Now let's inject anomalies directly into the binary!
    with open(db_path, 'rb+') as f:
        db_data = bytearray(f.read())
        
        # Page 1 Header is 100 bytes. B-Tree header is 8 bytes.
        # So Cell Pointers start at offset 108.
        # Let's corrupt the first pointer to point OUT OF BOUNDS (e.g. 5000 > page_size 4096)
        struct.pack_into('>H', db_data, 108, 5000)
        
        # Let's corrupt the second pointer to point INTO THE HEADER (e.g. 50 < 108)
        struct.pack_into('>H', db_data, 110, 50)
        
        # Now let's inject an "Orphaned Payload" in the slack space
        # Slack space is typically around offset 150 onwards for a small DB
        # A simple SQLite payload: HeaderSize=3, Type1=int8(1), Type2=int8(1), Data=66, Data=67
        # Bytes: 0x03 0x01 0x01 0x42 0x43
        slack_offset = 200
        db_data[slack_offset:slack_offset+5] = b'\x03\x01\x01\x42\x43'
        
        # Write back to file
        f.seek(0)
        f.write(db_data)

    print(f"Created highly anomalous database: {db_path}!")

if __name__ == '__main__':
    generate_anomalous_db()
