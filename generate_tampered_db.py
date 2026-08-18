import sqlite3
import time
import os
import struct

def generate_tampered_db():
    db_path = 'tampered_data.db'
    
    # Cleanup
    for f in [db_path, db_path+'-wal', db_path+'-shm']:
        if os.path.exists(f):
            os.remove(f)
            
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE employees (
            id INTEGER PRIMARY KEY,
            name TEXT
        )
    ''')
    
    employees = [
        (1, "Alice"),
        (2, "Bob"),
        (3, "Charlie")
    ]
    
    for emp in employees:
        cursor.execute(
            'INSERT INTO employees (id, name) VALUES (?, ?)', 
            emp
        )
    conn.commit()
    conn.close() 

    # Now let's maliciously swap the cell pointers!
    # By swapping the pointers for RowID 1 and RowID 2, they will be read out of order.
    with open(db_path, 'rb+') as f:
        db_data = bytearray(f.read())
        
        # Cell Pointers start at offset 108 (100 byte DB header + 8 byte B-Tree leaf header)
        ptr1 = struct.unpack_from('>H', db_data, 108)[0]
        ptr2 = struct.unpack_from('>H', db_data, 110)[0]
        
        # Swap them!
        struct.pack_into('>H', db_data, 108, ptr2)
        struct.pack_into('>H', db_data, 110, ptr1)
        
        f.seek(0)
        f.write(db_data)

    print(f"Created tampered database: {db_path}!")

if __name__ == '__main__':
    generate_tampered_db()
