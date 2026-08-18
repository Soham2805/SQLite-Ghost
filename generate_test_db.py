import sqlite3
import time
import os

def generate_custom_db():
    conn = sqlite3.connect('test_data.db')
    conn.execute('PRAGMA journal_mode=WAL;')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE employees (
            id INTEGER PRIMARY KEY,
            name TEXT,
            role TEXT,
            salary INTEGER,
            hired_timestamp INTEGER,
            biography TEXT
        )
    ''')

    current_time = int(time.time())
    
    # Insert some valid records with larger payloads
    employees = [
        ("Alice", "Engineer", 90000, current_time - 100000, "Alice is a great engineer " * 10),
        ("Bob", "Manager", 120000, current_time - 200000, "Bob loves to manage people " * 10),
        ("Charlie", "Technician", 60000, current_time - 300000, "Charlie fixes the things " * 10),
        ("Diana", "HR", 75000, current_time - 400000, "Diana ensures compliance " * 10),
        ("Eve", "Spy", 150000, current_time - 5000, "Eve is secretly stealing secrets for a competitor! " * 10)
    ]
    
    for emp in employees:
        cursor.execute(
            'INSERT INTO employees (name, role, salary, hired_timestamp, biography) VALUES (?, ?, ?, ?, ?)', 
            emp
        )
    conn.commit()

    # Delete 'Eve' (the spy) to send her large record to unallocated slack space
    cursor.execute('DELETE FROM employees WHERE name = "Eve"')
    conn.commit()

    # Create an uncommitted 'Phantom Record' in the WAL file
    cursor.execute(
        'INSERT INTO employees (name, role, salary, hired_timestamp, biography) VALUES (?, ?, ?, ?, ?)', 
        ("Frank", "Ghost Employee", 0, current_time + 1000, "Frank doesn't exist but receives paychecks! " * 10)
    )
    
    print("Created test_data.db and test_data.db-wal! Hard-exiting to preserve WAL...")
    
    # Hard exit without closing connection to ensure WAL is not checkpointed/deleted
    os._exit(0)

if __name__ == '__main__':
    # Delete old ones
    try:
        os.remove('test_data.db')
        os.remove('test_data.db-wal')
        os.remove('test_data.db-shm')
    except:
        pass
    generate_custom_db()
