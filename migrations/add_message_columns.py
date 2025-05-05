from flask import current_app
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import os

def add_message_columns():
    db_path = os.path.join(current_app.root_path, 'school.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Add new columns to the message table
        cursor.execute('''
            ALTER TABLE message 
            ADD COLUMN read BOOLEAN DEFAULT 0
        ''')
        cursor.execute('''
            ALTER TABLE message 
            ADD COLUMN cleared_by_sender BOOLEAN DEFAULT 0
        ''')
        cursor.execute('''
            ALTER TABLE message 
            ADD COLUMN cleared_by_receiver BOOLEAN DEFAULT 0
        ''')
        
        conn.commit()
        print("Successfully added new columns to message table")
    except sqlite3.OperationalError as e:
        print(f"Error adding columns: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    add_message_columns() 