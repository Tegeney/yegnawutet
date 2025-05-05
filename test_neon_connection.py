from sqlalchemy import create_engine, text
import os

# Replace this with your actual Neon database URL
db_url = os.getenv('DATABASE_URL', 'postgresql://your-neon-connection-string')
print("Connecting to:", db_url)

try:
    engine = create_engine(db_url)
    
    with engine.connect() as conn:
        # Test the connection
        result = conn.execute(text("SELECT 1"))
        print("Connection test result:", result.scalar())
        
        # Create a test table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS test_table (
                id serial PRIMARY KEY,
                name varchar(50)
            )
        """))
        
        # Insert a test record
        conn.execute(text("INSERT INTO test_table (name) VALUES ('hello_neon')"))
        conn.commit()
        
        # Query the test data
        result = conn.execute(text("SELECT * FROM test_table"))
        print("\nTest table contents:")
        for row in result:
            print(row)
            
    print("\nDatabase connection and operations successful!")
    
except Exception as e:
    print("Error:", str(e)) 