from sqlalchemy import create_engine, text

db_url = "postgresql://postgres:tegenepro@db.ksgkcuitgxytrrhusfcv.supabase.co:5432/postgres"
print("Connecting to:", db_url)

engine = create_engine(db_url)

with engine.connect() as conn:
    result = conn.execute(text("SELECT 1"))
    print("Connection test result:", result.scalar())

with engine.connect() as conn:
    conn.execute(text("CREATE TABLE IF NOT EXISTS test_table (id serial PRIMARY KEY, name varchar(50));"))
    conn.execute(text("INSERT INTO test_table (name) VALUES ('hello_supabase');"))
    conn.commit()
    result = conn.execute(text("SELECT * FROM test_table;"))
    for row in result:
        print(row)