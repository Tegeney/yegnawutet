from app import db
from sqlalchemy import text

def add_student_info_columns():
    """Add student information columns to the User table."""
    try:
        # Add new columns
        with db.engine.connect() as connection:
            connection.execute(text('ALTER TABLE user ADD COLUMN age INTEGER'))
            connection.execute(text('ALTER TABLE user ADD COLUMN nationality VARCHAR(50)'))
            connection.execute(text('ALTER TABLE user ADD COLUMN school VARCHAR(100)'))
            connection.execute(text('ALTER TABLE user ADD COLUMN woreda VARCHAR(50)'))
            connection.execute(text('ALTER TABLE user ADD COLUMN zone VARCHAR(50)'))
            connection.commit()
        print("Successfully added student information columns to User table")
    except Exception as e:
        print(f"Error adding columns: {str(e)}")
        raise 