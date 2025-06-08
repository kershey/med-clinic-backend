from sqlalchemy import create_engine, text
from src.config import settings

def test_connection():
    try:
        # Create engine
        engine = create_engine(settings.database_url)
        
        # Test connection
        with engine.connect() as conn:
            # Drop alembic_version table if it exists
            conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
            
            # Create alembic_version table
            conn.execute(text("""
                CREATE TABLE alembic_version (
                    version_num VARCHAR(32) PRIMARY KEY
                )
            """))
            
            # Insert the merge revision
            conn.execute(text("INSERT INTO alembic_version (version_num) VALUES ('a01031a50d97')"))
            
            # Commit the transaction
            conn.commit()
            
            print("Successfully reset alembic_version table")
            
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    test_connection() 