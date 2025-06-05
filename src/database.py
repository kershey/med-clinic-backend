"""
Database connection and session management.
Provides SQLAlchemy engine, session, and base class for models.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import settings

# Create SQLAlchemy engine for database connection
engine = create_engine(settings.database_url)

# Create session factory for database sessions
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Create base class for declarative models
Base = declarative_base()

def get_db():
    """
    Database dependency - Creates and yields a database session.
    
    The session is automatically closed after the request is processed,
    even if an exception occurs during request handling.
    
    Yields:
        SQLAlchemy Session: Database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
