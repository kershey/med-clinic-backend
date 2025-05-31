"""
Database connection and session management.
Provides SQLAlchemy engine, session, and base class for models.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Get database URL from environment variable
DATABASE_URL = os.getenv("DATABASE_URL")

# Create SQLAlchemy engine for database connection
engine = create_engine(DATABASE_URL)

# Create session factory for database sessions
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Create base class for declarative models
Base = declarative_base()