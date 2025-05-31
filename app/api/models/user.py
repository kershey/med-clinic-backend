from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from ..database import Base

class User(Base):
    """
    User Model - Stores all user information in the system
    
    Fields:
    - id: Primary key for user identification
    - email: Unique email address for login and communication
    - full_name: User's complete name
    - gender: User's gender (optional)
    - address: User's physical address (optional)
    - contact: User's contact number (optional)
    - password_hash: Securely hashed password (never store raw passwords)
    - is_active: Whether user account is active
    - is_verified: Whether email has been verified
    - role: User role (patient, doctor, staff, admin)
    - profile_image: URL to user's profile image (optional)
    - verification_code: Code sent to email for verification
    - created_at: Timestamp when user was created
    - updated_at: Timestamp when user was last updated
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    gender = Column(String, nullable=True)
    address = Column(String, nullable=True)
    contact = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    role = Column(String, default="patient")
    profile_image = Column(String, nullable=True)
    verification_code = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
