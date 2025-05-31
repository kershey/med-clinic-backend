from typing import Optional
from pydantic import BaseModel, EmailStr
from datetime import datetime

class UserBase(BaseModel):
    """
    Base User Schema - Contains fields common to all user-related schemas
    
    Fields:
    - email: User's email address
    - full_name: User's full name
    """
    email: EmailStr
    full_name: str

class UserCreate(UserBase):
    """
    User Creation Schema - Used when registering a new user
    
    Extends UserBase with:
    - password: User's plain text password (will be hashed before storage)
    - gender: User's gender (optional)
    - address: User's address (optional)
    - contact: User's contact number (optional)
    """
    password: str
    gender: Optional[str] = None
    address: Optional[str] = None
    contact: Optional[str] = None

class UserLogin(BaseModel):
    """
    User Login Schema - Used for authentication
    
    Fields:
    - email: User's email address
    - password: User's plain text password
    """
    email: EmailStr
    password: str

class UserVerify(BaseModel):
    """
    User Verification Schema - Used to verify email address
    
    Fields:
    - email: User's email address
    - verification_code: Code sent to user's email
    """
    email: EmailStr
    verification_code: str

class UserResponse(BaseModel):
    """
    User Response Schema - Used when returning user data
    
    Fields:
    - id: User ID
    - email: Email address
    - full_name: User's full name
    - gender: User's gender (if provided)
    - address: User's address (if provided)
    - contact: User's contact number (if provided)
    - is_active: Whether user account is active
    - is_verified: Whether email has been verified
    - role: User role (patient, doctor, staff, admin)
    - profile_image: URL to user's profile image (if uploaded)
    - created_at: When the account was created
    - updated_at: When the account was last updated
    """
    id: int
    email: EmailStr
    full_name: str
    gender: Optional[str] = None
    address: Optional[str] = None
    contact: Optional[str] = None
    is_active: bool
    is_verified: bool
    role: str
    profile_image: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        """Configuration for Pydantic model to enable ORM mode"""
        from_attributes = True
