"""
Core security utilities for authentication and password handling.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from jose import jwt, JWTError
from passlib.context import CryptContext
import secrets
import hashlib
import os
import logging

from ..config import settings
from ..auth.models import UserRole, AccountStatus

# Set up logging
logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: Plain text password
        
    Returns:
        str: Hashed password
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against a hash.
    
    Args:
        plain_password: Plain text password
        hashed_password: Hashed password to compare against
        
    Returns:
        bool: True if password matches hash
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_permissions_for_role(role: UserRole, account_status: AccountStatus) -> List[str]:
    """
    Get list of permissions based on user role and account status.
    
    Args:
        role: User role enum
        account_status: Account status enum
        
    Returns:
        List of permission strings
    """
    base_permissions = ["read:profile", "update:profile"]
    
    # No permissions for non-active accounts
    if account_status not in [AccountStatus.ACTIVE]:
        return []
    
    # Role-specific permissions
    if role == UserRole.PATIENT:
        return base_permissions + [
            "read:doctors",
            "create:appointment",
            "read:appointments",
            "update:appointments",
            "read:medical_records",
            "create:payment",
            "read:payments"
        ]
    elif role == UserRole.DOCTOR:
        return base_permissions + [
            "read:appointments",
            "update:appointments",
            "read:medical_records",
            "create:medical_records",
            "update:medical_records",
            "read:patients",
            "update:availability"
        ]
    elif role == UserRole.STAFF:
        return base_permissions + [
            "read:appointments",
            "create:appointments",
            "update:appointments",
            "delete:appointments",
            "read:patients",
            "update:patients",
            "read:doctors",
            "update:doctors",
            "read:payments",
            "update:payments",
            "create:notifications",
            "read:reports"
        ]
    elif role == UserRole.ADMIN:
        return base_permissions + [
            "read:*",
            "create:*",
            "update:*",
            "delete:*",
            "manage:users",
            "manage:system",
            "read:logs",
            "create:backups"
        ]
    
    return base_permissions

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Data to encode in the token
        expires_delta: Token expiration time
        
    Returns:
        str: Encoded JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.access_token_expire_minutes
        )
    
    to_encode.update({"exp": expire})
    
    # Add permissions based on role and account status
    if "role" in data and "account_status" in data:
        permissions = get_permissions_for_role(
            UserRole(data["role"]), 
            AccountStatus(data["account_status"])
        )
        to_encode.update({"permissions": permissions})
    
    encoded_jwt = jwt.encode(
        to_encode, settings.secret_key, algorithm=settings.algorithm
    )
    
    return encoded_jwt

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        Dict containing token payload if valid, None if invalid
    """
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload
    except JWTError:
        return None

def create_refresh_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a refresh token for token renewal.
    
    Args:
        data: Dictionary containing claims to be encoded in the token
        expires_delta: Optional custom expiration time (default: 7 days)
        
    Returns:
        str: Encoded refresh token
    """
    to_encode = data.copy()
    
    # Set longer expiration for refresh tokens (7 days by default)
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=7))
    to_encode.update({"exp": expire, "type": "refresh"})
    
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

def generate_secure_reset_token() -> str:
    """
    Generate a secure token for password reset.
    
    Returns:
        str: Secure random token
    """
    return secrets.token_urlsafe(32)

def hash_token(token: str) -> str:
    """
    Hash a token for secure storage.
    
    Args:
        token: Token to hash
        
    Returns:
        str: Hashed token
    """
    return hashlib.sha256(token.encode()).hexdigest()

def verify_token_hash(token: str, hashed_token: str) -> bool:
    """
    Verify a token against a hash.
    
    Args:
        token: Plain text token
        hashed_token: Hashed token to compare against
        
    Returns:
        bool: True if token matches hash
    """
    return hash_token(token) == hashed_token

    """
    Validate password strength.
    
    Args:
        password: Password to validate
        
    Returns:
        bool: True if password meets strength requirements
    """
    # Password must be at least 8 characters
    if len(password) < 8:
        return False
    
    # Password must contain at least one uppercase letter
    if not any(c.isupper() for c in password):
        return False
    
    # Password must contain at least one lowercase letter
    if not any(c.islower() for c in password):
        return False
    
    # Password must contain at least one digit
    if not any(c.isdigit() for c in password):
        return False
    
    # Password must contain at least one special character
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
    if not any(c in special_chars for c in password):
        return False
    
    return True

def is_token_expired(expiry_time: datetime) -> bool:
    """
    Check if a token has expired.
    
    Args:
        expiry_time: Token expiration time
        
    Returns:
        bool: True if token has expired
    """
    return datetime.now(timezone.utc) > expiry_time

def get_token_expiry_time(minutes: int = 30) -> datetime:
    """
    Get token expiration time.
    
    Args:
        minutes: Minutes until expiration
        
    Returns:
        datetime: Expiration time
    """
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)
