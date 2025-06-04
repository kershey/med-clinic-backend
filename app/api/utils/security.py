"""
Security utilities for password reset and token management.

This module provides secure token generation, hashing, and password validation
following industry best practices for authentication security.
"""
import secrets
import hashlib
import re
from typing import Dict, List
from datetime import datetime, timedelta, timezone


def generate_secure_reset_token() -> str:
    """
    Generate a cryptographically secure reset token.
    
    Returns:
        str: A 32-byte URL-safe token (43 characters when base64 encoded)
    """
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """
    Hash a token with a random salt for secure storage.
    
    Args:
        token: The plain text token to hash
        
    Returns:
        str: The hashed token with salt appended (hex format)
    """
    # Generate a random 32-byte salt
    salt = secrets.token_bytes(32)
    
    # Hash the token with the salt using PBKDF2
    token_hash = hashlib.pbkdf2_hmac('sha256', token.encode(), salt, 100000)
    
    # Return hash + salt as hex string
    return token_hash.hex() + salt.hex()


def verify_token_hash(token: str, stored_hash: str) -> bool:
    """
    Verify a token against its stored hash.
    
    Args:
        token: The plain text token to verify
        stored_hash: The stored hash (includes salt)
        
    Returns:
        bool: True if token matches, False otherwise
    """
    try:
        # Extract hash and salt from stored value
        hash_part = stored_hash[:64]  # First 64 chars are the hash
        salt_part = bytes.fromhex(stored_hash[64:])  # Rest is the salt
        
        # Hash the provided token with the extracted salt
        token_hash = hashlib.pbkdf2_hmac('sha256', token.encode(), salt_part, 100000)
        
        # Compare hashes
        return token_hash.hex() == hash_part
        
    except (ValueError, IndexError):
        # Invalid hash format
        return False


class PasswordValidation:
    """Result of password strength validation."""
    
    def __init__(self, is_valid: bool, errors: List[str]):
        self.is_valid = is_valid
        self.errors = errors


def validate_password_strength(password: str) -> PasswordValidation:
    """
    Validate password meets security requirements.
    
    Requirements:
    - At least 8 characters long
    - Contains lowercase letter
    - Contains number
    
    Optional (recommended but not required):
    - Uppercase letter
    - Special character
    
    Args:
        password: The password to validate
        
    Returns:
        PasswordValidation: Object with validation result and error messages
    """
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one number")
    
    # Check for common weak passwords
    weak_passwords = ['password', '12345678', 'qwerty123', 'admin123']
    if password.lower() in weak_passwords:
        errors.append("Password is too common, please choose a stronger password")
    
    return PasswordValidation(is_valid=len(errors) == 0, errors=errors)


def get_token_expiry_time(minutes: int = 15) -> datetime:
    """
    Get expiry time for a token.
    
    Args:
        minutes: Number of minutes from now (default: 15)
        
    Returns:
        datetime: The expiry timestamp (timezone-aware)
    """
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


def is_token_expired(expires_at: datetime) -> bool:
    """
    Check if a token has expired.
    
    Args:
        expires_at: When the token expires
        
    Returns:
        bool: True if expired, False if still valid
    """
    return datetime.now(timezone.utc) > expires_at


def should_lock_account(attempts: int, threshold: int = 5) -> bool:
    """
    Determine if account should be locked based on attempts.
    
    Args:
        attempts: Number of failed attempts
        threshold: Maximum allowed attempts (default: 5)
        
    Returns:
        bool: True if account should be locked
    """
    return attempts >= threshold


def get_account_lock_duration(hours: int = 24) -> datetime:
    """
    Get timestamp for when account lock expires.
    
    Args:
        hours: Number of hours to lock account (default: 24)
        
    Returns:
        datetime: When the account lock expires (timezone-aware)
    """
    return datetime.now(timezone.utc) + timedelta(hours=hours) 