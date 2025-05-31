"""
JWT token creation and verification utilities.
Handles the creation of access tokens for user authentication.
"""
from datetime import datetime, timedelta
from jose import jwt
from ..config import settings

def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    Create a new JWT access token.
    
    Args:
        data: Dictionary containing claims to be encoded in the token
        expires_delta: Optional custom expiration time
        
    Returns:
        str: Encoded JWT token
    """
    # Create a copy of the data to avoid modifying the original
    to_encode = data.copy()
    
    # Set expiration time based on provided delta or use default
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    
    # Add expiration claim to the payload
    to_encode.update({"exp": expire})
    
    # Encode the token with the secret key and algorithm
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
