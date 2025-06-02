"""
JWT token creation and verification utilities.
Enhanced to handle role-based authentication with account status validation.
"""
from datetime import datetime, timedelta
from jose import jwt, JWTError
from typing import Dict, List, Optional
from ..config import settings
from ..models.user import UserRole, AccountStatus

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

def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    Create a new JWT access token with enhanced payload.
    
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
    
    # Add permissions based on role and account status
    if "role" in data and "account_status" in data:
        permissions = get_permissions_for_role(
            UserRole(data["role"]), 
            AccountStatus(data["account_status"])
        )
        to_encode.update({"permissions": permissions})
    
    # Encode the token with the secret key and algorithm
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

def verify_token(token: str) -> Optional[Dict]:
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

def create_refresh_token(data: dict, expires_delta: timedelta = None):
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
    expire = datetime.utcnow() + (expires_delta or timedelta(days=7))
    to_encode.update({"exp": expire, "type": "refresh"})
    
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

def verify_account_status(account_status: AccountStatus, required_status: List[AccountStatus] = None) -> bool:
    """
    Verify if account status allows access.
    
    Args:
        account_status: Current account status
        required_status: List of allowed statuses (default: [ACTIVE])
        
    Returns:
        bool: True if status allows access
    """
    if required_status is None:
        required_status = [AccountStatus.ACTIVE]
    
    return account_status in required_status
