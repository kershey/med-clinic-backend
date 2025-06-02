"""
FastAPI dependencies for authentication and authorization.
Enhanced to support role-based access control with account status verification.
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import List, Optional
from .database import SessionLocal
from .models.user import User, UserRole, AccountStatus
from .auth.jwt import verify_token, verify_account_status

# OAuth2 scheme for JWT token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

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

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Get current authenticated user from JWT token with database verification.
    
    Args:
        token: JWT token from Authorization header
        db: Database session
        
    Returns:
        User: Current authenticated user
        
    Raises:
        HTTPException: If token is invalid or user not found
    """
    # Verify and decode token
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user ID from token payload
    user_id = payload.get("id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Fetch user from database
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user

def get_current_active_user(current_user: User = Depends(get_current_user)):
    """
    Get current user and verify account is active.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User: Active user
        
    Raises:
        HTTPException: If account is not active
    """
    if not verify_account_status(current_user.account_status, [AccountStatus.ACTIVE]):
        status_messages = {
            AccountStatus.PENDING_VERIFICATION: "Email verification required",
            AccountStatus.PENDING_ACTIVATION: "Account pending activation by administrator", 
            AccountStatus.DISABLED: "Account disabled, pending approval",
            AccountStatus.DEACTIVATED: "Account has been deactivated",
            AccountStatus.RED_TAG: "Account flagged for review"
        }
        
        message = status_messages.get(current_user.account_status, "Account access denied")
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account status: {current_user.account_status.value}. {message}"
        )
    
    return current_user

def require_roles(allowed_roles: List[UserRole]):
    """
    Dependency factory to require specific roles.
    
    Args:
        allowed_roles: List of roles that are allowed access
        
    Returns:
        Function that checks if user has required role
    """
    def role_checker(current_user: User = Depends(get_current_active_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {[role.value for role in allowed_roles]}. Your role: {current_user.role.value}"
            )
        return current_user
    return role_checker

def require_permissions(required_permissions: List[str]):
    """
    Dependency factory to require specific permissions.
    
    Args:
        required_permissions: List of permissions required for access
        
    Returns:
        Function that checks if user has required permissions
    """
    def permission_checker(token: str = Depends(oauth2_scheme)):
        payload = verify_token(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        user_permissions = payload.get("permissions", [])
        
        # Check if user has admin wildcard permission
        if "read:*" in user_permissions or "create:*" in user_permissions:
            return payload
        
        # Check specific permissions
        missing_permissions = [perm for perm in required_permissions if perm not in user_permissions]
        if missing_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permissions: {missing_permissions}"
            )
        
        return payload
    return permission_checker

# Convenience dependencies for specific roles
require_patient = require_roles([UserRole.PATIENT])
require_doctor = require_roles([UserRole.DOCTOR])
require_staff = require_roles([UserRole.STAFF])
require_admin = require_roles([UserRole.ADMIN])

# Dependencies for staff/admin access (either role allowed)
require_staff_or_admin = require_roles([UserRole.STAFF, UserRole.ADMIN])
require_doctor_or_staff = require_roles([UserRole.DOCTOR, UserRole.STAFF])
require_any_staff = require_roles([UserRole.DOCTOR, UserRole.STAFF, UserRole.ADMIN])

def get_current_user_with_verification_status(current_user: User = Depends(get_current_user)):
    """
    Get current user allowing unverified accounts (for verification endpoints).
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User: User (regardless of verification status)
    """
    return current_user
