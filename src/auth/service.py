"""
Authentication service layer for business logic.
"""
import logging
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from fastapi import BackgroundTasks, HTTPException, status
from pydantic import EmailStr
from typing import Dict, Any, Optional, Tuple

from ..core.security import (
    hash_password, 
    verify_password, 
    create_access_token,
    create_refresh_token,
    generate_secure_reset_token,
    hash_token,
    verify_token_hash,
    is_token_expired,
    get_token_expiry_time
)
from .models import User, UserRole, AccountStatus
from .utils import (
    generate_verification_code,
    send_verification_email,
    send_password_reset_email,
    send_password_changed_notification
)
from .exceptions import (
    InvalidCredentialsException,
    EmailAlreadyExistsException,
    VerificationCodeInvalidException,
    AccountStatusException,
    TokenExpiredException,
    InvalidTokenException,
    PasswordResetException,
    AccountLockedException
)
from ..config import settings

# Set up logging
logger = logging.getLogger(__name__)

async def register_patient(
    db: Session,
    email: EmailStr,
    full_name: str,
    password: str,
    gender: Optional[str] = None,
    address: Optional[str] = None,
    contact: Optional[str] = None,
    background_tasks: Optional[BackgroundTasks] = None
) -> Dict[str, Any]:
    """
    Register a new patient user.
    
    Args:
        db: Database session
        email: User's email address
        full_name: User's full name
        password: User's password
        gender: User's gender (optional)
        address: User's address (optional)
        contact: User's contact number (optional)
        background_tasks: FastAPI BackgroundTasks for email sending
        
    Returns:
        Dict with registration success message and verification instructions
        
    Raises:
        EmailAlreadyExistsException: If email already exists
    """
    logger.info(f"Patient registration attempt for email: {email}")
    
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        logger.warning(f"Registration failed: Email {email} already registered")
        raise EmailAlreadyExistsException()
    
    # Generate verification code
    verification_code = generate_verification_code()
    
    # Create new patient user
    user_obj = User(
        email=email,
        full_name=full_name,
        gender=gender,
        address=address,
        contact=contact,
        password_hash=hash_password(password),
        role=UserRole.PATIENT,
        account_status=AccountStatus.PENDING_VERIFICATION,
        verification_code=verification_code,
        is_verified=False
    )
    
    # Save to database
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    logger.info(f"Patient account created: {user_obj.id}")
    
    # Send verification email
    try:
        await send_verification_email(email, verification_code)
        logger.info(f"Verification email sent to {email}")
        
        return {
            "message": "Patient account created successfully. Please check your email for verification code.",
            "user_id": user_obj.id,
            "email": email,
            "next_step": "verify_email"
        }
    except Exception as e:
        error_str = str(e)
        logger.error(f"Failed to send verification email: {error_str}")
        
        # Provide specific error messages based on the type of failure
        if "Authentication failed" in error_str:
            error_detail = "Email authentication failed. Please contact support."
        elif "configuration is incomplete" in error_str:
            error_detail = "Email service configuration error. Please contact support."
        elif "timeout" in error_str.lower() or "connection" in error_str.lower():
            error_detail = "Email service temporarily unavailable. Please try resend verification."
        else:
            error_detail = "Email service unavailable"
        
        return {
            "message": "Patient account created but verification email failed to send. Please use resend verification.",
            "user_id": user_obj.id,
            "email": email,
            "error": error_detail,
            "next_step": "resend_verification",
            "retry_available": True
        }

async def register_doctor(
    db: Session,
    email: EmailStr,
    full_name: str,
    password: str,
    specialization: str,
    bio: Optional[str] = None,
    gender: Optional[str] = None,
    address: Optional[str] = None,
    contact: Optional[str] = None
) -> Dict[str, Any]:
    """
    Register a new doctor user.
    
    Args:
        db: Database session
        email: Doctor's email address
        full_name: Doctor's full name
        password: Doctor's password
        specialization: Doctor's medical specialization
        bio: Doctor's professional biography (optional)
        gender: Doctor's gender (optional)
        address: Doctor's address (optional)
        contact: Doctor's contact number (optional)
        
    Returns:
        Dict with registration success message and approval instructions
        
    Raises:
        EmailAlreadyExistsException: If email already exists
    """
    logger.info(f"Doctor registration attempt for email: {email}")
    
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        logger.warning(f"Registration failed: Email {email} already registered")
        raise EmailAlreadyExistsException()
    
    
    # Create new doctor user with DISABLED status
    user_obj = User(
        email=email,
        full_name=full_name,
        gender=gender,
        address=address,
        contact=contact,
        password_hash=hash_password(password),
        role=UserRole.DOCTOR,
        account_status=AccountStatus.DISABLED,
        is_verified=True  # Doctors don't need email verification, just admin approval
    )
    
    # Save to database
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    logger.info(f"Doctor account created (pending approval): {user_obj.id}")
    
    # Note: In a real system, you might want to notify admins about new doctor registration
    
    return {
        "message": "Doctor account created successfully. Your account is pending administrator approval.",
        "user_id": user_obj.id,
        "email": email,
        "status": "pending_approval",
    }

async def login_user(
    db: Session,
    email: str,
    password: str
) -> Dict[str, Any]:
    """
    Authenticate a user and generate access token.
    
    Args:
        db: Database session
        email: User's email address
        password: User's password
        
    Returns:
        Dict with access token and user information
        
    Raises:
        InvalidCredentialsException: If credentials are invalid
        AccountStatusException: If account status prevents login
    """
    # Find user by email
    user = db.query(User).filter(User.email == email).first()
    
    # Check if user exists and password is correct
    if not user or not verify_password(password, user.password_hash):
        logger.warning(f"Login failed: Invalid credentials for {email}")
        raise InvalidCredentialsException()
    
    # Check if account is active
    if user.account_status not in [AccountStatus.ACTIVE]:
        logger.warning(f"Login failed: Account status {user.account_status} for {email}")
        
        status_messages = {
            AccountStatus.PENDING_VERIFICATION: "Email verification required",
            AccountStatus.PENDING_ACTIVATION: "Account pending activation by administrator", 
            AccountStatus.DISABLED: "Account disabled, pending approval",
            AccountStatus.DEACTIVATED: "Account has been deactivated",
            AccountStatus.RED_TAG: "Account flagged for review"
        }
        
        message = status_messages.get(user.account_status, "Account access denied")
        
        raise AccountStatusException(user.account_status.value, message)
    
    # Generate access token
    token_data = {
        "id": user.id,
        "email": user.email,
        "role": user.role.value,
        "account_status": user.account_status.value
    }
    
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    
    logger.info(f"Login successful: User {user.id} ({email})")
    
    # Return token and user information
    from .schemas import UserResponse
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": UserResponse.from_orm(user),
        "permissions": []  # Permissions will be added by the token creation function
    }

async def verify_email(
    db: Session,
    email: str,
    verification_code: str
) -> Dict[str, Any]:
    """
    Verify user's email address with verification code.
    
    Args:
        db: Database session
        email: User's email address
        verification_code: Verification code sent to email
        
    Returns:
        Dict with verification success message
        
    Raises:
        InvalidCredentialsException: If email not found
        VerificationCodeInvalidException: If verification code is invalid
    """
    # Find user by email
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        logger.warning(f"Verification failed: Email {email} not found")
        raise InvalidCredentialsException("Email not found")
    
    # Check if account is already verified
    if user.is_verified:
        logger.info(f"Account already verified: {email}")
        return {
            "message": "Email already verified",
            "user_id": user.id,
            "email": email,
            "status": user.account_status.value
        }
    
    # Check verification code
    if not user.verification_code or user.verification_code != verification_code:
        logger.warning(f"Verification failed: Invalid code for {email}")
        raise VerificationCodeInvalidException()
    
    # Update user status
    user.is_verified = True
    user.account_status = AccountStatus.ACTIVE
    user.verification_code = None  # Clear verification code after use
    
    db.commit()
    logger.info(f"Email verified: {email}")
    
    return {
        "message": "Email verified successfully",
        "user_id": user.id,
        "email": email,
        "status": user.account_status.value
    }

async def resend_verification(
    db: Session,
    email: str
) -> Dict[str, Any]:
    """
    Resend verification email.
    
    Args:
        db: Database session
        email: User's email address
        
    Returns:
        Dict with resend success message
        
    Raises:
        InvalidCredentialsException: If email not found
    """
    # Find user by email
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        logger.warning(f"Resend verification failed: Email {email} not found")
        raise InvalidCredentialsException("Email not found")
    
    # Check if account is already verified
    if user.is_verified:
        logger.info(f"Account already verified: {email}")
        return {
            "message": "Email already verified",
            "user_id": user.id,
            "email": email,
            "status": user.account_status.value
        }
    
    # Generate new verification code
    verification_code = generate_verification_code()
    user.verification_code = verification_code
    
    db.commit()
    
    # Send verification email
    try:
        await send_verification_email(email, verification_code)
        logger.info(f"Verification email resent to {email}")
        
        return {
            "message": "Verification email sent successfully",
            "user_id": user.id,
            "email": email,
            "next_step": "verify_email"
        }
    except Exception as e:
        logger.error(f"Failed to resend verification email: {str(e)}")
        
        return {
            "message": "Failed to send verification email",
            "user_id": user.id,
            "email": email,
            "error": str(e),
            "next_step": "resend_verification",
            "retry_available": True
        }

async def forgot_password(
    db: Session,
    email: str,
    request_url: str
) -> Dict[str, Any]:
    """
    Initiate password reset process.
    
    Args:
        db: Database session
        email: User's email address
        request_url: Base URL for password reset
        
    Returns:
        Dict with password reset instructions
        
    Raises:
        InvalidCredentialsException: If email not found
        AccountLockedException: If account is locked due to too many reset attempts
    """
    # Find user by email
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        logger.warning(f"Password reset failed: Email {email} not found")
        # For security, don't reveal that email doesn't exist
        return {
            "message": "If your email is registered, you will receive password reset instructions"
        }
    
    # Check if account is locked due to too many reset attempts
    if user.reset_locked_until and not is_token_expired(user.reset_locked_until):
        logger.warning(f"Password reset failed: Account locked for {email}")
        
        # Calculate remaining lock time
        now = datetime.now(timezone.utc)
        remaining_seconds = int((user.reset_locked_until - now).total_seconds())
        remaining_minutes = max(1, remaining_seconds // 60)
        
        raise AccountLockedException(
            f"Too many reset attempts. Please try again in {remaining_minutes} minutes"
        )
    
    # Generate reset token
    reset_token = generate_secure_reset_token()
    token_hash = hash_token(reset_token)
    token_expires = get_token_expiry_time(30)  # 30 minutes expiry
    
    # Update user with token information
    user.reset_token_hash = token_hash
    user.reset_token_expires = token_expires
    user.reset_token_created = datetime.now(timezone.utc)
    user.reset_attempts_count = 0  # Reset the counter
    user.reset_locked_until = None  # Clear any lock
    
    db.commit()
    
    # Build reset URL
    reset_url = f"{request_url}/reset-password?token={reset_token}&email={email}"
    
    # Send password reset email
    try:
        await send_password_reset_email(email, user.full_name, reset_url, token_expires)
        logger.info(f"Password reset email sent to {email}")
        
        return {
            "message": "Password reset instructions sent to your email"
        }
    except Exception as e:
        logger.error(f"Failed to send password reset email: {str(e)}")
        
        return {
            "message": "Password reset initiated. Please check your email for instructions",
            "error": "Email delivery may be delayed"
        }

async def reset_password(
    db: Session,
    email: str,
    reset_token: str,
    new_password: str
) -> Dict[str, Any]:
    """
    Reset user's password using reset token.
    
    Args:
        db: Database session
        email: User's email address
        reset_token: Token received via email
        new_password: New password
        
    Returns:
        Dict with password reset success message
        
    Raises:
        InvalidCredentialsException: If email not found
        InvalidTokenException: If reset token is invalid
        TokenExpiredException: If reset token has expired
        AccountLockedException: If account is locked due to too many reset attempts
    """
    # Find user by email
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        logger.warning(f"Password reset failed: Email {email} not found")
        raise InvalidCredentialsException("Invalid email or token")
    
    # Check if account is locked due to too many reset attempts
    if user.reset_locked_until and not is_token_expired(user.reset_locked_until):
        logger.warning(f"Password reset failed: Account locked for {email}")
        
        # Calculate remaining lock time
        now = datetime.now(timezone.utc)
        remaining_seconds = int((user.reset_locked_until - now).total_seconds())
        remaining_minutes = max(1, remaining_seconds // 60)
        
        raise AccountLockedException(
            f"Too many reset attempts. Please try again in {remaining_minutes} minutes"
        )
    
    # Increment reset attempts counter
    user.reset_attempts_count += 1
    
    # Check if too many attempts (lock after 5 attempts)
    if user.reset_attempts_count >= 5:
        # Lock account for 30 minutes
        user.reset_locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
        db.commit()
        
        logger.warning(f"Password reset failed: Too many attempts for {email}")
        raise AccountLockedException("Too many reset attempts. Account locked for 30 minutes")
    
    # Check if token exists and is valid
    if not user.reset_token_hash or not verify_token_hash(reset_token, user.reset_token_hash):
        db.commit()  # Save the attempt counter
        logger.warning(f"Password reset failed: Invalid token for {email}")
        raise InvalidTokenException("Invalid reset token")
    
    # Check if token has expired
    if not user.reset_token_expires or is_token_expired(user.reset_token_expires):
        db.commit()  # Save the attempt counter
        logger.warning(f"Password reset failed: Expired token for {email}")
        raise TokenExpiredException("Reset token has expired")
    
    
    # Update password
    user.password_hash = hash_password(new_password)
    user.reset_token_hash = None
    user.reset_token_expires = None
    user.reset_token_created = None
    user.reset_attempts_count = 0
    user.reset_locked_until = None
    user.password_changed_at = datetime.now(timezone.utc)
    
    db.commit()
    logger.info(f"Password reset successful for {email}")
    
    # Send password changed notification
    try:
        await send_password_changed_notification(email, user.full_name)
    except Exception as e:
        logger.error(f"Failed to send password changed notification: {str(e)}")
    
    return {
        "message": "Password reset successful. You can now log in with your new password"
    }

async def refresh_token(
    user: User,
    db: Session
) -> Dict[str, Any]:
    """
    Refresh access token.
    
    Args:
        user: Current user
        db: Database session
        
    Returns:
        Dict with new access token
    """
    # Generate new access token
    token_data = {
        "id": user.id,
        "email": user.email,
        "role": user.role.value,
        "account_status": user.account_status.value
    }
    
    access_token = create_access_token(token_data)
    
    logger.info(f"Token refreshed for user {user.id} ({user.email})")
    
    # Return token and user information
    from .schemas import UserResponse
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse.from_orm(user),
        "permissions": []  # Permissions will be added by the token creation function
    }
