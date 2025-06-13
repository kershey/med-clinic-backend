"""
Authentication service layer for business logic.
"""
import logging
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from fastapi import BackgroundTasks, HTTPException, status, Request
from pydantic import EmailStr
from typing import Dict, Any, Optional, Tuple, List

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
from ..core.audit_service import create_audit_log
from ..core.audit_models import AuditLog
from .models import User, UserRole, AccountStatus, DoctorStatus
from ..doctors.models import Doctor
from .schemas import UserPasswordChangeInternal, StaffFirstLoginPasswordSet, AuditLogResponse
from .utils import (
    generate_verification_code,
    send_verification_email,
    send_password_reset_email,
    send_password_changed_notification,
    send_staff_activation_email
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
    profile_image: Optional[str] = None,
    background_tasks: Optional[BackgroundTasks] = None,
    request: Optional[Request] = None
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
        profile_image: URL to user's profile image (optional, provided by Uploadcare)
        background_tasks: FastAPI BackgroundTasks for email sending
        request: FastAPI request object for audit logging
        
    Returns:
        Dict with registration success message and verification instructions
        
    Raises:
        EmailAlreadyExistsException: If email already exists
    """
    logger.info(f"Patient registration attempt for email: {email}")
    await create_audit_log(db, action="PATIENT_REGISTRATION_INITIATED", request=request, details={"email": email})
    
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        logger.warning(f"Registration failed: Email {email} already registered")
        await create_audit_log(db, action="PATIENT_REGISTRATION_FAILED_EMAIL_EXISTS", request=request, details={"email": email})
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
        is_verified=False,
        profile_image=profile_image
    )
    
    # Save to database
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    logger.info(f"Patient account created: {user_obj.id}")
    await create_audit_log(db, action="PATIENT_REGISTRATION_SUCCESS", user_id=user_obj.id, request=request, details={"email": email, "user_id": user_obj.id})
    
    # Send verification email
    try:
        await send_verification_email(email, verification_code)
        logger.info(f"Verification email sent to {email}")
        await create_audit_log(db, action="VERIFICATION_EMAIL_SENT", user_id=user_obj.id, request=request, details={"email": email, "type": "patient_registration"})
        
        return {
            "message": "Patient account created successfully. Please check your email for verification code.",
            "user_id": user_obj.id,
            "email": email,
            "next_step": "verify_email"
        }
    except Exception as e:
        error_str = str(e)
        logger.error(f"Failed to send verification email: {error_str}")
        await create_audit_log(db, action="VERIFICATION_EMAIL_FAILED_TO_SEND", user_id=user_obj.id, request=request, details={"email": email, "error": error_str, "type": "patient_registration"})
        
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
    contact: Optional[str] = None,
    profile_image: Optional[str] = None,
    request: Optional[Request] = None
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
        profile_image: URL to doctor's profile image (optional, provided by Uploadcare)
        request: FastAPI request object for audit logging
        
    Returns:
        Dict with registration success message and approval instructions
        
    Raises:
        EmailAlreadyExistsException: If email already exists
    """
    logger.info(f"Doctor registration attempt for email: {email}")
    await create_audit_log(db, action="DOCTOR_REGISTRATION_INITIATED", request=request, details={"email": email, "specialization": specialization})
    
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        logger.warning(f"Registration failed: Email {email} already registered")
        await create_audit_log(db, action="DOCTOR_REGISTRATION_FAILED_EMAIL_EXISTS", request=request, details={"email": email})
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
        is_verified=True,  # Doctors don't need email verification, just admin approval
        profile_image=profile_image
    )
    
    # Save to database
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    logger.info(f"Doctor account created (pending approval): {user_obj.id}")
    await create_audit_log(db, action="DOCTOR_REGISTRATION_SUCCESS_PENDING_APPROVAL", user_id=user_obj.id, request=request, details={"email": email, "user_id": user_obj.id})
    
    # Note: In a real system, you might want to notify admins about new doctor registration
    
    return {
        "message": "Doctor account created successfully. Your account is pending administrator approval.",
        "user_id": user_obj.id,
        "email": email,
        "status": "pending_approval",
    }

async def register_staff(
    db: Session,
    email: EmailStr,
    full_name: str,
    password: str,
    gender: Optional[str] = None,
    address: Optional[str] = None,
    contact: Optional[str] = None,
    profile_image: Optional[str] = None,
    created_by_id: Optional[int] = None,
    background_tasks: Optional[BackgroundTasks] = None,
    request: Optional[Request] = None
) -> Dict[str, Any]:
    """
    Register a new staff user.
    
    Args:
        db: Database session
        email: Staff's email address
        full_name: Staff's full name
        password: Staff's password (temporary for initial creation)
        gender: Staff's gender (optional)
        address: Staff's address (optional)
        contact: Staff's contact number (optional)
        profile_image: URL to staff's profile image (optional, provided by Uploadcare)
        created_by_id: ID of the admin/staff who created this account (optional)
        background_tasks: FastAPI BackgroundTasks for email sending
        request: FastAPI request object for audit logging
        
    Returns:
        Dict with account creation success message
        
    Raises:
        EmailAlreadyExistsException: If email already exists
    """
    logger.info(f"Staff registration attempt for email: {email}")
    await create_audit_log(db, action="STAFF_REGISTRATION_INITIATED_BY_ADMIN", user_id=created_by_id, request=request, details={"target_email": email, "admin_id": created_by_id})
    
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        logger.warning(f"Registration failed: Email {email} already registered")
        await create_audit_log(db, action="STAFF_REGISTRATION_FAILED_EMAIL_EXISTS", user_id=created_by_id, request=request, details={"target_email": email, "admin_id": created_by_id})
        raise EmailAlreadyExistsException()
    
    # Create new staff user
    user_obj = User(
        email=email,
        full_name=full_name,
        gender=gender,
        address=address,
        contact=contact,
        password_hash=hash_password(password),
        role=UserRole.STAFF,
        account_status=AccountStatus.PENDING_ACTIVATION,
        is_verified=True,
        created_by=created_by_id,
        created_at=datetime.now(timezone.utc),
        profile_image=profile_image
    )
    
    # Save to database
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    logger.info(f"Staff account created: {user_obj.id}")
    await create_audit_log(db, action="STAFF_REGISTRATION_SUCCESS_PENDING_ACTIVATION", user_id=created_by_id, request=request, details={"target_email": email, "staff_user_id": user_obj.id, "admin_id": created_by_id})
    
    # Send activation email in background
    if background_tasks:
        background_tasks.add_task(
            send_staff_activation_email,
            email=email,
            full_name=full_name,
            temp_password=password
        )
        # Consider logging email send success/failure here or within the task
        await create_audit_log(db, action="STAFF_ACTIVATION_EMAIL_SENT", user_id=user_obj.id, request=request, details={"email": email, "type": "staff_registration"})
    
    return {
        "message": "Staff account created successfully. Activation email has been sent.",
        "user_id": user_obj.id,
        "email": email,
        "status": "pending_activation",
        "created_by": created_by_id,
        "created_at": user_obj.created_at.isoformat()
    }

async def login_user(
    db: Session,
    email: str,
    password: str,
    request: Optional[Request] = None
) -> Dict[str, Any]:
    """
    Authenticate a user and generate access token.
    
    Args:
        db: Database session
        email: User's email address
        password: User's password
        request: FastAPI request object for audit logging
        
    Returns:
        Dict with access token and user information
        
    Raises:
        InvalidCredentialsException: If credentials are invalid
        AccountStatusException: If account status prevents login
    """
    # Find user by email
    user = db.query(User).filter(User.email == email).first()
    
    # Log attempt before checking user to capture attempts on non-existent users
    await create_audit_log(db, action="USER_LOGIN_ATTEMPT", request=request, details={"email": email, "user_exists": bool(user)})
    
    # Check if user exists and password is correct
    if not user or not verify_password(password, user.password_hash):
        logger.warning(f"Login failed: Invalid credentials for {email}")
        # If user exists, log with user_id, otherwise log with email only
        user_id_for_log = user.id if user else None
        await create_audit_log(db, action="USER_LOGIN_FAILED_INVALID_CREDENTIALS", user_id=user_id_for_log, request=request, details={"email": email})
        raise InvalidCredentialsException()
    
    # Check if account is active
    if user.account_status not in [AccountStatus.ACTIVE]:
        logger.warning(f"Login failed: Account status {user.account_status} for {email}")
        
        status_messages = {
            AccountStatus.PENDING_VERIFICATION: "Email verification required. Please check your email for the verification code.",
            AccountStatus.PENDING_ACTIVATION: "Account pending activation by administrator", 
            AccountStatus.DISABLED: "Account disabled, pending approval",
            AccountStatus.DEACTIVATED: "Account has been deactivated",
            AccountStatus.RED_TAG: "Account flagged for review"
        }
        
        message = status_messages.get(user.account_status, "Account access denied")
        
        raise AccountStatusException(user.account_status, message)
    
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
    verification_code: str,
    request: Optional[Request] = None
) -> Dict[str, Any]:
    """
    Verify user's email address with verification code.
    
    Args:
        db: Database session
        email: User's email address
        verification_code: Verification code sent to email
        request: FastAPI request object for audit logging
        
    Returns:
        Dict with verification success message
        
    Raises:
        InvalidCredentialsException: If email not found
        VerificationCodeInvalidException: If verification code is invalid
    """
    await create_audit_log(db, action="EMAIL_VERIFICATION_ATTEMPT", request=request, details={"email": email, "code_provided": bool(verification_code)})
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        logger.warning(f"Verification failed: Email {email} not found")
        await create_audit_log(db, action="EMAIL_VERIFICATION_FAILED_EMAIL_NOT_FOUND", request=request, details={"email": email})
        raise InvalidCredentialsException("Email not found")
    
    if user.is_verified:
        logger.info(f"Account already verified: {email}")
        await create_audit_log(db, action="EMAIL_VERIFICATION_ALREADY_VERIFIED", user_id=user.id, request=request, details={"email": email})
        return {
            "message": "Email already verified",
            "user_id": user.id,
            "email": email,
            "status": user.account_status.value
        }
    
    if not user.verification_code or user.verification_code != verification_code:
        logger.warning(f"Verification failed: Invalid code for {email}")
        await create_audit_log(db, action="EMAIL_VERIFICATION_FAILED_INVALID_CODE", user_id=user.id, request=request, details={"email": email})
        raise VerificationCodeInvalidException()
    
    old_status = user.account_status
    user.is_verified = True
    user.account_status = AccountStatus.ACTIVE
    user.verification_code = None
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    logger.info(f"Email verified: {email}")
    await create_audit_log(db, action="EMAIL_VERIFICATION_SUCCESS", user_id=user.id, request=request, details={"email": email, "old_status": old_status.value, "new_status": user.account_status.value})
    
    return {
        "message": "Email verified successfully",
        "user_id": user.id,
        "email": email,
        "status": user.account_status.value
    }

async def resend_verification(
    db: Session,
    email: str,
    request: Optional[Request] = None
) -> Dict[str, Any]:
    """
    Resend verification email.
    
    Args:
        db: Database session
        email: User's email address
        request: FastAPI request object for audit logging
        
    Returns:
        Dict with resend success message
        
    Raises:
        InvalidCredentialsException: If email not found
    """
    await create_audit_log(db, action="RESEND_VERIFICATION_EMAIL_ATTEMPT", request=request, details={"email": email})
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        logger.warning(f"Resend verification failed: Email {email} not found")
        await create_audit_log(db, action="RESEND_VERIFICATION_FAILED_EMAIL_NOT_FOUND", request=request, details={"email": email})
        raise InvalidCredentialsException("Email not found")
    
    if user.is_verified:
        logger.info(f"Account already verified, no need to resend verification: {email}")
        await create_audit_log(db, action="RESEND_VERIFICATION_ALREADY_VERIFIED", user_id=user.id, request=request, details={"email": email})
        return {
            "message": "Email already verified",
            "user_id": user.id,
            "email": email,
            "status": user.account_status.value
        }
    
    # Generate new verification code
    verification_code = generate_verification_code()
    user.verification_code = verification_code
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    
    try:
        await send_verification_email(email, verification_code)
        logger.info(f"Verification email resent to {email}")
        await create_audit_log(db, action="RESEND_VERIFICATION_EMAIL_SENT_SUCCESS", user_id=user.id, request=request, details={"email": email, "type": "resend_verification"})
    except Exception as e:
        logger.error(f"Failed to resend verification email: {str(e)}")
        await create_audit_log(db, action="RESEND_VERIFICATION_EMAIL_SENT_FAILED", user_id=user.id, request=request, details={"email": email, "error": str(e), "type": "resend_verification"})
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
    request_url: str,
    request: Optional[Request] = None
) -> Dict[str, Any]:
    """
    Initiate password reset process.
    
    Args:
        db: Database session
        email: User's email address
        request_url: Base URL for password reset
        request: FastAPI request object for audit logging IP
        
    Returns:
        Dict with password reset instructions
        
    Raises:
        InvalidCredentialsException: If email not found
        AccountLockedException: If account is locked due to too many reset attempts
    """
    await create_audit_log(db, action="FORGOT_PASSWORD_ATTEMPT", request=request, details={"email": email})
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        logger.warning(f"Password reset failed: Email {email} not found")
        await create_audit_log(db, action="FORGOT_PASSWORD_FAILED_EMAIL_NOT_FOUND", request=request, details={"email": email})
        return {
            "message": "If your email is registered, you will receive password reset instructions"
        }
    
    if user.reset_locked_until and not is_token_expired(user.reset_locked_until):
        logger.warning(f"Password reset failed: Account locked for {email}")
        await create_audit_log(db, action="FORGOT_PASSWORD_FAILED_ACCOUNT_LOCKED", user_id=user.id, request=request, details={"email": email, "locked_until": user.reset_locked_until.isoformat()})
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
    user.updated_at = datetime.now(timezone.utc)
    
    db.commit()
    
    # Build reset URL
    reset_url = f"{request_url}/reset-password?token={reset_token}&email={email}"
    
    # Send password reset email
    try:
        await send_password_reset_email(email, user.full_name, reset_url, token_expires)
        logger.info(f"Password reset email sent to {email}")
        await create_audit_log(db, action="FORGOT_PASSWORD_EMAIL_SENT_SUCCESS", user_id=user.id, request=request, details={"email": email})
        
        return {
            "message": "Password reset instructions sent to your email"
        }
    except Exception as e:
        logger.error(f"Failed to send password reset email: {str(e)}")
        await create_audit_log(db, action="FORGOT_PASSWORD_EMAIL_SENT_FAILED", user_id=user.id, request=request, details={"email": email, "error": str(e)})
        
        return {
            "message": "Password reset initiated. Please check your email for instructions",
            "error": "Email delivery may be delayed"
        }

async def reset_password(
    db: Session,
    email: str,
    reset_token: str,
    new_password: str,
    request: Optional[Request] = None
) -> Dict[str, Any]:
    """
    Reset user's password using reset token.
    
    Args:
        db: Database session
        email: User's email address
        reset_token: Token received via email
        new_password: New password
        request: FastAPI request object for audit logging
        
    Returns:
        Dict with password reset success message
        
    Raises:
        InvalidCredentialsException: If email not found
        InvalidTokenException: If reset token is invalid
        TokenExpiredException: If reset token has expired
        AccountLockedException: If account is locked due to too many reset attempts
    """
    await create_audit_log(db, action="RESET_PASSWORD_ATTEMPT", request=request, details={"email": email, "token_provided": bool(reset_token)})
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        logger.warning(f"Password reset failed: Email {email} not found")
        await create_audit_log(db, action="RESET_PASSWORD_FAILED_EMAIL_NOT_FOUND", request=request, details={"email": email})
        raise InvalidCredentialsException("Invalid email or token")
    
    if user.reset_locked_until and not is_token_expired(user.reset_locked_until):
        logger.warning(f"Password reset failed: Account locked for {email}")
        await create_audit_log(db, action="RESET_PASSWORD_FAILED_ACCOUNT_LOCKED", user_id=user.id, request=request, details={"email": email, "locked_until": user.reset_locked_until.isoformat()})
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
    db: Session,
    request: Optional[Request] = None
) -> Dict[str, Any]:
    """
    Refresh access token.
    Args:
        user: Current user (already identified by the refresh token)
        db: Database session (for potential audit logging or other DB ops)
        request: FastAPI request object for audit logging
    Returns:
        Dict with new access token
    """
    token_data = {
        "id": user.id,
        "email": user.email,
        "role": user.role.value,
        "account_status": user.account_status.value
    }
    access_token = create_access_token(token_data)
    
    logger.info(f"Token refreshed for user {user.id} ({user.email})")
    await create_audit_log(db, action="USER_ACCESS_TOKEN_REFRESHED", user_id=user.id, request=request, details={"email": user.email})
    
    from .schemas import UserResponse
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse.from_orm(user),
        "permissions": [] 
    }

async def create_bootstrap_admin(
    db: Session,
    email: str,
    password: str,
    full_name: str = "System Administrator",
    request: Optional[Request] = None
) -> Dict[str, Any]:
    """
    Create the first admin account from environment variables.
    Args:
        db: Database session
        email: Admin email from environment
        password: Admin password from environment
        full_name: Admin full name (defaults to "System Administrator")
        request: FastAPI request object for audit logging
    Returns:
        Dict with creation success message
    Raises:
        HTTPException: If bootstrap admin already exists or creation fails
    """
    logger.info("Attempting to create bootstrap admin account")
    await create_audit_log(db, action="BOOTSTRAP_ADMIN_CREATION_INITIATED", request=request, details={"email": email})

    existing_admin = db.query(User).filter(User.role == UserRole.ADMIN).first()
    if existing_admin:
        logger.warning("Bootstrap admin creation failed: Admin already exists")
        await create_audit_log(db, action="BOOTSTRAP_ADMIN_CREATION_FAILED_ADMIN_EXISTS", request=request, details={"email": email, "existing_admin_email": existing_admin.email})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bootstrap admin already exists"
        )
    
    try:
        admin = User(
            email=email,
            full_name=full_name,
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
            account_status=AccountStatus.ACTIVE,
            is_verified=True,
            created_by=None, 
            verification_code=None
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
        
        logger.info(f"Bootstrap admin created successfully: {admin.id}")
        await create_audit_log(db, action="BOOTSTRAP_ADMIN_CREATION_SUCCESS", user_id=admin.id, request=request, details={"email": admin.email, "user_id": admin.id})
        
        return {
            "message": "Bootstrap admin created successfully",
            "admin_id": admin.id,
            "email": admin.email,
            "status": "active",
            "created_at": admin.created_at.isoformat()
        }
    except Exception as e:
        logger.error(f"Error creating bootstrap admin: {str(e)}")
        await create_audit_log(db, action="BOOTSTRAP_ADMIN_CREATION_FAILED_EXCEPTION", request=request, details={"email": email, "error": str(e)})
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create bootstrap admin"
        )

async def register_admin(
    db: Session,
    email: EmailStr,
    full_name: str,
    password: str,
    gender: Optional[str] = None,
    address: Optional[str] = None,
    contact: Optional[str] = None,
    profile_image: Optional[str] = None,
    admin_level: int = 1,
    justification: str = "Admin registration request",
    background_tasks: Optional[BackgroundTasks] = None,
    request: Optional[Request] = None
) -> Dict[str, Any]:
    """
    Register a new admin user (self-registration).
    Args:
        db: Database session
        email: Admin's email address
        full_name: Admin's full name
        password: Admin's password
        gender: Admin's gender (optional)
        address: Admin's address (optional)
        contact: Admin's contact number (optional)
        profile_image: URL to admin's profile image (optional, provided by Uploadcare)
        admin_level: Level of admin access (1-5, where 5 is highest)
        justification: Reason for requesting admin access
        background_tasks: FastAPI BackgroundTasks for email sending (currently unused but kept for consistency)
        request: FastAPI request object for audit logging
    Returns:
        Dict with registration success message and approval instructions
    Raises:
        EmailAlreadyExistsException: If email already exists
    """
    logger.info(f"Admin self-registration attempt for email: {email}")
    await create_audit_log(db, action="ADMIN_SELF_REGISTRATION_INITIATED", request=request, details={"email": email, "justification": justification, "admin_level": admin_level})
    
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        logger.warning(f"Admin self-registration failed: Email {email} already registered")
        await create_audit_log(db, action="ADMIN_SELF_REGISTRATION_FAILED_EMAIL_EXISTS", request=request, details={"email": email})
        raise EmailAlreadyExistsException()
    
    user_obj = User(
        email=email,
        full_name=full_name,
        gender=gender,
        address=address,
        contact=contact,
        password_hash=hash_password(password),
        role=UserRole.ADMIN,
        account_status=AccountStatus.DISABLED, # Admins start as DISABLED, requiring approval
        is_verified=True, # Self-registered admins are considered email-verified implicitly
        created_by=None, 
        profile_image=profile_image,
        # Consider storing admin_level and justification in the User model or a related AdminProfile model
    )
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    logger.info(f"Admin account (self-registered, pending approval) created: {user_obj.id}")
    await create_audit_log(db, action="ADMIN_SELF_REGISTRATION_SUCCESS_PENDING_APPROVAL", user_id=user_obj.id, request=request, details={"email": email, "user_id": user_obj.id, "justification": justification})
    
    # TODO: Notify existing active admins about the new pending admin registration.

    return {
        "message": "Admin account created successfully. Your account is pending administrator approval.",
        "user_id": user_obj.id,
        "email": email,
        "admin_level": admin_level,
        "status": "pending_approval",
        "next_step": "wait_for_admin_approval",
        "justification": justification
    }

async def change_password_internal(
    db: Session,
    current_user: User,
    password_data: UserPasswordChangeInternal,
    request: Optional[Request] = None
) -> Dict[str, Any]:
    """
    Allows a currently authenticated user to change their password.

    Args:
        db: Database session.
        current_user: The authenticated user object.
        password_data: Contains current_password and new_password.
        request: FastAPI request object for audit logging.

    Returns:
        A dictionary confirming successful password change.

    Raises:
        InvalidCredentialsException: If the current password is incorrect.
    """
    if not verify_password(password_data.current_password, current_user.password_hash):
        await create_audit_log(
            db=db, 
            action="USER_PASSWORD_CHANGE_FAILED_WRONG_OLD_PASS", 
            user_id=current_user.id,
            request=request,
            details={"reason": "Incorrect current password"}
        )
        raise InvalidCredentialsException(detail="Incorrect current password.")

    current_user.password_hash = hash_password(password_data.new_password)
    current_user.password_changed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(current_user)

    await create_audit_log(
        db=db, 
        action="USER_PASSWORD_CHANGED_SUCCESS", 
        user_id=current_user.id,
        request=request
    )
    logger.info(f"User {current_user.email} successfully changed their password.")
    return {"message": "Password changed successfully."}

async def admin_activate_user_account(
    db: Session,
    user_to_activate_id: int,
    activating_admin: User,
    request: Optional[Request] = None
) -> User:
    """
    Admin activates a user account, typically a doctor or a self-registered admin.
    Changes status from DISABLED to ACTIVE.

    Args:
        db: Database session.
        user_to_activate_id: ID of the user whose account is to be activated.
        activating_admin: The admin performing the action.
        request: FastAPI request object for audit logging.

    Returns:
        The updated user object.

    Raises:
        HTTPException: If user not found, not an admin, or account not in a valid state for activation.
    """
    user_to_activate = db.query(User).filter(User.id == user_to_activate_id).first()

    if not user_to_activate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User to activate not found.")

    if user_to_activate.id == activating_admin.id and user_to_activate.role == UserRole.ADMIN:
        # This check might be more relevant in the router for self-registration approval flow
        pass # Allowing an admin to activate their own account if it was somehow disabled after self-reg.

    allowed_initial_statuses = [AccountStatus.DISABLED]
    action_prefix = ""

    if user_to_activate.role == UserRole.DOCTOR:
        action_prefix = "DOCTOR_ACCOUNT"
        if user_to_activate.account_status not in allowed_initial_statuses:
            await create_audit_log(
                db=db, 
                action=f"{action_prefix}_ACTIVATION_FAILED_INVALID_STATUS", 
                user_id=activating_admin.id,
                request=request,
                details={"target_user_id": user_to_activate_id, "current_status": user_to_activate.account_status.value, "reason": "Doctor account not in DISABLED state."}
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Doctor account is not in a disabled state for activation. Current status: {user_to_activate.account_status.value}")
    elif user_to_activate.role == UserRole.ADMIN:
        action_prefix = "ADMIN_ACCOUNT"
        # For admin self-registration flow, they start as DISABLED
        if user_to_activate.account_status not in allowed_initial_statuses:
            await create_audit_log(
                db=db, 
                action=f"{action_prefix}_ACTIVATION_FAILED_INVALID_STATUS", 
                user_id=activating_admin.id,
                request=request,
                details={"target_user_id": user_to_activate_id, "current_status": user_to_activate.account_status.value, "reason": "Admin account not in DISABLED state for this activation path."}
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Admin account is not in a disabled state for activation. Current status: {user_to_activate.account_status.value}")
    else:
        # Generic activation for other roles if needed, though spec focuses on Doctor/Admin approval
        action_prefix = "USER_ACCOUNT"
        # If we want to prevent activating other roles this way:
        # raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This activation path is for Doctors or Admins only.")
        if user_to_activate.account_status not in allowed_initial_statuses:
             await create_audit_log(
                db=db, 
                action=f"{action_prefix}_ACTIVATION_FAILED_INVALID_STATUS", 
                user_id=activating_admin.id,
                request=request,
                details={"target_user_id": user_to_activate_id, "current_status": user_to_activate.account_status.value, "reason": "User account not in DISABLED state."}
            )
             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"User account is not in a disabled state for activation. Current status: {user_to_activate.account_status.value}")


    old_status = user_to_activate.account_status
    user_to_activate.account_status = AccountStatus.ACTIVE
    user_to_activate.updated_at = datetime.now(timezone.utc)
    # For doctors, their is_verified might be true already, but ensure it is.
    if user_to_activate.role == UserRole.DOCTOR:
        user_to_activate.is_verified = True 

    db.commit()
    db.refresh(user_to_activate)

    await create_audit_log(
        db=db, 
        action=f"{action_prefix}_ACTIVATED_BY_ADMIN", 
        user_id=activating_admin.id,
        request=request,
        details={"target_user_id": user_to_activate_id, "email": user_to_activate.email, "old_status": old_status.value, "new_status": AccountStatus.ACTIVE.value}
    )
    logger.info(f"{action_prefix} {user_to_activate.email} (ID: {user_to_activate_id}) activated by admin {activating_admin.email} (ID: {activating_admin.id}).")
    
    # TODO: Send notification email to the activated user

    return user_to_activate

async def admin_deactivate_user_account(
    db: Session,
    user_to_deactivate_id: int,
    deactivating_admin: User,
    request: Optional[Request] = None
) -> User:
    """
    Admin deactivates a user account.
    Changes status to DEACTIVATED.

    Args:
        db: Database session.
        user_to_deactivate_id: ID of the user whose account is to be deactivated.
        deactivating_admin: The admin performing the action.
        request: FastAPI request object for audit logging.

    Returns:
        The updated user object.

    Raises:
        HTTPException: If user not found, or trying to deactivate self (if not allowed).
    """
    user_to_deactivate = db.query(User).filter(User.id == user_to_deactivate_id).first()

    if not user_to_deactivate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User to deactivate not found.")

    if user_to_deactivate.id == deactivating_admin.id:
        # Potentially prevent admin from deactivating their own account, or require another admin
        await create_audit_log(
            db=db, 
            action="USER_DEACTIVATION_FAILED_SELF", 
            user_id=deactivating_admin.id,
            request=request,
            details={"target_user_id": user_to_deactivate_id, "reason": "Admin tried to deactivate self"}
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Administrators cannot deactivate their own accounts through this endpoint.")

    if user_to_deactivate.account_status == AccountStatus.DEACTIVATED:
        logger.info(f"User {user_to_deactivate.email} (ID: {user_to_deactivate_id}) is already deactivated.")
        return user_to_deactivate # Or raise an exception if preferred

    old_status = user_to_deactivate.account_status
    user_to_deactivate.account_status = AccountStatus.DEACTIVATED
    user_to_deactivate.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(user_to_deactivate)

    await create_audit_log(
        db=db, 
        action="USER_DEACTIVATED_BY_ADMIN", 
        user_id=deactivating_admin.id,
        request=request,
        details={"target_user_id": user_to_deactivate_id, "email": user_to_deactivate.email, "old_status": old_status.value, "new_status": AccountStatus.DEACTIVATED.value}
    )
    logger.info(f"User {user_to_deactivate.email} (ID: {user_to_deactivate_id}) deactivated by admin {deactivating_admin.email} (ID: {deactivating_admin.id}).")
    
    # TODO: Send notification email to the deactivated user

    return user_to_deactivate

async def admin_set_doctor_onhire_status(
    db: Session,
    doctor_user_id: int, # This should be the User ID of the doctor
    new_onhire_status: DoctorStatus,
    admin_user: User,
    request: Optional[Request] = None
) -> Doctor:
    """
    Admin sets the on-hire (availability) status of a doctor.

    Args:
        db: Database session.
        doctor_user_id: The User ID of the doctor whose status is to be updated.
        new_onhire_status: The new DoctorStatus to set.
        admin_user: The admin performing the action.
        request: FastAPI request object for audit logging.

    Returns:
        The updated Doctor object.

    Raises:
        HTTPException: If the doctor or their user record is not found.
    """
    # Find the User record for the doctor first
    doctor_user = db.query(User).filter(User.id == doctor_user_id, User.role == UserRole.DOCTOR).first()
    if not doctor_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Doctor (User ID: {doctor_user_id}) not found.")

    # Then find the associated Doctor profile
    doctor_profile = db.query(Doctor).filter(Doctor.user_id == doctor_user.id).first()
    if not doctor_profile:
        # This case should ideally not happen if data integrity is maintained
        # (i.e., every DOCTOR user has a corresponding Doctor profile)
        await create_audit_log(
            db=db,
            action="DOCTOR_ONHIRE_STATUS_FAILED_NO_PROFILE",
            user_id=admin_user.id,
            request=request,
            details={"target_user_id": doctor_user_id, "reason": "Doctor profile not found for this user."}
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Doctor profile for User ID {doctor_user_id} not found.")

    old_status = doctor_profile.availability_status
    doctor_profile.availability_status = new_onhire_status
    doctor_profile.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(doctor_profile)

    await create_audit_log(
        db=db,
        action="DOCTOR_ONHIRE_STATUS_UPDATED",
        user_id=admin_user.id,
        request=request,
        details={
            "target_doctor_user_id": doctor_user_id,
            "doctor_email": doctor_user.email,
            "old_onhire_status": old_status.value if old_status else None,
            "new_onhire_status": new_onhire_status.value
        }
    )
    logger.info(f"Doctor {doctor_user.email} (User ID: {doctor_user_id}) on-hire status changed to {new_onhire_status.value} by admin {admin_user.email}.")
    return doctor_profile

async def staff_set_password_first_login(
    db: Session,
    staff_user: User, # Assumes staff_user is already authenticated (e.g. with temp password)
    password_data: StaffFirstLoginPasswordSet,
    request: Optional[Request] = None
) -> User:
    """
    Allows a staff member to set their password upon first login and activates their account.
    Changes account status from PENDING_ACTIVATION to ACTIVE.

    Args:
        db: Database session.
        staff_user: The authenticated staff user (identified via temporary credentials).
        password_data: Contains new_password and confirm_password.
        request: FastAPI request object for audit logging.

    Returns:
        The updated staff user object.

    Raises:
        HTTPException: If passwords don't match, account not PENDING_ACTIVATION, or not a staff role.
    """
    if staff_user.role != UserRole.STAFF:
        await create_audit_log(
            db=db,
            action="STAFF_FIRST_LOGIN_PW_SET_FAILED_NOT_STAFF",
            user_id=staff_user.id,
            request=request,
            details={"reason": "User is not a staff member."}
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Action only allowed for staff members.")

    if staff_user.account_status != AccountStatus.PENDING_ACTIVATION:
        await create_audit_log(
            db=db,
            action="STAFF_FIRST_LOGIN_PW_SET_FAILED_NOT_PENDING_ACTIVATION",
            user_id=staff_user.id,
            request=request,
            details={"current_status": staff_user.account_status.value, "reason": "Account not in PENDING_ACTIVATION state."}
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account is not pending first login activation.")

    if password_data.new_password != password_data.confirm_password:
        # No audit log needed here as it's a simple validation error, not a security event.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New passwords do not match.")

    staff_user.password_hash = hash_password(password_data.new_password)
    staff_user.account_status = AccountStatus.ACTIVE
    staff_user.password_changed_at = datetime.now(timezone.utc)
    staff_user.updated_at = datetime.now(timezone.utc)
    # Potentially clear any temporary token/flag used for first login if applicable

    db.commit()
    db.refresh(staff_user)

    await create_audit_log(
        db=db,
        action="STAFF_ACCOUNT_ACTIVATED_FIRST_LOGIN_PW_SET",
        user_id=staff_user.id,
        request=request,
        details={"email": staff_user.email, "new_status": AccountStatus.ACTIVE.value}
    )
    logger.info(f"Staff member {staff_user.email} (ID: {staff_user.id}) activated account and set password.")
    
    # TODO: Send a confirmation email that password has been set and account is active.

    return staff_user

async def get_bootstrap_admin_status(db: Session) -> Dict[str, Any]:
    """
    Checks if a bootstrap admin account exists in the system.

    Args:
        db: Database session.

    Returns:
        A dictionary indicating if the bootstrap admin exists and a message.
    """
    existing_admin = db.query(User).filter(User.role == UserRole.ADMIN, User.created_by == None).first()
    if existing_admin:
        return {"bootstrap_admin_exists": True, "message": "Bootstrap admin account is configured."}
    else:
        return {"bootstrap_admin_exists": False, "message": "Bootstrap admin account not found. System may need initialization."}

async def check_general_activation_token_status(db: Session, token: str) -> Dict[str, Any]:
    """
    Checks the status of a generic activation token.
    This is a placeholder for a more specific token verification logic if needed.
    For example, it could check against a table of one-time activation tokens.

    Args:
        db: Database session.
        token: The activation token to check.

    Returns:
        A dictionary indicating if the token is valid and a message.
    """
    # This is a simplified example. In a real system, you'd look up the token
    # in a dedicated table, check its expiry, type, associated user, etc.
    # For now, we'll assume a token is valid if it's not empty and has a certain length.
    # This function needs to be fleshed out based on how activation tokens are generated and stored.
    
    # Example: Check against user verification codes (if that's the intent for this generic endpoint)
    user_with_token = db.query(User).filter(User.verification_code == token).first()
    if user_with_token:
        if user_with_token.account_status == AccountStatus.PENDING_VERIFICATION:
            return {"is_valid": True, "message": "Token is valid and associated with a pending verification.", "email": user_with_token.email}
        elif user_with_token.is_verified:
            return {"is_valid": False, "message": "Token is for an already verified account.", "email": user_with_token.email}
        else:
            return {"is_valid": False, "message": "Token found but account status is not PENDING_VERIFICATION.", "email": user_with_token.email}

    # Example: Check against password reset tokens
    user_with_reset_token = db.query(User).filter(verify_token_hash(token, User.reset_token_hash)).first() 
    # ^ This verify_token_hash needs to be callable directly or logic adapted
    # For simplicity, let's assume direct check or a different mechanism for reset tokens as they are handled by reset_password flow.

    # Placeholder logic for a generic token:
    if token and len(token) > 10: # Arbitrary check
        # In a real system, you would query a specific table for this token.
        # For now, we don't have a generic activation token store.
        logger.warning(f"check_general_activation_token_status called with token: {token}, but no generic token store exists.")
        # This endpoint might be intended for email verification tokens before user identifies their email.
        # Let's assume it's for pre-email-submission verification code check (though unlikely flow)
        return {"is_valid": False, "message": "Generic token validation not fully implemented. Token appears structurally plausible but cannot be verified further without a dedicated store or clear use case."}
    
    return {"is_valid": False, "message": "Invalid or unknown activation token."}

async def get_audit_logs_service(
    db: Session,
    user_id_filter: Optional[int] = None,
    limit: int = 100,
    offset: int = 0 
) -> List[AuditLogResponse]:
    """
    Retrieves audit logs, optionally filtered by user_id.

    Args:
        db: Database session.
        user_id_filter: Optional user ID to filter logs for.
        limit: Maximum number of logs to return.
        offset: Number of logs to skip (for pagination).

    Returns:
        A list of AuditLogResponse objects.
    """
    query = db.query(AuditLog).order_by(AuditLog.timestamp.desc())

    if user_id_filter:
        query = query.filter(AuditLog.user_id == user_id_filter)
    
    audit_log_entries = query.limit(limit).offset(offset).all()
    
    # Enrich with username
    response_logs = []
    for log_entry in audit_log_entries:
        username = None
        if log_entry.user_id and log_entry.user:
            username = log_entry.user.email # Or log_entry.user.full_name
        response_logs.append(
            AuditLogResponse(
                id=log_entry.id,
                user_id=log_entry.user_id,
                username=username,
                action=log_entry.action,
                details=log_entry.details,
                ip_address=log_entry.ip_address,
                timestamp=log_entry.timestamp
            )
        )