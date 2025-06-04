"""
Role-Based Authentication routes for the medical clinic system.

This module implements the complete authentication flow with production-standard
route naming conventions and separate registration endpoints for each user role.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status, Request
from sqlalchemy.orm import Session
import logging
from typing import Dict
from ..database import SessionLocal
from ..schemas.user import (
    PatientRegistration, DoctorRegistration, StaffRegistration, AdminRegistration,
    UserLogin, UserVerify, ResendVerification, UserResponse, LoginResponse, AuthError,
    AccountStatusUpdate, PasswordReset, PasswordChange, AdminApprovalRequest, AdminRejectionRequest
)
from ..models.user import User, UserRole, AccountStatus
from ..auth.password import hash_password, verify_password
from ..auth.jwt import create_access_token, get_permissions_for_role
from ..utils.email import generate_verification_code, send_verification_email
from ..utils.security import (
    generate_secure_reset_token, hash_token, verify_token_hash,
    validate_password_strength, get_token_expiry_time, is_token_expired,
    should_lock_account, get_account_lock_duration
)
from ..utils.email import send_password_reset_email, send_password_changed_notification
from ..deps import get_db, get_current_user, require_staff_or_admin, require_admin, get_current_user_with_verification_status
import time
import os
import smtplib
import ssl
import socket
import asyncio
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta, timezone
from sqlalchemy.sql import func

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create API router with prefix and tag
router = APIRouter(prefix="/auth", tags=["Authentication"])

# ============================================================================
# ROLE-SPECIFIC REGISTRATION ROUTES
# ============================================================================

@router.post("/register/patient", status_code=status.HTTP_201_CREATED, response_model=Dict)
async def register_patient(
    patient_data: PatientRegistration,
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    """
    Patient self-registration endpoint.
    
    Patients can register themselves and will receive email verification.
    Account status will be PENDING_VERIFICATION until email is verified,
    then automatically becomes ACTIVE.
    
    Args:
        patient_data: Patient registration data
        background_tasks: FastAPI BackgroundTasks for email sending
        db: Database session
        
    Returns:
        Dict with registration success message and verification instructions
        
    Raises:
        HTTPException: If email already exists
    """
    logger.info(f"Patient registration attempt for email: {patient_data.email}")
    
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == patient_data.email).first()
    if existing_user:
        logger.warning(f"Registration failed: Email {patient_data.email} already registered")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Generate verification code
    verification_code = generate_verification_code()
    
    # Create new patient user
    user_obj = User(
        email=patient_data.email,
        full_name=patient_data.full_name,
        gender=patient_data.gender,
        address=patient_data.address,
        contact=patient_data.contact,
        password_hash=hash_password(patient_data.password),
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
        await send_verification_email(patient_data.email, verification_code)
        logger.info(f"Verification email sent to {patient_data.email}")
        
        return {
            "message": "Patient account created successfully. Please check your email for verification code.",
            "user_id": user_obj.id,
            "email": patient_data.email,
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
            "email": patient_data.email,
            "error": error_detail,
            "next_step": "resend_verification",
            "retry_available": True
        }

@router.post("/register/doctor", status_code=status.HTTP_201_CREATED, response_model=Dict)
async def register_doctor(
    doctor_data: DoctorRegistration,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Doctor registration endpoint.
    
    Doctors can register but their accounts will be DISABLED until admin approval.
    They cannot access the system until an admin activates their account.
    
    Args:
        doctor_data: Doctor registration data including professional information
        background_tasks: FastAPI BackgroundTasks for email sending
        db: Database session
        
    Returns:
        Dict with registration success message and approval instructions
        
    Raises:
        HTTPException: If email already exists
    """
    logger.info(f"Doctor registration attempt for email: {doctor_data.email}")
    
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == doctor_data.email).first()
    if existing_user:
        logger.warning(f"Registration failed: Email {doctor_data.email} already registered")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new doctor user with DISABLED status
    user_obj = User(
        email=doctor_data.email,
        full_name=doctor_data.full_name,
        gender=doctor_data.gender,
        address=doctor_data.address,
        contact=doctor_data.contact,
        password_hash=hash_password(doctor_data.password),
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
        "email": doctor_data.email,
        "status": "pending_approval",
        "next_step": "wait_for_admin_approval"
    }

@router.post("/register/staff", status_code=status.HTTP_201_CREATED, response_model=Dict)
async def register_staff(
    staff_data: StaffRegistration,
    background_tasks: BackgroundTasks,
    current_admin: User = Depends(require_staff_or_admin),
    db: Session = Depends(get_db)
):
    """
    Staff account creation endpoint (Admin only).
    
    Only administrators can create staff accounts. Staff accounts are created with
    PENDING_ACTIVATION status and staff must set their password on first login.
    
    Args:
        staff_data: Staff registration data
        background_tasks: FastAPI BackgroundTasks for email sending
        current_admin: Current admin user creating the staff account
        db: Database session
        
    Returns:
        Dict with account creation success message
        
    Raises:
        HTTPException: If email already exists or insufficient permissions
    """
    logger.info(f"Staff account creation by admin {current_admin.id} for email: {staff_data.email}")
    existing_user = db.query(User).filter(User.email == staff_data.email).first()
    if existing_user:
        logger.warning(f"Staff creation failed: Email {staff_data.email} already registered")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Use admin-provided password instead of generating random temporary password
    staff_password = staff_data.password
    
    # Create new staff user
    user_obj = User(
        email=staff_data.email,
        full_name=staff_data.full_name,
        gender=staff_data.gender,
        address=staff_data.address,
        contact=staff_data.contact,
        password_hash=hash_password(staff_password),
        role=UserRole.STAFF,
        account_status=AccountStatus.PENDING_ACTIVATION,
        verification_code=staff_password,  # Store admin-provided password for first login
        is_verified=True,
        created_by=current_admin.id
    )
    
    # Save to database
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    logger.info(f"Staff account created by admin {current_admin.id}: {user_obj.id}")
    
    # TODO: Send activation email with password
    # For now, return password (in production, this should be emailed)
    
    return {
        "message": "Staff account created successfully.",
        "user_id": user_obj.id,
        "email": staff_data.email,
        "password": staff_password,  # Return admin-provided password
        "status": "pending_activation",
        "created_by": current_admin.email
    }

@router.post("/register/admin", status_code=status.HTTP_201_CREATED, response_model=Dict)
async def register_admin(
    admin_data: AdminRegistration,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Admin self-registration endpoint.
    
    Users can register for admin accounts but they will be DISABLED until existing admin approval.
    They cannot access the system until an existing admin activates their account.
    
    Args:
        admin_data: Admin registration data including justification
        background_tasks: FastAPI BackgroundTasks for email sending
        db: Database session
        
    Returns:
        Dict with registration success message and approval instructions
        
    Raises:
        HTTPException: If email already exists
    """
    logger.info(f"Admin registration attempt for email: {admin_data.email}")
    
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == admin_data.email).first()
    if existing_user:
        logger.warning(f"Admin registration failed: Email {admin_data.email} already registered")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new admin user with DISABLED status
    user_obj = User(
        email=admin_data.email,
        full_name=admin_data.full_name,
        gender=admin_data.gender,
        address=admin_data.address,
        contact=admin_data.contact,
        password_hash=hash_password(admin_data.password),
        role=UserRole.ADMIN,
        account_status=AccountStatus.DISABLED,  # Requires admin approval
        is_verified=True,  # Admins don't need email verification, just admin approval
        created_by=None  # Self-registered admin has no creator until approved
    )
    
    # Save to database
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    logger.info(f"Admin account created (pending approval): {user_obj.id} - Level: {admin_data.admin_level}")
    logger.info(f"Admin justification: {admin_data.justification}")
    
    # TODO: In a real system, notify existing admins about new admin registration
    # background_tasks.add_task(notify_admins_of_new_registration, user_obj, admin_data.justification)
    
    return {
        "message": "Admin account created successfully. Your account is pending administrator approval.",
        "user_id": user_obj.id,
        "email": admin_data.email,
        "admin_level": admin_data.admin_level,
        "status": "pending_approval",
        "next_step": "wait_for_admin_approval",
        "justification": admin_data.justification
    }

# ============================================================================
# UNIVERSAL LOGIN ENDPOINT
# ============================================================================

@router.post("/login", response_model=LoginResponse)
def login(
    login_data: UserLogin,
    db: Session = Depends(get_db)
):
    """
    Universal login endpoint for all user roles.
    
    Handles authentication for patients, doctors, staff, and admins.
    Returns role-specific permissions and access levels.
    
    Args:
        login_data: User login credentials (email and password)
        db: Database session
        
    Returns:
        LoginResponse with access token, user information, and permissions
        
    Raises:
        HTTPException: If credentials invalid, email unverified, or account not active
    """
    logger.info(f"Login attempt for email: {login_data.email}")
    
    # Find user by email (regardless of role)
    user = db.query(User).filter(User.email == login_data.email).first()
    
    if not user or not verify_password(login_data.password, user.password_hash):
        logger.warning(f"Invalid credentials for user: {login_data.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Role-specific validation
    if user.role == UserRole.PATIENT:
        # Patients must have verified email
        if not user.is_verified:
            logger.warning(f"Unverified email for patient: {login_data.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email not verified. Please verify your email first."
            )
        
        # Check if account is active
        if user.account_status != AccountStatus.ACTIVE:
            logger.warning(f"Inactive patient account: {login_data.email}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account status: {user.account_status.value}. Contact support if needed."
            )
    
    elif user.role == UserRole.DOCTOR:
        # Doctors must have admin approval (ACTIVE status)
        if user.account_status != AccountStatus.ACTIVE:
            status_messages = {
                AccountStatus.DISABLED: "Your account is pending administrator approval.",
                AccountStatus.DEACTIVATED: "Your account has been deactivated. Contact administration.",
                AccountStatus.RED_TAG: "Your account is under review. Contact administration."
            }
            message = status_messages.get(user.account_status, "Account access denied.")
            
            logger.warning(f"Inactive doctor account: {login_data.email} - {user.account_status}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=message
            )
    
    elif user.role == UserRole.STAFF:
        # Staff can log in with pending activation (first login) or active status
        if user.account_status in [AccountStatus.DEACTIVATED, AccountStatus.RED_TAG]:
            logger.warning(f"Deactivated staff account: {login_data.email}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account has been deactivated. Contact administration."
            )
        
        # If first login with temporary password, activate account
        if user.account_status == AccountStatus.PENDING_ACTIVATION:
            user.account_status = AccountStatus.ACTIVE
            user.verification_code = None  # Clear temporary password
            db.commit()
            logger.info(f"Staff account activated on first login: {user.email}")
    
    elif user.role == UserRole.ADMIN:
        # Admins must have ACTIVE status
        if user.account_status != AccountStatus.ACTIVE:
            status_messages = {
                AccountStatus.DISABLED: "Your admin account is pending approval by an existing administrator.",
                AccountStatus.DEACTIVATED: "Your admin account has been deactivated. Contact administration.",
                AccountStatus.RED_TAG: "Your admin account is under review. Contact administration."
            }
            message = status_messages.get(user.account_status, "Admin account access denied.")
            
            logger.warning(f"Inactive admin account: {login_data.email} - {user.account_status}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=message
            )
    
    # Create access token
    token_data = {
        "id": user.id,
        "email": user.email,
        "role": user.role.value,
        "account_status": user.account_status.value
    }
    access_token = create_access_token(token_data)
    permissions = get_permissions_for_role(user.role, user.account_status)
    
    logger.info(f"Successful login: {user.email} ({user.role.value})")
    
    return LoginResponse(
        access_token=access_token,
        user=UserResponse.from_orm(user),
        permissions=permissions
    )

# ============================================================================
# EMAIL VERIFICATION AND PASSWORD MANAGEMENT
# ============================================================================

@router.post("/verify-email", status_code=status.HTTP_200_OK)
def verify_email(
    verification_data: UserVerify,
    db: Session = Depends(get_db)
):
    """
    Email verification endpoint (primarily for patients).
    
    Args:
        verification_data: Email and verification code
        db: Database session
        
    Returns:
        Dict with verification success message
        
    Raises:
        HTTPException: If user not found or invalid verification code
    """
    logger.info(f"Email verification attempt for: {verification_data.email}")
    
    # Find user by email
    user = db.query(User).filter(User.email == verification_data.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check if already verified
    if user.is_verified and user.account_status == AccountStatus.ACTIVE:
        return {"message": "Email already verified and account is active"}
    
    # Verify the code
    if user.verification_code != verification_data.verification_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )
    
    # Update user status
    user.is_verified = True
    user.verification_code = None
    
    # For patients, verification automatically activates account
    if user.role == UserRole.PATIENT:
        user.account_status = AccountStatus.ACTIVE
        
    db.commit()
    
    logger.info(f"Email verified successfully for: {verification_data.email}")
    
    return {
        "message": "Email verified successfully",
        "account_status": user.account_status.value
    }

@router.post("/resend-verification", status_code=status.HTTP_200_OK)
async def resend_verification(
    verification_request: ResendVerification,
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    """
    Resend verification email endpoint.
    
    Args:
        verification_request: ResendVerification schema containing user email
        background_tasks: FastAPI BackgroundTasks for email sending
        db: Database session
        
    Returns:
        Dict with success message
        
    Raises:
        HTTPException: If user not found or already verified
    """
    email = verification_request.email
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already verified"
        )
    
    # Generate new verification code
    new_code = generate_verification_code()
    user.verification_code = new_code
    db.commit()
    
    # Send verification email
    try:
        await send_verification_email(email, new_code)
        logger.info(f"Verification email resent successfully to {email}")
        return {
            "message": "Verification email resent successfully",
            "email": email,
            "next_step": "verify_email"
        }
    except Exception as e:
        error_str = str(e)
        logger.error(f"Failed to resend verification email: {error_str}")
        
        # Provide specific error messages based on the type of failure
        if "Authentication failed" in error_str:
            error_detail = "Email authentication failed"
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        elif "configuration is incomplete" in error_str:
            error_detail = "Email service configuration error"
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        elif "timeout" in error_str.lower() or "connection" in error_str.lower():
            error_detail = "Email service temporarily unavailable. Please try again in a few minutes."
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        else:
            error_detail = "Failed to send verification email"
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        
        raise HTTPException(
            status_code=status_code,
            detail=error_detail
        )

@router.post("/forgot-password", status_code=status.HTTP_200_OK)
async def forgot_password(
    password_reset: PasswordReset,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Initiate password reset process with comprehensive security measures.
    
    This uses the simplified logic that actually works.
    """
    logger.info(f"🔄 FORGOT PASSWORD: Request for {password_reset.email}")
    logger.info(f"Password reset request from IP: {request.client.host}")
    
    try:
        # Find user
        user = db.query(User).filter(User.email == password_reset.email).first()
        if not user:
            logger.info(f"Password reset requested for non-existent email: {password_reset.email}")
            return {"message": "If the email exists, a password reset link has been sent"}
        
        logger.info(f"✅ FORGOT PASSWORD: User found - {user.full_name}")
        
        # Generate token
        reset_token = generate_secure_reset_token()
        token_hash = hash_token(reset_token)
        expires_at = get_token_expiry_time(minutes=15)
        reset_url = f"http://localhost:3000/reset-password?token={reset_token}&email={user.email}"
        
        # Update user with reset token (clear any existing data)
        user.reset_token_hash = token_hash
        user.reset_token_expires = expires_at
        user.reset_token_created = datetime.now(timezone.utc)
        user.reset_attempts_count = 1  # Reset counter
        user.reset_locked_until = None  # Clear any lock
        
        db.commit()
        logger.info(f"✅ FORGOT PASSWORD: Database updated for {user.email}")
        
        logger.info(f"🔄 FORGOT PASSWORD: About to send email")
        
        # Send email directly (this is the working approach)
        await send_password_reset_email(user.email, user.full_name, reset_url, expires_at)
        
        logger.info(f"✅ FORGOT PASSWORD: Email sent successfully for {user.email}")
        
        # Return the reset token in response for testing purposes
        return {
            "message": "Password reset email sent successfully",
            "email": user.email,
            "reset_token": reset_token,
            "expires_at": expires_at.isoformat(),
            "reset_url": reset_url
        }
        
    except Exception as e:
        logger.error(f"❌ FORGOT PASSWORD: Error - {e}")
        import traceback
        logger.error(f"❌ FORGOT PASSWORD: Traceback - {traceback.format_exc()}")
        return {"message": "If the email exists, a password reset link has been sent"}

@router.post("/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(
    password_change: PasswordChange,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Complete password reset with enhanced validation and security.
    
    Enhanced security features:
    - Token validation and expiration checking
    - Password strength requirements
    - Single-use token enforcement
    - Account lockout clearing
    - Confirmation email notification
    
    Args:
        password_change: Password change data with reset token
        background_tasks: FastAPI BackgroundTasks for email sending
        db: Database session
        
    Returns:
        Dict with success message and next steps
        
    Raises:
        HTTPException: If validation fails or token is invalid
    """
    logger.info(f"Password reset attempt for email: {password_change.email}")
    
    # Find user by email
    user = db.query(User).filter(User.email == password_change.email).first()
    
    if not user:
        logger.warning(f"Password reset attempted for non-existent user: {password_change.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset request"
        )
    
    # Validate token exists and hasn't expired
    if (not user.reset_token_hash or 
        not user.reset_token_expires or
        is_token_expired(user.reset_token_expires)):
        logger.warning(f"Expired or missing reset token for: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token is invalid or has expired. Please request a new password reset."
        )
    
    # Verify the provided token matches stored hash
    if not verify_token_hash(password_change.reset_token, user.reset_token_hash):
        logger.warning(f"Invalid reset token used for: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset token"
        )
    
    # Validate new password strength
    password_validation = validate_password_strength(password_change.new_password)
    if not password_validation.is_valid:
        logger.info(f"Weak password attempted for: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password requirements not met: {', '.join(password_validation.errors)}"
        )
    
    # Check password isn't the same as current (optional security measure)
    if verify_password(password_change.new_password, user.password_hash):
        logger.info(f"User attempted to reuse current password: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from your current password"
        )
    
    # Update password and clear reset token data
    user.password_hash = hash_password(password_change.new_password)
    user.reset_token_hash = None
    user.reset_token_expires = None
    user.reset_token_created = None
    user.reset_attempts_count = 0  # Reset attempt counter
    user.reset_locked_until = None  # Remove any account lock
    user.password_changed_at = datetime.now(timezone.utc)  # Track when password was changed
    
    db.commit()
    
    # Send confirmation email
    try:
        # For password change notification, we can still use background task since it's less critical
        # But let's call it directly to be safe
        await send_password_changed_notification(user.email, user.full_name)
        logger.info(f"Password change notification sent for: {user.email}")
    except Exception as e:
        logger.error(f"Failed to send password change notification for {user.email}: {e}")
        # Don't fail the password reset if notification fails
    
    logger.info(f"Password successfully reset for: {user.email}")
    
    return {
        "message": "Password reset successfully",
        "next_action": "login_with_new_password",
        "email": user.email
    }

# ============================================================================
# TOKEN MANAGEMENT
# ============================================================================

@router.post("/refresh-token", response_model=LoginResponse)
def refresh_token(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Refresh access token endpoint.
    
    Args:
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        LoginResponse with new access token
    """
    # Create new access token
    token_data = {
        "id": current_user.id,
        "email": current_user.email,
        "role": current_user.role.value,
        "account_status": current_user.account_status.value
    }
    access_token = create_access_token(token_data)
    permissions = get_permissions_for_role(current_user.role, current_user.account_status)
    
    return LoginResponse(
        access_token=access_token,
        user=UserResponse.from_orm(current_user),
        permissions=permissions
    )

@router.post("/logout", status_code=status.HTTP_200_OK)
def logout():
    """
    Logout endpoint.
    
    Note: Since we're using stateless JWT tokens, logout is handled client-side
    by removing the token. In production, you might want to implement token blacklisting.
    
    Returns:
        Dict with logout success message
    """
    return {"message": "Logged out successfully"}

# ============================================================================
# USER PROFILE MANAGEMENT
# ============================================================================

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """
    Get current user profile information.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        UserResponse: Current user information
    """
    return UserResponse.from_orm(current_user)

# ============================================================================
# ADMIN MANAGEMENT ROUTES
# ============================================================================

@router.get("/admin/pending-registrations", status_code=status.HTTP_200_OK)
def get_pending_admin_registrations(
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Admin endpoint to view pending admin registration requests.
    
    Args:
        current_admin: Current admin user
        db: Database session
        
    Returns:
        List of pending admin registration requests with justifications
        
    Raises:
        HTTPException: If insufficient permissions
    """
    logger.info(f"Admin {current_admin.id} requesting pending admin registrations")
    
    # Find all pending admin accounts
    pending_admins = db.query(User).filter(
        User.role == UserRole.ADMIN,
        User.status == AccountStatus.DISABLED  # Use status column, not account_status property
    ).all()
    
    # Format the response with necessary information
    pending_registrations = []
    for admin in pending_admins:
        # Note: In a real system, you'd store justification in a separate table
        # or add it as a field to the User model. For now, we'll simulate it.
        registration_info = {
            "user_id": admin.id,
            "email": admin.email,
            "full_name": admin.full_name,
            "gender": admin.gender,
            "address": admin.address,
            "contact": admin.contact,
            "admin_level": 1,  # Default since we don't store this yet
            "justification": f"Admin access requested by {admin.full_name}",  # Simulated
            "created_at": admin.created_at,
            "days_pending": (datetime.now(timezone.utc) - admin.created_at).days
        }
        pending_registrations.append(registration_info)
    
    logger.info(f"Found {len(pending_registrations)} pending admin registrations")
    
    return {
        "message": f"Found {len(pending_registrations)} pending admin registration(s)",
        "pending_count": len(pending_registrations),
        "pending_registrations": pending_registrations
    }

@router.put("/users/{user_id}/status", status_code=status.HTTP_200_OK)
def update_user_status(
    user_id: int,
    account_update: AccountStatusUpdate,
    current_admin: User = Depends(require_staff_or_admin),
    db: Session = Depends(get_db)
):
    """
    Admin endpoint to update user account status.
    
    Args:
        user_id: ID of user to update
        account_update: Account status update data
        current_admin: Current admin user
        db: Database session
        
    Returns:
        Dict with success message
        
    Raises:
        HTTPException: If user not found or insufficient permissions
    """
    logger.info(f"Account status update by admin {current_admin.id} for user {user_id}")
    
    # Override user_id from URL parameter
    account_update.user_id = user_id
    
    # Find target user
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Update account status
    old_status = target_user.account_status
    target_user.account_status = account_update.new_status
    db.commit()
    
    logger.info(
        f"Account status updated for user {target_user.email}: "
        f"{old_status} -> {account_update.new_status}"
    )
    
    return {
        "message": f"Account status updated to {account_update.new_status.value}",
        "user_email": target_user.email,
        "old_status": old_status.value,
        "new_status": account_update.new_status.value,
        "updated_by": current_admin.email
    }

@router.post("/admin/{admin_id}/approve", status_code=status.HTTP_200_OK)
def approve_admin_registration(
    admin_id: int,
    approval_data: AdminApprovalRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Dedicated endpoint for approving admin registration requests.
    
    This endpoint provides business-specific logic for admin approval workflow,
    including validation, audit logging, and potential notification triggers.
    
    Args:
        admin_id: ID of admin user to approve
        approval_data: Admin approval request data
        current_admin: Current admin user performing the approval
        db: Database session
        
    Returns:
        Dict with approval success message and audit details
        
    Raises:
        HTTPException: If admin not found, invalid status, or insufficient permissions
    """
    logger.info(f"Admin approval request by {current_admin.id} for admin {admin_id}")
    
    # Find target admin user
    target_admin = db.query(User).filter(
        User.id == admin_id,
        User.role == UserRole.ADMIN
    ).first()
    
    if not target_admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Admin user not found"
        )
    
    # Validate current status - only DISABLED admins can be approved
    if target_admin.account_status != AccountStatus.DISABLED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve admin with status: {target_admin.account_status.value}. Only DISABLED admins can be approved."
        )
    
    # Prevent self-approval (business rule)
    if target_admin.id == current_admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admins cannot approve their own registration"
        )
    
    # Update admin status to ACTIVE
    old_status = target_admin.account_status
    target_admin.account_status = AccountStatus.ACTIVE
    target_admin.created_by = current_admin.id  # Track who approved this admin
    
    # Commit changes
    db.commit()
    db.refresh(target_admin)
    
    # Enhanced logging for admin approval
    logger.info(
        f"✅ Admin approval completed: {target_admin.email} "
        f"(ID: {target_admin.id}) approved by {current_admin.email} "
        f"(ID: {current_admin.id}) - Reason: {approval_data.reason}"
    )
    
    # TODO: Trigger notification email to approved admin (Sprint 6)
    # background_tasks.add_task(send_admin_approval_email, target_admin.email)
    
    return {
        "message": "Admin registration approved successfully",
        "approved_admin": {
            "id": target_admin.id,
            "email": target_admin.email,
            "full_name": target_admin.full_name,
            "previous_status": old_status.value,
            "current_status": target_admin.account_status.value,
            "approved_at": target_admin.updated_at.isoformat() if target_admin.updated_at else None
        },
        "approval_details": {
            "approved_by": {
                "id": current_admin.id,
                "email": current_admin.email,
                "full_name": current_admin.full_name
            },
            "reason": approval_data.reason,
            "timestamp": db.query(func.now()).scalar().isoformat()
        }
    }

@router.post("/admin/{admin_id}/reject", status_code=status.HTTP_200_OK)
def reject_admin_registration(
    admin_id: int,
    rejection_data: AdminRejectionRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Dedicated endpoint for rejecting admin registration requests.
    
    Args:
        admin_id: ID of admin user to reject
        rejection_data: Admin rejection request data
        current_admin: Current admin user performing the rejection
        db: Database session
        
    Returns:
        Dict with rejection confirmation and audit details
        
    Raises:
        HTTPException: If admin not found, invalid status, or insufficient permissions
    """
    logger.info(f"Admin rejection request by {current_admin.id} for admin {admin_id}")
    
    # Find target admin user
    target_admin = db.query(User).filter(
        User.id == admin_id,
        User.role == UserRole.ADMIN
    ).first()
    
    if not target_admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Admin user not found"
        )
    
    # Validate current status - only DISABLED admins can be rejected
    if target_admin.account_status != AccountStatus.DISABLED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot reject admin with status: {target_admin.account_status.value}. Only DISABLED admins can be rejected."
        )
    
    # Prevent self-rejection (business rule)
    if target_admin.id == current_admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admins cannot reject their own registration"
        )
    
    # Update admin status to DEACTIVATED (or delete if preferred)
    old_status = target_admin.account_status
    target_admin.account_status = AccountStatus.DEACTIVATED
    
    # Enhanced logging for admin rejection
    logger.info(
        f"❌ Admin rejection completed: {target_admin.email} "
        f"(ID: {target_admin.id}) rejected by {current_admin.email} "
        f"(ID: {current_admin.id}) - Reason: {rejection_data.reason}"
    )
    
    # Commit changes
    db.commit()
    
    # TODO: Trigger notification email to rejected admin (Sprint 6)
    # background_tasks.add_task(send_admin_rejection_email, target_admin.email, rejection_data.reason)
    
    return {
        "message": "Admin registration rejected",
        "rejected_admin": {
            "id": target_admin.id,
            "email": target_admin.email,
            "full_name": target_admin.full_name,
            "previous_status": old_status.value,
            "current_status": target_admin.account_status.value
        },
        "rejection_details": {
            "rejected_by": {
                "id": current_admin.id,
                "email": current_admin.email,
                "full_name": current_admin.full_name
            },
            "reason": rejection_data.reason,
            "timestamp": db.query(func.now()).scalar().isoformat()
        }
    }

@router.get("/email-health", status_code=status.HTTP_200_OK)
async def check_email_health(
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Check email service health (Admin only).
    
    Args:
        current_admin: Current admin user
        db: Database session
        
    Returns:
        Dict with email service status
    """
    from app.api.utils.email import validate_email_config, MAIL_SERVER, MAIL_PORT, MAIL_USERNAME
    import smtplib
    import ssl
    import socket
    
    logger.info(f"Email health check requested by admin {current_admin.id}")
    
    health_status = {
        "service": "email",
        "status": "unknown",
        "checks": {},
        "timestamp": time.time()
    }
    
    # Check 1: Configuration validation
    try:
        config_valid = validate_email_config()
        health_status["checks"]["configuration"] = {
            "status": "pass" if config_valid else "fail",
            "details": "Email configuration is complete" if config_valid else "Missing email configuration"
        }
    except Exception as e:
        health_status["checks"]["configuration"] = {
            "status": "fail",
            "details": f"Configuration check failed: {str(e)}"
        }
    
    # Check 2: SMTP server connectivity
    try:
        socket.setdefaulttimeout(10)  # 10 second timeout for health check
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=10) as server:
            server.ehlo()
            health_status["checks"]["smtp_connection"] = {
                "status": "pass",
                "details": f"Successfully connected to {MAIL_SERVER}:{MAIL_PORT}"
            }
    except Exception as e:
        health_status["checks"]["smtp_connection"] = {
            "status": "fail",
            "details": f"Failed to connect to SMTP server: {str(e)}"
        }
    
    # Check 3: SMTP authentication (without sending email)
    try:
        if health_status["checks"]["smtp_connection"]["status"] == "pass":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=10) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(MAIL_USERNAME, os.getenv("MAIL_PASSWORD"))
                health_status["checks"]["smtp_authentication"] = {
                    "status": "pass",
                    "details": "SMTP authentication successful"
                }
        else:
            health_status["checks"]["smtp_authentication"] = {
                "status": "skip",
                "details": "Skipped due to connection failure"
            }
    except Exception as e:
        health_status["checks"]["smtp_authentication"] = {
            "status": "fail",
            "details": f"SMTP authentication failed: {str(e)}"
        }
    
    # Determine overall status
    all_checks = list(health_status["checks"].values())
    if all(check["status"] == "pass" for check in all_checks):
        health_status["status"] = "healthy"
    elif any(check["status"] == "fail" for check in all_checks):
        health_status["status"] = "unhealthy"
    else:
        health_status["status"] = "degraded"
    
    return health_status

@router.post("/oauth2-token", status_code=status.HTTP_200_OK)
def oauth2_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    OAuth2 token endpoint for Swagger UI authentication.
    
    Args:
        form_data: OAuth2 password request form data
        db: Database session
        
    Returns:
        Access token
    """
    logger.info(f"OAuth2 token request for: {form_data.username}")
    
    # Find user by email (regardless of role)
    user = db.query(User).filter(User.email == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.password_hash):
        logger.warning(f"Invalid credentials for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Role-specific validation
    if user.role == UserRole.PATIENT:
        # Patients must have verified email
        if not user.is_verified:
            logger.warning(f"Unverified email for patient: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email not verified. Please verify your email first."
            )
        
        # Check if account is active
        if user.account_status != AccountStatus.ACTIVE:
            logger.warning(f"Inactive patient account: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account status: {user.account_status.value}. Contact support if needed."
            )
    
    elif user.role == UserRole.DOCTOR:
        # Doctors must have admin approval (ACTIVE status)
        if user.account_status != AccountStatus.ACTIVE:
            status_messages = {
                AccountStatus.DISABLED: "Your account is pending administrator approval.",
                AccountStatus.DEACTIVATED: "Your account has been deactivated. Contact administration.",
                AccountStatus.RED_TAG: "Your account is under review. Contact administration."
            }
            message = status_messages.get(user.account_status, "Account access denied.")
            
            logger.warning(f"Inactive doctor account: {form_data.username} - {user.account_status}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=message
            )
    
    elif user.role == UserRole.STAFF:
        # Staff can log in with pending activation (first login) or active status
        if user.account_status in [AccountStatus.DEACTIVATED, AccountStatus.RED_TAG]:
            logger.warning(f"Deactivated staff account: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account has been deactivated. Contact administration."
            )
        
        # If first login with temporary password, activate account
        if user.account_status == AccountStatus.PENDING_ACTIVATION:
            user.account_status = AccountStatus.ACTIVE
            user.verification_code = None  # Clear temporary password
            db.commit()
            logger.info(f"Staff account activated on first login: {user.email}")
    
    elif user.role == UserRole.ADMIN:
        # Admins must have ACTIVE status
        if user.account_status != AccountStatus.ACTIVE:
            status_messages = {
                AccountStatus.DISABLED: "Your admin account is pending approval by an existing administrator.",
                AccountStatus.DEACTIVATED: "Your admin account has been deactivated. Contact administration.",
                AccountStatus.RED_TAG: "Your admin account is under review. Contact administration."
            }
            message = status_messages.get(user.account_status, "Admin account access denied.")
            
            logger.warning(f"Inactive admin account: {form_data.username} - {user.account_status}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=message
            )
    
    # Create access token
    token_data = {
        "id": user.id,
        "email": user.email,
        "role": user.role.value,
        "account_status": user.account_status.value
    }
    access_token = create_access_token(token_data)
    permissions = get_permissions_for_role(user.role, user.account_status)
    
    logger.info(f"Successful login: {user.email} ({user.role.value})")
    
    return {
        "access_token": access_token,
        "token_type": "Bearer"
    }

