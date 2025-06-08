"""
Authentication routes for the medical clinic system.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import func
import logging
from typing import Dict, Any, List, Optional
import time
import smtplib
import ssl
import os
from datetime import datetime, timezone
import random
import string
from pydantic import EmailStr

from ..database import get_db
from .models import User, UserRole, AccountStatus, DoctorStatus
from .schemas import (
    PatientRegistration, DoctorRegistration, StaffRegistration, AdminRegistration,
    UserLogin, UserVerify, ResendVerification, UserResponse, LoginResponse, AuthError,
    AccountStatusUpdate, PasswordReset, PasswordChange, AdminApprovalRequest, AdminRejectionRequest,
    BootstrapAdminRequest, StaffActivation, DoctorApprovalRequest
)
from .dependencies import (
    get_current_user, get_current_active_user, require_staff_or_admin, require_admin,
    get_current_user_with_verification_status
)
from .service import (
    register_patient, register_doctor, login_user, verify_email,
    resend_verification, forgot_password, reset_password, refresh_token,
    create_bootstrap_admin
)
from .exceptions import (
    InvalidCredentialsException, EmailAlreadyExistsException,
    VerificationCodeInvalidException, AccountStatusException,
    TokenExpiredException, InvalidTokenException,
    PasswordResetException,
    AccountLockedException
)
from ..core.security import hash_password
from ..config import settings

# Set up logging
logger = logging.getLogger(__name__)

# Create API router
router = APIRouter()

# ============================================================================
# BOOTSTRAP ADMIN ROUTES
# ============================================================================

@router.post("/bootstrap-admin", status_code=status.HTTP_201_CREATED)
async def bootstrap_admin_route(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Bootstrap admin creation endpoint.
    This endpoint is only available during system initialization when no admin exists.
    
    The system will attempt to create the first admin account using environment variables:
    - BOOTSTRAP_ADMIN_EMAIL
    - BOOTSTRAP_ADMIN_PASSWORD
    - BOOTSTRAP_ADMIN_NAME (optional)
    
    Args:
        request: FastAPI request object
        db: Database session
        
    Returns:
        Dict with bootstrap admin creation status
        
    Raises:
        HTTPException: If bootstrap process fails or admin already exists
    """
    try:
        # Get bootstrap credentials from environment
        admin_email = os.getenv("BOOTSTRAP_ADMIN_EMAIL")
        admin_password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD")
        admin_name = os.getenv("BOOTSTRAP_ADMIN_NAME", "System Administrator")
        
        # Validate environment variables
        if not admin_email or not admin_password:
            logger.error("Bootstrap admin creation failed: Missing environment variables")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Bootstrap admin credentials not configured"
            )
        
        # Check if any admin exists
        existing_admin = db.query(User).filter(User.role == UserRole.ADMIN).first()
        if existing_admin:
            logger.warning("Bootstrap admin creation failed: Admin already exists")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="System already has an admin account"
            )
        
        # Create bootstrap admin
        result = await create_bootstrap_admin(
            db=db,
            email=admin_email,
            password=admin_password,
            full_name=admin_name
        )
        
        # Log bootstrap success
        logger.info("Bootstrap admin created successfully")
        
        return {
            "message": "Bootstrap admin created successfully",
            "admin_email": admin_email,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "next_steps": [
                "Login with bootstrap credentials",
                "Change password immediately",
                "Remove bootstrap environment variables",
                "Create additional admin accounts if needed"
            ]
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Unexpected error during bootstrap admin creation: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create bootstrap admin"
        )

# ============================================================================
# ROLE-SPECIFIC REGISTRATION ROUTES
# ============================================================================

@router.post("/register/patient", status_code=status.HTTP_201_CREATED)
async def register_patient_route(
    background_tasks: BackgroundTasks,
    patient_data: PatientRegistration,
    db: Session = Depends(get_db)
):
    """
    Patient self-registration endpoint.
    
    Patients can register themselves and will receive email verification.
    Account status will be PENDING_VERIFICATION until email is verified,
    then automatically becomes ACTIVE.
    
    Args:
        background_tasks: FastAPI BackgroundTasks for email sending
        patient_data: Patient registration data (email, full_name, password, gender, address, contact, profile_image)
        db: Database session
        
    Returns:
        Dict with registration success message and verification instructions
        
    Raises:
        HTTPException: If email already exists or other error occurs
    """
    try:
        result = await register_patient(
            db=db,
            email=patient_data.email,
            full_name=patient_data.full_name,
            password=patient_data.password,
            gender=patient_data.gender,
            address=patient_data.address,
            contact=patient_data.contact,
            profile_image=patient_data.profile_image,
            background_tasks=background_tasks
        )
        return result
    except EmailAlreadyExistsException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail
        )
    except Exception as e:
        logger.error(f"Unexpected error during patient registration: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during registration"
        )

@router.post("/register/doctor", status_code=status.HTTP_201_CREATED)
async def register_doctor_route(
    doctor_data: DoctorRegistration,
    db: Session = Depends(get_db)
):
    """
    Doctor registration endpoint.
    
    Doctors can register but their accounts will be DISABLED until admin approval.
    They cannot access the system until an admin activates their account.
    
    Args:
        doctor_data: Doctor registration data (email, full_name, password, specialization, bio, gender, address, contact, profile_image)
        db: Database session
        
    Returns:
        Dict with registration success message and approval instructions
        
    Raises:
        HTTPException: If email already exists or other error occurs
    """
    try:
        result = await register_doctor(
            db=db,
            email=doctor_data.email,
            full_name=doctor_data.full_name,
            password=doctor_data.password,
            specialization=doctor_data.specialization,
            bio=doctor_data.bio,
            gender=doctor_data.gender,
            address=doctor_data.address,
            contact=doctor_data.contact,
            profile_image=doctor_data.profile_image
        )
        return result
    except EmailAlreadyExistsException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail
        )
    except Exception as e:
        logger.error(f"Unexpected error during doctor registration: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during registration"
        )

@router.post("/login", response_model=LoginResponse)
async def login_route(
    login_data: UserLogin,
    db: Session = Depends(get_db)
):
    """
    User login endpoint.
    
    Args:
        login_data: User login credentials
        db: Database session
        
    Returns:
        LoginResponse with access token and user information
        
    Raises:
        HTTPException: If credentials are invalid or account status prevents login
    """
    try:
        result = await login_user(
            db=db,
            email=login_data.email,
            password=login_data.password
        )
        return result
    except InvalidCredentialsException as e:
        logger.warning(f"Login failed: Invalid credentials for {login_data.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.detail
        )
    except AccountStatusException as e:
        logger.warning(f"Login failed: Account status issue for {login_data.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=e.detail
        )
    except Exception as e:
        logger.error(f"Unexpected error during login: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during login"
        )

@router.post("/verify-email", status_code=status.HTTP_200_OK)
async def verify_email_route(
    verification_data: UserVerify,
    db: Session = Depends(get_db)
):
    """
    Email verification endpoint.
    
    Args:
        verification_data: Email and verification code
        db: Database session
        
    Returns:
        Dict with verification success message
        
    Raises:
        HTTPException: If email not found or verification code is invalid
    """
    try:
        result = await verify_email(
            db=db,
            email=verification_data.email,
            verification_code=verification_data.verification_code
        )
        return result
    except InvalidCredentialsException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail
        )
    except VerificationCodeInvalidException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail
        )
    except Exception as e:
        logger.error(f"Unexpected error during email verification: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during email verification"
        )

@router.post("/resend-verification", status_code=status.HTTP_200_OK)
async def resend_verification_route(
    verification_request: ResendVerification,
    db: Session = Depends(get_db)
):
    """
    Resend verification email endpoint.
    
    Args:
        verification_request: Email to resend verification to
        db: Database session
        
    Returns:
        Dict with resend success message
        
    Raises:
        HTTPException: If email not found
    """
    try:
        result = await resend_verification(
            db=db,
            email=verification_request.email
        )
        return result
    except InvalidCredentialsException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail
        )
    except Exception as e:
        logger.error(f"Unexpected error during resend verification: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while resending verification"
        )

@router.post("/forgot-password", status_code=status.HTTP_200_OK)
async def forgot_password_route(
    password_reset: PasswordReset,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Forgot password endpoint to initiate password reset.
    
    Args:
        password_reset: Email for password reset
        request: FastAPI request object for building reset URL
        db: Database session
        
    Returns:
        Dict with password reset instructions
        
    Raises:
        HTTPException: If account is locked due to too many reset attempts
    """
    try:
        # Build base URL for password reset
        base_url = str(request.base_url).rstrip('/')
        request_url = settings.frontend_url or base_url
        
        result = await forgot_password(
            db=db,
            email=password_reset.email,
            request_url=request_url
        )
        return result
    except AccountLockedException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail
        )
    except Exception as e:
        logger.error(f"Unexpected error during forgot password: {str(e)}")
        # For security, don't reveal specific errors
        return {
            "message": "If your email is registered, you will receive password reset instructions"
        }

@router.post("/reset-password", status_code=status.HTTP_200_OK)
async def reset_password_route(
    password_change: PasswordChange,
    db: Session = Depends(get_db)
):
    """
    Reset password endpoint.
    
    Args:
        password_change: Email, reset token, and new password
        db: Database session
        
    Returns:
        Dict with password reset success message
        
    Raises:
        HTTPException: If token is invalid or expired, or password doesn't meet requirements
    """
    try:
        result = await reset_password(
            db=db,
            email=password_change.email,
            reset_token=password_change.reset_token,
            new_password=password_change.new_password
        )
        return result
    except InvalidCredentialsException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail
        )
    except InvalidTokenException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail
        )
    except TokenExpiredException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail
        )
    except AccountLockedException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail
        )
    except Exception as e:
        logger.error(f"Unexpected error during password reset: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during password reset"
        )

@router.post("/refresh-token", response_model=LoginResponse)
async def refresh_token_route(
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
    try:
        result = await refresh_token(
            user=current_user,
            db=db
        )
        return result
    except Exception as e:
        logger.error(f"Unexpected error during token refresh: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during token refresh"
        )

@router.post("/logout", status_code=status.HTTP_200_OK)
def logout():
    """
    Logout endpoint.
    
    Note: Since JWT tokens are stateless, the client should simply discard the token.
    This endpoint is provided for API completeness.
    
    Returns:
        Dict with logout success message
    """
    return {"message": "Successfully logged out"}

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """
    Get current user profile endpoint.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        UserResponse with user profile information
    """
    return current_user

@router.post("/oauth2-token")
async def oauth2_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    OAuth2 token endpoint for compatibility with OAuth2 clients.
    
    Args:
        form_data: OAuth2 form data with username and password
        db: Database session
        
    Returns:
        Dict with access token information
        
    Raises:
        HTTPException: If credentials are invalid
    """
    try:
        result = await login_user(
            db=db,
            email=form_data.username,  # OAuth2 uses 'username' field
            password=form_data.password
        )
        
        # Convert to OAuth2 compatible response
        return {
            "access_token": result["access_token"],
            "token_type": result["token_type"],
            "user_id": result["user"].id,
            "email": result["user"].email,
            "role": result["user"].role.value
        }
    except InvalidCredentialsException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
            headers={"WWW-Authenticate": "Bearer"}
        )
    except AccountStatusException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
            headers={"WWW-Authenticate": "Bearer"}
        )
    except Exception as e:
        logger.error(f"Unexpected error during OAuth2 token generation: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during authentication",
            headers={"WWW-Authenticate": "Bearer"}
        )

@router.post("/register/staff", status_code=status.HTTP_201_CREATED, response_model=Dict)
async def register_staff_route(
    background_tasks: BackgroundTasks,
    staff_data: StaffRegistration,
    current_admin: User = Depends(require_staff_or_admin),
    db: Session = Depends(get_db)
):
    """
    Staff account creation endpoint (Admin only).
    
    Only administrators can create staff accounts. Staff accounts are created with
    PENDING_ACTIVATION status and staff must set their password on first login.
    An email notification is sent to the staff member with activation instructions.
    
    Args:
        background_tasks: FastAPI BackgroundTasks for email sending
        staff_data: Staff registration data (email, full_name, password, gender, address, contact, profile_image)
        current_admin: Current admin user creating the staff account
        db: Database session
        
    Returns:
        Dict with account creation success message
        
    Raises:
        HTTPException: If email already exists or insufficient permissions
    """
    try:
        # Check if email already exists
        existing_user = db.query(User).filter(User.email == staff_data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Generate a secure temporary password
        temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        
        result = await register_staff(
            db=db,
            email=staff_data.email,
            full_name=staff_data.full_name,
            password=temp_password,  # Use temporary password
            gender=staff_data.gender,
            address=staff_data.address,
            contact=staff_data.contact,
            profile_image=staff_data.profile_image,
            created_by_id=current_admin.id,
            background_tasks=background_tasks
        )
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Unexpected error during staff registration: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during registration"
        )

async def send_staff_activation_email(email: str, full_name: str, temp_password: str):
    """
    Send staff activation email with temporary password.
    
    Args:
        email: Staff member's email
        full_name: Staff member's full name
        temp_password: Temporary password for first login
    """
    try:
        from ..utils.email import send_email
        
        subject = "Welcome to the Medical Clinic System - Staff Account Activation"
        template = """
        Dear {full_name},

        Welcome to the Medical Clinic System! Your staff account has been created.

        To activate your account, please follow these steps:
        1. Login to the system using your email and the temporary password below
        2. You will be prompted to set a new password
        3. After setting your password, your account will be fully activated

        Your temporary password is: {temp_password}

        Please change this password immediately after your first login.

        If you have any questions, please contact your administrator.

        Best regards,
        Medical Clinic System Team
        """
        
        await send_email(
            email_to=email,
            subject=subject,
            template=template.format(
                full_name=full_name,
                temp_password=temp_password
            )
        )
        
        logger.info(f"Staff activation email sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send staff activation email to {email}: {str(e)}")

@router.post("/register/admin", status_code=status.HTTP_201_CREATED, response_model=Dict)
async def register_admin_route(
    background_tasks: BackgroundTasks,
    admin_data: AdminRegistration,
    db: Session = Depends(get_db)
):
    """
    Admin self-registration endpoint.
    
    Users can register for admin accounts but they will be DISABLED until existing admin approval.
    They cannot access the system until an existing admin activates their account.
    
    Args:
        background_tasks: FastAPI BackgroundTasks for email sending
        admin_data: Admin registration data (email, full_name, password, justification, gender, address, contact, profile_image, admin_level)
        db: Database session
        
    Returns:
        Dict with registration success message and approval instructions
        
    Raises:
        HTTPException: If email already exists
    """
    try:
        # Check if email already exists
        existing_user = db.query(User).filter(User.email == admin_data.email).first()
        if existing_user:
            raise EmailAlreadyExistsException()
        
        result = await register_admin(
            db=db,
            email=admin_data.email,
            full_name=admin_data.full_name,
            password=admin_data.password,
            gender=admin_data.gender,
            address=admin_data.address,
            contact=admin_data.contact,
            profile_image=admin_data.profile_image,
            admin_level=admin_data.admin_level,
            justification=admin_data.justification,
            background_tasks=background_tasks
        )
        return result
    except EmailAlreadyExistsException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail
        )
    except Exception as e:
        logger.error(f"Unexpected error during admin registration: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during registration"
        )

# ============================================================================
# ADMIN MANAGEMENT ROUTES
# ============================================================================

@router.get("/admin/pending-registrations", status_code=status.HTTP_200_OK)
def get_pending_admin_registrations_route(
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
    try:
        # Find all pending admin accounts
        pending_admins = db.query(User).filter(
            User.role == UserRole.ADMIN,
            User.account_status == AccountStatus.DISABLED
        ).all()
        
        # Format the response
        pending_registrations = []
        for admin in pending_admins:
            registration_info = {
                "user_id": admin.id,
                "email": admin.email,
                "full_name": admin.full_name,
                "gender": admin.gender,
                "address": admin.address,
                "contact": admin.contact,
                "admin_level": 1,  # Default since we don't store this yet
                "justification": f"Admin access requested by {admin.full_name}",
                "created_at": admin.created_at,
                "days_pending": (datetime.now(timezone.utc) - admin.created_at).days
            }
            pending_registrations.append(registration_info)
        
        return {
            "message": f"Found {len(pending_registrations)} pending admin registration(s)",
            "pending_count": len(pending_registrations),
            "pending_registrations": pending_registrations
        }
    except Exception as e:
        logger.error(f"Error fetching pending admin registrations: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while fetching pending registrations"
        )

@router.put("/users/{user_id}/status", status_code=status.HTTP_200_OK)
def update_user_status_route(
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
    try:
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
        
        return {
            "message": f"Account status updated to {account_update.new_status.value}",
            "user_email": target_user.email,
            "old_status": old_status.value,
            "new_status": account_update.new_status.value,
            "updated_by": current_admin.email
        }
    except Exception as e:
        logger.error(f"Error updating user status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating user status"
        )

@router.post("/admin/{admin_id}/approve", status_code=status.HTTP_200_OK)
def approve_admin_registration_route(
    admin_id: int,
    approval_data: AdminApprovalRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Dedicated endpoint for approving admin registration requests.
    
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
    try:
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
        
        # Validate current status
        if target_admin.account_status != AccountStatus.DISABLED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot approve admin with status: {target_admin.account_status.value}"
            )
        
        # Prevent self-approval
        if target_admin.id == current_admin.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Admins cannot approve their own registration"
            )
        
        # Update admin status
        old_status = target_admin.account_status
        current_time = datetime.now(timezone.utc)
        target_admin.account_status = AccountStatus.ACTIVE
        target_admin.created_by = current_admin.id
        target_admin.updated_at = current_time
        
        db.commit()
        db.refresh(target_admin)
        
        return {
            "message": "Admin registration approved successfully",
            "approved_admin": {
                "id": target_admin.id,
                "email": target_admin.email,
                "full_name": target_admin.full_name,
                "previous_status": old_status.value,
                "current_status": target_admin.account_status.value,
                "approved_at": current_time.isoformat()
            },
            "approval_details": {
                "approved_by": {
                    "id": current_admin.id,
                    "email": current_admin.email,
                    "full_name": current_admin.full_name
                },
                "reason": approval_data.reason,
                "timestamp": current_time.isoformat()
            }
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error approving admin registration: {str(e)}")
        db.rollback()  # Rollback the transaction on error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while approving admin registration"
        )

@router.post("/admin/{admin_id}/reject", status_code=status.HTTP_200_OK)
def reject_admin_registration_route(
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
    try:
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
        
        # Validate current status
        if target_admin.account_status != AccountStatus.DISABLED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot reject admin with status: {target_admin.account_status.value}"
            )
        
        # Prevent self-rejection
        if target_admin.id == current_admin.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Admins cannot reject their own registration"
            )
        
        # Update admin status
        old_status = target_admin.account_status
        target_admin.account_status = AccountStatus.DEACTIVATED
        
        db.commit()
        
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
    except Exception as e:
        logger.error(f"Error rejecting admin registration: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while rejecting admin registration"
        )

@router.get("/email-health", status_code=status.HTTP_200_OK)
async def check_email_health_route(
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
    try:
        from ..utils.email import validate_email_config, MAIL_SERVER, MAIL_PORT, MAIL_USERNAME
        
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
            socket.setdefaulttimeout(10)
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
        
        # Check 3: SMTP authentication
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
    except Exception as e:
        logger.error(f"Error checking email health: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while checking email health"
        )

# ============================================================================
# STAFF ACTIVATION ROUTES
# ============================================================================

@router.post("/staff/{staff_id}/activate", status_code=status.HTTP_200_OK)
async def activate_staff_account(
    staff_id: int,
    activation: StaffActivation,
    db: Session = Depends(get_db)
):
    """
    Staff account activation endpoint.
    This endpoint is used by staff to activate their account and set their password.
    
    Args:
        staff_id: ID of staff to activate
        activation: Activation data including new password
        db: Database session
        
    Returns:
        Dict with activation success message
        
    Raises:
        HTTPException: If staff not found, invalid status, or passwords don't match
    """
    try:
        # Find staff user
        staff = db.query(User).filter(
            User.id == staff_id,
            User.role == UserRole.STAFF
        ).first()
        
        if not staff:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Staff account not found"
            )
        
        # Verify account status
        if staff.account_status != AccountStatus.PENDING_ACTIVATION:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot activate account with status: {staff.account_status.value}"
            )
        
        # Verify passwords match
        if activation.new_password != activation.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Passwords do not match"
            )
        
        # Update staff account
        staff.password_hash = hash_password(activation.new_password)
        staff.account_status = AccountStatus.ACTIVE
        staff.verification_code = None  # Clear temporary password
        staff.password_changed_at = datetime.now(timezone.utc)
        
        db.commit()
        db.refresh(staff)
        
        logger.info(f"Staff account {staff_id} activated successfully")
        
        return {
            "message": "Staff account activated successfully",
            "staff_id": staff.id,
            "email": staff.email,
            "status": "active",
            "activated_at": staff.password_changed_at.isoformat()
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error activating staff account: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate staff account"
        )

@router.post("/doctors/{doctor_id}/approve", status_code=status.HTTP_200_OK)
async def approve_doctor_registration_route(
    doctor_id: int,
    approval_data: DoctorApprovalRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Approve or reject a doctor registration.
    
    This endpoint allows admins to approve or reject doctor registrations.
    When approved, the doctor's account status changes to 'Active' and they can
    access the doctor portal to complete their profile.
    
    Args:
        doctor_id: ID of doctor user to approve
        approval_data: Doctor approval request data
        current_admin: Current admin user performing the approval
        db: Database session
        
    Returns:
        Dict with approval success message and audit details
        
    Raises:
        HTTPException: If doctor not found, invalid status, or insufficient permissions
    """
    try:
        # Find target doctor user
        target_doctor = db.query(User).filter(
            User.id == doctor_id,
            User.role == UserRole.DOCTOR
        ).first()
        
        if not target_doctor:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Doctor user not found"
            )
        
        # Validate current status
        if target_doctor.account_status != AccountStatus.DISABLED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot approve doctor with status: {target_doctor.account_status.value}"
            )
        
        # Update doctor status
        old_status = target_doctor.account_status
        current_time = datetime.now(timezone.utc)
        
        if approval_data.is_approved:
            target_doctor.account_status = AccountStatus.ACTIVE
            target_doctor.doctor_status = DoctorStatus.AVAILABLE
        else:
            target_doctor.account_status = AccountStatus.DEACTIVATED
        
        target_doctor.created_by = current_admin.id
        target_doctor.updated_at = current_time
        
        db.commit()
        db.refresh(target_doctor)
        
        return {
            "message": "Doctor registration processed successfully",
            "doctor": {
                "id": target_doctor.id,
                "email": target_doctor.email,
                "full_name": target_doctor.full_name,
                "previous_status": old_status.value,
                "current_status": target_doctor.account_status.value,
                "processed_at": current_time.isoformat()
            },
            "approval_details": {
                "approved_by": {
                    "id": current_admin.id,
                    "email": current_admin.email,
                    "full_name": current_admin.full_name
                },
                "is_approved": approval_data.is_approved,
                "reason": approval_data.reason,
                "timestamp": current_time.isoformat()
            }
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error processing doctor registration: {str(e)}")
        db.rollback()  # Rollback the transaction on error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing doctor registration"
        )
