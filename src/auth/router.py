"""
Authentication routes for the medical clinic system.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import logging
from typing import Dict, Any

from ..database import get_db
from .models import User, UserRole, AccountStatus
from .schemas import (
    PatientRegistration, DoctorRegistration, StaffRegistration, AdminRegistration,
    UserLogin, UserVerify, ResendVerification, UserResponse, LoginResponse, AuthError,
    AccountStatusUpdate, PasswordReset, PasswordChange, AdminApprovalRequest, AdminRejectionRequest
)
from .dependencies import (
    get_current_user, get_current_active_user, require_staff_or_admin, require_admin,
    get_current_user_with_verification_status
)
from .service import (
    register_patient, register_doctor, login_user, verify_email,
    resend_verification, forgot_password, reset_password, refresh_token
)
from .exceptions import (
    InvalidCredentialsException, EmailAlreadyExistsException,
    VerificationCodeInvalidException, AccountStatusException,
    TokenExpiredException, InvalidTokenException,
    PasswordResetException,
    AccountLockedException
)
from ..config import settings

# Set up logging
logger = logging.getLogger(__name__)

# Create API router
router = APIRouter()

# ============================================================================
# ROLE-SPECIFIC REGISTRATION ROUTES
# ============================================================================

@router.post("/register/patient", status_code=status.HTTP_201_CREATED)
async def register_patient_route(
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
        doctor_data: Doctor registration data including professional information
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
            contact=doctor_data.contact
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
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail
        )
    except AccountStatusException as e:
        raise HTTPException(
            status_code=e.status_code,
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
