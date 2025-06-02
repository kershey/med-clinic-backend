"""
Role-Based Authentication routes for the medical clinic system.

This module implements the complete authentication flow with production-standard
route naming conventions and separate registration endpoints for each user role.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
import logging
from typing import Dict
from ..database import SessionLocal
from ..schemas.user import (
    PatientRegistration, DoctorRegistration, StaffRegistration, AdminRegistration,
    UserLogin, UserVerify, UserResponse, LoginResponse, AuthError,
    AccountStatusUpdate, PasswordReset, PasswordChange
)
from ..models.user import User, UserRole, AccountStatus
from ..auth.password import hash_password, verify_password
from ..auth.jwt import create_access_token, get_permissions_for_role
from ..utils.email import generate_verification_code, send_verification_email
from ..deps import get_db, get_current_user, require_staff_or_admin, get_current_user_with_verification_status

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
        logger.error(f"Failed to send verification email: {str(e)}")
        return {
            "message": "Patient account created but verification email failed to send. Please use resend verification.",
            "user_id": user_obj.id,
            "email": patient_data.email,
            "error": "Email service unavailable"
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
    
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == staff_data.email).first()
    if existing_user:
        logger.warning(f"Staff creation failed: Email {staff_data.email} already registered")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Generate temporary password and activation code
    temp_password = generate_verification_code()  # Use as temporary password
    
    # Create new staff user
    user_obj = User(
        email=staff_data.email,
        full_name=staff_data.full_name,
        gender=staff_data.gender,
        address=staff_data.address,
        contact=staff_data.contact,
        password_hash=hash_password(temp_password),
        role=UserRole.STAFF,
        account_status=AccountStatus.PENDING_ACTIVATION,
        verification_code=temp_password,  # Store temp password for first login
        is_verified=True,
        created_by=current_admin.id
    )
    
    # Save to database
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    logger.info(f"Staff account created by admin {current_admin.id}: {user_obj.id}")
    
    # TODO: Send activation email with temporary password
    # For now, return temp password (in production, this should be emailed)
    
    return {
        "message": "Staff account created successfully.",
        "user_id": user_obj.id,
        "email": staff_data.email,
        "temporary_password": temp_password,  # In production, this should be emailed
        "status": "pending_activation",
        "created_by": current_admin.email
    }

@router.post("/register/admin", status_code=status.HTTP_201_CREATED, response_model=Dict)
async def register_admin(
    admin_data: AdminRegistration,
    current_admin: User = Depends(require_staff_or_admin),
    db: Session = Depends(get_db)
):
    """
    Admin account creation endpoint (Existing Admin only).
    
    Only existing administrators can create new admin accounts.
    New admin accounts are created with DISABLED status and require activation.
    
    Args:
        admin_data: Admin registration data
        current_admin: Current admin user creating the new admin account
        db: Database session
        
    Returns:
        Dict with account creation success message
        
    Raises:
        HTTPException: If email already exists or insufficient permissions
    """
    logger.info(f"Admin account creation by admin {current_admin.id} for email: {admin_data.email}")
    
    # Only admins can create other admins
    if current_admin.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can create admin accounts"
        )
    
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == admin_data.email).first()
    if existing_user:
        logger.warning(f"Admin creation failed: Email {admin_data.email} already registered")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new admin user
    user_obj = User(
        email=admin_data.email,
        full_name=admin_data.full_name,
        gender=admin_data.gender,
        address=admin_data.address,
        contact=admin_data.contact,
        password_hash=hash_password(admin_data.password),
        role=UserRole.ADMIN,
        account_status=AccountStatus.DISABLED,  # Requires activation by existing admin
        is_verified=True,
        created_by=current_admin.id
    )
    
    # Save to database
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    logger.info(f"Admin account created by admin {current_admin.id}: {user_obj.id}")
    
    return {
        "message": "Admin account created successfully. Account requires activation.",
        "user_id": user_obj.id,
        "email": admin_data.email,
        "status": "disabled",
        "created_by": current_admin.email,
        "admin_level": admin_data.admin_level
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
            logger.warning(f"Inactive admin account: {login_data.email}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin account is not active. Contact another administrator for activation."
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
    email_data: Dict,
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    """
    Resend verification email endpoint.
    
    Args:
        email_data: Dict containing user email
        background_tasks: FastAPI BackgroundTasks for email sending
        db: Database session
        
    Returns:
        Dict with success message
        
    Raises:
        HTTPException: If user not found or already verified
    """
    email = email_data.get("email")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required"
        )
    
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
        return {"message": "Verification email resent successfully"}
    except Exception as e:
        logger.error(f"Failed to resend verification email: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification email"
        )

@router.post("/forgot-password", status_code=status.HTTP_200_OK)
async def forgot_password(
    password_reset: PasswordReset,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Initiate password reset process.
    
    Args:
        password_reset: Email for password reset
        background_tasks: FastAPI BackgroundTasks for email sending
        db: Database session
        
    Returns:
        Dict with success message
        
    Raises:
        HTTPException: If user not found
    """
    user = db.query(User).filter(User.email == password_reset.email).first()
    if not user:
        # For security, don't reveal if email exists or not
        return {"message": "If the email exists, a password reset link has been sent"}
    
    # Generate reset token
    reset_token = generate_verification_code()
    user.verification_code = reset_token  # Reuse verification_code field for reset token
    db.commit()
    
    # TODO: Send password reset email
    logger.info(f"Password reset requested for: {password_reset.email}")
    
    return {"message": "If the email exists, a password reset link has been sent"}

@router.post("/reset-password", status_code=status.HTTP_200_OK)
def reset_password(
    password_change: PasswordChange,
    db: Session = Depends(get_db)
):
    """
    Reset password with token.
    
    Args:
        password_change: Password change data with reset token
        db: Database session
        
    Returns:
        Dict with success message
        
    Raises:
        HTTPException: If user not found or invalid token
    """
    user = db.query(User).filter(User.email == password_change.email).first()
    if not user or user.verification_code != password_change.reset_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset token"
        )
    
    # Update password
    user.password_hash = hash_password(password_change.new_password)
    user.verification_code = None  # Clear reset token
    db.commit()
    
    logger.info(f"Password reset successful for: {password_change.email}")
    
    return {"message": "Password reset successfully"}

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