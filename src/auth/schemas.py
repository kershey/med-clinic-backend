"""
User Schemas - Pydantic models for user data validation and serialization.

Enhanced to support role-based authentication flow with specific schemas for each user role.
"""
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from .models import UserRole, AccountStatus, DoctorStatus

class UserBase(BaseModel):
    """
    Base User Schema - Contains fields common to all user-related schemas
    
    Fields:
    - email: User's email address
    - full_name: User's full name
    """
    email: EmailStr
    full_name: str

class UserCreate(UserBase):
    """
    User Creation Schema - Used when registering a new user
    
    Extends UserBase with:
    - password: User's plain text password (will be hashed before storage)
    - gender: User's gender (optional)
    - address: User's address (optional)
    - contact: User's contact number (optional)
    """
    password: str
    gender: Optional[str] = None
    address: Optional[str] = None
    contact: Optional[str] = None

# Role-specific registration schemas
class PatientRegistration(UserCreate):
    """
    Patient Registration Schema - Used for patient self-registration
    
    Patients can register themselves and will have PENDING_VERIFICATION status
    """
    pass

class DoctorRegistration(UserCreate):
    """
    Doctor Registration Schema - Used for doctor registration
    
    Includes additional professional information:
    - specialization: Doctor's medical specialization
    - license_number: Medical license number
    - bio: Professional biography (optional)
    """
    specialization: str = Field(..., description="Doctor's medical specialization")
    bio: Optional[str] = Field(None, description="Professional biography")

class StaffRegistration(UserCreate):
    """
    Staff Registration Schema - Used when admin creates staff accounts
    
    Includes:
    - department: Staff department/role
    - employee_id: Employee identification number
    """
    # department: str = Field(..., description="Staff department/role")
    # employee_id: str = Field(..., description="Employee identification number")

class AdminRegistration(UserCreate):
    """
    Admin Registration Schema - Used for admin self-registration
    
    Includes:
    - admin_level: Level of admin access (1-5, where 5 is highest)
    - justification: Reason for requesting admin access
    """
    admin_level: int = Field(default=1, ge=1, le=5, description="Admin access level")
    justification: str = Field(..., description="Reason for requesting admin access")

class UserLogin(BaseModel):
    """
    User Login Schema - Used for authentication
    
    Fields:
    - email: User's email address
    - password: User's plain text password
    """
    email: EmailStr
    password: str

class UserVerify(BaseModel):
    """
    User Verification Schema - Used to verify email address
    
    Fields:
    - email: User's email address
    - verification_code: Code sent to user's email
    """
    email: EmailStr
    verification_code: str

class ResendVerification(BaseModel):
    """
    Resend Verification Schema - Used to resend verification email
    
    Fields:
    - email: User's email address
    """
    email: EmailStr

class PasswordReset(BaseModel):
    """
    Password Reset Schema - Used for password reset requests
    
    Fields:
    - email: User's email address
    """
    email: EmailStr

class PasswordChange(BaseModel):
    """
    Password Change Schema - Used for changing password with reset token
    
    Fields:
    - email: User's email address
    - reset_token: Token received via email
    - new_password: New password
    """
    email: EmailStr
    reset_token: str
    new_password: str

class AccountStatusUpdate(BaseModel):
    """
    Account Status Update Schema - Used by admin/staff to update account status
    
    Fields:
    - user_id: ID of user whose status to update
    - new_status: New account status
    - reason: Reason for status change (optional)
    """
    user_id: int
    new_status: AccountStatus
    reason: Optional[str] = None

class AdminApprovalRequest(BaseModel):
    """
    Admin Approval Request Schema - Used for approving admin registration
    
    Fields:
    - reason: Reason for approving the admin registration
    """
    reason: str = Field(..., description="Reason for approving admin registration", min_length=10)

class AdminRejectionRequest(BaseModel):
    """
    Admin Rejection Request Schema - Used for rejecting admin registration
    
    Fields:
    - reason: Reason for rejecting the admin registration
    """
    reason: str = Field(..., description="Reason for rejecting admin registration", min_length=10)

class UserResponse(BaseModel):
    """
    User Response Schema - Used when returning user data
    
    Fields:
    - id: User ID
    - email: Email address
    - full_name: User's full name
    - gender: User's gender (if provided)
    - address: User's address (if provided)
    - contact: User's contact number (if provided)
    - department: Staff department/role (if provided)
    - employee_id: Employee identification number (if provided)
    - is_active: Whether user account is active (deprecated)
    - is_verified: Whether email has been verified
    - role: User role (patient, doctor, staff, admin)
    - account_status: Current account status
    - profile_image: URL to user's profile image (if uploaded)
    - created_by: ID of admin/staff who created this account
    - created_at: When the account was created
    - updated_at: When the account was last updated
    """
    id: int
    email: EmailStr
    full_name: str
    gender: Optional[str] = None
    address: Optional[str] = None
    contact: Optional[str] = None
    is_active: bool
    is_verified: bool
    role: UserRole
    account_status: AccountStatus
    profile_image: Optional[str] = None
    created_by: Optional[int] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        """Configuration for Pydantic model to enable ORM mode"""
        from_attributes = True

class LoginResponse(BaseModel):
    """
    Login Response Schema - Returned after successful authentication
    
    Fields:
    - access_token: JWT access token
    - token_type: Type of token (always "bearer")
    - user: User information
    - permissions: List of permissions based on role and account status
    """
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
    permissions: List[str]

class AuthError(BaseModel):
    """
    Authentication Error Schema - Used for authentication error responses
    
    Fields:
    - error: Error type
    - message: Human-readable error message
    - suggestions: List of suggested actions (optional)
    """
    error: str
    message: str
    suggestions: Optional[List[str]] = None

class BootstrapAdminRequest(BaseModel):
    """
    Bootstrap Admin Request Schema - Used for initial admin creation
    
    Fields:
    - email: Admin's email address
    - password: Admin's password
    - full_name: Admin's full name (optional)
    """
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    
    class Config:
        """Configuration for Pydantic model"""
        json_schema_extra = {
            "example": {
                "email": "admin@clinic.com",
                "password": "secure_password123",
                "full_name": "System Administrator"
            }
        }

class StaffActivation(BaseModel):
    """
    Staff Activation Schema - Used for staff account activation
    
    Fields:
    - staff_id: ID of staff to activate
    - new_password: New password to set
    - confirm_password: Password confirmation
    """
    staff_id: int
    new_password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=8)
    
    class Config:
        """Configuration for Pydantic model"""
        schema_extra = {
            "example": {
                "staff_id": 1,
                "new_password": "newSecurePassword123",
                "confirm_password": "newSecurePassword123"
            }
        }
