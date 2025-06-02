"""
User Model - Stores all user information in the system with enhanced role-based authentication support.

This model supports the complete role-based authentication flow with account status management.
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum
from sqlalchemy.sql import func
import enum
from ..database import Base

class UserRole(str, enum.Enum):
    """
    Enumeration for user roles in the medical clinic system.
    
    Roles:
    - PATIENT: Regular patients who can book appointments
    - DOCTOR: Medical practitioners who provide consultations
    - STAFF: Administrative staff who manage appointments and operations
    - ADMIN: System administrators with full access
    """
    PATIENT = "PATIENT"
    DOCTOR = "DOCTOR"
    STAFF = "STAFF"
    ADMIN = "ADMIN"

class AccountStatus(str, enum.Enum):
    """
    Enumeration for account status types in the authentication flow.
    
    Status Types:
    - PENDING_VERIFICATION: New account awaiting email verification
    - PENDING_ACTIVATION: Account created by admin awaiting first login
    - DISABLED: Account created but not yet approved for access
    - ACTIVE: Account verified and approved for system access
    - DEACTIVATED: Previously active account that has been suspended
    - RED_TAG: Account flagged for investigation or special handling
    """
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    PENDING_ACTIVATION = "PENDING_ACTIVATION"
    DISABLED = "DISABLED"
    ACTIVE = "ACTIVE"
    DEACTIVATED = "DEACTIVATED"
    RED_TAG = "RED_TAG"

class User(Base):
    """
    User Model - Stores all user information in the system
    
    Fields:
    - id: Primary key for user identification
    - email: Unique email address for login and communication
    - full_name: User's complete name
    - gender: User's gender (optional)
    - address: User's physical address (optional)
    - contact: User's contact number (optional)
    - password_hash: Securely hashed password (never store raw passwords)
    - is_active: Whether user account is active (deprecated - use status)
    - is_verified: Whether email has been verified
    - role: User role (patient, doctor, staff, admin)
    - status: Current account status for role-based authentication flow (mapped to 'status' column)
    - profile_image: URL to user's profile image (optional)
    - verification_code: Code sent to email for verification
    - created_at: Timestamp when user was created
    - updated_at: Timestamp when user was last updated
    - created_by: ID of admin/staff who created this account (for staff/doctor accounts)
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    gender = Column(String, nullable=True)
    address = Column(String, nullable=True)
    contact = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)  # Keeping for backward compatibility
    is_verified = Column(Boolean, default=False)
    role = Column(Enum(UserRole), default=UserRole.PATIENT)
    status = Column(Enum(AccountStatus), default=AccountStatus.PENDING_VERIFICATION, name='status')
    profile_image = Column(String, nullable=True)
    verification_code = Column(String, nullable=True)
    created_by = Column(Integer, nullable=True)  # Foreign key to admin/staff who created this account
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    @property
    def account_status(self):
        """Backward compatibility property for account_status."""
        return self.status
        
    @account_status.setter
    def account_status(self, value):
        """Backward compatibility setter for account_status."""
        self.status = value
