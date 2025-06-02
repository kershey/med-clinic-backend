"""
Bootstrap utilities for first admin creation.
Handles automatic creation of the first admin user from environment variables.
"""
import logging
from sqlalchemy.orm import Session
from ..models.user import User, UserRole, AccountStatus
from ..auth.password import hash_password
from ..config import settings

logger = logging.getLogger(__name__)

def admin_exists(db: Session) -> bool:
    """
    Check if any admin user exists in the database.
    
    Args:
        db: Database session
        
    Returns:
        bool: True if at least one admin exists, False otherwise
    """
    admin_count = db.query(User).filter(User.role == UserRole.ADMIN).count()
    return admin_count > 0

def create_bootstrap_admin(db: Session) -> bool:
    """
    Create the first admin user from environment variables.
    
    Args:
        db: Database session
        
    Returns:
        bool: True if admin was created successfully, False otherwise
    """
    try:
        # Validate environment variables
        if not settings.bootstrap_admin_email or not settings.bootstrap_admin_password:
            logger.warning("Bootstrap admin credentials not provided in environment variables")
            return False
        
        # Check if email already exists (safety check)
        existing_user = db.query(User).filter(User.email == settings.bootstrap_admin_email).first()
        if existing_user:
            logger.warning(f"Bootstrap failed: Email {settings.bootstrap_admin_email} already exists")
            return False
        
        # Create bootstrap admin user
        bootstrap_admin = User(
            email=settings.bootstrap_admin_email,
            full_name="System Administrator",
            password_hash=hash_password(settings.bootstrap_admin_password),
            role=UserRole.ADMIN,
            account_status=AccountStatus.ACTIVE,  # Bootstrap admin is immediately active
            is_verified=True,  # Bootstrap admin is pre-verified
            created_by=None  # Bootstrap admin has no creator (system created)
        )
        
        # Save to database
        db.add(bootstrap_admin)
        db.commit()
        db.refresh(bootstrap_admin)
        
        logger.info(f"✅ Bootstrap admin created successfully: {bootstrap_admin.email} (ID: {bootstrap_admin.id})")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to create bootstrap admin: {str(e)}")
        db.rollback()
        return False

def bootstrap_admin_if_needed(db: Session) -> None:
    """
    Check if admin exists and create bootstrap admin if needed.
    This function should be called during application startup.
    
    Args:
        db: Database session
    """
    logger.info("🔍 Checking for existing admin users...")
    
    if admin_exists(db):
        admin_count = db.query(User).filter(User.role == UserRole.ADMIN).count()
        logger.info(f"✅ Admin users found ({admin_count} total). Bootstrap not needed.")
        return
    
    logger.info("🚀 No admin users found. Attempting bootstrap admin creation...")
    
    if create_bootstrap_admin(db):
        logger.info("🎉 Bootstrap admin creation completed successfully!")
        logger.info("💡 You can now log in with the bootstrap credentials and change them if needed.")
    else:
        logger.warning("⚠️  Bootstrap admin creation skipped.")
        logger.info("💡 To create the first admin, set BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD in your .env file.") 