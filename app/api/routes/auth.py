"""
Authentication routes for user registration, login, and email verification.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
import logging
from ..database import SessionLocal
from ..schemas.user import UserCreate, UserLogin, UserVerify, UserResponse
from ..models.user import User
from ..auth.password import hash_password, verify_password
from ..auth.jwt import create_access_token
from ..utils.email import generate_verification_code, send_verification_email_background, send_verification_email

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create API router with prefix and tag
router = APIRouter(prefix="/auth", tags=["Auth"])

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

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    user: UserCreate, 
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    """
    Register a new user and send verification email.
    
    Args:
        user: User data for registration
        background_tasks: FastAPI BackgroundTasks for asynchronous email sending
        db: Database session
        
    Returns:
        Dict with success message
        
    Raises:
        HTTPException: If email is already registered
    """
    # Log registration attempt
    logger.info(f"Registration attempt for email: {user.email}")
    
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        logger.warning(f"Registration failed: Email {user.email} already registered")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Generate verification code
    verification_code = generate_verification_code()
    logger.info(f"Generated verification code for {user.email}")
    
    # Create new user with hashed password and verification code
    user_obj = User(
        email=user.email,
        full_name=user.full_name,
        gender=user.gender,
        address=user.address,
        contact=user.contact,
        password_hash=hash_password(user.password),
        verification_code=verification_code,
        is_verified=False
    )
    
    # Add and commit to database
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    logger.info(f"User created in database: {user_obj.id}")
    
    # Send verification email directly (not in background)
    try:
        logger.info(f"Attempting to send verification email to {user.email}")
        # Send email synchronously
        await send_verification_email(user.email, verification_code)
        logger.info(f"Email sent successfully to {user.email}")
        
        return {
            "message": "User registered successfully. Please check your email for verification code.",
            "user_id": user_obj.id,
            "verification_code": verification_code  # Temporarily including for debugging
        }
    except Exception as e:
        logger.error(f"Failed to send verification email: {str(e)}")
        # If email fails, still return success but with a warning
        return {
            "message": "User registered successfully, but there was an issue sending the verification email. Please use the resend verification endpoint.",
            "user_id": user_obj.id,
            "error": str(e),
            "verification_code": verification_code  # Temporarily including for debugging
        }

@router.post("/verify-email", status_code=status.HTTP_200_OK)
def verify_email(verification_data: UserVerify, db: Session = Depends(get_db)):
    """
    Verify user email with the provided verification code.
    
    Args:
        verification_data: Contains email and verification code
        db: Database session
        
    Returns:
        Dict with success message
        
    Raises:
        HTTPException: If user not found or invalid verification code
    """
    # Find user by email
    user = db.query(User).filter(User.email == verification_data.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check if already verified
    if user.is_verified:
        return {"message": "Email already verified"}
    
    # Verify the code
    if user.verification_code != verification_data.verification_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )
    
    # Update user status
    user.is_verified = True
    user.verification_code = None  # Clear the code after verification
    db.commit()
    
    return {"message": "Email verified successfully"}

@router.post("/login", response_model=dict)
def login(user: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticate user and return access token.
    
    Args:
        user: Login credentials
        db: Database session
        
    Returns:
        Dict with access token and token type
        
    Raises:
        HTTPException: If invalid credentials or email not verified
    """
    # Find user by email
    user_obj = db.query(User).filter(User.email == user.email).first()
    
    # Check if user exists and password is correct
    if not user_obj or not verify_password(user.password, user_obj.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Check if email is verified
    if not user_obj.is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified. Please verify your email first."
        )
    
    # Check if user is active
    if not user_obj.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is inactive. Please contact support."
        )
    
    # Create and return access token
    token_data = {
        "id": user_obj.id, 
        "email": user_obj.email, 
        "role": user_obj.role
    }
    token = create_access_token(token_data)
    
    return {
        "access_token": token, 
        "token_type": "bearer",
        "user": {
            "id": user_obj.id,
            "email": user_obj.email,
            "full_name": user_obj.full_name,
            "role": user_obj.role
        }
    }

@router.post("/resend-verification", status_code=status.HTTP_200_OK)
async def resend_verification(
    email: dict, 
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    """
    Resend verification email with a new verification code.
    
    Args:
        email: Dict containing user email
        background_tasks: FastAPI BackgroundTasks for asynchronous email sending
        db: Database session
        
    Returns:
        Dict with success message
        
    Raises:
        HTTPException: If user not found or already verified
    """
    user_email = email.get("email")
    if not user_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required"
        )
    
    # Find user by email
    user = db.query(User).filter(User.email == user_email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check if already verified
    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already verified"
        )
    
    # Generate new verification code
    new_code = generate_verification_code()
    user.verification_code = new_code
    db.commit()
    
    # Send verification email in background
    await send_verification_email_background(
        background_tasks, 
        user_email, 
        new_code
    )
    
    return {"message": "Verification email resent successfully"} 