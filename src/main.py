"""
Main FastAPI application entry point.
Configures the application, middleware, and includes routers.
"""
from dotenv import load_dotenv

# Load environment variables from .env file first
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
from .auth.router import router as auth_router
# These will be uncommented as they are implemented
# from .appointments.router import router as appointments_router
# from .patients.router import router as patients_router
# from .doctors.router import router as doctors_router
from .database import engine, get_db
from .config import settings
from .auth.models import Base  # Import all models here for creating tables
from .exceptions import register_exception_handlers
from .core.middleware import setup_middlewares
from .core.bootstrap import bootstrap_admin_if_needed

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create database tables if they don't exist
Base.metadata.create_all(bind=engine)

# Bootstrap admin creation
logger.info("🚀 Starting Medical Clinic API...")
try:
    # Create database session for bootstrap
    db = next(get_db())
    bootstrap_admin_if_needed(db)
except Exception as e:
    logger.error(f"❌ Bootstrap process failed: {str(e)}")

# Create FastAPI application
app = FastAPI(
    title="Medical Clinic API",
    description="API for the Medical Clinic appointment system",
    version="1.0.0"
)

# Register exception handlers
register_exception_handlers(app)

# Configure CORS middleware
origins = [
    "http://localhost:3000",  # Frontend development server
    "https://medical-clinic.vercel.app"  # Production frontend (update with actual URL)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup custom middleware
setup_middlewares(app)

# Include routers
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
# These will be uncommented as they are implemented
# app.include_router(appointments_router, prefix="/api/v1/appointments", tags=["appointments"])
# app.include_router(patients_router, prefix="/api/v1/patients", tags=["patients"])
# app.include_router(doctors_router, prefix="/api/v1/doctors", tags=["doctors"])

# Root endpoint
@app.get("/")
def root():
    """
    Root endpoint for API health check.
    
    Returns:
        dict: Simple welcome message
    """
    return {"message": "Welcome to Medical Clinic API"}

# Health check endpoint
@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring.
    
    Returns:
        dict: Health status information
    """
    return {"status": "healthy", "database": "connected"}
