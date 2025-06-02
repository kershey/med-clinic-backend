"""
Main FastAPI application entry point.
Configures the application, middleware, and includes routers.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import auth
from .database import engine
from .deps import get_db
from .models.user import Base  # or from wherever your User model is declared
from .utils.bootstrap import bootstrap_admin_if_needed
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create database tables if they don't exist
Base.metadata.create_all(bind=engine)

# Bootstrap admin creation (run after database tables are created)
logger.info("🚀 Starting Java Medical Clinic API...")
try:
    # Create database session for bootstrap
    db = next(get_db())
    bootstrap_admin_if_needed(db)
    db.close()
except Exception as e:
    logger.error(f"❌ Bootstrap process failed: {str(e)}")

# Create FastAPI application
app = FastAPI(
    title="Java Medical Clinic API",
    description="API for the Java Medical Clinic appointment system",
    version="1.0.0"
)

# Configure CORS middleware
origins = [
    "http://localhost:3000",  # Frontend development server
    "https://java-medical-clinic.vercel.app"  # Production frontend (update with actual URL)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)

# Root endpoint
@app.get("/")
def root():
    """
    Root endpoint for API health check.
    
    Returns:
        dict: Simple welcome message
    """
    return {"message": "Welcome to Java Medical Clinic API"}
