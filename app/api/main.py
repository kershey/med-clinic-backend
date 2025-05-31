"""
Main FastAPI application entry point.
Configures the application, middleware, and includes routers.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import auth
from .database import engine
from .models.user import Base  # or from wherever your User model is declared


# Create database tables if they don't exist
Base.metadata.create_all(bind=engine)

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
