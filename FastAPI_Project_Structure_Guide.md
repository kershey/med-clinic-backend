# FastAPI Project Structure Guide

## Recommended Structure for Appointment System Backend

### 📋 Table of Contents

- [Project Overview](#project-overview)
- [Directory Structure](#directory-structure)
- [Module Breakdown](#module-breakdown)
- [Implementation Examples](#implementation-examples)
- [Best Practices](#best-practices)
- [Benefits](#benefits)
- [Getting Started](#getting-started)

---

## 🎯 Project Overview

This guide outlines the recommended project structure for a FastAPI-based appointment system backend. The structure follows domain-driven design principles, ensuring scalability, maintainability, and clear separation of concerns.

### Key Principles

- **Domain-Driven Design**: Each feature gets its own module
- **Separation of Concerns**: Clear separation between API, business logic, and data layers
- **Scalability**: Easy to add new features without affecting existing code
- **Testability**: Structure supports comprehensive testing
- **Python Best Practices**: Follows PEP standards and community conventions

---

## 📁 Directory Structure

```
backend-fastapi/
├── src/
│   ├── auth/
│   │   ├── __init__.py        # Package initialization
│   │   ├── router.py          # API endpoints
│   │   ├── schemas.py         # Pydantic models (request/response)
│   │   ├── models.py          # SQLAlchemy models
│   │   ├── service.py         # Business logic layer
│   │   ├── dependencies.py    # Auth dependencies & guards
│   │   ├── exceptions.py      # Auth-specific exceptions
│   │   ├── config.py          # Auth-related settings
│   │   └── utils.py           # Auth utility functions
│   ├── appointments/
│   │   ├── __init__.py
│   │   ├── router.py
│   │   ├── schemas.py
│   │   ├── models.py
│   │   ├── service.py
│   │   ├── dependencies.py    # Appointment-specific dependencies
│   │   ├── exceptions.py
│   │   └── utils.py
│   ├── patients/
│   │   ├── __init__.py
│   │   ├── router.py
│   │   ├── schemas.py
│   │   ├── models.py
│   │   ├── service.py
│   │   └── utils.py
│   ├── doctors/
│   │   ├── __init__.py
│   │   ├── router.py
│   │   ├── schemas.py
│   │   ├── models.py
│   │   ├── service.py
│   │   └── utils.py
│   ├── core/                  # Shared/common functionality
│   │   ├── __init__.py
│   │   ├── security.py        # JWT, password hashing
│   │   ├── pagination.py      # Pagination utilities
│   │   ├── permissions.py     # Role-based access control
│   │   └── middleware.py      # Custom middleware
│   ├── config.py              # Global application settings
│   ├── database.py            # Database connection & session
│   ├── exceptions.py          # Global exception handlers
│   └── main.py                # FastAPI app initialization
├── tests/
│   ├── __init__.py
│   ├── conftest.py            # Pytest fixtures & test configuration
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── test_router.py
│   │   ├── test_service.py
│   │   ├── test_models.py
│   │   └── test_utils.py
│   ├── appointments/
│   │   ├── __init__.py
│   │   ├── test_router.py
│   │   ├── test_service.py
│   │   └── test_models.py
│   └── core/
│       ├── __init__.py
│       ├── test_security.py
│       └── test_pagination.py
├── alembic/
│   ├── versions/
│   ├── env.py
│   └── script.py.mako
├── requirements/
│   ├── base.txt               # Core dependencies
│   ├── dev.txt                # Development dependencies
│   ├── test.txt               # Testing dependencies
│   └── prod.txt               # Production dependencies
├── scripts/                   # Utility scripts
│   ├── init_db.py
│   ├── seed_data.py
│   └── run_tests.py
├── .env.example              # Environment variables template
├── .env                      # Local environment variables (git-ignored)
├── .gitignore
├── docker-compose.yml        # For local development
├── Dockerfile                # For production deployment
├── pyproject.toml            # Modern Python project configuration
├── README.md
└── alembic.ini
```

---

## 🔧 Module Breakdown

### Domain Modules (auth, appointments, patients, doctors)

Each domain module follows the same pattern for consistency:

#### `router.py` - API Layer

- Contains FastAPI route definitions
- Handles HTTP requests/responses
- Minimal business logic (delegates to service layer)
- Request validation using Pydantic schemas

#### `schemas.py` - Data Contracts

- Pydantic models for request/response validation
- API input/output schemas
- Data transfer objects (DTOs)

#### `models.py` - Data Layer

- SQLAlchemy ORM models
- Database table definitions
- Relationships between entities

#### `service.py` - Business Logic

- Core business logic and rules
- Data processing and validation
- Coordination between different data sources
- Transaction management

#### `dependencies.py` - Dependency Injection

- FastAPI dependency functions
- Authentication guards
- Permission checks
- Database session management

#### `exceptions.py` - Error Handling

- Domain-specific exceptions
- Custom error types
- Error messages and codes

#### `utils.py` - Helper Functions

- Utility functions specific to the domain
- Data transformation helpers
- Common calculations

#### `config.py` - Module Configuration

- Module-specific settings
- Feature flags
- Constants

### Core Module

Shared functionality across all domains:

- **`security.py`**: JWT handling, password hashing, authentication utilities
- **`pagination.py`**: Pagination logic and utilities
- **`permissions.py`**: Role-based access control (RBAC)
- **`middleware.py`**: Custom middleware for logging, security, etc.

### Global Files

- **`config.py`**: Application-wide settings and configuration
- **`database.py`**: Database connection, session management
- **`exceptions.py`**: Global exception handlers
- **`main.py`**: FastAPI application initialization and setup

---

## 💻 Implementation Examples

### Main Application Setup

```python
# src/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.config import settings
from src.database import engine
from src.auth.router import router as auth_router
from src.appointments.router import router as appointments_router
from src.patients.router import router as patients_router
from src.doctors.router import router as doctors_router

app = FastAPI(
    title="Appointment System API",
    description="FastAPI backend for appointment management",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router, prefix="/api/v1/auth", tags=["authentication"])
app.include_router(appointments_router, prefix="/api/v1/appointments", tags=["appointments"])
app.include_router(patients_router, prefix="/api/v1/patients", tags=["patients"])
app.include_router(doctors_router, prefix="/api/v1/doctors", tags=["doctors"])

@app.get("/")
async def root():
    return {"message": "Appointment System API", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "database": "connected"}
```

### Domain Module Example - Appointments

#### Router Implementation

```python
# src/appointments/router.py
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import date
from src.database import get_db
from src.auth.dependencies import get_current_user
from src.core.pagination import paginate
from . import schemas, service
from .exceptions import AppointmentNotFound, SlotNotAvailable

router = APIRouter()

@router.post("/", response_model=schemas.AppointmentResponse)
async def create_appointment(
    appointment_data: schemas.AppointmentCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new appointment"""
    try:
        appointment = await service.create_appointment(db, appointment_data, current_user.id)
        return appointment
    except SlotNotAvailable as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

@router.get("/", response_model=List[schemas.AppointmentResponse])
async def get_user_appointments(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    status_filter: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get user's appointments with pagination and filtering"""
    appointments = await service.get_user_appointments(
        db, current_user.id, skip, limit, status_filter
    )
    return appointments

@router.get("/{appointment_id}", response_model=schemas.AppointmentResponse)
async def get_appointment(
    appointment_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get specific appointment by ID"""
    try:
        appointment = await service.get_appointment_by_id(db, appointment_id, current_user.id)
        return appointment
    except AppointmentNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Appointment not found")

@router.put("/{appointment_id}", response_model=schemas.AppointmentResponse)
async def update_appointment(
    appointment_id: int,
    appointment_update: schemas.AppointmentUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Update an existing appointment"""
    try:
        appointment = await service.update_appointment(
            db, appointment_id, appointment_update, current_user.id
        )
        return appointment
    except AppointmentNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Appointment not found")
    except SlotNotAvailable as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

@router.delete("/{appointment_id}")
async def cancel_appointment(
    appointment_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Cancel an appointment"""
    try:
        await service.cancel_appointment(db, appointment_id, current_user.id)
        return {"message": "Appointment cancelled successfully"}
    except AppointmentNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Appointment not found")
```

#### Service Layer Implementation

```python
# src/appointments/service.py
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
from . import models, schemas
from .exceptions import SlotNotAvailable, AppointmentNotFound

async def create_appointment(
    db: Session,
    appointment_data: schemas.AppointmentCreate,
    user_id: int
) -> models.Appointment:
    """Create a new appointment with availability checking"""

    # Check if slot is available
    is_available = await check_slot_availability(
        db, appointment_data.doctor_id, appointment_data.appointment_date
    )

    if not is_available:
        raise SlotNotAvailable("The selected time slot is not available")

    # Check if user has overlapping appointments
    has_conflict = await check_user_conflict(
        db, user_id, appointment_data.appointment_date
    )

    if has_conflict:
        raise SlotNotAvailable("You already have an appointment at this time")

    # Create appointment
    db_appointment = models.Appointment(
        **appointment_data.dict(),
        patient_id=user_id,
        status="scheduled",
        created_at=datetime.utcnow()
    )

    db.add(db_appointment)
    db.commit()
    db.refresh(db_appointment)

    # TODO: Send confirmation email/SMS

    return db_appointment

async def check_slot_availability(
    db: Session,
    doctor_id: int,
    appointment_date: datetime
) -> bool:
    """Check if the requested slot is available for the doctor"""
    existing_appointment = db.query(models.Appointment).filter(
        models.Appointment.doctor_id == doctor_id,
        models.Appointment.appointment_date == appointment_date,
        models.Appointment.status.in_(["scheduled", "confirmed"])
    ).first()

    return existing_appointment is None

async def check_user_conflict(
    db: Session,
    user_id: int,
    appointment_date: datetime
) -> bool:
    """Check if user has conflicting appointments"""
    # Check for appointments within 30 minutes before/after
    buffer_time = timedelta(minutes=30)
    start_time = appointment_date - buffer_time
    end_time = appointment_date + buffer_time

    conflicting_appointment = db.query(models.Appointment).filter(
        models.Appointment.patient_id == user_id,
        models.Appointment.appointment_date.between(start_time, end_time),
        models.Appointment.status.in_(["scheduled", "confirmed"])
    ).first()

    return conflicting_appointment is not None

async def get_user_appointments(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int = 10,
    status_filter: Optional[str] = None
) -> List[models.Appointment]:
    """Get user's appointments with pagination and filtering"""
    query = db.query(models.Appointment).filter(
        models.Appointment.patient_id == user_id
    )

    if status_filter:
        query = query.filter(models.Appointment.status == status_filter)

    return query.offset(skip).limit(limit).all()

async def get_appointment_by_id(
    db: Session,
    appointment_id: int,
    user_id: int
) -> models.Appointment:
    """Get specific appointment by ID (with user authorization)"""
    appointment = db.query(models.Appointment).filter(
        models.Appointment.id == appointment_id,
        models.Appointment.patient_id == user_id
    ).first()

    if not appointment:
        raise AppointmentNotFound("Appointment not found")

    return appointment

async def update_appointment(
    db: Session,
    appointment_id: int,
    appointment_update: schemas.AppointmentUpdate,
    user_id: int
) -> models.Appointment:
    """Update an existing appointment"""
    appointment = await get_appointment_by_id(db, appointment_id, user_id)

    # If changing date/time, check availability
    if appointment_update.appointment_date and appointment_update.appointment_date != appointment.appointment_date:
        is_available = await check_slot_availability(
            db, appointment.doctor_id, appointment_update.appointment_date
        )
        if not is_available:
            raise SlotNotAvailable("The new time slot is not available")

    # Update fields
    for field, value in appointment_update.dict(exclude_unset=True).items():
        setattr(appointment, field, value)

    appointment.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(appointment)

    return appointment

async def cancel_appointment(
    db: Session,
    appointment_id: int,
    user_id: int
) -> None:
    """Cancel an appointment"""
    appointment = await get_appointment_by_id(db, appointment_id, user_id)

    appointment.status = "cancelled"
    appointment.updated_at = datetime.utcnow()

    db.commit()

    # TODO: Send cancellation notification
```

#### Schema Definitions

```python
# src/appointments/schemas.py
from pydantic import BaseModel, Field, validator
from typing import Optional
from datetime import datetime
from enum import Enum

class AppointmentStatus(str, Enum):
    SCHEDULED = "scheduled"
    CONFIRMED = "confirmed"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    NO_SHOW = "no_show"

class AppointmentBase(BaseModel):
    doctor_id: int = Field(..., description="ID of the doctor")
    appointment_date: datetime = Field(..., description="Date and time of appointment")
    reason: Optional[str] = Field(None, max_length=500, description="Reason for appointment")
    notes: Optional[str] = Field(None, max_length=1000, description="Additional notes")

    @validator('appointment_date')
    def validate_future_date(cls, v):
        if v <= datetime.now():
            raise ValueError('Appointment date must be in the future')
        return v

    @validator('appointment_date')
    def validate_business_hours(cls, v):
        # Assuming business hours are 9 AM to 5 PM, Monday to Friday
        if v.weekday() >= 5:  # Saturday = 5, Sunday = 6
            raise ValueError('Appointments only available Monday to Friday')
        if not (9 <= v.hour < 17):
            raise ValueError('Appointments only available between 9 AM and 5 PM')
        return v

class AppointmentCreate(AppointmentBase):
    pass

class AppointmentUpdate(BaseModel):
    appointment_date: Optional[datetime] = None
    reason: Optional[str] = Field(None, max_length=500)
    notes: Optional[str] = Field(None, max_length=1000)
    status: Optional[AppointmentStatus] = None

class AppointmentResponse(AppointmentBase):
    id: int
    patient_id: int
    status: AppointmentStatus
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
```

#### Model Definitions

```python
# src/appointments/models.py
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.database import Base
from .schemas import AppointmentStatus

class Appointment(Base):
    __tablename__ = "appointments"

    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    doctor_id = Column(Integer, ForeignKey("doctors.id"), nullable=False)
    appointment_date = Column(DateTime, nullable=False)
    status = Column(Enum(AppointmentStatus), default=AppointmentStatus.SCHEDULED)
    reason = Column(String(500))
    notes = Column(Text)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    # Relationships
    patient = relationship("User", back_populates="appointments")
    doctor = relationship("Doctor", back_populates="appointments")

    def __repr__(self):
        return f"<Appointment(id={self.id}, patient_id={self.patient_id}, doctor_id={self.doctor_id}, date={self.appointment_date})>"
```

---

## ✅ Best Practices

### 1. **Consistent File Naming**

- Use lowercase with underscores (snake_case)
- Be descriptive and specific
- Follow Python naming conventions

### 2. **Import Organization**

```python
# Standard library imports
from datetime import datetime
from typing import List, Optional

# Third-party imports
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel

# Local imports
from src.database import get_db
from . import schemas, service
```

### 3. **Error Handling**

- Create domain-specific exceptions
- Use appropriate HTTP status codes
- Provide clear error messages

### 4. **Documentation**

- Add docstrings to all functions
- Use type hints consistently
- Document API endpoints with descriptions

### 5. **Security**

- Always validate user permissions
- Use dependency injection for authentication
- Sanitize user input

### 6. **Testing**

- Mirror test structure to source structure
- Test each layer independently
- Use fixtures for common test data

---

## 🚀 Benefits

### **Scalability**

- Easy to add new features/domains
- Minimal impact when modifying existing features
- Clear boundaries between modules

### **Maintainability**

- Consistent structure across all modules
- Easy to locate specific functionality
- Clear separation of concerns

### **Team Collaboration**

- Multiple developers can work on different modules
- Minimal merge conflicts
- Clear ownership of code sections

### **Testing**

- Each layer can be tested independently
- Easy to mock dependencies
- Clear test organization

### **Code Reusability**

- Services can be reused across different endpoints
- Shared utilities in core module
- Consistent patterns across domains

---

## 🎯 Getting Started

### 1. **Initial Setup**

```bash
# Create project structure
mkdir -p src/{auth,appointments,patients,doctors,core}
mkdir -p tests/{auth,appointments,patients,doctors,core}
mkdir -p requirements scripts

# Create __init__.py files
touch src/__init__.py
find src -type d -exec touch {}/__init__.py \;
find tests -type d -exec touch {}/__init__.py \;
```

### 2. **Dependencies**

```bash
# Install core dependencies
pip install fastapi uvicorn sqlalchemy alembic pydantic python-jose[cryptography] passlib[bcrypt] python-multipart

# Development dependencies
pip install pytest pytest-asyncio httpx black isort mypy
```

### 3. **Environment Setup**

```bash
# Copy environment template
cp .env.example .env

# Edit with your configuration
nano .env
```

### 4. **Database Setup**

```bash
# Initialize Alembic
alembic init alembic

# Create first migration
alembic revision --autogenerate -m "Initial migration"

# Apply migrations
alembic upgrade head
```

### 5. **Run the Application**

```bash
# Development
uvicorn src.main:app --reload

# Production
uvicorn src.main:app --host 0.0.0.0 --port 8000
```

---

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [Pydantic Documentation](https://pydantic-docs.helpmanual.io/)
- [Alembic Documentation](https://alembic.sqlalchemy.org/)
- [Python Project Structure Best Practices](https://docs.python-guide.org/writing/structure/)

---

_This structure is designed to grow with your project while maintaining clarity and best practices. Start simple and add complexity as needed._
