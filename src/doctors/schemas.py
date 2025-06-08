"""
Doctor Schemas - Pydantic models for doctor profile data validation and serialization.

This module defines the schemas used for doctor profile updates and responses.
Note: Doctor registration and approval are handled through auth schemas.
"""
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, validator
from datetime import datetime
from decimal import Decimal
from ..auth.models import DoctorStatus, AccountStatus, UserRole
from ..auth.schemas import UserResponse

class ScheduleDay(BaseModel):
    """
    Schema for a single day's schedule in a queue-based system
    
    Fields:
    - is_available: Whether the doctor is available on this day
    - max_queue_size: Maximum number of patients that can be in queue for this day
    - current_queue_size: Current number of patients in queue (read-only)
    - estimated_wait_time: Estimated wait time in minutes (read-only)
    """
    is_available: bool = Field(
        default=False,
        description="Whether the doctor is available on this day"
    )
    max_queue_size: Optional[int] = Field(
        None,
        ge=1,
        description="Maximum number of patients that can be in queue for this day"
    )
    current_queue_size: Optional[int] = Field(
        None,
        ge=0,
        description="Current number of patients in queue (read-only)"
    )
    estimated_wait_time: Optional[int] = Field(
        None,
        ge=0,
        description="Estimated wait time in minutes (read-only)"
    )

class DoctorSchedule(BaseModel):
    """Schema for doctor's weekly schedule"""
    monday: ScheduleDay = Field(default_factory=ScheduleDay)
    tuesday: ScheduleDay = Field(default_factory=ScheduleDay)
    wednesday: ScheduleDay = Field(default_factory=ScheduleDay)
    thursday: ScheduleDay = Field(default_factory=ScheduleDay)
    friday: ScheduleDay = Field(default_factory=ScheduleDay)
    saturday: ScheduleDay = Field(default_factory=ScheduleDay)
    sunday: ScheduleDay = Field(default_factory=ScheduleDay)

class DoctorProfileUpdate(BaseModel):
    """
    Doctor Profile Update Schema - Used when updating a doctor profile
    
    Fields:
    - specialization: Doctor's medical specialization
    - clinic_address: Physical address of the doctor's clinic (optional)
    - fee: Consultation fee (optional)
    - bio: Professional biography (optional)
    - schedule: Weekly availability schedule (optional)
    """
    specialization: Optional[str] = Field(None, description="Doctor's medical specialization")
    clinic_address: Optional[str] = Field(None, description="Physical address of the doctor's clinic")
    fee: Optional[Decimal] = Field(None, description="Consultation fee")
    bio: Optional[str] = Field(None, description="Professional biography")
    schedule: Optional[Dict[str, Any]] = Field(None, description="Weekly availability schedule")

class DoctorResponse(BaseModel):
    """
    Doctor Response Schema - Used when returning doctor data
    
    Fields:
    - id: Doctor profile ID
    - user: User information
    - specialization: Doctor's medical specialization
    - clinic_address: Physical address of the doctor's clinic
    - fee: Consultation fee
    - bio: Professional biography
    - availability_status: Current availability status
    - schedule: Weekly availability schedule
    - created_at: When the doctor profile was created
    - updated_at: When the doctor profile was last updated
    """
    id: int
    user: UserResponse
    specialization: str
    clinic_address: Optional[str] = None
    fee: Optional[Decimal] = None
    bio: Optional[str] = None
    availability_status: DoctorStatus
    schedule: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        """Configuration for Pydantic model to enable ORM mode"""
        from_attributes = True

class DoctorListResponse(BaseModel):
    """
    Doctor List Response Schema - Used when returning a list of doctors
    
    Fields:
    - doctors: List of doctor profiles
    - total: Total number of doctors
    - page: Current page number
    - page_size: Number of doctors per page
    - total_pages: Total number of pages
    """
    doctors: List[DoctorResponse]
    total: int
    page: int
    page_size: int
    total_pages: int

class DoctorSearchParams(BaseModel):
    """
    Doctor Search Parameters Schema - Used for filtering doctor lists
    
    Fields:
    - specialization: Filter by specialization
    - availability_status: Filter by availability status
    - name: Search by doctor's name
    - account_status: Filter by user account status (e.g., ACTIVE, PENDING_VERIFICATION, DISABLED)
    """
    specialization: Optional[str] = None
    availability_status: Optional[DoctorStatus] = None
    name: Optional[str] = None
    account_status: Optional[AccountStatus] = None

class DoctorAvailabilityUpdate(BaseModel):
    """
    Doctor Availability Update Schema - Used when updating doctor availability status
    
    Fields:
    - status: New availability status (AVAILABLE, UNAVAILABLE, ON_LEAVE, ON_CALL)
    """
    status: DoctorStatus = Field(
        ...,
        description="Doctor's availability status"
    )

    class Config:
        """Configuration for Pydantic model"""
        json_schema_extra = {
            "example": {
                "status": "AVAILABLE"
            }
        }

class ScheduleTimeSlot(BaseModel):
    """
    Schema for a time slot in a doctor's schedule
    
    Fields:
    - start_time: Start time in 24-hour format (HH:MM)
    - end_time: End time in 24-hour format (HH:MM)
    - max_patients: Maximum number of patients for this slot
    """
    start_time: str = Field(..., description="Start time in 24-hour format (HH:MM)")
    end_time: str = Field(..., description="End time in 24-hour format (HH:MM)")
    max_patients: int = Field(..., ge=1, description="Maximum number of patients for this slot")

    @validator("start_time", "end_time")
    def validate_time_format(cls, v):
        """Validate time format is HH:MM"""
        try:
            hour, minute = map(int, v.split(":"))
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                raise ValueError
        except ValueError:
            raise ValueError("Time must be in HH:MM format")
        return v

    @validator("end_time")
    def validate_end_after_start(cls, v, values):
        """Validate end time is after start time"""
        if "start_time" in values:
            start = values["start_time"]
            if v <= start:
                raise ValueError("End time must be after start time")
        return v

class ScheduleDay(BaseModel):
    """
    Schema for a single day's schedule
    
    Fields:
    - is_available: Whether the doctor is available on this day
    - time_slots: List of time slots for this day
    - max_queue_size: Maximum number of patients that can be in queue for this day
    - current_queue_size: Current number of patients in queue (read-only)
    - estimated_wait_time: Estimated wait time in minutes (read-only)
    """
    is_available: bool = Field(
        default=False,
        description="Whether the doctor is available on this day"
    )
    time_slots: Optional[List[ScheduleTimeSlot]] = Field(
        default_factory=list,
        description="List of time slots for this day"
    )
    max_queue_size: Optional[int] = Field(
        None,
        ge=1,
        description="Maximum number of patients that can be in queue for this day"
    )
    current_queue_size: Optional[int] = Field(
        None,
        ge=0,
        description="Current number of patients in queue (read-only)"
    )
    estimated_wait_time: Optional[int] = Field(
        None,
        ge=0,
        description="Estimated wait time in minutes (read-only)"
    )

    @validator("time_slots")
    def validate_time_slots(cls, v, values):
        """Validate time slots when day is available"""
        if values.get("is_available") and not v:
            raise ValueError("Time slots are required when day is available")
        return v

class DoctorSchedule(BaseModel):
    """
    Schema for doctor's weekly schedule
    
    Fields:
    - monday: Monday schedule
    - tuesday: Tuesday schedule
    - wednesday: Wednesday schedule
    - thursday: Thursday schedule
    - friday: Friday schedule
    - saturday: Saturday schedule
    - sunday: Sunday schedule
    """
    monday: ScheduleDay = Field(default_factory=ScheduleDay)
    tuesday: ScheduleDay = Field(default_factory=ScheduleDay)
    wednesday: ScheduleDay = Field(default_factory=ScheduleDay)
    thursday: ScheduleDay = Field(default_factory=ScheduleDay)
    friday: ScheduleDay = Field(default_factory=ScheduleDay)
    saturday: ScheduleDay = Field(default_factory=ScheduleDay)
    sunday: ScheduleDay = Field(default_factory=ScheduleDay)

    class Config:
        """Configuration for Pydantic model"""
        json_schema_extra = {
            "example": {
                "monday": {
                    "is_available": True,
                    "time_slots": [
                        {
                            "start_time": "09:00",
                            "end_time": "12:00",
                            "max_patients": 10
                        },
                        {
                            "start_time": "14:00",
                            "end_time": "17:00",
                            "max_patients": 10
                        }
                    ],
                    "max_queue_size": 20
                },
                "tuesday": {
                    "is_available": True,
                    "time_slots": [
                        {
                            "start_time": "09:00",
                            "end_time": "12:00",
                            "max_patients": 10
                        }
                    ],
                    "max_queue_size": 10
                },
                "wednesday": {
                    "is_available": False,
                    "time_slots": [],
                    "max_queue_size": None
                },
                "thursday": {
                    "is_available": False,
                    "time_slots": [],
                    "max_queue_size": None
                },
                "friday": {
                    "is_available": False,
                    "time_slots": [],
                    "max_queue_size": None
                },
                "saturday": {
                    "is_available": False,
                    "time_slots": [],
                    "max_queue_size": None
                },
                "sunday": {
                    "is_available": False,
                    "time_slots": [],
                    "max_queue_size": None
                }
            }
        }

class PendingDoctorUser(BaseModel):
    """
    Pending Doctor User Schema - Used when returning pending doctor users awaiting approval
    
    Fields:
    - id: User ID
    - email: User's email address
    - full_name: User's full name
    - role: User role (should be DOCTOR)
    - status: Account status (DISABLED or PENDING_VERIFICATION)
    - is_verified: Whether email has been verified
    - created_at: When the user was created
    """
    id: int
    email: str
    full_name: str
    role: UserRole
    status: AccountStatus
    is_verified: bool
    created_at: datetime

    class Config:
        """Configuration for Pydantic model to enable ORM mode"""
        from_attributes = True

class PendingDoctorListResponse(BaseModel):
    """
    Pending Doctor List Response Schema - Used when returning a list of pending doctor users
    
    Fields:
    - doctors: List of pending doctor users
    - total: Total number of pending doctors
    - page: Current page number
    - page_size: Number of doctors per page
    - total_pages: Total number of pages
    """
    doctors: List[PendingDoctorUser]
    total: int
    page: int
    page_size: int
    total_pages: int
