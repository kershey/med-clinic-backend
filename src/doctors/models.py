"""
Doctor Model - Stores doctor-specific information and schedule management.

This model extends the base User model with doctor-specific fields and relationships.
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON, Numeric, Enum, func
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from ..database import Base
from ..auth.models import User, DoctorStatus

class Doctor(Base):
    """
    Doctor Model - Stores doctor-specific information
    
    Fields:
    - id: Primary key for doctor profile
    - user_id: Foreign key to User model
    - specialization: Doctor's medical specialization
    - clinic_address: Physical address of the doctor's clinic
    - fee: Consultation fee
    - bio: Professional biography
    - availability_status: Current availability status
    - schedule: Weekly availability schedule (JSON)
    - created_at: When the doctor profile was created
    - updated_at: When the doctor profile was last updated
    """
    __tablename__ = "doctors"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    specialization = Column(String, nullable=False)
    clinic_address = Column(String, nullable=True)
    fee = Column(Numeric(10, 2), nullable=True)  # 10 digits total, 2 decimal places
    bio = Column(String, nullable=True)
    availability_status = Column(Enum(DoctorStatus), default=DoctorStatus.UNAVAILABLE)
    schedule = Column(JSON, nullable=True)  # Stores weekly schedule as JSON
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    user = relationship("User", back_populates="doctor_profile", uselist=False)
    appointments = relationship("Appointment", back_populates="doctor")
    medical_records = relationship("MedicalRecord", back_populates="doctor")

    def __repr__(self):
        """String representation of the Doctor model"""
        return f"<Doctor(id={self.id}, user_id={self.user_id}, specialization='{self.specialization}')>"

    @property
    def is_available(self) -> bool:
        """Check if doctor is currently available for appointments"""
        return self.availability_status == DoctorStatus.AVAILABLE

    @property
    def full_name(self) -> str:
        """Get doctor's full name from associated user"""
        return self.user.full_name if self.user else None

    @property
    def email(self) -> str:
        """Get doctor's email from associated user"""
        return self.user.email if self.user else None

    def update_schedule(self, schedule_data: dict) -> None:
        """
        Update doctor's weekly schedule
        
        Args:
            schedule_data: Dictionary containing schedule for each day
        """
        self.schedule = schedule_data
        self.updated_at = datetime.now(timezone.utc)

    def update_availability(self, status: DoctorStatus) -> None:
        """
        Update doctor's availability status
        
        Args:
            status: New availability status
        """
        self.availability_status = status
        self.updated_at = datetime.now(timezone.utc)
