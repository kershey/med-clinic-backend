"""
Patient Model - Stores patient-specific information.

This model extends the base User model with patient-specific fields and relationships.
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Date, func
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from ..database import Base
from ..auth.models import User

class Patient(Base):
    """
    Patient Model - Stores patient-specific information
    
    Fields:
    - id: Primary key for patient profile
    - user_id: Foreign key to User model
    - date_of_birth: Patient's date of birth
    - gender: Patient's gender
    - address: Patient's address
    - emergency_contact: Emergency contact information
    - medical_history: Medical history notes
    - allergies: Known allergies
    - created_at: When the patient profile was created
    - updated_at: When the patient profile was last updated
    """
    __tablename__ = "patients"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    date_of_birth = Column(Date, nullable=True)
    gender = Column(String, nullable=True)
    address = Column(String, nullable=True)
    emergency_contact = Column(String, nullable=True)
    medical_history = Column(String, nullable=True)
    allergies = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    user = relationship("User", back_populates="patient_profile", uselist=False)
    appointments = relationship("Appointment", back_populates="patient")
    medical_records = relationship("MedicalRecord", back_populates="patient", cascade="all, delete-orphan")

    def __repr__(self):
        """String representation of the Patient model"""
        return f"<Patient(id={self.id}, user_id={self.user_id})>"

    @property
    def full_name(self) -> str:
        """Get patient's full name from associated user"""
        return self.user.full_name if self.user else None

    @property
    def email(self) -> str:
        """Get patient's email from associated user"""
        return self.user.email if self.user else None
