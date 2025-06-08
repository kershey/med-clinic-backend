"""
Appointment Model - Stores appointment information and scheduling.

This model manages the relationship between doctors and patients for appointments.
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Enum, func
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import enum
from ..database import Base

class AppointmentStatus(str, enum.Enum):
    """Enum for appointment status"""
    SCHEDULED = "SCHEDULED"
    CONFIRMED = "CONFIRMED"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    NO_SHOW = "NO_SHOW"

class Appointment(Base):
    """
    Appointment Model - Stores appointment information
    
    Fields:
    - id: Primary key for appointment
    - doctor_id: Foreign key to Doctor model
    - patient_id: Foreign key to Patient model
    - appointment_date: Date and time of the appointment
    - status: Current status of the appointment
    - reason: Reason for the appointment
    - notes: Additional notes about the appointment
    - created_at: When the appointment was created
    - updated_at: When the appointment was last updated
    """
    __tablename__ = "appointments"

    id = Column(Integer, primary_key=True, index=True)
    doctor_id = Column(Integer, ForeignKey("doctors.id", ondelete="CASCADE"), nullable=False)
    patient_id = Column(Integer, ForeignKey("patients.id", ondelete="CASCADE"), nullable=False)
    appointment_date = Column(DateTime(timezone=True), nullable=False)
    status = Column(Enum(AppointmentStatus, name="appointment_status"), default=AppointmentStatus.SCHEDULED)
    reason = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    doctor = relationship("Doctor", back_populates="appointments")
    patient = relationship("Patient", back_populates="appointments")

    def __repr__(self):
        """String representation of the Appointment model"""
        return f"<Appointment(id={self.id}, doctor_id={self.doctor_id}, patient_id={self.patient_id}, date='{self.appointment_date}')>"

    def update_status(self, status: AppointmentStatus) -> None:
        """
        Update appointment status
        
        Args:
            status: New appointment status
        """
        self.status = status
        self.updated_at = datetime.now(timezone.utc)
