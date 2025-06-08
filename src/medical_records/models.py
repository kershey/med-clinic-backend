"""
Medical Record Model - Stores patient medical records and doctor notes.

This model maintains a record of patient medical history, diagnoses, and treatments.
"""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, func
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from ..database import Base

class MedicalRecord(Base):
    """
    Medical Record Model - Stores patient medical records
    
    Fields:
    - id: Primary key for medical record
    - patient_id: Foreign key to Patient model
    - doctor_id: Foreign key to Doctor model
    - diagnosis: Medical diagnosis
    - treatment: Treatment prescribed
    - notes: Additional medical notes
    - prescription: Prescribed medications
    - created_at: When the record was created
    - updated_at: When the record was last updated
    """
    __tablename__ = "medical_records"

    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id", ondelete="CASCADE"), nullable=False)
    doctor_id = Column(Integer, ForeignKey("doctors.id", ondelete="SET NULL"), nullable=True)
    diagnosis = Column(Text, nullable=True)
    treatment = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    prescription = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    patient = relationship("Patient", back_populates="medical_records")
    doctor = relationship("Doctor", back_populates="medical_records")

    def __repr__(self):
        """String representation of the MedicalRecord model"""
        return f"<MedicalRecord(id={self.id}, patient_id={self.patient_id}, doctor_id={self.doctor_id})>" 