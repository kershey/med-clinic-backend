"""
Doctor Service - Business logic for doctor profile management.

This module provides service functions for doctor profile CRUD operations,
schedule management, and doctor approval workflow.
"""
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from fastapi import HTTPException, status
import logging
from datetime import datetime, timezone

from ..auth.models import User, UserRole, DoctorStatus, AccountStatus
from ..auth.exceptions import ResourceNotFoundException, PermissionDeniedException
from .models import Doctor
from .schemas import DoctorProfileUpdate, DoctorSearchParams

# Set up logging
logger = logging.getLogger(__name__)

def get_doctor_profile(db: Session, doctor_id: int) -> Doctor:
    """
    Get a doctor profile by ID.
    
    Args:
        db: Database session
        doctor_id: ID of the doctor profile
        
    Returns:
        Doctor: Doctor profile
        
    Raises:
        ResourceNotFoundException: If doctor profile not found
    """
    doctor = db.query(Doctor).filter(Doctor.id == doctor_id).first()
    if not doctor:
        raise ResourceNotFoundException("Doctor profile not found")
    return doctor

def get_doctor_profile_by_user_id(db: Session, user_id: int) -> Doctor:
    """
    Get a doctor profile by user ID.
    If the user has DOCTOR role but no profile exists, create a basic one.
    
    Args:
        db: Database session
        user_id: ID of the user
        
    Returns:
        Doctor: Doctor profile
        
    Raises:
        ResourceNotFoundException: If user not found or user is not a doctor
    """
    # First check if user exists and is a doctor
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise ResourceNotFoundException("User not found")
    
    if user.role != UserRole.DOCTOR:
        raise ResourceNotFoundException("User is not a doctor")
    
    # Try to get existing doctor profile
    doctor = db.query(Doctor).filter(Doctor.user_id == user_id).first()
    
    # If no doctor profile exists, create a basic one
    if not doctor:
        doctor = Doctor(
            user_id=user_id,
            specialization="General Medicine",  # Default specialization
            availability_status=DoctorStatus.UNAVAILABLE,  # Default to unavailable
            schedule=None  # Empty schedule initially
        )
        db.add(doctor)
        try:
            db.commit()
            db.refresh(doctor)
            logger.info(f"Created doctor profile for user {user_id}")
        except Exception as e:
            db.rollback()
            logger.error(f"Error creating doctor profile for user {user_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while creating doctor profile"
            )
    
    return doctor

def update_doctor_profile(
    db: Session,
    doctor_id: int,
    profile_data: DoctorProfileUpdate,
    current_user_id: int
) -> Doctor:
    """
    Update a doctor profile.
    
    Args:
        db: Database session
        doctor_id: ID of the doctor profile
        profile_data: Updated profile data
        current_user_id: ID of the user making the update
        
    Returns:
        Doctor: Updated doctor profile
        
    Raises:
        ResourceNotFoundException: If doctor profile not found
        PermissionDeniedException: If user lacks permission to update
    """
    # Get doctor profile
    doctor = get_doctor_profile(db, doctor_id)
    
    # Check permissions
    current_user = db.query(User).filter(User.id == current_user_id).first()
    if not current_user:
        raise ResourceNotFoundException("User not found")
    
    if current_user.role != UserRole.ADMIN and doctor.user_id != current_user_id:
        raise PermissionDeniedException("You don't have permission to update this profile")
    
    # Update fields
    update_data = profile_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(doctor, field, value)
    
    doctor.updated_at = datetime.now(timezone.utc)
    
    try:
        db.commit()
        db.refresh(doctor)
        logger.info(f"Doctor profile {doctor_id} updated by user {current_user_id}")
        return doctor
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating doctor profile {doctor_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating the doctor profile"
        )

def get_doctors(
    db: Session,
    page: int,
    page_size: int,
    search_params: DoctorSearchParams
) -> Tuple[List[Doctor], int, int]:
    """
    Get a paginated list of doctors with optional filtering.
    
    Args:
        db: Database session
        page: Page number (1-based)
        page_size: Number of items per page
        search_params: Search parameters for filtering
        
    Returns:
        Tuple containing:
        - List of doctor profiles
        - Total count of matching doctors
        - Total number of pages
    """
    # Start with base query
    query = db.query(Doctor).join(User)

    # Apply account status filter
    # if search_params.account_status:
    #     query = query.filter(User.account_status == search_params.account_status)
    # else:
    #     # Default to ACTIVE, PENDING_VERIFICATION, and DISABLED if no status is specified
    #     query = query.filter(or_(
    #         User.account_status == AccountStatus.ACTIVE,
    #         User.account_status == AccountStatus.PENDING_VERIFICATION,
    #         User.account_status == AccountStatus.DISABLED
    #     ))
    
    # Apply specialization filter
    if search_params.specialization:
        query = query.filter(Doctor.specialization.ilike(f"%{search_params.specialization}%"))
    
    # Apply availability status filter
    if search_params.availability_status:
        query = query.filter(Doctor.availability_status == search_params.availability_status)
    
    # Apply name search filter
    if search_params.name:
        query = query.filter(
            or_(
                User.full_name.ilike(f"%{search_params.name}%"),
                User.email.ilike(f"%{search_params.name}%")
            )
        )
    
    # Get total count
    total = query.count()
    
    # Calculate pagination
    total_pages = (total + page_size - 1) // page_size
    offset = (page - 1) * page_size
    
    # Get paginated results
    doctors = query.offset(offset).limit(page_size).all()
    
    return doctors, total, total_pages

def get_pending_doctor_approvals(
    db: Session,
    page: int,
    page_size: int
) -> Tuple[List[User], int, int]:
    """
    Get a paginated list of doctor users pending approval.
    
    Args:
        db: Database session
        page: Page number (1-based)
        page_size: Number of items per page
        
    Returns:
        Tuple containing:
        - List of pending doctor users (not Doctor profiles)
        - Total count of pending doctors
        - Total number of pages
    """
    # Query doctor USERS (not Doctor profiles) with DISABLED or PENDING_VERIFICATION status
    # These are doctors who have registered but haven't been approved yet
    query = db.query(User).filter(
        User.role == UserRole.DOCTOR,
        or_(
            User.status == AccountStatus.DISABLED,
            User.status == AccountStatus.PENDING_VERIFICATION
        )
    )
    
    # Get total count
    total = query.count()
    logger.info(f"Found {total} doctor users with DISABLED or PENDING_VERIFICATION account status.")
    
    # Calculate pagination
    total_pages = (total + page_size - 1) // page_size
    offset = (page - 1) * page_size
    
    # Get paginated results
    users = query.offset(offset).limit(page_size).all()
    
    return users, total, total_pages

def delete_doctor_profile(db: Session, doctor_id: int, current_user_id: int) -> None:
    """
    Delete a doctor profile.
    
    Args:
        db: Database session
        doctor_id: ID of the doctor profile
        current_user_id: ID of the user making the deletion
        
    Raises:
        ResourceNotFoundException: If doctor profile not found
        PermissionDeniedException: If user lacks permission to delete
    """
    # Get doctor profile
    doctor = get_doctor_profile(db, doctor_id)
    
    # Check permissions
    current_user = db.query(User).filter(User.id == current_user_id).first()
    if not current_user:
        raise ResourceNotFoundException("User not found")
    
    if current_user.role != UserRole.ADMIN and doctor.user_id != current_user_id:
        raise PermissionDeniedException("You don't have permission to delete this profile")
    
    try:
        db.delete(doctor)
        db.commit()
        logger.info(f"Doctor profile {doctor_id} deleted by user {current_user_id}")
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting doctor profile {doctor_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while deleting the doctor profile"
        )

def update_doctor_schedule(
    db: Session,
    doctor_id: int,
    schedule_data: Dict[str, Any],
    current_user_id: int
) -> Doctor:
    """
    Update a doctor's weekly schedule.
    
    Args:
        db: Database session
        doctor_id: ID of the doctor profile
        schedule_data: New schedule data
        current_user_id: ID of the user making the update
        
    Returns:
        Doctor: Updated doctor profile
        
    Raises:
        ResourceNotFoundException: If doctor profile not found
        PermissionDeniedException: If user lacks permission to update
    """
    # Get doctor profile
    doctor = get_doctor_profile(db, doctor_id)
    
    # Check permissions
    if doctor.user_id != current_user_id:
        raise PermissionDeniedException("You don't have permission to update this schedule")
    
    # Update schedule
    doctor.update_schedule(schedule_data)
    
    try:
        db.commit()
        db.refresh(doctor)
        logger.info(f"Doctor {doctor_id} schedule updated by user {current_user_id}")
        return doctor
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating doctor {doctor_id} schedule: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating the schedule"
        )

def update_doctor_availability(
    db: Session,
    doctor_id: int,
    status: DoctorStatus,
    current_user_id: int
) -> Doctor:
    """
    Update a doctor's availability status.
    
    Args:
        db: Database session
        doctor_id: ID of the doctor profile
        status: New availability status
        current_user_id: ID of the user making the update
        
    Returns:
        Doctor: Updated doctor profile
        
    Raises:
        ResourceNotFoundException: If doctor profile not found
        PermissionDeniedException: If user lacks permission to update
    """
    # Get doctor profile
    doctor = get_doctor_profile(db, doctor_id)
    
    # Check permissions
    if doctor.user_id != current_user_id:
        raise PermissionDeniedException("You don't have permission to update this status")
    
    # Update status
    doctor.update_availability(status)
    
    try:
        db.commit()
        db.refresh(doctor)
        logger.info(f"Doctor {doctor_id} availability updated to {status} by user {current_user_id}")
        return doctor
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating doctor {doctor_id} availability: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating the availability status"
        )
