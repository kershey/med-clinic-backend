"""
Doctor Router - API endpoints for doctor profile management.

This module provides endpoints for updating, querying, and managing doctor profiles.
Note: Doctor registration and approval are handled through /api/v1/auth/
"""
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
import math

from ..database import get_db
from ..auth.dependencies import get_current_active_user, require_doctor, require_admin
from ..auth.models import UserRole, DoctorStatus, AccountStatus
from .models import Doctor
from .schemas import (
    DoctorProfileUpdate, 
    DoctorResponse, 
    DoctorListResponse, 
    DoctorSearchParams,
    DoctorSchedule,
    DoctorAvailabilityUpdate,
    PendingDoctorListResponse
)
from .service import (
    get_doctor_profile, 
    get_doctor_profile_by_user_id,
    update_doctor_profile, 
    get_doctors,
    get_pending_doctor_approvals,
    delete_doctor_profile,
    update_doctor_schedule,
    update_doctor_availability
)

router = APIRouter()

@router.get("/me", response_model=DoctorResponse)
async def get_my_doctor_profile(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_doctor)
):
    """
    Get the current doctor's profile
    
    This endpoint allows doctors to view their own profile.
    """
    return get_doctor_profile_by_user_id(db, current_user.id)

@router.put("/me", response_model=DoctorResponse)
async def update_my_doctor_profile(
    profile_data: DoctorProfileUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_doctor)
):
    """
    Update the current doctor's profile
    
    This endpoint allows doctors to update their own profile.
    """
    doctor = get_doctor_profile_by_user_id(db, current_user.id)
    return update_doctor_profile(db, doctor.id, profile_data, current_user.id)

@router.get("/", response_model=DoctorListResponse)
async def list_doctors(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    specialization: Optional[str] = Query(None, description="Filter by specialization"),
    name: Optional[str] = Query(None, description="Search by doctor name"),
    account_status: Optional[AccountStatus] = Query(None, description="Filter by user account status (e.g., ACTIVE, PENDING_VERIFICATION, DISABLED)"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """
    Get a paginated list of approved doctors
    
    This endpoint allows users to browse doctors with optional filtering.
    By default, doctors with ACTIVE, PENDING_VERIFICATION, or DISABLED user accounts are returned.
    """
    search_params = DoctorSearchParams(
        specialization=specialization,
        name=name,
        account_status=account_status
    )
    
    doctors, total, total_pages = get_doctors(db, page, page_size, search_params)
    
    return DoctorListResponse(
        doctors=doctors,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )

@router.get("/pending-approvals", response_model=PendingDoctorListResponse)
async def list_pending_doctor_approvals(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """
    Get a paginated list of doctor users pending approval
    
    This endpoint allows admins to view doctor users that need approval.
    """
    doctors, total, total_pages = get_pending_doctor_approvals(db, page, page_size)
    
    return PendingDoctorListResponse(
        doctors=doctors,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )

@router.get("/{doctor_id}", response_model=DoctorResponse)
async def get_doctor(
    doctor_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """
    Get a doctor profile by ID
    
    This endpoint allows users to view a specific doctor's profile.
    """
    return get_doctor_profile(db, doctor_id)

@router.put("/{doctor_id}", response_model=DoctorResponse)
async def update_doctor(
    doctor_id: int,
    profile_data: DoctorProfileUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """
    Update a doctor profile
    
    This endpoint allows doctors to update their own profile or admins to update any doctor's profile.
    """
    return update_doctor_profile(db, doctor_id, profile_data, current_user.id)

@router.delete("/{doctor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_doctor(
    doctor_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """
    Delete a doctor profile
    
    This endpoint allows doctors to delete their own profile or admins to delete any doctor's profile.
    """
    delete_doctor_profile(db, doctor_id, current_user.id)
    return {"message": "Doctor profile deleted successfully"}

@router.put("/me/schedule", response_model=DoctorResponse)
async def update_my_schedule(
    schedule_data: DoctorSchedule,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_doctor)
):
    """
    Update the current doctor's weekly schedule
    
    This endpoint allows doctors to update their weekly availability schedule.
    The schedule is stored as a JSON object with days of the week as keys.
    """
    # Get the doctor profile first (this will auto-create if needed)
    doctor = get_doctor_profile_by_user_id(db, current_user.id)
    return update_doctor_schedule(db, doctor.id, schedule_data.model_dump(), current_user.id)

@router.put("/me/availability", response_model=DoctorResponse)
async def update_my_availability(
    availability_data: DoctorAvailabilityUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_doctor)
):
    """
    Update the current doctor's availability status
    
    This endpoint allows doctors to update their current availability status
    (e.g., AVAILABLE, UNAVAILABLE, ON_LEAVE, ON_CALL).
    """
    # Get the doctor profile first (this will auto-create if needed)
    doctor = get_doctor_profile_by_user_id(db, current_user.id)
    return update_doctor_availability(db, doctor.id, availability_data.status, current_user.id)

@router.get("/me/schedule", response_model=DoctorSchedule)
async def get_my_schedule(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_doctor)
):
    """
    Get the current doctor's weekly schedule
    
    This endpoint allows doctors to view their weekly availability schedule.
    """
    doctor = get_doctor_profile_by_user_id(db, current_user.id)
    
    # Return schedule if it exists, otherwise return empty schedule
    if doctor.schedule:
        return DoctorSchedule(**doctor.schedule)
    else:
        return DoctorSchedule()

@router.get("/me/availability", response_model=DoctorAvailabilityUpdate)
async def get_my_availability(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_doctor)
):
    """
    Get the current doctor's availability status
    
    This endpoint allows doctors to view their current availability status.
    """
    doctor = get_doctor_profile_by_user_id(db, current_user.id)
    return DoctorAvailabilityUpdate(status=doctor.availability_status)
