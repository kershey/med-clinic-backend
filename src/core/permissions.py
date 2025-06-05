"""
Core permissions utilities for role-based access control.
"""
from enum import Enum
from typing import Dict, List, Set, Optional
from ..auth.models import UserRole

class Permission(str, Enum):
    """
    Permission types for role-based access control.
    """
    # User management permissions
    VIEW_USERS = "view_users"
    CREATE_USER = "create_user"
    UPDATE_USER = "update_user"
    DELETE_USER = "delete_user"
    
    # Patient-specific permissions
    VIEW_PATIENT_RECORDS = "view_patient_records"
    CREATE_PATIENT = "create_patient"
    UPDATE_PATIENT = "update_patient"
    
    # Doctor-specific permissions
    VIEW_DOCTOR_SCHEDULE = "view_doctor_schedule"
    CREATE_DOCTOR = "create_doctor"
    UPDATE_DOCTOR = "update_doctor"
    
    # Appointment permissions
    VIEW_APPOINTMENTS = "view_appointments"
    CREATE_APPOINTMENT = "create_appointment"
    UPDATE_APPOINTMENT = "update_appointment"
    CANCEL_APPOINTMENT = "cancel_appointment"
    
    # Admin permissions
    APPROVE_USERS = "approve_users"
    SYSTEM_SETTINGS = "system_settings"
    VIEW_LOGS = "view_logs"


# Role-based permission mapping
ROLE_PERMISSIONS: Dict[UserRole, List[Permission]] = {
    UserRole.ADMIN: [
        # Admin has all permissions
        Permission.VIEW_USERS,
        Permission.CREATE_USER,
        Permission.UPDATE_USER,
        Permission.DELETE_USER,
        Permission.VIEW_PATIENT_RECORDS,
        Permission.CREATE_PATIENT,
        Permission.UPDATE_PATIENT,
        Permission.VIEW_DOCTOR_SCHEDULE,
        Permission.CREATE_DOCTOR,
        Permission.UPDATE_DOCTOR,
        Permission.VIEW_APPOINTMENTS,
        Permission.CREATE_APPOINTMENT,
        Permission.UPDATE_APPOINTMENT,
        Permission.CANCEL_APPOINTMENT,
        Permission.APPROVE_USERS,
        Permission.SYSTEM_SETTINGS,
        Permission.VIEW_LOGS,
    ],
    UserRole.STAFF: [
        # Staff has user management and appointment permissions
        Permission.VIEW_USERS,
        Permission.CREATE_USER,
        Permission.UPDATE_USER,
        Permission.VIEW_PATIENT_RECORDS,
        Permission.CREATE_PATIENT,
        Permission.UPDATE_PATIENT,
        Permission.VIEW_DOCTOR_SCHEDULE,
        Permission.VIEW_APPOINTMENTS,
        Permission.CREATE_APPOINTMENT,
        Permission.UPDATE_APPOINTMENT,
        Permission.CANCEL_APPOINTMENT,
    ],
    UserRole.DOCTOR: [
        # Doctors can view their own schedule and patient records
        Permission.VIEW_PATIENT_RECORDS,
        Permission.VIEW_DOCTOR_SCHEDULE,
        Permission.VIEW_APPOINTMENTS,
        Permission.UPDATE_APPOINTMENT,
    ],
    UserRole.PATIENT: [
        # Patients can manage their own appointments
        Permission.VIEW_APPOINTMENTS,
        Permission.CREATE_APPOINTMENT,
        Permission.CANCEL_APPOINTMENT,
    ],
}


def get_permissions_for_role(role: UserRole) -> Set[Permission]:
    """
    Get permissions for a specific role.
    
    Args:
        role: User role
        
    Returns:
        Set[Permission]: Set of permissions for the role
    """
    return set(ROLE_PERMISSIONS.get(role, []))


def has_permission(role: UserRole, permission: Permission) -> bool:
    """
    Check if a role has a specific permission.
    
    Args:
        role: User role
        permission: Permission to check
        
    Returns:
        bool: True if the role has the permission
    """
    return permission in get_permissions_for_role(role)


def validate_permissions(role: UserRole, required_permissions: List[Permission]) -> bool:
    """
    Validate that a role has all required permissions.
    
    Args:
        role: User role
        required_permissions: List of required permissions
        
    Returns:
        bool: True if the role has all required permissions
    """
    user_permissions = get_permissions_for_role(role)
    return all(perm in user_permissions for perm in required_permissions)
