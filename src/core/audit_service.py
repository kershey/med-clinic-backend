from sqlalchemy.orm import Session
from fastapi import Request
from typing import Optional, Dict, Any

from .audit_models import AuditLog
from ..auth.models import User # For typing

async def create_audit_log(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    request: Optional[Request] = None,
    details: Optional[Dict[str, Any]] = None
) -> AuditLog:
    """
    Creates an audit log entry.

    Args:
        db: The database session.
        action: A string describing the action performed (e.g., 'USER_LOGIN_SUCCESS', 'PASSWORD_RESET_REQUEST').
        user_id: The ID of the user who performed the action (if applicable).
        request: The FastAPI request object to extract IP address (if available).
        details: A dictionary containing additional context or data related to the action.

    Returns:
        The created AuditLog object.
    """
    ip_address = None
    if request and request.client:
        ip_address = request.client.host

    audit_entry = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=ip_address,
        details=details
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry 