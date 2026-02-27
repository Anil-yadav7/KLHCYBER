"""FastAPI routes for managing monitored email addresses.

This router handles all CRUD operations for the MonitoredEmail entity,
including adding new emails, listing active monitoring tasks, and fetching
breach histories.
"""

import hashlib
import logging
from datetime import date, datetime
from typing import Any, Optional

from email_validator import EmailNotValidError, validate_email
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from backend.database.connection import get_db_session
from backend.database.models import BreachEvent, MonitoredEmail
from backend.utils.crypto import encrypt_email
from backend.workers.scan_tasks import process_single_email

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/emails", tags=["Email Monitoring"])


# -------------------------------------------------------------------------
# Pydantic Schemas
# -------------------------------------------------------------------------

class EmailCreateRequest(BaseModel):
    """Payload validating the request to add a new monitored email."""
    email: str
    phone_number: Optional[str] = None


class BreachEventResponse(BaseModel):
    """Serialization schema for returning safe BreachEvent data to clients."""
    id: int
    breach_name: str
    breach_date: Optional[date]
    severity: str
    data_classes: list[str]
    detected_at: datetime
    is_notified: bool

    model_config = ConfigDict(from_attributes=True)


class EmailResponse(BaseModel):
    """Serialization schema for returning monitored email abstractions.
    
    Explicitly omits the decrypted email to preserve security invariants.
    """
    id: int
    email_preview: str
    is_active: bool
    added_at: datetime
    last_scanned_at: Optional[datetime]
    scan_count: int
    breach_count: int

    model_config = ConfigDict(from_attributes=True)


# -------------------------------------------------------------------------
# Dependencies
# -------------------------------------------------------------------------

def get_current_user() -> dict[str, Any]:
    """Mock authentication dependency.
    
    Returns:
        A hardcoded dictionary representing the authenticated user state.
    """
    return {"id": 1, "username": "demo_user"}


# -------------------------------------------------------------------------
# API Routes
# -------------------------------------------------------------------------

@router.post("/", response_model=EmailResponse, status_code=status.HTTP_201_CREATED)
def add_monitored_email(
    request: EmailCreateRequest,
    db: Session = Depends(get_db_session),
    current_user: dict[str, Any] = Depends(get_current_user)
) -> dict[str, Any]:
    """Add a new email address to the monitoring queue.
    
    Validates the structure of the incoming address, encrypts it on disk,
    and immediately queues a Celery background job to scan it against HIBP.
    
    Args:
        request: The parsed, validated JSON payload.
        db: The injected SQLAlchemy active database session.
        current_user: The resolved authentication context.
        
    Returns:
        The instantiated monitored email serialized using EmailResponse.
        
    Raises:
        HTTPException: If the email is invalid (400) or already monitored (409).
    """
    try:
        # Resolve to a normalized address, rejecting malformed structures immediately
        valid_email_info = validate_email(request.email, check_deliverability=False)
        normalized_email: str = valid_email_info.normalized.lower()
    except EmailNotValidError as e:
        logger.warning(f"Rejecting invalid email submission: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Cryptographic transformations
    email_hash_obj = hashlib.sha256(normalized_email.encode("utf-8"))
    email_hash: str = email_hash_obj.hexdigest()

    # Prevent duplicating monitoring records
    user_id: int = current_user["id"]
    existing = db.query(MonitoredEmail).filter(
        MonitoredEmail.user_id == user_id,
        MonitoredEmail.email_hash == email_hash
    ).first()

    if existing:
        if existing.is_active:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This email address is already actively monitored by your account."
            )
        else:
            # If it exists but is inactive, user is implicitly restoring tracking
            existing.is_active = True
            db.flush()
            
            # Defer initial deep scan into the background
            process_single_email.delay(existing.id)
            db.commit()
            
            # Generate expected response dict matching EmailResponse schema layout
            breach_count: int = db.query(BreachEvent).filter_by(monitored_email_id=existing.id).count()
            return {
                "id": existing.id,
                "email_preview": existing.email_preview,
                "is_active": existing.is_active,
                "added_at": existing.added_at,
                "last_scanned_at": existing.last_scanned_at,
                "scan_count": existing.scan_count,
                "breach_count": breach_count
            }

    # Derive the obfuscated preview (e.g. joh***@gmail.com)
    username_part, domain_part = normalized_email.split("@")
    if len(username_part) > 3:
        preview = f"{username_part[:3]}***@{domain_part}"
    else:
        preview = f"{username_part}***@{domain_part}"

    encrypted_val: str = encrypt_email(normalized_email)

    new_monitored_email = MonitoredEmail(
        email_encrypted=encrypted_val,
        email_hash=email_hash,
        email_preview=preview,
        user_id=user_id,
        is_active=True,
        scan_count=0
    )
    
    db.add(new_monitored_email)
    db.flush()  # Acquire auto-increment ID
    
    # Defer the synchronous heavy-lifting into Celery
    process_single_email.delay(new_monitored_email.id)
    
    db.commit()
    logger.info(f"Successfully added monitoring task for email {preview}")

    return {
        "id": new_monitored_email.id,
        "email_preview": new_monitored_email.email_preview,
        "is_active": new_monitored_email.is_active,
        "added_at": new_monitored_email.added_at,
        "last_scanned_at": new_monitored_email.last_scanned_at,
        "scan_count": new_monitored_email.scan_count,
        "breach_count": 0
    }


@router.get("/", response_model=list[EmailResponse])
def list_monitored_emails(
    db: Session = Depends(get_db_session),
    current_user: dict[str, Any] = Depends(get_current_user)
) -> list[dict[str, Any]]:
    """Retrieve all actively monitored emails assigned to the current user.
    
    Args:
        db: Automatically injected database connection pool session.
        current_user: Authenticated identity representation.
        
    Returns:
        List of serialized EmailResponse models.
    """
    user_id: int = current_user["id"]
    emails: list[MonitoredEmail] = db.query(MonitoredEmail).filter(
        MonitoredEmail.user_id == user_id,
        MonitoredEmail.is_active == True
    ).all()

    result_list: list[dict[str, Any]] = []
    for email in emails:
        breach_count: int = db.query(BreachEvent).filter_by(monitored_email_id=email.id).count()
        result_list.append({
            "id": email.id,
            "email_preview": email.email_preview,
            "is_active": email.is_active,
            "added_at": email.added_at,
            "last_scanned_at": email.last_scanned_at,
            "scan_count": email.scan_count,
            "breach_count": breach_count
        })

    return result_list


@router.delete("/{email_id}", status_code=status.HTTP_204_NO_CONTENT)
def stop_monitoring_email(
    email_id: int,
    db: Session = Depends(get_db_session),
    current_user: dict[str, Any] = Depends(get_current_user)
) -> None:
    """Soft delete an actively monitored email address.
    
    Args:
        email_id: Subject primary key mapped in the URL path segment.
        db: Request-bound database session connection.
        current_user: Request-bound identity dictionary.
        
    Raises:
        HTTPException: 404 Not Found if record cannot be matched to the user identity.
    """
    user_id: int = current_user["id"]
    email: MonitoredEmail | None = db.query(MonitoredEmail).filter(
        MonitoredEmail.id == email_id,
        MonitoredEmail.user_id == user_id
    ).first()

    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email record not found.")

    email.is_active = False
    db.commit()
    logger.info(f"User {user_id} stopped monitoring email {email.email_preview}")


@router.get("/{email_id}/breaches", response_model=list[BreachEventResponse])
def get_breaches_for_email(
    email_id: int,
    db: Session = Depends(get_db_session),
    current_user: dict[str, Any] = Depends(get_current_user)
) -> list[BreachEvent]:
    """Retrieve all chronicled data breach exposures linked against a monitored address.
    
    Args:
        email_id: Identifying handle for the target email address.
        db: Database session factory instance context.
        current_user: Associated security identity.
        
    Returns:
        Ordered array mapping SQLAlchemy BreachEvent rows via BreachEventResponse schema.
        
    Raises:
        HTTPException: 404 Not Found if the email record doesn't track back to this user.
    """
    # Enforce strict IDOR (Insecure Direct Object Reference) mitigation
    user_id: int = current_user["id"]
    email_exists = db.query(MonitoredEmail.id).filter(
        MonitoredEmail.id == email_id,
        MonitoredEmail.user_id == user_id
    ).first()

    if not email_exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Email record not found."
        )

    breaches = db.query(BreachEvent).filter(
        BreachEvent.monitored_email_id == email_id
    ).order_by(BreachEvent.detected_at.desc()).all()

    return breaches
