"""FastAPI routes for querying and analyzing breach data.

This router provides endpoints for retrieving breach events, aggregated statistics,
and generating on-demand remediation advice.
"""

import csv
import io
import logging
from datetime import date, datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from backend.database.connection import get_db_session
from backend.database.models import BreachEvent, MonitoredEmail, RemediationCache
from backend.remediation.llm_advisor import LLMAdvisor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/breaches", tags=["Breach Data"])


# -------------------------------------------------------------------------
# Pydantic Schemas
# -------------------------------------------------------------------------

class BreachListResponse(BaseModel):
    """Schema for a breach event in a list view."""
    id: int
    monitored_email_id: int
    breach_name: str
    breach_date: Optional[date]
    severity: str
    severity_score: int
    data_classes: list[str]
    detected_at: datetime
    is_notified: bool

    model_config = ConfigDict(from_attributes=True)


class PaginatedBreachResponse(BaseModel):
    """Schema for a paginated list of breach events."""
    items: list[BreachListResponse]
    total: int
    limit: int
    offset: int


class BreachStatsResponse(BaseModel):
    """Schema for the aggregated breach statistics dashboard."""
    total_breaches: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    emails_monitored: int
    newest_breach_date: Optional[datetime]
    risk_score: int


class BreachDetailResponse(BaseModel):
    """Schema for the full details of a specific breach event."""
    id: int
    monitored_email_id: int
    breach_name: str
    breach_domain: Optional[str]
    breach_date: Optional[date]
    detected_at: datetime
    data_classes: list[str]
    pwn_count: Optional[int]
    severity: str
    severity_score: int
    is_verified: bool
    is_fabricated: bool
    is_sensitive: bool
    is_notified: bool
    notified_at: Optional[datetime]
    remediation_text: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class RemediationRegenerateResponse(BaseModel):
    """Schema for the result of a remediation regeneration request."""
    breach_event_id: int
    remediation_text: str


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

@router.get("/", response_model=PaginatedBreachResponse)
def list_breaches(
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    limit: int = Query(50, ge=1, le=100, description="Items per page"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db_session),
    current_user: dict[str, Any] = Depends(get_current_user)
) -> dict[str, Any]:
    """Retrieve all breach events associated with the current user's monitored emails."""
    user_id: int = current_user["id"]

    query = db.query(BreachEvent).join(MonitoredEmail).filter(
        MonitoredEmail.user_id == user_id
    )

    if severity:
        query = query.filter(BreachEvent.severity == severity.upper())

    total_count: int = query.count()
    breaches = query.order_by(BreachEvent.detected_at.desc()).offset(offset).limit(limit).all()

    return {
        "items": breaches,
        "total": total_count,
        "limit": limit,
        "offset": offset
    }


@router.get("/stats", response_model=BreachStatsResponse)
def get_breach_stats(
    db: Session = Depends(get_db_session),
    current_user: dict[str, Any] = Depends(get_current_user)
) -> dict[str, Any]:
    """Calculate and return aggregated breach statistics for the dashboard."""
    user_id: int = current_user["id"]

    emails_monitored: int = db.query(MonitoredEmail).filter(
        MonitoredEmail.user_id == user_id,
        MonitoredEmail.is_active == True
    ).count()

    breaches = db.query(BreachEvent).join(MonitoredEmail).filter(
        MonitoredEmail.user_id == user_id
    ).all()

    total_breaches: int = len(breaches)
    critical_count: int = sum(1 for b in breaches if b.severity == "CRITICAL")
    high_count: int = sum(1 for b in breaches if b.severity == "HIGH")
    medium_count: int = sum(1 for b in breaches if b.severity == "MEDIUM")
    low_count: int = sum(1 for b in breaches if b.severity == "LOW")

    newest_breach_date: Optional[datetime] = None
    if breaches:
        latest = max(breaches, key=lambda b: b.detected_at)
        newest_breach_date = latest.detected_at

    raw_risk_score: int = (critical_count * 25) + (high_count * 10) + (medium_count * 5) + (low_count * 1)
    risk_score: int = min(raw_risk_score, 100)

    return {
        "total_breaches": total_breaches,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "emails_monitored": emails_monitored,
        "newest_breach_date": newest_breach_date,
        "risk_score": risk_score
    }


@router.get("/export/csv")
def export_breaches_csv(
    db: Session = Depends(get_db_session),
    current_user: dict[str, Any] = Depends(get_current_user)
) -> StreamingResponse:
    """Export all of the user's breach data as a downloadable CSV file."""
    user_id: int = current_user["id"]

    breaches = db.query(BreachEvent).join(MonitoredEmail).filter(
        MonitoredEmail.user_id == user_id
    ).order_by(BreachEvent.detected_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["breach_name", "severity", "breach_date", "detected_at", "data_classes"])

    for b in breaches:
        b_date: str = b.breach_date.isoformat() if b.breach_date else "Unknown"
        d_at: str = b.detected_at.isoformat() if b.detected_at else "Unknown"
        classes_str: str = ", ".join(b.data_classes) if b.data_classes else ""
        writer.writerow([b.breach_name, b.severity, b_date, d_at, classes_str])

    output.seek(0)
    
    current_date: str = datetime.utcnow().strftime("%Y-%m-%d")
    filename: str = f"breachshield_export_{current_date}.csv"
    
    headers: dict[str, str] = {
        "Content-Disposition": f"attachment; filename={filename}"
    }

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers=headers
    )


@router.get("/{breach_id}", response_model=BreachDetailResponse)
def get_breach_details(
    breach_id: int,
    db: Session = Depends(get_db_session),
    current_user: dict[str, Any] = Depends(get_current_user)
) -> BreachEvent:
    """Retrieve exhaustive details for a specific breach incident."""
    user_id: int = current_user["id"]

    breach = db.query(BreachEvent).join(MonitoredEmail).filter(
        BreachEvent.id == breach_id,
        MonitoredEmail.user_id == user_id
    ).first()

    if not breach:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Breach event not found.")

    return breach


@router.post("/{breach_id}/regenerate-remediation", response_model=RemediationRegenerateResponse)
def regenerate_remediation(
    breach_id: int,
    db: Session = Depends(get_db_session),
    current_user: dict[str, Any] = Depends(get_current_user)
) -> dict[str, Any]:
    """Force Anthropics Claude to regenerate the remediation workflow, ignoring cache."""
    user_id: int = current_user["id"]

    breach = db.query(BreachEvent).join(MonitoredEmail).filter(
        BreachEvent.id == breach_id,
        MonitoredEmail.user_id == user_id
    ).first()

    if not breach:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Breach event not found.")

    advisor = LLMAdvisor()
    
    # 1. Manually compute the deterministic cache key to locate it
    cache_key: str = advisor._build_cache_key(breach.breach_name, breach.data_classes)
    
    # 2. Delete the specific cache entry from the system
    db.query(RemediationCache).filter(RemediationCache.cache_key == cache_key).delete()
    db.commit()

    # 3. Request fresh remediation advice (which will automatically re-cache)
    fresh_remediation: str = advisor.generate_remediation(
        breach_name=breach.breach_name,
        data_classes=breach.data_classes,
        db_session=db
    )

    breach.remediation_text = fresh_remediation
    db.commit()

    return {
        "breach_event_id": breach.id,
        "remediation_text": fresh_remediation
    }
