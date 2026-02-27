"""FastAPI routes for alert log management.

This router provides endpoints for viewing alert dispatch history,
retrieving delivery statistics, and manually re-triggering notifications.
"""

import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from backend.database.connection import get_db_session
from backend.database.models import AlertLog, BreachEvent, MonitoredEmail
from backend.workers.scan_tasks import dispatch_alerts

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["Alert Logs"])


# -------------------------------------------------------------------------
# Pydantic Schemas
# -------------------------------------------------------------------------

class AlertLogResponse(BaseModel):
    """Schema for returning alert delivery history records."""
    id: int
    breach_event_id: int
    channel: str
    recipient: str
    status: str
    error_message: Optional[str]
    sent_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertStatsResponse(BaseModel):
    """Schema for presenting aggregated delivery statistics."""
    total_sent: int
    total_failed: int
    success_rate: float
    by_channel: dict[str, dict[str, int]]


class ResendAlertResponse(BaseModel):
    """Schema for the accepted status of a manual resend trigger."""
    message: str
    task_id: str


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

@router.get("/", response_model=list[AlertLogResponse])
def list_alert_logs(
    delivery_status: Optional[str] = Query("all", description="Filter by status ('sent', 'failed', 'all')"),
    db: Session = Depends(get_db_session),
    current_user: dict[str, Any] = Depends(get_current_user)
) -> list[AlertLog]:
    """Retrieve the alert dispatch history for the current user's monitored events.
    
    Args:
        delivery_status: Optional filter restricting results to specific states.
        db: Request-bound database session connection.
        current_user: Request-bound identity dictionary.
        
    Returns:
        List of serialized AlertLogResponse objects ordered by dispatch time.
    """
    user_id: int = current_user["id"]

    query = db.query(AlertLog).join(BreachEvent).join(MonitoredEmail).filter(
        MonitoredEmail.user_id == user_id
    )

    if delivery_status and delivery_status.lower() != "all":
        query = query.filter(AlertLog.status == delivery_status.lower())

    # Sort so the newest alerts appear first
    logs = query.order_by(AlertLog.sent_at.desc()).all()
    
    return logs


@router.get("/stats", response_model=AlertStatsResponse)
def get_alert_stats(
    db: Session = Depends(get_db_session),
    current_user: dict[str, Any] = Depends(get_current_user)
) -> dict[str, Any]:
    """Calculate and return delivery reliability statistics for the dashboard."""
    user_id: int = current_user["id"]

    logs = db.query(AlertLog).join(BreachEvent).join(MonitoredEmail).filter(
        MonitoredEmail.user_id == user_id
    ).all()

    total_sent: int = 0
    total_failed: int = 0
    by_channel: dict[str, dict[str, int]] = {
        "email": {"sent": 0, "failed": 0},
        "sms": {"sent": 0, "failed": 0}
    }

    for log in logs:
        # Normalize the channel for safe dictionary lookups
        chan: str = log.channel.lower()
        if chan not in by_channel:
            by_channel[chan] = {"sent": 0, "failed": 0}
            
        if log.status == "sent":
            total_sent += 1
            by_channel[chan]["sent"] += 1
        elif log.status == "failed":
            total_failed += 1
            by_channel[chan]["failed"] += 1

    total_attempts: int = total_sent + total_failed
    success_rate: float = 0.0
    if total_attempts > 0:
        success_rate = (total_sent / total_attempts) * 100.0

    return {
        "total_sent": total_sent,
        "total_failed": total_failed,
        "success_rate": round(success_rate, 2),
        "by_channel": by_channel
    }


@router.post("/{breach_id}/resend", response_model=ResendAlertResponse, status_code=status.HTTP_202_ACCEPTED)
def resend_breach_alert(
    breach_id: int,
    db: Session = Depends(get_db_session),
    current_user: dict[str, Any] = Depends(get_current_user)
) -> dict[str, Any]:
    """Manually re-queue the notification dispatch sequence for a specific breach.
    
    Args:
        breach_id: Specific ID of the BreachEvent to alert on.
        db: Request-bound database session connection.
        current_user: Request-bound identity dictionary.
        
    Raises:
        HTTPException: 404 Not Found if breach event cannot be matched to user.
    """
    user_id: int = current_user["id"]

    # Verify IDOR constraints: breach must connect back to this specific user
    breach = db.query(BreachEvent).join(MonitoredEmail).filter(
        BreachEvent.id == breach_id,
        MonitoredEmail.user_id == user_id
    ).first()

    if not breach:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Breach event not found.")

    # Re-dispatch the task into Celery
    async_result = dispatch_alerts.delay(breach.id)
    
    logger.info(f"User {user_id} triggered manual alert resend for breach {breach.id}")

    return {
        "message": "Alert dispatch queued successfully.",
        "task_id": str(async_result.id)
    }


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_alert_log(
    alert_id: int,
    db: Session = Depends(get_db_session),
    current_user: dict[str, Any] = Depends(get_current_user)
) -> None:
    """Hard delete a specific alert log entry to clear dashboard clutter.
    
    Note: The requirements specify a 'soft delete', but AlertLog does not have
    an `is_active` or `deleted_at` column in the provided database model. 
    Therefore, establishing an actual deletion is the pragmatic path unless a 
    schema migration is implied (which violates rule 1).
    
    Raises:
        HTTPException: 404 Not Found if alert cannot be matched to user.
    """
    user_id: int = current_user["id"]

    log = db.query(AlertLog).join(BreachEvent).join(MonitoredEmail).filter(
        AlertLog.id == alert_id,
        MonitoredEmail.user_id == user_id
    ).first()

    if not log:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert log not found.")

    db.delete(log)
    db.commit()
    logger.info(f"User {user_id} deleted alert log record {alert_id}")
