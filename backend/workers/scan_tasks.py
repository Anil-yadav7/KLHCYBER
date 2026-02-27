"""Celery tasks for BreachShield orchestration.

Contains all Celery task functions that power automated breach scanning.
This is the orchestration layer that wires all components together.
"""

import logging
from datetime import datetime, timedelta
from typing import Any

from .celery_app import celery_app
from ..alerts.email_alert import EmailAlertSender
from ..alerts.sms_alert import SMSAlertSender
from ..database.connection import get_db
from ..database.models import AlertLog, BreachEvent, MonitoredEmail, User
from ..ingestion.hibp_client import HIBPClient
from ..remediation.llm_advisor import LLMAdvisor
from ..scoring.severity_engine import calculate_severity
from ..utils.crypto import decrypt_email

logger = logging.getLogger(__name__)


@celery_app.task(name="backend.workers.scan_tasks.scan_all_monitored_emails", bind=True, max_retries=3)
def scan_all_monitored_emails(self: Any) -> dict[str, Any]:
    """Perform a comprehensive periodic sweep across all active monitored emails.
    
    Yields individual subtasks for each email sequence.
    
    Returns:
        Dictionary mapping dispatch operational outcome.
    """
    with get_db() as db_session:
        try:
            active_emails: list[MonitoredEmail] = db_session.query(MonitoredEmail).filter(
                MonitoredEmail.is_active == True
            ).all()

            for email in active_emails:
                # Dispatch execution to workers efficiently via delay instead of serial processing
                process_single_email.delay(email.id)

            logger.info(f"Dispatched asynchronous suite of {len(active_emails)} email scans.")
            return {"status": "dispatched", "email_count": len(active_emails)}
            
        except Exception as e:
            logger.error(f"Failed to scan all monitored emails: {e}")
            try:
                self.retry(exc=e)
            except self.MaxRetriesExceededError:
                return {"status": "failed", "error": str(e)}
            return {"status": "retrying"}


@celery_app.task(name="backend.workers.scan_tasks.process_single_email", bind=True, max_retries=3, default_retry_delay=120)
def process_single_email(self: Any, monitored_email_id: int) -> dict[str, Any]:
    """Execute a highly-specific HIBP API sweep against exactly one address record.
    
    Args:
        monitored_email_id: ID mapped to the database object.
        
    Returns:
        Dictionary containing tracking ID and discoveries.
    """
    count: int = 0
    with get_db() as db_session:
        try:
            monitored_email = db_session.query(MonitoredEmail).filter(MonitoredEmail.id == monitored_email_id).first()
            if not monitored_email or not monitored_email.is_active:
                logger.info(f"MonitoredEmail '{monitored_email_id}' is inactive or missing. Aborting scan.")
                return {"email_id": monitored_email_id, "new_breaches": 0}

            decrypted_email: str = decrypt_email(monitored_email.email_encrypted)
            
            with HIBPClient() as client:
                breaches = client.get_breaches_for_email(decrypted_email)
                advisor = LLMAdvisor()
                
                for raw_breach in breaches:
                    breach_data = client.normalize_breach(raw_breach)
                    
                    # Prevent redundant entries
                    existing = db_session.query(BreachEvent).filter_by(
                        monitored_email_id=monitored_email_id,
                        breach_name=breach_data["name"]
                    ).first()
                    
                    if existing:
                        continue
                        
                    severity_result = calculate_severity(breach_data["data_classes"])
                    
                    remediation = advisor.generate_remediation(
                        breach_name=breach_data["name"],
                        data_classes=breach_data["data_classes"],
                        db_session=db_session
                    )
                    
                    parsed_breach_date = None
                    if breach_data["breach_date"]:
                        try:
                            parsed_breach_date = datetime.strptime(breach_data["breach_date"], "%Y-%m-%d").date()
                        except ValueError:
                            pass
                            
                    new_breach = BreachEvent(
                        monitored_email_id=monitored_email_id,
                        breach_name=breach_data["name"],
                        breach_domain=breach_data["domain"],
                        breach_date=parsed_breach_date,
                        detected_at=datetime.utcnow(),
                        data_classes=breach_data["data_classes"],
                        pwn_count=breach_data["pwn_count"],
                        severity=severity_result.label,
                        severity_score=severity_result.score,
                        is_verified=breach_data["is_verified"],
                        is_fabricated=breach_data["is_fabricated"],
                        is_sensitive=breach_data["is_sensitive"],
                        remediation_text=remediation
                    )
                    
                    db_session.add(new_breach)
                    db_session.flush()  # Acquire ID before commit
                    count += 1
                    
                    # Defer notification workflow into separate reliable task
                    dispatch_alerts.delay(new_breach.id)
                    
            monitored_email.last_scanned_at = datetime.utcnow()
            monitored_email.scan_count += 1
            db_session.commit()
            
            logger.info(f"Completed scan for ID {monitored_email_id}, discovered {count} new breaches.")
            return {"email_id": monitored_email_id, "new_breaches": count}
            
        except Exception as e:
            logger.error(f"Failed to scan email {monitored_email_id}: {e}", exc_info=True)
            db_session.rollback()
            try:
                self.retry(exc=e)
            except self.MaxRetriesExceededError:
                return {"email_id": monitored_email_id, "new_breaches": count, "error": str(e)}
            return {"email_id": monitored_email_id, "new_breaches": count, "status": "retrying"}


@celery_app.task(name="backend.workers.scan_tasks.dispatch_alerts", bind=True, max_retries=2)
def dispatch_alerts(self: Any, breach_event_id: int) -> dict[str, Any]:
    """Orchestrate sending multi-channel alert delivery for a qualified breach event.
    
    Args:
        breach_event_id: The table ID linking to breach severity metrics.
        
    Returns:
        Mapping of platforms successfully pushed to.
    """
    channels: list[str] = []
    with get_db() as db_session:
        try:
            breach_event = db_session.query(BreachEvent).filter(BreachEvent.id == breach_event_id).first()
            if not breach_event or breach_event.is_notified:
                logger.warning(f"Aborting dispatch. BreachEvent {breach_event_id} missing or already notified.")
                return {"breach_event_id": breach_event_id, "channels_notified": channels}
                
            monitored_email = breach_event.monitored_email
            owner = monitored_email.owner
            
            # decrypt_email required here in previous spec to get full email? The owner has the real email.
            # However, we must pass the obfuscated mapped email downstream
            preview_address: str = monitored_email.email_preview
            date_str: str = breach_event.breach_date.strftime("%Y-%m-%d") if breach_event.breach_date else "Unknown"
            
            email_agent = EmailAlertSender()
            email_result = email_agent.send_breach_alert(
                to_email=owner.email,
                breach_name=breach_event.breach_name,
                severity=breach_event.severity,
                data_classes=breach_event.data_classes,
                remediation_text=breach_event.remediation_text or "",
                email_preview=preview_address,
                breach_date=date_str
            )
            
            email_log = AlertLog(
                breach_event_id=breach_event_id,
                channel="email",
                recipient=owner.email,
                status=email_result.get("status", "failed"),
                error_message=email_result.get("error")
            )
            db_session.add(email_log)
            if email_result.get("status") == "sent":
                channels.append("email")
                
            sms_agent = SMSAlertSender()
            phone_number: str | None = getattr(owner, "phone_number", None)
            
            if phone_number:
                sms_result = sms_agent.send_breach_sms(
                    to_phone=phone_number,
                    breach_name=breach_event.breach_name,
                    severity=breach_event.severity,
                    email_preview=preview_address
                )
                
                sms_log = AlertLog(
                    breach_event_id=breach_event_id,
                    channel="sms",
                    recipient=phone_number,
                    status=sms_result.get("status", "failed"),
                    error_message=sms_result.get("error")
                )
                db_session.add(sms_log)
                if sms_result.get("status") == "sent":
                    channels.append("sms")
                    
            breach_event.is_notified = True
            breach_event.notified_at = datetime.utcnow()
            db_session.commit()
            
            return {"breach_event_id": breach_event_id, "channels_notified": channels}
            
        except Exception as e:
            logger.error(f"Error dispatching alerts for event {breach_event_id}: {e}", exc_info=True)
            db_session.rollback()
            try:
                self.retry(exc=e)
            except self.MaxRetriesExceededError:
                return {"breach_event_id": breach_event_id, "channels_notified": channels, "error": str(e)}
            return {"breach_event_id": breach_event_id, "channels_notified": channels, "status": "retrying"}


@celery_app.task(name="backend.workers.scan_tasks.send_weekly_summaries")
def send_weekly_summaries() -> dict[str, Any]:
    """Compile aggregated breach statistics from the last 7 days and dispatch.
    
    Returns:
        Mapping tracking processing completion counts.
    """
    total_users_notified: int = 0
    with get_db() as db_session:
        try:
            active_users: list[User] = db_session.query(User).filter(User.is_active == True).all()
            email_agent = EmailAlertSender()
            seven_days_ago: datetime = datetime.utcnow() - timedelta(days=7)
            
            for user in active_users:
                monitored_emails = user.monitored_emails
                total_monitored: int = len(monitored_emails)
                
                if total_monitored == 0:
                    continue
                    
                total_breaches: int = 0
                new_this_week: int = 0
                highest_score: int = 0
                
                for account in monitored_emails:
                    for breach in account.breach_events:
                        total_breaches += 1
                        if breach.detected_at and breach.detected_at >= seven_days_ago:
                            new_this_week += 1
                        if breach.severity_score > highest_score:
                            highest_score = breach.severity_score
                            
                summary_stats: dict[str, Any] = {
                    "total_monitored": total_monitored,
                    "total_breaches": total_breaches,
                    "new_this_week": new_this_week,
                    "risk_score": highest_score
                }
                
                email_agent.send_weekly_summary(
                    to_email=user.email,
                    summary_stats=summary_stats
                )
                
                total_users_notified += 1
                
            return {"users_notified": total_users_notified}
            
        except Exception as e:
            logger.error(f"Failed to transmit weekly statistical summaries: {e}", exc_info=True)
            return {"users_notified": total_users_notified, "status": "failed", "error": str(e)}
