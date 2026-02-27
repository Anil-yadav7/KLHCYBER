"""SMS alert delivery system using the Twilio API.

This module builds and dispatches SMS alerts for CRITICAL and HIGH severity breaches.
It ensures messages remain within the 160-character limit boundary.
"""

import logging
from typing import Any

from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client

from ..config.settings import settings

logger = logging.getLogger(__name__)


def build_sms_message(breach_name: str, severity: str, email_preview: str) -> str:
    """Build a precise SMS message adhering to the 160-character limit.
    
    If the breach name causes the message to exceed the maximum character
    limit, the breach name will be strategically truncated.
    
    Args:
        breach_name: Title of the platform that suffered the breach.
        severity: Calculated impact severity (e.g., CRITICAL).
        email_preview: Obfuscated email address matching the record.
        
    Returns:
        A strictly constrained string suitable for SMS dispatch.
    """
    base_structure: str = f"[BreachShield] {severity} ALERT: {email_preview} found in {{}} breach. Change your password NOW. Reply STOP to unsubscribe."
    
    # Calculate exactly how much room is left for the breach name
    # The length of '{}' is 2 characters, so subtract 2 from the base framework
    available_length: int = 160 - (len(base_structure) - 2)
    
    if len(breach_name) > available_length:
        # Subtract 3 to account for the ellipsis '...'
        truncated_name: str = breach_name[:(available_length - 3)] + "..."
        message: str = base_structure.format(truncated_name)
    else:
        message: str = base_structure.format(breach_name)

    assert len(message) <= 160, f"SMS parsing error: Length {len(message)} > 160 chars."
    return message


class SMSAlertSender:
    """Service class linking BreachShield high-severity alerts with the Twilio API."""

    def __init__(self) -> None:
        """Initialize the Twilio client utilizing specific settings declarations."""
        self.client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        self.from_number: str = settings.TWILIO_FROM_NUMBER

    def send_breach_sms(
        self,
        to_phone: str,
        breach_name: str,
        severity: str,
        email_preview: str
    ) -> dict[str, Any]:
        """Dispatch a high-priority SMS containing immediate remediation steps.
        
        This mechanism only fires for CRITICAL and HIGH severity impacts.
        
        Args:
            to_phone: The recipient's strictly formatted E.164 phone number.
            breach_name: Title of the target platform.
            severity: The computed risk level.
            email_preview: The user's obfuscated impacted email string.
            
        Returns:
            Dictionary containing final transmission 'status'.
        """
        # SMS Gatekeeper: Only escalate high severity events to SMS
        if severity not in ("CRITICAL", "HIGH"):
            logger.info(f"SMS skipped for {email_preview} — severity '{severity}' is below threshold.")
            return {"status": "skipped", "reason": "severity_below_threshold"}

        # Validate the E.164 format strictly starts with '+' followed by numbers
        if not to_phone.startswith("+") or not to_phone[1:].isdigit():
            logger.error(f"Invalid phone number format provided: {to_phone}")
            return {"status": "failed", "error": "Invalid phone number format"}

        msg_body: str = build_sms_message(
            breach_name=breach_name,
            severity=severity,
            email_preview=email_preview
        )

        try:
            logger.info(f"Attempting to dispatch Twilio SMS to {email_preview} for {severity} breach.")
            message = self.client.messages.create(
                body=msg_body,
                from_=self.from_number,
                to=to_phone
            )
            logger.info(f"Successfully dispatched SMS alert regarding {breach_name}. SID: {message.sid}")
            return {"status": "sent", "sid": message.sid}
            
        except TwilioRestException as e:
            # Twilio-specific failure states (e.g. invalid permissions, carrier filters)
            logger.error(f"Twilio API rejected the SMS dispatch: {e}")
            return {"status": "failed", "error": str(e)}
            
        except Exception as e:
            # Fallback wrapper for network conditions and system errors
            logger.error(f"Unexpected exception while transmitting SMS alert: {e}", exc_info=True)
            return {"status": "failed", "error": str(e)}
