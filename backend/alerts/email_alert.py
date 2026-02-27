"""Email alert delivery system using the SendGrid API.

This module builds and dispatches professional HTML emails to notify users
when their monitored credentials have been compromised in a data breach.
"""

import logging
from typing import Any

import sendgrid
from sendgrid.helpers.mail import Content, Email, Mail, To

from ..config.settings import settings

logger = logging.getLogger(__name__)


def build_html_email(
    breach_name: str,
    severity: str,
    data_classes: list[str],
    remediation_text: str,
    email_preview: str,
    breach_date: str
) -> str:
    """Construct a complete HTML email body for a breach alert.
    
    Format adheres to strict inline CSS rules for maximum compatibility with
    various email clients.
    
    Args:
        breach_name: The name of the platform breached.
        severity: The severity tier (LOW, MEDIUM, HIGH, CRITICAL).
        data_classes: A list of the specific data types exposed.
        remediation_text: AI-generated advice for the user.
        email_preview: The obfuscated monitored email address.
        breach_date: The date the breach occurred.
        
    Returns:
        A formatted HTML string.
    """
    # Determine the strict hex code banner color based on severity tier
    banner_color: str = "#808080"  # Gray default
    if severity == "CRITICAL":
        banner_color = "#D32F2F"  # Red
    elif severity == "HIGH":
        banner_color = "#ED6C02"  # Orange
    elif severity == "MEDIUM":
        banner_color = "#ED6C02"  # Yellow-Orange
    elif severity == "LOW":
        banner_color = "#2E7D32"  # Green

    # Build the bulleted <li> list from the data classes
    data_list_items: str = "".join([f"<li>{item}</li>" for item in data_classes])

    html_template: str = f"""
    <!DOCTYPE html>
    <html>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 20px;">
            <tr>
                <td align="center">
                    <table border="0" cellpadding="0" cellspacing="0" width="600" style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                        
                        <!-- Header -->
                        <tr>
                            <td align="center" style="padding: 20px 0; background-color: #1a1a1a; color: #ffffff;">
                                <h2 style="margin: 0; font-size: 24px;">🛡️ BreachShield Alert</h2>
                            </td>
                        </tr>
                        
                        <!-- Severity Banner -->
                        <tr>
                            <td align="center" style="padding: 10px 0; background-color: {banner_color}; color: #ffffff;">
                                <h3 style="margin: 0; font-size: 18px;">SEVERITY: {severity}</h3>
                            </td>
                        </tr>
                        
                        <!-- Body Content -->
                        <tr>
                            <td style="padding: 30px 40px;">
                                <h1 style="color: #333333; margin-top: 0; font-size: 28px;">{breach_name}</h1>
                                <p style="font-size: 16px; color: #555555; line-height: 1.5;">
                                    Your monitored email <strong>{email_preview}</strong> was found in this breach.
                                </p>
                                <p style="font-size: 14px; color: #777777;">
                                    Breach date: {breach_date}
                                </p>
                                
                                <h3 style="color: #333333; margin-top: 25px; border-bottom: 2px solid #eeeeee; padding-bottom: 5px;">What was exposed:</h3>
                                <ul style="color: #555555; font-size: 15px; line-height: 1.6;">
                                    {data_list_items}
                                </ul>
                                
                                <h3 style="color: #333333; margin-top: 25px; border-bottom: 2px solid #eeeeee; padding-bottom: 5px;">Action Plan:</h3>
                                <pre style="background-color: #f8f9fa; padding: 15px; border-radius: 4px; border: 1px solid #e9ecef; color: #333333; font-family: Arial, sans-serif; font-size: 14px; line-height: 1.6; white-space: pre-wrap;">{remediation_text}</pre>
                            </td>
                        </tr>
                        
                        <!-- Footer -->
                        <tr>
                            <td align="center" style="padding: 20px; background-color: #f8f9fa; border-top: 1px solid #eeeeee; color: #888888; font-size: 12px;">
                                <p style="margin: 0;">BreachShield — Protecting your digital identity</p>
                                <p style="margin: 5px 0 0 0;">This is an automated security alert.</p>
                            </td>
                        </tr>
                        
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    return html_template


class EmailAlertSender:
    """Service class linking BreachShield alerts with the SendGrid API."""

    def __init__(self) -> None:
        """Initialize the SendGrid client utilizing strict settings definitions."""
        self.sg = sendgrid.SendGridAPIClient(api_key=settings.SENDGRID_API_KEY)
        self.from_email: str = settings.FROM_EMAIL
        self.from_name: str = settings.FROM_NAME

    def send_breach_alert(
        self,
        to_email: str,
        breach_name: str,
        severity: str,
        data_classes: list[str],
        remediation_text: str,
        email_preview: str,
        breach_date: str = "Unknown"
    ) -> dict[str, Any]:
        """Dispatch a single structured email alert informing a user of a compromised account.
        
        Args:
            to_email: Full, unencrypted recipient email address.
            breach_name: Title of the platform that suffered the breach.
            severity: Calculated impact severity.
            data_classes: Array of exposed data elements.
            remediation_text: AI-generated action plan.
            email_preview: Obfuscated email address matching the breached record.
            breach_date: Human-readable date indicating when the breach happened.
            
        Returns:
            Dictionary containing final delivery 'status', robust to exceptions.
        """
        # Determine strict subject line nomenclature based on alert payload severity
        subject: str = f"ℹ️ Notice: Your email found in the {breach_name} breach"
        if severity in ("CRITICAL", "HIGH"):
            subject = f"🚨 URGENT: Your credentials found in the {breach_name} breach"
        elif severity == "MEDIUM":
            subject = f"⚠️ Alert: Your data found in the {breach_name} breach"

        html_content_str: str = build_html_email(
            breach_name=breach_name,
            severity=severity,
            data_classes=data_classes,
            remediation_text=remediation_text,
            email_preview=email_preview,
            breach_date=breach_date,
        )

        from_email_obj = Email(self.from_email, self.from_name)
        to_email_obj = To(to_email)
        content_obj = Content("text/html", html_content_str)
        
        message = Mail(
            from_email=from_email_obj,
            to_emails=to_email_obj,
            subject=subject,
            html_content=content_obj,
        )

        try:
            logger.info(f"Attempting to dispatch SendGrid email to {email_preview}")
            response = self.sg.send(message)
            
            # SendGrid reliably issues a 202 ACCEPTED status when ingress is successful
            if response.status_code == 202:
                logger.info(f"Successfully dispatched alert email regarding {breach_name}")
                return {"status": "sent", "code": int(response.status_code)}
            else:
                logger.warning(f"Unexpected SendGrid response code: {response.status_code}")
                return {"status": "failed", "error": f"Unexpected code {response.status_code}"}
                
        except Exception as e:
            # Trap all possible transmission exceptions to guarantee we return a dict map
            logger.error(f"Failed to transmit email alert to SendGrid API: {e}", exc_info=True)
            return {"status": "failed", "error": str(e)}

    def send_weekly_summary(
        self,
        to_email: str,
        summary_stats: dict[str, Any]
    ) -> dict[str, Any]:
        """Dispatch a weekly digest containing statistical summaries of the user's coverage.
        
        Args:
            to_email: Plaintext recipient email address.
            summary_stats: Core metrics dictionary detailing account posture.
            
        Returns:
            Dictionary containing transmission 'status'.
        """
        subject: str = "📊 BreachShield: Your Weekly Security Digest"
        
        monitored: int = summary_stats.get("total_monitored", 0)
        breaches: int = summary_stats.get("total_breaches", 0)
        new_breaches: int = summary_stats.get("new_this_week", 0)
        score: int = summary_stats.get("risk_score", 0)

        html_content_str: str = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
            <h2>Your Weekly BreachShield Digest</h2>
            <p>Here is a summary of your digital security profile for the past week:</p>
            <ul>
                <li><strong>Monitored Emails:</strong> {monitored}</li>
                <li><strong>Total Known Breaches:</strong> {breaches}</li>
                <li><strong>New Breaches This Week:</strong> <span style="color: {'#D32F2F' if new_breaches > 0 else '#2E7D32'}">{new_breaches}</span></li>
                <li><strong>Overall Risk Score:</strong> {score}/100</li>
            </ul>
            <p>Log in to your BreachShield dashboard for complete remediation details.</p>
        </body>
        </html>
        """

        from_email_obj = Email(self.from_email, self.from_name)
        to_email_obj = To(to_email)
        content_obj = Content("text/html", html_content_str)
        
        message = Mail(
            from_email=from_email_obj,
            to_emails=to_email_obj,
            subject=subject,
            html_content=content_obj,
        )

        try:
            logger.info("Dispatching weekly SendGrid digest to user.")
            response = self.sg.send(message)
            
            if response.status_code == 202:
                return {"status": "sent", "code": int(response.status_code)}
                
            return {"status": "failed", "error": f"Unexpected code {response.status_code}"}
            
        except Exception as e:
            logger.error(f"Failed to transmit weekly digest email: {e}", exc_info=True)
            return {"status": "failed", "error": str(e)}
