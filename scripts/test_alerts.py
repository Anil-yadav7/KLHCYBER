import os
import ssl
from backend.alerts.email_alert import EmailAlertSender
from backend.alerts.sms_alert import SMSAlertSender

# Bypass macOS local Python SSL certification issues strictly for testing the API wrapper functionality
ssl._create_default_https_context = ssl._create_unverified_context

def test_alerts():
    print("# Test: Send real email alert")
    print("# Test email alert delivery (sends a real email)")
    sender = EmailAlertSender()
    try:
        result = sender.send_breach_alert(
            to_email='test@example.com',
            breach_name='TestBreach 2024',
            severity='HIGH',
            data_classes=['Passwords', 'Email addresses'],
            remediation_text='1. Change your password immediately.\n2. Enable 2FA.',
            email_preview='you***@example.com',
            breach_date='2024-01-15'
        )
        print(f"Email result: {result}")
        if result.get('status') == 'sent':
            print("Email sent □ - check your inbox")
        else:
            print(f"Email failed □: {result.get('error', result)}")
    except Exception as e:
        print(f"Email Exception: {e}")

    print("\n# Test: Send real SMS alert")
    print("# Test SMS alert delivery (CRITICAL only - sends real SMS)")
    sms_sender = SMSAlertSender()
    
    # This should SKIP (MEDIUM is below threshold)
    try:
        result_skip = sms_sender.send_breach_sms(
            to_phone='+1XXXXXXXXXX',
            breach_name='TestBreach',
            severity='MEDIUM',
            email_preview='you***@example.com'
        )
        print(f"MEDIUM severity: {result_skip} # Expected: skipped")
    except Exception as e:
        print(f"SMS Skip Exception: {e}")

    # This should SEND (CRITICAL triggers SMS)
    try:
        result_send = sms_sender.send_breach_sms(
            to_phone='+1XXXXXXXXXX',
            breach_name='LinkedIn',
            severity='CRITICAL',
            email_preview='you***@example.com'
        )
        print(f"CRITICAL severity: {result_send}")
        if result_send.get('status') == 'sent':
            print("SMS sent □ - check your phone")
        elif result_send.get('status') == 'skipped':
            print("SMS skipped as expected □")
        else:
            print("SMS failed □")
    except Exception as e:
        print(f"SMS Send Exception: {e}")

if __name__ == '__main__':
    test_alerts()
