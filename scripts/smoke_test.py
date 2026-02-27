"""Smoke test script to verify imports and basic logic for the BreachShield deployment."""

import sys
import os

# Ensure the backend module is resolvable in the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def run_tests():
    print("Starting BreachShield Smoke Tests...")
    
    # 1. Test Imports
    print("\n--- Testing Imports ---")
    try:
        from backend.config.settings import settings
        from backend.database.connection import get_db_session
        from backend.database.models import User, MonitoredEmail
        from backend.ingestion.hibp_client import HIBPClient
        from backend.scoring.severity_engine import calculate_severity, get_severity_badge, is_critical_breach
        from backend.remediation.llm_advisor import LLMAdvisor
        from backend.alerts.email_alert import EmailAlertSender
        from backend.alerts.sms_alert import build_sms_message
        from backend.workers.celery_app import celery_app
        from backend.api.main import app
        from backend.utils.crypto import generate_email_preview
        print("[PASS] All major backend modules imported successfully.")
    except Exception as e:
        print(f"[FAIL] Import error: {e}")
        sys.exit(1)

    # 2. Test calculate_severity
    print("\n--- Testing calculate_severity ---")
    try:
        result = calculate_severity(['Passwords'])
        assert result.label == 'CRITICAL', f"Expected CRITICAL, got {result.label}"
        print("[PASS] calculate_severity(['Passwords']) correctly returned CRITICAL.")
    except Exception as e:
        print(f"[FAIL] calculate_severity error: {e}")
        sys.exit(1)

    # 3. Test generate_email_preview
    print("\n--- Testing generate_email_preview ---")
    try:
        preview = generate_email_preview('john@gmail.com')
        assert preview == 'joh***@gmail.com', f"Expected 'joh***@gmail.com', got '{preview}'"
        print("[PASS] generate_email_preview('john@gmail.com') correctly returned 'joh***@gmail.com'.")
    except Exception as e:
        print(f"[FAIL] generate_email_preview error: {e}")
        sys.exit(1)

    # 4. Test build_sms_message
    print("\n--- Testing build_sms_message ---")
    try:
        msg = build_sms_message('LinkedIn', 'CRITICAL', 'joh***@gmail.com')
        assert len(msg) < 160, f"Message length {len(msg)} is not under 160 characters."
        print(f"[PASS] build_sms_message length is {len(msg)} (under 160 limit).")
    except Exception as e:
        print(f"[FAIL] build_sms_message error: {e}")
        sys.exit(1)
        
    print("\nAll smoke tests passed! System is ready.")

if __name__ == "__main__":
    run_tests()
