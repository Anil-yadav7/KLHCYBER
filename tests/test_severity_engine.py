"""Unit tests for the severity grading engine.

Validates the accuracy of the mathematical weight associations, label boundaries,
ceiling constraints (score capping), and deterministic classification logic.
"""

from backend.scoring.severity_engine import (
    SeverityResult,
    calculate_severity,
    get_severity_badge,
    is_critical_breach,
)


def test_critical_when_passwords_exposed() -> None:
    """Verify that exposing 'Passwords' instantly pushes the label to CRITICAL."""
    data_classes: list[str] = ["Usernames", "Passwords"]
    result: SeverityResult = calculate_severity(data_classes)
    
    assert result.label == "CRITICAL"
    # Even if score < 12 via standard math, the threshold explicitly pushes
    # known critical vectors (Passwords/hashes) to the upper tier.


def test_critical_when_credit_cards_exposed() -> None:
    """Verify that exposing financial data ('Credit cards') instantly pushes to CRITICAL."""
    data_classes: list[str] = ["Email addresses", "Credit cards"]
    result: SeverityResult = calculate_severity(data_classes)
    
    assert result.label == "CRITICAL"


def test_low_when_only_usernames() -> None:
    """Ensure weak, commonly exposed fields default to a safe LOW label and low score."""
    data_classes: list[str] = ["Avatars", "Browser user agent details"]
    result: SeverityResult = calculate_severity(data_classes)
    
    # Avatars (1) + Browser (2) = 3. A score of 3 is explicitly LOW (< 6).
    assert result.label == "LOW"
    assert result.score == 3


def test_empty_data_classes_returns_low() -> None:
    """A breach exposing 0 known data classes should fall-back to a generic LOW 0-score."""
    data_classes: list[str] = []
    result: SeverityResult = calculate_severity(data_classes)
    
    assert result.label == "LOW"
    assert result.score == 0
    assert result.top_risk == "None"


def test_score_capped_at_100() -> None:
    """Protect against edge-case breaches where exposure counts exceed the 100 max boundary."""
    # Build a massive, highly-weighted vector set
    data_classes: list[str] = [
        "Passwords", "Credit cards", "Social security numbers", 
        "Financial transactions", "Biometric data", "Authentication tokens",
        "Personal health data", "Historical passwords", "Private messages",
        "Phone numbers", "Physical addresses", "IP addresses"
    ]
    
    result: SeverityResult = calculate_severity(data_classes)
    assert result.score == 100
    assert result.label == "CRITICAL"


def test_severity_badge_format() -> None:
    """Confirm the UI mapping helper correctly applies the standard semantic emoji."""
    assert get_severity_badge("CRITICAL") == "🔴 CRITICAL"
    assert get_severity_badge("HIGH") == "🟠 HIGH"
    assert get_severity_badge("MEDIUM") == "🟡 MEDIUM"
    assert get_severity_badge("LOW") == "🟢 LOW"
    assert get_severity_badge("UNKNOWN") == "⚪ UNKNOWN" # Default fallback


def test_is_critical_breach_true() -> None:
    """Test standard boolean helper returns True for known critical attack surfaces."""
    data_classes: list[str] = ["Email addresses", "Passwords", "Purchases"]
    assert is_critical_breach(data_classes) is True


def test_is_critical_breach_false() -> None:
    """Test standard boolean helper returns False when sensitive identity bounds aren't crossed."""
    data_classes: list[str] = ["Names", "Email addresses", "Device information"]
    assert is_critical_breach(data_classes) is False


def test_severity_result_has_top_risk() -> None:
    """Ensure the severity engine deterministicly surfaces the highest weighted exposure."""
    data_classes: list[str] = ["IP addresses", "Credit cards", "Names"]
    result: SeverityResult = calculate_severity(data_classes)
    
    # Credit cards (10 pt weight) is higher than IP (2) and Names (1)
    assert result.top_risk == "Credit cards"


def test_medium_severity_range() -> None:
    """Verify that aggregate math pushing into the 6-11 boundary triggers the MEDIUM flag."""
    # Names (3) + Email addresses (5) = 8
    data_classes: list[str] = ["Names", "Email addresses"]
    result: SeverityResult = calculate_severity(data_classes)
    
    assert 6 <= result.score <= 11
    assert result.label == "MEDIUM"
