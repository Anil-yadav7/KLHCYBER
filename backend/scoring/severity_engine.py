"""Severity scoring engine for BreachShield.

Converts a list of exposed data_classes from a HIBP breach into a severity
label and a numeric score. This module contains pure business logic with no
external API or database dependencies.
"""

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

DATA_CLASS_WEIGHTS: dict[str, int] = {
    'Passwords': 25,
    'Password hints': 20,
    'Auth tokens': 20,
    'Credit cards': 25,
    'Bank account numbers': 25,
    'Social security numbers': 25,
    'Passport numbers': 20,
    'Government issued IDs': 20,
    'Private messages': 15,
    'Security questions and answers': 18,
    'Biometric data': 22,
    'Health insurance information': 18,
    'Medical records': 20,
    'Financial transactions': 18,
    'Purchases': 10,
    'Phone numbers': 8,
    'Physical addresses': 8,
    'Dates of birth': 7,
    'Genders': 3,
    'Geographic locations': 5,
    'Ethnicities': 5,
    'Email addresses': 5,
    'Usernames': 4,
    'Names': 3,
    'IP addresses': 4,
    'Device information': 3,
    'Browser user agent details': 2,
    'Avatars': 1,
    'Website activity': 3,
}

SEVERITY_THRESHOLDS: dict[str, int] = {
    'CRITICAL': 25,
    'HIGH': 12,
    'MEDIUM': 6,
    'LOW': 0,
}


@dataclass
class SeverityResult:
    """Dataclass representing the computed severity of a data breach.
    
    Attributes:
        label: The severity tier string (LOW, MEDIUM, HIGH, CRITICAL).
        score: The numeric risk score from 0 to 100.
        matched_classes: The specific data elements that contributed to the score.
        top_risk: The single highest-scoring data class exposed.
        description: A human-readable summary of the exposure.
    """
    label: str
    score: int
    matched_classes: list[str]
    top_risk: str
    description: str


def calculate_severity(data_classes: list[str]) -> SeverityResult:
    """Calculate the severity score and risk tier for a set of breached data classes.

    Args:
        data_classes: A list of strings representing exposed data elements from HIBP.

    Returns:
        A populated SeverityResult object with computed risk metrics.
    """
    if not data_classes:
        # Special case: an empty data classes list cannot be scored
        return SeverityResult('LOW', 0, [], 'None', 'No data classes reported')

    raw_score: int = 0
    matched_classes: list[str] = []
    top_risk: str = 'None'
    highest_weight: int = -1

    for c in data_classes:
        # Default weight of 2 applied if a class is not recognized in our dict
        weight: int = DATA_CLASS_WEIGHTS.get(c, 2)
        raw_score += weight

        if c in DATA_CLASS_WEIGHTS:
            matched_classes.append(c)

        if weight > highest_weight:
            highest_weight = weight
            top_risk = c

    score: int = min(raw_score, 100)

    label: str = 'LOW'
    if is_critical_breach(data_classes) or score >= SEVERITY_THRESHOLDS['CRITICAL']:
        # Critical types or high volume pushes it straight to Critical
        label = 'CRITICAL'
        score = max(score, SEVERITY_THRESHOLDS['CRITICAL'])
    elif score >= SEVERITY_THRESHOLDS['HIGH']:
        label = 'HIGH'
    elif score >= SEVERITY_THRESHOLDS['MEDIUM']:
        label = 'MEDIUM'

    description: str = ""
    if 'Passwords' in data_classes:
        # Passwords rank as high criticality because it provides direct account access
        description = 'Your login credentials were directly exposed.'
    elif 'Credit cards' in data_classes or 'Bank account numbers' in data_classes:
        # Financial information poses a direct monetary risk
        description = 'Your financial data was exposed.'
    else:
        # Default description falls back to summarizing the first item
        description = f'{len(data_classes)} types of personal data were exposed including {data_classes[0]}.'

    return SeverityResult(label, score, matched_classes, top_risk, description)


def get_severity_badge(label: str) -> str:
    """Convert a severity label into an emoji-prefixed display badge.

    Args:
        label: The severity label string (e.g. 'HIGH').

    Returns:
        An emoji-prefixed string for UI display.
    """
    if label == 'CRITICAL':
        return '🔴 CRITICAL'
    if label == 'HIGH':
        return '🟠 HIGH'
    if label == 'MEDIUM':
        return '🟡 MEDIUM'
    if label == 'LOW':
        return '🟢 LOW'
    
    # Catch-all special case for undefined or malformed labels
    return '⚪ UNKNOWN'


def is_critical_breach(data_classes: list[str]) -> bool:
    """Determine if a breach contains exceptionally critical data elements.

    Checks against a strict whitelist of high-risk data types.

    Args:
        data_classes: A list of strings representing exposed data elements.

    Returns:
        True if any highly critical risk data types are present, False otherwise.
    """
    critical_types: set[str] = {
        'Passwords', 'Credit cards', 'Bank account numbers',
        'Social security numbers', 'Auth tokens', 'Biometric data'
    }

    for c in data_classes:
        if c in critical_types:
            # Short-circuit logic: immediate match of critical risk
            return True

    return False
