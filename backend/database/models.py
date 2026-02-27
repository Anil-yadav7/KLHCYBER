"""Database models for the BreachShield application.

This module defines all database tables as SQLAlchemy ORM models.
"""

import logging
from datetime import datetime

from sqlalchemy import Boolean, Column, Date, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from ..database.connection import Base

logger = logging.getLogger(__name__)


class User(Base):
    """User account model for managing authentication and application access."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    monitored_emails = relationship("MonitoredEmail", back_populates="owner")

    def __repr__(self) -> str:
        """Return a string representation of the User.
        
        Returns:
            A string identifier for the user.
        """
        return f"<User id={self.id} username={self.username}>"


class MonitoredEmail(Base):
    """Model representing an email address being monitored for data breaches."""
    __tablename__ = "monitored_emails"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_encrypted = Column(String(512), nullable=False)
    email_hash = Column(String(64), unique=True, nullable=False, index=True)
    email_preview = Column(String(50), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    added_at = Column(DateTime, default=datetime.utcnow)
    last_scanned_at = Column(DateTime, nullable=True)
    scan_count = Column(Integer, default=0)

    # Relationships
    owner = relationship("User", back_populates="monitored_emails")
    breach_events = relationship("BreachEvent", back_populates="monitored_email")

    def __repr__(self) -> str:
        """Return a string representation of the MonitoredEmail.
        
        Returns:
            A string identifier for the monitored email instance.
        """
        return f"<MonitoredEmail id={self.id} preview={self.email_preview}>"


class BreachEvent(Base):
    """Model representing a known data breach linked to a monitored email."""
    __tablename__ = "breach_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    monitored_email_id = Column(Integer, ForeignKey("monitored_emails.id"), nullable=False)
    breach_name = Column(String(200), nullable=False)
    breach_domain = Column(String(200), nullable=True)
    breach_date = Column(Date, nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow)
    data_classes = Column(JSON, nullable=False)
    pwn_count = Column(Integer, nullable=True)
    severity = Column(String(10), nullable=False)
    severity_score = Column(Integer, nullable=False)
    is_verified = Column(Boolean, default=True)
    is_notified = Column(Boolean, default=False)
    notified_at = Column(DateTime, nullable=True)
    is_fabricated = Column(Boolean, default=False)
    is_sensitive = Column(Boolean, default=False)
    remediation_text = Column(Text, nullable=True)

    __table_args__ = (
        # Ensure a specific breach is only recorded once per monitored email
        UniqueConstraint("monitored_email_id", "breach_name", name="uix_email_breach"),
    )

    # Relationships
    monitored_email = relationship("MonitoredEmail", back_populates="breach_events")
    alert_logs = relationship("AlertLog", back_populates="breach_event")

    def __repr__(self) -> str:
        """Return a string representation of the BreachEvent.
        
        Returns:
            A string identifier containing the breach name and severity.
        """
        return f"<BreachEvent id={self.id} breach={self.breach_name} severity={self.severity}>"


class AlertLog(Base):
    """Model for tracking outgoing breach notifications (e.g., email, SMS)."""
    __tablename__ = "alert_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    breach_event_id = Column(Integer, ForeignKey("breach_events.id"), nullable=False)
    channel = Column(String(20), nullable=False)
    recipient = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False)
    sent_at = Column(DateTime, default=datetime.utcnow)
    error_message = Column(String(500), nullable=True)
    provider_message_id = Column(String(200), nullable=True)

    # Relationships
    breach_event = relationship("BreachEvent", back_populates="alert_logs")

    def __repr__(self) -> str:
        """Return a string representation of the AlertLog.
        
        Returns:
            A string indicating the channel and delivery status of the alert.
        """
        return f"<AlertLog id={self.id} channel={self.channel} status={self.status}>"


class RemediationCache(Base):
    """Model caching AI-generated remediation advice to avoid repeated LLM calls.
    
    The same breach affecting multiple users will generate identical advice
    provided the breached data classes are the same.
    """
    __tablename__ = "remediation_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cache_key = Column(String(64), unique=True, nullable=False, index=True)
    breach_name = Column(String(200), nullable=False)
    data_classes_json = Column(JSON, nullable=False)
    remediation_text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    hit_count = Column(Integer, default=1)

    def __repr__(self) -> str:
        """Return a string representation of the RemediationCache.
        
        Returns:
            A string indicating the partial cache key resolving to this entry.
        """
        return f"<RemediationCache key={self.cache_key[:16]}...>"
