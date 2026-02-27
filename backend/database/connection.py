"""Database connection and session management for BreachShield.

This module provides the SQLAlchemy engine, session factory, and declarative
base required for interacting with the database. It also provides dependency
injection helpers for FastAPI route handlers.
"""

import logging
from contextlib import contextmanager
from typing import Any, Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from ..config.settings import settings

logger = logging.getLogger(__name__)

# Dynamic configuration based on the type of database we are connecting to
engine_kwargs: dict[str, Any] = {
    "echo": settings.DATABASE_ECHO,
    "pool_pre_ping": True,
}

# SQLite requires specific arguments to allow multi-threading in FastAPI
# This connects_args check must only be applied to SQLite, not PostgreSQL
if settings.DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

try:
    engine: Engine = create_engine(settings.DATABASE_URL, **engine_kwargs)
except Exception as e:
    logger.error(f"Failed to create database engine: {e}")
    raise

# Session factory for creating new database sessions contextually
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all SQLAlchemy declarative models to inherit from
Base = declarative_base()


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """Context manager for obtaining a database session.
    
    This function handles creating a session and ensuring it is properly
    closed after use, regardless of whether an exception occurred.
    
    Yields:
        A SQLAlchemy database session.
        
    Raises:
        Exception: If a database error occurs while yielding the session.
    """
    db: Session = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database error in get_db context manager: {e}")
        raise
    finally:
        db.close()


def get_db_session() -> Generator[Session, None, None]:
    """FastAPI dependency for obtaining a database session.
    
    This function yields a database session and safely commits transactions
    if everything succeeds. If an exception is raised, it rolls back the
    transaction to prevent data corruption.
    
    Yields:
        A SQLAlchemy database session.
        
    Raises:
        Exception: Re-raises any exceptions encountered during the session use.
    """
    db: Session = SessionLocal()
    try:
        yield db
        # Automatically commit changes if execution completes successfully
        db.commit()
    except Exception as e:
        # Roll back invalid or incomplete transactions to maintain DB integrity
        logger.error(f"Database transaction error in get_db_session: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """Initialize the database by creating all tables defined in the models.
    
    Returns:
        None.
        
    Raises:
        Exception: If table creation fails.
    """
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database tables: {e}")
        raise
