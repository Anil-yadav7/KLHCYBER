"""Main FastAPI application entry point.

Creates the app instance, registers all API routers, configures middleware,
and handles ASGI startup/shutdown events.
"""

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from .routes.alerts import router as alerts_router
from .routes.breaches import router as breaches_router
from .routes.emails import router as emails_router
from backend.config.settings import settings
from backend.database.connection import get_db_session, init_db

# Configure core Python logging globally before instantiating the app
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s — %(name)s — %(levelname)s — %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and teardown lifecycle events.
    
    Replaces deprecated @app.on_event("startup") and @app.on_event("shutdown").
    """
    # --- Startup operations ---
    try:
        init_db()
        logger.info("BreachShield API started successfully")
        logger.info(f"Running app version: {settings.APP_VERSION}")
    except Exception as e:
        logger.error(f"Critical error during API startup initialization: {e}", exc_info=True)
        raise e

    yield  # The application runs during this yield

    # --- Shutdown operations ---
    logger.info("BreachShield API shutting down")


# Instantiate the FastAPI core application
app = FastAPI(
    title="BreachShield API",
    description="Dark Web Breach Monitoring API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Apply restrictive CORS policy pointing at Streamlit's default port
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount segmented functionality routers to the unified /api/v1 prefix
app.include_router(emails_router, prefix="/api/v1")
app.include_router(breaches_router, prefix="/api/v1")
app.include_router(alerts_router, prefix="/api/v1")


@app.get("/", status_code=status.HTTP_200_OK, tags=["System"])
def root_health_check() -> dict[str, str]:
    """Provide a minimal root-level system health beacon."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION
    }


@app.get("/api/v1/health", status_code=status.HTTP_200_OK, tags=["System"])
def detailed_health_check(db: Session = Depends(get_db_session)) -> dict[str, str]:
    """Assess subsystem health including active database connectivity."""
    db_status: str = "disconnected"
    
    try:
        # A simple lightweight query scalar to prove connection viability
        result = db.execute(text("SELECT 1")).scalar()
        if result == 1:
            db_status = "connected"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "disconnected"

    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "database": db_status
    }
