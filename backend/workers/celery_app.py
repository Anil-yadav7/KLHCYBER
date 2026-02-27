"""Celery application configuration for BreachShield background workers.

This module creates and configures the Celery application instance used
for asynchronous tasks and periodic scheduled jobs.
"""

import logging

from celery import Celery
from celery.schedules import crontab

from ..config.settings import settings

logger = logging.getLogger(__name__)

# Initialize the Celery application with the broker and result backend
# We include 'backend.workers.scan_tasks' so Celery can discover tasks
celery_app = Celery(
    "breachshield",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["backend.workers.scan_tasks"],
)

# Configure Celery application settings explicitly
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # task_acks_late ensures a task is only acknowledged after it has completed execution,
    # which prevents data/task loss if a worker crashes mid-execution.
    task_acks_late=True,
    # worker_prefetch_multiplier=1 forces workers to only fetch one task at a time,
    # preventing them from hoarding tasks and balancing the load effectively.
    worker_prefetch_multiplier=1,
    task_max_retries=3,
    task_default_retry_delay=60,
)

# Schedule periodic tasks (Celery Beat)
celery_app.conf.beat_schedule = {
    # Run a full scan on all monitored emails every 6 hours
    "scan-all-emails-every-6-hours": {
        "task": "backend.workers.scan_tasks.scan_all_monitored_emails",
        "schedule": crontab(minute=0, hour="*/6"),
        "options": {"queue": "periodic"},
    },
    # Send a weekly security summary digest email every Monday morning
    "send-weekly-summary-monday": {
        "task": "backend.workers.scan_tasks.send_weekly_summaries",
        "schedule": crontab(minute=0, hour=8, day_of_week="monday"),
        "options": {"queue": "notifications"},
    },
}


def get_celery_app() -> Celery:
    """Return the configured Celery application instance.
    
    Returns:
        The globally configured Celery application.
    """
    return celery_app
