#!/bin/bash
echo "Starting Redis broker..."
./vendor/redis/src/redis-server > redis.log 2>&1 &
echo $! > run_redis.pid

echo "Sourcing Python environment..."
source venv/bin/activate

echo "Starting FastAPI server..."
uvicorn backend.api.main:app --port 8000 > api.log 2>&1 &
echo $! > run_api.pid

echo "Starting Celery worker..."
celery -A backend.workers.celery_app.celery_app worker --loglevel=info > worker.log 2>&1 &
echo $! > run_worker.pid

echo "Starting Celery beat scheduler..."
celery -A backend.workers.celery_app.celery_app beat --loglevel=info > beat.log 2>&1 &
echo $! > run_beat.pid

echo "Starting Streamlit dashboard..."
streamlit run frontend/dashboard.py --server.port 8501 --server.headless true > frontend.log 2>&1 &
echo $! > run_frontend.pid

echo "All 5 BreachShield services have been launched in the background!"
echo "Check the following files for logs: redis.log, api.log, worker.log, beat.log, frontend.log"
