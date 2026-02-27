# KLHCYBER

# BreachShield 🛡️

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0+-009688.svg)
![Celery](https://img.shields.io/badge/celery-5.3+-37814A.svg)
![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg)

BreachShield is a highly-performant, production-grade Dark Web Breach Monitoring platform. It continuously secures your digital identity by automating tracking of email addresses against known data breaches via the HaveIBeenPwned API, calculating precise risk severity scores, generating AI-powered remediation advice using Anthropic Claude, and dispatching real-time multi-channel alerts via SendGrid and Twilio to keep you protected.

## Architecture Diagram

```text
                            +-------------------+
                            |  Streamlit UI     |
                            |   (dashboard)     |
                            +--------+----------+
                                     | (HTTP)
                                     v
+-------------------+       +-------------------+       +-------------------+
|  PostgreSQL DB    | <---- |   FastAPI App     | ----> |  Redis Broker     |
|   (postgres)      | (ORM) |      (api)        |       |     (redis)       |
+-------------------+       +--------+----------+       +--------+----------+
        ^                            |                           ^
        |                            v                           |
        |                   +-------------------+                |
        +------------------ |   Celery Worker   | ---------------+
        |                   | (celery_worker)   |                |
        |                   +-------------------+                |
        |                                                        |
+-------+-----------+       +-------------------+       +--------+----------+
|  Celery Beat      | ----> |  Celery Flower    | <---- | External APIs     |
| (celery_beat)     |       |     (flower)      |       | (HIBP, Anthropic) |
+-------------------+       +-------------------+       +-------------------+
```

## Prerequisites

* **Python 3.11+**
* **Docker Desktop** (for containerized deployment)
* **Have I Been Pwned (HIBP) API Key** (for raw breach intelligence)
* **SendGrid Account & API Key** (for reliable email alerts)
* **Twilio Account & API Key** (for high-severity SMS alerts)
* **Anthropic SDK Key** (for AI-powered remediation advice)

## Quick Start

1. **Clone the repository and enter the directory**
   ```bash
   git clone https://github.com/yourusername/breachshield.git
   cd breachshield
   ```

2. **Configure your environment**
   ```bash
   cp .env.example .env
   # Open .env in your editor and fill in your real API keys and database credentials.
   ```

3. **Launch the platform via Docker Compose**
   ```bash
   docker-compose up --build
   ```

4. **Access the Application Dashboard**
   Open [http://localhost:8501](http://localhost:8501) in your browser.

5. **Explore the Interactive API Documentation**
   Open [http://localhost:8000/docs](http://localhost:8000/docs) in your browser.

## Running Without Docker (Local Development)

1. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the Redis broker locally**
   ```bash
   # On macOS using Homebrew:
   brew install redis
   brew services start redis
   
   # Or on Ubuntu/Debian:
   sudo apt update && sudo apt install redis
   ```

3. **Start the FastAPI application**
   ```bash
   uvicorn backend.api.main:app --reload
   ```

4. **Start the Celery worker**
   ```bash
   celery -A backend.workers.celery_app.celery_app worker
   ```

5. **Start the Celery beat scheduler**
   ```bash
   celery -A backend.workers.celery_app.celery_app beat
   ```

6. **Start the Streamlit dashboard**
   ```bash
   streamlit run frontend/dashboard.py
   ```

## Environment Variables

| Variable | Purpose | Example Value |
| :--- | :--- | :--- |
| `APP_NAME` | Descriptive title of the application instance | `BreachShield API` |
| `APP_VERSION` | Active semantic version string | `1.0.0` |
| `API_BASE_URL` | Base API URL used by frontend dashboard | `http://localhost:8000/api/v1` |
| `LOG_LEVEL` | Console logging verbosity | `INFO` |
| `DATABASE_URL` | SQLAlchemy connection string | `sqlite:///./breachshield.db` |
| `HIBP_API_KEY` | Authorization key for HaveIBeenPwned endpoints | `your_hibp_api_key_here` |
| `HIBP_RATE_LIMIT_SECONDS` | Delay between calls to obey rate limits | `1.6` |
| `SENDGRID_API_KEY` | Secret key for SendGrid email dispatches | `SG.your_sendgrid_api_key` |
| `FROM_EMAIL` | Authorized sender address mapped to SendGrid | `alerts@yourdomain.com` |
| `FROM_NAME` | Human-readable string for outbound alerts | `BreachShield Security` |
| `TWILIO_ACCOUNT_SID` | Twilio Account SID identifier | `ACxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| `TWILIO_AUTH_TOKEN` | Twilio Account Authentication Token | `your_twilio_auth_token_here` |
| `TWILIO_FROM_NUMBER` | E.164 formatted registered Twilio number | `+15551234567` |
| `ANTHROPIC_API_KEY` | Key for Anthropics Claude language models | `sk-ant-api03...` |
| `CLAUDE_MODEL` | Precise Anthropic model tag to use | `claude-3-5-sonnet-20241022` |
| `CELERY_BROKER_URL` | Connection URL pointing to Redis broker | `redis://localhost:6379/0` |
| `CELERY_RESULT_BACKEND` | Connection URL for Celery state storage | `redis://localhost:6379/1` |
| `SECRET_KEY` | Root application cryptographic secret key | `generate_a_long_random_secret_here` |
| `ENCRYPTION_KEY` | Fernet-compatible database encryption key | `your_base64_generated_fernet_key` |

## API Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Root-level system health beacon. |
| `GET` | `/api/v1/health` | Subsystem health check, including database connectivity. |
| `POST` | `/api/v1/emails/` | Add a new email to the monitoring queue and trigger initial scan. |
| `GET` | `/api/v1/emails/` | List all actively monitored emails assigned to the current user. |
| `DELETE` | `/api/v1/emails/{email_id}` | Soft delete an actively monitored email address. |
| `GET` | `/api/v1/emails/{email_id}/breaches` | Retrieve all data breach exposures linked against a monitored address. |
| `GET` | `/api/v1/breaches/` | Get all breach events for the user (paginated, sortable, filterable). |
| `GET` | `/api/v1/breaches/stats` | Retrieve aggregated breach statistics for the analytic dashboard. |
| `GET` | `/api/v1/breaches/export/csv` | Export all of a user's breach data as a fast CSV download. |
| `GET` | `/api/v1/breaches/{breach_id}` | Retrieve exhaustive details (and AI remediation plan) for an incident. |
| `POST` | `/api/v1/breaches/{breach_id}/regenerate-remediation` | Force Anthropic Claude to bypass cache and regenerate advice. |
| `GET` | `/api/v1/alerts/` | Retrieve alert dispatch history (view delivered vs failed notifications). |
| `GET` | `/api/v1/alerts/stats` | Get multi-channel communication success metrics and rates. |
| `POST` | `/api/v1/alerts/{breach_id}/resend` | Manually requeue and resend notification suite for a breach. |
| `DELETE` | `/api/v1/alerts/{alert_id}` | Hard delete a specific alert log entry from history. |

## Running Tests

Execute the isolated unit test suite using Pytest and measure coverage across the backend logic:
```bash
pytest tests/ -v --cov=backend
```

## Project Structure

```text
breachshield/
│
├── .env.example
├── docker-compose.yml
├── requirements.txt
├── README.md
│
├── backend/
│   ├── config/
│   │   └── settings.py
│   ├── database/
│   │   ├── connection.py
│   │   └── models.py
│   ├── ingestion/
│   │   └── hibp_client.py
│   ├── scoring/
│   │   └── severity_engine.py
│   ├── remediation/
│   │   └── llm_advisor.py
│   ├── alerts/
│   │   ├── email_alert.py
│   │   └── sms_alert.py
│   ├── workers/
│   │   ├── celery_app.py
│   │   └── scan_tasks.py
│   ├── api/
│   │   ├── main.py
│   │   └── routes/
│   │       ├── emails.py
│   │       ├── breaches.py
│   │       └── alerts.py
│   └── utils/
│       └── crypto.py
│
├── frontend/
│   └── dashboard.py
│
└── tests/
    └── test_severity_engine.py
```

## Tech Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **API Framework** | FastAPI | High-performance asynchronous REST API architecture |
| **Database** | PostgreSQL / SQLite | Persistent storage, ACID compliance, SQLAlchemy ORM mappings |
| **Message Broker** | Redis | Fast in-memory datastore for Celery queues and results |
| **Task Queue** | Celery | Robust background job scheduling and asynchronous task execution |
| **Dashboard UI** | Streamlit | Intuitive, reactive data visualization and administration frontend |
| **AI LLM** | Anthropic Claude | Context-aware, deterministic remediation plan generation |
| **Data Ingestion** | HIBP API | Up-to-the-minute dark web credential monitoring queries |
| **Alert Delivery** | SendGrid / Twilio | Reliable programmatic dispatch of Email and SMS notifications |
| **Containerization**| Docker | Consistent, reproducible local testing and cluster-ready deployment |

## Contributing Guidelines

1. Fork the repository and create a new feature branch (`git checkout -b feature/your-feature-name`).
2. Write Pythonic, production-grade 3.11+ code enriched with type hints (`typing`) and docstrings.
3. Validate your architectural logic ensuring it follows the core structural guidelines.
4. Add comprehensive unit tests. Follow the `pytest tests/ -v` testing strategy.
5. Create a descriptive pull request linking to any related issues. Let's merge it!

## License

This project is licensed under the **MIT License**.
