# Docket Tracker SA

A Flask-based police case and docket accountability tracker with role-based dashboards, case lifecycle controls, custody transfers, escalation guardrails, and append-only audit history.

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Demo accounts

| Username | Password | Role |
| --- | --- | --- |
| `admin` | `admin123` | System Administrator |
| `commander` | `commander123` | Station Commander |
| `supervisor` | `supervisor123` | Supervisor |
| `detective` | `detective123` | Detective |
| `clerk` | `clerk123` | Admin Clerk |

The SQLite database is created and seeded automatically on first run. Demo credentials must be replaced before any real deployment.
