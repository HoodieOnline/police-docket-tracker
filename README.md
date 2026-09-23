# Docket Tracker SA

A Flask-based police case and docket accountability tracker with role-based dashboards, case lifecycle controls, custody transfers, escalation guardrails, and append-only audit history.

The app also includes a legal and directive reference page plus per-case compliance checkpoints covering fair-trial safeguards, CAS registration, SAPS 5 / investigation-diary review, prosecutor and command inspection, chain of custody, child and special-offence screening, and PAIA/POPIA access review. These are operational prompts only and must be checked against current official legislation, SAPS instructions, NPA guidance and authorised legal advice.

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
| `detective` | `detective123` | Detective |
| `clerk` | `clerk123` | Admin Clerk |

The SQLite database is created and seeded automatically on first run. Demo credentials must be replaced before any real deployment.
