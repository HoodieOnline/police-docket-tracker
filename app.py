import os
import secrets
import sqlite3
from functools import wraps
from hashlib import pbkdf2_hmac, sha256
from hmac import compare_digest
from datetime import datetime, timedelta, timezone

from flask import Flask, has_request_context, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("DOCKET_TRACKER_SECRET_KEY") or secrets.token_hex(32)

DB_PATH = os.environ.get(
    "DOCKET_TRACKER_DB",
    os.path.join(os.path.dirname(__file__), "docket_tracker.db"),
)

STATUS_COLORS = {
    "Submitted": "background: rgba(148,163,184,0.12); color: #dbe4ed;",
    "Registered": "background: rgba(78,195,255,0.12); color: #dff4ff;",
    "Assigned": "background: rgba(96,165,250,0.12); color: #dbeafe;",
    "Under Investigation": "background: rgba(167,139,250,0.12); color: #e3d9ff;",
    "Awaiting Evidence": "background: rgba(192,132,252,0.12); color: #f3e8ff;",
    "Awaiting Supervisor Review": "background: rgba(251,146,60,0.12); color: #ffedd5;",
    "Awaiting Court": "background: rgba(251,191,36,0.12); color: #fde7a7;",
    "Escalated": "background: rgba(251,113,133,0.12); color: #ffbfd0;",
    "Finalized": "background: rgba(45,212,191,0.12); color: #baf7ec;",
    "Closed": "background: rgba(45,212,191,0.12); color: #baf7ec;",
}

CASE_STATUSES = [
    "Submitted",
    "Registered",
    "Assigned",
    "Under Investigation",
    "Awaiting Evidence",
    "Awaiting Supervisor Review",
    "Awaiting Court",
    "Finalized",
    "Escalated",
    "Closed",
]

CASE_TRANSITIONS = {
    "Registered": {
        "Assigned": "assign",
        "Escalated": "escalate",
    },
    "Assigned": {
        "Under Investigation": "update_case",
        "Escalated": "escalate",
    },
    "Under Investigation": {
        "Awaiting Evidence": "update_case",
        "Awaiting Supervisor Review": "update_case",
        "Escalated": "escalate",
    },
    "Awaiting Evidence": {
        "Under Investigation": "update_case",
        "Awaiting Supervisor Review": "update_case",
        "Escalated": "escalate",
    },
    "Awaiting Supervisor Review": {
        "Under Investigation": "approve",
        "Awaiting Court": "approve",
        "Escalated": "escalate",
    },
    "Awaiting Court": {
        "Under Investigation": "approve",
        "Finalized": "approve",
        "Escalated": "escalate",
    },
    "Escalated": {
        "Assigned": "approve",
        "Under Investigation": "approve",
        "Awaiting Evidence": "approve",
        "Awaiting Supervisor Review": "approve",
        "Awaiting Court": "approve",
    },
    "Finalized": {},
    "Submitted": {},
    "Closed": {},
}

LEGAL_REFERENCES = [
    ("Primary legislation", "Constitution of the Republic of South Africa, 1996 (Act 108 of 1996), section 35", "Fair-trial rights and the rights of arrested, detained and accused persons. Docket handling must protect procedural fairness."),
    ("Primary legislation", "Criminal Procedure Act 51 of 1977", "Investigation, arrest, bail, search and seizure, statements, and presentation of the docket to court."),
    ("Primary legislation", "South African Police Service Act 68 of 1995", "SAPS powers and duties relevant to investigation and the investigating officer."),
    ("Primary legislation", "National Prosecuting Authority Act 32 of 1998", "Investigation guidance, docket circulation between Detective and Prosecutor, and prosecution decisions."),
    ("Special-protection legislation", "Child Justice Act 75 of 2008", "Additional procedures where a suspect or victim is a child."),
    ("Special-protection legislation", "Domestic Violence Act 116 of 1998", "Special handling and protection requirements for domestic-violence-related dockets."),
    ("Special-protection legislation", "Criminal Law (Sexual Offences and Related Matters) Amendment Act 32 of 2007", "Special handling and protection requirements for sexual-offence-related dockets."),
    ("Information governance", "Promotion of Access to Information Act 2 of 2000 (PAIA)", "Access requests must be assessed against the applicable access-to-information process."),
    ("Information governance", "Protection of Personal Information Act 4 of 2013 (POPIA)", "Personal information in dockets must be accessed, used, retained and disclosed lawfully."),
    ("SAPS directive", "National Instruction 3 of 2011", "Opening and registering a docket on CAS and recording the CAS number."),
    ("SAPS directive", "National Instruction 22 of 1998 / SO (G) 321 — Docket Management", "Investigation diary (SAPS 5) completion and inspection by the CSC Commander, Detective Commander and Prosecutor."),
    ("SAPS directive", "Standing Order 333 — Chain of custody", "Movement of the docket from CSC to Detective, Commander inspection, NPA and Court must be traceable."),
]

COMPLIANCE_CHECKS = [
    ("Constitution / fair-trial safeguards", "Confirm that handling preserves the rights of arrested, detained and accused persons."),
    ("CAS registration", "Record the CAS number and confirm the docket was opened and registered correctly."),
    ("Investigation diary / SAPS 5", "Confirm required investigation-diary entries are complete and ready for inspection."),
    ("Command and prosecutor inspection", "Record inspection or guidance by the CSC Commander, Detective Commander and Prosecutor where applicable."),
    ("Chain of custody", "Record every docket movement and receiving location from CSC through Detective, command, NPA and Court."),
    ("Child Justice screening", "Confirm whether child-specific procedures apply to any suspect or victim and record the safeguarding decision."),
    ("Domestic violence screening", "Confirm whether domestic-violence protections and instructions apply."),
    ("Sexual offences screening", "Confirm whether sexual-offence protections and instructions apply."),
    ("PAIA / POPIA access review", "Record the access classification and review any request before disclosure."),
]

ROLE_PERMISSIONS = {
    "System Administrator": {"view_all", "manage_users", "register", "verify", "assign", "approve", "transfer", "escalate", "close"},
    "Station Commander": {"view_all", "assign", "approve", "transfer", "escalate", "close"},
    "Captain": {"view_station", "transfer", "escalate"},
    "Supervisor": {"view_station", "approve", "transfer", "escalate"},
    "Detective": {"view_assigned", "update_case", "transfer", "receive_docket"},
    "Admin Clerk": {"register", "verify", "view_station", "transfer"},
    "Complainant": {"view_own", "report_case"},
}


PASSWORD_ITERATIONS = 310_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PASSWORD_ITERATIONS,
        salt.hex(),
        digest.hex(),
    )


def verify_password(password: str, stored_hash: str) -> tuple[bool, bool]:
    if stored_hash.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt_hex, digest_hex = stored_hash.split("$", 3)
            digest = pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                bytes.fromhex(salt_hex),
                int(iterations),
            )
            return compare_digest(digest.hex(), digest_hex), False
        except (ValueError, TypeError):
            return False, False
    legacy_digest = sha256(password.encode("utf-8")).hexdigest()
    return compare_digest(legacy_digest, stored_hash), True


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT,
            station TEXT,
            email TEXT,
            phone_number TEXT,
            user_type TEXT NOT NULL DEFAULT 'Employee',
            account_status TEXT NOT NULL DEFAULT 'Active',
            created_at TEXT,
            last_login TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS stations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            address TEXT NOT NULL DEFAULT '',
            contact_number TEXT NOT NULL DEFAULT '',
            commander_user_id INTEGER REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS complainants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            id_number TEXT NOT NULL DEFAULT '',
            phone_number TEXT NOT NULL,
            address TEXT NOT NULL DEFAULT '',
            date_registered TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS case_statuses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS case_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
            employee_number TEXT NOT NULL UNIQUE,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            station_id INTEGER REFERENCES stations(id),
            phone_number TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            employment_status TEXT NOT NULL DEFAULT 'Active',
            role_id INTEGER REFERENCES roles(id),
            date_registered TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS case_controls (
            case_id TEXT PRIMARY KEY,
            next_action TEXT NOT NULL,
            due_at TEXT NOT NULL,
            escalation_level INTEGER NOT NULL DEFAULT 0,
            acknowledged_by TEXT,
            acknowledged_at TEXT,
            last_reminder_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT UNIQUE,
            case_type_id INTEGER REFERENCES case_types(id),
            status_id INTEGER REFERENCES case_statuses(id),
            complainant TEXT,
            station TEXT,
            assigned_to TEXT,
            status TEXT,
            days_open INTEGER,
            progress INTEGER,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            statement TEXT NOT NULL DEFAULT '',
            complainant_user_id INTEGER REFERENCES users(id),
            incident_date TEXT,
            incident_location TEXT NOT NULL DEFAULT '',
            case_type TEXT NOT NULL DEFAULT 'General',
            priority TEXT NOT NULL DEFAULT 'Normal',
            created_by INTEGER REFERENCES users(id),
            verified_by INTEGER REFERENCES users(id),
            closed_at TEXT,
            closing_reason TEXT NOT NULL DEFAULT '',
            docket_format TEXT NOT NULL DEFAULT 'Electronic',
            current_location TEXT NOT NULL DEFAULT '',
            assigned_employee_id INTEGER REFERENCES employees(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dockets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            docket_number TEXT NOT NULL UNIQUE,
            case_id TEXT NOT NULL UNIQUE REFERENCES cases(case_id),
            created_by INTEGER REFERENCES users(id),
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            physical_available INTEGER NOT NULL DEFAULT 0,
            current_holder_employee_id INTEGER REFERENCES employees(id),
            storage_location TEXT NOT NULL DEFAULT '',
            closed_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS detective_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL REFERENCES cases(case_id),
            docket_id INTEGER REFERENCES dockets(id),
            detective_id INTEGER NOT NULL REFERENCES employees(id),
            assigned_by INTEGER REFERENCES users(id),
            assigned_at TEXT NOT NULL,
            accepted_at TEXT,
            completed_at TEXT,
            status TEXT NOT NULL DEFAULT 'Assigned',
            notes TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS docket_movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            docket_id INTEGER NOT NULL REFERENCES dockets(id),
            from_employee_id INTEGER REFERENCES employees(id),
            to_employee_id INTEGER REFERENCES employees(id),
            from_location TEXT NOT NULL,
            to_location TEXT NOT NULL,
            moved_by_user_id INTEGER REFERENCES users(id),
            moved_at TEXT NOT NULL,
            movement_type TEXT NOT NULL,
            reason TEXT NOT NULL,
            received_at TEXT,
            received_by_employee_id INTEGER REFERENCES employees(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            case_id TEXT REFERENCES cases(case_id),
            notification_type TEXT NOT NULL,
            channel TEXT NOT NULL DEFAULT 'In-app',
            message TEXT NOT NULL,
            recipient_address TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            delivery_status TEXT NOT NULL DEFAULT 'Queued'
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS case_status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL REFERENCES cases(case_id),
            previous_status TEXT NOT NULL,
            new_status TEXT NOT NULL,
            changed_by_user_id INTEGER REFERENCES users(id),
            changed_at TEXT NOT NULL,
            reason TEXT NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS docket_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            action TEXT,
            location TEXT,
            time TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            actor TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS custody_transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            from_location TEXT NOT NULL,
            to_location TEXT NOT NULL,
            transferred_by TEXT NOT NULL,
            acknowledged_by TEXT,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS refusal_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            reported_by TEXT NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS legal_references (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            title TEXT UNIQUE NOT NULL,
            summary TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS case_compliance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            check_name TEXT NOT NULL,
            requirement TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Not reviewed',
            notes TEXT NOT NULL DEFAULT '',
            reviewed_by TEXT,
            reviewed_at TEXT,
            UNIQUE(case_id, check_name)
        )
        """
    )
    ensure_columns(
        conn,
        "employees",
        {
            "role_id": "INTEGER",
            "specialties": "TEXT NOT NULL DEFAULT ''",
        },
    )
    ensure_columns(
        conn,
        "users",
        {
            "email": "TEXT",
            "phone_number": "TEXT",
            "user_type": "TEXT NOT NULL DEFAULT 'Employee'",
            "account_status": "TEXT NOT NULL DEFAULT 'Active'",
            "created_at": "TEXT",
            "last_login": "TEXT",
        },
    )
    ensure_columns(
        conn,
        "cases",
        {
            "statement": "TEXT NOT NULL DEFAULT ''",
            "case_type_id": "INTEGER",
            "status_id": "INTEGER",
            "complainant_user_id": "INTEGER",
            "complainant_phone": "TEXT NOT NULL DEFAULT ''",
            "complainant_email": "TEXT NOT NULL DEFAULT ''",
            "complainant_id_number": "TEXT NOT NULL DEFAULT ''",
            "complainant_address": "TEXT NOT NULL DEFAULT ''",
            "created_at": "TEXT",
            "incident_date": "TEXT",
            "incident_location": "TEXT NOT NULL DEFAULT ''",
            "case_type": "TEXT NOT NULL DEFAULT 'General'",
            "priority": "TEXT NOT NULL DEFAULT 'Normal'",
            "created_by": "INTEGER",
            "verified_by": "INTEGER",
            "closed_at": "TEXT",
            "closing_reason": "TEXT NOT NULL DEFAULT ''",
            "docket_format": "TEXT NOT NULL DEFAULT 'Electronic'",
            "current_location": "TEXT NOT NULL DEFAULT ''",
            "assigned_employee_id": "INTEGER",
        },
    )
    ensure_columns(
        conn,
        "dockets",
        {
            "physical_serial": "TEXT NOT NULL DEFAULT ''",
            "evidence_list": "TEXT NOT NULL DEFAULT ''",
        },
    )
    ensure_columns(
        conn,
        "custody_transfers",
        {
            "movement_id": "INTEGER",
            "movement_type": "TEXT NOT NULL DEFAULT 'Electronic'",
            "from_employee_id": "INTEGER",
            "to_employee_id": "INTEGER",
            "received_at": "TEXT",
            "received_by_employee_id": "INTEGER",
        },
    )
    ensure_columns(
        conn,
        "audit_events",
        {"ip_address": "TEXT NOT NULL DEFAULT ''"},
    )
    ensure_columns(
        conn,
        "notifications",
        {"recipient_address": "TEXT NOT NULL DEFAULT ''"},
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cases_complainant ON cases(complainant_user_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cases_assigned_employee ON cases(assigned_employee_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_case_history_case_date ON case_status_history(case_id, changed_at)"
    )
    conn.commit()
    conn.close()


def ensure_columns(conn, table_name, columns):
    existing = {
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    }
    for name, definition in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {name} {definition}")


def refresh_guardrails(conn):
    now = datetime.now(timezone.utc)
    overdue = conn.execute(
        """
        SELECT c.case_id, c.status, cc.next_action, cc.due_at, cc.escalation_level
        FROM cases c JOIN case_controls cc ON cc.case_id = c.case_id
        WHERE c.status NOT IN ('Finalized', 'Closed')
        """
    ).fetchall()
    for case in overdue:
        due_at = parse_iso(case["due_at"])
        if not due_at or due_at > now:
            continue
        if case["escalation_level"] >= 2:
            continue
        next_level = case["escalation_level"] + 1
        conn.execute(
            "UPDATE case_controls SET escalation_level = ?, last_reminder_at = ? WHERE case_id = ?",
            (next_level, now.isoformat(timespec="seconds"), case["case_id"]),
        )
        conn.execute(
            "UPDATE cases SET status = 'Escalated', status_id = ?, updated_at = CURRENT_TIMESTAMP WHERE case_id = ?",
            (status_id_for(conn, "Escalated"), case["case_id"]),
        )
        conn.execute(
            """
            INSERT INTO case_status_history
                (case_id, previous_status, new_status, changed_at, reason)
            VALUES (?, ?, 'Escalated', ?, ?)
            """,
            (
                case["case_id"],
                case["status"],
                now.isoformat(timespec="seconds"),
                f"Required action overdue: {case['next_action']}",
            ),
        )
        add_audit_event(
            conn,
            case["case_id"],
            "Guardrail escalation",
            f"Required action overdue: {case['next_action']}. Escalation level {next_level}.",
        )


def init_seed_data(conn):
    refresh_guardrails(conn)
    conn.commit()

    role_descriptions = {
        "Complainant": "Submits reports and follows their own case status.",
        "Admin Clerk": "Verifies reports, opens dockets and registers employees.",
        "Detective": "Receives assigned dockets and investigates cases.",
        "Captain": "Monitors station activity and escalations.",
        "Station Commander": "Reviews pending dockets, assigns detectives and approves investigation closure.",
        "System Administrator": "Maintains system access and configuration.",
    }
    conn.executemany(
        "INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)",
        list(role_descriptions.items()),
    )
    conn.executemany(
        "INSERT OR IGNORE INTO case_statuses (name) VALUES (?)",
        [(status,) for status in CASE_STATUSES],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO case_types (name) VALUES (?)",
        [(name,) for name in (
            "General",
            "Theft",
            "Assault",
            "Fraud",
            "Robbery",
            "Burglary",
            "Missing person",
            "Other",
        )],
    )
    conn.execute(
        "INSERT OR IGNORE INTO stations (name) VALUES (?)",
        ("Johannesburg Central",),
    )
    demo_users = [
        ("admin", "admin123", "System Administrator", "Johannesburg Central"),
        ("detective", "detective123", "Detective", "Johannesburg Central"),
        ("clerk", "clerk123", "Admin Clerk", "Johannesburg Central"),
        ("captain", "captain123", "Captain", "Johannesburg Central"),
        ("commander", "commander123", "Station Commander", "Johannesburg Central"),
    ]
    for username, password, role, station in demo_users:
        conn.execute(
            """
            INSERT OR IGNORE INTO users
                (username, password_hash, role, station, user_type, account_status, created_at)
            VALUES (?, ?, ?, ?, 'Employee', 'Active', ?)
            """,
            (username, hash_password(password), role, station, now_iso()),
        )

    conn.execute(
        """
        INSERT OR IGNORE INTO users
            (username, password_hash, role, station, email, phone_number,
             user_type, account_status, created_at)
        VALUES (?, ?, 'Complainant', '', ?, ?, 'Complainant', 'Active', ?)
        """,
        (
            "demo_complainant",
            hash_password("complainant123"),
            "demo.complainant@example.test",
            "+27000000000",
            now_iso(),
        ),
    )
    demo_complainant = conn.execute(
        "SELECT id FROM users WHERE username = 'demo_complainant'"
    ).fetchone()
    conn.execute(
        """
        INSERT OR IGNORE INTO complainants
            (user_id, first_name, last_name, phone_number, date_registered)
        VALUES (?, 'Demo', 'Complainant', '+27000000000', ?)
        """,
        (demo_complainant["id"], now_iso()),
    )

    station_id = conn.execute(
        "SELECT id FROM stations WHERE name = ?", ("Johannesburg Central",)
    ).fetchone()["id"]
    employee_names = {
        "admin": ("System", "Administrator", "EMP-000001"),
        "detective": ("Kabelo", "Ndlovu", "EMP-000002"),
        "clerk": ("Nomsa", "Maseko", "EMP-000003"),
        "captain": ("Thabo", "Mokoena", "EMP-000004"),
        "commander": ("Lerato", "Dlamini", "EMP-000005"),
    }
    for username, (first_name, last_name, employee_number) in employee_names.items():
        user = conn.execute(
            "SELECT id, email, phone_number, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        role_id = conn.execute(
            "SELECT id FROM roles WHERE name = ?", (user["role"],)
        ).fetchone()
        conn.execute(
            """
            INSERT OR IGNORE INTO employees
                (user_id, employee_number, first_name, last_name, station_id, role_id,
                 phone_number, email, date_registered)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"],
                employee_number,
                first_name,
                last_name,
                station_id,
                role_id["id"],
                user["phone_number"] or "",
                user["email"] or "",
                now_iso(),
            ),
        )
    detective = conn.execute(
        "SELECT id FROM employees WHERE employee_number = 'EMP-000002'"
    ).fetchone()
    conn.execute(
        "UPDATE employees SET specialties = 'General investigations' "
        "WHERE employee_number = 'EMP-000002' AND specialties = ''"
    )
    conn.execute(
        """
        UPDATE cases SET assigned_employee_id = ?
        WHERE assigned_employee_id IS NULL AND assigned_to LIKE '%K. Ndlovu%'
        """,
        (detective["id"],),
    )
    legacy_cases = conn.execute(
        "SELECT case_id, station, docket_format FROM cases"
    ).fetchall()
    for legacy_case in legacy_cases:
        conn.execute(
            """
            INSERT OR IGNORE INTO dockets
                (docket_number, case_id, created_at, physical_available, storage_location)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                f"DKT-{legacy_case['case_id']}",
                legacy_case["case_id"],
                now_iso(),
                1 if legacy_case["docket_format"] == "Physical" else 0,
                f"{legacy_case['station']} records",
            ),
        )

    case_count = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    if case_count == 0:
        cases = [
            ("DTS-2026-0482", "N. Mokoena", "Johannesburg Central", "Detective K. Ndlovu", "Under Investigation", 11, 68),
            ("DTS-2026-0471", "P. Khumalo", "Durban South", "Detective S. Padayachee", "Registered", 4, 32),
            ("DTS-2026-0458", "R. Sibanda", "Cape Town", "Captain M. Mokoena", "Awaiting Court", 21, 86),
            ("DTS-2026-0432", "L. Dlamini", "Pretoria", "Detective Z. Khuzwayo", "Finalized", 33, 100),
            ("DTS-2026-0501", "A. Mngadi", "Gqeberha", "Docket Unit", "Escalated", 8, 54),
        ]
        conn.executemany(
            "INSERT INTO cases (case_id, complainant, station, assigned_to, status, days_open, progress) VALUES (?, ?, ?, ?, ?, ?, ?)",
            cases,
        )

    log_count = conn.execute("SELECT COUNT(*) FROM docket_logs").fetchone()[0]
    if log_count == 0:
        logs = [
            ("DTS-2026-0482", "Case registered by admin clerk", "Case desk", "06:30"),
            ("DTS-2026-0482", "Docket transferred to detective unit", "Johannesburg Central", "08:15"),
            ("DTS-2026-0482", "Evidence uploaded and linked", "Evidence locker", "12:40"),
            ("DTS-2026-0482", "Supervisor review requested", "Command office", "15:10"),
            ("DTS-2026-0501", "Escalation for overdue review", "Captain desk", "17:05"),
        ]
        conn.executemany(
            "INSERT INTO docket_logs (case_id, action, location, time) VALUES (?, ?, ?, ?)",
            logs,
        )

    audit_count = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    if audit_count == 0:
        seed_time = datetime.now(timezone.utc).isoformat()
        conn.executemany(
            "INSERT INTO audit_events (case_id, actor, actor_role, action, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("DTS-2026-0482", "clerk", "Admin Clerk", "Case registered", "Initial complaint captured and receipt issued.", seed_time),
                ("DTS-2026-0482", "detective", "Detective", "Status changed", "Registered -> Under Investigation.", seed_time),
                ("DTS-2026-0501", "supervisor", "Supervisor", "Escalated", "Overdue supervisor review flagged.", seed_time),
            ],
        )

    all_cases = conn.execute(
        "SELECT case_id, status FROM cases WHERE status NOT IN ('Finalized', 'Closed')"
    ).fetchall()
    for case in all_cases:
        conn.execute(
            "INSERT OR IGNORE INTO case_controls (case_id, next_action, due_at) VALUES (?, ?, ?)",
            (case["case_id"], "Complete the next documented case action", datetime.fromtimestamp(add_days(2), timezone.utc).isoformat(timespec="seconds")),
        )

    conn.executemany(
        "INSERT OR IGNORE INTO legal_references (category, title, summary) VALUES (?, ?, ?)",
        LEGAL_REFERENCES,
    )
    all_case_ids = conn.execute("SELECT case_id FROM cases").fetchall()
    for case in all_case_ids:
        conn.executemany(
            "INSERT OR IGNORE INTO case_compliance (case_id, check_name, requirement) VALUES (?, ?, ?)",
            [(case["case_id"], name, requirement) for name, requirement in COMPLIANCE_CHECKS],
        )
    for case in conn.execute(
        "SELECT id, status, case_type FROM cases"
    ).fetchall():
        conn.execute(
            "INSERT OR IGNORE INTO case_statuses (name) VALUES (?)",
            (case["status"],),
        )
        conn.execute(
            "INSERT OR IGNORE INTO case_types (name) VALUES (?)",
            (case["case_type"] or "General",),
        )
        status_id = conn.execute(
            "SELECT id FROM case_statuses WHERE name = ?", (case["status"],)
        ).fetchone()["id"]
        case_type_id = conn.execute(
            "SELECT id FROM case_types WHERE name = ?",
            (case["case_type"] or "General",),
        ).fetchone()["id"]
        conn.execute(
            "UPDATE cases SET status_id = ?, case_type_id = ? WHERE id = ?",
            (status_id, case_type_id, case["id"]),
        )

    conn.commit()
    conn.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_iso(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def add_days(days):
    return (datetime.now(timezone.utc).timestamp() + (days * 86400))


def add_audit_event(conn, case_id, action, details):
    actor = session.get("user", "system") if has_request_context() else "system"
    actor_role = session.get("role", "System") if has_request_context() else "System"
    ip_address = request.remote_addr or "" if has_request_context() else ""
    conn.execute(
        """
        INSERT INTO audit_events
            (case_id, actor, actor_role, action, details, created_at, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (case_id, actor, actor_role, action, details, now_iso(), ip_address),
    )


def queue_notification(
    conn,
    user_id,
    case_id,
    message,
    channel="In-app",
    recipient_address="",
):
    delivery_status = (
        "Queued - SMS gateway not configured"
        if channel == "SMS"
        else "Queued"
    )
    conn.execute(
        """
        INSERT INTO notifications
            (user_id, case_id, notification_type, channel, message, recipient_address,
             created_at, delivery_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            case_id,
            "Case update",
            channel,
            message,
            recipient_address,
            now_iso(),
            delivery_status,
        ),
    )


def record_case_status(conn, case_id, previous_status, new_status, reason):
    conn.execute(
        """
        UPDATE cases
        SET status = ?, updated_at = CURRENT_TIMESTAMP,
            closed_at = CASE WHEN ? IN ('Closed', 'Finalized') THEN ? ELSE closed_at END
        WHERE case_id = ?
        """,
        (new_status, new_status, now_iso(), case_id),
    )
    conn.execute(
        """
        INSERT INTO case_status_history
            (case_id, previous_status, new_status, changed_by_user_id, changed_at, reason)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            previous_status,
            new_status,
            session.get("user_id") if has_request_context() else None,
            now_iso(),
            reason,
        ),
    )
    add_audit_event(
        conn,
        case_id,
        "Status changed",
        f"{previous_status} -> {new_status}. Reason: {reason}",
    )


def station_id_for(conn, station_name):
    conn.execute(
        "INSERT OR IGNORE INTO stations (name) VALUES (?)",
        (station_name,),
    )
    return conn.execute(
        "SELECT id FROM stations WHERE name = ?", (station_name,)
    ).fetchone()["id"]


def status_id_for(conn, status):
    conn.execute(
        "INSERT OR IGNORE INTO case_statuses (name) VALUES (?)",
        (status,),
    )
    return conn.execute(
        "SELECT id FROM case_statuses WHERE name = ?", (status,)
    ).fetchone()["id"]


def case_type_id_for(conn, case_type):
    conn.execute(
        "INSERT OR IGNORE INTO case_types (name) VALUES (?)",
        (case_type,),
    )
    return conn.execute(
        "SELECT id FROM case_types WHERE name = ?", (case_type,)
    ).fetchone()["id"]


def case_visible_to_current_user(case):
    role = session.get("role")
    if role == "Complainant":
        return case["complainant_user_id"] == session.get("user_id")
    if role == "Detective":
        return case["assigned_employee_id"] == session.get("employee_id")
    if role in {"Captain", "Supervisor"}:
        return case["station"] == session.get("station")
    if role in {"Admin Clerk", "Station Commander"}:
        return case["station"] == session.get("station")
    return role == "System Administrator"


def has_permission(permission):
    return permission in ROLE_PERMISSIONS.get(session.get("role"), set())


def allowed_statuses(current_status, role):
    permissions = ROLE_PERMISSIONS.get(role, set())
    return [
        status
        for status, permission in CASE_TRANSITIONS.get(current_status, {}).items()
        if permission in permissions and status != "Assigned"
    ]


def request_error(message, status_code):
    return render_template(
        "request_error.html",
        current_page="cases",
        user_name=session.get("user", "Officer"),
        user_role=session.get("role", "Station Commander"),
        user_station=session.get("station", "Johannesburg Central"),
        integrity_score=72,
        message=message,
    ), status_code


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                return render_template("forbidden.html", required_roles=", ".join(roles)), 403
            return view(*args, **kwargs)

        return wrapped
    return decorator


def commit_guardrails(conn):
    refresh_guardrails(conn)
    conn.commit()


init_db()
seed_conn = get_db()
init_seed_data(seed_conn)


def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            """
            SELECT id, username, password_hash, role, station, account_status
            FROM users WHERE username = ?
            """,
            (username,),
        ).fetchone()
        valid, legacy_hash = (
            verify_password(password, user["password_hash"])
            if user
            else (False, False)
        )
        if user and valid and user["account_status"] == "Active":
            if legacy_hash:
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (hash_password(password), user["id"]),
                )
            conn.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (now_iso(), user["id"]),
            )
            employee = conn.execute(
                "SELECT id FROM employees WHERE user_id = ?", (user["id"],)
            ).fetchone()
            conn.close()
            session.clear()
            session["user"] = user["username"]
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["station"] = user["station"] or ""
            session["employee_id"] = employee["id"] if employee else None
            if user["role"] == "Complainant":
                return redirect(url_for("my_cases"))
            if user["role"] == "Admin Clerk":
                return redirect(url_for("clerk_dashboard"))
            return redirect(url_for("dashboard"))
        conn.close()

        return render_template(
            "login.html",
            error="Invalid username or password, or this account is inactive.",
        )

    if "user" in session:
        if session.get("role") == "Complainant":
            return redirect(url_for("my_cases"))
        if session.get("role") == "Admin Clerk":
            return redirect(url_for("clerk_dashboard"))
        return redirect(url_for("dashboard"))
    return render_template("login.html", error=None)


@app.route("/register", methods=["GET", "POST"])
def register_complainant():
    if request.method == "GET":
        return render_template("register.html", error=None)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    phone_number = request.form.get("phone_number", "").strip()
    email = request.form.get("email", "").strip().lower()
    id_number = request.form.get("id_number", "").strip()
    address = request.form.get("address", "").strip()
    if (
        not username
        or len(password) < 10
        or not first_name
        or not last_name
        or not phone_number
    ):
        return render_template(
            "register.html",
            error="Enter your name and phone number, and choose a password of at least 10 characters.",
        ), 400

    conn = get_db()
    try:
        cursor = conn.execute(
            """
            INSERT INTO users
                (username, password_hash, role, station, email, phone_number,
                 user_type, account_status, created_at)
            VALUES (?, ?, 'Complainant', '', ?, ?, 'Complainant', 'Active', ?)
            """,
            (username, hash_password(password), email or None, phone_number, now_iso()),
        )
    except sqlite3.IntegrityError:
        conn.close()
        return render_template(
            "register.html",
            error="That username is already in use. Please choose another.",
        ), 409
    user_id = cursor.lastrowid
    conn.execute(
        """
        INSERT INTO complainants
            (user_id, first_name, last_name, id_number, phone_number, address, date_registered)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, first_name, last_name, id_number, phone_number, address, now_iso()),
    )
    conn.commit()
    conn.close()
    session.clear()
    session.update(
        user=username,
        user_id=user_id,
        role="Complainant",
        station="",
        employee_id=None,
    )
    return redirect(url_for("my_cases"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/my-cases")
@require_login
def my_cases():
    if session.get("role") != "Complainant":
        return redirect(url_for("dashboard"))
    conn = get_db()
    cases = conn.execute(
        """
        SELECT case_id, station, status, created_at, updated_at, closing_reason
        FROM cases WHERE complainant_user_id = ?
        ORDER BY created_at DESC, id DESC
        """,
        (session["user_id"],),
    ).fetchall()
    notifications = conn.execute(
        """
        SELECT case_id, channel, message, delivery_status, created_at
        FROM notifications WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 8
        """,
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return render_template(
        "my_cases.html",
        current_page="my_cases",
        user_name=session["user"],
        user_role=session["role"],
        user_station="Complainant portal",
        integrity_score=100,
        cases=cases,
        notifications=notifications,
    )


@app.route("/my-cases/<case_id>")
@require_login
@role_required("Complainant")
def my_case_status(case_id):
    conn = get_db()
    case = conn.execute(
        """
        SELECT case_id, station, status, created_at, closing_reason
        FROM cases WHERE case_id = ? AND complainant_user_id = ?
        """,
        (case_id, session["user_id"]),
    ).fetchone()
    if not case:
        conn.close()
        return "Case not found", 404
    history = conn.execute(
        """
        SELECT previous_status, new_status, changed_at, reason
        FROM case_status_history WHERE case_id = ? ORDER BY changed_at DESC
        """,
        (case_id,),
    ).fetchall()
    conn.close()
    return render_template(
        "my_case_status.html",
        current_page="my_cases",
        user_name=session["user"],
        user_role=session["role"],
        user_station="Complainant portal",
        integrity_score=100,
        case=case,
        history=history,
    )


@app.route("/report-case", methods=["GET", "POST"])
@require_login
def report_case():
    if not has_permission("report_case"):
        return render_template("forbidden.html", required_roles="Complainant"), 403
    conn = get_db()
    stations = conn.execute("SELECT name FROM stations ORDER BY name").fetchall()
    case_types = conn.execute("SELECT name FROM case_types ORDER BY name").fetchall()
    if request.method == "GET":
        conn.close()
        return render_template(
            "report_case.html",
            current_page="my_cases",
            user_name=session["user"],
            user_role=session["role"],
            user_station="Complainant portal",
            integrity_score=100,
            stations=stations,
            case_types=case_types,
        )

    station = request.form.get("station", "").strip()
    case_type = request.form.get("case_type", "").strip()
    statement = request.form.get("statement", "").strip()
    incident_date = request.form.get("incident_date", "").strip()
    incident_location = request.form.get("incident_location", "").strip()
    if (
        not station
        or not case_type
        or len(statement) < 30
        or not incident_date
        or not incident_location
        or station not in {item["name"] for item in stations}
        or case_type not in {item["name"] for item in case_types}
    ):
        conn.close()
        return request_error(
            "Choose a station and provide the incident date, location, category, and a statement of at least 30 characters.",
            400,
        )

    next_id = conn.execute(
        "SELECT COALESCE(MAX(id), 0) + 1 FROM cases"
    ).fetchone()[0]
    case_id = f"DTS-{datetime.now(timezone.utc).year}-{next_id:06d}"
    now = now_iso()
    case_type_id = conn.execute(
        "SELECT id FROM case_types WHERE name = ?", (case_type,)
    ).fetchone()["id"]
    submitted_status_id = conn.execute(
        "SELECT id FROM case_statuses WHERE name = 'Submitted'"
    ).fetchone()["id"]
    cursor = conn.execute(
        """
        INSERT INTO cases
            (case_id, case_type_id, status_id, complainant, station, assigned_to, status, days_open, progress,
             statement, complainant_user_id, incident_date, incident_location,
             case_type, priority, created_at, updated_at, created_by, current_location)
        VALUES (?, ?, ?, ?, ?, 'Awaiting verification', 'Submitted', 0, 5, ?, ?, ?, ?, ?, 'Normal', ?, ?, ?, ?)
        """,
        (
            case_id,
            case_type_id,
            submitted_status_id,
            session["user"],
            station,
            statement,
            session["user_id"],
            incident_date,
            incident_location,
            case_type,
            now,
            now,
            session["user_id"],
            f"{station} public counter",
        ),
    )
    conn.execute(
        """
        INSERT INTO case_status_history
            (case_id, previous_status, new_status, changed_by_user_id, changed_at, reason)
        VALUES (?, '', 'Submitted', ?, ?, 'Online report submitted by complainant')
        """,
        (case_id, session["user_id"], now),
    )
    conn.execute(
        "INSERT INTO case_controls (case_id, next_action, due_at) VALUES (?, ?, ?)",
        (
            case_id,
            "Clerk to verify the submitted report",
            datetime.fromtimestamp(add_days(1), timezone.utc).isoformat(timespec="seconds"),
        ),
    )
    add_audit_event(conn, case_id, "Report submitted", "Complainant submitted an incident statement.")
    queue_notification(
        conn,
        session["user_id"],
        case_id,
        f"Your report {case_id} was received and is awaiting station verification.",
    )
    complainant = conn.execute(
        "SELECT phone_number FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if complainant and complainant["phone_number"]:
        queue_notification(
            conn,
            session["user_id"],
            case_id,
            f"Your report {case_id} was received and is awaiting station verification.",
            channel="SMS",
            recipient_address=complainant["phone_number"],
        )
    clerk_users = conn.execute(
        "SELECT id FROM users WHERE role = 'Admin Clerk' AND account_status = 'Active'"
    ).fetchall()
    for clerk in clerk_users:
        queue_notification(
            conn,
            clerk["id"],
            case_id,
            f"New complainant report {case_id} requires verification.",
        )
    conn.commit()
    conn.close()
    return redirect(url_for("my_cases"))


@app.route("/employees", methods=["GET", "POST"])
@require_login
@role_required("Admin Clerk", "System Administrator")
def employees():
    conn = get_db()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip()
        station = request.form.get("station", "").strip()
        station_address = request.form.get("station_address", "").strip()
        station_contact = request.form.get("station_contact", "").strip()
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone_number = request.form.get("phone_number", "").strip()
        specialties = request.form.get("specialties", "").strip()
        if (
            not username
            or len(password) < 10
            or role not in {"Admin Clerk", "Detective", "Captain", "Station Commander"}
            or not station
            or not first_name
            or not last_name
            or not phone_number
        ):
            conn.close()
            return request_error(
                "Provide the employee details, an approved employee role, and a password of at least 10 characters.",
                400,
            )
        if (
            session.get("role") != "System Administrator"
            and station != session.get("station")
        ):
            conn.close()
            return render_template(
                "forbidden.html",
                required_roles="Clerk assigned to the selected station",
            ), 403
        try:
            user_cursor = conn.execute(
                """
                INSERT INTO users
                    (username, password_hash, role, station, email, phone_number,
                     user_type, account_status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'Employee', 'Active', ?)
                """,
                (
                    username,
                    hash_password(password),
                    role,
                    station,
                    email or None,
                    phone_number,
                    now_iso(),
                ),
            )
        except sqlite3.IntegrityError:
            conn.close()
            return request_error("That username is already registered.", 409)
        station_id = station_id_for(conn, station)
        conn.execute(
            """
            UPDATE stations
            SET address = CASE WHEN ? = '' THEN address ELSE ? END,
                contact_number = CASE WHEN ? = '' THEN contact_number ELSE ? END
            WHERE id = ?
            """,
            (
                station_address,
                station_address,
                station_contact,
                station_contact,
                station_id,
            ),
        )
        employee_id = conn.execute(
            "SELECT COALESCE(MAX(id), 0) + 1 FROM employees"
        ).fetchone()[0]
        employee_number = f"EMP-{employee_id:06d}"
        conn.execute(
            """
            INSERT INTO employees
                (user_id, employee_number, first_name, last_name, station_id, role_id,
                 phone_number, email, date_registered, specialties)
            VALUES (?, ?, ?, ?, ?, (SELECT id FROM roles WHERE name = ?), ?, ?, ?, ?)
            """,
            (
                user_cursor.lastrowid,
                employee_number,
                first_name,
                last_name,
                station_id,
                role,
                phone_number,
                email,
                now_iso(),
                specialties if role == "Detective" else "",
            ),
        )
        if role == "Station Commander":
            conn.execute(
                "UPDATE stations SET commander_user_id = ? WHERE id = ?",
                (user_cursor.lastrowid, station_id),
            )
        add_audit_event(
            conn,
            None,
            "Employee registered",
            f"{employee_number} ({role}) registered for {station}.",
        )
        conn.commit()
        conn.close()
        return redirect(url_for("employees"))

    employee_query = """
        SELECT e.employee_number, e.first_name, e.last_name, e.email, e.phone_number,
               e.specialties,
               e.employment_status, s.name AS station, s.address AS station_address,
               s.contact_number AS station_contact, u.username, u.role
        FROM employees e
        JOIN users u ON u.id = e.user_id
        LEFT JOIN stations s ON s.id = e.station_id
    """
    if session.get("role") == "System Administrator":
        employee_rows = conn.execute(
            employee_query + " ORDER BY s.name, e.employee_number"
        ).fetchall()
    else:
        employee_rows = conn.execute(
            employee_query + " WHERE s.name = ? ORDER BY e.employee_number",
            (session.get("station", ""),),
        ).fetchall()
    conn.close()
    return render_template(
        "employees.html",
        current_page="employees",
        user_name=session["user"],
        user_role=session["role"],
        user_station=session.get("station", ""),
        integrity_score=100,
        employees=employee_rows,
    )


@app.route("/assignments")
@require_login
@role_required("Station Commander", "System Administrator")
def assignments():
    conn = get_db()
    case_query = """
        SELECT c.*, d.id AS docket_id, d.docket_number
        FROM cases c LEFT JOIN dockets d ON d.case_id = c.case_id
        WHERE c.status NOT IN ('Closed', 'Finalized')
    """
    if session.get("role") == "System Administrator":
        cases = conn.execute(
            case_query + " ORDER BY c.created_at DESC, c.id DESC"
        ).fetchall()
    else:
        cases = conn.execute(
            case_query + " AND c.station = ? ORDER BY c.created_at DESC, c.id DESC",
            (session.get("station", ""),),
        ).fetchall()
    detective_query = """
        SELECT e.id, e.employee_number, e.first_name, e.last_name, e.specialties,
               s.name AS station,
               (SELECT COUNT(*) FROM cases c
                WHERE c.assigned_employee_id = e.id
                  AND c.status NOT IN ('Closed', 'Finalized')) AS active_cases
        FROM employees e JOIN users u ON u.id = e.user_id
        LEFT JOIN stations s ON s.id = e.station_id
        WHERE u.role = 'Detective' AND u.account_status = 'Active'
    """
    if session.get("role") == "System Administrator":
        detectives = conn.execute(
            detective_query + " ORDER BY s.name, e.last_name, e.first_name"
        ).fetchall()
    else:
        detectives = conn.execute(
            detective_query + " AND s.name = ? ORDER BY e.last_name, e.first_name",
            (session.get("station", ""),),
        ).fetchall()
    conn.close()
    return render_template(
        "assignments.html",
        current_page="assignments",
        user_name=session["user"],
        user_role=session["role"],
        user_station=session.get("station", ""),
        integrity_score=100,
        cases=cases,
        detectives=detectives,
        can_assign=session.get("role") in {"Station Commander", "System Administrator"},
    )


@app.route("/cases/<case_id>/verify", methods=["POST"])
@require_login
@role_required("Admin Clerk", "System Administrator")
def verify_case(case_id):
    conn = get_db()
    case = conn.execute(
        "SELECT * FROM cases WHERE case_id = ?", (case_id,)
    ).fetchone()
    if not case:
        conn.close()
        return "Case not found", 404
    if case["status"] != "Submitted":
        conn.close()
        return request_error("Only a submitted report can be verified.", 409)
    if (
        session.get("role") != "System Administrator"
        and case["station"] != session.get("station")
    ):
        conn.close()
        return render_template(
            "forbidden.html",
            required_roles="Clerk assigned to the case station",
        ), 403

    docket_format = request.form.get("docket_format", "Electronic").strip()
    if docket_format not in {"Electronic", "Physical"}:
        conn.close()
        return request_error("Choose Electronic or Physical docket format.", 400)
    now = now_iso()
    storage_location = request.form.get("storage_location", "").strip()
    physical_serial = request.form.get("physical_serial", "").strip()
    evidence_list = request.form.get("evidence_list", "").strip()
    if not storage_location or not evidence_list:
        conn.close()
        return request_error("Provide a shelf location and record the evidence list, or enter 'None'.", 400)
    if docket_format == "Physical" and not physical_serial:
        conn.close()
        return request_error("A physical docket requires its physical serial number.", 400)
    clerk = conn.execute(
        "SELECT id FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    docket_number = f"DKT-{case_id}"
    conn.execute(
        """
        INSERT INTO dockets
            (docket_number, case_id, created_by, created_at, physical_available,
             current_holder_employee_id, storage_location, physical_serial, evidence_list)
        VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)
        """,
        (
            docket_number,
            case_id,
            clerk["id"],
            now,
            1 if docket_format == "Physical" else 0,
            storage_location,
            physical_serial,
            evidence_list,
        ),
    )
    docket_id = conn.execute(
        "SELECT id FROM dockets WHERE case_id = ?", (case_id,)
    ).fetchone()["id"]
    conn.execute(
        """
        UPDATE cases
        SET status = 'Registered', status_id = ?, progress = 15, verified_by = ?,
            docket_format = ?, current_location = ?, updated_at = CURRENT_TIMESTAMP
        WHERE case_id = ?
        """,
        (
            status_id_for(conn, "Registered"),
            session["user_id"],
            docket_format,
            storage_location,
            case_id,
        ),
    )
    conn.execute(
        """
        INSERT INTO case_status_history
            (case_id, previous_status, new_status, changed_by_user_id, changed_at, reason)
        VALUES (?, 'Submitted', 'Registered', ?, ?, 'Report verified and docket opened by clerk')
        """,
        (case_id, session["user_id"], now),
    )
    conn.execute(
        "UPDATE case_controls SET next_action = ?, due_at = ? WHERE case_id = ?",
        (
            "Station Commander to assign an investigating detective",
            datetime.fromtimestamp(add_days(1), timezone.utc).isoformat(timespec="seconds"),
            case_id,
        ),
    )
    conn.execute(
        "INSERT INTO docket_logs (case_id, action, location, time) VALUES (?, ?, ?, ?)",
        (case_id, f"{docket_format} docket opened: {docket_number}", storage_location, now),
    )
    add_audit_event(conn, case_id, "Report verified and docket opened", docket_number)
    complainant = conn.execute(
        "SELECT phone_number FROM users WHERE id = ?",
        (case["complainant_user_id"],),
    ).fetchone() if case["complainant_user_id"] else None
    complainant_phone = (
        complainant["phone_number"]
        if complainant
        else case["complainant_phone"]
    )
    if complainant:
        message = (
            f"Your report {case_id} has been verified and opened for investigation. "
            "It is awaiting detective assignment."
        )
        queue_notification(conn, case["complainant_user_id"], case_id, message)
    if complainant_phone:
        queue_notification(
            conn,
            case["complainant_user_id"],
            case_id,
            (
                f"Your report {case_id} has been verified and opened for investigation. "
                "It is awaiting detective assignment."
            ),
            channel="SMS",
            recipient_address=complainant_phone,
        )
    command_users = conn.execute(
        """
        SELECT id FROM users
        WHERE station = ? AND role = 'Station Commander'
              AND account_status = 'Active'
        """,
        (case["station"],),
    ).fetchall()
    for worker in command_users:
        queue_notification(
            conn,
            worker["id"],
            case_id,
            f"Docket {docket_number} is open and awaiting detective assignment.",
        )
    conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/cases/<case_id>/assign", methods=["POST"])
@require_login
@role_required("Station Commander", "System Administrator")
def assign_detective(case_id):
    conn = get_db()
    case = conn.execute(
        "SELECT * FROM cases WHERE case_id = ?", (case_id,)
    ).fetchone()
    if not case:
        conn.close()
        return "Case not found", 404
    if (
        session.get("role") != "System Administrator"
        and case["station"] != session.get("station")
    ):
        conn.close()
        return render_template("forbidden.html", required_roles="Station Commander for this station"), 403
    if case["status"] not in {"Registered", "Assigned"}:
        conn.close()
        return request_error("Only registered or assigned cases can be assigned.", 409)

    try:
        detective_id = int(request.form.get("detective_id", ""))
    except ValueError:
        conn.close()
        return request_error("Choose an active detective.", 400)
    detective = conn.execute(
        """
        SELECT e.*, u.id AS user_id, u.username, s.name AS station_name
        FROM employees e
        JOIN users u ON u.id = e.user_id
        LEFT JOIN stations s ON s.id = e.station_id
        WHERE e.id = ? AND u.role = 'Detective' AND u.account_status = 'Active'
        """,
        (detective_id,),
    ).fetchone()
    if not detective or detective["station_name"] != case["station"]:
        conn.close()
        return request_error("Select an active detective at the case station.", 400)
    docket = conn.execute(
        "SELECT * FROM dockets WHERE case_id = ?", (case_id,)
    ).fetchone()
    if not docket:
        conn.close()
        return request_error("The clerk must open a docket before assignment.", 409)

    now = now_iso()
    previous_employee_id = case["assigned_employee_id"]
    conn.execute(
        """
        UPDATE detective_assignments SET status = 'Reassigned'
        WHERE case_id = ? AND status IN ('Assigned', 'Accepted')
        """,
        (case_id,),
    )
    conn.execute(
        """
        INSERT INTO detective_assignments
            (case_id, docket_id, detective_id, assigned_by, assigned_at, status)
        VALUES (?, ?, ?, ?, ?, 'Assigned')
        """,
        (case_id, docket["id"], detective_id, session["user_id"], now),
    )
    conn.execute(
        """
        UPDATE cases
        SET assigned_employee_id = ?, assigned_to = ?, status = 'Assigned',
            status_id = ?,
            progress = 25, updated_at = CURRENT_TIMESTAMP
        WHERE case_id = ?
        """,
        (
            detective_id,
            f"Detective {detective['first_name']} {detective['last_name']}",
            status_id_for(conn, "Assigned"),
            case_id,
        ),
    )
    from_location = case["current_location"] or f"{case['station']} case intake"
    to_location = f"{case['station']} detective unit"
    conn.execute(
        """
        INSERT INTO docket_movements
            (docket_id, from_employee_id, to_employee_id, from_location, to_location,
             moved_by_user_id, moved_at, movement_type, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            docket["id"],
            previous_employee_id,
            detective_id,
            from_location,
            to_location,
            session["user_id"],
            now,
            case["docket_format"],
            "Station Commander assigned docket for investigation",
        ),
    )
    movement_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        """
        INSERT INTO custody_transfers
            (case_id, from_location, to_location, transferred_by, reason, created_at,
             movement_id, movement_type, from_employee_id, to_employee_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            from_location,
            to_location,
            session["user"],
            "Station Commander assigned docket for investigation",
            now,
            movement_id,
            case["docket_format"],
            previous_employee_id,
            detective_id,
        ),
    )
    conn.execute(
        """
        UPDATE dockets SET storage_location = ?
        WHERE id = ?
        """,
        (to_location, docket["id"]),
    )
    conn.execute(
        """
        INSERT INTO case_status_history
            (case_id, previous_status, new_status, changed_by_user_id, changed_at, reason)
        VALUES (?, ?, 'Assigned', ?, ?, ?)
        """,
        (
            case_id,
            case["status"],
            session["user_id"],
            now,
            "Detective assignment by Station Commander",
        ),
    )
    conn.execute(
        "UPDATE case_controls SET next_action = ?, due_at = ? WHERE case_id = ?",
        (
            "Assigned detective to acknowledge docket receipt",
            datetime.fromtimestamp(add_days(1), timezone.utc).isoformat(timespec="seconds"),
            case_id,
        ),
    )
    queue_notification(
        conn,
        detective["user_id"],
        case_id,
        f"You have been assigned docket {docket['docket_number']}. Please confirm receipt.",
    )
    commanders = conn.execute(
        """
        SELECT id FROM users
        WHERE station = ? AND role = 'Station Commander'
              AND account_status = 'Active'
        """,
        (case["station"],),
    ).fetchall()
    for commander in commanders:
        queue_notification(
            conn,
            commander["id"],
            case_id,
            f"Docket {docket['docket_number']} assigned to {detective['first_name']} {detective['last_name']}.",
        )
    if case["complainant_user_id"]:
        queue_notification(
            conn,
            case["complainant_user_id"],
            case_id,
            f"Docket {case_id} has been assigned to an investigating detective.",
        )
    add_audit_event(
        conn,
        case_id,
        "Detective assigned",
        f"{detective['employee_number']} assigned; docket movement {movement_id} awaits receipt confirmation.",
    )
    conn.commit()
    conn.close()
    return redirect(url_for("dashboard"))


@app.route("/cases/<case_id>/receive", methods=["POST"])
@require_login
@role_required("Detective")
def receive_docket(case_id):
    conn = get_db()
    assignment = conn.execute(
        """
        SELECT a.*, d.docket_number
        FROM detective_assignments a
        JOIN dockets d ON d.id = a.docket_id
        WHERE a.case_id = ? AND a.detective_id = ? AND a.status = 'Assigned'
        ORDER BY a.assigned_at DESC LIMIT 1
        """,
        (case_id, session.get("employee_id")),
    ).fetchone()
    if not assignment:
        conn.close()
        return render_template("forbidden.html", required_roles="The detective assigned to this docket"), 403
    now = now_iso()
    conn.execute(
        "UPDATE detective_assignments SET accepted_at = ?, status = 'Accepted' WHERE id = ?",
        (now, assignment["id"]),
    )
    pending_movements = conn.execute(
        """
        SELECT id FROM docket_movements
        WHERE docket_id = ? AND to_employee_id = ? AND received_at IS NULL
        ORDER BY moved_at DESC LIMIT 1
        """,
        (assignment["docket_id"], session["employee_id"]),
    ).fetchone()
    if pending_movements:
        conn.execute(
            """
            UPDATE docket_movements
            SET received_at = ?, received_by_employee_id = ?
            WHERE id = ?
            """,
            (now, session["employee_id"], pending_movements["id"]),
        )
    if pending_movements:
        conn.execute(
            """
            UPDATE custody_transfers
            SET received_at = ?, received_by_employee_id = ?
            WHERE movement_id = ?
            """,
            (now, session["employee_id"], pending_movements["id"]),
        )
    conn.execute(
        "UPDATE dockets SET current_holder_employee_id = ? WHERE id = ?",
        (session["employee_id"], assignment["docket_id"]),
    )
    add_audit_event(
        conn,
        case_id,
        "Docket receipt confirmed",
        f"{assignment['docket_number']} received by {session['user']}.",
    )
    conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/docket-movements/<int:movement_id>/receive", methods=["POST"])
@require_login
def receive_movement(movement_id):
    conn = get_db()
    movement = conn.execute(
        """
        SELECT m.*, d.case_id, c.assigned_employee_id
        FROM docket_movements m JOIN dockets d ON d.id = m.docket_id
        JOIN cases c ON c.case_id = d.case_id
        WHERE m.id = ?
        """,
        (movement_id,),
    ).fetchone()
    if (
        not movement
        or not session.get("employee_id")
        or movement["to_employee_id"] != session.get("employee_id")
        or movement["assigned_employee_id"] != session.get("employee_id")
        or movement["received_at"]
    ):
        conn.close()
        return render_template("forbidden.html", required_roles="The employee awaiting this docket"), 403
    now = now_iso()
    conn.execute(
        """
        UPDATE docket_movements SET received_at = ?, received_by_employee_id = ?
        WHERE id = ?
        """,
        (now, session["employee_id"], movement_id),
    )
    conn.execute(
        """
        UPDATE custody_transfers
        SET received_at = ?, received_by_employee_id = ?
        WHERE movement_id = ?
        """,
        (now, session["employee_id"], movement_id),
    )
    conn.execute(
        "UPDATE dockets SET current_holder_employee_id = ? WHERE id = ?",
        (session["employee_id"], movement["docket_id"]),
    )
    add_audit_event(
        conn,
        movement["case_id"],
        "Docket movement received",
        f"Movement {movement_id} confirmed by {session['user']}.",
    )
    conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=movement["case_id"]))


@app.route("/notifications")
@require_login
def notifications():
    conn = get_db()
    messages = conn.execute(
        """
        SELECT case_id, notification_type, channel, message, created_at, delivery_status
        FROM notifications WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 100
        """,
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return render_template(
        "notifications.html",
        current_page="notifications",
        user_name=session["user"],
        user_role=session["role"],
        user_station=session.get("station", ""),
        integrity_score=100,
        messages=messages,
    )


@app.route("/cases/<case_id>/close", methods=["POST"])
@require_login
@role_required("Station Commander", "System Administrator")
def close_case(case_id):
    reason = request.form.get("closing_reason", "").strip()
    outcome = request.form.get("outcome", "").strip()
    if outcome not in {"Investigation completed", "Dead end"} or not reason:
        return request_error("Choose a closure outcome and provide the closing reason.", 400)
    if request.form.get("report_reviewed") != "yes":
        return request_error("Confirm that the investigation report and evidence have been reviewed.", 400)
    conn = get_db()
    case = conn.execute(
        "SELECT * FROM cases WHERE case_id = ?", (case_id,)
    ).fetchone()
    if not case:
        conn.close()
        return "Case not found", 404
    if (
        session.get("role") != "System Administrator"
        and case["station"] != session.get("station")
    ):
        conn.close()
        return render_template("forbidden.html", required_roles="Station Commander for this station"), 403
    if case["status"] != "Awaiting Supervisor Review":
        conn.close()
        return request_error("A detective must submit the investigation report before closure approval.", 409)
    now = now_iso()
    conn.execute(
        """
        UPDATE cases SET status = 'Closed', status_id = ?, progress = 100, closed_at = ?,
            closing_reason = ?, updated_at = CURRENT_TIMESTAMP
        WHERE case_id = ?
        """,
        (status_id_for(conn, "Closed"), now, f"{outcome}: {reason}", case_id),
    )
    conn.execute(
        "UPDATE dockets SET status = 'Closed', closed_at = ? WHERE case_id = ?",
        (now, case_id),
    )
    conn.execute(
        """
        UPDATE detective_assignments SET status = 'Completed', completed_at = ?
        WHERE case_id = ? AND status IN ('Assigned', 'Accepted')
        """,
        (now, case_id),
    )
    conn.execute(
        """
        INSERT INTO case_status_history
            (case_id, previous_status, new_status, changed_by_user_id, changed_at, reason)
        VALUES (?, ?, 'Closed', ?, ?, ?)
        """,
        (
            case_id,
            case["status"],
            session["user_id"],
            now,
            f"Investigation report and evidence reviewed. {outcome}: {reason}",
        ),
    )
    add_audit_event(
        conn,
        case_id,
        "Commander approved case closure",
        f"Investigation report and evidence reviewed. {outcome}: {reason}",
    )
    message = f"Case {case_id} has been closed: {outcome}. Please contact your station for details."
    if case["complainant_user_id"]:
        queue_notification(conn, case["complainant_user_id"], case_id, message)
    if case["complainant_user_id"] or case["complainant_phone"]:
        queue_notification(
            conn,
            case["complainant_user_id"],
            case_id,
            message,
            channel="SMS",
            recipient_address=case["complainant_phone"],
        )
    conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/")
@require_login
def index():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@require_login
def dashboard():
    if session.get("role") == "Admin Clerk":
        return redirect(url_for("clerk_dashboard"))
    if session.get("role") == "Complainant":
        return redirect(url_for("my_cases"))
    conn = get_db()
    commit_guardrails(conn)
    cases = conn.execute("SELECT * FROM cases ORDER BY updated_at DESC").fetchall()
    role = session.get("role", "Station Commander")
    visible_cases = [case for case in cases if case_visible_to_current_user(case)]
    visible_case_ids = [case["case_id"] for case in visible_cases]
    if role == "System Administrator":
        recent_activity = conn.execute(
            "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 8"
        ).fetchall()
    elif visible_case_ids:
        placeholders = ",".join("?" for _ in visible_case_ids)
        recent_activity = conn.execute(
            f"SELECT * FROM audit_events WHERE case_id IN ({placeholders}) ORDER BY created_at DESC LIMIT 8",
            visible_case_ids,
        ).fetchall()
    else:
        recent_activity = []
    role = session.get("role", "Station Commander")
    command_cases = []
    detectives = []
    if role in {"Station Commander", "System Administrator"}:
        command_query = """
            SELECT c.*, d.id AS docket_id, d.docket_number, d.physical_serial,
                   d.storage_location, d.evidence_list
            FROM cases c LEFT JOIN dockets d ON d.case_id = c.case_id
            WHERE c.status IN ('Registered', 'Awaiting Supervisor Review')
        """
        if role == "System Administrator":
            command_cases = conn.execute(
                command_query + " ORDER BY c.created_at ASC, c.id ASC"
            ).fetchall()
            detective_query = """
                SELECT e.id, e.employee_number, e.first_name, e.last_name,
                       e.specialties, s.name AS station,
                       (SELECT COUNT(*) FROM cases c
                        WHERE c.assigned_employee_id = e.id
                          AND c.status NOT IN ('Closed', 'Finalized')) AS active_cases
                FROM employees e JOIN users u ON u.id = e.user_id
                LEFT JOIN stations s ON s.id = e.station_id
                WHERE u.role = 'Detective' AND u.account_status = 'Active'
                ORDER BY s.name, e.last_name, e.first_name
            """
            detectives = conn.execute(detective_query).fetchall()
        else:
            command_cases = conn.execute(
                command_query + " AND c.station = ? ORDER BY c.created_at ASC, c.id ASC",
                (session.get("station", ""),),
            ).fetchall()
            detective_query = """
                SELECT e.id, e.employee_number, e.first_name, e.last_name,
                       e.specialties, s.name AS station,
                       (SELECT COUNT(*) FROM cases c
                        WHERE c.assigned_employee_id = e.id
                          AND c.status NOT IN ('Closed', 'Finalized')) AS active_cases
                FROM employees e JOIN users u ON u.id = e.user_id
                LEFT JOIN stations s ON s.id = e.station_id
                WHERE u.role = 'Detective' AND u.account_status = 'Active'
                      AND s.name = ?
                ORDER BY e.last_name, e.first_name
            """
            detectives = conn.execute(
                detective_query, (session.get("station", ""),)
            ).fetchall()
    conn.close()
    chart_statuses = [
        ("Submitted", "var(--primary)"),
        ("Registered", "var(--primary)"),
        ("Assigned", "var(--purple)"),
        ("Under Investigation", "var(--purple)"),
        ("Awaiting Evidence", "var(--warning)"),
        ("Escalated", "var(--danger)"),
        ("Closed", "var(--success)"),
    ]
    largest_status_count = max(
        (sum(1 for case in visible_cases if case["status"] == label) for label, _ in chart_statuses),
        default=0,
    )
    status_breakdown = [
        {
            "label": label,
            "count": sum(1 for case in visible_cases if case["status"] == label),
            "height": max(
                8,
                round(
                    100
                    * sum(1 for case in visible_cases if case["status"] == label)
                    / largest_status_count
                ),
            ) if largest_status_count else 8,
            "color": color,
        }
        for label, color in chart_statuses
    ]

    open_cases = sum(1 for case in visible_cases if case["status"] not in {"Finalized", "Closed"})
    require_action = sum(
        1 for case in visible_cases
        if case["status"] in ["Registered", "Awaiting Supervisor Review", "Escalated", "Under Investigation"]
    )
    avg_days = round(
        sum(case["days_open"] for case in visible_cases) / len(visible_cases), 1
    ) if visible_cases else 0
    finalized = sum(1 for case in visible_cases if case["status"] in {"Finalized", "Closed"})

    summary = {
        "open_cases": open_cases,
        "open_trend": {
            "System Administrator": "System-wide view",
            "Station Commander": "Station-wide view",
            "Captain": "Station oversight",
            "Supervisor": "Review queue monitored",
            "Detective": "Assigned caseload",
            "Admin Clerk": "Intake queue",
        }.get(role, "Operational view"),
        "require_action": require_action,
        "action_trend": {
            "System Administrator": "Access and workflow health",
            "Station Commander": "Assignments and escalations",
            "Captain": "Station workflow overview",
            "Supervisor": "Reviews and exceptions",
            "Detective": "Investigation tasks",
            "Admin Clerk": "Registration and receipts",
        }.get(role, "Current actions"),
        "avg_days": avg_days,
        "days_trend": "Live from case records",
        "finalized": finalized,
    }

    queue_rules = {
        "System Administrator": ["Escalated"],
        "Station Commander": ["Escalated"],
        "Captain": ["Escalated"],
        "Supervisor": ["Escalated", "Awaiting Supervisor Review"],
        "Detective": ["Assigned", "Under Investigation", "Awaiting Evidence"],
        "Admin Clerk": ["Registered"],
    }
    action_queue = [
        dict(case) for case in visible_cases
        if case["status"] in queue_rules.get(role, ["Registered", "Escalated"])
    ]
    role_copy = {
        "System Administrator": ("System control centre", "Monitor account access, workflow integrity, and audit health."),
        "Station Commander": ("Station command dashboard", "Review the pending docket queue, assign detectives, and approve completed investigation reports."),
        "Captain": ("Station oversight dashboard", "Review station activity and escalations."),
        "Supervisor": ("Supervision and review queue", "Resolve overdue reviews, refusal reports, and custody exceptions."),
        "Detective": ("Investigation workspace", "Progress assigned dockets, request evidence, and keep the custody chain current."),
        "Admin Clerk": ("Case intake desk", "Register complaints, issue receipts, and route dockets to the correct owner."),
    }
    metric_labels = {
        "System Administrator": ("All open cases", "System exceptions", "Avg. days open", "Closed records"),
        "Station Commander": ("Open station cases", "Pending command actions", "Avg. days open", "Approved closures"),
        "Captain": ("Station cases", "Escalations to monitor", "Avg. days open", "Closed cases"),
        "Supervisor": ("Cases under oversight", "Reviews and exceptions", "Avg. days open", "Closed cases"),
        "Detective": ("My open dockets", "Investigation tasks", "Avg. days assigned", "Closed dockets"),
    }
    queue_titles = {
        "System Administrator": "System-wide exceptions",
        "Station Commander": "Escalations requiring review",
        "Captain": "Station escalation queue",
        "Supervisor": "Reviews and exceptions queue",
        "Detective": "My investigation queue",
    }
    queue_descriptions = {
        "System Administrator": "Station cases and exceptions that need system-level monitoring.",
        "Station Commander": "Overdue or escalated station cases requiring command attention.",
        "Captain": "Station escalations available for oversight; detective assignment remains with the Station Commander.",
        "Supervisor": "Cases awaiting review or escalated for supervisory attention.",
        "Detective": "Your assigned dockets with investigation work still outstanding.",
    }
    activity_titles = {
        "System Administrator": "Recent system activity",
        "Station Commander": "Recent station command activity",
        "Captain": "Recent station activity",
        "Supervisor": "Recent review activity",
        "Detective": "Recent activity on my dockets",
    }

    return render_template(
        "dashboard.html",
        current_page="dashboard",
        user_name=session.get("user", "Officer"),
        user_role=session.get("role", "Station Commander"),
        user_station=session.get("station", "Johannesburg Central"),
        integrity_score=72,
        summary=summary,
        status_breakdown=status_breakdown,
        recent_activity=recent_activity,
        action_queue=action_queue,
        command_cases=command_cases,
        detectives=detectives,
        dashboard_title=role_copy.get(role, ("Operations dashboard", "Monitor current case activity."))[0],
        dashboard_description=role_copy.get(role, ("Operations dashboard", "Monitor current case activity."))[1],
        role=role,
        metric_labels=metric_labels.get(
            role,
            ("Open cases", "Requiring action", "Avg. days open", "Closed cases"),
        ),
        queue_title=queue_titles.get(role, "Your action queue"),
        queue_description=queue_descriptions.get(
            role,
            f"Cases and tasks that require attention for the {role} role.",
        ),
        activity_title=activity_titles.get(role, "Recent activity"),
    )


@app.route("/clerk")
@require_login
@role_required("Admin Clerk")
def clerk_dashboard():
    conn = get_db()
    commit_guardrails(conn)
    cases = conn.execute(
        "SELECT * FROM cases WHERE station = ? ORDER BY updated_at DESC",
        (session.get("station", ""),),
    ).fetchall()
    recent_activity = conn.execute(
        """
        SELECT a.* FROM audit_events a JOIN cases c ON c.case_id = a.case_id
        WHERE c.station = ? ORDER BY a.created_at DESC LIMIT 6
        """,
        (session.get("station", ""),),
    ).fetchall()
    conn.close()

    intake_cases = [case for case in cases if case["status"] == "Submitted"]
    summary = {
        "registered": len(intake_cases),
        "open_cases": sum(
            1 for case in cases if case["status"] not in {"Finalized", "Closed"}
        ),
        "receipts": sum(1 for event in recent_activity if event["actor"] == session["user"]),
        "transfers": sum(1 for event in recent_activity if event["action"] == "Docket transferred"),
    }
    return render_template(
        "clerk_dashboard.html",
        current_page="clerk",
        user_name=session["user"],
        user_role=session["role"],
        user_station=session["station"],
        integrity_score=72,
        summary=summary,
        intake_cases=intake_cases,
        recent_activity=recent_activity,
    )


@app.route("/cases", methods=["GET"])
@require_login
def cases():
    if session.get("role") == "Complainant":
        return redirect(url_for("my_cases"))
    query = request.args.get("q", "").strip().lower()
    selected_status = request.args.get("status", "All")

    conn = get_db()
    commit_guardrails(conn)
    case_rows = conn.execute(
        "SELECT * FROM cases ORDER BY updated_at DESC, id DESC"
    ).fetchall()
    case_types = conn.execute(
        "SELECT name FROM case_types ORDER BY name"
    ).fetchall()
    conn.close()

    filtered = []
    for case in case_rows:
        if not case_visible_to_current_user(case):
            continue
        haystack = " ".join([
            case["case_id"], case["complainant"], case["station"], case["assigned_to"], case["status"]
        ]).lower()
        matches_query = not query or query in haystack
        matches_status = selected_status == "All" or case["status"] == selected_status
        if matches_query and matches_status:
            filtered.append(dict(case))

    return render_template(
        "cases.html",
        current_page="cases",
        user_name=session.get("user", "Officer"),
        user_role=session.get("role", "Station Commander"),
        user_station=session.get("station", "Johannesburg Central"),
        integrity_score=72,
        cases=filtered,
        status_palette=STATUS_COLORS,
        search_query=request.args.get("q", ""),
        selected_status=selected_status,
        can_register=has_permission("register"),
        case_types=case_types,
    )


@app.route("/cases/new", methods=["POST"])
@require_login
def create_case():
    if not has_permission("register"):
        return render_template("forbidden.html", required_roles="Admin Clerk"), 403
    case_id = request.form.get("case_id", "").strip()
    complainant = request.form.get("complainant", "").strip()
    station = request.form.get("station", "").strip()
    statement = request.form.get("statement", "").strip()
    incident_date = request.form.get("incident_date", "").strip()
    incident_location = request.form.get("incident_location", "").strip()
    case_type = request.form.get("case_type", "General").strip() or "General"
    complainant_phone = request.form.get("complainant_phone", "").strip()
    complainant_email = request.form.get("complainant_email", "").strip()
    complainant_id_number = request.form.get("complainant_id_number", "").strip()
    complainant_address = request.form.get("complainant_address", "").strip()
    days_open = 0
    if (
        not complainant
        or not station
        or not statement
        or len(statement) < 30
        or not incident_date
        or not incident_location
    ):
        return redirect(url_for("cases"))
    if (
        session.get("role") != "System Administrator"
        and station != session.get("station")
    ):
        return render_template(
            "forbidden.html",
            required_roles="Clerk assigned to the selected station",
        ), 403

    conn = get_db()
    if not case_id:
        next_id = conn.execute(
            "SELECT COALESCE(MAX(id), 0) + 1 FROM cases"
        ).fetchone()[0]
        case_id = f"DTS-{datetime.now(timezone.utc).year}-{next_id:06d}"
    case_type_id = case_type_id_for(conn, case_type)
    submitted_status_id = status_id_for(conn, "Submitted")
    try:
        conn.execute(
            """
            INSERT INTO cases
                (case_id, case_type_id, status_id, complainant, station, assigned_to, status, days_open, progress,
                 statement, incident_date, incident_location, case_type, created_by,
                 created_at, current_location, complainant_phone, complainant_email,
                 complainant_id_number, complainant_address)
            VALUES (?, ?, ?, ?, ?, 'Awaiting verification', 'Submitted', ?, 5, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                case_type_id,
                submitted_status_id,
                complainant,
                station,
                days_open,
                statement,
                incident_date,
                incident_location,
                case_type,
                session["user_id"],
                now_iso(),
                f"{station} case intake",
                complainant_phone,
                complainant_email,
                complainant_id_number,
                complainant_address,
            ),
        )
    except sqlite3.IntegrityError:
        conn.close()
        return request_error("That case ID is already registered.", 409)
    conn.execute(
        "INSERT INTO docket_logs (case_id, action, location, time) VALUES (?, ?, ?, ?)",
        (case_id, "Report captured for verification", station, now_iso()),
    )
    add_audit_event(conn, case_id, "Report captured", f"Clerk captured complaint at {station}.")
    conn.execute(
        "INSERT INTO case_controls (case_id, next_action, due_at, escalation_level) VALUES (?, ?, ?, 0)",
        (case_id, "Clerk to verify the report and open the docket", datetime.fromtimestamp(add_days(1), timezone.utc).isoformat(timespec="seconds")),
    )
    conn.execute(
        """
        INSERT INTO case_status_history
            (case_id, previous_status, new_status, changed_by_user_id, changed_at, reason)
        VALUES (?, '', 'Submitted', ?, ?, 'Complaint captured by administration clerk')
        """,
        (case_id, session["user_id"], now_iso()),
    )
    conn.commit()
    conn.close()

    return redirect(url_for("cases"))


@app.route("/cases/<case_id>")
@require_login
def case_detail(case_id):
    if session.get("role") == "Complainant":
        return redirect(url_for("my_case_status", case_id=case_id))
    conn = get_db()
    commit_guardrails(conn)
    case = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    if not case:
        conn.close()
        return "Case not found", 404
    if not case_visible_to_current_user(case):
        conn.close()
        return render_template(
            "forbidden.html",
            required_roles="The case complainant or authorized station staff",
        ), 403
    audit_events = conn.execute(
        "SELECT * FROM audit_events WHERE case_id = ? ORDER BY created_at DESC", (case_id,)
    ).fetchall()
    custody = conn.execute(
        "SELECT * FROM custody_transfers WHERE case_id = ? ORDER BY created_at DESC", (case_id,)
    ).fetchall()
    refusal = conn.execute(
        "SELECT * FROM refusal_reviews WHERE case_id = ? ORDER BY created_at DESC LIMIT 1", (case_id,)
    ).fetchone()
    control = conn.execute(
        "SELECT * FROM case_controls WHERE case_id = ?", (case_id,)
    ).fetchone()
    compliance = conn.execute(
        "SELECT * FROM case_compliance WHERE case_id = ? ORDER BY id", (case_id,)
    ).fetchall()
    movements = conn.execute(
        """
        SELECT m.*, from_e.employee_number AS from_employee_number,
               to_e.employee_number AS to_employee_number,
               received_e.employee_number AS received_employee_number,
               u.username AS moved_by
        FROM docket_movements m
        LEFT JOIN employees from_e ON from_e.id = m.from_employee_id
        LEFT JOIN employees to_e ON to_e.id = m.to_employee_id
        LEFT JOIN employees received_e ON received_e.id = m.received_by_employee_id
        LEFT JOIN users u ON u.id = m.moved_by_user_id
        JOIN dockets d ON d.id = m.docket_id
        WHERE d.case_id = ? ORDER BY m.moved_at DESC
        """,
        (case_id,),
    ).fetchall()
    status_history = conn.execute(
        """
        SELECT h.*, u.username AS changed_by
        FROM case_status_history h
        LEFT JOIN users u ON u.id = h.changed_by_user_id
        WHERE h.case_id = ? ORDER BY h.changed_at DESC
        """,
        (case_id,),
    ).fetchall()
    detectives = conn.execute(
        """
        SELECT e.id, e.employee_number, e.first_name, e.last_name,
               e.specialties, s.name AS station,
               (SELECT COUNT(*) FROM cases active_case
                WHERE active_case.assigned_employee_id = e.id
                  AND active_case.status NOT IN ('Closed', 'Finalized')) AS active_cases
        FROM employees e JOIN users u ON u.id = e.user_id
        LEFT JOIN stations s ON s.id = e.station_id
        WHERE u.role = 'Detective' AND u.account_status = 'Active'
              AND s.name = ?
        ORDER BY e.last_name, e.first_name
        """,
        (case["station"],),
    ).fetchall()
    latest_assignment = conn.execute(
        """
        SELECT status, accepted_at FROM detective_assignments
        WHERE case_id = ? ORDER BY assigned_at DESC LIMIT 1
        """,
        (case_id,),
    ).fetchone()
    docket = conn.execute(
        "SELECT * FROM dockets WHERE case_id = ?", (case_id,)
    ).fetchone()
    station_employees = conn.execute(
        """
        SELECT e.id, e.employee_number, e.first_name, e.last_name, u.role
        FROM employees e JOIN users u ON u.id = e.user_id
        LEFT JOIN stations s ON s.id = e.station_id
        WHERE u.account_status = 'Active' AND s.name = ?
        ORDER BY e.last_name, e.first_name
        """,
        (case["station"],),
    ).fetchall()
    conn.close()
    available_statuses = allowed_statuses(case["status"], session.get("role"))
    return render_template(
        "case_detail.html",
        current_page="cases",
        user_name=session.get("user", "Officer"),
        user_role=session.get("role", "Station Commander"),
        user_station=session.get("station", "Johannesburg Central"),
        integrity_score=72,
        employee_id=session.get("employee_id"),
        case=dict(case),
        status_palette=STATUS_COLORS,
        audit_events=audit_events,
        custody=custody,
        movements=movements,
        status_history=status_history,
        detectives=detectives,
        station_employees=station_employees,
        docket=docket,
        latest_assignment=latest_assignment,
        can_verify=has_permission("verify") and case["status"] == "Submitted",
        can_assign=(
            session.get("role") in {"Station Commander", "System Administrator"}
            and case["status"] in {"Registered", "Assigned"}
        ),
        can_close=(
            session.get("role") in {"Station Commander", "System Administrator"}
            and case["status"] == "Awaiting Supervisor Review"
        ),
        can_receive=(
            session.get("role") == "Detective"
            and case["assigned_employee_id"] == session.get("employee_id")
            and latest_assignment
            and latest_assignment["accepted_at"] is None
        ),
        refusal=refusal,
        control=control,
        statuses=available_statuses,
        can_update=bool(available_statuses),
        can_manage_lifecycle=(
            has_permission("update_case")
            or has_permission("approve")
            or has_permission("assign")
            or has_permission("escalate")
        ),
        can_transfer=has_permission("transfer"),
        can_escalate=has_permission("escalate"),
        compliance=compliance,
        can_review_compliance=(
            has_permission("update_case")
            or has_permission("approve")
            or has_permission("assign")
        ),
        can_document_delay=(
            has_permission("update_case")
            or has_permission("approve")
            or has_permission("assign")
        ),
    )


@app.route("/legal")
@require_login
def legal_references():
    conn = get_db()
    references = conn.execute(
        "SELECT * FROM legal_references ORDER BY CASE category WHEN 'Primary legislation' THEN 1 WHEN 'Special-protection legislation' THEN 2 WHEN 'Information governance' THEN 3 ELSE 4 END, title"
    ).fetchall()
    conn.close()
    return render_template(
        "legal.html",
        current_page="legal",
        user_name=session.get("user", "Officer"),
        user_role=session.get("role", "Station Commander"),
        user_station=session.get("station", "Johannesburg Central"),
        integrity_score=72,
        references=references,
    )


@app.route("/cases/<case_id>/compliance", methods=["POST"])
@require_login
def update_compliance(case_id):
    if not (has_permission("update_case") or has_permission("approve") or has_permission("assign")):
        return render_template("forbidden.html", required_roles="Detective, Supervisor, or Station Commander"), 403
    check_name = request.form.get("check_name", "").strip()
    status = request.form.get("status", "Not reviewed").strip()
    notes = request.form.get("notes", "").strip()
    if status not in {"Not reviewed", "In progress", "Complete", "Not applicable"}:
        return request_error("Choose a valid compliance checkpoint status.", 400)
    conn = get_db()
    case = conn.execute(
        "SELECT * FROM cases WHERE case_id = ?", (case_id,)
    ).fetchone()
    if not case:
        conn.close()
        return "Case not found", 404
    if not case_visible_to_current_user(case):
        conn.close()
        return render_template("forbidden.html", required_roles="Authorized staff at the case station"), 403
    result = conn.execute(
        "UPDATE case_compliance SET status = ?, notes = ?, reviewed_by = ?, reviewed_at = ? WHERE case_id = ? AND check_name = ?",
        (status, notes, session["user"], now_iso(), case_id, check_name),
    )
    if result.rowcount:
        add_audit_event(conn, case_id, "Compliance checkpoint updated", f"{check_name}: {status}. {notes}".strip())
        conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/cases/<case_id>/status", methods=["POST"])
@require_login
def update_case_status(case_id):
    new_status = request.form.get("status", "").strip()
    reason = request.form.get("reason", "").strip()
    if new_status not in CASE_STATUSES:
        return request_error("Choose a valid case status.", 400)
    if not reason:
        return request_error("A reason is required for every status change.", 400)
    if new_status == "Assigned" and not has_permission("assign"):
        return render_template(
            "forbidden.html",
            required_roles="Station Commander",
        ), 403
    if new_status == "Assigned":
        return request_error(
            "Use the Station Commander's detective-assignment workflow to assign a docket.",
            409,
        )
    conn = get_db()
    case = conn.execute(
        "SELECT * FROM cases WHERE case_id = ?", (case_id,)
    ).fetchone()
    if not case:
        conn.close()
        return "Case not found", 404
    if not case_visible_to_current_user(case):
        conn.close()
        return render_template(
            "forbidden.html",
            required_roles="Authorized staff at the case station",
        ), 403
    required_permission = CASE_TRANSITIONS.get(case["status"], {}).get(new_status)
    if not required_permission:
        conn.close()
        return request_error(
            f"A case cannot move from {case['status']} to {new_status}.",
            409,
        )
    if not has_permission(required_permission):
        conn.close()
        return render_template(
            "forbidden.html",
            required_roles={
                "assign": "Station Commander",
                "approve": "Supervisor or Station Commander",
                "update_case": "Detective",
                "escalate": "Supervisor or Station Commander",
            }[required_permission],
        ), 403
    progress = min(100, max(10, {"Registered": 15, "Assigned": 25, "Under Investigation": 55,
                                 "Awaiting Evidence": 65, "Awaiting Supervisor Review": 78,
                                 "Awaiting Court": 88, "Finalized": 100, "Escalated": 45}.get(new_status, 10)))
    conn.execute(
        "UPDATE cases SET status = ?, status_id = ?, progress = ?, updated_at = CURRENT_TIMESTAMP WHERE case_id = ?",
        (new_status, status_id_for(conn, new_status), progress, case_id),
    )
    conn.execute(
        "UPDATE case_controls SET next_action = ?, due_at = ?, escalation_level = 0, acknowledged_by = NULL, acknowledged_at = NULL WHERE case_id = ?",
        (
            "Complete the next documented case action",
            datetime.fromtimestamp(add_days(2 if new_status != "Awaiting Court" else 5), timezone.utc).isoformat(timespec="seconds"),
            case_id,
        ),
    )
    conn.execute(
        """
        INSERT INTO case_status_history
            (case_id, previous_status, new_status, changed_by_user_id, changed_at, reason)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (case_id, case["status"], new_status, session["user_id"], now_iso(), reason),
    )
    add_audit_event(
        conn,
        case_id,
        "Status changed",
        f"{case['status']} -> {new_status}. Reason: {reason}",
    )
    if case["complainant_user_id"]:
        queue_notification(
            conn,
            case["complainant_user_id"],
            case_id,
            f"Case {case_id} status updated to {new_status}.",
        )
    conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/cases/<case_id>/acknowledge", methods=["POST"])
@require_login
def acknowledge_case(case_id):
    if not has_permission("approve"):
        return render_template("forbidden.html", required_roles="Supervisor or Station Commander"), 403
    conn = get_db()
    case = conn.execute(
        """
        SELECT c.*, cc.escalation_level
        FROM cases c JOIN case_controls cc ON cc.case_id = c.case_id
        WHERE c.case_id = ?
        """,
        (case_id,),
    ).fetchone()
    if not case:
        conn.close()
        return "Case not found", 404
    if not case_visible_to_current_user(case):
        conn.close()
        return render_template("forbidden.html", required_roles="Authorized staff at the case station"), 403
    if case["escalation_level"] == 0:
        conn.close()
        return request_error("There is no active escalation to acknowledge.", 409)
    conn.execute(
        "UPDATE case_controls SET acknowledged_by = ?, acknowledged_at = ?, escalation_level = 0, due_at = ? WHERE case_id = ?",
        (session["user"], now_iso(), datetime.fromtimestamp(add_days(2), timezone.utc).isoformat(timespec="seconds"), case_id),
    )
    add_audit_event(conn, case_id, "Escalation acknowledged", "Supervisor accepted responsibility for the overdue action and reset the review deadline.")
    conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/cases/<case_id>/delay", methods=["POST"])
@require_login
def record_delay_reason(case_id):
    if not (
        has_permission("update_case")
        or has_permission("approve")
        or has_permission("assign")
    ):
        return render_template(
            "forbidden.html",
            required_roles="Detective, Supervisor, or Station Commander",
        ), 403
    reason = request.form.get("reason", "").strip()
    if not reason:
        return request_error("A reason is required to document a delay.", 400)
    conn = get_db()
    case = conn.execute(
        "SELECT * FROM cases WHERE case_id = ?", (case_id,)
    ).fetchone()
    if not case:
        conn.close()
        return "Case not found", 404
    if not case_visible_to_current_user(case):
        conn.close()
        return render_template("forbidden.html", required_roles="Authorized staff at the case station"), 403
    conn.execute(
        "UPDATE case_controls SET next_action = ?, due_at = ?, escalation_level = 0 WHERE case_id = ?",
        (f"Review recorded delay: {reason}", datetime.fromtimestamp(add_days(1), timezone.utc).isoformat(timespec="seconds"), case_id),
    )
    add_audit_event(conn, case_id, "Delay explanation recorded", f"{session['user']} documented: {reason}")
    conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/cases/<case_id>/custody", methods=["POST"])
@require_login
def transfer_custody(case_id):
    if not has_permission("transfer"):
        return render_template("forbidden.html", required_roles="Authorized docket custodian"), 403
    to_location = request.form.get("to_location", "").strip()
    reason = request.form.get("reason", "").strip()
    movement_type = request.form.get("movement_type", "Electronic").strip()
    if not to_location or not reason or movement_type not in {"Electronic", "Physical"}:
        return request_error("Provide a destination, valid movement type, and reason.", 400)
    conn = get_db()
    case = conn.execute(
        "SELECT * FROM cases WHERE case_id = ?", (case_id,)
    ).fetchone()
    if not case:
        conn.close()
        return "Case not found", 404
    if not case_visible_to_current_user(case):
        conn.close()
        return render_template("forbidden.html", required_roles="Authorized staff at the case station"), 403
    if case["status"] in {"Closed", "Finalized"}:
        conn.close()
        return request_error("A closed docket cannot be moved through the active workflow.", 409)
    docket = conn.execute(
        "SELECT * FROM dockets WHERE case_id = ?", (case_id,)
    ).fetchone()
    if not docket:
        conn.close()
        return request_error("The report must be verified and a docket opened before movement.", 409)
    to_employee_id = None
    recipient = None
    recipient_value = request.form.get("to_employee_id", "").strip()
    if recipient_value:
        try:
            to_employee_id = int(recipient_value)
        except ValueError:
            conn.close()
            return request_error("Choose a valid employee recipient.", 400)
        recipient = conn.execute(
            """
            SELECT e.id, e.employee_number, e.user_id, s.name AS station
            FROM employees e JOIN users u ON u.id = e.user_id
            LEFT JOIN stations s ON s.id = e.station_id
            WHERE e.id = ? AND u.account_status = 'Active'
            """,
            (to_employee_id,),
        ).fetchone()
        if not recipient or recipient["station"] != case["station"]:
            conn.close()
            return request_error("Choose an active recipient at the case station.", 400)
    now = now_iso()
    from_location = case["current_location"] or docket["storage_location"] or case["station"]
    conn.execute(
        """
        INSERT INTO docket_movements
            (docket_id, from_employee_id, to_employee_id, from_location, to_location,
             moved_by_user_id, moved_at, movement_type, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            docket["id"],
            docket["current_holder_employee_id"],
            to_employee_id,
            from_location,
            to_location,
            session["user_id"],
            now,
            movement_type,
            reason,
        ),
    )
    movement_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        """
        INSERT INTO custody_transfers
            (case_id, from_location, to_location, transferred_by, reason, created_at,
             movement_id, movement_type, from_employee_id, to_employee_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            from_location,
            to_location,
            session["user"],
            reason,
            now,
            movement_id,
            movement_type,
            docket["current_holder_employee_id"],
            to_employee_id,
        ),
    )
    conn.execute(
        "INSERT INTO docket_logs (case_id, action, location, time) VALUES (?, ?, ?, ?)",
        (case_id, f"{movement_type} docket moved: {from_location} -> {to_location}", to_location, now),
    )
    conn.execute(
        "UPDATE cases SET current_location = ?, updated_at = CURRENT_TIMESTAMP WHERE case_id = ?",
        (to_location, case_id),
    )
    conn.execute(
        "UPDATE dockets SET storage_location = ? WHERE id = ?",
        (to_location, docket["id"]),
    )
    if recipient:
        queue_notification(
            conn,
            recipient["user_id"],
            case_id,
            f"A {movement_type.lower()} docket movement for {case_id} awaits your receipt confirmation.",
        )
    add_audit_event(
        conn,
        case_id,
        "Docket transferred",
        f"{movement_type}: {from_location} -> {to_location}. Reason: {reason}",
    )
    conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/cases/<case_id>/refusal", methods=["POST"])
@require_login
def report_refusal(case_id):
    if session.get("role") == "Complainant":
        return render_template("forbidden.html", required_roles="Station staff"), 403
    reason = request.form.get("reason", "").strip()
    if not reason:
        return request_error("A reason is required to report a refusal or dispute.", 400)
    conn = get_db()
    case = conn.execute(
        "SELECT * FROM cases WHERE case_id = ?", (case_id,)
    ).fetchone()
    if not case:
        conn.close()
        return "Case not found", 404
    if not case_visible_to_current_user(case):
        conn.close()
        return render_template("forbidden.html", required_roles="Authorized staff at the case station"), 403
    if case["status"] in {"Finalized", "Closed"}:
        conn.close()
        return request_error(
            "A finalized case cannot be escalated. Record the dispute through the authorized review process.",
            409,
        )
    conn.execute(
        "INSERT INTO refusal_reviews (case_id, reported_by, reason, status, created_at) VALUES (?, ?, ?, ?, ?)",
        (case_id, session["user"], reason, "Open", now_iso()),
    )
    conn.execute(
        "UPDATE cases SET status = 'Escalated', status_id = ?, progress = 45, updated_at = CURRENT_TIMESTAMP WHERE case_id = ?",
        (status_id_for(conn, "Escalated"), case_id),
    )
    conn.execute(
        """
        INSERT INTO case_status_history
            (case_id, previous_status, new_status, changed_by_user_id, changed_at, reason)
        VALUES (?, ?, 'Escalated', ?, ?, ?)
        """,
        (case_id, case["status"], session["user_id"], now_iso(), reason),
    )
    add_audit_event(conn, case_id, "Refusal/dispute reported", f"Reported by {session['user']}: {reason}")
    conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/dockets")
@require_login
def dockets():
    if session.get("role") == "Complainant":
        return render_template("forbidden.html", required_roles="Station staff"), 403
    conn = get_db()
    movement_query = """
        SELECT m.*, d.case_id, u.username AS transferred_by,
               m.moved_at AS created_at
        FROM docket_movements m
        JOIN dockets d ON d.id = m.docket_id
        JOIN cases c ON c.case_id = d.case_id
        LEFT JOIN users u ON u.id = m.moved_by_user_id
    """
    log_query = """
        SELECT a.* FROM audit_events a
        JOIN cases c ON c.case_id = a.case_id
    """
    if session.get("role") == "System Administrator":
        movement_events = conn.execute(
            movement_query + " ORDER BY m.moved_at DESC LIMIT 50"
        ).fetchall()
        log_messages = conn.execute(
            log_query + " ORDER BY a.created_at DESC LIMIT 8"
        ).fetchall()
    elif session.get("role") == "Detective":
        movement_events = conn.execute(
            movement_query
            + " WHERE c.assigned_employee_id = ? ORDER BY m.moved_at DESC LIMIT 50",
            (session.get("employee_id"),),
        ).fetchall()
        log_messages = conn.execute(
            log_query
            + " WHERE c.assigned_employee_id = ? ORDER BY a.created_at DESC LIMIT 8",
            (session.get("employee_id"),),
        ).fetchall()
    else:
        movement_events = conn.execute(
            movement_query + " WHERE c.station = ? ORDER BY m.moved_at DESC LIMIT 50",
            (session.get("station", ""),),
        ).fetchall()
        log_messages = conn.execute(
            log_query + " WHERE c.station = ? ORDER BY a.created_at DESC LIMIT 8",
            (session.get("station", ""),),
        ).fetchall()
    conn.close()

    return render_template(
        "dockets.html",
        current_page="dockets",
        user_name=session.get("user", "Officer"),
        user_role=session.get("role", "Station Commander"),
        user_station=session.get("station", "Johannesburg Central"),
        integrity_score=72,
        movements=movement_events,
        logs=log_messages,
    )


@app.route("/reports")
@require_login
def reports():
    if session.get("role") == "Complainant":
        return render_template("forbidden.html", required_roles="Station staff"), 403
    today = datetime.now(timezone.utc).date()
    start_date = request.args.get("start_date", f"{today.year}-01-01")
    end_date = request.args.get("end_date", today.isoformat())
    try:
        start = datetime.strptime(start_date, "%Y-%m-%d").date()
        end = datetime.strptime(end_date, "%Y-%m-%d").date()
    except ValueError:
        return request_error("Enter valid start and end dates.", 400)
    if start > end:
        return request_error("The start date must be on or before the end date.", 400)

    conn = get_db()
    if session.get("role") == "System Administrator":
        closed_cases = conn.execute(
            """
            SELECT case_id, station, status, closed_at, closing_reason
            FROM cases
            WHERE status IN ('Closed', 'Finalized') AND closed_at >= ? AND closed_at < ?
            ORDER BY closed_at DESC
            """,
            (start.isoformat(), (end + timedelta(days=1)).isoformat()),
        ).fetchall()
    elif session.get("role") == "Detective":
        closed_cases = conn.execute(
            """
            SELECT case_id, station, status, closed_at, closing_reason
            FROM cases
            WHERE assigned_employee_id = ? AND status IN ('Closed', 'Finalized')
              AND closed_at >= ? AND closed_at < ?
            ORDER BY closed_at DESC
            """,
            (
                session.get("employee_id"),
                start.isoformat(),
                (end + timedelta(days=1)).isoformat(),
            ),
        ).fetchall()
    else:
        closed_cases = conn.execute(
            """
            SELECT case_id, station, status, closed_at, closing_reason
            FROM cases
            WHERE station = ? AND status IN ('Closed', 'Finalized')
              AND closed_at >= ? AND closed_at < ?
            ORDER BY closed_at DESC
            """,
            (
                session.get("station", ""),
                start.isoformat(),
                (end + timedelta(days=1)).isoformat(),
            ),
        ).fetchall()
    conn.close()
    key_metrics = [
        {"label": "Closed in range", "value": len(closed_cases)},
        {
            "label": "Completed",
            "value": sum(
                1 for case in closed_cases if "completed" in case["closing_reason"].lower()
            ),
        },
        {
            "label": "Dead end",
            "value": sum(
                1 for case in closed_cases if "dead end" in case["closing_reason"].lower()
            ),
        },
    ]

    return render_template(
        "reports.html",
        current_page="reports",
        user_name=session.get("user", "Officer"),
        user_role=session.get("role", "Station Commander"),
        user_station=session.get("station", "Johannesburg Central"),
        integrity_score=72,
        key_metrics=key_metrics,
        closed_cases=closed_cases,
        start_date=start.isoformat(),
        end_date=end.isoformat(),
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
