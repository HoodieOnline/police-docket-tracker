import os
import sqlite3
from functools import wraps
from hashlib import sha256
from datetime import datetime, timezone

from flask import Flask, has_request_context, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = "docket-tracker-sa-development-secret"

DB_PATH = os.path.join(os.path.dirname(__file__), "docket_tracker.db")

STATUS_COLORS = {
    "Registered": "background: rgba(78,195,255,0.12); color: #dff4ff;",
    "Assigned": "background: rgba(96,165,250,0.12); color: #dbeafe;",
    "Under Investigation": "background: rgba(167,139,250,0.12); color: #e3d9ff;",
    "Awaiting Evidence": "background: rgba(192,132,252,0.12); color: #f3e8ff;",
    "Awaiting Supervisor Review": "background: rgba(251,146,60,0.12); color: #ffedd5;",
    "Awaiting Court": "background: rgba(251,191,36,0.12); color: #fde7a7;",
    "Escalated": "background: rgba(251,113,133,0.12); color: #ffbfd0;",
    "Finalized": "background: rgba(45,212,191,0.12); color: #baf7ec;",
}

CASE_STATUSES = [
    "Registered",
    "Assigned",
    "Under Investigation",
    "Awaiting Evidence",
    "Awaiting Supervisor Review",
    "Awaiting Court",
    "Finalized",
    "Escalated",
]

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
    "System Administrator": {"view_all", "manage_users", "register", "transfer"},
    "Station Commander": {"view_all", "assign", "approve", "transfer", "escalate"},
    "Supervisor": {"view_all", "approve", "transfer", "escalate"},
    "Detective": {"view_assigned", "update_case", "transfer"},
    "Admin Clerk": {"register", "view_all", "transfer"},
}


def hash_password(password: str) -> str:
    return sha256(password.encode("utf-8")).hexdigest()


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
            station TEXT
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
            complainant TEXT,
            station TEXT,
            assigned_to TEXT,
            status TEXT,
            days_open INTEGER,
            progress INTEGER,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
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
    conn.commit()
    conn.close()


def refresh_guardrails(conn):
    now = datetime.now(timezone.utc)
    overdue = conn.execute(
        """
        SELECT c.case_id, c.status, cc.next_action, cc.due_at, cc.escalation_level
        FROM cases c JOIN case_controls cc ON cc.case_id = c.case_id
        WHERE c.status != 'Finalized'
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
            "UPDATE cases SET status = 'Escalated', updated_at = CURRENT_TIMESTAMP WHERE case_id = ?",
            (case["case_id"],),
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

    demo_users = [
        ("admin", "admin123", "System Administrator", "Johannesburg Central"),
        ("commander", "commander123", "Station Commander", "Johannesburg Central"),
        ("detective", "detective123", "Detective", "Johannesburg Central"),
        ("clerk", "clerk123", "Admin Clerk", "Johannesburg Central"),
    ]
    for username, password, role, station in demo_users:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role, station) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, station),
        )
        conn.execute(
            "UPDATE users SET password_hash = ?, role = ?, station = ? WHERE username = ?",
            (hash_password(password), role, station, username),
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
        "SELECT case_id, status FROM cases WHERE status != 'Finalized'"
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
    conn.execute(
        "INSERT INTO audit_events (case_id, actor, actor_role, action, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (case_id, actor, actor_role, action, details, now_iso()),
    )


def has_permission(permission):
    return permission in ROLE_PERMISSIONS.get(session.get("role"), set())


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
            "SELECT username, password_hash, role, station FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()

        if user and user["password_hash"] == hash_password(password):
            session["user"] = user["username"]
            session["role"] = user["role"]
            session["station"] = user["station"]
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid username or password.")

    if "user" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@require_login
def index():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@require_login
def dashboard():
    conn = get_db()
    commit_guardrails(conn)
    cases = conn.execute("SELECT * FROM cases ORDER BY updated_at DESC").fetchall()
    recent_activity = conn.execute(
        "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 8"
    ).fetchall()
    conn.close()

    role = session.get("role", "Station Commander")
    status_breakdown = [
        {"label": "Registered", "height": 52, "color": "linear-gradient(180deg, var(--primary), rgba(78, 195, 255, 0.65))"},
        {"label": "In progress", "height": 82, "color": "linear-gradient(180deg, var(--purple), rgba(167, 139, 250, 0.7))"},
        {"label": "Awaiting court", "height": 64, "color": "linear-gradient(180deg, var(--warning), rgba(251, 191, 36, 0.68))"},
        {"label": "Finalized", "height": 38, "color": "linear-gradient(180deg, var(--success), rgba(45, 212, 191, 0.72))"},
        {"label": "Escalated", "height": 44, "color": "linear-gradient(180deg, var(--danger), rgba(251, 113, 133, 0.76))"},
    ]

    visible_cases = list(cases)
    if role == "Detective":
        visible_cases = [
            case for case in cases
            if session.get("user", "").lower() in case["assigned_to"].lower()
            or "Detective" in case["assigned_to"]
        ]
    open_cases = sum(1 for case in visible_cases if case["status"] != "Finalized")
    require_action = sum(
        1 for case in visible_cases
        if case["status"] in ["Registered", "Awaiting Supervisor Review", "Escalated", "Under Investigation"]
    )
    avg_days = round(
        sum(case["days_open"] for case in visible_cases) / len(visible_cases), 1
    ) if visible_cases else 0
    finalized = sum(1 for case in visible_cases if case["status"] == "Finalized")

    summary = {
        "open_cases": open_cases,
        "open_trend": {
            "System Administrator": "System-wide view",
            "Station Commander": "Station-wide view",
            "Supervisor": "Review queue monitored",
            "Detective": "Assigned caseload",
            "Admin Clerk": "Intake queue",
        }.get(role, "Operational view"),
        "require_action": require_action,
        "action_trend": {
            "System Administrator": "Access and workflow health",
            "Station Commander": "Assignments and escalations",
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
        "Station Commander": ["Registered", "Escalated", "Awaiting Supervisor Review"],
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
        "Station Commander": ("Station command dashboard", "Assign responsibility, clear escalations, and monitor station performance."),
        "Supervisor": ("Supervision and review queue", "Resolve overdue reviews, refusal reports, and custody exceptions."),
        "Detective": ("Investigation workspace", "Progress assigned dockets, request evidence, and keep the custody chain current."),
        "Admin Clerk": ("Case intake desk", "Register complaints, issue receipts, and route dockets to the correct owner."),
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
        dashboard_title=role_copy.get(role, ("Operations dashboard", "Monitor current case activity."))[0],
        dashboard_description=role_copy.get(role, ("Operations dashboard", "Monitor current case activity."))[1],
        role=role,
    )


@app.route("/cases", methods=["GET"])
@require_login
def cases():
    query = request.args.get("q", "").strip().lower()
    selected_status = request.args.get("status", "All")

    conn = get_db()
    commit_guardrails(conn)
    case_rows = conn.execute("SELECT * FROM cases ORDER BY updated_at DESC").fetchall()
    conn.close()

    filtered = []
    for case in case_rows:
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
    )


@app.route("/cases/new", methods=["POST"])
@require_login
def create_case():
    if not has_permission("register"):
        return render_template("forbidden.html", required_roles="Admin Clerk"), 403
    case_id = request.form.get("case_id", "").strip()
    complainant = request.form.get("complainant", "").strip()
    station = request.form.get("station", "").strip()
    assigned_to = request.form.get("assigned_to", "").strip()
    status = request.form.get("status", "Registered")
    try:
        days_open = max(0, int(request.form.get("days_open", 0) or 0))
    except ValueError:
        return redirect(url_for("cases"))
    progress = min(100, max(10, days_open * 4 + 10))

    if not case_id or not complainant or not station or not assigned_to:
        return redirect(url_for("cases"))

    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO cases (case_id, complainant, station, assigned_to, status, days_open, progress) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (case_id, complainant, station, assigned_to, status, days_open, progress),
    )
    conn.execute(
        "INSERT INTO docket_logs (case_id, action, location, time) VALUES (?, ?, ?, ?)",
        (case_id, "New case registered", station, "NOW"),
    )
    add_audit_event(conn, case_id, "Case registered", f"Complaint received at {station}; receipt issued.")
    conn.execute(
        "INSERT OR REPLACE INTO case_controls (case_id, next_action, due_at, escalation_level) VALUES (?, ?, ?, 0)",
        (case_id, "Assign a responsible officer and confirm receipt", datetime.fromtimestamp(add_days(1), timezone.utc).isoformat(timespec="seconds")),
    )
    conn.commit()
    conn.close()

    return redirect(url_for("cases"))


@app.route("/cases/<case_id>")
@require_login
def case_detail(case_id):
    conn = get_db()
    commit_guardrails(conn)
    case = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    if not case:
        conn.close()
        return "Case not found", 404
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
    conn.close()
    can_update = has_permission("update_case") or has_permission("approve") or has_permission("assign")
    return render_template(
        "case_detail.html",
        current_page="cases",
        user_name=session.get("user", "Officer"),
        user_role=session.get("role", "Station Commander"),
        user_station=session.get("station", "Johannesburg Central"),
        integrity_score=72,
        case=dict(case),
        status_palette=STATUS_COLORS,
        audit_events=audit_events,
        custody=custody,
        refusal=refusal,
        control=control,
        statuses=CASE_STATUSES,
        can_update=can_update,
        can_transfer=has_permission("transfer"),
        can_escalate=has_permission("escalate"),
        compliance=compliance,
        can_review_compliance=has_permission("update_case") or has_permission("approve") or has_permission("assign"),
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
        return redirect(url_for("case_detail", case_id=case_id))
    conn = get_db()
    if not conn.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone():
        conn.close()
        return "Case not found", 404
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
    if not (has_permission("update_case") or has_permission("approve") or has_permission("assign")):
        return render_template("forbidden.html", required_roles="Detective, Supervisor, or Station Commander"), 403
    new_status = request.form.get("status", "").strip()
    reason = request.form.get("reason", "").strip()
    if new_status not in CASE_STATUSES or not reason:
        return redirect(url_for("case_detail", case_id=case_id))
    conn = get_db()
    case = conn.execute("SELECT status FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    if not case:
        conn.close()
        return "Case not found", 404
    progress = min(100, max(10, {"Registered": 15, "Assigned": 25, "Under Investigation": 55,
                                 "Awaiting Evidence": 65, "Awaiting Supervisor Review": 78,
                                 "Awaiting Court": 88, "Finalized": 100, "Escalated": 45}.get(new_status, 10)))
    conn.execute(
        "UPDATE cases SET status = ?, progress = ?, updated_at = CURRENT_TIMESTAMP WHERE case_id = ?",
        (new_status, progress, case_id),
    )
    conn.execute(
        "UPDATE case_controls SET next_action = ?, due_at = ?, escalation_level = 0, acknowledged_by = NULL, acknowledged_at = NULL WHERE case_id = ?",
        (
            "Complete the next documented case action",
            datetime.fromtimestamp(add_days(2 if new_status != "Awaiting Court" else 5), timezone.utc).isoformat(timespec="seconds"),
            case_id,
        ),
    )
    add_audit_event(conn, case_id, "Status changed", f"{case['status']} -> {new_status}. Reason: {reason}")
    conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/cases/<case_id>/acknowledge", methods=["POST"])
@require_login
def acknowledge_case(case_id):
    if not (has_permission("approve") or has_permission("assign")):
        return render_template("forbidden.html", required_roles="Supervisor or Station Commander"), 403
    conn = get_db()
    if not conn.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone():
        conn.close()
        return "Case not found", 404
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
    reason = request.form.get("reason", "").strip()
    if not reason:
        return redirect(url_for("case_detail", case_id=case_id))
    conn = get_db()
    if not conn.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone():
        conn.close()
        return "Case not found", 404
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
        return render_template("forbidden.html", required_roles="Detective, Supervisor, Station Commander, or Admin Clerk"), 403
    from_location = request.form.get("from_location", "").strip()
    to_location = request.form.get("to_location", "").strip()
    reason = request.form.get("reason", "").strip()
    if not from_location or not to_location or not reason:
        return redirect(url_for("case_detail", case_id=case_id))
    conn = get_db()
    if not conn.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone():
        conn.close()
        return "Case not found", 404
    conn.execute(
        "INSERT INTO custody_transfers (case_id, from_location, to_location, transferred_by, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (case_id, from_location, to_location, session["user"], reason, now_iso()),
    )
    conn.execute(
        "INSERT INTO docket_logs (case_id, action, location, time) VALUES (?, ?, ?, ?)",
        (case_id, f"Custody transfer: {from_location} -> {to_location}", to_location, now_iso()),
    )
    add_audit_event(conn, case_id, "Docket transferred", f"{from_location} -> {to_location}. Reason: {reason}")
    conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/cases/<case_id>/refusal", methods=["POST"])
@require_login
def report_refusal(case_id):
    reason = request.form.get("reason", "").strip()
    if not reason:
        return redirect(url_for("case_detail", case_id=case_id))
    conn = get_db()
    if not conn.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone():
        conn.close()
        return "Case not found", 404
    conn.execute(
        "INSERT INTO refusal_reviews (case_id, reported_by, reason, status, created_at) VALUES (?, ?, ?, ?, ?)",
        (case_id, session["user"], reason, "Open", now_iso()),
    )
    conn.execute(
        "UPDATE cases SET status = 'Escalated', updated_at = CURRENT_TIMESTAMP WHERE case_id = ?",
        (case_id,),
    )
    add_audit_event(conn, case_id, "Refusal/dispute reported", f"Reported by {session['user']}: {reason}")
    conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/dockets")
@require_login
def dockets():
    conn = get_db()
    movement_events = conn.execute(
        "SELECT * FROM custody_transfers ORDER BY created_at DESC LIMIT 20"
    ).fetchall()
    log_messages = conn.execute(
        "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 8"
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
    report_bars = [
        {"label": "Jan", "height": 58},
        {"label": "Feb", "height": 68},
        {"label": "Mar", "height": 75},
        {"label": "Apr", "height": 88},
        {"label": "May", "height": 72},
    ]

    key_metrics = [
        {"label": "Resolved", "value": "314"},
        {"label": "Escalated", "value": "27"},
        {"label": "Audit score", "value": "94%"},
    ]

    return render_template(
        "reports.html",
        current_page="reports",
        user_name=session.get("user", "Officer"),
        user_role=session.get("role", "Station Commander"),
        user_station=session.get("station", "Johannesburg Central"),
        integrity_score=72,
        report_bars=report_bars,
        key_metrics=key_metrics,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
