import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone


_test_data = tempfile.TemporaryDirectory(prefix="docket-tracker-tests-")
os.environ["DOCKET_TRACKER_DB"] = os.path.join(_test_data.name, "test.db")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as docket_app


class CaseLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        docket_app.app.config.update(TESTING=True)
        cls.client = docket_app.app.test_client()

    def setUp(self):
        with self.client.session_transaction() as session:
            session.clear()
        self.case_id = f"TEST-{self._testMethodName}"
        conn = docket_app.get_db()
        detective = conn.execute(
            "SELECT e.id FROM employees e JOIN users u ON u.id = e.user_id WHERE u.username = 'detective'"
        ).fetchone()
        conn.execute(
            """
            INSERT INTO cases
                (case_id, complainant, station, assigned_to, status, days_open, progress,
                 assigned_employee_id, created_at, current_location)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
            """,
            (
                self.case_id,
                "Test complainant",
                "Johannesburg Central",
                "Detective K. Ndlovu",
                "Assigned",
                1,
                15,
                detective["id"],
                "Johannesburg Central case intake",
            ),
        )
        conn.execute(
            """
            INSERT INTO case_controls (case_id, next_action, due_at)
            VALUES (?, ?, ?)
            """,
            (
                self.case_id,
                "Test next action",
                (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
            ),
        )
        conn.execute(
            """
            INSERT INTO dockets (docket_number, case_id, created_at, storage_location)
            VALUES (?, ?, CURRENT_TIMESTAMP, 'Johannesburg Central case intake')
            """,
            (f"DKT-{self.case_id}", self.case_id),
        )
        conn.commit()
        conn.close()

    def set_case_status(self, status):
        conn = docket_app.get_db()
        conn.execute(
            "UPDATE cases SET status = ? WHERE case_id = ?",
            (status, self.case_id),
        )
        conn.commit()
        conn.close()

    def login_as(self, role, username=None):
        username = username or role.lower().replace(" ", "_")
        conn = docket_app.get_db()
        user = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        employee = conn.execute(
            "SELECT id FROM employees WHERE user_id = ?",
            (user["id"],),
        ).fetchone() if user else None
        conn.close()
        with self.client.session_transaction() as session:
            session["user"] = username
            session["user_id"] = user["id"] if user else 1
            session["role"] = role
            session["station"] = "Johannesburg Central"
            session["employee_id"] = employee["id"] if employee else None

    def case_status(self):
        conn = docket_app.get_db()
        row = conn.execute(
            "SELECT status FROM cases WHERE case_id = ?", (self.case_id,)
        ).fetchone()
        conn.close()
        return row["status"]

    def post_status(self, status, reason="Documented test reason"):
        return self.client.post(
            f"/cases/{self.case_id}/status",
            data={"status": status, "reason": reason},
        )

    def test_detective_can_progress_case_to_investigation(self):
        self.login_as("Detective", "detective")

        response = self.post_status("Under Investigation")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.case_status(), "Under Investigation")

    def test_detective_cannot_skip_to_court(self):
        self.login_as("Detective", "detective")

        response = self.post_status("Awaiting Court")

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.case_status(), "Assigned")

    def test_supervisor_cannot_assign_a_new_case(self):
        self.set_case_status("Registered")
        self.login_as("Supervisor")

        response = self.post_status("Assigned")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.case_status(), "Registered")

    def test_captain_assigns_registered_case_to_detective(self):
        self.set_case_status("Registered")
        self.login_as("Captain", "captain")
        conn = docket_app.get_db()
        detective_id = conn.execute(
            "SELECT id FROM employees WHERE employee_number = 'EMP-000002'"
        ).fetchone()["id"]
        conn.close()

        response = self.client.post(
            f"/cases/{self.case_id}/assign",
            data={"detective_id": str(detective_id)},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.case_status(), "Assigned")

    def test_clerk_cannot_change_case_status(self):
        self.set_case_status("Registered")
        self.login_as("Admin Clerk")

        response = self.post_status("Escalated")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.case_status(), "Registered")

    def test_finalized_case_is_terminal(self):
        self.set_case_status("Finalized")
        self.login_as("Station Commander")

        response = self.post_status("Under Investigation")

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.case_status(), "Finalized")

    def test_status_change_requires_a_reason(self):
        self.login_as("Detective", "detective")

        response = self.post_status("Under Investigation", reason="")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.case_status(), "Assigned")

    def test_registration_ignores_forged_initial_status(self):
        self.login_as("Admin Clerk", "clerk")

        response = self.client.post(
            "/cases/new",
            data={
                "case_id": f"{self.case_id}-NEW",
                "complainant": "New complainant",
                "station": "Johannesburg Central",
                "case_type": "Theft",
                "incident_date": "2026-09-29",
                "incident_location": "Test address",
                "statement": "A sufficiently long statement describing the reported incident.",
                "days_open": 1,
            },
        )

        self.assertEqual(response.status_code, 302)
        conn = docket_app.get_db()
        row = conn.execute(
            "SELECT status FROM cases WHERE case_id = ?",
            (f"{self.case_id}-NEW",),
        ).fetchone()
        conn.close()
        self.assertEqual(row["status"], "Submitted")

    def test_case_registry_hides_registration_controls_from_detectives(self):
        self.login_as("Detective", "detective")

        response = self.client.get("/cases")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'id="newCaseBtn"', response.data)

    def test_lifecycle_options_are_role_specific(self):
        self.assertEqual(
            docket_app.allowed_statuses("Assigned", "Detective"),
            ["Under Investigation"],
        )
        self.assertEqual(
            docket_app.allowed_statuses("Registered", "Supervisor"),
            ["Escalated"],
        )

    def test_case_registry_shows_registration_controls_to_clerks(self):
        self.login_as("Admin Clerk", "clerk")

        response = self.client.get("/cases")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="newCaseBtn"', response.data)

    def test_complainant_clerk_captain_detective_full_workflow(self):
        response = self.client.post(
            "/register",
            data={
                "username": "complainant_flow",
                "password": "secure-test-password",
                "first_name": "Test",
                "last_name": "Complainant",
                "phone_number": "+27123456789",
                "email": "complainant@example.test",
            },
        )
        self.assertEqual(response.status_code, 302)

        response = self.client.post(
            "/report-case",
            data={
                "station": "Johannesburg Central",
                "case_type": "Theft",
                "incident_date": "2026-09-28",
                "incident_location": "Test location",
                "statement": "A detailed statement with more than thirty characters for testing.",
            },
        )
        self.assertEqual(response.status_code, 302)
        conn = docket_app.get_db()
        case = conn.execute(
            "SELECT * FROM cases WHERE complainant = 'complainant_flow'"
        ).fetchone()
        self.assertIsNotNone(case)
        self.assertEqual(case["status"], "Submitted")
        case_id = case["case_id"]
        sms = conn.execute(
            "SELECT * FROM notifications WHERE case_id = ? AND channel = 'SMS'",
            (case_id,),
        ).fetchone()
        self.assertEqual(sms["recipient_address"], "+27123456789")
        self.assertIn("gateway not configured", sms["delivery_status"])
        conn.close()

        self.login_as("Admin Clerk", "clerk")
        response = self.client.post(
            f"/cases/{case_id}/verify",
            data={
                "docket_format": "Physical",
                "storage_location": "Johannesburg Central evidence room",
            },
        )
        self.assertEqual(response.status_code, 302)
        conn = docket_app.get_db()
        case = conn.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        docket = conn.execute(
            "SELECT * FROM dockets WHERE case_id = ?", (case_id,)
        ).fetchone()
        self.assertEqual(case["status"], "Registered")
        self.assertEqual(docket["docket_number"], f"DKT-{case_id}")
        self.assertEqual(docket["physical_available"], 1)
        conn.close()

        self.login_as("Captain", "captain")
        conn = docket_app.get_db()
        detective_id = conn.execute(
            "SELECT id FROM employees WHERE employee_number = 'EMP-000002'"
        ).fetchone()["id"]
        conn.close()
        response = self.client.post(
            f"/cases/{case_id}/assign",
            data={"detective_id": str(detective_id)},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            self.client.get(f"/cases/{case_id}").status_code,
            200,
        )

        self.login_as("Detective", "detective")
        self.assertEqual(self.client.get(f"/cases/{case_id}").status_code, 200)
        response = self.client.post(f"/cases/{case_id}/receive")
        self.assertEqual(response.status_code, 302)
        conn = docket_app.get_db()
        movement = conn.execute(
            """
            SELECT received_at, movement_type FROM docket_movements
            WHERE docket_id = ? ORDER BY id DESC LIMIT 1
            """,
            (docket["id"],),
        ).fetchone()
        self.assertIsNotNone(movement["received_at"])
        self.assertEqual(movement["movement_type"], "Physical")
        conn.close()

        self.login_as("Captain", "captain")
        response = self.client.post(
            f"/cases/{case_id}/close",
            data={
                "outcome": "Investigation completed",
                "closing_reason": "Test workflow closure",
            },
        )
        self.assertEqual(response.status_code, 302)
        conn = docket_app.get_db()
        case = conn.execute(
            "SELECT status, closed_at, closing_reason FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        self.assertEqual(case["status"], "Closed")
        self.assertIsNotNone(case["closed_at"])
        self.assertIn("Test workflow closure", case["closing_reason"])
        conn.close()

        self.login_as("Complainant", "complainant_flow")
        response = self.client.get("/my-cases")
        self.assertEqual(response.status_code, 200)
        self.assertIn(case_id.encode(), response.data)
        self.assertEqual(
            self.client.get(f"/cases/{case_id}").status_code,
            302,
        )

    def test_password_hash_uses_salted_pbkdf2(self):
        first = docket_app.hash_password("password-for-test")
        second = docket_app.hash_password("password-for-test")

        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("pbkdf2_sha256$"))
        self.assertEqual(
            docket_app.verify_password("password-for-test", first),
            (True, False),
        )
        self.assertEqual(
            docket_app.verify_password("wrong-password", first),
            (False, False),
        )

    def test_clerk_employee_registration_generates_employee_number(self):
        self.login_as("Admin Clerk", "clerk")

        response = self.client.post(
            "/employees",
            data={
                "username": "new_detective",
                "password": "a-strong-test-password",
                "role": "Detective",
                "station": "Johannesburg Central",
                "first_name": "Amina",
                "last_name": "Test",
                "email": "amina@example.test",
                "phone_number": "+27111111111",
            },
        )

        self.assertEqual(response.status_code, 302)
        conn = docket_app.get_db()
        employee = conn.execute(
            """
            SELECT e.employee_number, e.role_id, u.password_hash
            FROM employees e JOIN users u ON u.id = e.user_id
            WHERE u.username = 'new_detective'
            """
        ).fetchone()
        conn.close()
        self.assertRegex(employee["employee_number"], r"^EMP-\d{6}$")
        self.assertIsNotNone(employee["role_id"])
        self.assertTrue(employee["password_hash"].startswith("pbkdf2_sha256$"))

    def test_role_screens_and_closed_date_report_render(self):
        self.login_as("Admin Clerk", "clerk")
        self.assertEqual(self.client.get("/employees").status_code, 200)
        self.assertEqual(self.client.get("/cases").status_code, 200)
        self.login_as("Captain", "captain")
        self.assertEqual(self.client.get("/assignments").status_code, 200)
        self.assertEqual(self.client.get("/reports?start_date=2026-01-01&end_date=2026-12-31").status_code, 200)
        self.assertEqual(self.client.get("/dockets").status_code, 200)


if __name__ == "__main__":
    unittest.main()
