"""End-to-end smoke coverage for the SQLite application API (stdlib only)."""

import http.cookiejar
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import server  # noqa: E402


class APIClient:
    def __init__(self, base: str):
        self.base = base
        self.opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf = ""

    def call(self, path, method="GET", body=None, csrf=True, expected=200):
        headers = {"Accept": "application/json"}
        payload = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(body).encode()
        if method not in ("GET", "HEAD") and csrf and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        request = Request(self.base + path, data=payload, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=5)
            code, raw = response.status, response.read()
        except HTTPError as exc:
            code, raw = exc.code, exc.read()
        self_assert = code == expected
        if not self_assert:
            raise AssertionError(f"{method} {path}: expected {expected}, got {code}: {raw[:500]!r}")
        data = json.loads(raw) if raw else {}
        if isinstance(data, dict) and data.get("csrf"):
            self.csrf = data["csrf"]
        return data


class ApplicationWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="inmei-test-")
        db_path = Path(cls.temp.name) / "workflow.sqlite3"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        cls.base = f"http://127.0.0.1:{port}"
        cls.env = os.environ.copy() | {"HOST": "127.0.0.1", "PORT": str(port), "IN_MPE_DB": str(db_path)}
        server.DB_PATH = db_path
        server.init_db()
        with server.db() as conn:
            conn.execute(
                "INSERT INTO users(id,full_name,phone,password_hash,role,status,created_at) "
                "VALUES(?,?,?,?, 'admin','Accepted',?)",
                ("test-admin", "Local Admin", "+79990000000", server.password_hash("admin-test-password-123"), server.now()),
            )
        cls.process = subprocess.Popen(
            [sys.executable, "server.py"], cwd=ROOT, env=cls.env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        cls.admin = APIClient(cls.base)
        for _ in range(100):
            if cls.process.poll() is not None:
                raise RuntimeError(cls.process.stderr.read().decode(errors="replace"))
            try:
                cls.admin.call("/api/session")
                break
            except (OSError, HTTPError, AssertionError):
                time.sleep(0.1)
        else:
            raise RuntimeError("application did not start")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        try:
            cls.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.process.kill()
            cls.process.wait()
        cls.temp.cleanup()

    def test_candidate_booking_admin_interviewer_and_public_content(self):
        admin, base = self.admin, self.base

        # The HTTP service must never expose application source or its database.
        for path in ("/server.py", "/README.md", "/data/workflow.sqlite3", "/.git/config"):
            with self.assertRaises(HTTPError) as error:
                admin.opener.open(base + path, timeout=3)
            self.assertEqual(error.exception.code, 404, path)

        admin.call("/api/auth/login", "POST", {"phone": "+79990000000", "password": "admin-test-password-123"})
        first, second = APIClient(base), APIClient(base)
        first.call("/api/session")
        first.call("/api/profile", "PATCH", {"name": "No CSRF", "group": "Э-1", "experience": "junior", "vk_url": ""}, csrf=False, expected=403)
        second.call("/api/session")

        first.call("/api/auth/register", "POST", {
            "name": "Анна Тест", "phone": "+79990000001", "password": "candidate-test-password-123",
            "group": "Э-13м-26", "experience": "junior", "consent": True,
        }, expected=201)
        second.call("/api/auth/register", "POST", {
            "name": "Иван Тест", "phone": "+79990000002", "password": "candidate-test-password-123",
            "group": "Э-13м-26", "experience": "experienced", "consent": True,
        }, expected=201)
        first.call("/api/admin/overview", expected=403)

        starts = (datetime.now() + timedelta(days=2)).replace(hour=13, minute=0, second=0, microsecond=0)
        start_value = starts.isoformat(timespec="minutes")
        slot_id = admin.call("/api/admin/slots", "POST", {
            "starts_at": start_value, "location": "Тестовый корпус, 1", "capacity": 1,
        }, expected=201)["id"]
        self.assertEqual(len(first.call("/api/slots")["slots"]), 1)
        first.call("/api/bookings", "POST", {"slot_id": slot_id}, expected=201)
        first.call("/api/bookings", "POST", {"slot_id": slot_id}, expected=409)
        second.call("/api/bookings", "POST", {"slot_id": slot_id}, expected=409)
        first_booking = first.call("/api/dashboard")["bookings"][0]["booking_id"]

        # Cancelling releases a place; a user cannot keep another active booking.
        second_slot = admin.call("/api/admin/slots", "POST", {
            "starts_at": (starts + timedelta(days=1)).isoformat(timespec="minutes"),
            "location": "Тестовый корпус, 2", "capacity": 1,
        }, expected=201)["id"]
        first.call("/api/bookings", "POST", {"slot_id": second_slot}, expected=409)
        first.call("/api/bookings/cancel", "POST", {"booking_id": first_booking})
        second.call("/api/bookings", "POST", {"slot_id": slot_id}, expected=201)

        candidate_id = second.call("/api/dashboard")["user"]["id"]
        admin.call(f"/api/admin/users/{candidate_id}/status", "POST", {"status": "Interview"})
        self.assertEqual(second.call("/api/dashboard")["user"]["status"], "Interview")
        admin.call("/api/admin/materials", "POST", {"title": "Инструкция тест", "body": "Читаемый текст"}, expected=201)
        admin.call("/api/admin/events", "POST", {
            "title": "Встреча тест", "description": "Описание", "starts_at": start_value, "location": "МЭИ", "capacity": 1,
        }, expected=201)
        public = admin.call("/api/public")
        self.assertTrue(any(item["title"] == "Встреча тест" for item in public["events"]))
        self.assertTrue(any(item["title"] == "Инструкция тест" for item in public["materials"]))
        event_id = next(item["id"] for item in public["events"] if item["title"] == "Встреча тест")
        material_id = next(item["id"] for item in public["materials"] if item["title"] == "Инструкция тест")
        first.call("/api/events/bookings", "POST", {"event_id": event_id}, expected=201)
        second.call("/api/events/bookings", "POST", {"event_id": event_id}, expected=409)
        event_booking = first.call("/api/dashboard")["my_events"][0]["booking_id"]
        first.call("/api/events/bookings/cancel", "POST", {"booking_id": event_booking})
        second.call("/api/events/bookings", "POST", {"event_id": event_id}, expected=201)
        second_event_booking = second.call("/api/dashboard")["my_events"][0]["booking_id"]
        admin.call(f"/api/admin/event-bookings/{second_event_booking}/attendance", "POST", {"status": "attended"})
        self.assertEqual(second.call("/api/dashboard")["my_events"][0]["booking_status"], "attended")
        admin.call(f"/api/admin/events/{event_id}", "PATCH", {"title": "Встреча изменена"})
        admin.call(f"/api/admin/materials/{material_id}", "PATCH", {"title": "Инструкция изменена", "published": False})
        public = admin.call("/api/public")
        self.assertTrue(any(item["title"] == "Встреча изменена" for item in public["events"]))
        self.assertFalse(any(item["title"] == "Инструкция изменена" for item in public["materials"]))

        attestation_slot = admin.call("/api/admin/slots", "POST", {
            "starts_at": (starts + timedelta(days=2)).isoformat(timespec="minutes"),
            "location": "Тестовая аудитория", "capacity": 2, "kind": "attestation",
        }, expected=201)["id"]
        second.call("/api/bookings", "POST", {"slot_id": attestation_slot}, expected=403)
        admin.call(f"/api/admin/users/{candidate_id}/status", "POST", {"status": "Attestation"})
        second.call("/api/bookings", "POST", {"slot_id": attestation_slot}, expected=201)
        self.assertEqual(len(second.call("/api/dashboard")["bookings"]), 2)

        # Two independent sessions competing for a single place must not overbook it.
        racers = [APIClient(base), APIClient(base)]
        for index, racer in enumerate(racers, start=3):
            racer.call("/api/session")
            racer.call("/api/auth/register", "POST", {
                "name": f"Кандидат {index}", "phone": f"+7999000000{index}",
                "password": "candidate-test-password-123", "group": "Э-13м-26",
                "experience": "junior", "consent": True,
            }, expected=201)
        race_slot = admin.call("/api/admin/slots", "POST", {
            "starts_at": (starts + timedelta(days=3)).isoformat(timespec="minutes"),
            "location": "Тестовый корпус, 3", "capacity": 1,
        }, expected=201)["id"]
        def attempt_booking(racer):
            try:
                racer.call("/api/bookings", "POST", {"slot_id": race_slot}, expected=201)
                return True
            except AssertionError as exc:
                if "got 409" in str(exc): return False
                raise
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(attempt_booking, racers))
        self.assertCountEqual(outcomes, [True, False])
        self.assertEqual(admin.call("/api/admin/overview")["slots"][0]["capacity"], 1)

        admin.call(f"/api/admin/users/{candidate_id}/role", "POST", {"role": "interviewer"})
        admin.call(f"/api/admin/slots/{slot_id}", "POST", {"action": "interviewer", "interviewer_id": candidate_id})
        interviewer = APIClient(base)
        interviewer.call("/api/session")
        interviewer.call("/api/auth/login", "POST", {"phone": "+79990000002", "password": "candidate-test-password-123"})
        review = interviewer.call("/api/work")["reviews"]
        self.assertEqual(len(review), 1)
        self.assertNotIn("grade", review[0])
        interviewer.call(f"/api/admin/bookings/{review[0]['id']}/result", "POST", {"result": "Подходит", "grade": 8}, expected=403)
        interviewer.call(f"/api/admin/bookings/{review[0]['id']}/result", "POST", {"result": "Подходит"})
        admin.call(f"/api/admin/bookings/{review[0]['id']}/result", "POST", {"result": "Подходит", "grade": 8})
        saved_review = next(item for item in admin.call("/api/work")["reviews"] if item["id"] == review[0]["id"])
        self.assertEqual(saved_review["grade"], 8)


if __name__ == "__main__":
    unittest.main()
