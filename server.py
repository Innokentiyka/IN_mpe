#!/usr/bin/env python3
"""Small, dependency-free application server for the IN MEI MVP."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from getpass import getpass
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse
from zoneinfo import ZoneInfo

os.umask(0o077)
ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("IN_MPE_DB", ROOT / "data" / "in_mpe.sqlite3"))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
SESSION_DAYS = 7
PBKDF2_ROUNDS = 600_000
MAX_BODY = 16_384
MOSCOW = ZoneInfo("Europe/Moscow")
ROLE_LABELS = {"candidate": "Кандидат", "mentor": "Наставник", "interviewer": "Интервьюер", "admin": "Администратор"}
STATUS_LABELS = {"Submitted": "Заявка отправлена", "Interview": "Интервью", "School": "Школа ИН", "Attestation": "Аттестация", "Accepted": "Наставник", "Rejected": "Отказ"}
ALLOWED_STATUSES = set(STATUS_LABELS)
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
LOGIN_LOCK = threading.Lock()


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if DB_PATH.parent == ROOT / "data":
        DB_PATH.parent.chmod(0o700)
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    if DB_PATH.exists():
        DB_PATH.chmod(0o600)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_db() -> None:
    with db() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY, full_name TEXT NOT NULL, phone TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'candidate'
            CHECK(role IN ('candidate','mentor','interviewer','admin')),
          status TEXT NOT NULL DEFAULT 'Submitted',
          study_group TEXT NOT NULL DEFAULT '', vk_url TEXT NOT NULL DEFAULT '',
          experience TEXT NOT NULL DEFAULT 'junior', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
          csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
        CREATE TABLE IF NOT EXISTS interview_slots (
          id TEXT PRIMARY KEY, starts_at TEXT NOT NULL, location TEXT NOT NULL,
          capacity INTEGER NOT NULL CHECK(capacity BETWEEN 1 AND 100),
          interviewer_id TEXT REFERENCES users(id) ON DELETE SET NULL,
          kind TEXT NOT NULL DEFAULT 'interview' CHECK(kind IN ('interview','attestation')),
          status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','cancelled')),
          created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS slots_date ON interview_slots(starts_at, status);
        CREATE TABLE IF NOT EXISTS bookings (
          id TEXT PRIMARY KEY, slot_id TEXT NOT NULL REFERENCES interview_slots(id),
          user_id TEXT NOT NULL REFERENCES users(id), status TEXT NOT NULL DEFAULT 'active'
            CHECK(status IN ('active','cancelled','completed')),
          result TEXT NOT NULL DEFAULT '', grade INTEGER, created_at TEXT NOT NULL,
          UNIQUE(slot_id,user_id)
        );
        CREATE INDEX IF NOT EXISTS bookings_user ON bookings(user_id,status);
        CREATE TABLE IF NOT EXISTS notifications (
          id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          message TEXT NOT NULL, created_at TEXT NOT NULL, read_at TEXT
        );
        CREATE INDEX IF NOT EXISTS notices_user ON notifications(user_id,created_at DESC);
        CREATE TABLE IF NOT EXISTS materials (
          id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL,
          published INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
          starts_at TEXT NOT NULL, location TEXT NOT NULL DEFAULT '',
          capacity INTEGER NOT NULL DEFAULT 100 CHECK(capacity BETWEEN 1 AND 500),
          published INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS event_bookings (
          id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES events(id),
          user_id TEXT NOT NULL REFERENCES users(id),
          status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','cancelled','attended','absent')),
          created_at TEXT NOT NULL, UNIQUE(event_id,user_id)
        );
        CREATE INDEX IF NOT EXISTS event_bookings_event ON event_bookings(event_id,status);
        CREATE TABLE IF NOT EXISTS audit_log (
          id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES users(id),
          action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """)
        columns={row["name"] for row in conn.execute("PRAGMA table_info(interview_slots)")}
        if "kind" not in columns:
            conn.execute("ALTER TABLE interview_slots ADD COLUMN kind TEXT NOT NULL DEFAULT 'interview'")
        event_columns={row["name"] for row in conn.execute("PRAGMA table_info(events)")}
        if "capacity" not in event_columns:
            conn.execute("ALTER TABLE events ADD COLUMN capacity INTEGER NOT NULL DEFAULT 100")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


DUMMY_PASSWORD_HASH = password_hash(secrets.token_urlsafe(32))


def password_matches(password: str, saved: str) -> bool:
    try:
        algorithm, rounds, salt_hex, expected = saved.split("$", 3)
        if algorithm != "pbkdf2_sha256" or int(rounds) < 100_000 or int(rounds) > 2_000_000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def clean_text(value: object, label: str, maximum: int, minimum: int = 1) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Поле «{label}» заполнено некорректно.")
    value = value.strip()
    if not minimum <= len(value) <= maximum or any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError(f"Проверьте поле «{label}» (от {minimum} до {maximum} символов).")
    return value


def normalize_phone(value: object) -> str:
    phone = clean_text(value, "телефон", 24, 8)
    if not re.fullmatch(r"\+?[0-9 ()\-]{8,23}", phone):
        raise ValueError("Укажите корректный номер телефона.")
    digits = re.sub(r"\D", "", phone)
    if not 8 <= len(digits) <= 15:
        raise ValueError("Укажите корректный номер телефона.")
    return ("+" if phone.startswith("+") else "") + digits


def parse_local_datetime(value: object) -> str:
    raw = clean_text(value, "дата и время", 40)
    try:
        date = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError("Укажите дату и время в корректном формате.") from exc
    if date.tzinfo is None:
        date = date.replace(tzinfo=MOSCOW)
    date = date.astimezone(timezone.utc)
    if date < datetime.now(timezone.utc) - timedelta(minutes=1):
        raise ValueError("Нельзя создать запись на прошедшее время.")
    return date.isoformat(timespec="minutes")


def local_time(value: str) -> str:
    try:
        date = datetime.fromisoformat(value)
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return date.astimezone(MOSCOW).strftime("%d.%m.%Y, %H:%M")
    except ValueError:
        return value


def session_digest(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def user_json(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    return {"id": row["id"], "name": row["full_name"], "phone": row["phone"],
            "role": row["role"], "role_label": ROLE_LABELS[row["role"]],
            "status": row["status"], "status_label": STATUS_LABELS.get(row["status"], row["status"]),
            "group": row["study_group"], "vk_url": row["vk_url"], "experience": row["experience"]}


class AppHandler(SimpleHTTPRequestHandler):
    server_version = "INMEI"
    sys_version = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt: str, *args) -> None:
        # Do not put request query strings or personal data in routine logs.
        print(f"{self.address_string()} {self.command} {self.path.split('?')[0]} {args[1] if len(args) > 1 else ''}")

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
        super().end_headers()

    def serve_static(self, route: str, head: bool = False) -> None:
        allowed = {
            "/": ROOT / "index.html",
            "/index.html": ROOT / "index.html",
            "/privacy.html": ROOT / "privacy.html",
            "/public/styles.css": ROOT / "public" / "styles.css",
            "/public/app.js": ROOT / "public" / "app.js",
            "/public/brandmark.png": ROOT / "public" / "brandmark.png",
            "/public/favicon.svg": ROOT / "public" / "favicon.svg",
        }
        path = allowed.get(route)
        if path is None or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", self.guess_type(str(path)))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache" if path.suffix in (".html", ".js") else "public, max-age=3600")
        self.end_headers()
        if not head:self.wfile.write(body)

    def do_HEAD(self) -> None:
        route=urlparse(self.path).path
        if route in ("/","/index.html","/privacy.html") or route.startswith("/public/"):
            self.serve_static(route,head=True)
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def send_json(self, payload: dict, status: int = 200, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Некорректный размер запроса.") from exc
        if length < 1 or length > MAX_BODY:
            raise ValueError("Размер запроса превышает допустимый предел.")
        if "application/json" not in self.headers.get("Content-Type", ""):
            raise ValueError("Ожидается запрос в формате JSON.")
        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Не удалось прочитать данные запроса.") from exc
        if not isinstance(data, dict):
            raise ValueError("Некорректный формат запроса.")
        return data

    def session(self, create: bool = False) -> tuple[sqlite3.Row | None, str | None, str | None]:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("inmei_session")
        raw = morsel.value if morsel else ""
        csrf = None
        with db() as conn:
            record = conn.execute("SELECT * FROM sessions WHERE token_hash=? AND expires_at>?", (session_digest(raw), now())).fetchone() if raw else None
            if record is None and create:
                raw = secrets.token_urlsafe(32)
                csrf = secrets.token_urlsafe(32)
                expiry = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat(timespec="seconds")
                conn.execute("DELETE FROM sessions WHERE expires_at<=?", (now(),))
                conn.execute("INSERT INTO sessions(token_hash,csrf_token,expires_at,created_at) VALUES(?,?,?,?)",
                             (session_digest(raw), csrf, expiry, now()))
                record = conn.execute("SELECT * FROM sessions WHERE token_hash=?", (session_digest(raw),)).fetchone()
                secure = "; Secure" if COOKIE_SECURE else ""
                self._new_cookie = f"inmei_session={raw}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_DAYS*86400}{secure}"
            elif record is not None:
                csrf = self.headers.get("X-CSRF-Token") or record["csrf_token"]
                if not hmac.compare_digest(csrf, record["csrf_token"]):
                    csrf = None
            user = conn.execute("SELECT * FROM users WHERE id=?", (record["user_id"],)).fetchone() if record and record["user_id"] else None
            return record, csrf, (user["id"] if user else None)

    def require_csrf(self, record: sqlite3.Row | None) -> bool:
        token = self.headers.get("X-CSRF-Token", "")
        return bool(record and token and hmac.compare_digest(token, record["csrf_token"]))

    def require_user(self, roles: set[str] | None = None) -> sqlite3.Row | None:
        _, _, user_id = self.session()
        if not user_id:
            self.send_json({"error": "Войдите в систему, чтобы продолжить."}, 401)
            return None
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user is None:
            self.send_json({"error": "Сессия завершена. Войдите снова."}, 401)
            return None
        if roles and user["role"] not in roles:
            self.send_json({"error": "Недостаточно прав для этого действия."}, 403)
            return None
        return user

    def request_session(self, create: bool = False):
        return self.session(create=create)

    def rate_limited(self, scope: str, maximum: int, window: int = 900) -> bool:
        key=f"{scope}:{self.client_address[0]}"; tick=time.time()
        with LOGIN_LOCK:
            attempts=[x for x in LOGIN_ATTEMPTS.get(key,[]) if tick-x<window]
            LOGIN_ATTEMPTS[key]=attempts
            if len(attempts)>=maximum:return True
            attempts.append(tick)
            return False

    def do_GET(self) -> None:
        route = urlparse(self.path).path
        try:
            if route in ("/", "/index.html", "/privacy.html") or route.startswith("/public/"):
                self.serve_static(route)
                return
            if route == "/api/session":
                record, csrf, user_id = self.session(create=True)
                with db() as conn:
                    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone() if user_id else None
                headers = {"Set-Cookie": self._new_cookie} if getattr(self, "_new_cookie", None) else None
                self.send_json({"user": user_json(user), "csrf": csrf}, extra_headers=headers)
                return
            if route == "/api/public":
                with db() as conn:
                    events = conn.execute("""SELECT e.id,e.title,e.description,e.starts_at,e.location,e.capacity,
                      e.capacity-(SELECT COUNT(*) FROM event_bookings b WHERE b.event_id=e.id AND b.status IN ('active','attended','absent')) remaining
                      FROM events e WHERE e.published=1 AND e.starts_at>? ORDER BY e.starts_at LIMIT 12""", (now(),)).fetchall()
                    materials = conn.execute("SELECT id,title,body,created_at FROM materials WHERE published=1 ORDER BY created_at DESC LIMIT 20").fetchall()
                self.send_json({"events": [dict(x) | {"display_time": local_time(x["starts_at"])} for x in events],
                                "materials": [dict(x) for x in materials]})
                return
            if route == "/api/slots":
                user=self.require_user()
                if user is None:return
                with db() as conn:
                    rows = conn.execute("""SELECT s.*,u.full_name interviewer,
                       s.capacity-(SELECT COUNT(*) FROM bookings b WHERE b.slot_id=s.id AND b.status='active') remaining
                       FROM interview_slots s LEFT JOIN users u ON u.id=s.interviewer_id
                       WHERE s.status='open' AND s.starts_at>? AND (s.kind='interview' OR ?='Attestation')
                       ORDER BY s.starts_at LIMIT 100""", (now(), user["status"])).fetchall()
                self.send_json({"slots": [dict(x) | {"display_time": local_time(x["starts_at"])} for x in rows]})
                return
            if route == "/api/dashboard":
                user = self.require_user()
                if user is None: return
                with db() as conn:
                    bookings = conn.execute("""SELECT b.id booking_id,b.status booking_status,
                       s.id slot_id,s.starts_at,s.location,s.interviewer_id,s.status slot_status,
                       u.full_name interviewer FROM bookings b JOIN interview_slots s ON s.id=b.slot_id
                       LEFT JOIN users u ON u.id=s.interviewer_id WHERE b.user_id=? AND b.status='active'
                       ORDER BY s.starts_at""", (user["id"],)).fetchall()
                    notices = conn.execute("SELECT id,message,created_at FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 20", (user["id"],)).fetchall()
                    materials = conn.execute("SELECT id,title,body,created_at FROM materials WHERE published=1 ORDER BY created_at DESC LIMIT 20").fetchall()
                    upcoming_events = conn.execute("""SELECT e.id,e.title,e.description,e.starts_at,e.location,
                      e.capacity-(SELECT COUNT(*) FROM event_bookings c WHERE c.event_id=e.id AND c.status IN ('active','attended','absent')) remaining,
                      EXISTS(SELECT 1 FROM event_bookings b WHERE b.event_id=e.id AND b.user_id=? AND b.status IN ('active','attended','absent')) booked
                      FROM events e WHERE e.published=1 AND e.starts_at>? ORDER BY e.starts_at LIMIT 30""", (user["id"],now())).fetchall()
                    my_events=conn.execute("""SELECT b.id booking_id,b.status booking_status,e.id event_id,e.title,e.starts_at,e.location
                      FROM event_bookings b JOIN events e ON e.id=b.event_id WHERE b.user_id=? AND b.status!='cancelled'
                      ORDER BY e.starts_at DESC LIMIT 50""",(user["id"],)).fetchall()
                self.send_json({"user": user_json(user), "bookings": [dict(x) | {"display_time": local_time(x["starts_at"])} for x in bookings],
                                "notifications": [dict(x) for x in notices], "materials": [dict(x) for x in materials],
                                "upcoming_events":[dict(x) | {"display_time":local_time(x["starts_at"])} for x in upcoming_events],
                                "my_events":[dict(x) | {"display_time":local_time(x["starts_at"])} for x in my_events]})
                return
            if route == "/api/admin/overview":
                user = self.require_user({"admin", "interviewer"})
                if user is None: return
                with db() as conn:
                    if user["role"] == "admin":
                        applicants = conn.execute("SELECT id,full_name,phone,study_group,experience,status,role,created_at FROM users WHERE role IN ('candidate','mentor') ORDER BY created_at DESC LIMIT 300").fetchall()
                        slots = conn.execute("""SELECT s.*,u.full_name interviewer,
                          s.capacity-(SELECT COUNT(*) FROM bookings b WHERE b.slot_id=s.id AND b.status='active') remaining,
                          (SELECT COUNT(*) FROM bookings b WHERE b.slot_id=s.id AND b.status='active') booked
                          FROM interview_slots s LEFT JOIN users u ON u.id=s.interviewer_id ORDER BY s.starts_at DESC LIMIT 100""").fetchall()
                        interviewers = conn.execute("SELECT id,full_name,role FROM users WHERE role IN ('admin','interviewer') ORDER BY full_name").fetchall()
                        events = conn.execute("""SELECT e.id,e.title,e.description,e.starts_at,e.location,e.capacity,e.published,
                          (SELECT COUNT(*) FROM event_bookings b WHERE b.event_id=e.id AND b.status IN ('active','attended','absent')) booked
                          FROM events e ORDER BY e.starts_at DESC LIMIT 100""").fetchall()
                        event_attendees=conn.execute("""SELECT b.id,b.event_id,b.status,u.full_name,u.phone,u.study_group,e.title event_title,e.starts_at
                          FROM event_bookings b JOIN users u ON u.id=b.user_id JOIN events e ON e.id=b.event_id
                          ORDER BY e.starts_at DESC,b.created_at LIMIT 500""").fetchall()
                        materials = conn.execute("SELECT id,title,body,published,created_at FROM materials ORDER BY created_at DESC LIMIT 100").fetchall()
                        counts = {x["status"]: x["n"] for x in conn.execute("SELECT status,COUNT(*) n FROM users WHERE role IN ('candidate','mentor') GROUP BY status")}
                        booking_total = conn.execute("SELECT COUNT(*) FROM bookings WHERE status='active'").fetchone()[0]
                    else:
                        applicants = conn.execute("""SELECT DISTINCT u.id,u.full_name,u.phone,u.study_group,u.experience,u.status,u.role,u.created_at
                          FROM users u JOIN bookings b ON b.user_id=u.id JOIN interview_slots s ON s.id=b.slot_id
                          WHERE s.interviewer_id=? AND b.status='active' ORDER BY s.starts_at""", (user["id"],)).fetchall()
                        slots = conn.execute("""SELECT s.*,u.full_name interviewer,
                          s.capacity-(SELECT COUNT(*) FROM bookings b WHERE b.slot_id=s.id AND b.status='active') remaining,
                          (SELECT COUNT(*) FROM bookings b WHERE b.slot_id=s.id AND b.status='active') booked
                          FROM interview_slots s LEFT JOIN users u ON u.id=s.interviewer_id
                          WHERE s.interviewer_id=? ORDER BY s.starts_at DESC LIMIT 100""", (user["id"],)).fetchall()
                        interviewers=[]; events=[]; event_attendees=[]; materials=[]; counts={}; booking_total=len(applicants)
                    self.send_json({"applicants":[dict(x) | {"status_label":STATUS_LABELS.get(x["status"],x["status"])} for x in applicants],
                                    "slots":[dict(x) | {"display_time":local_time(x["starts_at"])} for x in slots],
                                    "interviewers":[dict(x) for x in interviewers],
                                    "events":[dict(x) | {"display_time":local_time(x["starts_at"])} for x in events],
                                    "event_attendees":[dict(x) | {"display_time":local_time(x["starts_at"])} for x in event_attendees],
                                    "materials":[dict(x) for x in materials],
                                    "stats":{"applicants":sum(counts.values()),"interviews":booking_total,"statuses":counts}})
                return
            if route == "/api/work":
                actor=self.require_user({"admin","interviewer"})
                if actor is None:return
                with db() as conn:
                    condition="" if actor["role"]=="admin" else "AND s.interviewer_id=?"
                    args=() if actor["role"]=="admin" else (actor["id"],)
                    rows=conn.execute(f"""SELECT b.id,b.status,b.result,b.grade,b.created_at,
                      u.full_name,u.study_group,s.starts_at,s.location FROM bookings b
                      JOIN users u ON u.id=b.user_id JOIN interview_slots s ON s.id=b.slot_id
                      WHERE b.status IN ('active','completed') {condition} ORDER BY s.starts_at DESC LIMIT 300""",args).fetchall()
                reviews=[]
                for row in rows:
                    item=dict(row) | {"display_time":local_time(row["starts_at"])}
                    if actor["role"]!="admin":item.pop("grade",None)
                    reviews.append(item)
                self.send_json({"reviews":reviews});return
            if route.startswith("/api/"):
                self.send_json({"error": "Такой раздел не найден."}, 404)
                return
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        except (ValueError, sqlite3.Error) as exc:
            self.send_json({"error": str(exc) if isinstance(exc, ValueError) else "Не удалось выполнить запрос."}, 400)

    def do_POST(self) -> None:
        route = urlparse(self.path).path
        try:
            body = self.read_json()
            if route in ("/api/auth/register", "/api/auth/login"):
                record, _, _ = self.session()
                if not self.require_csrf(record):
                    self.send_json({"error": "Обновите страницу и попробуйте снова."}, 403); return
                if route.endswith("register"):
                    if self.rate_limited("register",6):self.send_json({"error":"Слишком много регистраций. Повторите попытку через 15 минут."},429);return
                    self.register(body); return
                self.login(body); return
            record, _, _ = self.session()
            if not self.require_csrf(record):
                self.send_json({"error": "Обновите страницу и попробуйте снова."}, 403); return
            if route == "/api/auth/logout":
                with db() as conn:
                    cookie = SimpleCookie(self.headers.get("Cookie", "")); raw = cookie.get("inmei_session")
                    if raw: conn.execute("DELETE FROM sessions WHERE token_hash=?", (session_digest(raw.value),))
                secure="; Secure" if COOKIE_SECURE else ""
                self.send_json({"ok": True}, extra_headers={"Set-Cookie": f"inmei_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}"}); return
            if route == "/api/bookings":
                user = self.require_user()
                if user is None: return
                if user["role"] not in ("candidate", "mentor"):
                    self.send_json({"error":"Записаться на интервью может только кандидат."},403); return
                slot_id = clean_text(body.get("slot_id"), "слот", 36)
                with db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    slot = conn.execute("SELECT * FROM interview_slots WHERE id=? AND status='open' AND starts_at>?", (slot_id, now())).fetchone()
                    if slot is None:
                        conn.rollback(); self.send_json({"error":"Это время больше недоступно."},409); return
                    if slot["kind"]=="attestation" and user["status"]!="Attestation":
                        conn.rollback();self.send_json({"error":"Запись на аттестацию откроется после прохождения Школы ИН и обновления статуса администратором."},403);return
                    old = conn.execute("SELECT id,status FROM bookings WHERE slot_id=? AND user_id=?", (slot_id,user["id"])).fetchone()
                    if old and old["status"] == "active":
                        conn.rollback(); self.send_json({"error":"Вы уже записаны на это время."},409); return
                    other = conn.execute("SELECT s.starts_at FROM bookings b JOIN interview_slots s ON s.id=b.slot_id WHERE b.user_id=? AND b.status='active' AND s.kind=?", (user["id"],slot["kind"])).fetchone()
                    if other:
                        kind_label="интервью" if slot["kind"]=="interview" else "аттестацию"
                        conn.rollback(); self.send_json({"error":f"У вас уже есть активная запись на {kind_label} ({local_time(other['starts_at'])}). Сначала отмените её."},409); return
                    count = conn.execute("SELECT COUNT(*) FROM bookings WHERE slot_id=? AND status='active'", (slot_id,)).fetchone()[0]
                    if count >= slot["capacity"]:
                        conn.rollback(); self.send_json({"error":"Свободных мест уже нет. Обновите список времени."},409); return
                    if old:
                        conn.execute("UPDATE bookings SET status='active',result='',grade=NULL,created_at=? WHERE id=?", (now(),old["id"]))
                        booking_id=old["id"]
                    else:
                        booking_id=str(uuid.uuid4())
                        conn.execute("INSERT INTO bookings(id,slot_id,user_id,created_at) VALUES(?,?,?,?)", (booking_id,slot_id,user["id"],now()))
                    conn.execute("INSERT INTO notifications(id,user_id,message,created_at) VALUES(?,?,?,?)", (str(uuid.uuid4()),user["id"],f"Вы записаны на интервью: {local_time(slot['starts_at'])}. Место: {slot['location']}.",now()))
                    self.audit(conn,user["id"],"booking.created","booking",booking_id)
                    conn.commit()
                self.send_json({"ok":True,"booking_id":booking_id},201); return
            if route == "/api/bookings/cancel":
                user = self.require_user()
                if user is None: return
                booking_id=clean_text(body.get("booking_id"),"запись",36)
                with db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    booking=conn.execute("SELECT b.*,s.starts_at FROM bookings b JOIN interview_slots s ON s.id=b.slot_id WHERE b.id=? AND b.user_id=? AND b.status='active'",(booking_id,user["id"])).fetchone()
                    if not booking:
                        conn.rollback(); self.send_json({"error":"Активная запись не найдена."},404); return
                    if datetime.fromisoformat(booking["starts_at"]) <= datetime.now(timezone.utc)+timedelta(hours=2):
                        conn.rollback(); self.send_json({"error":"Отменить запись можно не позднее чем за 2 часа. Свяжитесь с администратором."},409); return
                    conn.execute("UPDATE bookings SET status='cancelled' WHERE id=?",(booking_id,))
                    conn.execute("INSERT INTO notifications(id,user_id,message,created_at) VALUES(?,?,?,?)",(str(uuid.uuid4()),user["id"],"Вы отменили запись на интервью.",now()))
                    self.audit(conn,user["id"],"booking.cancelled","booking",booking_id); conn.commit()
                self.send_json({"ok":True}); return
            if route == "/api/events/bookings":
                user=self.require_user()
                if user is None:return
                if user["role"] not in ("candidate","mentor"):
                    self.send_json({"error":"Записаться на событие может только кандидат или наставник."},403);return
                event_id=clean_text(body.get("event_id"),"событие",36)
                with db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    event=conn.execute("SELECT * FROM events WHERE id=? AND published=1 AND starts_at>?",(event_id,now())).fetchone()
                    if not event:
                        conn.rollback();self.send_json({"error":"Это событие больше недоступно."},404);return
                    old=conn.execute("SELECT id,status FROM event_bookings WHERE event_id=? AND user_id=?",(event_id,user["id"])).fetchone()
                    if old and old["status"]!='cancelled':
                        conn.rollback();self.send_json({"error":"Вы уже записаны на это событие."},409);return
                    attendees=conn.execute("SELECT COUNT(*) FROM event_bookings WHERE event_id=? AND status IN ('active','attended','absent')",(event_id,)).fetchone()[0]
                    if attendees>=event["capacity"]:
                        conn.rollback();self.send_json({"error":"Свободных мест на событие больше нет."},409);return
                    booking_id=old["id"] if old else str(uuid.uuid4())
                    if old:conn.execute("UPDATE event_bookings SET status='active',created_at=? WHERE id=?",(now(),booking_id))
                    else:conn.execute("INSERT INTO event_bookings(id,event_id,user_id,created_at) VALUES(?,?,?,?)",(booking_id,event_id,user["id"],now()))
                    conn.execute("INSERT INTO notifications(id,user_id,message,created_at) VALUES(?,?,?,?)",(str(uuid.uuid4()),user["id"],f"Вы записаны на событие «{event['title']}» ({local_time(event['starts_at'])}).",now()))
                    self.audit(conn,user["id"],"event_booking.created","event_booking",booking_id);conn.commit()
                self.send_json({"ok":True,"booking_id":booking_id},201);return
            if route == "/api/events/bookings/cancel":
                user=self.require_user()
                if user is None:return
                booking_id=clean_text(body.get("booking_id"),"запись",36)
                with db() as conn:
                    row=conn.execute("SELECT b.id,b.event_id,e.title,e.starts_at FROM event_bookings b JOIN events e ON e.id=b.event_id WHERE b.id=? AND b.user_id=? AND b.status='active'",(booking_id,user["id"])).fetchone()
                    if not row:self.send_json({"error":"Активная запись не найдена."},404);return
                    if datetime.fromisoformat(row["starts_at"])<=datetime.now(timezone.utc)+timedelta(hours=2):
                        self.send_json({"error":"Отменить запись можно не позднее чем за 2 часа до события."},409);return
                    conn.execute("UPDATE event_bookings SET status='cancelled' WHERE id=?",(booking_id,))
                    conn.execute("INSERT INTO notifications(id,user_id,message,created_at) VALUES(?,?,?,?)",(str(uuid.uuid4()),user["id"],f"Вы отменили запись на событие «{row['title']}».",now()))
                    self.audit(conn,user["id"],"event_booking.cancelled","event_booking",booking_id)
                self.send_json({"ok":True});return
            if route == "/api/admin/slots":
                admin=self.require_user({"admin"})
                if admin is None:return
                starts=parse_local_datetime(body.get("starts_at")); location=clean_text(body.get("location"),"место",160)
                kind=body.get("kind","interview")
                if kind not in ("interview","attestation"):raise ValueError("Выберите тип записи из списка.")
                try: capacity=int(body.get("capacity",1))
                except (ValueError,TypeError) as exc: raise ValueError("Количество мест должно быть целым числом.") from exc
                if not 1<=capacity<=100: raise ValueError("Количество мест: от 1 до 100.")
                interviewer_id=body.get("interviewer_id") or None
                with db() as conn:
                    if interviewer_id:
                        interviewer=conn.execute("SELECT id FROM users WHERE id=? AND role IN ('interviewer','admin')",(interviewer_id,)).fetchone()
                        if not interviewer: raise ValueError("Интервьюер не найден.")
                    slot_id=str(uuid.uuid4())
                    conn.execute("INSERT INTO interview_slots(id,starts_at,location,capacity,interviewer_id,kind,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",(slot_id,starts,location,capacity,interviewer_id,kind,admin["id"],now()))
                    self.audit(conn,admin["id"],"slot.created","slot",slot_id)
                self.send_json({"ok":True,"id":slot_id},201); return
            if route.startswith("/api/admin/slots/"):
                admin=self.require_user({"admin"})
                if admin is None:return
                slot_id=unquote(route.rsplit("/",1)[-1]); action=body.get("action")
                with db() as conn:
                    slot=conn.execute("SELECT * FROM interview_slots WHERE id=?",(slot_id,)).fetchone()
                    if not slot:self.send_json({"error":"Интервал не найден."},404);return
                    if action=="cancel":
                        conn.execute("UPDATE interview_slots SET status='cancelled' WHERE id=?",(slot_id,))
                        bookings=conn.execute("SELECT user_id FROM bookings WHERE slot_id=? AND status='active'",(slot_id,)).fetchall()
                        for booking in bookings:
                            conn.execute("UPDATE bookings SET status='cancelled' WHERE slot_id=? AND user_id=? AND status='active'",(slot_id,booking["user_id"]))
                            conn.execute("INSERT INTO notifications(id,user_id,message,created_at) VALUES(?,?,?,?)",(str(uuid.uuid4()),booking["user_id"],f"Интервью {local_time(slot['starts_at'])} отменено. Выберите другое свободное время.",now()))
                    elif action=="capacity":
                        try: capacity=int(body.get("capacity"))
                        except (ValueError,TypeError) as exc: raise ValueError("Некорректное количество мест.") from exc
                        booked=conn.execute("SELECT COUNT(*) FROM bookings WHERE slot_id=? AND status='active'",(slot_id,)).fetchone()[0]
                        if capacity<booked or capacity>100: raise ValueError(f"Число мест не может быть меньше уже записанных ({booked}) и больше 100.")
                        conn.execute("UPDATE interview_slots SET capacity=? WHERE id=?",(capacity,slot_id))
                    elif action=="interviewer":
                        interviewer_id=body.get("interviewer_id") or None
                        if interviewer_id and not conn.execute("SELECT 1 FROM users WHERE id=? AND role IN ('interviewer','admin')",(interviewer_id,)).fetchone(): raise ValueError("Интервьюер не найден.")
                        conn.execute("UPDATE interview_slots SET interviewer_id=? WHERE id=?",(interviewer_id,slot_id))
                    else: raise ValueError("Неизвестное действие с расписанием.")
                    self.audit(conn,admin["id"],f"slot.{action}","slot",slot_id)
                self.send_json({"ok":True});return
            if route.startswith("/api/admin/users/") and route.endswith("/status"):
                admin=self.require_user({"admin"})
                if admin is None:return
                user_id=unquote(route.split("/")[-2]); status=clean_text(body.get("status"),"статус",20)
                if status not in ALLOWED_STATUSES: raise ValueError("Неизвестный статус заявки.")
                with db() as conn:
                    user=conn.execute("SELECT id FROM users WHERE id=? AND role IN ('candidate','mentor')",(user_id,)).fetchone()
                    if not user:self.send_json({"error":"Кандидат не найден."},404);return
                    conn.execute("UPDATE users SET status=?,role=CASE WHEN ?='Accepted' THEN 'mentor' ELSE role END WHERE id=?",(status,status,user_id))
                    conn.execute("INSERT INTO notifications(id,user_id,message,created_at) VALUES(?,?,?,?)",(str(uuid.uuid4()),user_id,"Статус заявки обновлён: "+STATUS_LABELS[status],now()))
                    self.audit(conn,admin["id"],"candidate.status_changed","user",user_id)
                self.send_json({"ok":True});return
            if route.startswith("/api/admin/users/") and route.endswith("/role"):
                admin=self.require_user({"admin"})
                if admin is None:return
                user_id=unquote(route.split("/")[-2]); role=body.get("role")
                if role not in ("candidate","mentor","interviewer"):raise ValueError("Недопустимая роль.")
                with db() as conn:
                    row=conn.execute("SELECT id FROM users WHERE id=?",(user_id,)).fetchone()
                    if not row:self.send_json({"error":"Пользователь не найден."},404);return
                    conn.execute("UPDATE users SET role=? WHERE id=?",(role,user_id))
                    self.audit(conn,admin["id"],"user.role_changed","user",user_id)
                self.send_json({"ok":True});return
            if route.startswith("/api/admin/bookings/") and route.endswith("/result"):
                actor=self.require_user({"admin","interviewer"})
                if actor is None:return
                booking_id=unquote(route.split("/")[-2]); result=clean_text(body.get("result"),"результат интервью",1000)
                grade=body.get("grade")
                if actor["role"]=="interviewer" and grade not in (None,""):
                    self.send_json({"error":"Оценку может внести только администратор."},403);return
                if grade not in (None,""):
                    try:grade=int(grade)
                    except (TypeError,ValueError) as exc:raise ValueError("Оценка должна быть числом.") from exc
                    if not 1<=grade<=10:raise ValueError("Оценка должна быть от 1 до 10.")
                with db() as conn:
                    row=conn.execute("SELECT b.user_id,s.interviewer_id FROM bookings b JOIN interview_slots s ON s.id=b.slot_id WHERE b.id=?",(booking_id,)).fetchone()
                    if not row:self.send_json({"error":"Запись не найдена."},404);return
                    if actor["role"]=="interviewer" and row["interviewer_id"]!=actor["id"]:
                        self.send_json({"error":"Вы можете фиксировать результат только назначенных вам интервью."},403);return
                    conn.execute("UPDATE bookings SET result=?,grade=?,status='completed' WHERE id=?",(result,grade,booking_id))
                    conn.execute("INSERT INTO notifications(id,user_id,message,created_at) VALUES(?,?,?,?)",(str(uuid.uuid4()),row["user_id"],"Интервью завершено. Результат доступен администратору.",now()))
                    self.audit(conn,actor["id"],"interview.result_saved","booking",booking_id)
                self.send_json({"ok":True});return
            if route == "/api/admin/materials":
                admin=self.require_user({"admin"})
                if admin is None:return
                title=clean_text(body.get("title"),"заголовок",140); content=clean_text(body.get("body"),"текст",8000)
                material_id=str(uuid.uuid4())
                with db() as conn:
                    conn.execute("INSERT INTO materials(id,title,body,created_by,created_at) VALUES(?,?,?,?,?)",(material_id,title,content,admin["id"],now()))
                    self.audit(conn,admin["id"],"material.created","material",material_id)
                self.send_json({"ok":True,"id":material_id},201);return
            if route == "/api/admin/events":
                admin=self.require_user({"admin"})
                if admin is None:return
                title=clean_text(body.get("title"),"название",140); description=clean_text(body.get("description"),"описание",2000)
                starts=parse_local_datetime(body.get("starts_at")); location=clean_text(body.get("location",""),"место",160,0)
                try:capacity=int(body.get("capacity",100))
                except (ValueError,TypeError) as exc:raise ValueError("Количество мест должно быть целым числом.") from exc
                if not 1<=capacity<=500:raise ValueError("Количество мест: от 1 до 500.")
                event_id=str(uuid.uuid4())
                with db() as conn:
                    conn.execute("INSERT INTO events(id,title,description,starts_at,location,capacity,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",(event_id,title,description,starts,location,capacity,admin["id"],now()))
                    self.audit(conn,admin["id"],"event.created","event",event_id)
                self.send_json({"ok":True,"id":event_id},201);return
            if route.startswith("/api/admin/event-bookings/") and route.endswith("/attendance"):
                admin=self.require_user({"admin"})
                if admin is None:return
                booking_id=unquote(route.split("/")[-2]); status=body.get("status")
                if status not in ("active","attended","absent","cancelled"):raise ValueError("Неизвестный статус участия.")
                with db() as conn:
                    changed=conn.execute("UPDATE event_bookings SET status=? WHERE id=?",(status,booking_id)).rowcount
                    if not changed:self.send_json({"error":"Запись участника не найдена."},404);return
                    self.audit(conn,admin["id"],"event.attendance_changed","event_booking",booking_id)
                self.send_json({"ok":True});return
            self.send_json({"error":"Такой раздел не найден."},404)
        except ValueError as exc:
            self.send_json({"error":str(exc)},400)
        except sqlite3.IntegrityError as exc:
            message="Пользователь с таким телефоном уже зарегистрирован." if "users.phone" in str(exc) else "Операцию нельзя выполнить: проверьте связанные записи."
            self.send_json({"error":message},409)
        except sqlite3.Error:
            self.send_json({"error":"Не удалось выполнить запрос. Попробуйте позже."},500)

    def do_PATCH(self) -> None:
        route=urlparse(self.path).path
        try:
            record,_,_=self.session()
            if not self.require_csrf(record):self.send_json({"error":"Обновите страницу и попробуйте снова."},403);return
            user=self.require_user()
            if user is None:return
            body=self.read_json()
            if route.startswith("/api/admin/materials/") or route.startswith("/api/admin/events/"):
                admin=self.require_user({"admin"})
                if admin is None:return
                item_id=unquote(route.rsplit("/",1)[-1])
                published=body.get("published",True)
                if not isinstance(published,bool):raise ValueError("Проверьте статус публикации.")
                with db() as conn:
                    if route.startswith("/api/admin/materials/"):
                        existing=conn.execute("SELECT * FROM materials WHERE id=?",(item_id,)).fetchone()
                        if not existing:self.send_json({"error":"Материал не найден."},404);return
                        title=clean_text(body.get("title",existing["title"]),"заголовок",140); content=clean_text(body.get("body",existing["body"]),"текст",8000)
                        published=body.get("published",bool(existing["published"]))
                        if not isinstance(published,bool):raise ValueError("Проверьте статус публикации.")
                        changed=conn.execute("UPDATE materials SET title=?,body=?,published=? WHERE id=?",(title,content,int(published),item_id)).rowcount
                        entity="material"
                    else:
                        existing=conn.execute("SELECT * FROM events WHERE id=?",(item_id,)).fetchone()
                        if not existing:self.send_json({"error":"Событие не найдено."},404);return
                        title=clean_text(body.get("title",existing["title"]),"название",140); description=clean_text(body.get("description",existing["description"]),"описание",2000)
                        starts=parse_local_datetime(body["starts_at"]) if "starts_at" in body else existing["starts_at"]
                        location=clean_text(body.get("location",existing["location"]),"место",160,0)
                        try:capacity=int(body.get("capacity",existing["capacity"]))
                        except (ValueError,TypeError) as exc:raise ValueError("Количество мест должно быть целым числом.") from exc
                        booked=conn.execute("SELECT COUNT(*) FROM event_bookings WHERE event_id=? AND status IN ('active','attended','absent')",(item_id,)).fetchone()[0]
                        if not max(1,booked)<=capacity<=500:raise ValueError(f"Количество мест должно быть не меньше уже записанных ({booked}) и не больше 500.")
                        published=body.get("published",bool(existing["published"]))
                        if not isinstance(published,bool):raise ValueError("Проверьте статус публикации.")
                        changed=conn.execute("UPDATE events SET title=?,description=?,starts_at=?,location=?,capacity=?,published=? WHERE id=?",(title,description,starts,location,capacity,int(published),item_id)).rowcount
                        entity="event"
                    if not changed:self.send_json({"error":"Материал не найден."},404);return
                    self.audit(conn,admin["id"],entity+".updated",entity,item_id)
                self.send_json({"ok":True});return
            if route!="/api/profile":self.send_json({"error":"Такой раздел не найден."},404);return
            if user["role"] not in ("candidate","mentor"):self.send_json({"error":"Профиль кандидата недоступен для этой роли."},403);return
            name=clean_text(body.get("name"),"имя",120); study_group=clean_text(body.get("group",""),"учебная группа",80,0)
            experience=body.get("experience","junior")
            if experience not in ("junior","experienced"):raise ValueError("Выберите вариант опыта из списка.")
            vk=clean_text(body.get("vk_url",""),"ссылка ВКонтакте",250,0)
            if vk and (not vk.startswith("https://vk.com/") or any(c in vk for c in "\r\n\\")):raise ValueError("Для ссылки укажите адрес вида https://vk.com/имя.")
            with db() as conn:
                conn.execute("UPDATE users SET full_name=?,study_group=?,experience=?,vk_url=? WHERE id=?",(name,study_group,experience,vk,user["id"]))
                self.audit(conn,user["id"],"profile.updated","user",user["id"])
                updated=conn.execute("SELECT * FROM users WHERE id=?",(user["id"],)).fetchone()
            self.send_json({"ok":True,"user":user_json(updated)})
        except ValueError as exc:self.send_json({"error":str(exc)},400)
        except sqlite3.Error:self.send_json({"error":"Не удалось сохранить профиль."},500)

    def register(self, body: dict) -> None:
        name=clean_text(body.get("name"),"имя",120,2); phone=normalize_phone(body.get("phone"))
        study_group=clean_text(body.get("group"),"учебная группа",80,1)
        experience=body.get("experience","junior")
        if experience not in ("junior","experienced"):raise ValueError("Выберите вариант опыта из списка.")
        password=body.get("password")
        if not isinstance(password,str) or not 12<=len(password)<=128:raise ValueError("Пароль должен содержать от 12 до 128 символов.")
        if body.get("consent") is not True:raise ValueError("Для создания аккаунта подтвердите согласие на обработку данных.")
        user_id=str(uuid.uuid4()); raw=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32)
        expiry=(datetime.now(timezone.utc)+timedelta(days=SESSION_DAYS)).isoformat(timespec="seconds")
        with db() as conn:
            cookie=SimpleCookie(self.headers.get("Cookie","")); old=cookie.get("inmei_session")
            if old:conn.execute("DELETE FROM sessions WHERE token_hash=?",(session_digest(old.value),))
            conn.execute("INSERT INTO users(id,full_name,phone,password_hash,study_group,experience,created_at) VALUES(?,?,?,?,?,?,?)",(user_id,name,phone,password_hash(password),study_group,experience,now()))
            conn.execute("INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)",(session_digest(raw),user_id,csrf,expiry,now()))
            conn.execute("INSERT INTO notifications(id,user_id,message,created_at) VALUES(?,?,?,?)",(str(uuid.uuid4()),user_id,"Добро пожаловать! Заполните профиль и выберите удобное время интервью.",now()))
        secure="; Secure" if COOKIE_SECURE else ""
        self.send_json({"ok":True,"user":{"id":user_id,"name":name,"phone":phone,"role":"candidate","role_label":ROLE_LABELS["candidate"],"status":"Submitted","status_label":STATUS_LABELS["Submitted"],"group":study_group,"experience":experience,"vk_url":""},"csrf":csrf},201, {"Set-Cookie":f"inmei_session={raw}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_DAYS*86400}{secure}"})

    def login(self, body: dict) -> None:
        ip=self.client_address[0]
        if self.rate_limited("login",8):self.send_json({"error":"Слишком много попыток входа. Подождите 15 минут."},429);return
        try:phone=normalize_phone(body.get("phone"))
        except ValueError:phone=""
        password=body.get("password","")
        with db() as conn: user=conn.execute("SELECT * FROM users WHERE phone=?",(phone,)).fetchone() if phone else None
        saved_hash=user["password_hash"] if user else DUMMY_PASSWORD_HASH
        valid=password_matches(password,saved_hash) if isinstance(password,str) and len(password)<=128 else False
        if not valid:
            self.send_json({"error":"Телефон или пароль указаны неверно."},401);return
        with LOGIN_LOCK:LOGIN_ATTEMPTS.pop("login:"+ip,None)
        raw=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32); expiry=(datetime.now(timezone.utc)+timedelta(days=SESSION_DAYS)).isoformat(timespec="seconds")
        cookie=SimpleCookie(self.headers.get("Cookie","")); old=cookie.get("inmei_session")
        with db() as conn:
            if old:conn.execute("DELETE FROM sessions WHERE token_hash=?",(session_digest(old.value),))
            conn.execute("INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)",(session_digest(raw),user["id"],csrf,expiry,now()))
        secure="; Secure" if COOKIE_SECURE else ""
        self.send_json({"ok":True,"user":user_json(user),"csrf":csrf},extra_headers={"Set-Cookie":f"inmei_session={raw}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_DAYS*86400}{secure}"})

    @staticmethod
    def audit(conn: sqlite3.Connection, actor: str, action: str, entity_type: str, entity_id: str) -> None:
        conn.execute("INSERT INTO audit_log(id,actor_id,action,entity_type,entity_id,created_at) VALUES(?,?,?,?,?,?)",(str(uuid.uuid4()),actor,action,entity_type,entity_id,now()))


def create_admin(phone: str | None = None) -> None:
    init_db()
    phone=normalize_phone(phone or input("Телефон администратора: "))
    name=clean_text(input("Имя администратора: "),"имя",120,2)
    password=getpass("Новый пароль (не менее 12 символов): ")
    if len(password)<12 or len(password)>128:raise SystemExit("Пароль должен содержать от 12 до 128 символов.")
    with db() as conn:
        exists=conn.execute("SELECT 1 FROM users WHERE phone=?",(phone,)).fetchone()
        if exists:raise SystemExit("Аккаунт с этим телефоном уже существует; назначьте роль через консоль базы данных.")
        conn.execute("INSERT INTO users(id,full_name,phone,password_hash,role,status,created_at) VALUES(?,?,?,?, 'admin','Accepted',?)",(str(uuid.uuid4()),name,phone,password_hash(password),now()))
    print("Аккаунт администратора создан. Теперь можно запускать сервер.")


def reset_password(phone: str | None = None) -> None:
    init_db()
    phone=normalize_phone(phone or input("Телефон пользователя: "))
    password=getpass("Новый пароль (не менее 12 символов): ")
    if len(password)<12 or len(password)>128:raise SystemExit("Пароль должен содержать от 12 до 128 символов.")
    with db() as conn:
        user=conn.execute("SELECT id FROM users WHERE phone=?",(phone,)).fetchone()
        if not user:raise SystemExit("Пользователь с таким телефоном не найден.")
        conn.execute("UPDATE users SET password_hash=? WHERE id=?",(password_hash(password),user["id"]))
        conn.execute("DELETE FROM sessions WHERE user_id=?",(user["id"],))
    print("Пароль изменён; прежние сессии завершены.")


def main() -> None:
    if len(sys.argv)>1 and sys.argv[1]=="create-admin":
        create_admin(sys.argv[2] if len(sys.argv)>2 else None);return
    if len(sys.argv)>1 and sys.argv[1]=="reset-password":
        reset_password(sys.argv[2] if len(sys.argv)>2 else None);return
    init_db()
    server=ThreadingHTTPServer((HOST,PORT),AppHandler)
    print(f"ИН МЭИ running at http://{HOST}:{PORT} (SQLite: {DB_PATH})")
    try:server.serve_forever()
    except KeyboardInterrupt:print("\nStopping server")
    finally:server.server_close()


if __name__=="__main__":main()
