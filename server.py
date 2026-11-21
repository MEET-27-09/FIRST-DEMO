#!/usr/bin/env python3
"""
CIRS - Campus Item Recovery System
==================================

A single-file server that replaces the Express API and serves the built React
frontend. It uses only the Python standard library (no Flask, no pip installs).

Setup (Windows PowerShell or any OS), from the CIRS folder:

    python server.py

Then open http://localhost:5000

The built frontend (frontend/dist) already points at http://localhost:5000/api,
so keep the default PORT. If you change PORT, rebuild the frontend with
VITE_API_URL set to the new API address.

Optional environment variables:
    PORT            default 5000
    JWT_SECRET      default: a random secret, saved to .jwt_secret
    JWT_EXPIRES_IN  default 7d (accepts 30m, 12h, 7d, or plain seconds)
    CLIENT_URL      default http://localhost:5173 (only needed for the Vite dev server)

Data is stored in cirs.db (SQLite). Uploaded photos go to uploads/.
"""

import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import subprocess
import traceback
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DIST_DIR = BASE_DIR / "frontend" / "dist"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = BASE_DIR / "cirs.db"
SECRET_PATH = BASE_DIR / ".jwt_secret"

PORT = int(os.environ.get("PORT", "5000"))
CLIENT_URL = os.environ.get("CLIENT_URL", "http://localhost:5173")
JWT_EXPIRES_IN = os.environ.get("JWT_EXPIRES_IN", "7d")

MAX_JSON_BYTES = 1024 * 1024
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_BODY_BYTES = MAX_IMAGE_BYTES + 1024 * 1024
PBKDF2_ITERATIONS = 260_000

TYPE_VALUES = ("lost", "found")
STATUS_VALUES = ("active", "recovered")
IMAGE_EXTENSIONS = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/gif": ".gif"}
MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
}


def load_secret():
    secret = os.environ.get("JWT_SECRET")
    if secret:
        return secret
    if SECRET_PATH.exists():
        return SECRET_PATH.read_text(encoding="utf-8").strip()
    secret = secrets.token_urlsafe(48)
    SECRET_PATH.write_text(secret, encoding="utf-8")
    print("Created .jwt_secret (set JWT_SECRET in the environment to use your own).")
    return secret


JWT_SECRET = load_secret()


# ---------------------------------------------------------------------------
# Errors and small helpers
# ---------------------------------------------------------------------------

class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def s(value):
    """Convert a request value to a string ('' for None)."""
    return "" if value is None else str(value)


def text_field(value, label, limit, required=True):
    text = s(value).strip()
    if required and not text:
        raise ApiError(400, f"{label} is required.")
    if len(text) > limit:
        raise ApiError(400, f"{label} must be {limit} characters or fewer.")
    return text


def check_id(value):
    if not re.fullmatch(r"[0-9a-fA-F]{24}", s(value)):
        raise ApiError(400, "The requested identifier is invalid.")
    return value.lower()


def now_iso():
    return to_js_iso(datetime.now(timezone.utc))


def to_js_iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_date(text):
    """Parse an ISO date or datetime string. Naive values are treated as UTC."""
    dt = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_item_date(value):
    try:
        return parse_date(s(value))
    except ValueError:
        raise ApiError(400, "Please enter a valid date.")


def escape_like(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def contains_pattern(value):
    return "%" + escape_like(s(value).lower()) + "%"


# ---------------------------------------------------------------------------
# Passwords and tokens (replaces bcryptjs and jsonwebtoken)
# ---------------------------------------------------------------------------

def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def check_password(password, stored):
    try:
        _scheme, iterations, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except ValueError:
        return False


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def expires_in_seconds(value):
    match = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", value.lower())
    if not match:
        return 7 * 86400
    return int(match.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]


def sign(message):
    return b64url(hmac.new(JWT_SECRET.encode("utf-8"), message.encode("ascii"), hashlib.sha256).digest())


def create_token(user_id):
    now = int(datetime.now(timezone.utc).timestamp())
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(json.dumps(
        {"id": user_id, "iat": now, "exp": now + expires_in_seconds(JWT_EXPIRES_IN)},
        separators=(",", ":")
    ).encode())
    return f"{header}.{payload}.{sign(header + '.' + payload)}"


def verify_token(token):
    try:
        header, payload, signature = token.split(".")
        if not hmac.compare_digest(signature, sign(header + "." + payload)):
            return None
        data = json.loads(b64url_decode(payload))
        if data.get("exp", 0) < int(datetime.now(timezone.utc).timestamp()):
            return None
        return data.get("id")
    except (ValueError, TypeError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Database (replaces MongoDB + Mongoose)
# ---------------------------------------------------------------------------

ITEM_SELECT = """
SELECT i.*, u.name AS r_name, u.college AS r_college, u.email AS r_email
FROM items i LEFT JOIN users u ON u.id = i.reporter_id
"""


def connect():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    UPLOAD_DIR.mkdir(exist_ok=True)
    db = connect()
    db.execute("PRAGMA journal_mode = WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            email       TEXT NOT NULL UNIQUE,
            password    TEXT NOT NULL,
            college     TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS items (
            id             TEXT PRIMARY KEY,
            type           TEXT NOT NULL CHECK (type IN ('lost', 'found')),
            name           TEXT NOT NULL,
            category       TEXT NOT NULL,
            description    TEXT NOT NULL,
            location       TEXT NOT NULL,
            date           TEXT NOT NULL,
            image          TEXT NOT NULL DEFAULT '',
            contact        TEXT NOT NULL,
            status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'recovered')),
            reporter_id    TEXT NOT NULL REFERENCES users(id),
            reporter_name  TEXT NOT NULL,
            reporter_email TEXT NOT NULL,
            created_at     TEXT NOT NULL,
            updated_at     TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_items_type ON items(type);
        CREATE INDEX IF NOT EXISTS idx_items_status ON items(status);
        CREATE INDEX IF NOT EXISTS idx_items_reporter ON items(reporter_id);
    """)
    db.commit()
    db.close()


def user_view(row):
    return {"id": row["id"], "name": row["name"], "email": row["email"], "college": row["college"]}


def item_json(row, mode="public"):
    """
    mode None   -> reporter is the id string (unpopulated, like create/update)
    mode public -> reporter is {_id, name, college}
    mode full   -> reporter also includes email (item details page)
    """
    if mode is None:
        reporter = row["reporter_id"]
    elif row["r_name"] is None:
        reporter = None
    else:
        reporter = {"_id": row["reporter_id"], "name": row["r_name"], "college": row["r_college"]}
        if mode == "full":
            reporter["email"] = row["r_email"]
    return {
        "_id": row["id"],
        "type": row["type"],
        "name": row["name"],
        "category": row["category"],
        "description": row["description"],
        "location": row["location"],
        "date": row["date"],
        "image": row["image"],
        "contact": row["contact"],
        "status": row["status"],
        "reporter": reporter,
        "reporterName": row["reporter_name"],
        "reporterEmail": row["reporter_email"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
        "__v": 0,
    }


def require_user(req, db):
    header = req.headers.get("Authorization") or ""
    if not header.startswith("Bearer "):
        raise ApiError(401, "Please sign in to continue.")
    user_id = verify_token(header[7:].strip())
    if not user_id:
        raise ApiError(401, "Your session has expired. Please sign in again.")
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise ApiError(401, "Your account could not be found.")
    return row


# ---------------------------------------------------------------------------
# Smart matching (same scoring as backend/utils/matching.js)
# ---------------------------------------------------------------------------

NON_ALNUM = re.compile(r"[^a-z0-9\s]")


def normalize(value):
    return NON_ALNUM.sub(" ", s(value).lower()).strip()


def words(value):
    return {word for word in re.split(r"\s+", normalize(value)) if len(word) > 2}


def overlap(left, right):
    a, b = words(left), words(right)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def match_fields(row):
    return {
        "type": row["type"],
        "status": row["status"],
        "name": row["name"],
        "category": row["category"],
        "description": row["description"],
        "location": row["location"],
        "date": parse_date(row["date"]),
    }


def score_match(source, candidate):
    if source["type"] == candidate["type"] or source["status"] != "active" or candidate["status"] != "active":
        return 0
    name_score = overlap(source["name"], candidate["name"])
    text_score = overlap(source["description"], candidate["description"])
    category_score = 1 if normalize(source["category"]) == normalize(candidate["category"]) else 0
    location_score = overlap(source["location"], candidate["location"])
    days = abs((source["date"] - candidate["date"]).total_seconds()) / 86400
    date_score = max(0.0, 1 - days / 45)
    total = (name_score * 0.35 + category_score * 0.25 + location_score * 0.2
             + text_score * 0.15 + date_score * 0.05) * 100
    return math.floor(total + 0.5)  # JavaScript-style rounding


# ---------------------------------------------------------------------------
# Request body parsing (JSON, form-data with image uploads, urlencoded)
# ---------------------------------------------------------------------------

class Request:
    def __init__(self, query, body, files, headers):
        self.query = query
        self.body = body
        self.files = files
        self.headers = headers


def parse_multipart(raw, content_type):
    match = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', content_type)
    if not match:
        raise ApiError(400, "Invalid form data.")
    delimiter = b"--" + (match.group(1) or match.group(2)).strip().encode("latin-1")
    fields, files = {}, {}
    for part in raw.split(delimiter)[1:]:
        if part.startswith(b"--"):
            break
        if part.startswith(b"\r\n"):
            part = part[2:]
        if part.endswith(b"\r\n"):
            part = part[:-2]
        head, separator, content = part.partition(b"\r\n\r\n")
        if not separator:
            continue
        headers = {}
        for line in head.decode("utf-8", "replace").split("\r\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        params = {}
        for chunk in headers.get("content-disposition", "").split(";")[1:]:
            if "=" in chunk:
                key, value = chunk.split("=", 1)
                params[key.strip().lower()] = value.strip().strip('"')
        name = params.get("name")
        if not name:
            continue
        if "filename" in params:
            if not params["filename"]:
                continue  # empty file input
            files[name] = {
                "filename": params["filename"],
                "content_type": headers.get("content-type", "").split(";")[0].strip().lower(),
                "data": content,
            }
        else:
            fields[name] = content.decode("utf-8", "replace")
    return fields, files


def parse_body(raw, content_type):
    kind = content_type.split(";")[0].strip().lower()
    if kind == "multipart/form-data":
        return parse_multipart(raw, content_type)
    if kind == "application/x-www-form-urlencoded":
        parsed = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items()}, {}
    if not raw:
        return {}, {}
    if len(raw) > MAX_JSON_BYTES:
        raise ApiError(413, "The request body is too large.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise ApiError(400, "Invalid JSON body.")
    if not isinstance(data, dict):
        raise ApiError(400, "Invalid JSON body.")
    return data, {}


def save_image(upload):
    if upload is None:
        return ""
    if upload["content_type"] not in IMAGE_EXTENSIONS:
        raise ApiError(400, "Please upload a JPEG, PNG, WebP, or GIF image.")
    if len(upload["data"]) > MAX_IMAGE_BYTES:
        raise ApiError(400, "Image must be 5 MB or smaller.")
    filename = f"{uuid.uuid4().hex}{IMAGE_EXTENSIONS[upload['content_type']]}"
    (UPLOAD_DIR / filename).write_bytes(upload["data"])
    return f"/uploads/{filename}"


# ---------------------------------------------------------------------------
# Auth handlers  (/api/auth)
# ---------------------------------------------------------------------------

def h_register(req, db):
    name, email = s(req.body.get("name")).strip(), s(req.body.get("email")).strip().lower()
    password = s(req.body.get("password"))
    if not name or not email or not password:
        raise ApiError(400, "Name, email, and password are required.")
    if len(password) < 8:
        raise ApiError(400, "Password must be at least 8 characters.")
    name = text_field(name, "Name", 80)
    college = text_field(req.body.get("college"), "College", 120, required=False)

    user_id = secrets.token_hex(12)
    now = now_iso()
    try:
        db.execute(
            "INSERT INTO users (id, name, email, password, college, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, name, email, hash_password(password), college, now, now),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise ApiError(409, "An account with this email already exists.")
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return 201, {"token": create_token(user_id), "user": user_view(row)}


def h_login(req, db):
    email = s(req.body.get("email")).strip().lower()
    password = s(req.body.get("password"))
    row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not row or not check_password(password, row["password"]):
        raise ApiError(401, "Email or password is incorrect.")
    return 200, {"token": create_token(row["id"]), "user": user_view(row)}


def h_me(req, db):
    return 200, {"user": user_view(require_user(req, db))}


# ---------------------------------------------------------------------------
# Item handlers  (/api/items)
# ---------------------------------------------------------------------------

def h_health(req, db):
    return 200, {"status": "ok"}


def h_list_items(req, db):
    query = req.query
    where, params = [], []
    if query.get("type") in TYPE_VALUES:
        where.append("i.type = ?")
        params.append(query["type"])
    if query.get("status") in STATUS_VALUES:
        where.append("i.status = ?")
        params.append(query["status"])
    if query.get("category"):
        where.append("i.category = ?")
        params.append(query["category"])
    if query.get("location"):
        where.append("LOWER(i.location) LIKE ? ESCAPE '\\'")
        params.append(contains_pattern(query["location"]))
    if query.get("search"):
        pattern = contains_pattern(query["search"])
        where.append("(" + " OR ".join(
            f"LOWER(i.{column}) LIKE ? ESCAPE '\\'" for column in ("name", "description", "location", "category")
        ) + ")")
        params.extend([pattern] * 4)

    order = {"oldest": "i.date ASC", "name": "i.name ASC"}.get(query.get("sort"), "i.date DESC")
    sql = ITEM_SELECT
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {order} LIMIT 100"
    rows = db.execute(sql, params).fetchall()
    return 200, {"items": [item_json(row) for row in rows]}


def h_stats(req, db):
    counts = {
        "lost": db.execute("SELECT COUNT(*) FROM items WHERE type = 'lost'").fetchone()[0],
        "found": db.execute("SELECT COUNT(*) FROM items WHERE type = 'found'").fetchone()[0],
        "recovered": db.execute("SELECT COUNT(*) FROM items WHERE status = 'recovered'").fetchone()[0],
    }
    return 200, {"stats": counts}


def h_get_item(req, db, item_id):
    oid = check_id(item_id)
    row = db.execute(ITEM_SELECT + " WHERE i.id = ?", (oid,)).fetchone()
    if not row:
        raise ApiError(404, "This item report could not be found.")
    return 200, {"item": item_json(row, mode="full")}


def h_create_item(req, db):
    user = require_user(req, db)
    body = req.body
    item_type = s(body.get("type")).strip()
    if item_type not in TYPE_VALUES:
        raise ApiError(400, "Choose whether the item was lost or found.")
    if any(not s(body.get(key)).strip() for key in ("name", "category", "description", "location", "date", "contact")):
        raise ApiError(400, "Complete all required report fields.")

    name = text_field(body.get("name"), "Item name", 100)
    category = text_field(body.get("category"), "Category", 50)
    description = text_field(body.get("description"), "Description", 2000)
    location = text_field(body.get("location"), "Location", 150)
    contact = text_field(body.get("contact"), "Contact", 150)
    date = to_js_iso(parse_item_date(body.get("date")))
    image = save_image(req.files.get("image"))

    item_id = secrets.token_hex(12)
    now = now_iso()
    db.execute(
        """INSERT INTO items (id, type, name, category, description, location, date, image, contact,
                              status, reporter_id, reporter_name, reporter_email, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)""",
        (item_id, item_type, name, category, description, location, date, image, contact,
         user["id"], user["name"], user["email"], now, now),
    )
    db.commit()
    row = db.execute(ITEM_SELECT + " WHERE i.id = ?", (item_id,)).fetchone()
    return 201, {"item": item_json(row, mode=None)}


def h_update_item(req, db, item_id):
    user = require_user(req, db)
    oid = check_id(item_id)
    row = db.execute("SELECT id FROM items WHERE id = ? AND reporter_id = ?", (oid, user["id"])).fetchone()
    if not row:
        raise ApiError(404, "Report not found or you do not have permission to edit it.")

    body = req.body
    changes = {}
    if body.get("name") is not None:
        changes["name"] = text_field(body["name"], "Item name", 100)
    if body.get("category") is not None:
        changes["category"] = text_field(body["category"], "Category", 50)
    if body.get("description") is not None:
        changes["description"] = text_field(body["description"], "Description", 2000)
    if body.get("location") is not None:
        changes["location"] = text_field(body["location"], "Location", 150)
    if body.get("contact") is not None:
        changes["contact"] = text_field(body["contact"], "Contact", 150)
    if body.get("date") is not None:
        changes["date"] = to_js_iso(parse_item_date(body["date"]))
    if body.get("status") is not None:
        if s(body["status"]) not in STATUS_VALUES:
            raise ApiError(400, "Status must be active or recovered.")
        changes["status"] = s(body["status"])
    image = save_image(req.files.get("image"))
    if image:
        changes["image"] = image

    if changes:
        changes["updated_at"] = now_iso()
        assignments = ", ".join(f"{column} = ?" for column in changes)
        db.execute(f"UPDATE items SET {assignments} WHERE id = ?", [*changes.values(), oid])
        db.commit()
    row = db.execute(ITEM_SELECT + " WHERE i.id = ?", (oid,)).fetchone()
    return 200, {"item": item_json(row, mode=None)}


def h_delete_item(req, db, item_id):
    user = require_user(req, db)
    oid = check_id(item_id)
    cursor = db.execute("DELETE FROM items WHERE id = ? AND reporter_id = ?", (oid, user["id"]))
    db.commit()
    if cursor.rowcount == 0:
        raise ApiError(404, "Report not found or you do not have permission to delete it.")
    return 200, {"message": "Report deleted."}


def h_matches(req, db, item_id):
    oid = check_id(item_id)
    row = db.execute("SELECT * FROM items WHERE id = ?", (oid,)).fetchone()
    if not row:
        raise ApiError(404, "This item report could not be found.")
    opposite = "found" if row["type"] == "lost" else "lost"
    candidates = db.execute(
        ITEM_SELECT + " WHERE i.type = ? AND i.status = 'active' AND i.id <> ? LIMIT 100",
        (opposite, oid),
    ).fetchall()

    source = match_fields(row)
    scored = []
    for candidate in candidates:
        score = score_match(source, match_fields(candidate))
        if score >= 20:
            scored.append((score, candidate))
    scored.sort(key=lambda pair: -pair[0])
    matches = [{"item": item_json(candidate, "public"), "score": score} for score, candidate in scored[:6]]
    return 200, {"matches": matches}


# ---------------------------------------------------------------------------
# Profile handlers  (/api/profile)
# ---------------------------------------------------------------------------

def h_get_profile(req, db):
    user = require_user(req, db)

    def fetch(condition):
        rows = db.execute(
            ITEM_SELECT + f" WHERE i.reporter_id = ? AND {condition} ORDER BY i.created_at DESC",
            (user["id"],),
        ).fetchall()
        return [item_json(row, mode=None) for row in rows]

    return 200, {
        "user": user_view(user),
        "reports": {
            "lost": fetch("i.type = 'lost'"),
            "found": fetch("i.type = 'found'"),
            "recovered": fetch("i.status = 'recovered'"),
        },
    }


def h_update_profile(req, db):
    user = require_user(req, db)
    body = req.body
    name, email, college = user["name"], user["email"], user["college"]
    if body.get("name") is not None:
        name = text_field(body["name"], "Name", 80)
    if s(body.get("email")).strip():
        email = s(body["email"]).strip().lower()
        taken = db.execute("SELECT 1 FROM users WHERE email = ? AND id <> ?", (email, user["id"])).fetchone()
        if taken:
            raise ApiError(409, "An account with this email already exists.")
    if body.get("college") is not None:
        college = text_field(body["college"], "College", 120, required=False)

    db.execute(
        "UPDATE users SET name = ?, email = ?, college = ?, updated_at = ? WHERE id = ?",
        (name, email, college, now_iso(), user["id"]),
    )
    db.commit()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    return 200, {"user": user_view(row)}


# ---------------------------------------------------------------------------
# Routing table (method, path pattern, handler)
# ---------------------------------------------------------------------------

ROUTES = [
    ("GET", re.compile(r"^/api/health$"), h_health),
    ("POST", re.compile(r"^/api/auth/register$"), h_register),
    ("POST", re.compile(r"^/api/auth/login$"), h_login),
    ("GET", re.compile(r"^/api/auth/me$"), h_me),
    ("GET", re.compile(r"^/api/items$"), h_list_items),
    ("POST", re.compile(r"^/api/items$"), h_create_item),
    ("GET", re.compile(r"^/api/items/stats$"), h_stats),
    ("GET", re.compile(r"^/api/items/([^/]+)/matches$"), h_matches),
    ("GET", re.compile(r"^/api/items/([^/]+)$"), h_get_item),
    ("PATCH", re.compile(r"^/api/items/([^/]+)$"), h_update_item),
    ("DELETE", re.compile(r"^/api/items/([^/]+)$"), h_delete_item),
    ("GET", re.compile(r"^/api/profile$"), h_get_profile),
    ("PATCH", re.compile(r"^/api/profile$"), h_update_profile),
]


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class CIRSHandler(BaseHTTPRequestHandler):
    server_version = "CIRS/1.0"

    def do_OPTIONS(self):
        self._send(204, b"", "text/plain; charset=utf-8")

    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method):
        try:
            parts = urlsplit(self.path)
            path = unquote(parts.path)
            if path == "/api" or path.startswith("/api/"):
                self._api(method, path, parts.query)
            elif path.startswith("/uploads/") and method == "GET":
                self._serve_upload(path[len("/uploads/"):])
            elif method == "GET":
                self._serve_frontend(path)
            else:
                raise ApiError(404, "The requested resource was not found.")
        except ApiError as error:
            self._json(error.status, {"message": error.message})
        except Exception:
            traceback.print_exc()
            self._json(500, {"message": "Something went wrong."})

    def _api(self, method, path, query_string):
        raw = self._read_body()
        body, files = parse_body(raw, self.headers.get("Content-Type", ""))
        req = Request(
            query={key: values[0] for key, values in parse_qs(query_string, keep_blank_values=True).items()},
            body=body,
            files=files,
            headers=self.headers,
        )
        for route_method, pattern, handler in ROUTES:
            if route_method != method:
                continue
            match = pattern.match(path)
            if match:
                db = connect()
                try:
                    status, payload = handler(req, db, *match.groups())
                finally:
                    db.close()
                return self._json(status, payload)
        raise ApiError(404, "The requested resource was not found.")

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            if "multipart/form-data" in self.headers.get("Content-Type", "").lower():
                raise ApiError(400, "Image must be 5 MB or smaller.")
            raise ApiError(413, "The request body is too large.")
        return self.rfile.read(length) if length > 0 else b""

    def _serve_upload(self, name):
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            raise ApiError(404, "The requested resource was not found.")
        file_path = UPLOAD_DIR / name
        if not file_path.is_file():
            raise ApiError(404, "The requested resource was not found.")
        self._serve_file(file_path, "public, max-age=86400")

    def _serve_frontend(self, path):
        if not DIST_DIR.is_dir():
            return self._send(
                503,
                f"Website build not found at {DIST_DIR}. Stop server.py, run it again, or run 'npm run build' inside the frontend folder.".encode("utf-8"),
                "text/plain; charset=utf-8",
            )
        root = DIST_DIR.resolve()
        target = (root / path.lstrip("/")).resolve()
        if target != root and root not in target.parents:
            raise ApiError(404, "The requested resource was not found.")
        if target.is_file():
            cache = "public, max-age=31536000, immutable" if "assets" in target.relative_to(root).parts else "no-cache"
            return self._serve_file(target, cache)
        if Path(path).suffix:
            raise ApiError(404, "The requested resource was not found.")
        # Single-page app: unknown routes get index.html so client-side routing works.
        index = root / "index.html"
        if not index.is_file():
            raise ApiError(404, "The requested resource was not found.")
        self._serve_file(index, "no-cache")

    def _serve_file(self, file_path, cache):
        content_type = MIME_TYPES.get(file_path.suffix.lower(), "application/octet-stream")
        self._send(200, file_path.read_bytes(), content_type, cache)

    def _json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _send(self, status, body, content_type, cache="no-store"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("Access-Control-Allow-Origin", CLIENT_URL)
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)


def find_frontend_dir():
    """Find the 'frontend' folder whether server.py sits in CIRS/, backend/, or a copy elsewhere."""
    starts = [BASE_DIR, BASE_DIR.parent, Path.cwd(), Path.cwd().parent]
    for start in starts:
        for folder in (start, start / "CIRS", start / "CIRS" / "CIRS"):
            if (folder / "frontend" / "package.json").is_file():
                return folder / "frontend"
    return None


def ensure_frontend_build():
    """Locate frontend/dist (building it with npm if missing) and point the server at it."""
    global DIST_DIR
    frontend = find_frontend_dir()
    if frontend is None:
        print("Could not find the 'frontend' folder near server.py.")
        print(f"server.py is running from: {BASE_DIR}")
        print("Put server.py in the CIRS folder, the one that contains 'frontend' and 'backend'.")
        return False

    DIST_DIR = frontend / "dist"
    if (DIST_DIR / "index.html").is_file():
        print(f"Website found: {DIST_DIR}")
        return True

    print(f"Website build not found at {DIST_DIR}. Building it now...")
    if subprocess.run("npm --version", shell=True, capture_output=True).returncode != 0:
        print("Node.js (npm) is needed to build the website. Install Node.js 20+ from https://nodejs.org,")
        print("then run this again.")
        return False
    if not (frontend / "node_modules").is_dir():
        print("Installing frontend packages (first run only, this can take a minute)...")
        if subprocess.run("npm install", shell=True, cwd=frontend).returncode != 0:
            print("npm install failed. See the errors above.")
            return False
    print("Running 'npm run build'...")
    if subprocess.run("npm run build", shell=True, cwd=frontend).returncode != 0:
        print("npm run build failed. See the errors above.")
        return False
    if (DIST_DIR / "index.html").is_file():
        print(f"Website built: {DIST_DIR}")
        return True
    print("Build finished but frontend/dist/index.html was not created.")
    return False


def main():
    init_db()
    try:
        server = ThreadingHTTPServer(("0.0.0.0", PORT), CIRSHandler)
    except OSError as error:
        raise SystemExit(f"Could not start on port {PORT}: {error}. Is another program using it?")
    server.daemon_threads = True
    print(f"CIRS is running at http://localhost:{PORT}")
    if not ensure_frontend_build():
        print("The API will still run, but the website cannot be shown until the build succeeds.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCIRS stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
