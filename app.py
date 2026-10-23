import os
import hmac
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "secureburn.db")
# Configure SECRET_KEY as an environment variable when deploying.
SERVER_SECRET = os.environ.get("SECRET_KEY", "LOCAL-DEVELOPMENT-ONLY-change-before-deploy").encode()


def utc_now():
    return datetime.now(timezone.utc)


def connect_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                ciphertext TEXT NOT NULL,
                iv TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                payload_hmac TEXT NOT NULL,
                created_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            )
        """)


def sign_payload(message_id, ciphertext, iv, expires_at):
    payload = f"{message_id}|{ciphertext}|{iv}|{expires_at}".encode("utf-8")
    return hmac.new(SERVER_SECRET, payload, hashlib.sha256).hexdigest()


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    return response


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/m/<message_id>")
def message_page(message_id):
    return render_template("view_message.html", message_id=message_id)


@app.post("/api/messages")
def create_message():
    data = request.get_json(silent=True) or {}
    ciphertext = data.get("ciphertext", "")
    iv = data.get("iv", "")
    token = data.get("token", "")
    try:
        minutes = int(data.get("expires_minutes", 60))
    except (TypeError, ValueError):
        return jsonify(error="Choose a valid expiry period."), 400

    if not all(isinstance(x, str) for x in (ciphertext, iv, token)):
        return jsonify(error="Invalid request format."), 400
    if not ciphertext or len(ciphertext) > 1_500_000 or not iv:
        return jsonify(error="Message data is missing or too large."), 400
    if len(token) < 20 or len(token) > 200:
        return jsonify(error="Invalid access token."), 400
    if minutes not in (5, 15, 30, 60, 360, 1440):
        return jsonify(error="Choose one of the available expiry periods."), 400

    message_id = secrets.token_urlsafe(12)
    now = utc_now()
    expires_at = (now + timedelta(minutes=minutes)).isoformat()
    created_at = now.isoformat()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    signature = sign_payload(message_id, ciphertext, iv, expires_at)

    with connect_db() as conn:
        conn.execute("""
            INSERT INTO messages
            (id, ciphertext, iv, expires_at, token_hash, payload_hmac, created_at, used)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
        """, (message_id, ciphertext, iv, expires_at, token_hash, signature, created_at))

    return jsonify(message_id=message_id, expires_at=expires_at), 201


@app.get("/api/messages/<message_id>")
def get_message(message_id):
    token = request.headers.get("X-Message-Token", "")
    if not token:
        return jsonify(error="The secret access token is missing."), 401

    # A write transaction prevents two simultaneous successful one-time reads.
    with connect_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()

        if row is None:
            conn.rollback()
            return jsonify(error="Message not found or already removed."), 404
        if row["used"]:
            conn.rollback()
            return jsonify(error="This message has already been opened."), 410

        try:
            expiry = datetime.fromisoformat(row["expires_at"])
        except ValueError:
            conn.rollback()
            return jsonify(error="Invalid expiry data."), 500

        if utc_now() >= expiry:
            conn.execute("DELETE FROM messages WHERE id = ?", (message_id,))
            conn.commit()
            return jsonify(error="This message has expired."), 410

        provided_hash = hashlib.sha256(token.encode()).hexdigest()
        if not hmac.compare_digest(provided_hash, row["token_hash"]):
            conn.rollback()
            return jsonify(error="Invalid access token."), 403

        expected_signature = sign_payload(
            message_id, row["ciphertext"], row["iv"], row["expires_at"]
        )
        if not hmac.compare_digest(expected_signature, row["payload_hmac"]):
            conn.rollback()
            return jsonify(error="Stored message integrity check failed."), 500

        conn.execute("UPDATE messages SET used = 1 WHERE id = ?", (message_id,))
        conn.commit()

    return jsonify(
        ciphertext=row["ciphertext"],
        iv=row["iv"],
        expires_at=row["expires_at"]
    )


@app.errorhandler(413)
def too_large(_error):
    return jsonify(error="Message is too large. Please shorten it."), 413


init_db()

if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", "5000")))
