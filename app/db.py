import hashlib
import os
import secrets
import sqlite3

from flask import current_app, g

from .passwords import hash_password

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password        TEXT NOT NULL,          -- hash Argon2 (seguro) o MD5 (vulnerable)
    role            TEXT NOT NULL DEFAULT 'user',
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT                    -- fecha ISO UTC o NULL
);
CREATE TABLE IF NOT EXISTS reset_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    token      TEXT NOT NULL,               -- SHA-256 del token (seguro) o token en claro (vulnerable)
    expires_at TEXT,
    used       INTEGER NOT NULL DEFAULT 0
);
"""


def get_db():
    if "db" not in g:
        path = current_app.config["DATABASE"]
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        g.db = sqlite3.connect(path)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_app(app):
    app.teardown_appcontext(close_db)


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        _seed_users(conn)
    conn.commit()


def _seed_users(conn):
    log = current_app.logger
    if current_app.config["APP_MODE"] == "vulnerable":
        # VULN: credenciales por defecto conocidas y hash MD5 sin sal.
        for username, password, role in [
            ("admin", "admin123", "admin"),
            ("maria", "princesa", "user"),
        ]:
            md5 = hashlib.md5(password.encode()).hexdigest()
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, md5, role),
            )
        log.warning("Modo VULNERABLE: usuarios de ejemplo admin/admin123 y maria/princesa")
    else:
        password = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(16)
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')",
            ("admin", hash_password(password)),
        )
        if not os.environ.get("ADMIN_PASSWORD"):
            log.warning("Usuario 'admin' creado con contraseña aleatoria: %s", password)
