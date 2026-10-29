"""Modo SEGURO: cada ruta aplica la defensa que falta en auth_vulnerable.py."""
import hashlib
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import (Blueprint, abort, current_app, flash, g, redirect, render_template,
                   request, session, url_for)

from .db import get_db
from .decorators import login_required, role_required
from .extensions import limiter
from .passwords import (DUMMY_HASH, hash_password, needs_rehash, password_problems,
                        verify_password)
from .weather import get_santiago_weather

bp = Blueprint("auth", __name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
GENERIC_LOGIN_ERROR = "Usuario o contraseña incorrectos, o cuenta bloqueada temporalmente."


def _now():
    return datetime.now(timezone.utc)


def _sha256(value):
    return hashlib.sha256(value.encode()).hexdigest()


@bp.before_app_request
def load_user():
    # El usuario y su ROL se leen siempre de la base de datos, nunca de una cookie editable.
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


@bp.route("/")
def index():
    return redirect(url_for("auth.weather" if g.user else "auth.login"))


@bp.route("/registro", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        problems = []
        if not USERNAME_RE.match(username):
            problems.append("El usuario debe tener 3-30 caracteres: letras, números, _ . -")
        problems += password_problems(password, username)
        if password != request.form.get("password2", ""):
            problems.append("Las contraseñas no coinciden.")
        if not problems:
            db = get_db()
            try:
                # Consulta parametrizada (?): los datos nunca se mezclan con el SQL.
                db.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, hash_password(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                problems.append("No se pudo crear la cuenta con ese nombre de usuario.")
            else:
                flash("Cuenta creada. Ya puedes iniciar sesión.", "ok")
                return redirect(url_for("auth.login"))
        for p in problems:
            flash(p, "error")
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user is None:
            verify_password(DUMMY_HASH, password)  # mismo tiempo de respuesta
            flash(GENERIC_LOGIN_ERROR, "error")
            return render_template("login.html"), 401

        if user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > _now():
            current_app.logger.warning("Intento de login en cuenta bloqueada: %s", username)
            flash(GENERIC_LOGIN_ERROR, "error")
            return render_template("login.html"), 401

        if not verify_password(user["password"], password):
            attempts = user["failed_attempts"] + 1
            locked_until = None
            if attempts >= current_app.config["MAX_FAILED_ATTEMPTS"]:
                minutes = current_app.config["LOCKOUT_MINUTES"]
                locked_until = (_now() + timedelta(minutes=minutes)).isoformat()
                attempts = 0
                current_app.logger.warning("Cuenta bloqueada por intentos fallidos: %s", username)
            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            db.commit()
            flash(GENERIC_LOGIN_ERROR, "error")
            return render_template("login.html"), 401

        # Login correcto
        if needs_rehash(user["password"]):
            db.execute("UPDATE users SET password = ? WHERE id = ?",
                       (hash_password(password), user["id"]))
        db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                   (user["id"],))
        db.commit()
        session.clear()  # evita "session fixation"
        session.permanent = True
        session["user_id"] = user["id"]
        return redirect(url_for("auth.weather"))
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/clima")
@login_required
def weather():
    return render_template("weather.html", weather=get_santiago_weather())


@bp.route("/perfil/<int:user_id>")
@login_required
def profile(user_id):
    # Control de acceso: solo el propio usuario o un admin pueden ver un perfil.
    if g.user["id"] != user_id and g.user["role"] != "admin":
        abort(403)
    user = get_db().execute("SELECT id, username, role FROM users WHERE id = ?",
                            (user_id,)).fetchone()
    if user is None:
        abort(404)
    return render_template("profile.html", profile=user)


@bp.route("/admin")
@role_required("admin")
def admin():
    users = get_db().execute(
        "SELECT id, username, role, failed_attempts, locked_until FROM users ORDER BY id"
    ).fetchall()
    return render_template("admin.html", users=users)


@bp.route("/admin/usuarios/<int:user_id>/desbloquear", methods=["POST"])
@role_required("admin")
def unlock(user_id):
    db = get_db()
    db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
               (user_id,))
    db.commit()
    flash("Cuenta desbloqueada.", "ok")
    return redirect(url_for("auth.admin"))


@bp.route("/admin/usuarios/<int:user_id>/rol", methods=["POST"])
@role_required("admin")
def change_role(user_id):
    role = request.form.get("role")
    if role not in ("user", "admin"):  # lista blanca de valores permitidos
        abort(400)
    if user_id == g.user["id"]:
        flash("No puedes cambiar tu propio rol.", "error")
        return redirect(url_for("auth.admin"))
    db = get_db()
    db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    db.commit()
    current_app.logger.info("Admin %s cambió el rol del usuario %s a %s",
                            g.user["username"], user_id, role)
    flash("Rol actualizado.", "ok")
    return redirect(url_for("auth.admin"))


@bp.route("/recuperar", methods=["GET", "POST"])
@limiter.limit("3 per minute", methods=["POST"])
def forgot():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        db = get_db()
        user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if user:
            token = secrets.token_urlsafe(32)  # aleatorio criptográficamente seguro
            expires = _now() + timedelta(minutes=current_app.config["RESET_TOKEN_MINUTES"])
            # Invalida tokens anteriores y guarda solo el HASH del nuevo token.
            db.execute("UPDATE reset_tokens SET used = 1 WHERE user_id = ?", (user["id"],))
            db.execute(
                "INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
                (user["id"], _sha256(token), expires.isoformat()),
            )
            db.commit()
            link = url_for("auth.reset", token=token, _external=True)
            # Simulación de email: en una app real esto se enviaría por correo.
            current_app.logger.warning("[EMAIL SIMULADO] Enlace de recuperación para %s: %s",
                                       username, link)
        # Mismo mensaje exista o no el usuario (evita enumeración).
        flash("Si el usuario existe, se envió un enlace de recuperación "
              "(revisa los logs del contenedor).", "ok")
        return redirect(url_for("auth.login"))
    return render_template("forgot.html")


@bp.route("/restablecer/<token>", methods=["GET", "POST"])
def reset(token):
    db = get_db()
    row = db.execute(
        "SELECT t.id, t.user_id, t.expires_at, u.username FROM reset_tokens t "
        "JOIN users u ON u.id = t.user_id WHERE t.token = ? AND t.used = 0",
        (_sha256(token),),
    ).fetchone()
    if row is None or datetime.fromisoformat(row["expires_at"]) < _now():
        flash("El enlace no es válido o expiró.", "error")
        return redirect(url_for("auth.forgot"))

    if request.method == "POST":
        password = request.form.get("password", "")
        problems = password_problems(password, row["username"])
        if password != request.form.get("password2", ""):
            problems.append("Las contraseñas no coinciden.")
        if not problems:
            db.execute(
                "UPDATE users SET password = ?, failed_attempts = 0, locked_until = NULL "
                "WHERE id = ?",
                (hash_password(password), row["user_id"]),
            )
            db.execute("UPDATE reset_tokens SET used = 1 WHERE id = ?", (row["id"],))
            db.commit()
            flash("Contraseña actualizada. Inicia sesión.", "ok")
            return redirect(url_for("auth.login"))
        for p in problems:
            flash(p, "error")
    return render_template("reset.html")
