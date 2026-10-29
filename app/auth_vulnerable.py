"""Modo VULNERABLE: código con fallas INTENCIONALES para practicar.

!!! NO uses este código como ejemplo de cómo programar. !!!
Cada falla está marcada con "VULN:" y su corrección está en auth_secure.py.
Ejecuta este modo solo en tu computador (docker-compose lo publica en 127.0.0.1).
"""
import hashlib
import sqlite3
import time

from flask import (Blueprint, abort, current_app, flash, g, redirect, render_template,
                   request, session, url_for)

from .db import get_db
from .weather import get_santiago_weather

bp = Blueprint("auth", __name__)


def md5(text):
    # VULN: MD5 sin sal. Es rapidísimo de calcular -> fácil de romper con hashcat/john,
    # y dos usuarios con la misma clave tienen el mismo hash.
    return hashlib.md5(text.encode()).hexdigest()


@bp.before_app_request
def load_user():
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        row = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row:
            g.user = dict(row)
            # VULN: el rol se toma de una cookie que el usuario puede editar en su navegador.
            g.user["role"] = request.cookies.get("role", "user")


@bp.route("/")
def index():
    return redirect(url_for("auth.weather" if g.user else "auth.login"))


@bp.route("/registro", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # VULN: sin validar el nombre (permite HTML/JS -> XSS) ni la fortaleza de la clave.
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (username, md5(password)))
            db.commit()
        except sqlite3.IntegrityError:
            flash("El usuario ya existe.", "error")  # VULN: enumeración de usuarios
            return render_template("register.html")
        flash("Cuenta creada. Ya puedes iniciar sesión.", "ok")
        return redirect(url_for("auth.login"))
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    # VULN: sin límite de intentos ni bloqueo de cuenta -> fuerza bruta con Hydra.
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # VULN: inyección SQL. El texto del usuario se pega dentro de la consulta.
        # Prueba como usuario:   admin' --
        query = ("SELECT * FROM users WHERE username = '" + username +
                 "' AND password = '" + md5(password) + "'")
        current_app.logger.info("SQL ejecutado: %s", query)
        user = db.execute(query).fetchone()
        if user:
            session["user_id"] = user["id"]
            resp = redirect(url_for("auth.weather"))
            resp.set_cookie("role", user["role"])  # VULN: rol en cookie sin firmar
            return resp
        exists = db.execute("SELECT id FROM users WHERE username = '" + username + "'").fetchone()
        # VULN: mensajes distintos revelan qué usuarios existen.
        if exists:
            flash("Login fallido: contraseña incorrecta.", "error")
        else:
            flash("Login fallido: el usuario no existe.", "error")
        return render_template("login.html"), 401
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    resp = redirect(url_for("auth.login"))
    resp.delete_cookie("role")
    return resp


@bp.route("/clima")
def weather():
    if g.user is None:
        return redirect(url_for("auth.login"))
    return render_template("weather.html", weather=get_santiago_weather())


@bp.route("/perfil/<int:user_id>")
def profile(user_id):
    if g.user is None:
        return redirect(url_for("auth.login"))
    # VULN: IDOR. No se verifica que el perfil sea del usuario conectado;
    # cambiando el número en la URL ves a otros usuarios (¡y su hash!).
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        abort(404)
    return render_template("profile.html", profile=user)


def _is_admin():
    # VULN: la "seguridad" depende solo de la cookie 'role'.
    return request.cookies.get("role") == "admin"


@bp.route("/admin")
def admin():
    if not _is_admin():
        abort(403)
    users = get_db().execute("SELECT * FROM users ORDER BY id").fetchall()
    return render_template("admin.html", users=users)


@bp.route("/admin/usuarios/<int:user_id>/desbloquear", methods=["POST"])
def unlock(user_id):
    if not _is_admin():
        abort(403)
    db = get_db()
    db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
               (user_id,))
    db.commit()
    flash("Cuenta desbloqueada.", "ok")
    return redirect(url_for("auth.admin"))


# VULN: acepta GET y no tiene token CSRF -> un enlace malicioso puede cambiar roles.
@bp.route("/admin/usuarios/<int:user_id>/rol", methods=["GET", "POST"])
def change_role(user_id):
    if not _is_admin():
        abort(403)
    role = request.values.get("role", "user")
    db = get_db()
    db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    db.commit()
    flash("Rol actualizado.", "ok")
    return redirect(url_for("auth.admin"))


@bp.route("/recuperar", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        username = request.form.get("username", "")
        db = get_db()
        user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            flash("Ese usuario no existe.", "error")  # VULN: enumeración
            return render_template("forgot.html")
        # VULN: token predecible (segundos desde 1970), guardado en claro, sin expiración.
        token = str(int(time.time()))
        db.execute("INSERT INTO reset_tokens (user_id, token) VALUES (?, ?)",
                   (user["id"], token))
        db.commit()
        link = url_for("auth.reset", token=token, _external=True)
        current_app.logger.warning("[EMAIL SIMULADO] Enlace de recuperación para %s: %s",
                                   username, link)
        flash("Te enviamos un enlace de recuperación (revisa los logs del contenedor).", "ok")
        return redirect(url_for("auth.login"))
    return render_template("forgot.html")


@bp.route("/restablecer/<token>", methods=["GET", "POST"])
def reset(token):
    db = get_db()
    row = db.execute("SELECT user_id FROM reset_tokens WHERE token = ?", (token,)).fetchone()
    if row is None:
        flash("El enlace no es válido.", "error")
        return redirect(url_for("auth.forgot"))
    if request.method == "POST":
        db.execute("UPDATE users SET password = ? WHERE id = ?",
                   (md5(request.form.get("password", "")), row["user_id"]))
        db.commit()  # VULN: el token no se marca como usado: sirve infinitas veces.
        flash("Contraseña actualizada. Inicia sesión.", "ok")
        return redirect(url_for("auth.login"))
    return render_template("reset.html")
