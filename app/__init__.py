"""Clima Santiago: laboratorio de usuarios, contraseñas y ciberseguridad.

La misma aplicación arranca en uno de dos modos según la variable APP_MODE:
  - secure      -> buenas prácticas (Argon2, CSRF, bloqueo, rate limit, cabeceras).
  - vulnerable  -> fallas INTENCIONALES para practicar ataques. Solo uso local.
"""
import logging

from flask import Flask, render_template
from markupsafe import Markup

from . import db
from .config import load_config
from .extensions import csrf, limiter


def create_app(overrides=None):
    app = Flask(__name__)
    load_config(app)
    if overrides:
        app.config.update(overrides)

    logging.basicConfig(level=logging.INFO)
    vulnerable = app.config["APP_MODE"] == "vulnerable"

    db.init_app(app)
    limiter.init_app(app)

    if vulnerable:
        from .auth_vulnerable import bp

        # VULN: sin CSRF. Definimos csrf_token() vacío para reutilizar las plantillas.
        app.jinja_env.globals["csrf_token"] = lambda: ""
    else:
        from .auth_secure import bp
        from flask_talisman import Talisman

        csrf.init_app(app)
        # Cabeceras de seguridad: CSP, X-Frame-Options, X-Content-Type-Options...
        Talisman(
            app,
            force_https=False,  # en local usamos http; en producción debe ser True
            session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
            content_security_policy={"default-src": "'self'"},
        )

    app.register_blueprint(bp)

    @app.context_processor
    def inject_mode():
        return {"vulnerable": vulnerable}

    @app.template_filter("nombre")
    def show_name(value):
        # VULN (modo vulnerable): Markup() marca el texto como "seguro" y Jinja deja de
        # escaparlo -> un nombre como <script>...</script> se ejecuta (XSS almacenado).
        # En modo seguro se devuelve tal cual y Jinja lo escapa automáticamente.
        return Markup(value) if vulnerable else value

    @app.errorhandler(429)
    def too_many_requests(e):
        return render_template("error.html", message="Demasiados intentos. Espera un momento."), 429

    with app.app_context():
        db.init_db()

    return app
