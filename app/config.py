import os
import secrets

# VULN (solo modo vulnerable): clave secreta escrita en el código. Cualquiera que lea
# el repositorio puede firmar cookies de sesión falsas. Bandit la detecta (B105).
VULN_SECRET_KEY = "super-secreto-123"


def load_config(app):
    mode = os.environ.get("APP_MODE", "secure").lower()
    if mode not in ("secure", "vulnerable"):
        raise ValueError("APP_MODE debe ser 'secure' o 'vulnerable'")

    app.config["APP_MODE"] = mode
    app.config["DATABASE"] = os.environ.get("DATABASE", f"/data/{mode}.db")

    if mode == "vulnerable":
        app.config.update(
            SECRET_KEY=VULN_SECRET_KEY,
            SESSION_COOKIE_HTTPONLY=False,  # VULN: JavaScript (y un XSS) puede leer la cookie
            SESSION_COOKIE_SAMESITE=None,
            SESSION_COOKIE_SECURE=False,
            RATELIMIT_ENABLED=False,  # VULN: sin límite de intentos
        )
    else:
        # La clave se lee de una variable de entorno (archivo .env, nunca en git).
        # Si falta, se genera una aleatoria: las sesiones se pierden al reiniciar.
        secret = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
        app.config.update(
            SECRET_KEY=secret,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE="Lax",
            # En local usamos http, así que Secure=False. Con HTTPS pon SESSION_COOKIE_SECURE=1.
            SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
            PERMANENT_SESSION_LIFETIME=1800,  # 30 minutos
            RATELIMIT_ENABLED=True,
        )

    # Política de bloqueo (solo se aplica en modo seguro)
    app.config["MAX_FAILED_ATTEMPTS"] = 5
    app.config["LOCKOUT_MINUTES"] = 15
    app.config["RESET_TOKEN_MINUTES"] = 15
