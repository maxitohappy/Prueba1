import re
import sqlite3

from conftest import csrf_from, login, register

GOOD_PASSWORD = "NubeSantiago42x"


def db_rows(app, sql, params=()):
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def test_password_is_stored_with_argon2(app, client):
    register(client, "ana", GOOD_PASSWORD)
    stored = db_rows(app, "SELECT password FROM users WHERE username = 'ana'")[0]["password"]
    assert stored.startswith("$argon2id$")
    assert GOOD_PASSWORD not in stored


def test_weak_passwords_are_rejected(app, client):
    for weak in ["corta1", "solamenteletras", "123456789012", "ana-segura-123"]:
        register(client, "ana", weak)
    assert db_rows(app, "SELECT * FROM users WHERE username = 'ana'") == []


def test_login_and_weather_requires_session(client):
    assert client.get("/clima").status_code == 302
    register(client, "ana", GOOD_PASSWORD)
    assert login(client, "ana", GOOD_PASSWORD).status_code == 302
    assert client.get("/clima").status_code == 200


def test_sql_injection_does_not_bypass_login(client):
    resp = login(client, "admin' --", "cualquiera")
    assert resp.status_code == 401
    assert client.get("/clima").status_code == 302


def test_error_message_does_not_reveal_existing_users(client):
    unknown = login(client, "no-existe", "x").get_data(as_text=True)
    wrong = login(client, "admin", "x").get_data(as_text=True)
    assert "incorrectos" in unknown and "incorrectos" in wrong
    assert "no existe" not in unknown


def test_account_locks_after_five_failures(app, client):
    register(client, "ana", GOOD_PASSWORD)
    for _ in range(5):
        login(client, "ana", "mala-clave")
    row = db_rows(app, "SELECT locked_until FROM users WHERE username = 'ana'")[0]
    assert row["locked_until"] is not None
    # Ni siquiera la contraseña correcta funciona mientras está bloqueada
    assert login(client, "ana", GOOD_PASSWORD).status_code == 401


def test_admin_can_unlock_account(app, client):
    register(client, "ana", GOOD_PASSWORD)
    for _ in range(5):
        login(client, "ana", "mala-clave")
    login(client, "admin", "AdminSeguro2026x")
    ana_id = db_rows(app, "SELECT id FROM users WHERE username = 'ana'")[0]["id"]
    client.post(f"/admin/usuarios/{ana_id}/desbloquear")
    client.post("/logout")
    assert login(client, "ana", GOOD_PASSWORD).status_code == 302


def test_normal_user_cannot_access_admin_even_with_role_cookie(client):
    register(client, "ana", GOOD_PASSWORD)
    login(client, "ana", GOOD_PASSWORD)
    client.set_cookie("role", "admin")
    assert client.get("/admin").status_code == 403
    assert client.post("/admin/usuarios/2/rol", data={"role": "admin"}).status_code == 403


def test_admin_can_access_admin_panel(client):
    login(client, "admin", "AdminSeguro2026x")
    assert client.get("/admin").status_code == 200


def test_user_cannot_view_other_profiles(client):
    register(client, "ana", GOOD_PASSWORD)
    login(client, "ana", GOOD_PASSWORD)
    assert client.get("/perfil/1").status_code == 403  # perfil del admin
    assert client.get("/perfil/2").status_code == 200  # el suyo


def test_xss_in_username_is_rejected(app, client):
    register(client, "<script>alert(1)</script>", GOOD_PASSWORD)
    assert len(db_rows(app, "SELECT * FROM users")) == 1  # solo el admin


def _request_reset(app, client, caplog, username="ana"):
    with caplog.at_level("WARNING"):
        client.post("/recuperar", data={"username": username})
    match = re.search(r"/restablecer/(\S+)", caplog.text)
    return match.group(1) if match else None


def test_password_reset_token_is_single_use(app, client, caplog):
    register(client, "ana", GOOD_PASSWORD)
    token = _request_reset(app, client, caplog)
    assert token and len(token) >= 40
    stored = db_rows(app, "SELECT token FROM reset_tokens")[0]["token"]
    assert stored != token  # se guarda el hash, no el token

    new = "OtraClaveSegura99"
    resp = client.post(f"/restablecer/{token}", data={"password": new, "password2": new})
    assert resp.status_code == 302
    assert login(client, "ana", new).status_code == 302
    # Segundo uso del mismo enlace: rechazado
    assert client.get(f"/restablecer/{token}").headers["Location"].endswith("/recuperar")


def test_password_reset_token_expires(app, client, caplog):
    register(client, "ana", GOOD_PASSWORD)
    token = _request_reset(app, client, caplog)
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.execute("UPDATE reset_tokens SET expires_at = '2000-01-01T00:00:00+00:00'")
    conn.commit()
    conn.close()
    assert client.get(f"/restablecer/{token}").headers["Location"].endswith("/recuperar")


def test_forgot_password_same_message_for_unknown_user(client, caplog):
    resp = client.post("/recuperar", data={"username": "no-existe"}, follow_redirects=True)
    assert "Si el usuario existe" in resp.get_data(as_text=True)


def test_csrf_token_is_required(make_app):
    client = make_app(RATELIMIT_ENABLED=False).test_client()
    assert login(client, "admin", "AdminSeguro2026x").status_code == 400
    token = csrf_from(client.get("/login").get_data(as_text=True))
    resp = client.post("/login", data={"username": "admin", "password": "AdminSeguro2026x",
                                       "csrf_token": token})
    assert resp.status_code == 302


def test_login_rate_limit(make_app):
    client = make_app(WTF_CSRF_ENABLED=False).test_client()
    codes = [login(client, f"u{i}", "x").status_code for i in range(11)]
    assert codes[-1] == 429


def test_security_headers(client):
    headers = client.get("/login").headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_session_cookie_is_httponly(client):
    login(client, "admin", "AdminSeguro2026x")
    cookie = client.get_cookie("session")
    assert cookie is not None and cookie.http_only
