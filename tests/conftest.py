import re

import pytest

from app import create_app
from app.extensions import limiter


@pytest.fixture
def make_app(tmp_path, monkeypatch):
    def factory(mode="secure", **overrides):
        monkeypatch.setenv("APP_MODE", mode)
        monkeypatch.setenv("ADMIN_PASSWORD", "AdminSeguro2026x")
        monkeypatch.setattr("app.weather.get_santiago_weather", lambda: None)
        config = {"TESTING": True, "DATABASE": str(tmp_path / f"{mode}.db")}
        config.update(overrides)
        app = create_app(config)
        if app.config["RATELIMIT_ENABLED"]:
            limiter.reset()  # el contador vive en memoria: lo limpiamos entre tests
        return app

    return factory


@pytest.fixture
def app(make_app):
    # CSRF y rate limit desactivados para probar la lógica; tienen sus propios tests.
    return make_app(WTF_CSRF_ENABLED=False, RATELIMIT_ENABLED=False)


@pytest.fixture
def client(app):
    return app.test_client()


def register(client, username, password):
    return client.post("/registro", data={"username": username, "password": password,
                                          "password2": password})


def login(client, username, password):
    return client.post("/login", data={"username": username, "password": password})


def csrf_from(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
