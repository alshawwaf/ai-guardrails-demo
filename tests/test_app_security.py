"""Security regression tests for the Flask app (spec section 7).

All credentials here are random values generated at test time. No test talks
to the network: outbound HTTP is replaced with fakes via monkeypatch.
"""

import base64
import csv
import html
import io
import json
import logging
import os
import re
import secrets
import stat
import sys
import time
import types
import uuid

import pytest
import requests
from flask import Flask
from werkzeug.security import generate_password_hash

PUBLIC_ENDPOINTS = {"login", "static", "health", "health_check"}
SECRET_FIELDS = {
    "api_key": "DEMO_API_KEY",
    "openai_api_key": "OPENAI_API_KEY",
    "azure_openai_api_key": "AZURE_OPENAI_API_KEY",
    "gemini_api_key": "GEMINI_API_KEY",
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "azure_cs_key": "AZURE_CONTENT_SAFETY_KEY",
}
GUARD_URL_DEFAULT = "https://api.lakera.ai/v2/guard"


def fake_key(prefix="test"):
    return "%s-%s" % (prefix, secrets.token_hex(12))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload if payload is not None else {})
        self.headers = {"Content-Type": "application/json"}

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON")
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError("%s error" % self.status_code)


class RecordingPost:
    """Stand-in for requests.post: records calls, answers from a routing function."""

    def __init__(self, router):
        self.calls = []
        self.router = router

    def __call__(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return self.router(url, kwargs)

    def urls(self):
        return [c["url"] for c in self.calls]


@pytest.fixture
def clean_settings(app_module):
    """Empty Settings table before and after a test."""

    def _wipe():
        with app_module.app.app_context():
            app_module.db.create_all()
            app_module.Settings.query.delete()
            app_module.db.session.commit()

    _wipe()
    yield
    _wipe()


@pytest.fixture
def pre_upgrade_install(app_module, monkeypatch, tmp_path):
    """An install whose saved settings were never upgraded (no instance/.settings_format)."""
    marker = tmp_path / ".settings_format"
    monkeypatch.setattr(app_module, "SETTINGS_FORMAT_PATH", str(marker))
    return marker


@pytest.fixture
def no_model_lists(app_module, monkeypatch):
    """Settings/playground pages must not try to reach model providers."""
    monkeypatch.setattr(app_module, "get_gemini_models", lambda: [])
    monkeypatch.setattr(app_module, "get_ollama_models", lambda: [])
    monkeypatch.setattr(app_module, "get_available_models", lambda key: [])
    monkeypatch.setattr(app_module, "get_anthropic_models", lambda key: [])


def _url_for_rule(rule):
    return re.sub(r"<(?:[^:<>]+:)?([^<>]+)>", "x", rule.rule)


# ---------------------------------------------------------------------------
# 7.1 Auth gate
# ---------------------------------------------------------------------------


def test_every_route_requires_login(app_module, client):
    """Unauthenticated GET/POST/... to every route: 401 JSON for APIs, 302 to /login for pages."""
    # A row that DELETE /api/logs would remove if the gate let it through.
    marker = "gate-marker-" + uuid.uuid4().hex
    with app_module.app.app_context():
        app_module.save_log_to_db(
            {"id": str(uuid.uuid4()), "timestamp": "2026-01-01 00:00:00", "prompt": marker}
        )

    checked = 0
    for rule in app_module.app.url_map.iter_rules():
        if rule.endpoint in PUBLIC_ENDPOINTS:
            continue
        path = _url_for_rule(rule)
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            response = client.open(path, method=method)
            checked += 1
            if app_module.is_api_path(path):
                assert response.status_code == 401, (method, path, response.status_code)
                assert response.get_json() == {"error": "Sign in required"}, (method, path)
            else:
                assert response.status_code == 302, (method, path, response.status_code)
                assert response.headers["Location"].endswith("/login"), (method, path)
    assert checked >= 25  # the app has ~30 routes; guard against an empty url_map

    with app_module.app.app_context():
        assert app_module.Log.query.filter_by(prompt=marker).count() == 1


@pytest.mark.parametrize(
    "path",
    ["/api/does-not-exist", "/gateway/api/status", "/apispec_1.json", "/api/settings"],
)
def test_api_paths_get_json_401(client, path):
    response = client.get(path)
    assert response.status_code == 401
    assert response.get_json() == {"error": "Sign in required"}


def test_unknown_page_redirects_to_login(client):
    response = client.get("/no-such-page")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_public_endpoints_stay_open(client):
    assert client.get("/health").status_code == 200
    assert client.get("/login").status_code == 200
    assert client.get("/static/css/main.css").status_code == 200


def test_preflight_options_passes_without_data(client):
    response = client.open(
        "/api/settings",
        method="OPTIONS",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert response.status_code == 200
    assert response.get_data() == b""
    assert "Access-Control-Allow-Origin" not in response.headers
    # A plain OPTIONS (not a preflight) goes through the gate.
    assert client.open("/api/settings", method="OPTIONS").status_code == 401


def test_logged_in_client_reaches_api(logged_in_client):
    assert logged_in_client.get("/api/settings").status_code == 200


# ---------------------------------------------------------------------------
# 7.1 / 7.2b Login
# ---------------------------------------------------------------------------


def _assert_not_signed_in(client):
    assert client.get("/api/settings").status_code == 401


def test_login_bypass_with_unset_credentials_fails(client, monkeypatch):
    monkeypatch.delenv("DEFAULT_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("DEFAULT_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("DEFAULT_ADMIN_PASSWORD_HASH", raising=False)
    response = client.post("/login", data={})
    assert response.status_code != 302
    _assert_not_signed_in(client)
    response = client.post("/login", data={"email": "", "password": ""})
    assert response.status_code != 302
    assert b"DEFAULT_ADMIN" in response.data
    _assert_not_signed_in(client)


def test_login_bypass_with_empty_env_values_fails(client, monkeypatch):
    monkeypatch.setenv("DEFAULT_ADMIN_EMAIL", "")
    monkeypatch.setenv("DEFAULT_ADMIN_PASSWORD", "")
    for form in ({}, {"email": "", "password": ""}, {"email": "a@b.c"}):
        response = client.post("/login", data=form)
        assert response.status_code != 302
    _assert_not_signed_in(client)


def test_missing_form_fields_rejected(client):
    for form in ({}, {"email": os.environ["DEFAULT_ADMIN_EMAIL"]}, {"password": os.environ["DEFAULT_ADMIN_PASSWORD"]}):
        response = client.post("/login", data=form)
        assert response.status_code == 400
        assert b"Enter your email and password." in response.data
    _assert_not_signed_in(client)


@pytest.mark.parametrize("placeholder", ["change_me_please", "set-me"])
def test_default_password_refused(client, monkeypatch, placeholder):
    monkeypatch.setenv("DEFAULT_ADMIN_PASSWORD", placeholder)
    response = client.post(
        "/login", data={"email": os.environ["DEFAULT_ADMIN_EMAIL"], "password": placeholder}
    )
    assert response.status_code == 503
    assert (
        b"Set DEFAULT_ADMIN_PASSWORD (or DEFAULT_ADMIN_PASSWORD_HASH) in .env before signing in."
        in response.data
    )
    _assert_not_signed_in(client)
    # The login page explains why sign-in is disabled.
    assert b"Sign-in is disabled" in client.get("/login").data


def test_wrong_password_rejected(client, admin_credentials):
    response = client.post(
        "/login", data={"email": admin_credentials["email"], "password": admin_credentials["password"] + "x"}
    )
    assert response.status_code == 401
    assert b"Invalid email or password." in response.data
    _assert_not_signed_in(client)


def test_correct_password_signs_in(client, admin_credentials):
    response = client.post("/login", data=admin_credentials)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/playground")
    assert client.get("/api/settings").status_code == 200


def test_password_hash_supported(client, monkeypatch):
    password = secrets.token_urlsafe(16)
    monkeypatch.setenv("DEFAULT_ADMIN_PASSWORD_HASH", generate_password_hash(password))
    monkeypatch.delenv("DEFAULT_ADMIN_PASSWORD", raising=False)
    email = os.environ["DEFAULT_ADMIN_EMAIL"]
    assert client.post("/login", data={"email": email, "password": "wrong-" + password}).status_code == 401
    response = client.post("/login", data={"email": email, "password": password})
    assert response.status_code == 302


def test_login_is_rate_limited(client, admin_credentials):
    statuses = [
        client.post("/login", data={"email": admin_credentials["email"], "password": "nope"}).status_code
        for _ in range(11)
    ]
    assert statuses[:10] == [401] * 10
    assert statuses[10] == 429


def test_logout_ends_session(logged_in_client):
    assert logged_in_client.get("/logout").status_code == 302
    _assert_not_signed_in(logged_in_client)


# ---------------------------------------------------------------------------
# 7.1 Secret key, cookies, debug
# ---------------------------------------------------------------------------


def test_secret_key_from_env_used(app_module):
    assert app_module.app.secret_key == os.environ["FLASK_SECRET_KEY"]


@pytest.mark.parametrize("env_value", [None, "", "dev_secret_key", "change_this_to_a_random_secret_string",
                                       "set-me"])
def test_placeholder_secret_key_replaced_by_file(app_module, tmp_path, env_value):
    key, source = app_module.resolve_secret_key(env_value, str(tmp_path))
    assert source == "generated"
    assert re.fullmatch(r"[0-9a-f]{64}", key)
    path = tmp_path / ".flask_secret"
    assert path.read_text().strip() == key
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # A second worker reads the same key.
    again, source2 = app_module.resolve_secret_key(env_value, str(tmp_path))
    assert (again, source2) == (key, "file")


def test_cookie_flags(app_module, client, admin_credentials):
    cfg = app_module.app.config
    assert cfg["SESSION_COOKIE_HTTPONLY"] is True
    assert cfg["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert cfg["REMEMBER_COOKIE_HTTPONLY"] is True
    assert cfg["REMEMBER_COOKIE_SAMESITE"] == "Lax"
    assert cfg["SESSION_COOKIE_SECURE"] is False  # SESSION_COOKIE_SECURE unset -> lab http default
    response = client.post("/login", data=admin_credentials)
    cookie = response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_debug_off_by_default(app_module, monkeypatch):
    monkeypatch.delenv("FLASK_DEBUG", raising=False)
    assert app_module.debug_enabled() is False
    assert app_module.app.debug is False
    for value, expected in (("1", True), ("true", True), ("TRUE", True), ("0", False), ("yes", False), ("", False)):
        monkeypatch.setenv("FLASK_DEBUG", value)
        assert app_module.debug_enabled() is expected, value


def test_app_run_uses_debug_gate():
    source = open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "app.py"), encoding="utf-8").read()
    assert "debug=True" not in source
    assert "app.run(debug=debug_enabled()" in source


# ---------------------------------------------------------------------------
# 7.1 Same-origin and CORS
# ---------------------------------------------------------------------------


VALID_BENCHMARK = {"prompt": "hello", "results": [{"vendor": "AI Guardrails", "flagged": False, "details": ["ok"]}]}


def test_wrong_origin_post_forbidden(logged_in_client):
    response = logged_in_client.post(
        "/api/benchmark/log", json=VALID_BENCHMARK, headers={"Origin": "https://evil.example"}
    )
    assert response.status_code == 403
    response = logged_in_client.post(
        "/api/benchmark/log", json=VALID_BENCHMARK, headers={"Referer": "https://evil.example/page"}
    )
    assert response.status_code == 403
    response = logged_in_client.delete("/api/logs", headers={"Origin": "null"})
    assert response.status_code == 403
    # Same host but another port is another origin.
    response = logged_in_client.post(
        "/api/benchmark/log",
        json=VALID_BENCHMARK,
        headers={"Origin": "http://localhost:8081", "Host": "localhost:9000"},
    )
    assert response.status_code == 403


def test_same_origin_post_allowed(logged_in_client):
    response = logged_in_client.post(
        "/api/benchmark/log", json=VALID_BENCHMARK, headers={"Origin": "http://localhost"}
    )
    assert response.status_code == 200
    response = logged_in_client.post(
        "/api/benchmark/log",
        json=VALID_BENCHMARK,
        headers={"Origin": "http://localhost:9000", "Host": "localhost:9000"},
    )
    assert response.status_code == 200
    response = logged_in_client.post(
        "/api/benchmark/log", json=VALID_BENCHMARK, headers={"Referer": "http://localhost/benchmarking"}
    )
    assert response.status_code == 200


def test_cross_origin_login_post_forbidden(client, admin_credentials):
    response = client.post("/login", data=admin_credentials, headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    _assert_not_signed_in(client)


def test_cors_wildcard_ignored(app_module, logged_in_client):
    # conftest sets CORS_ORIGINS="*"
    assert os.environ["CORS_ORIGINS"] == "*"
    assert app_module.CORS_ALLOWED_ORIGINS == []
    response = logged_in_client.get("/api/settings", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in response.headers


def test_forwarded_headers_not_trusted_by_default(app_module):
    # TRUSTED_PROXY_HOPS is unset in tests: X-Forwarded-* must not change the client IP
    assert app_module.TRUSTED_PROXY_HOPS == 0
    assert type(app_module.app.wsgi_app).__name__ != "ProxyFix"
    with app_module.app.test_request_context(
            "/", environ_base={"REMOTE_ADDR": "10.9.9.9"},
            headers={"X-Forwarded-For": "203.0.113.9"}):
        from flask import request
        assert request.remote_addr == "10.9.9.9"


def test_parse_cors_origins(app_module):
    parse = app_module.parse_cors_origins
    assert parse("*") == []
    assert parse("") == []
    assert parse(" * , https://devhub.example.com/ ,http://LAB.test:8080") == [
        "https://devhub.example.com",
        "http://lab.test:8080",
    ]
    assert parse("javascript:alert(1), https://a.example/path, https://*.example") == []


def test_configure_cors_only_for_explicit_origins(app_module, monkeypatch):
    calls = []
    fake_cors = types.ModuleType("flask_cors")
    fake_cors.CORS = lambda flask_app, **kwargs: calls.append(kwargs)
    monkeypatch.setitem(sys.modules, "flask_cors", fake_cors)

    assert app_module.configure_cors(Flask("cors-star"), "*") == []
    assert calls == []
    assert app_module.configure_cors(Flask("cors-list"), "*,https://devhub.example.com") == [
        "https://devhub.example.com"
    ]
    # Every /api/* route needs the session cookie: listed origins get credentials.
    assert calls == [
        {"resources": {r"/api/*": {"origins": ["https://devhub.example.com"], "supports_credentials": True}}}
    ]


# ---------------------------------------------------------------------------
# 7.2 Secrets at rest and in responses
# ---------------------------------------------------------------------------


def test_secret_settings_stored_encrypted(app_module, clean_settings):
    value = fake_key("sk")
    with app_module.app.app_context():
        app_module.set_setting("OPENAI_API_KEY", value)
        app_module.set_setting("AZURE_OPENAI_ENDPOINT", "https://example.invalid")
        raw = app_module.db.session.get(app_module.Settings, "OPENAI_API_KEY").value
        assert raw.startswith("enc:v2:")  # bound to the setting name
        assert value not in raw
        assert app_module.get_setting("OPENAI_API_KEY") == value
        # Non-secret values stay readable; endpoints that receive a key carry an
        # integrity tag bound to their name.
        raw_endpoint = app_module.db.session.get(app_module.Settings, "AZURE_OPENAI_ENDPOINT").value
        assert raw_endpoint.startswith("mac:v1:") and raw_endpoint.endswith(":https://example.invalid")
        assert app_module.get_setting("AZURE_OPENAI_ENDPOINT") == "https://example.invalid"
        app_module.set_setting("DEMO_PROJECT_ID", "project-plain")
        assert app_module.db.session.get(app_module.Settings, "DEMO_PROJECT_ID").value == "project-plain"


def test_get_setting_outside_app_context(app_module, clean_settings):
    value = fake_key()
    app_module.set_setting("GEMINI_API_KEY", value)
    assert app_module.get_setting("GEMINI_API_KEY") == value


def test_startup_migration_encrypts_plaintext_rows(app_module, clean_settings, pre_upgrade_install):
    value = fake_key()
    with app_module.app.app_context():
        app_module.db.session.add(app_module.Settings(key="ANTHROPIC_API_KEY", value=value))
        app_module.db.session.add(app_module.Settings(key="OLLAMA_API_URL", value="http://127.0.0.1:9"))
        app_module.db.session.commit()
        assert app_module.migrate_plaintext_secrets() == 1
        raw = app_module.db.session.get(app_module.Settings, "ANTHROPIC_API_KEY").value
        assert raw.startswith("enc:v2:") and value not in raw
        assert app_module.get_setting("ANTHROPIC_API_KEY") == value
        assert app_module.db.session.get(app_module.Settings, "OLLAMA_API_URL").value == "http://127.0.0.1:9"
        assert app_module.migrate_plaintext_secrets() == 0


def test_undecryptable_value_treated_as_unset(app_module, clean_settings):
    with app_module.app.app_context():
        bogus = "enc:v1:%s:%s" % (
            base64.b64encode(os.urandom(12)).decode(),
            base64.b64encode(os.urandom(32)).decode(),
        )
        app_module.db.session.add(app_module.Settings(key="OPENAI_API_KEY", value=bogus))
        app_module.db.session.commit()
        assert app_module.get_setting("OPENAI_API_KEY", "fallback") == "fallback"


def test_api_settings_returns_no_secret_values(app_module, logged_in_client, clean_settings):
    values = {key: fake_key() for key in SECRET_FIELDS.values()}
    with app_module.app.app_context():
        for key, value in values.items():
            app_module.set_setting(key, value)
        app_module.set_setting("DEMO_PROJECT_ID", "project-" + secrets.token_hex(4))
        app_module.set_setting("AZURE_CONTENT_SAFETY_ENDPOINT", "https://cs.example.invalid")
    response = logged_in_client.get("/api/settings")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    for value in values.values():
        assert value not in body
    data = response.get_json()
    assert set(data) == {"guardrails_configured", "guardrails_key_configured", "azure_cs_configured",
                         "azure_configured", "project_id_set", "masked"}
    assert data["guardrails_configured"] is True
    assert data["guardrails_key_configured"] is True
    assert data["azure_cs_configured"] is True
    assert data["project_id_set"] is True
    assert isinstance(data["azure_configured"], bool)
    for key, value in values.items():
        assert data["masked"][key] == "****" + value[-4:]


def test_api_settings_when_nothing_configured(logged_in_client, clean_settings):
    data = logged_in_client.get("/api/settings").get_json()
    assert data["guardrails_configured"] is False
    assert data["guardrails_key_configured"] is False
    assert data["azure_cs_configured"] is False
    assert data["project_id_set"] is False
    assert all(v == "" for v in data["masked"].values())


def test_settings_page_never_renders_secrets(app_module, logged_in_client, clean_settings, no_model_lists):
    values = {field: fake_key() for field in SECRET_FIELDS}
    form = dict(values)
    form.update(
        {
            "project_id": "project-demo",
            "azure_openai_endpoint": "https://aoai.example.invalid",
            "azure_openai_deployment": "gpt-test",
            "ollama_api_url": "http://127.0.0.1:9",
            "ollama_timeout": "42",
            "azure_cs_endpoint": "https://cs.example.invalid",
        }
    )
    response = logged_in_client.post("/settings", data=form)
    assert response.status_code == 302
    page = logged_in_client.get("/settings?saved=1").get_data(as_text=True)
    for value in values.values():
        assert value not in page
        assert "Saved (****%s). Leave blank to keep." % value[-4:] in page
    # Non-secret fields stay prefilled.
    for plain in ("project-demo", "https://aoai.example.invalid", "gpt-test", "http://127.0.0.1:9", 'value="42"'):
        assert plain in page
    assert "Settings saved successfully" in page
    assert "Everything is stored encrypted" not in page
    for name in SECRET_FIELDS:
        assert 'name="clear_%s"' % name in page

    # Blank submit keeps every secret.
    blank = {field: "" for field in SECRET_FIELDS}
    assert logged_in_client.post("/settings", data=blank).status_code == 302
    with app_module.app.app_context():
        for field, key in SECRET_FIELDS.items():
            assert app_module.get_setting(key) == values[field]

    # Clear removes one saved key only.
    assert logged_in_client.post("/settings", data={"clear_openai_api_key": "1"}).status_code == 302
    with app_module.app.app_context():
        assert app_module.get_setting("OPENAI_API_KEY") is None
        assert app_module.get_setting("GEMINI_API_KEY") == values["gemini_api_key"]


def test_settings_validation_rejects_bad_input(app_module, logged_in_client, clean_settings, no_model_lists):
    response = logged_in_client.post(
        "/settings", data={"ollama_api_url": "file:///etc/passwd", "ollama_timeout": "abc", "api_key": fake_key()}
    )
    assert response.status_code == 400
    page = response.get_data(as_text=True)
    assert "Nothing was saved." in page
    with app_module.app.app_context():
        assert app_module.get_setting("DEMO_API_KEY") is None
        assert app_module.get_setting("OLLAMA_API_URL") is None


# ---------------------------------------------------------------------------
# 7.2b Analyze / Lakera guard
# ---------------------------------------------------------------------------


def test_analyze_missing_prompt_returns_400(logged_in_client):
    assert logged_in_client.post("/api/analyze", json={}).status_code == 400
    assert logged_in_client.post("/api/analyze", json={"prompt": ""}).status_code == 400
    assert logged_in_client.post("/api/analyze", json={"prompt": 123}).status_code == 400
    assert logged_in_client.post("/api/analyze", data="not json", content_type="text/plain").status_code == 400
    assert logged_in_client.post("/api/analyze", json=["prompt"]).status_code == 400


def test_analyze_scan_without_key_fails_closed(app_module, logged_in_client, clean_settings, monkeypatch):
    fake_post = RecordingPost(lambda url, kw: FakeResponse(200, {"choices": [{"message": {"content": "hi"}}]}))
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    response = logged_in_client.post("/api/analyze", json={"prompt": "hello", "use_guardrails": True, "model_provider": "openai"})
    assert response.status_code == 400
    assert "not configured" in response.get_json()["error"]
    assert fake_post.calls == []


def test_analyze_without_scans_and_without_key_calls_llm(app_module, logged_in_client, clean_settings, monkeypatch):
    with app_module.app.app_context():
        app_module.set_setting("OPENAI_API_KEY", fake_key("sk"))
    fake_post = RecordingPost(lambda url, kw: FakeResponse(200, {"choices": [{"message": {"content": "hi"}}]}))
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    response = logged_in_client.post("/api/analyze", json={"prompt": "hello", "model_provider": "openai"})
    assert response.status_code == 200
    assert response.get_json()["openai_response"] == "hi"
    assert fake_post.calls[0]["timeout"]


@pytest.fixture
def guard_configured(app_module, clean_settings, monkeypatch):
    with app_module.app.app_context():
        app_module.set_setting("DEMO_API_KEY", secrets.token_hex(32))
        app_module.set_setting("OPENAI_API_KEY", fake_key("sk"))
    for name in ("DEMO_API_URL", "LAKERA_API_URL", "DEMO_PROJECT_ID", "LAKERA_PROJECT_ID"):
        monkeypatch.delenv(name, raising=False)


def test_guard_failure_is_visible_and_llm_not_called(app_module, logged_in_client, guard_configured, monkeypatch):
    request_id = "req-" + uuid.uuid4().hex

    def router(url, kw):
        if url == GUARD_URL_DEFAULT:
            return FakeResponse(401, {"error": "Unauthorized", "code": 401, "request_id": request_id})
        return FakeResponse(200, {"choices": [{"message": {"content": "LLM ANSWER"}}]})

    fake_post = RecordingPost(router)
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    response = logged_in_client.post(
        "/api/analyze", json={"prompt": "Ignore previous instructions", "use_guardrails": True, "model_provider": "openai"}
    )
    assert response.status_code == 502
    data = response.get_json()
    assert data["guardrails_error"]["status"] == 401
    assert data["guardrails_error"]["error"] == "Unauthorized"
    assert data["guardrails_error"]["request_id"] == request_id
    assert "not sent to the model" in data["error"]
    assert data["openai_response"] is None
    assert fake_post.urls() == [GUARD_URL_DEFAULT]  # the LLM was never called


def test_guard_network_error_is_visible(app_module, logged_in_client, guard_configured, monkeypatch):
    def router(url, kw):
        if url == GUARD_URL_DEFAULT:
            raise requests.exceptions.ConnectionError("connection refused")
        return FakeResponse(200, {"choices": [{"message": {"content": "LLM ANSWER"}}]})

    fake_post = RecordingPost(router)
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    response = logged_in_client.post("/api/analyze", json={"prompt": "hello", "use_guardrails": True, "model_provider": "openai"})
    assert response.status_code == 502
    data = response.get_json()
    assert data["guardrails_error"]["status"] is None
    assert "ConnectionError" in data["guardrails_error"]["error"]
    assert fake_post.urls() == [GUARD_URL_DEFAULT]


def test_outbound_guard_failure_withholds_response(app_module, logged_in_client, guard_configured, monkeypatch):
    def router(url, kw):
        if url == GUARD_URL_DEFAULT:
            if kw["json"]["messages"][0]["role"] == "user":
                return FakeResponse(200, {"flagged": False, "breakdown": []})
            return FakeResponse(500, {"error": "Internal error", "code": 500, "request_id": "r-1"})
        return FakeResponse(200, {"choices": [{"message": {"content": "SECRET LLM ANSWER"}}]})

    monkeypatch.setattr(app_module.requests, "post", RecordingPost(router))
    response = logged_in_client.post(
        "/api/analyze",
        json={"prompt": "hello", "use_guardrails": True, "use_guardrails_outbound": True, "model_provider": "openai"},
    )
    assert response.status_code == 502
    data = response.get_json()
    assert data["guardrails_outbound_error"]["status"] == 500
    assert data["openai_response"] is None
    assert "SECRET LLM ANSWER" not in response.get_data(as_text=True)


def test_guard_success_flow_and_request_shape(app_module, logged_in_client, guard_configured, monkeypatch):
    def router(url, kw):
        if url == GUARD_URL_DEFAULT:
            return FakeResponse(200, {"flagged": False, "breakdown": [{"detector_type": "prompt_attack", "detected": False}]})
        return FakeResponse(200, {"choices": [{"message": {"content": "fine"}}]})

    fake_post = RecordingPost(router)
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    response = logged_in_client.post("/api/analyze", json={"prompt": "hello", "use_guardrails": True, "model_provider": "openai"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["guardrails_error"] is None
    assert data["openai_response"] == "fine"
    guard_call = fake_post.calls[0]
    assert "project_id" not in guard_call["json"]  # empty project id is omitted
    assert guard_call["json"]["breakdown"] is True
    for call in fake_post.calls:
        assert call.get("timeout"), call["url"]


def test_guard_sends_project_id_when_set(app_module, logged_in_client, guard_configured, monkeypatch):
    with app_module.app.app_context():
        app_module.set_setting("DEMO_PROJECT_ID", "project-abc")
    fake_post = RecordingPost(lambda url, kw: FakeResponse(200, {"flagged": True, "breakdown": []}))
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    response = logged_in_client.post("/api/analyze", json={"prompt": "hello", "use_guardrails": True})
    assert response.status_code == 200
    assert fake_post.calls[0]["json"]["project_id"] == "project-abc"
    assert len(fake_post.calls) == 1  # flagged: the LLM is not called


def test_guard_url_env_precedence(app_module, monkeypatch):
    monkeypatch.delenv("DEMO_API_URL", raising=False)
    monkeypatch.delenv("LAKERA_API_URL", raising=False)
    assert app_module.guard_api_url() == GUARD_URL_DEFAULT
    monkeypatch.setenv("LAKERA_API_URL", "https://eu.api.lakera.ai/v2/guard")
    assert app_module.guard_api_url() == "https://eu.api.lakera.ai/v2/guard"
    monkeypatch.setenv("DEMO_API_URL", "https://us.api.lakera.ai/v2/guard")
    assert app_module.guard_api_url() == "https://us.api.lakera.ai/v2/guard"


def test_analyze_uses_lakera_api_url(app_module, logged_in_client, guard_configured, monkeypatch):
    monkeypatch.setenv("LAKERA_API_URL", "https://eu.api.lakera.ai/v2/guard")
    fake_post = RecordingPost(lambda url, kw: FakeResponse(200, {"flagged": True, "breakdown": []}))
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    logged_in_client.post("/api/analyze", json={"prompt": "hello", "use_guardrails": True})
    assert fake_post.urls() == ["https://eu.api.lakera.ai/v2/guard"]


def test_ollama_uses_configured_timeout(app_module, logged_in_client, clean_settings, monkeypatch):
    with app_module.app.app_context():
        app_module.set_setting("OLLAMA_TIMEOUT", "7")
    fake_post = RecordingPost(lambda url, kw: FakeResponse(200, {"response": "local answer"}))
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    monkeypatch.setattr(app_module, "resolve_ollama_url", lambda: "http://127.0.0.1:9")
    response = logged_in_client.post("/api/analyze", json={"prompt": "hello", "model_provider": "ollama"})
    assert response.status_code == 200
    assert fake_post.calls[0]["timeout"] == 7


def test_ollama_timeout_bad_value_falls_back(app_module, clean_settings):
    with app_module.app.app_context():
        app_module.set_setting("OLLAMA_TIMEOUT", "not-a-number")
        assert app_module.ollama_timeout_seconds() == 120


# ---------------------------------------------------------------------------
# 7.3 Logging
# ---------------------------------------------------------------------------


def test_prompts_are_not_logged_in_full(app_module, logged_in_client, guard_configured, monkeypatch, caplog):
    marker = "UNIQUE-PROMPT-" + uuid.uuid4().hex
    prompt = "Please summarise this text. " + marker + " " + ("x" * 200)

    def router(url, kw):
        if url == GUARD_URL_DEFAULT:
            return FakeResponse(200, {"flagged": False, "breakdown": [{"detector_type": "pii/email", "detected": True}]})
        return FakeResponse(200, {"choices": [{"message": {"content": "answer\twith\ttabs"}}]})

    monkeypatch.setattr(app_module.requests, "post", RecordingPost(router))
    caplog.set_level(logging.INFO)
    response = logged_in_client.post(
        "/api/analyze",
        json={"prompt": prompt, "use_guardrails": True, "use_guardrails_outbound": True, "model_provider": "openai"},
    )
    assert response.status_code == 200
    messages = [r.getMessage() for r in caplog.records]
    assert messages, "expected log records"
    joined = "\n".join(messages)
    assert marker not in joined
    assert "sha256=" in joined
    # No tab-separated "Inbound:/Outbound:" lines that migrate_logs_from_file() would re-ingest.
    for message in messages:
        assert "\t" not in message
        assert not message.startswith(("Inbound:", "Outbound:"))


def test_clean_log_text_redacts_credentials(app_module):
    clean = app_module._clean_log_text
    key = "sk-" + secrets.token_hex(16)
    text = "Authorization: Bearer %s\tapi_key=%s url=https://x.test/?key=%s" % (key, key, key)
    out = clean(text)
    assert key not in out
    assert "\t" not in out
    assert len(clean("z" * 1000)) == 300


def test_prompt_fingerprint(app_module):
    fp = app_module.prompt_fingerprint("hello\tworld " + "y" * 100)
    assert fp.startswith("len=112 sha256=")
    assert "\t" not in fp
    assert "y" * 61 not in fp


# ---------------------------------------------------------------------------
# CSV export and /api/benchmark/log validation
# ---------------------------------------------------------------------------


def test_csv_formula_injection_escaped(app_module, logged_in_client):
    dangerous = ["=HYPERLINK(\"http://x\")", "+SUM(1,2)", "-2+3", "@cmd", "\tTAB", "\rCR"]
    tag = uuid.uuid4().hex[:8]
    with app_module.app.app_context():
        for i, prompt in enumerate(dangerous):
            app_module.save_log_to_db(
                {
                    "id": str(uuid.uuid4()),
                    "timestamp": "2026-02-0%d 10:00:00" % (i + 1),
                    "prompt": prompt + tag,
                    "attack_vectors": ["=evil" + tag],
                    "error": "-err" + tag,
                }
            )
    response = logged_in_client.get("/api/logs/export/csv")
    assert response.status_code == 200
    rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
    ours = [row for row in rows if row and row[1].endswith(tag)]
    assert len(ours) == len(dangerous)
    for row in ours:
        assert row[1].startswith("'"), row
        assert row[3] == "'=evil" + tag
        assert row[5] == "'-err" + tag
    assert app_module.csv_safe_cell("plain") == "plain"
    assert app_module.csv_safe_cell(None) == ""


@pytest.mark.parametrize(
    "payload",
    [
        {"prompt": "x" * 20001, "results": [{"flagged": False}]},
        {"prompt": "", "results": [{"flagged": False}]},
        {"prompt": 5, "results": [{"flagged": False}]},
        {"prompt": "ok", "results": "nope"},
        {"prompt": "ok", "results": []},
        {"prompt": "ok", "results": [{"flagged": False}] * 21},
        {"prompt": "ok", "results": ["not-an-object"]},
        {"prompt": "ok", "results": [{"details": ["x" * 201]}]},
        {"prompt": "ok", "results": [{"details": [{"html": "<img>"}]}]},
        {"prompt": "ok", "results": [{"details": "string"}]},
        {"prompt": "ok", "results": [{"flagged": "yes"}]},
        {"prompt": "ok", "results": [{"vendor": "v" * 101}]},
        {"prompt": "ok", "results": [{"score": "high"}]},
    ],
)
def test_benchmark_log_validation_rejects(logged_in_client, payload):
    response = logged_in_client.post("/api/benchmark/log", json=payload)
    assert response.status_code == 400, payload


def test_benchmark_log_accepts_valid(app_module, logged_in_client):
    prompt = "bench-" + uuid.uuid4().hex
    payload = {
        "prompt": prompt,
        "results": [
            {"vendor": "AI Guardrails", "flagged": True, "score": 100, "execution_time": 0.2, "details": ["⚠️ prompt attack"], "raw_response": {"flagged": True}},
            {"vendor": "Azure AI", "flagged": False, "details": ["Hate: 0"], "error": None},
        ],
    }
    response = logged_in_client.post("/api/benchmark/log", json=payload)
    assert response.status_code == 200
    with app_module.app.app_context():
        row = app_module.Log.query.filter_by(prompt=prompt).one()
        assert row.result_json["flagged"] is True
        assert len(row.result_json["results"]) == 2


# ---------------------------------------------------------------------------
# 7.4 Gateway wiring
# ---------------------------------------------------------------------------


def test_record_gateway_log_shows_in_logs_and_dashboard(app_module, logged_in_client):
    prompt = "gateway-" + uuid.uuid4().hex
    # Called the way a background job would: no app context.
    entry = app_module.record_gateway_log(
        {
            "prompt": prompt,
            "timestamp": "2026-09-30T12:00:00Z",
            "verdict": "BLOCKED",
            "category": "prompt_attack",
            "request": {"provider": "openai"},
        }
    )
    assert entry["source"] == "gateway"
    assert entry["result"]["flagged"] is True
    assert entry["attack_vectors"] == ["prompt_attack"]
    assert "results" not in entry["result"]
    assert app_module.analysis_logs[0]["id"] == entry["id"]
    with app_module.app.app_context():
        row = app_module.Log.query.filter_by(uuid=entry["id"]).one()
        assert row.prompt == prompt
        assert row.result_json["flagged"] is True
        assert row.result_json["source"] == "gateway"
        assert row.request_json["source"] == "gateway"
        assert row.attack_vectors == ["prompt_attack"]

    logs = logged_in_client.get("/api/logs?per_page=100").get_json()["logs"]
    assert any(item["id"] == entry["id"] for item in logs)


def test_record_gateway_log_analyze_shape(app_module):
    entry = app_module.record_gateway_log(
        {
            "id": str(uuid.uuid4()),
            "timestamp": "2026-09-30 12:00:00",
            "prompt": "allowed prompt",
            "result": {"flagged": False, "results": [{"x": 1}]},
            "attack_vectors": [],
        }
    )
    assert entry["timestamp"] == "2026-09-30 12:00:00"
    assert entry["result"]["flagged"] is False
    assert "results" not in entry["result"] and entry["result"]["probe_results"] == [{"x": 1}]


def test_gateway_mode_initialised_with_callbacks():
    source = open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "app.py"), encoding="utf-8").read()
    assert "from gateway_mode import init_gateway_mode" in source
    assert "init_gateway_mode(app, get_setting=get_setting, record_log=record_gateway_log)" in source


def test_security_headers(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "same-origin"


# ---------------------------------------------------------------------------
# secure_settings (AES-256-GCM at rest)
# ---------------------------------------------------------------------------


@pytest.fixture
def secure_settings_mod(app_module):
    import secure_settings

    yield secure_settings
    # Back to the app's configuration (key from SETTINGS_ENCRYPTION_KEY).
    secure_settings.configure(app_module.instance_dir)


def test_encrypt_roundtrip_and_format(secure_settings_mod):
    ss = secure_settings_mod
    value = fake_key("sk-ant")
    token = ss.encrypt(value)
    assert re.fullmatch(r"enc:v1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+", token)
    assert value not in token
    assert ss.decrypt(token) == value
    assert ss.encrypt(value) != token  # random nonce per value
    assert ss.encrypt(token) == token  # already encrypted: unchanged
    assert ss.decrypt("plain-value") == "plain-value"  # migration passthrough
    assert ss.decrypt("") == ""


def test_tampered_ciphertext_rejected(secure_settings_mod):
    ss = secure_settings_mod
    token = ss.encrypt("value-" + secrets.token_hex(8))
    prefix, nonce, ct = token.rsplit(":", 2)
    raw = bytearray(base64.b64decode(ct))
    raw[0] ^= 0x01
    tampered = "%s:%s:%s" % (prefix, nonce, base64.b64encode(bytes(raw)).decode())
    with pytest.raises(ss.SettingsDecryptError):
        ss.decrypt(tampered)
    with pytest.raises(ss.SettingsDecryptError):
        ss.decrypt("enc:v1:not base64:???")


def test_secret_key_classification(secure_settings_mod):
    ss = secure_settings_mod
    for key in (
        "DEMO_API_KEY", "OPENAI_API_KEY", "AZURE_OPENAI_API_KEY", "GEMINI_API_KEY",
        "ANTHROPIC_API_KEY", "AZURE_CONTENT_SAFETY_KEY", "MGMT_API_KEY", "SOME_KEY",
        "MGMT_PASSWORD", "CLIENT_SECRET", "SESSION_TOKEN",
    ):
        assert ss.is_secret_key(key), key
    for key in ("DEMO_PROJECT_ID", "OLLAMA_API_URL", "OLLAMA_TIMEOUT", "AZURE_OPENAI_ENDPOINT",
                "AZURE_OPENAI_DEPLOYMENT", "AZURE_CONTENT_SAFETY_ENDPOINT", "", None):
        assert not ss.is_secret_key(key), key


def test_mask(secure_settings_mod):
    ss = secure_settings_mod
    assert ss.mask("") == ""
    assert ss.mask(None) == ""
    assert ss.mask("short") == "****"
    assert ss.mask("abcdefghijkl") == "****ijkl"


def test_invalid_env_key_is_rejected(secure_settings_mod, monkeypatch, tmp_path):
    ss = secure_settings_mod
    for bad in ("not-base64!!", base64.b64encode(b"too short").decode()):
        monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", bad)
        ss.configure(tmp_path)
        with pytest.raises(ss.SettingsKeyError):
            ss.ensure_key()
    assert not (tmp_path / ".settings_key").exists()


def test_key_file_generated_with_0600(secure_settings_mod, monkeypatch, tmp_path):
    ss = secure_settings_mod
    monkeypatch.delenv("SETTINGS_ENCRYPTION_KEY", raising=False)
    ss.configure(tmp_path)
    token = ss.encrypt("hello")
    assert ss.key_source() == "generated"
    key_file = tmp_path / ".settings_key"
    assert len(base64.b64decode(key_file.read_text().strip())) == 32
    if os.name == "posix":
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    ss.configure(tmp_path)  # a new process / worker
    assert ss.ensure_key() == "file"
    assert ss.decrypt(token) == "hello"


def test_secret_file_creation_is_race_safe(secure_settings_mod, tmp_path):
    import threading

    ss = secure_settings_mod
    path = tmp_path / "shared" / ".flask_secret"
    results = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        results.append(ss.read_or_create_secret_file(path, lambda: secrets.token_hex(32))[0])

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(results)) == 1
    assert path.read_text().strip() == results[0]
    assert [p.name for p in path.parent.iterdir()] == [".flask_secret"]  # no temp files left


@pytest.mark.parametrize("path", ["/", "/playground", "/dashboard", "/logs", "/benchmarking", "/settings", "/apidocs/"])
def test_pages_render_when_signed_in(logged_in_client, no_model_lists, path):
    response = logged_in_client.get(path)
    assert response.status_code == 200, path


def test_login_page_redirects_when_signed_in(logged_in_client):
    response = logged_in_client.get("/login")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/playground")


def test_api_spec_requires_login(app_module):
    anonymous = app_module.app.test_client()
    assert anonymous.get("/apispec_1.json").status_code == 401
    app_module.limiter.reset()
    signed_in = app_module.app.test_client()
    signed_in.post(
        "/login",
        data={"email": os.environ["DEFAULT_ADMIN_EMAIL"], "password": os.environ["DEFAULT_ADMIN_PASSWORD"]},
    )
    assert signed_in.get("/apispec_1.json").status_code == 200


# ---------------------------------------------------------------------------
# Sign-out ends the Gateway Mode engine session; sign-in starts a fresh one
# ---------------------------------------------------------------------------


class _StubEngineLog:
    path = None
    jsonl_path = None

    def info(self, *args, **kwargs):
        return 0

    warn = error = debug = info


class _StubEngineSession:
    """Stands in for aiguard.engine.Session (logged in to the Management API)."""

    def __init__(self):
        self.log = _StubEngineLog()
        self.closed = 0

    def close(self):
        self.closed += 1


@pytest.fixture
def gateway_store(app_module, monkeypatch):
    from gateway_mode import store

    made = []

    def factory(*, home):
        session = _StubEngineSession()
        made.append(session)
        return session

    monkeypatch.setattr(store, "session_factory", factory)
    ctx = app_module.app.extensions["gateway_mode"]
    ctx.store.close_all()
    yield ctx, made
    ctx.store.close_all()


def _browser_id():
    return secrets.token_urlsafe(24)  # the shape gateway_mode gives session["gw_sid"]


def test_logout_closes_gateway_session_and_forgets_gw_sid(logged_in_client, gateway_store):
    ctx, made = gateway_store
    sid = _browser_id()
    with logged_in_client.session_transaction() as sess:
        sess["gw_sid"] = sid
    ctx.store.create(("admin", sid))
    assert ctx.store.count() == 1
    stolen_cookie = logged_in_client.get_cookie("session").value

    assert logged_in_client.get("/logout").status_code == 302
    assert ctx.store.count() == 0
    assert made[0].closed == 1  # Management API session logged out, keys dropped
    with logged_in_client.session_transaction() as sess:
        assert "gw_sid" not in sess and "_user_id" not in sess

    # A copy of the pre-sign-out cookie still signs in (client-side sessions),
    # but no engine session is left to attach to.
    logged_in_client.set_cookie("session", stolen_cookie)
    status = logged_in_client.get("/gateway/api/status")
    assert status.status_code == 200 and status.get_json()["connected"] is False
    assert ctx.store.count() == 0


def test_sign_in_never_inherits_an_old_gateway_session(client, admin_credentials, gateway_store):
    ctx, made = gateway_store
    sid = _browser_id()
    with client.session_transaction() as sess:
        sess["gw_sid"] = sid
        sess["left_over"] = "x"
    ctx.store.create(("admin", sid))
    assert client.post("/login", data=admin_credentials).status_code == 302
    with client.session_transaction() as sess:
        assert "gw_sid" not in sess and "left_over" not in sess
        assert sess.get("_user_id") == "admin"
    assert ctx.store.count() == 0 and made[0].closed == 1
    assert client.get("/gateway/api/status").get_json()["connected"] is False


def test_sign_out_waits_for_a_running_gateway_job(app_module, logged_in_client, gateway_store, monkeypatch):
    ctx, made = gateway_store
    sid = _browser_id()
    with logged_in_client.session_transaction() as sess:
        sess["gw_sid"] = sid
    ctx.store.create(("admin", sid))
    busy = {"flag": True}
    monkeypatch.setattr(ctx.jobs, "is_busy", lambda owner: busy["flag"] and owner == ("admin", sid))
    monkeypatch.setattr(app_module, "SIGNOUT_POLL_SECONDS", 0.01)

    assert logged_in_client.get("/logout").status_code == 302
    assert ctx.store.count() == 1 and made[0].closed == 0  # an install is not cut off
    with logged_in_client.session_transaction() as sess:
        assert "gw_sid" not in sess  # nobody can reattach to it meanwhile

    busy["flag"] = False
    deadline = time.monotonic() + 5
    while ctx.store.count() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ctx.store.count() == 0 and made[0].closed == 1


# ---------------------------------------------------------------------------
# Session signing key strength
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("weak", ["demo", "secret", "a" * 31])
def test_short_secret_key_replaced_by_file(app_module, tmp_path, weak):
    assert app_module.secret_key_problem(weak) == "short"
    key, source = app_module.resolve_secret_key(weak, str(tmp_path))
    assert source == "generated"
    assert key != weak and re.fullmatch(r"[0-9a-f]{64}", key)


def test_long_secret_key_from_env_accepted(app_module, tmp_path):
    for strong in (secrets.token_hex(32), secrets.token_urlsafe(24)):
        assert len(strong) >= app_module.MIN_SECRET_KEY_LENGTH
        assert app_module.secret_key_problem(strong) is None
        assert app_module.resolve_secret_key(strong, str(tmp_path)) == (strong, "env")
    assert not (tmp_path / ".flask_secret").exists()
    assert app_module.secret_key_problem("set-me") == "placeholder"
    assert app_module.secret_key_problem("") == "unset"


def test_proxy_fix_applies_trusted_forwarded_headers(app_module):
    probe = Flask("proxy-fix-probe")

    @probe.route("/")
    def _where():
        from flask import jsonify, request

        return jsonify(scheme=request.scheme, host=request.host, addr=request.remote_addr)

    assert app_module.apply_proxy_fix(probe, 0) is False
    assert app_module.apply_proxy_fix(probe, 1) is True
    response = probe.test_client().get(
        "/",
        environ_base={"REMOTE_ADDR": "10.0.0.2"},
        headers={"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https",
                 "X-Forwarded-Host": "demo.lab", "X-Forwarded-Port": "8443"},
    )
    assert response.get_json() == {"scheme": "https", "host": "demo.lab:8443", "addr": "203.0.113.9"}


@pytest.fixture
def behind_one_proxy(app_module, monkeypatch):
    """The real app as docker-compose.prod.yml runs it: TRUSTED_PROXY_HOPS=1 (ProxyFix)."""
    original = app_module.app.wsgi_app
    monkeypatch.setattr(app_module, "TRUSTED_PROXY_HOPS", 1)
    assert app_module.apply_proxy_fix(app_module.app, 1) is True
    try:
        yield app_module
    finally:
        app_module.app.wsgi_app = original


def test_login_limit_is_per_client_behind_one_trusted_proxy(behind_one_proxy, client):
    # Every request comes from the nginx container; nginx appends the client address to
    # X-Forwarded-For ($proxy_add_x_forwarded_for), after whatever the client sent.
    nginx = {"REMOTE_ADDR": "172.18.0.5"}
    bad = {"email": "nobody@example.com", "password": "wrong-" + secrets.token_hex(6)}

    def attempt(xff):
        return client.post("/login", data=bad, headers={"X-Forwarded-For": xff},
                           environ_base=nginx).status_code

    assert [attempt("forged, 198.51.100.1") for _ in range(10)] == [401] * 10
    assert attempt("forged, 198.51.100.1") == 429
    # A different forged first entry is ignored: still the same client, still limited.
    assert attempt("203.0.113.77, 198.51.100.1") == 429
    # Another client behind the same proxy has its own budget.
    assert attempt("198.51.100.2") == 401


def test_same_origin_uses_forwarded_host_with_port_behind_one_proxy(behind_one_proxy,
                                                                    logged_in_client):
    # nginx: proxy_set_header X-Forwarded-Host $http_host (host AND port the browser used).
    # (The Host header stays "localhost" so the test client sends the session cookie; the
    # app must judge the origin by the trusted X-Forwarded-Host, not by Host.)
    proxied = {"Host": "localhost", "X-Forwarded-Host": "demo.example:8080",
               "X-Forwarded-Proto": "http", "X-Forwarded-For": "198.51.100.3"}

    def post(origin):
        headers = dict(proxied, Origin=origin)
        return logged_in_client.post("/api/benchmark/log", json=VALID_BENCHMARK,
                                     headers=headers,
                                     environ_base={"REMOTE_ADDR": "172.18.0.5"}).status_code

    assert post("http://demo.example:8080") == 200
    for origin in ("http://demo.example", "https://demo.example:8080", "http://localhost",
                   "http://demo.example:8081"):
        assert post(origin) == 403, origin


# ---------------------------------------------------------------------------
# Same-origin check: scheme, host and port must all match
# ---------------------------------------------------------------------------


def _post_benchmark(client, **headers):
    return client.post("/api/benchmark/log", json=VALID_BENCHMARK, headers=headers).status_code


def test_other_port_or_scheme_refused_when_host_has_no_port(logged_in_client):
    # nginx sends "Host: $host" (no port): only the scheme's default port matches.
    for origin in ("http://localhost:8080", "http://localhost:9000", "https://localhost",
                   "https://localhost:8443", "http://localhost.evil.example"):
        assert _post_benchmark(logged_in_client, Origin=origin, Host="localhost") == 403, origin
    assert _post_benchmark(logged_in_client, Referer="http://localhost:8080/x", Host="localhost") == 403
    assert _post_benchmark(logged_in_client, Origin="http://localhost", Host="localhost") == 200
    assert _post_benchmark(logged_in_client, Origin="http://localhost:80", Host="localhost") == 200
    # A form post from another port of the same host cannot change Settings.
    response = logged_in_client.post(
        "/settings", data={"azure_cs_endpoint": "https://attacker.example"},
        headers={"Origin": "http://localhost:9000", "Host": "localhost"},
    )
    assert response.status_code == 403


def _same_origin(app_module, origin, headers):
    with app_module.app.test_request_context("/api/benchmark/log", method="POST", headers=headers):
        return app_module.origin_is_same(origin)


def test_forwarded_origin_compared_exactly(app_module):
    tls_proxy = {"Host": "demo.lab", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "demo.lab"}
    assert _same_origin(app_module, "https://demo.lab", tls_proxy)
    assert _same_origin(app_module, "https://demo.lab/settings?x=1", tls_proxy)  # a Referer
    for origin in ("http://demo.lab", "https://demo.lab:8443", "http://demo.lab:9000", "https://other.lab",
                   "null", "", "https://demo.lab.evil.example"):
        assert not _same_origin(app_module, origin, tls_proxy), origin
    port_proxy = {"Host": "demo.lab", "X-Forwarded-Proto": "https", "X-Forwarded-Port": "8443"}
    assert _same_origin(app_module, "https://demo.lab:8443", port_proxy)
    assert not _same_origin(app_module, "https://demo.lab", port_proxy)
    # Host with a port wins over a default; the scheme still has to match.
    assert _same_origin(app_module, "http://demo.lab:9000", {"Host": "demo.lab:9000"})
    assert not _same_origin(app_module, "https://demo.lab:9000", {"Host": "demo.lab:9000"})
    assert not _same_origin(app_module, "http://demo.lab:9001", {"Host": "demo.lab:9000"})


def test_forwarded_headers_left_to_proxy_fix_when_hops_are_set(app_module, monkeypatch):
    # With TRUSTED_PROXY_HOPS, ProxyFix (not the raw headers) supplies the origin.
    monkeypatch.setattr(app_module, "TRUSTED_PROXY_HOPS", 1)
    headers = {"Host": "demo.lab", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "other.lab"}
    assert _same_origin(app_module, "http://demo.lab", headers)
    assert not _same_origin(app_module, "https://other.lab", headers)


def test_app_origin_is_matched_exactly(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "APP_ORIGINS", app_module.parse_cors_origins("https://demo.example.com, *"))
    assert app_module.APP_ORIGINS == ["https://demo.example.com"]
    internal = {"Host": "web:9000"}
    assert _same_origin(app_module, "https://demo.example.com", internal)
    assert _same_origin(app_module, "https://demo.example.com:443", internal)
    assert not _same_origin(app_module, "https://demo.example.com:8443", internal)
    assert not _same_origin(app_module, "http://demo.example.com", internal)


# ---------------------------------------------------------------------------
# Settings at rest: name-bound ciphertext, authenticated endpoints, no
# plaintext left in the database file
# ---------------------------------------------------------------------------


def test_v2_ciphertext_is_bound_to_the_setting_name(secure_settings_mod):
    ss = secure_settings_mod
    value = fake_key("lk")
    token = ss.encrypt(value, "DEMO_API_KEY")
    assert re.fullmatch(r"enc:v2:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+", token)
    assert ss.is_bound(token) and ss.is_encrypted(token)
    assert value not in token
    assert ss.decrypt(token, "DEMO_API_KEY") == value
    for other in ("AZURE_OPENAI_API_KEY", "demo_api_key", None):
        with pytest.raises(ss.SettingsDecryptError):
            ss.decrypt(token, other)
    # The given text is always encrypted, even when it looks encrypted.
    nested = ss.encrypt(token, "OPENAI_API_KEY")
    assert nested != token and ss.decrypt(nested, "OPENAI_API_KEY") == token
    legacy = ss.encrypt(value)  # unbound enc:v1 (read only for the migration)
    assert ss.decrypt(legacy) == value
    with pytest.raises(ss.SettingsDecryptError):
        ss.decrypt(legacy, "DEMO_API_KEY", allow_v1=False)


def test_signed_values_detect_tampering(secure_settings_mod):
    ss = secure_settings_mod
    url = "https://aoai.example.invalid"
    signed = ss.sign("AZURE_OPENAI_ENDPOINT", url)
    assert signed.startswith("mac:v1:") and signed.endswith(":" + url)
    assert ss.is_signed(signed)
    assert ss.verify("AZURE_OPENAI_ENDPOINT", signed) == url
    for name, stored in (
        ("AZURE_CONTENT_SAFETY_ENDPOINT", signed),  # copied to another row
        ("AZURE_OPENAI_ENDPOINT", signed.replace("aoai.example.invalid", "evil.example")),
        ("AZURE_OPENAI_ENDPOINT", url),  # no tag
        ("AZURE_OPENAI_ENDPOINT", "mac:v1:not-base64!:" + url),
    ):
        with pytest.raises(ss.SettingsIntegrityError):
            ss.verify(name, stored)


def test_ciphertext_copied_to_another_setting_is_not_used(app_module, clean_settings):
    guard_key = fake_key("lk")
    with app_module.app.app_context():
        app_module.set_setting("DEMO_API_KEY", guard_key)
        raw = app_module.db.session.get(app_module.Settings, "DEMO_API_KEY").value
        app_module.db.session.add(app_module.Settings(key="AZURE_OPENAI_API_KEY", value=raw))
        app_module.db.session.commit()
        assert app_module.get_setting("DEMO_API_KEY") == guard_key
        assert app_module.get_setting("AZURE_OPENAI_API_KEY") is None


def test_endpoint_changed_in_the_database_is_not_used(app_module, logged_in_client, clean_settings, monkeypatch):
    with app_module.app.app_context():
        app_module.set_setting("AZURE_OPENAI_API_KEY", fake_key("az"))
        app_module.set_setting("AZURE_OPENAI_DEPLOYMENT", "gpt-test")
        app_module.set_setting("AZURE_OPENAI_ENDPOINT", "https://aoai.example.invalid")
        assert app_module.get_setting("AZURE_OPENAI_ENDPOINT") == "https://aoai.example.invalid"
        row = app_module.db.session.get(app_module.Settings, "AZURE_OPENAI_ENDPOINT")
        row.value = row.value.replace("aoai.example.invalid", "attacker.example")  # tag kept
        app_module.db.session.commit()
        assert app_module.get_setting("AZURE_OPENAI_ENDPOINT") is None
        row = app_module.db.session.get(app_module.Settings, "AZURE_OPENAI_ENDPOINT")
        row.value = "https://attacker.example"  # untagged
        app_module.db.session.commit()
        assert app_module.get_setting("AZURE_OPENAI_ENDPOINT") is None

    fake_post = RecordingPost(lambda url, kw: FakeResponse(200, {"choices": [{"message": {"content": "hi"}}]}))
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    response = logged_in_client.post("/api/analyze", json={"prompt": "hello", "model_provider": "azure"})
    assert response.status_code == 200
    assert response.get_json()["openai_response"] == "Azure OpenAI not configured."
    assert fake_post.calls == []  # the Azure key never went anywhere


def test_migration_upgrades_old_rows(app_module, clean_settings, pre_upgrade_install):
    ss = app_module.secure_settings
    value = fake_key()
    with app_module.app.app_context():
        app_module.db.session.add(app_module.Settings(key="GEMINI_API_KEY", value=ss.encrypt(value)))  # enc:v1
        app_module.db.session.add(
            app_module.Settings(key="AZURE_CONTENT_SAFETY_ENDPOINT", value="https://cs.example.invalid")
        )
        app_module.db.session.commit()
        # After the startup migration only the current formats are used.
        assert app_module.get_setting("GEMINI_API_KEY") is None
        assert app_module.get_setting("AZURE_CONTENT_SAFETY_ENDPOINT") is None

        assert app_module.migrate_plaintext_secrets() == 2
        raw = app_module.db.session.get(app_module.Settings, "GEMINI_API_KEY").value
        assert raw.startswith("enc:v2:")
        assert app_module.get_setting("GEMINI_API_KEY") == value
        raw = app_module.db.session.get(app_module.Settings, "AZURE_CONTENT_SAFETY_ENDPOINT").value
        assert raw.startswith("mac:v1:")
        assert app_module.get_setting("AZURE_CONTENT_SAFETY_ENDPOINT") == "https://cs.example.invalid"
        assert app_module.migrate_plaintext_secrets() == 0
    assert pre_upgrade_install.exists()  # the upgrade is recorded and never runs again


def test_upgrade_never_launders_rows_written_later(app_module, clean_settings, caplog):
    # This install already upgraded (conftest's instance dir has the marker). A
    # database write that copies an old enc:v1 Guard key into another key's row
    # and adds an untagged endpoint must stay ignored after a restart.
    ss = app_module.secure_settings
    assert os.path.isfile(app_module.SETTINGS_FORMAT_PATH)
    guard_key = fake_key("lk")
    with app_module.app.app_context():
        app_module.db.session.add(app_module.Settings(key="AZURE_OPENAI_API_KEY", value=ss.encrypt(guard_key)))
        app_module.db.session.add(app_module.Settings(key="AZURE_OPENAI_ENDPOINT", value="https://attacker.example"))
        app_module.db.session.add(app_module.Settings(key="OPENAI_API_KEY", value="sk-planted-" + secrets.token_hex(8)))
        app_module.db.session.commit()
        with caplog.at_level(logging.WARNING):
            assert app_module.migrate_plaintext_secrets() == 0  # "restart"
        for key in ("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT", "OPENAI_API_KEY"):
            raw = app_module.db.session.get(app_module.Settings, key).value
            assert not raw.startswith(("enc:v2:", "mac:v1:")), key
            assert app_module.get_setting(key) is None, key
    assert any("AZURE_OPENAI_ENDPOINT" in r.getMessage() and "Re-enter them" in r.getMessage()
               for r in caplog.records)


def test_migration_leaves_no_plaintext_in_the_database_file(app_module, clean_settings, pre_upgrade_install, caplog):
    from sqlalchemy import text

    markers = {
        key: "PLAINTEXT-MARKER-%s-%s" % (key, secrets.token_hex(16))
        for key in ("GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_CONTENT_SAFETY_KEY")
    }
    with app_module.app.app_context():
        # A row that is not touched between the secrets keeps their freed cells
        # apart, so SQLite cannot reuse (overwrite) them for the new values:
        # without secure_delete + VACUUM every marker stays in the file.
        for index, (key, value) in enumerate(markers.items()):
            app_module.db.session.add(app_module.Settings(key=key, value=value))
            app_module.db.session.commit()
            app_module.db.session.add(app_module.Settings(key="PAD_%d" % index, value="padding-" + "p" * 40))
            app_module.db.session.commit()
        with caplog.at_level(logging.WARNING):
            assert app_module.migrate_plaintext_secrets() == len(markers)
        for key, value in markers.items():
            assert app_module.get_setting(key) == value
        assert app_module.db.session.execute(text("PRAGMA secure_delete")).scalar() == 1
        path = app_module.db.engine.url.database
    data = open(path, "rb").read()
    for value in markers.values():
        assert value.encode("utf-8") not in data
    assert any("Rotate those keys" in r.getMessage() for r in caplog.records)
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


# ---------------------------------------------------------------------------
# Keyed endpoints: https only, in the form and where the key is used
# ---------------------------------------------------------------------------


def test_settings_refuse_http_for_keyed_endpoints(app_module, logged_in_client, clean_settings, no_model_lists):
    for field in ("azure_openai_endpoint", "azure_cs_endpoint"):
        response = logged_in_client.post("/settings", data={field: "http://contoso.cognitiveservices.azure.com"})
        assert response.status_code == 400, field
        assert "must be an https:// URL" in response.get_data(as_text=True)
    # A local model server (no key) may use http.
    assert logged_in_client.post("/settings", data={"ollama_api_url": "http://127.0.0.1:9"}).status_code == 302


def test_http_endpoint_never_receives_a_key(app_module, logged_in_client, clean_settings, no_model_lists, monkeypatch):
    with app_module.app.app_context():
        # As saved by an older version (set_setting skips the form's validation).
        app_module.set_setting("AZURE_CONTENT_SAFETY_KEY", fake_key("cs"))
        app_module.set_setting("AZURE_CONTENT_SAFETY_ENDPOINT", "http://cs.example.invalid")
        app_module.set_setting("AZURE_OPENAI_API_KEY", fake_key("az"))
        app_module.set_setting("AZURE_OPENAI_ENDPOINT", "http://aoai.example.invalid")
        app_module.set_setting("AZURE_OPENAI_DEPLOYMENT", "gpt-test")
    fake_post = RecordingPost(lambda url, kw: FakeResponse(200, {"choices": [{"message": {"content": "hi"}}]}))
    monkeypatch.setattr(app_module.requests, "post", fake_post)

    assert logged_in_client.post("/api/scan/azure", json={"prompt": "hello"}).status_code == 400
    response = logged_in_client.post("/api/analyze", json={"prompt": "hello", "model_provider": "azure"})
    assert response.get_json()["openai_response"] == "Azure OpenAI not configured."
    result = app_module.scan_with_azure("hello", {"endpoint": "http://cs.example.invalid", "key": "k" * 32})
    assert result["error"] == "Azure Content Safety not configured"
    assert fake_post.calls == []
    data = logged_in_client.get("/api/settings").get_json()
    assert data["azure_cs_configured"] is False and data["azure_configured"] is False
    page = logged_in_client.get("/settings").get_data(as_text=True)
    assert "is not an https:// URL, so it is not used" in page

    # Environment values are checked the same way.
    with app_module.app.app_context():
        app_module.delete_setting("AZURE_CONTENT_SAFETY_ENDPOINT")
    monkeypatch.setenv("AZURE_CONTENT_SAFETY_ENDPOINT", "http://cs-env.example.invalid")
    assert logged_in_client.post("/api/scan/azure", json={"prompt": "hello"}).status_code == 400
    assert fake_post.calls == []


# ---------------------------------------------------------------------------
# Settings form: a value the user did not touch never blocks "Save changes"
# ---------------------------------------------------------------------------


def _form_fields(page):
    """name -> value of every text/number/password input of the rendered form."""
    fields = {}
    for tag in re.findall(r"<input\b[^>]*>", page):
        name = re.search(r'name="([^"]+)"', tag)
        if not name or 'type="checkbox"' in tag:
            continue
        value = re.search(r'value="([^"]*)"', tag)
        fields[html.unescape(name.group(1))] = html.unescape(value.group(1)) if value else ""
    return fields


def test_saved_out_of_range_timeout_does_not_block_saving(app_module, logged_in_client, clean_settings, no_model_lists):
    with app_module.app.app_context():
        app_module.set_setting("OLLAMA_TIMEOUT", "7200")  # accepted by older versions
    page = logged_in_client.get("/settings").get_data(as_text=True)
    assert 'name="ollama_timeout" value="3600"' in page  # clamped, as used at run time
    assert "outside 1-3600 s; 3600 s is used" in page
    form = _form_fields(page)
    new_key = fake_key("lk")
    form["api_key"] = new_key
    response = logged_in_client.post("/settings", data=form)
    assert response.status_code == 302
    with app_module.app.app_context():
        assert app_module.get_setting("DEMO_API_KEY") == new_key
        assert app_module.get_setting("OLLAMA_TIMEOUT") == "3600"


def test_unchanged_invalid_value_does_not_block_saving(app_module, logged_in_client, clean_settings, no_model_lists, monkeypatch):
    monkeypatch.setenv("AZURE_CONTENT_SAFETY_ENDPOINT", "http://cs-env.example.invalid")
    monkeypatch.setenv("OLLAMA_TIMEOUT", "7200")
    page = logged_in_client.get("/settings").get_data(as_text=True)
    form = _form_fields(page)
    assert form["azure_cs_endpoint"] == "http://cs-env.example.invalid"
    new_key = fake_key("lk")
    form["api_key"] = new_key
    assert logged_in_client.post("/settings", data=form).status_code == 302
    with app_module.app.app_context():
        assert app_module.get_setting("DEMO_API_KEY") == new_key
        assert app_module.get_setting("AZURE_CONTENT_SAFETY_ENDPOINT") is None  # not copied into the DB
    # A value the user changed is still validated.
    form["azure_cs_endpoint"] = "http://other.example.invalid"
    response = logged_in_client.post("/settings", data=form)
    assert response.status_code == 400
    assert "Nothing was saved." in response.get_data(as_text=True)


def test_settings_page_shows_hidden_invalid_fields():
    source = open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "js", "pages",
                               "settings.js"), encoding="utf-8").read()
    assert 'addEventListener("invalid"' in source and "closest(\".sp-pane\")" in source


def test_api_settings_reports_a_key_only_guard(app_module, logged_in_client, clean_settings, monkeypatch):
    for name in ("DEMO_PROJECT_ID", "LAKERA_PROJECT_ID"):
        monkeypatch.delenv(name, raising=False)
    with app_module.app.app_context():
        app_module.set_setting("DEMO_API_KEY", fake_key("lk"))
    data = logged_in_client.get("/api/settings").get_json()
    assert data["guardrails_key_configured"] is True
    assert data["guardrails_configured"] is False  # key and project ID
    assert data["project_id_set"] is False


# ---------------------------------------------------------------------------
# Content-Security-Policy and third-party scripts
# ---------------------------------------------------------------------------


def _csp(response):
    header = response.headers.get("Content-Security-Policy", "")
    out = {}
    for directive in header.split(";"):
        parts = directive.strip().split(None, 1)
        if parts:
            out[parts[0]] = parts[1] if len(parts) > 1 else ""
    return out


INLINE_SCRIPT = re.compile(r"<script\b(?![^>]*\bsrc=)(?![^>]*type=\"application/json\")[^>]*>", re.I)
INLINE_HANDLER = re.compile(r"<[^>]+\son[a-z]+\s*=", re.I)


def _assert_first_party_scripts_only(response, path):
    assert response.status_code == 200, path
    page = response.get_data(as_text=True)
    assert "cdn.jsdelivr.net" not in page, path
    assert re.findall(r'<script[^>]+src="https?://', page) == [], path
    csp = _csp(response)
    assert csp.get("script-src") == "'self'", (path, csp)
    assert csp.get("object-src") == "'none'" and csp.get("base-uri") == "'self'"


def test_credential_pages_load_no_third_party_script(logged_in_client, no_model_lists, gateway_store):
    for path in ("/settings", "/gateway/connect", "/gateway/configure"):
        _assert_first_party_scripts_only(logged_in_client.get(path), path)


def test_login_page_loads_no_third_party_script(client):
    _assert_first_party_scripts_only(client.get("/login"), "/login")


def test_chart_pages_allow_only_the_pinned_chartjs(app_module, logged_in_client, no_model_lists):
    url = app_module.CHARTJS_CDN_URL
    assert re.fullmatch(r"https://cdn\.jsdelivr\.net/npm/chart\.js@\d+\.\d+\.\d+/dist/[\w.]+\.js", url)
    vendored = app_module.chartjs_vendored()
    for path in ("/", "/playground", "/dashboard", "/benchmarking"):
        response = logged_in_client.get(path)
        assert response.status_code == 200, path
        page = response.get_data(as_text=True)
        csp = _csp(response)
        if vendored:
            assert "/static/vendor/chart.umd.js" in page and csp["script-src"] == "'self'"
        else:
            assert 'src="%s"' % url in page, path
            assert csp["script-src"] == "'self' " + url, path


@pytest.mark.parametrize("path", ["/", "/playground", "/dashboard", "/logs", "/benchmarking", "/settings",
                                  "/gateway/connect", "/gateway/configure", "/gateway/demo"])
def test_pages_have_no_inline_scripts(logged_in_client, no_model_lists, gateway_store, path):
    response = logged_in_client.get(path)
    assert response.status_code == 200, path
    page = response.get_data(as_text=True)
    assert not INLINE_SCRIPT.search(page), (path, INLINE_SCRIPT.search(page).group(0))
    assert not INLINE_HANDLER.search(page), (path, INLINE_HANDLER.search(page).group(0))


def test_playground_page_data_is_a_json_block(logged_in_client, no_model_lists, clean_settings, monkeypatch):
    nasty = "</script><script>alert(1)</script>"
    monkeypatch.setenv("DEFAULT_LLM_MODEL", nasty)
    page = logged_in_client.get("/playground").get_data(as_text=True)
    assert nasty not in page
    match = re.search(r'<script type="application/json" id="playground-data">(.*?)</script>', page, re.S)
    data = json.loads(match.group(1))
    assert set(data["llmData"]) == {"openai", "azure", "gemini", "anthropic", "ollama"}
    assert data["defaultModel"] == nasty


# ---------------------------------------------------------------------------
# Front end: failures are shown as failures, an ended session goes to /login
# ---------------------------------------------------------------------------


def _js(relative):
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "js", relative)
    return open(path, encoding="utf-8").read()


def _js_function(source, signature):
    body = source.split(signature, 1)[1]
    return re.split(r"\n(?:export )?function |\n  function ", body, maxsplit=1)[0]


def test_frontend_redirects_to_login_on_401():
    utils = _js("shared/utils.js")
    api_fetch = _js_function(utils, "export async function apiFetch")
    assert "response.status === 401" in api_fetch and "redirectToLogin()" in api_fetch
    assert 'window.location.assign("/login")' in utils
    for page in ("pages/dashboard.js", "pages/logs.js", "pages/playground.js", "pages/benchmarking.js"):
        source = _js(page)
        assert "apiFetch(" in source, page
        assert not re.search(r"(?<![\w.])fetch\(", source), page  # every API call goes through apiFetch
    dashboard = _js("pages/dashboard.js")
    assert "if (!response.ok" in _js_function(dashboard, "async function loadAnalytics")
    assert "if (!response.ok" in _js_function(_js("pages/logs.js"), "async function loadLogs")


def test_frontend_never_shows_a_failed_scan_as_safe():
    feed = _js_function(_js("pages/dashboard.js"), "function updateFeed")
    assert "log.error" in feed and "guardrails_error" in feed and '"Scan failed"' in feed
    stages = _js_function(_js("shared/pipeline.js"), "export function scanToStages")
    assert "data.guardrails_outbound_error" in stages
    display = _js_function(_js("shared/traffic-flow.js"), "export function displayResults")
    assert "data.guardrails_outbound_error" in display and '"Outbound Scan Failed"' in display
    assert "data.request_failed" in display
    assert "request_failed: !response.ok" in _js("pages/playground.js")


def test_benchmark_counts_a_key_only_guard_as_configured():
    steps = _js_function(_js("pages/benchmarking.js"), "function resetProgressSteps")
    assert "guardrails_key_configured" in steps
    assert "config.guardrails_configured" not in steps

