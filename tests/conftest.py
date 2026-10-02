"""Shared pytest setup for the Flask app.

1. Stubs heavy optional modules (transformers, llm_guard, azure, google.genai,
   flasgger, flask_cors) with ``types.ModuleType`` ONLY when they are not
   installed, so ``import app`` works on a laptop without torch.
2. Points the app at throw-away locations and random credentials BEFORE any
   test module imports ``app`` (tests/test_migration.py imports it at
   collection time): DATABASE_URL, LOGS_DIR, INSTANCE_DIR, AIGUARD_HOME,
   FLASK_SECRET_KEY, SETTINGS_ENCRYPTION_KEY, DEFAULT_ADMIN_EMAIL/PASSWORD.
   All values are generated at runtime; nothing here is a real secret.
3. Fixtures: ``app_module``, ``client``, ``logged_in_client``,
   ``admin_credentials``.
"""

from __future__ import annotations

import atexit
import base64
import importlib.machinery
import importlib.util
import os
import secrets
import shutil
import sys
import tempfile
import types

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


# ---------------------------------------------------------------------------
# 1. Stubs for heavy optional dependencies
# ---------------------------------------------------------------------------

STUBBED_MODULES = []  # names stubbed in this run (for diagnostics)


def _is_missing(name):
    try:
        return importlib.util.find_spec(name) is None
    except (ImportError, ValueError):
        return True


def _stub(name, **attrs):
    """Create (or reuse) a stub module, link it to its parent package."""
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        module.__spec__ = importlib.machinery.ModuleSpec(name, loader=None, is_package=True)
        module.__path__ = []
        module.__file__ = "<test stub %s>" % name
        sys.modules[name] = module
        STUBBED_MODULES.append(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    parent_name, _, child = name.rpartition(".")
    if parent_name:
        parent = sys.modules.get(parent_name)
        if parent is None:
            try:
                parent = importlib.import_module(parent_name)
            except ImportError:
                parent = _stub(parent_name)
        setattr(parent, child, module)
    return module


def _unavailable(what):
    def _raise(*_args, **_kwargs):
        raise RuntimeError("%s is not installed (test stub)" % what)

    return _raise


class _StubCallable:
    """Constructible placeholder that fails loudly if a test actually uses it."""

    _what = "dependency"

    def __init__(self, *args, **kwargs):
        raise RuntimeError("%s is not installed (test stub)" % self._what)


def _stub_class(qualname):
    return type(qualname.rsplit(".", 1)[-1], (_StubCallable,), {"_what": qualname})


def install_stubs():
    if _is_missing("transformers"):

        class AutoTokenizer:
            @classmethod
            def from_pretrained(cls, *args, **kwargs):
                raise RuntimeError("transformers is not installed (test stub)")

        class AutoModel(AutoTokenizer):
            pass

        _stub(
            "transformers",
            AutoTokenizer=AutoTokenizer,
            AutoModel=AutoModel,
            set_seed=lambda seed: None,
        )

    if _is_missing("google.genai"):
        _stub("google.genai", Client=_stub_class("google.genai.Client"))

    if _is_missing("flasgger"):

        class Swagger:
            """Registers the spec route like flasgger does (blueprint 'flasgger')."""

            def __init__(self, app=None, template=None, config=None, **kwargs):
                self.app = app
                self.template = template
                self.config = config or {}
                if app is not None:
                    self.init_app(app)

            def init_app(self, app):
                from flask import Blueprint, jsonify

                specs = self.config.get("specs") or [{}]
                blueprint = Blueprint("flasgger", __name__)
                for spec in specs:
                    blueprint.add_url_rule(
                        spec.get("route", "/apispec_1.json"),
                        spec.get("endpoint", "apispec_1"),
                        lambda: jsonify({"swagger": "2.0", "info": {}, "paths": {}}),
                    )
                app.register_blueprint(blueprint)

        _stub("flasgger", Swagger=Swagger)

    if _is_missing("flask_cors"):

        def CORS(app=None, *args, **kwargs):  # noqa: N802 - mirrors flask_cors.CORS
            return None

        _stub("flask_cors", CORS=CORS)

    if _is_missing("azure.ai.contentsafety"):
        _stub("azure")
        _stub("azure.ai")
        _stub(
            "azure.ai.contentsafety",
            ContentSafetyClient=_stub_class("azure.ai.contentsafety.ContentSafetyClient"),
        )
        _stub(
            "azure.ai.contentsafety.models",
            AnalyzeTextOptions=_stub_class("azure.ai.contentsafety.models.AnalyzeTextOptions"),
        )
    if _is_missing("azure.core"):
        _stub("azure")
        _stub("azure.core")
        _stub("azure.core.credentials", AzureKeyCredential=_stub_class("azure.core.credentials.AzureKeyCredential"))

        class HttpResponseError(Exception):
            pass

        _stub("azure.core.exceptions", HttpResponseError=HttpResponseError)

    if _is_missing("llm_guard"):
        _stub("llm_guard")
        _stub(
            "llm_guard.input_scanners",
            PromptInjection=_stub_class("llm_guard.input_scanners.PromptInjection"),
            Toxicity=_stub_class("llm_guard.input_scanners.Toxicity"),
            BanTopics=_stub_class("llm_guard.input_scanners.BanTopics"),
        )
        _stub("llm_guard.vault", Vault=_stub_class("llm_guard.vault.Vault"))
        _stub("llm_guard.model", Model=_stub_class("llm_guard.model.Model"))


install_stubs()


# ---------------------------------------------------------------------------
# 2. Isolated environment (set before anything imports app)
# ---------------------------------------------------------------------------

TEST_ROOT = tempfile.mkdtemp(prefix="aiguard-app-tests-")
atexit.register(shutil.rmtree, TEST_ROOT, True)

TEST_LOGS_DIR = os.path.join(TEST_ROOT, "logs")
TEST_INSTANCE_DIR = os.path.join(TEST_ROOT, "instance")
os.makedirs(TEST_LOGS_DIR, exist_ok=True)
os.makedirs(TEST_INSTANCE_DIR, exist_ok=True)

ADMIN_EMAIL = "test@example.com"
ADMIN_PASSWORD = secrets.token_urlsafe(18)

# Anything a developer shell or .env might carry that would change behaviour.
for _name in (
    "DB_PATH",
    "LOG_FILENAME",
    "FLASK_DEBUG",
    "SESSION_COOKIE_SECURE",
    "DEFAULT_ADMIN_PASSWORD_HASH",
    "DEMO_API_KEY",
    "LAKERA_API_KEY",
    "DEMO_PROJECT_ID",
    "LAKERA_PROJECT_ID",
    "DEMO_API_URL",
    "LAKERA_API_URL",
    "OPENAI_API_KEY",
    "OPENAI_API_URL",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_DEPLOYMENT",
    "GEMINI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AZURE_CONTENT_SAFETY_KEY",
    "AZURE_CONTENT_SAFETY_ENDPOINT",
    "DEFAULT_LLM_PROVIDER",
    "DEFAULT_LLM_MODEL",
    "AIGUARD_LOCAL_IP",
    "TRUSTED_PROXY_HOPS",
    # connection defaults a lab installer writes to .env (aiguard/envdefaults.py)
    "AIGUARD_MGMT_SERVER",
    "AIGUARD_MGMT_PORT",
    "AIGUARD_MGMT_SERVER_NAME",
    "AIGUARD_MGMT_TYPE",
    "AIGUARD_MGMT_DOMAIN",
    "AIGUARD_MGMT_CA_FILE",
    "AIGUARD_GATEWAY",
    "AIGUARD_MGMT_FINGERPRINT_SHA1",
):
    os.environ.pop(_name, None)

os.environ.update(
    {
        "PYTHON_DOTENV_DISABLED": "1",  # never read a developer's .env in tests
        "DATABASE_URL": "sqlite:///" + os.path.join(TEST_ROOT, "test_app.db").replace("\\", "/"),
        "LOGS_DIR": TEST_LOGS_DIR,
        "INSTANCE_DIR": TEST_INSTANCE_DIR,
        "AIGUARD_HOME": os.path.join(TEST_ROOT, "aiguard-home"),
        "FLASK_SECRET_KEY": secrets.token_hex(32),
        "SETTINGS_ENCRYPTION_KEY": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "DEFAULT_ADMIN_EMAIL": ADMIN_EMAIL,
        "DEFAULT_ADMIN_PASSWORD": ADMIN_PASSWORD,
        # "*" must be ignored by the app (tests/test_app_security.py checks it).
        "CORS_ORIGINS": "*",
        # Keep model-list lookups local and instant: port 9 on loopback refuses.
        "OLLAMA_API_URL": "http://127.0.0.1:9",
        "OLLAMA_CONTAINER_HOST": "127.0.0.1",
    }
)


# ---------------------------------------------------------------------------
# 3. Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def app_module():
    """The imported app.py module (imported lazily, after the env above)."""
    import app as app_module  # noqa: WPS433 - deliberate lazy import

    app_module.app.config["TESTING"] = True
    with app_module.app.app_context():
        app_module.db.create_all()
    return app_module


@pytest.fixture
def admin_credentials():
    return {"email": os.environ["DEFAULT_ADMIN_EMAIL"], "password": os.environ["DEFAULT_ADMIN_PASSWORD"]}


@pytest.fixture
def client(app_module):
    """Anonymous test client. Tables exist and the rate limiter starts empty."""
    with app_module.app.app_context():
        app_module.db.create_all()
    app_module.limiter.reset()
    with app_module.app.test_client() as test_client:
        yield test_client


@pytest.fixture
def logged_in_client(client, admin_credentials):
    """Test client signed in through the real /login form."""
    response = client.post("/login", data=admin_credentials)
    assert response.status_code == 302, "login fixture failed: HTTP %s" % response.status_code
    return client
