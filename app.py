from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    has_app_context,
    flash,
    redirect,
    session,
    url_for,
)
import requests
import os
import sys
import json
import hashlib
import hmac
import re
import secrets
import threading
import time
from datetime import datetime, timedelta
from urllib.parse import quote, urlsplit
from dotenv import load_dotenv
from werkzeug.security import check_password_hash
import transformers

# Force use of slow tokenizer to avoid OverflowError on Windows
_original_from_pretrained = transformers.AutoTokenizer.from_pretrained


def _patched_from_pretrained(*args, **kwargs):
    kwargs["use_fast"] = False
    return _original_from_pretrained(*args, **kwargs)


transformers.AutoTokenizer.from_pretrained = _patched_from_pretrained

import uuid
import logging
from flask_sqlalchemy import SQLAlchemy
from google import genai
import warnings
from flasgger import Swagger
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import traceback
import random
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
    fresh_login_required,
)

try:
    from transformers import set_seed

    set_seed(42)
except ImportError:
    pass

# --- Azure Content Safety Imports ---
import concurrent.futures
from azure.ai.contentsafety import ContentSafetyClient
from azure.core.credentials import AzureKeyCredential
from azure.core.exceptions import HttpResponseError

# --- LLM Guard Imports ---
from llm_guard.input_scanners import PromptInjection, Toxicity, BanTopics
from llm_guard.vault import Vault
from llm_guard.model import Model


# Suppress Google API warning about Python 3.10 support (EOL 2026)
warnings.filterwarnings("ignore", category=FutureWarning, module="google.api_core")

# Load environment variables
load_dotenv()

import secure_settings  # noqa: E402  (AES-256-GCM for secret Settings values)

basedir = os.path.abspath(os.path.dirname(__file__))
instance_dir = os.path.abspath(
    os.getenv("INSTANCE_DIR") or os.path.join(basedir, "instance")
)
# Owner-only when created here: it holds the session key, the settings key and
# the SQLite database (an existing directory's mode is left alone).
os.makedirs(instance_dir, mode=0o700, exist_ok=True)
secure_settings.configure(instance_dir)

# Configure Logging. This must run before anything calls logging.info() and
# friends: a module-level logging call on an unconfigured root logger installs
# a stderr handler, and basicConfig() below would then silently do nothing.
logs_dir = os.getenv("LOGS_DIR", "logs")
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

logging.basicConfig(
    filename=os.path.join(logs_dir, os.getenv("LOG_FILENAME", "application.log")),
    level=logging.INFO,
    format="%(asctime)s\t%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class _SingleLineLogFilter(logging.Filter):
    """Keep every message on one tab-free line.

    application.log doubles as the migration queue read by
    migrate_logs_from_file(): a line with two or more tabs is ingested as a
    Log row at the next start. Replacing tabs/newlines in messages means no
    logged text (user input, provider errors) can ever be re-ingested or forge
    extra log lines.
    """

    def filter(self, record):
        try:
            message = record.getMessage()
        except Exception:
            return True
        if "\t" in message or "\n" in message or "\r" in message:
            record.msg = message.replace("\t", " ").replace("\r", " ").replace("\n", " ")
            record.args = None
        return True


for _handler in logging.getLogger().handlers:
    _handler.addFilter(_SingleLineLogFilter())


def _startup_warning(message):
    """WARN once at startup, to application.log and stderr (container logs).

    Messages must never contain secret values or tab characters (tabs would
    make the line look like a migration record, see migrate_logs_from_file).
    """
    message = str(message).replace("\t", " ")
    logging.warning(message)
    try:
        sys.stderr.write("WARNING: %s\n" % message)
        sys.stderr.flush()
    except Exception:
        pass


def _env_int(name, default, minimum=None, maximum=None):
    """Integer env var with bounds; falls back to default on bad input."""
    raw = os.getenv(name)
    try:
        value = int(str(raw).strip()) if raw not in (None, "") else int(default)
    except (TypeError, ValueError):
        value = int(default)
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def env_flag(name, default=False):
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def debug_enabled():
    """Werkzeug debug mode only when FLASK_DEBUG is exactly '1' or 'true'."""
    return (os.getenv("FLASK_DEBUG") or "").strip().lower() in ("1", "true")


# Published placeholder values (.env.example, README) that must never be used.
PLACEHOLDER_SECRET_KEYS = frozenset(
    {"dev_secret_key", "change_this_to_a_random_secret_string", "set-me"}
)
PLACEHOLDER_PASSWORDS = frozenset({"change_me_please", "set-me"})
SECRET_KEY_FILENAME = ".flask_secret"
# Sessions are client-side signed cookies: a short key can be guessed offline
# (or online, one signed cookie per guess) and a session forged. 32 characters
# is about 128 bits for a random key; `secrets.token_hex(32)` gives 64.
MIN_SECRET_KEY_LENGTH = 32


def secret_key_problem(env_value):
    """None when FLASK_SECRET_KEY is usable, else 'unset', 'placeholder' or 'short'."""
    value = (env_value or "").strip()
    if not value:
        return "unset"
    if value in PLACEHOLDER_SECRET_KEYS:
        return "placeholder"
    if len(value) < MIN_SECRET_KEY_LENGTH:
        return "short"
    return None


def resolve_secret_key(env_value, instance_path):
    """Return (secret_key, source) with source 'env', 'file' or 'generated'.

    FLASK_SECRET_KEY wins unless it is empty, a published placeholder or
    shorter than MIN_SECRET_KEY_LENGTH; otherwise instance/.flask_secret (32
    random bytes, hex, mode 0600) is read, or created atomically so every
    gunicorn worker ends up with the same key.
    """
    value = (env_value or "").strip()
    if secret_key_problem(value) is None:
        return value, "env"
    try:
        key, created = secure_settings.read_or_create_secret_file(
            os.path.join(instance_path, SECRET_KEY_FILENAME),
            lambda: secrets.token_hex(32),
        )
    except OSError:
        # Read-only instance dir: a per-process random key (sessions end on restart).
        return secrets.token_hex(32), "ephemeral"
    return key, ("generated" if created else "file")


app = Flask(__name__, instance_path=instance_dir)

# Behind a reverse proxy (nginx, Traefik) the client address is in X-Forwarded-For.
# Trust exactly TRUSTED_PROXY_HOPS proxies (opt-in; 0/unset trusts none) so the
# login rate limit and the sign-in log see the real client IP, not the proxy's.
# The same hops also supply the scheme, host and port the browser used
# (X-Forwarded-Proto/Host/Port), which the same-origin check compares exactly.
TRUSTED_PROXY_HOPS = _env_int("TRUSTED_PROXY_HOPS", 0, minimum=0, maximum=5)


def apply_proxy_fix(flask_app, hops):
    """Wrap flask_app in werkzeug's ProxyFix for exactly ``hops`` proxies (0: no-op)."""
    if not hops:
        return False
    from werkzeug.middleware.proxy_fix import ProxyFix

    flask_app.wsgi_app = ProxyFix(
        flask_app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops, x_port=hops
    )
    return True


apply_proxy_fix(app, TRUSTED_PROXY_HOPS)

_env_secret = (os.getenv("FLASK_SECRET_KEY") or "").strip()
app.secret_key, _secret_source = resolve_secret_key(_env_secret, instance_dir)
_secret_problem = secret_key_problem(_env_secret)
if _secret_problem == "placeholder":
    _startup_warning(
        "FLASK_SECRET_KEY is set to a published placeholder value and was ignored."
    )
elif _secret_problem == "short":
    _startup_warning(
        "FLASK_SECRET_KEY is shorter than %d characters and was ignored (a short key "
        "lets anyone forge a sign-in). Generate one with: "
        "python -c \"import secrets; print(secrets.token_hex(32))\"" % MIN_SECRET_KEY_LENGTH
    )
if _secret_source == "generated":
    _startup_warning(
        "FLASK_SECRET_KEY is %s: generated instance/.flask_secret (mode 0600). "
        "Set FLASK_SECRET_KEY in .env to keep sessions valid across hosts."
        % ("not set" if _secret_problem == "unset" else "not usable")
    )
elif _secret_source == "ephemeral":
    _startup_warning(
        "FLASK_SECRET_KEY is not set and instance/.flask_secret could not be written: "
        "using a random per-process session key (sign-ins end on restart). Set FLASK_SECRET_KEY."
    )
elif _secret_source == "file":
    logging.info("Using the session key from instance/.flask_secret")

_cookie_secure = env_flag("SESSION_COOKIE_SECURE", False)
app.config.update(
    DEBUG=debug_enabled(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_cookie_secure,
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
    REMEMBER_COOKIE_SECURE=_cookie_secure,
    MAX_CONTENT_LENGTH=_env_int("MAX_CONTENT_LENGTH", 2 * 1024 * 1024, minimum=1024),
)

# Fail fast on a malformed SETTINGS_ENCRYPTION_KEY, and report a generated key.
secure_settings.ensure_key()
if secure_settings.key_source() == "generated":
    _startup_warning(
        "SETTINGS_ENCRYPTION_KEY is not set: generated instance/.settings_key (mode 0600). "
        "Back it up; saved API keys cannot be decrypted without it."
    )

# --- Flask-Login Configuration ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "error"

# Paths that answer JSON (401 instead of a redirect to the login page).
API_PATH_PREFIXES = ("/api/", "/gateway/api/")
API_EXACT_PATHS = frozenset({"/api", "/gateway/api", "/apispec_1.json"})
# Endpoints reachable without signing in. Everything else, including 404s and
# blueprint routes registered later (gateway mode), requires a signed-in user.
PUBLIC_ENDPOINTS = frozenset({"login", "static", "health", "health_check"})
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def is_api_path(path):
    path = path or ""
    return path in API_EXACT_PATHS or path.startswith(API_PATH_PREFIXES)


@login_manager.unauthorized_handler
def unauthorized():
    if is_api_path(request.path):
        return jsonify({"error": "Sign in required"}), 401
    return redirect(url_for("login"))


class User(UserMixin):
    def __init__(self, id):
        self.id = id
        self.email = os.getenv("DEFAULT_ADMIN_EMAIL")

    def get_id(self):
        return self.id


@login_manager.user_loader
def load_user(user_id):
    if user_id == "admin":
        return User(id="admin")
    return None


def parse_cors_origins(raw):
    """Explicit http(s) origins from a comma-separated CORS_ORIGINS value.

    "*" and malformed entries are dropped: a wildcard would let any web page
    drive the API from a signed-in browser.
    """
    origins = []
    for item in (raw or "").split(","):
        candidate = item.strip().rstrip("/")
        if not candidate or candidate == "*":
            continue
        try:
            parts = urlsplit(candidate)
            _ = parts.port  # raises ValueError on a bad port
        except ValueError:
            continue
        if (
            parts.scheme.lower() in ("http", "https")
            and parts.hostname
            and not parts.path
            and not parts.query
            and not parts.fragment
            and "*" not in parts.netloc
        ):
            origin = "%s://%s" % (parts.scheme.lower(), parts.netloc.lower())
            if origin not in origins:
                origins.append(origin)
    return origins


def configure_cors(flask_app, raw):
    """Enable flask_cors for /api/* only for explicit origins. Returns the origins used.

    Every /api/* route needs the signed-in session cookie, so the listed origins
    get Access-Control-Allow-Credentials and must call with credentials:'include'.
    The cookie is SameSite=Lax: browsers send it only from same-site origins
    (another subdomain of the same site, another port of the same host), never
    from a cross-site origin, so CORS_ORIGINS cannot open the API to other sites.
    """
    raw = (raw or "").strip()
    entries = [e.strip() for e in raw.split(",") if e.strip()]
    origins = parse_cors_origins(raw)
    if "*" in entries:
        _startup_warning(
            "CORS_ORIGINS contains '*', which is not allowed and was ignored. "
            "List explicit origins (for example https://devhub.example.com) to enable CORS for /api/*."
        )
    dropped = [e for e in entries if e != "*" and e.rstrip("/").lower() not in origins]
    if dropped:
        _startup_warning(
            "CORS_ORIGINS entries ignored (not an http(s) origin): %d" % len(dropped)
        )
    if origins:
        from flask_cors import CORS  # optional dependency, only needed when enabled

        CORS(
            flask_app,
            resources={r"/api/*": {"origins": origins, "supports_credentials": True}},
        )
        logging.info(
            "CORS_ORIGINS: %d origin(s) may call /api/* with the signed-in user's "
            "session (credentials). The session cookie is SameSite=Lax, so this works "
            "only for same-site origins; cross-site callers get 401.",
            len(origins),
        )
    return origins


# CORS: off unless CORS_ORIGINS lists explicit origins.
CORS_ALLOWED_ORIGINS = configure_cors(app, os.getenv("CORS_ORIGINS", ""))
# The browser-facing origin(s) of this app, e.g. https://demo.example.com, for a
# reverse proxy that sends neither the original Host port nor X-Forwarded-*.
# Optional: by default the origin is worked out from each request.
APP_ORIGINS = parse_cors_origins(os.getenv("APP_ORIGIN", ""))

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _split_netloc(netloc):
    """(host, port or None) from 'host', 'host:port' or '[v6]:port'."""
    try:
        parts = urlsplit("//" + (netloc or ""))
        return (parts.hostname or "").lower(), parts.port
    except ValueError:
        return "", None


def _origin_tuple(value):
    """(scheme, host, port) of an http(s) origin or URL with the port made explicit; else None."""
    try:
        parts = urlsplit((value or "").strip())
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None
    if scheme not in _DEFAULT_PORTS or not host:
        return None
    return scheme, host, (port if port is not None else _DEFAULT_PORTS[scheme])


def _last_header_value(name):
    values = [v.strip() for v in request.headers.get(name, "").split(",") if v.strip()]
    return values[-1] if values else ""


def request_origin():
    """(scheme, host, port) the browser addressed this request to.

    With TRUSTED_PROXY_HOPS set, ProxyFix has already applied X-Forwarded-*
    to the request. Without it, X-Forwarded-Proto/Host/Port (set by a proxy
    such as nginx or Traefik) are still used here: a browser cannot add them to
    a cross-site request (custom headers need a CORS preflight, which fails),
    so they cannot help a forged request pass; they only describe the proxy's
    public side. Without a port anywhere, the scheme's default port applies.
    """
    scheme = (request.scheme or "http").lower()
    netloc = request.host
    forwarded_port = None
    if not TRUSTED_PROXY_HOPS:
        proto = _last_header_value("X-Forwarded-Proto").lower()
        if proto in _DEFAULT_PORTS:
            scheme = proto
        netloc = _last_header_value("X-Forwarded-Host") or netloc
        port_text = _last_header_value("X-Forwarded-Port")
        if port_text.isdigit() and 0 < int(port_text) < 65536:
            forwarded_port = int(port_text)
    host, port = _split_netloc(netloc)
    if port is None:
        port = forwarded_port or _DEFAULT_PORTS.get(scheme, 80)
    return scheme, host, port


def origin_is_same(value):
    """True if an Origin/Referer URL is exactly this app's origin (or a listed one).

    Scheme, host name and port must all match the request's own origin (see
    request_origin), an APP_ORIGIN entry or a CORS_ORIGINS entry. A page on
    another port or scheme of the same host is another origin and is refused.
    """
    origin = _origin_tuple(value)
    if origin is None:
        return False
    for allowed in list(CORS_ALLOWED_ORIGINS) + list(APP_ORIGINS):
        if origin == _origin_tuple(allowed):
            return True
    return origin == request_origin()


def _origin_label(value):
    """'scheme://host:port' of an Origin/Referer value for a log line (no path or query)."""
    try:
        parts = urlsplit((value or "").strip())
    except ValueError:
        return "invalid"
    if parts.scheme and parts.netloc:
        return "%s://%s" % (parts.scheme, parts.netloc)
    return (value or "").strip()[:40] or "-"


def _cross_origin_refused():
    scheme, host, port = request_origin()
    sent = request.headers.get("Origin") or request.headers.get("Referer") or ""
    logging.warning(
        "Refused cross-origin %s %s (from %s, this app is %s://%s:%s). If this is the "
        "app's own page behind a reverse proxy, set TRUSTED_PROXY_HOPS or APP_ORIGIN.",
        request.method,
        _clean_log_text(request.path, 120),
        _clean_log_text(_origin_label(sent), 120),
        scheme,
        _clean_log_text(host, 120),
        port,
    )
    if is_api_path(request.path):
        return jsonify({"error": "Cross-origin request refused"}), 403
    return "Cross-origin request refused", 403


@app.before_request
def enforce_same_origin_and_login():
    """Global gate: same-origin for state-changing methods, then sign-in."""
    if request.method in STATE_CHANGING_METHODS:
        origin = request.headers.get("Origin")
        if origin is not None:
            if not origin_is_same(origin):
                return _cross_origin_refused()
        else:
            referer = request.headers.get("Referer")
            if referer and not origin_is_same(referer):
                return _cross_origin_refused()

    if request.method == "OPTIONS" and request.headers.get(
        "Access-Control-Request-Method"
    ):
        # CORS preflight: an empty response (no view runs, no data returned).
        return app.make_default_options_response()

    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if current_user.is_authenticated:
        return None
    return login_manager.unauthorized()


# Chart.js: a copy at static/vendor/chart.umd.js (served from this origin) is
# used when present; otherwise this one pinned file from jsDelivr. It is loaded
# only on the pages that draw charts, never where keys or passwords are typed
# (Settings, sign-in, Gateway Mode), and the CSP below allows exactly that file.
CHARTJS_CDN_URL = "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.js"
CHARTJS_VENDOR_PATH = "vendor/chart.umd.js"
CHART_ENDPOINTS = frozenset({"index", "playground", "dashboard", "benchmarking"})
# Swagger UI (/apidocs/) needs its third-party bundle and an inline init script.
CSP_SCRIPT_EXEMPT_ENDPOINTS = frozenset({"apidocs"})


def chartjs_vendored():
    return os.path.isfile(os.path.join(app.static_folder, *CHARTJS_VENDOR_PATH.split("/")))


def chartjs_src():
    """URL of the Chart.js bundle for <script src> (templates/_chartjs.html)."""
    if chartjs_vendored():
        return url_for("static", filename=CHARTJS_VENDOR_PATH)
    return CHARTJS_CDN_URL


@app.context_processor
def _template_helpers():
    return {"chartjs_src": chartjs_src}


def content_security_policy(endpoint):
    """CSP for an HTML page: scripts from this origin only (+ Chart.js on chart pages)."""
    directives = [
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'self'",
    ]
    if endpoint not in CSP_SCRIPT_EXEMPT_ENDPOINTS:
        sources = ["'self'"]
        if endpoint in CHART_ENDPOINTS and not chartjs_vendored():
            sources.append(CHARTJS_CDN_URL)
        directives.insert(0, "script-src " + " ".join(sources))
    return "; ".join(directives)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    if is_api_path(request.path):
        response.headers.setdefault("Cache-Control", "no-store")
    if response.mimetype == "text/html":
        response.headers.setdefault(
            "Content-Security-Policy", content_security_policy(request.endpoint)
        )
    return response


# --- Log hygiene helpers -----------------------------------------------------

_REDACT_PATTERNS = [
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{6,}"), r"\1****"),
    (
        re.compile(
            r"(?i)((?:authorization|x-api-key|api[-_]?key|ocp-apim-subscription-key|"
            r"access[-_]?token|token|secret|password|passwd)[\"']?\s*[:=]\s*[\"']?)"
            r"[^\"'\s,&}]{4,}"
        ),
        r"\1****",
    ),
    (re.compile(r"(?i)([?&](?:key|api[-_]?key|token|sig|code)=)[^&\s\"']+"), r"\1****"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{8,}"), "sk-ant-****"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{12,}"), "sk-****"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA****"),
    (re.compile(r"\b(?:lk|ghp|xoxb|xoxp)[-_][A-Za-z0-9_-]{8,}"), "****"),
    (re.compile(r"\b[0-9a-fA-F]{40,}\b"), "****"),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.S,
        ),
        "[private key]",
    ),
]


def _clean_log_text(text, limit=300):
    """Redact credentials, drop tabs/newlines, truncate. For log lines and error text."""
    if text is None:
        return ""
    text = str(text)
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    text = re.sub(r"[\t\r\n\x00-\x08\x0b\x0c\x0e-\x1f]+", " ", text)
    if len(text) > limit:
        text = text[: max(0, limit - 3)] + "..."
    return text


def _json_body():
    """The request's JSON object body, or None when missing/invalid/not an object."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _as_bool(value):
    """JSON booleans as-is; common string/number spellings accepted, others False."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return False


def _json_body_required():
    return jsonify({"error": "A JSON object body is required"}), 400


def prompt_fingerprint(prompt):
    """Log-safe description of a prompt: length, short hash, redacted first 60 chars."""
    prompt = prompt if isinstance(prompt, str) else str(prompt or "")
    digest = hashlib.sha256(prompt.encode("utf-8", "replace")).hexdigest()[:12]
    head = _clean_log_text(prompt[:60], 80)
    return 'len=%d sha256=%s head="%s"' % (len(prompt), digest, head.replace('"', "'"))

# Enable template auto-reload for development
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure rate limiting with environment variables
rate_limit_daily = os.getenv("RATE_LIMIT_DAILY", "1000000")
rate_limit_hourly = os.getenv("RATE_LIMIT_HOURLY", "100000")
rate_limit_storage = os.getenv("RATE_LIMIT_STORAGE", "memory://")

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[f"{rate_limit_daily} per day", f"{rate_limit_hourly} per hour"],
    storage_uri=rate_limit_storage,
)

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "AI Guardrails Demo API",
        "description": "API documentation for the AI Guardrails Demo application.",
        "version": "1.0.0",
    },
    "basePath": "/",  # base bash for blueprint registration
    "schemes": ["http", "https"],
}

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec_1",
            "route": "/apispec_1.json",
            "rule_filter": lambda rule: True,  # all in
            "model_filter": lambda tag: True,  # all in
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": False,  # Disable default (Flasgger) UI
    "specs_route": "/apispec_1.json",  # Serve spec but not UI
}

swagger = Swagger(app, template=swagger_template, config=swagger_config)


@app.route("/apidocs/")
def apidocs():
    return render_template("swagger.html")


@app.route("/health")
@limiter.exempt
def health_check():
    """
    Health check endpoint.
    ---
    tags:
      - System
    responses:
      200:
        description: Service is healthy
    """
    return (
        jsonify(
            {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "version": "1.0.0",
            }
        ),
        200,
    )


# Global cache for Models
MODEL_CACHE = {
    "openai": {"data": None, "timestamp": None},
    "gemini": {"data": None, "timestamp": None},
    "ollama": {"data": None, "timestamp": None},
    "anthropic": {"data": None, "timestamp": None},
}

# Global cache for Gemini Client
GEMINI_CACHE = {"api_key": None, "model_name": None, "model_instance": None}
CACHE_DURATION = timedelta(hours=1)


# Configure SQLite database
db_path = os.getenv("DB_PATH", os.path.join(instance_dir, "demo_logs.db"))
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///" + db_path
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


def _ensure_sqlite_parent_dir(uri):
    """Flask-SQLAlchemy only creates the folder for relative SQLite paths."""
    try:
        from sqlalchemy.engine import make_url

        url = make_url(uri)
        if url.get_backend_name() == "sqlite" and url.database not in (None, "", ":memory:"):
            if os.path.isabs(url.database):
                os.makedirs(os.path.dirname(url.database), exist_ok=True)
    except Exception:
        pass


_ensure_sqlite_parent_dir(app.config["SQLALCHEMY_DATABASE_URI"])

db = SQLAlchemy(app)


# Define Log model
class Log(db.Model):
    __tablename__ = "logs"
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    prompt = db.Column(db.Text, nullable=False)
    attack_vectors = db.Column(db.JSON, nullable=True)
    result_json = db.Column(db.JSON, nullable=True)
    request_json = db.Column(db.JSON, nullable=True)
    error = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.uuid,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "prompt": self.prompt,
            "attack_vectors": self.attack_vectors or [],
            "result": self.result_json,
            "request": self.request_json,
            "error": self.error,
        }


# Define Settings model
class Settings(db.Model):
    __tablename__ = "settings"
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text, nullable=True)


_DECRYPT_WARNED = set()

# Endpoint URLs that receive a saved API key. They stay readable in the
# database but carry an HMAC bound to the key name (secure_settings.sign), so a
# database write cannot point a saved key at another host.
INTEGRITY_SETTING_KEYS = frozenset({"AZURE_OPENAI_ENDPOINT", "AZURE_CONTENT_SAFETY_ENDPOINT"})

# False until migrate_plaintext_secrets() has upgraded every row. From then on,
# secret rows must be enc:v2 (bound to their name) and endpoint rows mac:v1:
# plaintext, enc:v1 or untagged values are ignored (treated as not set), so a
# value copied into the database from another row or an old backup is not used.
_SETTINGS_STRICT = False


def _protected_setting(key):
    return secure_settings.is_secret_key(key) or key in INTEGRITY_SETTING_KEYS


def _decode_setting(key, value):
    """Stored value -> usable value. Raises SettingsCryptoError when it must not be used."""
    if not value:
        return value
    if secure_settings.is_bound(value):
        return secure_settings.decrypt(value, key, allow_v1=False)
    if key in INTEGRITY_SETTING_KEYS and secure_settings.is_signed(value):
        return secure_settings.verify(key, value)
    if secure_settings.is_encrypted(value) or _protected_setting(key):
        if _SETTINGS_STRICT:
            raise secure_settings.SettingsIntegrityError(
                "stored in an old or unauthenticated format"
            )
        return secure_settings.decrypt(value)  # enc:v1, or plaintext before migration
    return value


def get_setting(key, default=None):
    """Read a Settings value; secret values are decrypted transparently.

    Works outside a request (background threads) by pushing an app context.
    A value that cannot be decrypted or authenticated (key changed, value
    copied from another row, written outside the app) is treated as unset.
    """
    if not has_app_context():
        with app.app_context():
            return get_setting(key, default)
    setting = db.session.get(Settings, key)
    if not setting:
        return default
    try:
        return _decode_setting(key, setting.value)
    except secure_settings.SettingsCryptoError:
        if key not in _DECRYPT_WARNED:
            _DECRYPT_WARNED.add(key)
            logging.warning(
                "Saved setting %s could not be decrypted or authenticated with the "
                "current settings key; treating it as not set. Re-enter it in Settings.",
                key,
            )
        return default


def _encode_setting(key, value):
    if value and secure_settings.is_secret_key(key):
        return secure_settings.encrypt(value, key)
    if value and key in INTEGRITY_SETTING_KEYS:
        return secure_settings.sign(key, value)
    return value


def set_setting(key, value):
    """Write a Settings value. Secret keys are stored AES-256-GCM encrypted (enc:v2)."""
    if value is None:
        return
    if not has_app_context():
        with app.app_context():
            return set_setting(key, value)
    value = _encode_setting(key, str(value))
    setting = db.session.get(Settings, key)
    if setting:
        setting.value = value
    else:
        setting = Settings(key=key, value=value)
        db.session.add(setting)
    db.session.commit()
    _DECRYPT_WARNED.discard(key)


def delete_setting(key):
    """Remove a saved value so the environment default (if any) applies again."""
    if not has_app_context():
        with app.app_context():
            return delete_setting(key)
    setting = db.session.get(Settings, key)
    if setting is not None:
        db.session.delete(setting)
        db.session.commit()
    _DECRYPT_WARNED.discard(key)


def _sqlite_engine():
    engine = db.engine
    return engine if engine.dialect.name == "sqlite" else None


def _sqlite_secure_delete_on_connect(dbapi_connection, _record):
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA secure_delete=ON")  # constant statement, no input
    finally:
        cursor.close()


def enable_sqlite_secure_delete():
    """PRAGMA secure_delete=ON on every SQLite connection of the app.

    SQLite then overwrites deleted and replaced content with zeros instead of
    leaving it in the file's free pages, so an updated or cleared API key does
    not linger in instance/demo_logs.db or the backups copied from it.
    """
    from sqlalchemy import event

    engine = _sqlite_engine()
    if engine is None or event.contains(engine, "connect", _sqlite_secure_delete_on_connect):
        return False
    event.listen(engine, "connect", _sqlite_secure_delete_on_connect)
    engine.dispose()  # connections opened before the listener get it on reconnect
    return True


def scrub_sqlite_free_space():
    """VACUUM the SQLite file (and truncate a WAL) so overwritten values are gone.

    Returns True when it ran. Never raises: the data is already re-encrypted,
    this only removes the old bytes.
    """
    try:
        engine = _sqlite_engine()
        if engine is None:
            return False
        db.session.remove()
        with engine.execution_options(isolation_level="AUTOCOMMIT").connect() as conn:
            conn.exec_driver_sql("PRAGMA secure_delete=ON")
            conn.exec_driver_sql("VACUUM")
            mode = conn.exec_driver_sql("PRAGMA journal_mode").scalar()
            if str(mode or "").lower() == "wal":
                conn.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
        return True
    except Exception as e:
        logging.warning(
            "Could not compact the database after re-encrypting saved settings "
            "(old values may remain in its free space): %s",
            _clean_log_text(e, 200),
        )
        return False


def restrict_sqlite_file_mode():
    """Best effort: make the SQLite database file owner-only (POSIX)."""
    if os.name != "posix":
        return
    try:
        engine = _sqlite_engine()
        path = engine.url.database if engine is not None else None
        if path and path != ":memory:" and os.path.isfile(path):
            if os.stat(path).st_mode & 0o077:
                os.chmod(path, 0o600)
    except Exception:
        pass


# Written once the saved settings have been upgraded (instance dir, next to
# .settings_key). From then on the upgrade never runs again: it cannot tell a
# legacy row from one written into the database later (a plaintext endpoint, an
# enc:v1 value copied out of an old backup), and re-encrypting or re-tagging
# such a row would make it look genuine.
SETTINGS_FORMAT_PATH = os.path.join(instance_dir, ".settings_format")
SETTINGS_FORMAT = "enc:v2 mac:v1"


def _legacy_setting(row):
    """True for a protected row in a format get_setting() no longer accepts."""
    value = row.value
    if not value:
        return False
    if secure_settings.is_secret_key(row.key):
        return not secure_settings.is_bound(value)
    if row.key in INTEGRITY_SETTING_KEYS:
        return not secure_settings.is_signed(value)
    return False


def migrate_plaintext_secrets():
    """Upgrade Settings rows to the current at-rest formats once. Returns how many changed.

    * secret keys: plaintext or enc:v1 -> enc:v2 (AES-256-GCM, the key name as
      associated data);
    * endpoint keys (INTEGRITY_SETTING_KEYS): plaintext -> mac:v1.

    When rows changed, the database file is VACUUMed so the old plaintext does
    not stay in its free pages. Afterwards get_setting() accepts only the
    current formats, and SETTINGS_FORMAT_PATH records that the upgrade ran: on
    later starts rows in an older format are reported and stay ignored. Keys
    that were stored in plaintext should be rotated, and backups taken before
    this start still contain them.
    """
    global _SETTINGS_STRICT
    changed = 0
    plaintext = 0
    if os.path.isfile(SETTINGS_FORMAT_PATH):
        try:
            legacy = [row.key for row in Settings.query.all() if _legacy_setting(row)]
        except Exception as e:
            logging.error("Could not read saved settings: %s", _clean_log_text(e, 200))
            legacy = []
        _SETTINGS_STRICT = True
        if legacy:
            _startup_warning(
                "%d saved setting(s) are in an older or unauthenticated format and are "
                "ignored (treated as not set): %s. This install already upgraded its "
                "saved settings (instance/.settings_format), so such values are not "
                "trusted. Re-enter them in Settings. To upgrade a restored pre-upgrade "
                "database instead, delete instance/.settings_format and restart."
                % (len(legacy), ", ".join(sorted(legacy)))
            )
        return 0
    try:
        for row in Settings.query.all():
            value = row.value
            if not value:
                continue
            if secure_settings.is_secret_key(row.key):
                if secure_settings.is_bound(value):
                    continue
                try:
                    clear = secure_settings.decrypt(value)  # enc:v1 or plaintext
                except secure_settings.SettingsCryptoError:
                    continue  # wrong key: left as is, get_setting treats it as unset
                if not secure_settings.is_encrypted(value):
                    plaintext += 1
                row.value = secure_settings.encrypt(clear, row.key)
                changed += 1
            elif row.key in INTEGRITY_SETTING_KEYS and not secure_settings.is_signed(value):
                row.value = secure_settings.sign(row.key, value)
                changed += 1
        if changed:
            db.session.commit()
            logging.info("Upgraded %d saved setting(s) to the current at-rest format", changed)
        _SETTINGS_STRICT = True
    except Exception as e:
        db.session.rollback()
        logging.error(
            "Could not upgrade saved settings to the current format: %s",
            _clean_log_text(e, 200),
        )
        return changed
    try:
        secure_settings.read_or_create_secret_file(SETTINGS_FORMAT_PATH, lambda: SETTINGS_FORMAT)
    except (OSError, secure_settings.SettingsCryptoError) as e:
        _startup_warning(
            "Could not write instance/.settings_format (%s): the saved-settings upgrade "
            "will run again at the next start." % _clean_log_text(e, 120)
        )
    if changed:
        scrub_sqlite_free_space()
    if plaintext:
        _startup_warning(
            "%d API key(s) saved by an older version were stored in plaintext and are "
            "encrypted now. Rotate those keys, and delete database backups made before "
            "this start: they still contain the plaintext values." % plaintext
        )
    return changed


def save_log_to_db(entry):
    log = Log(
        uuid=entry["id"],
        timestamp=datetime.strptime(entry["timestamp"], "%Y-%m-%d %H:%M:%S"),
        prompt=entry["prompt"],
        attack_vectors=entry.get("attack_vectors"),
        result_json=entry.get("result"),
        request_json=entry.get("request"),
        error=entry.get("error"),
    )
    db.session.add(log)
    db.session.commit()


_ANALYSIS_LOGS_LOCK = threading.Lock()
GATEWAY_PROMPT_MAX = 20000


def _normalize_log_timestamp(value):
    """'%Y-%m-%d %H:%M:%S' local time from a datetime, ISO string or None (now)."""
    fmt = "%Y-%m-%d %H:%M:%S"
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            return datetime.strptime(text, fmt).strftime(fmt)
        except ValueError:
            pass
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            dt = datetime.now()
    else:
        dt = datetime.now()
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt.strftime(fmt)


def record_gateway_log(entry):
    """Record a Gateway Mode run so Logs and Dashboard show it next to playground runs.

    Accepts the same dict shape analyze() builds ({id?, timestamp?, prompt,
    result: {flagged, ...}, attack_vectors, request?, response?}). Tolerates a
    top-level "flagged" or "verdict" ("BLOCKED" means flagged) and a "category"
    when attack_vectors is missing. Adds source="gateway" (top level, and inside
    result/request because the Log table has no source column). Safe to call
    from background threads. Returns the normalized entry.
    """
    if not isinstance(entry, dict):
        raise TypeError("record_gateway_log() needs a dict")
    e = dict(entry)
    prompt = e.get("prompt")
    if prompt is None:
        prompt = e.get("text", "")
    prompt = str(prompt)[:GATEWAY_PROMPT_MAX]

    result = e.get("result")
    result = dict(result) if isinstance(result, dict) else {}
    # A "results" key would make the Logs page treat the row as a benchmark run.
    if "results" in result:
        result["probe_results"] = result.pop("results")

    if "flagged" in result:
        flagged = bool(result["flagged"])
    elif "flagged" in e:
        flagged = bool(e.get("flagged"))
    else:
        verdict = str(e.get("verdict") or result.get("verdict") or "").upper()
        flagged = verdict == "BLOCKED"
    result["flagged"] = flagged

    vectors = e.get("attack_vectors")
    if vectors is None:
        vectors = result.get("attack_vectors")
    if vectors is None:
        category = e.get("category") or result.get("category")
        vectors = [category] if category else []
    if isinstance(vectors, str):
        vectors = [vectors]
    clean_vectors = []
    for v in vectors or []:
        v = str(v).strip()[:100]
        if v and v not in clean_vectors:
            clean_vectors.append(v)
    result["attack_vectors"] = clean_vectors
    result["source"] = "gateway"

    request_part = e.get("request")
    request_part = dict(request_part) if isinstance(request_part, dict) else {}
    request_part.setdefault("prompt", prompt)
    request_part["source"] = "gateway"

    normalized = dict(e)
    normalized.update(
        {
            "id": str(e.get("id") or uuid.uuid4()),
            "timestamp": _normalize_log_timestamp(e.get("timestamp")),
            "prompt": prompt,
            "result": result,
            "attack_vectors": clean_vectors,
            "request": request_part,
            "source": "gateway",
        }
    )
    error = normalized.get("error")
    normalized["error"] = _clean_log_text(error, 1000) if error else None
    # JSON columns and /api/analytics need plain JSON (no datetimes/objects).
    normalized = json.loads(json.dumps(normalized, default=str))

    def _save():
        try:
            save_log_to_db(normalized)
        except Exception as exc:
            db.session.rollback()
            logging.error("Failed to save gateway log: %s", _clean_log_text(exc, 200))

    if has_app_context():
        _save()
    else:
        with app.app_context():
            _save()

    with _ANALYSIS_LOGS_LOCK:
        analysis_logs.insert(0, normalized)
        if len(analysis_logs) > 100:
            analysis_logs.pop()
    return normalized


def migrate_logs_from_file():
    logs_dir = os.getenv("LOGS_DIR", "logs")
    log_file = os.path.join(logs_dir, os.getenv("LOG_FILENAME", "application.log"))
    if not os.path.exists(log_file):
        return

    try:
        with open(log_file, "r") as f:
            lines = f.readlines()

        if not lines:
            return

        new_logs = []
        for line in lines:
            parts = line.strip().split("\t")
            if len(parts) < 3:
                continue

            time_str = parts[0]
            prompt = parts[1]
            status = parts[2]
            details = parts[3] if len(parts) > 3 else ""

            try:
                timestamp = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    t = datetime.strptime(time_str, "%H:%M:%S").time()
                    timestamp = datetime.combine(datetime.now().date(), t)
                except ValueError:
                    continue

            result_json = None
            error_msg = None
            attack_vectors = []

            if status == "Success":
                try:
                    result_json = json.loads(details)
                    if result_json.get("breakdown"):
                        for r in result_json["breakdown"]:
                            if r.get("detected") and r.get("detector_type"):
                                vector = r["detector_type"].split("/")[-1]
                                if vector not in attack_vectors:
                                    attack_vectors.append(vector)
                except json.JSONDecodeError:
                    pass
            else:
                error_msg = details

            log = Log(
                uuid=str(uuid.uuid4()),
                timestamp=timestamp,
                prompt=prompt,
                attack_vectors=attack_vectors,
                result_json=result_json,
                error=error_msg,
            )
            new_logs.append(log)

        if new_logs:
            db.session.bulk_save_objects(new_logs)
            db.session.commit()
            print(f"Migrated {len(new_logs)} logs to DB.")

        # Clear the log file after migration
        with open(log_file, "w") as f:
            f.truncate(0)

    except Exception as e:
        print(f"Migration failed: {e}")


def load_recent_logs_from_db():
    """Load all logs from DB into memory for dashboard analytics"""
    global analysis_logs
    try:
        logs = Log.query.order_by(Log.timestamp.desc()).all()
        analysis_logs = []
        for log in logs:
            entry = {
                "id": log.uuid,
                "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "prompt": log.prompt,
                "attack_vectors": log.attack_vectors or [],
                "result": log.result_json,
                "request": log.request_json,
                "error": log.error,
            }
            if log.result_json:
                entry["response"] = log.result_json
            analysis_logs.append(entry)
        print(f"Loaded {len(analysis_logs)} logs from database into memory.")
    except Exception as e:
        print(f"Failed to load logs from DB: {e}")
        analysis_logs = []


# Anthropic (Claude) models offered as scan targets. Static list — the Messages
# API has no "list models" call we need here and these change rarely. Most
# capable first so it's the default selection.
ANTHROPIC_MODELS = [
    "claude-opus-4-8",
    "claude-sonnet-5",
    "claude-haiku-4-5",
    "claude-opus-4-7",
    "claude-sonnet-4-6",
]


def get_anthropic_models(api_key):
    """Live Claude model list from the Anthropic Models API when a key is set;
    falls back to the static ANTHROPIC_MODELS list otherwise (cached like the
    other providers)."""
    if not api_key:
        return ANTHROPIC_MODELS
    now = datetime.now()
    cached = MODEL_CACHE["anthropic"]
    if (
        cached["data"]
        and cached["timestamp"]
        and now - cached["timestamp"] < CACHE_DURATION
    ):
        return cached["data"]
    try:
        resp = requests.get(
            "https://api.anthropic.com/v1/models",
            headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
            timeout=3,
        )
        if resp.status_code == 200:
            ids = [m["id"] for m in resp.json().get("data", []) if m.get("id")]
            result = ids or ANTHROPIC_MODELS
            MODEL_CACHE["anthropic"] = {"data": result, "timestamp": now}
            return result
    except Exception as e:
        logging.warning("Anthropic model list fetch failed, using static list: %s", _clean_log_text(e))
    return ANTHROPIC_MODELS


def guard_credentials():
    """AI Guardrails (Lakera) key + project, resilient to redeploys.

    Precedence: settings DB (DEMO_*) > env DEMO_* > env LAKERA_* (the kept
    technical env names). Reading BOTH env names means a deploy that sets
    LAKERA_API_KEY configures the guard consistently everywhere — the Settings
    page, the /api/settings status, AND the scan — not just the Settings page.
    """
    key = (
        get_setting("DEMO_API_KEY")
        or os.getenv("DEMO_API_KEY")
        or os.getenv("LAKERA_API_KEY")
        or ""
    )
    project = (
        get_setting("DEMO_PROJECT_ID")
        or os.getenv("DEMO_PROJECT_ID")
        or os.getenv("LAKERA_PROJECT_ID")
        or ""
    )
    return key, project


# Endpoints that receive an API key in a header (Azure OpenAI "api-key",
# Content Safety "Ocp-Apim-Subscription-Key"): https only, so the key never
# crosses the network in cleartext. Ollama (no key) may use http.
_INSECURE_ENDPOINT_WARNED = set()


def https_endpoint(value):
    """The URL without a trailing '/' when it is https:// with a host name, else ''."""
    value = (value or "").strip()
    if not value or _CONTROL_CHARS.search(value):
        return ""
    try:
        parts = urlsplit(value)
        _ = parts.port
    except ValueError:
        return ""
    if parts.scheme.lower() != "https" or not parts.hostname:
        return ""
    return value.rstrip("/")


def keyed_endpoint(setting_key):
    """Saved (or env) endpoint for a keyed Azure service; '' unless it is https://.

    Enforced where the key is used, so values saved by older versions or set in
    the environment are refused too (the Settings form refuses http:// as well).
    """
    raw = get_setting(setting_key) or os.getenv(setting_key, "") or ""
    url = https_endpoint(raw)
    if raw.strip() and not url and setting_key not in _INSECURE_ENDPOINT_WARNED:
        _INSECURE_ENDPOINT_WARNED.add(setting_key)
        logging.warning(
            "%s is not an https:// URL and is not used: its API key is only sent over TLS. "
            "Change it on the Settings page.",
            setting_key,
        )
    return url


DEFAULT_GUARD_URL = "https://api.lakera.ai/v2/guard"
GUARD_TIMEOUT = _env_int("GUARD_TIMEOUT", 30, minimum=1, maximum=300)
LLM_TIMEOUT = _env_int("LLM_TIMEOUT", 60, minimum=1, maximum=600)
PROMPT_MAX_CHARS = _env_int("PROMPT_MAX_CHARS", 100000, minimum=1000)


def guard_api_url():
    """AI Guardrails endpoint: DEMO_API_URL, then LAKERA_API_URL, then the default."""
    return (
        (os.getenv("DEMO_API_URL") or "").strip()
        or (os.getenv("LAKERA_API_URL") or "").strip()
        or DEFAULT_GUARD_URL
    )


def guard_payload(messages, project_id):
    """Guard request body; project_id is omitted when empty (Lakera default policy)."""
    payload = {"messages": messages, "breakdown": True}
    if project_id:
        payload["project_id"] = project_id
    return payload


def _guard_error(status, response=None, exc=None):
    """Display-safe description of a failed Guard call (no keys, bounded size)."""
    err = {"status": status, "error": None, "request_id": None, "message": ""}
    if response is not None:
        body = None
        try:
            body = response.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            err["error"] = _clean_log_text(body.get("error") or body.get("message") or "", 300) or None
            rid = body.get("request_id") or (body.get("metadata") or {}).get("request_uuid")
            err["request_id"] = _clean_log_text(rid, 100) if rid else None
        if not err["error"]:
            err["error"] = _clean_log_text(getattr(response, "text", "") or "", 300) or None
        err["message"] = "AI Guardrails returned HTTP %s%s" % (
            status,
            (": " + err["error"]) if err["error"] else "",
        )
    elif exc is not None:
        err["error"] = _clean_log_text("%s: %s" % (type(exc).__name__, exc), 300)
        err["message"] = "AI Guardrails could not be reached (%s)" % err["error"]
    return err


def call_guard(api_key, project_id, messages, url=None, timeout=None):
    """POST to the Guard API. Returns (result_dict, None) or (None, error_dict)."""
    url = url or guard_api_url()
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        response = requests.post(
            url,
            headers=headers,
            json=guard_payload(messages, project_id),
            timeout=timeout or GUARD_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        err = _guard_error(None, exc=exc)
        logging.error("AI Guardrails request failed: %s", err["error"])
        return None, err
    if response.status_code != 200:
        err = _guard_error(response.status_code, response=response)
        logging.error(
            "AI Guardrails API error status=%s request_id=%s error=%s",
            response.status_code,
            err["request_id"],
            err["error"],
        )
        return None, err
    try:
        result = response.json()
    except ValueError:
        err = _guard_error(response.status_code, response=response)
        err["message"] = "AI Guardrails returned a non-JSON response"
        logging.error("AI Guardrails returned a non-JSON response")
        return None, err
    if not isinstance(result, dict):
        return None, {
            "status": response.status_code,
            "error": "unexpected response shape",
            "request_id": None,
            "message": "AI Guardrails returned an unexpected response",
        }
    return result, None


def _detected_types(result):
    return [
        str(r.get("detector_type"))
        for r in (result or {}).get("breakdown") or []
        if isinstance(r, dict) and r.get("detected") and r.get("detector_type")
    ]


def get_available_models(api_key):
    """Helper function to fetch available OpenAI models with caching"""
    if not api_key:
        return []

    # Check cache
    now = datetime.now()
    if MODEL_CACHE["openai"]["data"] and MODEL_CACHE["openai"]["timestamp"]:
        if now - MODEL_CACHE["openai"]["timestamp"] < CACHE_DURATION:
            return MODEL_CACHE["openai"]["data"]

    try:
        response = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=2,  # Reduced timeout
        )
        if response.status_code == 200:
            models = response.json().get("data", [])
            all_models = [m["id"] for m in models]
            result = sorted(all_models, reverse=True)

            # Update cache
            MODEL_CACHE["openai"]["data"] = result
            MODEL_CACHE["openai"]["timestamp"] = now
            return result

        return []
    except:
        return []


def gemini_client(api_key):
    """google-genai client with a request timeout (ms) where the SDK supports it."""
    try:
        return genai.Client(api_key=api_key, http_options={"timeout": LLM_TIMEOUT * 1000})
    except Exception:
        return genai.Client(api_key=api_key)


def ollama_timeout_seconds():
    """Configured Ollama timeout (Settings, then env), bounded to 1..3600 s."""
    raw = get_setting("OLLAMA_TIMEOUT") or os.getenv("OLLAMA_TIMEOUT") or "120"
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        value = 120
    return max(1, min(3600, value))


def get_gemini_models():
    """Helper function to fetch available Gemini models with caching"""
    api_key = get_setting("GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY")
    if not api_key:
        return []

    # Check cache
    now = datetime.now()
    if MODEL_CACHE["gemini"]["data"] and MODEL_CACHE["gemini"]["timestamp"]:
        if now - MODEL_CACHE["gemini"]["timestamp"] < CACHE_DURATION:
            return MODEL_CACHE["gemini"]["data"]

    try:
        client = gemini_client(api_key)
        models = list(client.models.list())

        # Debug: check first model
        if models:
            m = models[0]
            logging.info(f"[DEBUG] First Gemini model: {m.name}, Attributes: {dir(m)}")
            # Log supported methods if they exist
            supp_meth = (
                getattr(m, "supported_methods", [])
                or getattr(m, "supported_generation_methods", [])
                or getattr(m, "supported_actions", [])
            )
            logging.info(
                f"[DEBUG] Model {m.name} supported methods/actions: {supp_meth}"
            )

        gen_models = []
        for m in models:
            # Show all available models
            name = m.name.replace("models/", "")
            gen_models.append(name)

        result = sorted(list(set(gen_models)), reverse=True)

        # Update cache
        MODEL_CACHE["gemini"]["data"] = result
        MODEL_CACHE["gemini"]["timestamp"] = now
        return result
    except Exception as e:
        logging.error("Error fetching Gemini models: %s", _clean_log_text(e))
        return []


def resolve_ollama_url():
    """Ollama base URL used to actually reach the model server.

    Precedence: settings DB > env > default. Permanent guard for Dokploy: a
    stale OLLAMA_API_URL=http://localhost:11434 keeps getting re-pushed on every
    redeploy, but localhost can't reach Ollama from inside a container. So if the
    configured host is localhost/127.0.0.1 AND the agentic 'ollama-cpu' service
    is resolvable (i.e. we're in the deployed stack), transparently use it.
    Standalone deploys (ollama-cpu doesn't resolve) are left untouched.
    Override the container host via OLLAMA_CONTAINER_HOST.
    """
    import socket
    from urllib.parse import urlparse

    url = get_setting("OLLAMA_API_URL") or os.getenv(
        "OLLAMA_API_URL", "http://ollama-cpu:11434"
    )
    try:
        parsed = urlparse(url)
        if (parsed.hostname or "") in ("localhost", "127.0.0.1"):
            container_host = os.getenv("OLLAMA_CONTAINER_HOST", "ollama-cpu")
            try:
                socket.gethostbyname(container_host)
                url = f"{parsed.scheme or 'http'}://{container_host}:{parsed.port or 11434}"
            except OSError:
                pass  # ollama-cpu not resolvable → standalone; keep as configured
    except Exception:
        pass
    return url


def get_ollama_models():
    """Helper function to fetch available Ollama models with caching"""
    ollama_url = resolve_ollama_url()

    # Check cache
    now = datetime.now()
    if MODEL_CACHE["ollama"]["data"] and MODEL_CACHE["ollama"]["timestamp"]:
        if now - MODEL_CACHE["ollama"]["timestamp"] < CACHE_DURATION:
            return MODEL_CACHE["ollama"]["data"]

    try:
        response = requests.get(f"{ollama_url}/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get("models", [])
            result = sorted([m["name"] for m in models])

            # Update cache
            MODEL_CACHE["ollama"]["data"] = result
            MODEL_CACHE["ollama"]["timestamp"] = now
            return result
        return []
    except Exception as e:
        print(f"Error fetching Ollama models: {e}")
        return []


# --- Gateway Mode (Check Point AI Agent Security demo console) ---
# Registered before the DB init below so any tables it declares get created.
# Its routes sit behind the global login gate (enforce_same_origin_and_login).
from gateway_mode import init_gateway_mode  # noqa: E402

init_gateway_mode(app, get_setting=get_setting, record_log=record_gateway_log)

# Initialize DB
with app.app_context():
    enable_sqlite_secure_delete()
    db.create_all()
    restrict_sqlite_file_mode()
    # Before migrate_logs_from_file(): that call truncates application.log, and
    # nothing should be logged after it during import (tests rely on this).
    migrate_plaintext_secrets()
    migrate_logs_from_file()
    load_recent_logs_from_db()

    # Background pre-warm LLM Guard models - DISABLED for now
    # def warm_up_llm_guard():
    #     try:
    #         logging.info("Background: Pre-warming LLM Guard models...")
    #         get_llm_guard_pipeline()
    #     except Exception as e:
    #         logging.error(f"Background: Failed to warm up LLM Guard: {e}")
    #
    # executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    # executor.submit(warm_up_llm_guard)


# --- Auth Routes ---

LOGIN_NOT_CONFIGURED_MSG = (
    "Set DEFAULT_ADMIN_PASSWORD (or DEFAULT_ADMIN_PASSWORD_HASH) in .env before signing in."
)
LOGIN_NO_EMAIL_MSG = "Set DEFAULT_ADMIN_EMAIL in .env before signing in."


def _env_unquoted(name):
    """Env value with one pair of matching surrounding quotes removed.

    docker compose strips the quotes from NAME='value' in .env, but
    `docker run --env-file` (scripts/lab_run_web.sh) keeps them, which would
    turn a quoted password hash or password into a different value.
    """
    value = os.getenv(name) or ""
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in ("'", '"'):
        return stripped[1:-1]
    return value


def admin_login_config():
    """(email, password_hash, password, problem). problem is None when sign-in can work."""
    email = _env_unquoted("DEFAULT_ADMIN_EMAIL").strip()
    pw_hash = _env_unquoted("DEFAULT_ADMIN_PASSWORD_HASH").strip()
    password = _env_unquoted("DEFAULT_ADMIN_PASSWORD")
    if not email:
        return email, pw_hash, password, LOGIN_NO_EMAIL_MSG
    if not pw_hash and (not password or password in PLACEHOLDER_PASSWORDS):
        return email, pw_hash, password, LOGIN_NOT_CONFIGURED_MSG
    return email, pw_hash, password, None


def _password_matches(submitted, pw_hash, password):
    if pw_hash:
        try:
            return bool(check_password_hash(pw_hash, submitted))
        except (ValueError, TypeError):
            logging.warning("DEFAULT_ADMIN_PASSWORD_HASH is not a valid werkzeug hash")
            return False
    return hmac.compare_digest(
        submitted.encode("utf-8"), password.encode("utf-8")
    )


# Gateway Mode keeps one engine Session (logged in to the Management API, with
# the keys in memory) per (user id, session["gw_sid"]). Signing out ends it and
# signing in starts from a fresh Flask session, so the next person to sign in
# on the same browser never inherits it. A running job (install, rollback) is
# not cut off: the Session is closed as soon as the job ends.
GATEWAY_EXTENSION = "gateway_mode"
GATEWAY_SESSION_KEY = "gw_sid"
SIGNOUT_POLL_SECONDS = 1.0
SIGNOUT_MAX_WAIT_SECONDS = 6 * 60 * 60


def end_gateway_session(user_id, gw_sid, reason="sign-out"):
    """Close the Gateway Mode engine Session of (user_id, gw_sid).

    Returns "dropped", "deferred" (a job is running; closed when it ends),
    or "none" (nothing to close). Never raises.
    """
    ctx = app.extensions.get(GATEWAY_EXTENSION)
    if ctx is None or not isinstance(gw_sid, str) or not gw_sid or user_id is None:
        return "none"
    owner = (str(user_id), gw_sid)

    def busy():
        try:
            return bool(ctx.jobs.is_busy(owner))
        except Exception:  # a broken probe must not cut off a running install
            return True

    def drop():
        try:
            return bool(ctx.store.drop(owner, reason=reason))
        except Exception as exc:
            logging.warning(
                "Could not close the Gateway Mode session at sign-out: %s",
                _clean_log_text(exc, 200),
            )
            return False

    if not busy():
        return "dropped" if drop() else "none"

    def wait_then_drop():
        deadline = time.monotonic() + SIGNOUT_MAX_WAIT_SECONDS
        while busy() and time.monotonic() < deadline:
            time.sleep(SIGNOUT_POLL_SECONDS)
        drop()

    threading.Thread(target=wait_then_drop, name="aiguard-signout", daemon=True).start()
    logging.info("Sign-out: the Gateway Mode session closes when its running job ends")
    return "deferred"


@app.route("/login", methods=["GET", "POST"])
@limiter.limit(
    "10 per minute",
    methods=["POST"],
    error_message="Too many sign-in attempts. Wait a minute and try again.",
)
def login():
    if current_user.is_authenticated:
        return redirect(url_for("playground"))

    admin_email, pw_hash, admin_pass, problem = admin_login_config()

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        if problem:
            # Never compare against unset/empty/placeholder credentials.
            flash(problem, "error")
            return render_template("login.html"), 503
        if (
            not isinstance(email, str)
            or not isinstance(password, str)
            or not email.strip()
            or not password
            or len(email) > 320
            or len(password) > 1024
        ):
            flash("Enter your email and password.", "error")
            return render_template("login.html"), 400
        if password in PLACEHOLDER_PASSWORDS:
            flash(LOGIN_NOT_CONFIGURED_MSG, "error")
            return render_template("login.html"), 503

        email_ok = hmac.compare_digest(
            email.strip().lower().encode("utf-8"), admin_email.lower().encode("utf-8")
        )
        password_ok = _password_matches(password, pw_hash, admin_pass)
        if email_ok and password_ok:
            # A fresh session: nothing from before this sign-in (an old
            # gw_sid in particular) carries over.
            old_gw_sid = session.get(GATEWAY_SESSION_KEY)
            session.clear()
            end_gateway_session("admin", old_gw_sid)
            login_user(User(id="admin"))
            logging.info("Admin signed in from %s", _clean_log_text(get_remote_address(), 64))
            return redirect(url_for("playground"))
        logging.warning(
            "Failed sign-in from %s", _clean_log_text(get_remote_address(), 64)
        )
        flash("Invalid email or password.", "error")
        return render_template("login.html"), 401

    return render_template("login.html", login_problem=problem)


@app.route("/logout")
@login_required
def logout():
    end_gateway_session(current_user.get_id(), session.get(GATEWAY_SESSION_KEY))
    # Drop everything (gw_sid included); logout_user() afterwards still marks a
    # remember-me cookie for deletion.
    session.clear()
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    openai_api_key = get_setting("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY", "")
    available_models = get_available_models(openai_api_key)

    azure_api_key = get_setting("AZURE_OPENAI_API_KEY") or os.getenv(
        "AZURE_OPENAI_API_KEY", ""
    )
    azure_endpoint = keyed_endpoint("AZURE_OPENAI_ENDPOINT")
    azure_deployment = get_setting("AZURE_OPENAI_DEPLOYMENT") or os.getenv(
        "AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini-2024-07-18"
    )

    azure_cs_endpoint = keyed_endpoint("AZURE_CONTENT_SAFETY_ENDPOINT")
    azure_cs_key = get_setting("AZURE_CONTENT_SAFETY_KEY") or os.getenv(
        "AZURE_CONTENT_SAFETY_KEY", ""
    )

    is_azure_openai_configured = bool(azure_api_key and azure_endpoint)
    is_azure_content_safety_configured = bool(azure_cs_endpoint and azure_cs_key)

    gemini_models = get_gemini_models()
    ollama_models = get_ollama_models()
    anthropic_api_key = get_setting("ANTHROPIC_API_KEY") or os.getenv(
        "ANTHROPIC_API_KEY", ""
    )
    anthropic_models = get_anthropic_models(anthropic_api_key)

    # Server-side default provider/model used when the browser has no saved
    # preference. Lets a deployment pin, e.g., Ollama + an uncensored local
    # model so the playground works out of the box (a browser localStorage
    # choice still wins). See DEFAULT_LLM_PROVIDER / DEFAULT_LLM_MODEL.
    default_provider = get_setting("DEFAULT_LLM_PROVIDER") or os.getenv(
        "DEFAULT_LLM_PROVIDER", "ollama"
    )
    default_model = get_setting("DEFAULT_LLM_MODEL") or os.getenv(
        "DEFAULT_LLM_MODEL", "richardyoung/mythos-9b-unhinged-abliterated:latest"
    )

    return render_template(
        "playground.html",
        available_models=available_models,
        azure_deployment=azure_deployment,
        gemini_models=gemini_models,
        ollama_models=ollama_models,
        anthropic_models=anthropic_models,
        is_azure_openai_configured=is_azure_openai_configured,
        is_azure_content_safety_configured=is_azure_content_safety_configured,
        default_provider=default_provider,
        default_model=default_model,
    )


@app.route("/playground")
@login_required
def playground():
    openai_api_key = get_setting("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY", "")
    available_models = get_available_models(openai_api_key)

    azure_api_key = get_setting("AZURE_OPENAI_API_KEY") or os.getenv(
        "AZURE_OPENAI_API_KEY", ""
    )
    azure_endpoint = keyed_endpoint("AZURE_OPENAI_ENDPOINT")
    azure_deployment = get_setting("AZURE_OPENAI_DEPLOYMENT") or os.getenv(
        "AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini-2024-07-18"
    )

    azure_cs_endpoint = keyed_endpoint("AZURE_CONTENT_SAFETY_ENDPOINT")
    azure_cs_key = get_setting("AZURE_CONTENT_SAFETY_KEY") or os.getenv(
        "AZURE_CONTENT_SAFETY_KEY", ""
    )

    is_azure_openai_configured = bool(azure_api_key and azure_endpoint)
    is_azure_content_safety_configured = bool(azure_cs_endpoint and azure_cs_key)

    gemini_models = get_gemini_models()
    ollama_models = get_ollama_models()
    anthropic_api_key = get_setting("ANTHROPIC_API_KEY") or os.getenv(
        "ANTHROPIC_API_KEY", ""
    )
    anthropic_models = get_anthropic_models(anthropic_api_key)

    # Server-side default provider/model used when the browser has no saved
    # preference. Lets a deployment pin, e.g., Ollama + an uncensored local
    # model so the playground works out of the box (a browser localStorage
    # choice still wins). See DEFAULT_LLM_PROVIDER / DEFAULT_LLM_MODEL.
    default_provider = get_setting("DEFAULT_LLM_PROVIDER") or os.getenv(
        "DEFAULT_LLM_PROVIDER", "ollama"
    )
    default_model = get_setting("DEFAULT_LLM_MODEL") or os.getenv(
        "DEFAULT_LLM_MODEL", "richardyoung/mythos-9b-unhinged-abliterated:latest"
    )

    return render_template(
        "playground.html",
        available_models=available_models,
        azure_deployment=azure_deployment,
        gemini_models=gemini_models,
        ollama_models=ollama_models,
        anthropic_models=anthropic_models,
        is_azure_openai_configured=is_azure_openai_configured,
        is_azure_content_safety_configured=is_azure_content_safety_configured,
        default_provider=default_provider,
        default_model=default_model,
    )


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/logs")
@login_required
def logs():
    return render_template("logs.html")


@app.route("/benchmarking")
@login_required
def benchmarking():
    """
    Render the competitor benchmarking dashboard.
    """
    azure_cs_endpoint = keyed_endpoint("AZURE_CONTENT_SAFETY_ENDPOINT")
    azure_cs_key = get_setting("AZURE_CONTENT_SAFETY_KEY") or os.getenv(
        "AZURE_CONTENT_SAFETY_KEY", ""
    )
    is_azure_content_safety_configured = bool(azure_cs_endpoint and azure_cs_key)

    return render_template(
        "benchmarking.html",
        is_azure_content_safety_configured=is_azure_content_safety_configured,
    )


# Settings form fields -> Settings keys.
SECRET_SETTING_FIELDS = [
    ("api_key", "DEMO_API_KEY"),
    ("openai_api_key", "OPENAI_API_KEY"),
    ("azure_openai_api_key", "AZURE_OPENAI_API_KEY"),
    ("gemini_api_key", "GEMINI_API_KEY"),
    ("anthropic_api_key", "ANTHROPIC_API_KEY"),
    ("azure_cs_key", "AZURE_CONTENT_SAFETY_KEY"),
]
PLAIN_SETTING_FIELDS = [
    ("project_id", "DEMO_PROJECT_ID"),
    ("azure_openai_endpoint", "AZURE_OPENAI_ENDPOINT"),
    ("azure_openai_deployment", "AZURE_OPENAI_DEPLOYMENT"),
    ("ollama_api_url", "OLLAMA_API_URL"),
    ("ollama_timeout", "OLLAMA_TIMEOUT"),
    ("azure_cs_endpoint", "AZURE_CONTENT_SAFETY_ENDPOINT"),
]
URL_SETTING_FIELDS = {"azure_openai_endpoint", "ollama_api_url", "azure_cs_endpoint"}
# These URLs receive an API key in a header: https only (Ollama has no key).
HTTPS_ONLY_FIELDS = {"azure_openai_endpoint", "azure_cs_endpoint"}
OLLAMA_TIMEOUT_RANGE = (1, 3600)
SETTING_LABELS = {
    "api_key": "AI Guardrails API key",
    "openai_api_key": "OpenAI API key",
    "azure_openai_api_key": "Azure OpenAI API key",
    "gemini_api_key": "Gemini API key",
    "anthropic_api_key": "Anthropic API key",
    "azure_cs_key": "Azure Content Safety key",
    "project_id": "Project ID",
    "azure_openai_endpoint": "Azure OpenAI endpoint",
    "azure_openai_deployment": "Azure OpenAI deployment",
    "ollama_api_url": "Ollama API URL",
    "ollama_timeout": "Ollama timeout",
    "azure_cs_endpoint": "Azure Content Safety endpoint",
}
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _secret_env_value(setting_key):
    if setting_key == "DEMO_API_KEY":
        return os.getenv("DEMO_API_KEY") or os.getenv("LAKERA_API_KEY") or ""
    return os.getenv(setting_key) or ""


def secret_setting_status(setting_key):
    """{'configured', 'masked', 'source'} for a secret; never the value itself."""
    saved = get_setting(setting_key)
    if saved:
        return {"configured": True, "masked": secure_settings.mask(saved), "source": "saved"}
    env_value = _secret_env_value(setting_key)
    if env_value:
        return {"configured": True, "masked": secure_settings.mask(env_value), "source": "env"}
    return {"configured": False, "masked": "", "source": ""}


def _clamped_timeout_text(raw):
    """Ollama timeout for the form, clamped to OLLAMA_TIMEOUT_RANGE like at run time."""
    text = (raw or "").strip()
    try:
        seconds = int(text)
    except ValueError:
        return text
    low, high = OLLAMA_TIMEOUT_RANGE
    return str(max(low, min(high, seconds)))


def plain_setting_values():
    """Current non-secret values for the form. The Ollama timeout is clamped to
    the range the form accepts (the value used at run time), so a value saved by
    an older version can never make the hidden field block "Save changes"."""
    values = _raw_plain_setting_values()
    values["ollama_timeout"] = _clamped_timeout_text(values["ollama_timeout"])
    return values


def _raw_plain_setting_values():
    _, project_id = guard_credentials()
    return {
        "project_id": project_id,
        "azure_openai_endpoint": get_setting("AZURE_OPENAI_ENDPOINT")
        or os.getenv("AZURE_OPENAI_ENDPOINT", ""),
        "azure_openai_deployment": get_setting("AZURE_OPENAI_DEPLOYMENT")
        or os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini-2024-07-18"),
        # Same display default as before (resolve_ollama_url maps localhost to
        # the ollama-cpu container when that name resolves).
        "ollama_api_url": get_setting("OLLAMA_API_URL")
        or os.getenv("OLLAMA_API_URL", "http://localhost:11434"),
        "ollama_timeout": get_setting("OLLAMA_TIMEOUT") or os.getenv("OLLAMA_TIMEOUT", "120"),
        "azure_cs_endpoint": get_setting("AZURE_CONTENT_SAFETY_ENDPOINT")
        or os.getenv("AZURE_CONTENT_SAFETY_ENDPOINT", ""),
    }


def _validate_plain_setting(field, value):
    """Return (clean_value, error). Empty values are allowed (fall back to env)."""
    value = (value or "").strip()
    label = SETTING_LABELS.get(field, field)
    if not value:
        return "", None
    if len(value) > 2048 or _CONTROL_CHARS.search(value):
        return None, "%s is too long or contains control characters." % label
    if field in URL_SETTING_FIELDS:
        try:
            parts = urlsplit(value)
            _ = parts.port
        except ValueError:
            return None, "%s is not a valid URL." % label
        if field in HTTPS_ONLY_FIELDS:
            if parts.scheme.lower() != "https" or not parts.hostname:
                return None, (
                    "%s must be an https:// URL (the API key is sent to it)." % label
                )
        elif parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return None, "%s must be an http:// or https:// URL." % label
    if field == "ollama_timeout":
        try:
            seconds = int(value)
        except ValueError:
            return None, "Ollama timeout must be a whole number of seconds."
        low, high = OLLAMA_TIMEOUT_RANGE
        if not low <= seconds <= high:
            return None, "Ollama timeout must be between %d and %d seconds." % (low, high)
        value = str(seconds)
    if field in ("project_id", "azure_openai_deployment") and len(value) > 200:
        return None, "%s is too long." % label
    return value, None


def settings_warnings():
    """Notes about current values that are not used (never contains a secret)."""
    warnings = []
    current = _raw_plain_setting_values()
    for field, _key in PLAIN_SETTING_FIELDS:
        value = (current.get(field) or "").strip()
        if not value:
            continue
        _clean, error = _validate_plain_setting(field, value)
        if error is None:
            continue
        if field == "ollama_timeout" and _clamped_timeout_text(value) != value:
            warnings.append(
                "The Ollama timeout (%s s) is outside %d-%d s; %s s is used."
                % (value, OLLAMA_TIMEOUT_RANGE[0], OLLAMA_TIMEOUT_RANGE[1],
                   _clamped_timeout_text(value))
            )
        elif field in HTTPS_ONLY_FIELDS:
            warnings.append(
                "%s is not an https:// URL, so it is not used. Change it to https://."
                % SETTING_LABELS.get(field, field)
            )
        else:
            warnings.append("%s %s" % (error, "It is kept as is until you change it."))
    return warnings


def _render_settings(success=False, errors=None, values=None, status=200):
    secrets_status = {
        field: secret_setting_status(key) for field, key in SECRET_SETTING_FIELDS
    }
    return (
        render_template(
            "settings.html",
            success=success,
            errors=errors or [],
            warnings=settings_warnings(),
            secrets=secrets_status,
            values=values if values is not None else plain_setting_values(),
            gemini_models=get_gemini_models(),
            ollama_models=get_ollama_models(),
        ),
        status,
    )


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Settings page. Secret values are write-only: they are never rendered back.

    POST: a blank secret field keeps the saved value; "clear_<field>" removes
    it; non-secret fields are saved as submitted (blank = use the env default).
    A non-secret field submitted unchanged is never a reason to refuse the save:
    if its current value does not pass validation (saved by an older version,
    or set in the environment) it is left as it is and the rest is saved.
    """
    if request.method == "POST":
        errors = []
        secret_updates = {}
        secret_clears = []
        for field, key in SECRET_SETTING_FIELDS:
            if request.form.get("clear_" + field):
                secret_clears.append(key)
                continue
            submitted = (request.form.get(field) or "").strip()
            if not submitted:
                continue  # keep the existing value
            if len(submitted) > 4096 or _CONTROL_CHARS.search(submitted):
                errors.append(
                    "%s is too long or contains control characters."
                    % SETTING_LABELS.get(field, field)
                )
                continue
            secret_updates[key] = submitted

        plain_updates = {}
        submitted_values = plain_setting_values()
        form_values = dict(submitted_values)  # what the form showed (timeout clamped)
        raw_values = _raw_plain_setting_values()
        for field, key in PLAIN_SETTING_FIELDS:
            if field not in request.form:
                continue
            raw = request.form.get(field)
            submitted = (raw or "").strip()
            submitted_values[field] = submitted
            clean, error = _validate_plain_setting(field, raw)
            if error:
                unchanged = submitted in (
                    (form_values.get(field) or "").strip(),
                    (raw_values.get(field) or "").strip(),
                )
                if unchanged:
                    continue  # keep the current value; never block other changes
                errors.append(error)
            else:
                plain_updates[key] = clean

        if errors:
            return _render_settings(errors=errors, values=submitted_values, status=400)

        for key in secret_clears:
            delete_setting(key)
        for key, value in secret_updates.items():
            set_setting(key, value)
        for key, value in plain_updates.items():
            set_setting(key, value)
        # Model lists may change with new keys/URLs.
        MODEL_CACHE["gemini"] = {"data": None, "timestamp": None}
        MODEL_CACHE["ollama"] = {"data": None, "timestamp": None}
        return redirect(url_for("settings", saved=1))

    return _render_settings(success=request.args.get("saved") == "1")


@app.route("/api/settings", methods=["GET"])
@login_required
def get_api_settings():
    """
    Configuration status for the frontend (booleans and masked hints only).
    ---
    tags:
      - Settings
    responses:
      200:
        description: Which providers are configured; secret values are never returned
    """
    demo_api_key, demo_project_id = guard_credentials()
    azure_api_key = get_setting("AZURE_OPENAI_API_KEY") or os.getenv("AZURE_OPENAI_API_KEY", "")
    azure_endpoint = keyed_endpoint("AZURE_OPENAI_ENDPOINT")
    azure_deployment = get_setting("AZURE_OPENAI_DEPLOYMENT") or os.getenv("AZURE_OPENAI_DEPLOYMENT", "")
    azure_cs_key = get_setting("AZURE_CONTENT_SAFETY_KEY") or os.getenv("AZURE_CONTENT_SAFETY_KEY", "")
    azure_cs_endpoint = keyed_endpoint("AZURE_CONTENT_SAFETY_ENDPOINT")

    return jsonify(
        {
            "guardrails_configured": bool(demo_api_key and demo_project_id),
            # Scans need only the key (no project ID: Lakera's default policy).
            "guardrails_key_configured": bool(demo_api_key),
            "azure_cs_configured": bool(azure_cs_key and azure_cs_endpoint),
            "azure_configured": bool(azure_api_key and azure_endpoint and azure_deployment),
            "project_id_set": bool(demo_project_id),
            "masked": {
                key: secret_setting_status(key)["masked"]
                for _field, key in SECRET_SETTING_FIELDS
            },
        }
    )


def get_azure_content_safety_client():
    endpoint = keyed_endpoint("AZURE_CONTENT_SAFETY_ENDPOINT")
    key = get_setting("AZURE_CONTENT_SAFETY_KEY") or os.getenv(
        "AZURE_CONTENT_SAFETY_KEY"
    )
    if endpoint and key:
        return ContentSafetyClient(
            endpoint.strip().rstrip("/"), AzureKeyCredential(key.strip())
        )
    return None


def scan_with_azure(text, config=None):
    """
    Scan text with Azure AI Content Safety.
    Accepts an optional config dictionary to avoid database access in threads.
    """
    import time

    start_time = time.time()
    res_obj = {
        "vendor": "Azure AI",
        "score": 0,
        "flagged": False,
        "details": [],
    }

    if config:
        # https only: the key goes in the Ocp-Apim-Subscription-Key header.
        endpoint = https_endpoint(config.get("endpoint") or "")
        key = (config.get("key") or "").strip()
    else:
        # Fallback for direct calls (might fail in threads)
        client = get_azure_content_safety_client()
        if not client:
            res_obj["error"] = "Azure Content Safety not configured"
            res_obj["execution_time"] = 0
            return res_obj
        endpoint = None  # Internal to client
        key = None  # Internal to client

    try:
        if config and (not endpoint or not key):
            res_obj.update(
                {
                    "error": "Azure Content Safety not configured",
                    "details": ["Missing API Key/Endpoint"],
                    "execution_time": 0,
                }
            )
            return res_obj

        # Debug logging for endpoint setup
        if config:
            is_hex = all(c in "0123456789abcdefABCDEF" for c in key)
            logging.info(
                "Azure CS: Initializing with endpoint=%s, key=%s, is_hex=%s",
                _clean_log_text(endpoint, 200),
                secure_settings.mask(key),
                is_hex,
            )
            client = ContentSafetyClient(endpoint, AzureKeyCredential(key))
            if not is_hex:
                logging.warning(
                    "Azure CS: WARNING - Key is not a standard hex string. Ensure you copied a 'KEY' from the Azure Portal, not a Connection String or Project ID."
                )

        from azure.ai.contentsafety.models import AnalyzeTextOptions

        options = AnalyzeTextOptions(text=text)
        response = client.analyze_text(options)

        # Azure classifies into categories with severity 0-7
        # In v1.0.0+, these are in categories_analysis list
        details = []
        max_severity = 0

        if hasattr(response, "categories_analysis"):
            for cat in response.categories_analysis:
                # category can be an enum or string, handle both
                cat_name = getattr(
                    cat,
                    "category",
                    str(cat.get("category") if isinstance(cat, dict) else ""),
                )
                severity = getattr(
                    cat,
                    "severity",
                    cat.get("severity", 0) if isinstance(cat, dict) else 0,
                )
                details.append(f"{cat_name}: {severity}")
                if severity > max_severity:
                    max_severity = severity
        else:
            # Fallback for older SDK versions
            severities = []
            if hasattr(response, "hate_result") and response.hate_result:
                severities.append(response.hate_result.severity)
                details.append(f"Hate: {response.hate_result.severity}")
            if hasattr(response, "self_harm_result") and response.self_harm_result:
                severities.append(response.self_harm_result.severity)
                details.append(f"Self-Harm: {response.self_harm_result.severity}")
            if hasattr(response, "sexual_result") and response.sexual_result:
                severities.append(response.sexual_result.severity)
                details.append(f"Sexual: {response.sexual_result.severity}")
            if hasattr(response, "violence_result") and response.violence_result:
                severities.append(response.violence_result.severity)
                details.append(f"Violence: {response.violence_result.severity}")
            max_severity = max(severities) if severities else 0

        # Normalize score to 0-100 to match AI Guardrails (Azure is 0-7, so * 14.28 roughly)
        normalized_score = (max_severity / 7) * 100

        # --- New: Add Prompt Shield (Jailbreak Detection) ---
        # Note: Prompt Shield is a newer API not yet in the v1.0.0 SDK, so we use requests
        try:
            shield_url = (
                f"{endpoint}/contentsafety/text:shieldPrompt?api-version=2024-09-01"
            )
            shield_headers = {
                "Ocp-Apim-Subscription-Key": key,
                "Content-Type": "application/json",
            }
            # The API supports 'userPrompt' and 'documents'
            shield_body = {"userPrompt": text}

            shield_response = requests.post(
                shield_url, headers=shield_headers, json=shield_body, timeout=5
            )
            if shield_response.status_code == 200:
                shield_data = shield_response.json()
                user_result = shield_data.get("userPromptAnalysis", {})
                if user_result.get("attackDetected"):
                    details.append("⚠️ Prompt Injection/Jailbreak Detected")
                    # Boost score if jailbreak is detected to ensure it's flagged prominently
                    normalized_score = max(normalized_score, 100.0)
                    max_severity = max(max_severity, 7)  # Mark as high severity
                else:
                    details.append("✓ No Jailbreak Detected")
            else:
                logging.warning(
                    "Azure Prompt Shield API returned %s: %s",
                    shield_response.status_code,
                    _clean_log_text(shield_response.text, 300),
                )
        except Exception as shield_err:
            logging.error("Azure Prompt Shield Error: %s", _clean_log_text(shield_err))

        res_obj.update(
            {
                "score": round(normalized_score, 2),
                "flagged": max_severity > 0,
                "details": details,
                "execution_time": round(time.time() - start_time, 3),
                "raw_response": str(
                    response
                ),  # ContentSafetyClient responses are models, simplify for JSON
            }
        )
        return res_obj
    except Exception as e:
        logging.error("Azure Content Safety Error: %s", _clean_log_text(e, 300))
        res_obj.update(
            {
                "error": _clean_log_text(e, 300),
                "details": ["Error during scan"],
                "execution_time": round(time.time() - start_time, 3),
            }
        )
        return res_obj


def scan_guardrails_wrapper(text, config):
    import time

    start_time = time.time()
    res_obj = {
        "vendor": "AI Guardrails Demo (Security Partner)",
        "score": 0,
        "flagged": False,
        "details": [],
        "execution_time": 0,
    }
    if not config.get("api_key"):
        res_obj["error"] = "AI Guardrails API Key not configured"
        return res_obj

    try:
        headers = {
            "Authorization": f"Bearer {config['api_key']}",
            "Content-Type": "application/json",
        }
        payload = guard_payload(
            [{"role": "user", "content": text}], config.get("project_id")
        )
        resp = requests.post(
            config.get("url") or guard_api_url(), headers=headers, json=payload, timeout=10
        )
        res_obj["execution_time"] = round(time.time() - start_time, 3)

        if resp.status_code == 200:
            res = resp.json()
            max_score = 0
            flagged = res.get("flagged", False)

            if res.get("breakdown"):
                max_score = (
                    max([item.get("score", 0) for item in res["breakdown"]]) * 100
                )

            # If flagged but score is 0, set to 100 as a fallback
            if flagged and max_score == 0:
                max_score = 100

            # Build details - only show detected categories (no percentage, like playground)
            detected_categories = []
            for item in res.get("breakdown", []):
                detector = item.get("detector_type", "").split("/")[-1]
                detected = item.get("detected", False)
                if detected:
                    detected_categories.append(f"⚠️ {detector.replace('_', ' ')}")

            if not detected_categories:
                detected_categories = ["✓ No threats detected"]

            res_obj.update(
                {
                    "score": round(max_score, 2),
                    "flagged": flagged,
                    "details": detected_categories,
                    "raw_response": res,  # Include for expandable view
                }
            )
        else:
            err = _guard_error(resp.status_code, response=resp)
            res_obj["error"] = f"AI Guardrails API error: {resp.status_code}"
            res_obj["guardrails_error"] = err
            res_obj["details"] = [_clean_log_text(err.get("error") or "", 200)]
    except Exception as e:
        logging.error("AI Guardrails Wrapper Error: %s", _clean_log_text(e, 300))
        res_obj["error"] = _clean_log_text(e, 300)
        res_obj["details"] = ["Network error"]
        res_obj["execution_time"] = round(time.time() - start_time, 3)
    logging.info(f"AI Guardrails Scan Duration: {res_obj.get('execution_time')}")
    return res_obj


# LLM Guard Model Metadata
LLM_GUARD_MODELS = {
    "PromptInjection": {
        "name": "Prompt Injection",
        "description": "Detects prompt injection attacks using transformer models.",
        "options": [
            {
                "id": "deberta-v3-base",
                "name": "Standard (Deberta-v3)",
                "size": "738MB",
                "model": "protectai/deberta-v3-base-prompt-injection-v2",
                "default": True,
            },
        ],
        "active_model": "deberta-v3-base",
        "active": True,
    },
    "Toxicity": {
        "name": "Toxicity Detector",
        "description": "Identifies hateful, aggressive, or offensive content.",
        "options": [
            {
                "id": "unbiased-toxic-roberta",
                "name": "Standard (Roberta)",
                "size": "499MB",
                "model": "unitary/unbiased-toxic-roberta",
                "default": True,
            },
        ],
        "active_model": "unbiased-toxic-roberta",
        "active": False,
    },
    "BanTopics": {
        "name": "Topic Filtering",
        "description": "Blocks specific topics like violence, hate, or criminal activity.",
        "model": "MoritzLaurer/roberta-base-zeroshot-v2.0-c",
        "size": "499MB",
        "active": False,
    },
}

# Global LLM Guard Scanner instances
LLM_GUARD_PIPELINE = {}


def get_llm_guard_pipeline():
    """
    Initialize and return the LLM Guard scanner.
    """
    global LLM_GUARD_PIPELINE

    # Initialize enabled scanners if not already present
    # Prompt Injection
    if (
        LLM_GUARD_MODELS["PromptInjection"].get("active", False)
        and "PromptInjection" not in LLM_GUARD_PIPELINE
    ):
        try:
            model_id = LLM_GUARD_MODELS["PromptInjection"].get(
                "active_model", "deberta-v3-base"
            )

            # Find the model path/name from options
            model_name_or_path = None
            for opt in LLM_GUARD_MODELS["PromptInjection"]["options"]:
                if opt["id"] == model_id:
                    model_name_or_path = opt["model"]
                    break

            if model_name_or_path:
                logging.info(
                    f"Initializing PromptInjection scanner with {model_name_or_path}..."
                )
                LLM_GUARD_PIPELINE["PromptInjection"] = PromptInjection(
                    model=Model(path=model_name_or_path)
                )
            else:
                logging.info("Initializing default PromptInjection scanner...")
                LLM_GUARD_PIPELINE["PromptInjection"] = PromptInjection()

        except Exception as e:
            logging.error(f"Failed to initialize PromptInjection: {e}")
            import traceback

            traceback.print_exc()

    # Toxicity
    if (
        LLM_GUARD_MODELS["Toxicity"].get("active", False)
        and "Toxicity" not in LLM_GUARD_PIPELINE
    ):
        try:
            from llm_guard.input_scanners import Toxicity

            model_id = LLM_GUARD_MODELS["Toxicity"].get(
                "active_model", "unbiased-toxic-roberta"
            )
            model_name_or_path = None
            for opt in LLM_GUARD_MODELS["Toxicity"]["options"]:
                if opt["id"] == model_id:
                    model_name_or_path = opt["model"]
                    break

            logging.info(f"Initializing Toxicity scanner with {model_name_or_path}...")
            scanner = Toxicity(
                model=Model(path=model_name_or_path) if model_name_or_path else None
            )
            # Patch internal pipeline to return nested list
            original_pipe = scanner._pipeline

            def patched_pipe(*args, **kwargs):
                res = original_pipe(*args, **kwargs)
                if (
                    res
                    and isinstance(res, list)
                    and len(res) > 0
                    and isinstance(res[0], dict)
                ):
                    return [res]
                return res

            scanner._pipeline = patched_pipe
            LLM_GUARD_PIPELINE["Toxicity"] = scanner
        except Exception as e:
            logging.error(f"Failed to initialize Toxicity: {e}")
            import traceback

            traceback.print_exc()

    # BanTopics
    if (
        LLM_GUARD_MODELS["BanTopics"].get("active", False)
        and "BanTopics" not in LLM_GUARD_PIPELINE
    ):
        try:
            from llm_guard.input_scanners import BanTopics

            logging.info(
                f"Initializing BanTopics scanner with {LLM_GUARD_MODELS['BanTopics']['model']}..."
            )
            # Detects violence, hate, crime by default with zero-shot
            LLM_GUARD_PIPELINE["BanTopics"] = BanTopics(
                model=Model(path=LLM_GUARD_MODELS["BanTopics"]["model"]),
                topics=["violence", "hate", "crime"],
            )
        except Exception as e:
            logging.error(f"Failed to initialize BanTopics: {e}")
            import traceback

            traceback.print_exc()

    return list(LLM_GUARD_PIPELINE.values())


@app.route("/api/models/status", methods=["GET"])
def get_models_status():
    """Get the download status of all LLM Guard models."""
    status = []
    hf_home = os.getenv("HF_HOME", "/app/models_cache")

    for key, meta in LLM_GUARD_MODELS.items():
        # Check if the model directory exists in HF_HOME
        # This is a bit simplified; in reality, we'd check for specific files
        is_downloaded = False
        if "options" in meta:
            for opt in meta["options"]:
                # Check for cached files (huggingface style: models--user--modelname)
                model_slug = opt["model"].replace("/", "--")
                cache_dir = os.path.join(hf_home, "hub", f"models--{model_slug}")

                # More robust check: look for snapshots directory and ensure it has subdirs
                snapshot_dir = os.path.join(cache_dir, "snapshots")
                is_downloaded = os.path.exists(snapshot_dir) and os.listdir(
                    snapshot_dir
                )

                status.append(
                    {
                        "id": opt["id"],
                        "parent_key": key,
                        "name": opt["name"],
                        "size": opt["size"],
                        "downloaded": bool(is_downloaded),
                        "active": meta.get("active", False)
                        and (meta["active_model"] == opt["id"]),
                        "description": meta["description"],
                    }
                )
        else:
            model_slug = meta["model"].replace("/", "--")
            cache_dir = os.path.join(hf_home, "hub", f"models--{model_slug}")

            snapshot_dir = os.path.join(cache_dir, "snapshots")
            is_downloaded = os.path.exists(snapshot_dir) and os.listdir(snapshot_dir)

            status.append(
                {
                    "id": key,
                    "name": meta["name"],
                    "size": meta["size"],
                    "downloaded": bool(is_downloaded),
                    "active": meta.get(
                        "active", False
                    ),  # Uses 'active' flag directly from metadata
                    "description": meta["description"],
                }
            )

    return jsonify(status)


@app.route("/api/models/toggle", methods=["POST"])
def toggle_model():
    """Enable or disable a specific LLM Guard model."""
    data = _json_body()
    if data is None:
        return _json_body_required()
    model_id = data.get("id")
    enabled = _as_bool(data.get("enabled", False))

    if not model_id or not isinstance(model_id, str) or len(model_id) > 100:
        return jsonify({"error": "Model ID is required"}), 400

    # Handle main models (top-level keys)
    if model_id in LLM_GUARD_MODELS:
        LLM_GUARD_MODELS[model_id]["active"] = enabled

        # Update pipeline immediately
        if enabled:
            # Will be initialized on next get_llm_guard_pipeline call
            pass
        else:
            # Remove from pipeline if disabled
            if model_id in LLM_GUARD_PIPELINE:
                del LLM_GUARD_PIPELINE[model_id]
                logging.info("Disabled %s scanner", _clean_log_text(model_id, 100))

    # Handle sub-options (like PromptInjection specific models)
    else:
        # Find which parent this belongs to
        parent_key = None
        for key, meta in LLM_GUARD_MODELS.items():
            if "options" in meta:
                for opt in meta["options"]:
                    if opt["id"] == model_id:
                        parent_key = key
                        break

        if parent_key:
            if enabled:
                # Enable the parent category and set the specific model
                LLM_GUARD_MODELS[parent_key]["active"] = True
                LLM_GUARD_MODELS[parent_key]["active_model"] = model_id

                # Force re-init using new model
                if parent_key in LLM_GUARD_PIPELINE:
                    del LLM_GUARD_PIPELINE[parent_key]
            else:
                # Disabling a specific model disables the entire category
                # (since only one model can be active per category for now)
                LLM_GUARD_MODELS[parent_key]["active"] = False
                if parent_key in LLM_GUARD_PIPELINE:
                    del LLM_GUARD_PIPELINE[parent_key]

    return jsonify(
        {
            "success": True,
            "active_models": [
                k for k, v in LLM_GUARD_MODELS.items() if v.get("active", False)
            ],
        }
    )


@app.route("/api/models/download", methods=["POST"])
def download_model():
    """Trigger a download for a specific LLM Guard model."""
    data = _json_body()
    if data is None:
        return _json_body_required()
    model_id = data.get("id")
    if not model_id or not isinstance(model_id, str) or len(model_id) > 100:
        return jsonify({"error": "Model ID is required"}), 400

    # We simulate/trigger the download by initializing the scanner
    # In a production app, we would use a background task with progress updates
    try:
        logging.info("UI Triggered Download: %s", _clean_log_text(model_id, 100))
        if model_id == "deberta-v3-base":
            # For PromptInjection models, we can use a temporary instance to download
            # and then update the active scanner
            from llm_guard.input_scanners import PromptInjection

            # We would need to find the HF model path
            hf_path = None
            for opt in LLM_GUARD_MODELS["PromptInjection"]["options"]:
                if opt["id"] == model_id:
                    hf_path = opt["model"]
                    break

            if hf_path:
                # Initializing with the specific model triggers download
                # Note: llm-guard PromptInjection uses a specific model path if provided
                # For this demo, let's assume it downloads the default or we use transformers
                from transformers import AutoModel, AutoTokenizer

                AutoTokenizer.from_pretrained(hf_path)
                AutoModel.from_pretrained(hf_path)

                # Update metadata
                LLM_GUARD_MODELS["PromptInjection"]["active_model"] = model_id
                # Force re-init of pipeline scanner next time it's called
                if "PromptInjection" in LLM_GUARD_PIPELINE:
                    del LLM_GUARD_PIPELINE["PromptInjection"]

            return jsonify(
                {
                    "success": True,
                    "message": f"Model {model_id} downloaded/switched successfully",
                }
            )

        elif model_id in ["Toxicity", "BanTopics"]:
            # Trigger download
            if model_id == "Toxicity":
                scanner = Toxicity()
                # Patch internal pipeline to return nested list
                original_pipe = scanner._pipeline

                def patched_pipe(*args, **kwargs):
                    res = original_pipe(*args, **kwargs)
                    if (
                        res
                        and isinstance(res, list)
                        and len(res) > 0
                        and isinstance(res[0], dict)
                    ):
                        return [res]
                    return res

                scanner._pipeline = patched_pipe
                LLM_GUARD_PIPELINE["Toxicity"] = scanner
            else:
                LLM_GUARD_PIPELINE["BanTopics"] = BanTopics(topics=["violence"])

            return jsonify(
                {
                    "success": True,
                    "message": f"Scanner {model_id} downloaded successfully",
                }
            )

        return jsonify({"error": "Unknown model or scanner"}), 404
    except Exception as e:
        logging.error("Download Error: %s", _clean_log_text(e))
        return jsonify({"error": str(e)}), 500


def scan_with_llm_guard(text, config=None):
    """
    Scan text with LLM Guard PromptInjection scanner.
    """
    import time

    start_time = time.time()
    res_obj = {
        "vendor": "LLM Guard (Open Source)",
        "score": 0,
        "flagged": False,
        "details": [],
        "execution_time": 0,
    }
    try:
        pipeline = get_llm_guard_pipeline()

        if not pipeline:
            res_obj.update(
                {
                    "error": "No scanners initialized",
                    "details": ["Please enable a model"],
                    "execution_time": round(time.time() - start_time, 3),
                }
            )
            return res_obj

        max_score = 0
        any_flagged = False
        details = []

        # Iterate through all active scanners in pipeline
        breakdown = []
        # Ensure text is string (not bytes or other type)
        text_input = str(text) if text is not None else ""

        for scanner in pipeline:
            scanner_name = scanner.__class__.__name__
            try:
                # scan() returns (sanitized_text, is_valid, risk_score)
                _, is_valid, risk_score = scanner.scan(text_input)

                start_score = max(0, min(1, risk_score))
                display_score = round(start_score * 100, 1)

                # Treat as flagged if invalid OR score > 0.5 (for some scanners that valid=True but high score)
                flagged = not is_valid or start_score > 0.5

                breakdown.append(
                    {
                        "detector_type": scanner_name,
                        "score": start_score,
                        "model": (
                            scanner._model.name
                            if hasattr(scanner, "_model")
                            and hasattr(scanner._model, "name")
                            else "default"
                        ),
                        "detected": flagged,
                    }
                )

                if flagged:
                    any_flagged = True
                    max_score = max(max_score, start_score)
                    details.append(f"⚠️ {scanner_name}: {display_score}%")
                else:
                    details.append(f"✓ {scanner_name}: {display_score}%")

            except Exception as e:
                import traceback

                tb = traceback.format_exc()
                logging.error(
                    "Error in scanner %s: %s %s",
                    scanner_name,
                    _clean_log_text(e, 300),
                    _clean_log_text(tb, 1500),
                )

                # Robustly handle the error breakdown
                breakdown.append(
                    {
                        "detector_type": scanner_name,
                        "error": str(e),
                        "detected": False,
                        "score": 0,
                    }
                )
                details.append(_clean_log_text(f"Error {scanner_name}: {e}", 200))

        if not any_flagged:
            # Keep details populated so we see what WAS run
            if not details:
                details = ["✓ All checks passed"]

        res_obj.update(
            {
                "score": round(max_score * 100, 2),
                "flagged": any_flagged,
                "method": "Multi-Scanner",
                "model": "pipeline",
                "details": details,
                "breakdown": breakdown,
                "execution_time": round(time.time() - start_time, 3),
            }
        )
        return res_obj
    except Exception as e:
        logging.error("LLM Guard Scan Error: %s", _clean_log_text(e))
        import traceback

        traceback.print_exc()
        res_obj.update(
            {
                "error": str(e),
                "details": ["Scan failed - check logs"],
                "execution_time": round(time.time() - start_time, 3),
            }
        )
        return res_obj


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Analyze a prompt for potential threats.
    ---
    tags:
      - Analysis
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            prompt:
              type: string
              example: "How do I make a bomb?"
            use_guardrails:
              type: boolean
              default: false
            use_guardrails_outbound:
              type: boolean
              default: false
            model_provider:
              type: string
              enum: ['openai', 'azure', 'gemini', 'ollama']
              default: 'azure'
            model_name:
              type: string
    responses:
      200:
        description: Analysis result
        schema:
          type: object
          properties:
            prompt:
              type: string
            guardrails_result:
              type: object
            guardrails_outbound_result:
              type: object
            openai_response:
              type: string
            flagged:
              type: boolean
      400:
        description: Missing prompt, or a scan was requested without an AI Guardrails key
      502:
        description: A requested AI Guardrails scan failed (see guardrails_error); the LLM was not called
    """
    data = _json_body()
    if data is None:
        return _json_body_required()
    prompt = data.get("prompt")
    # Validate before touching the prompt (a missing prompt used to crash here).
    if not isinstance(prompt, str) or not prompt.strip():
        return jsonify({"error": "Prompt is required"}), 400
    if len(prompt) > PROMPT_MAX_CHARS:
        return (
            jsonify({"error": "Prompt is too long (max %d characters)" % PROMPT_MAX_CHARS}),
            413,
        )
    use_guardrails = _as_bool(data.get("use_guardrails", False))
    use_guardrails_outbound = _as_bool(data.get("use_guardrails_outbound", False))
    model_provider = data.get("model_provider") or "azure"
    model_name = data.get("model_name") or None
    if not isinstance(model_provider, str) or len(model_provider) > 50:
        return jsonify({"error": "model_provider must be a short string"}), 400
    if model_name is not None and (not isinstance(model_name, str) or len(model_name) > 200):
        return jsonify({"error": "model_name must be a string of at most 200 characters"}), 400

    logging.info(
        "Analyze request: %s inbound=%s outbound=%s provider=%s",
        prompt_fingerprint(prompt),
        use_guardrails,
        use_guardrails_outbound,
        _clean_log_text(model_provider, 30),
    )

    # DB (DEMO_*) first, then env DEMO_* / LAKERA_* — see guard_credentials().
    api_key, demo_project_id = guard_credentials()
    if (use_guardrails or use_guardrails_outbound) and not api_key:
        # Fail closed: a requested scan that cannot run must not reach the LLM.
        return (
            jsonify(
                {
                    "error": "AI Guardrails API key not configured. Please go to Settings.",
                    "guardrails_error": {
                        "status": None,
                        "error": "not configured",
                        "request_id": None,
                        "message": "AI Guardrails API key not configured",
                    },
                }
            ),
            400,
        )

    guardrails_result = None
    guardrails_outbound_result = None
    guardrails_flagged = False
    guardrails_error = None
    guardrails_outbound_error = None
    url = guard_api_url()

    def _store(openai_text, error=None):
        """Save the run to the DB and the in-memory list used by the dashboard."""
        inbound_vectors = []
        outbound_vectors = []
        if guardrails_result and guardrails_result.get("breakdown"):
            for r in guardrails_result["breakdown"]:
                if r.get("detected") and r.get("detector_type"):
                    vector = r["detector_type"].split("/")[-1]
                    if vector not in inbound_vectors:
                        inbound_vectors.append(vector)
            guardrails_result["attack_vectors"] = inbound_vectors
        if guardrails_outbound_result and guardrails_outbound_result.get("breakdown"):
            for r in guardrails_outbound_result["breakdown"]:
                if r.get("detected") and r.get("detector_type"):
                    vector = r["detector_type"].split("/")[-1]
                    if vector not in outbound_vectors:
                        outbound_vectors.append(vector)
            guardrails_outbound_result["attack_vectors"] = outbound_vectors
        attack_vectors = list(set(inbound_vectors + outbound_vectors))
        db_result = {
            "flagged": bool(
                guardrails_flagged
                or (
                    guardrails_outbound_result
                    and guardrails_outbound_result.get("flagged", False)
                )
            ),
            "inbound_result": guardrails_result,
            "outbound_result": guardrails_outbound_result,
            "openai_response": openai_text,
            "attack_vectors": attack_vectors,
        }
        if guardrails_error or guardrails_outbound_error:
            db_result["guardrails_error"] = guardrails_error or guardrails_outbound_error
        log_entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "prompt": prompt,
            "result": db_result,
            "attack_vectors": attack_vectors,
            "request": {
                "prompt": prompt,
                "use_guardrails": use_guardrails,
                "use_guardrails_outbound": use_guardrails_outbound,
            },
            "response": {
                "guardrails_inbound": guardrails_result,
                "guardrails_outbound": guardrails_outbound_result,
                "openai": openai_text,
            },
            "error": error,
        }
        try:
            save_log_to_db(log_entry)
        except Exception as e:
            db.session.rollback()
            logging.error("Failed to save log to DB: %s", _clean_log_text(e, 200))
        with _ANALYSIS_LOGS_LOCK:
            analysis_logs.insert(0, log_entry)
            if len(analysis_logs) > 100:
                analysis_logs.pop()

    # 1. AI Guardrails Inbound Scan (Conditional)
    if use_guardrails:
        started = time.monotonic()
        guardrails_result, guardrails_error = call_guard(
            api_key, demo_project_id, [{"role": "user", "content": prompt}], url=url
        )
        if guardrails_error is not None:
            message = (
                "AI Guardrails inbound scan failed (%s). The prompt was not sent to the model."
                % guardrails_error["message"]
            )
            _store(None, error=message)
            return (
                jsonify(
                    {
                        "error": message,
                        "prompt": prompt,
                        "guardrails_result": None,
                        "guardrails_outbound_result": None,
                        "guardrails_error": guardrails_error,
                        "guardrails_outbound_error": None,
                        "openai_response": None,
                        "flagged": False,
                    }
                ),
                502,
            )
        guardrails_flagged = bool(guardrails_result.get("flagged", False))
        logging.info(
            "Guardrails inbound scan ok flagged=%s detected=%s ms=%d %s",
            guardrails_flagged,
            _clean_log_text(",".join(_detected_types(guardrails_result)) or "-", 200),
            int((time.monotonic() - started) * 1000),
            prompt_fingerprint(prompt),
        )

    # 2. OpenAI Chat (If safe or skipped)
    openai_response = None
    if not guardrails_flagged:
        if model_provider == "azure":
            azure_api_key = get_setting("AZURE_OPENAI_API_KEY") or os.getenv(
                "AZURE_OPENAI_API_KEY"
            )
            azure_endpoint = keyed_endpoint("AZURE_OPENAI_ENDPOINT")
            azure_deployment = get_setting("AZURE_OPENAI_DEPLOYMENT") or os.getenv(
                "AZURE_OPENAI_DEPLOYMENT"
            )

            if azure_api_key and azure_endpoint and azure_deployment:
                try:
                    openai_url = (
                        f"{azure_endpoint}/openai/deployments/"
                        f"{quote(str(azure_deployment).strip(), safe='')}"
                        "/chat/completions?api-version=2024-02-15-preview"
                    )
                    openai_headers = {
                        "api-key": azure_api_key,
                        "Content-Type": "application/json",
                    }
                    openai_payload = {"messages": [{"role": "user", "content": prompt}]}
                    oa_response = requests.post(
                        openai_url,
                        headers=openai_headers,
                        json=openai_payload,
                        timeout=LLM_TIMEOUT,
                    )
                    oa_response.raise_for_status()
                    openai_data = oa_response.json()
                    openai_response = openai_data["choices"][0]["message"]["content"]
                except Exception as e:
                    logging.error("Azure OpenAI API Error: %s", _clean_log_text(e))
                    openai_response = f"Error calling Azure OpenAI: {_clean_log_text(e)}"
            else:
                openai_response = "Azure OpenAI not configured."

        elif model_provider == "gemini":
            gemini_api_key = get_setting("GEMINI_API_KEY") or os.getenv(
                "GEMINI_API_KEY"
            )

            if gemini_api_key:
                try:
                    # Check if re-configuration is needed (initialize client)
                    if (
                        GEMINI_CACHE["api_key"] != gemini_api_key
                        or GEMINI_CACHE["model_instance"] is None
                    ):
                        GEMINI_CACHE["api_key"] = gemini_api_key
                        GEMINI_CACHE["model_instance"] = gemini_client(gemini_api_key)

                    # Determine model name
                    target_model_name = (
                        model_name
                        if model_name and model_name.startswith("models/")
                        else f'models/{model_name or "gemini-2.0-flash"}'
                    )

                    client = GEMINI_CACHE["model_instance"]
                    response = client.models.generate_content(
                        model=target_model_name, contents=prompt
                    )
                    openai_response = response.text

                except Exception as e:
                    logging.error("Gemini API Error: %s", _clean_log_text(e))
                    openai_response = f"Error calling Gemini: {_clean_log_text(e)}"
            else:
                openai_response = "Gemini API key not configured."

        elif model_provider == "ollama":
            ollama_url = resolve_ollama_url()
            ollama_timeout = ollama_timeout_seconds()
            try:
                payload = {
                    "model": model_name
                    or os.getenv("OLLAMA_MODEL", "richardyoung/mythos-9b-unhinged-abliterated:latest"),
                    "prompt": prompt,
                    "stream": False,
                }
                response = requests.post(
                    f"{ollama_url}/api/generate", json=payload, timeout=ollama_timeout
                )
                if response.status_code == 200:
                    openai_response = response.json().get("response", "")
                else:
                    openai_response = (
                        f"Error calling Ollama: {_clean_log_text(response.text)}"
                    )
            except Exception as e:
                logging.error("Ollama API Error: %s", _clean_log_text(e))
                openai_response = f"Error calling Ollama: {_clean_log_text(e)}"

        elif model_provider == "anthropic":
            anthropic_api_key = get_setting("ANTHROPIC_API_KEY") or os.getenv(
                "ANTHROPIC_API_KEY"
            )
            if anthropic_api_key:
                try:
                    # Anthropic Messages API — raw REST, same pattern as the
                    # Azure/Ollama branches (no SDK dependency). x-api-key +
                    # anthropic-version headers; max_tokens is required.
                    an_response = requests.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "x-api-key": anthropic_api_key,
                            "anthropic-version": "2023-06-01",
                            "content-type": "application/json",
                        },
                        json={
                            "model": model_name or "claude-opus-4-8",
                            "max_tokens": 1024,
                            "messages": [{"role": "user", "content": prompt}],
                        },
                        timeout=LLM_TIMEOUT,
                    )
                    an_response.raise_for_status()
                    an_data = an_response.json()
                    # content is a list of blocks; take the first text block.
                    openai_response = next(
                        (
                            b.get("text", "")
                            for b in an_data.get("content", [])
                            if b.get("type") == "text"
                        ),
                        "",
                    )
                except Exception as e:
                    logging.error("Anthropic API Error: %s", _clean_log_text(e))
                    openai_response = f"Error calling Anthropic: {_clean_log_text(e)}"
            else:
                openai_response = "Anthropic API key not configured."

        else:  # Default to OpenAI
            openai_api_key = get_setting("OPENAI_API_KEY") or os.getenv(
                "OPENAI_API_KEY"
            )
            if openai_api_key:
                try:
                    openai_url = os.getenv(
                        "OPENAI_API_URL", "https://api.openai.com/v1/chat/completions"
                    )
                    openai_headers = {
                        "Authorization": f"Bearer {openai_api_key}",
                        "Content-Type": "application/json",
                    }
                    openai_payload = {
                        "model": model_name or "gpt-4o-mini",
                        "messages": [{"role": "user", "content": prompt}],
                    }
                    logging.info(
                        "Calling OpenAI model=%s %s",
                        _clean_log_text(openai_payload["model"], 100),
                        prompt_fingerprint(prompt),
                    )
                    oa_response = requests.post(
                        openai_url,
                        headers=openai_headers,
                        json=openai_payload,
                        timeout=LLM_TIMEOUT,
                    )
                    if oa_response.status_code == 429:
                        openai_response = "Error calling OpenAI: 429 Client Error (Too Many Requests). This usually means you've hit your rate limit or need to add credits to your OpenAI account."
                    else:
                        oa_response.raise_for_status()
                        openai_data = oa_response.json()
                        openai_response = openai_data["choices"][0]["message"][
                            "content"
                        ]

                except Exception as e:
                    logging.error("OpenAI API Error: %s", _clean_log_text(e))
                    if not openai_response:
                        openai_response = f"Error calling OpenAI: {_clean_log_text(e)}"
            else:
                openai_response = "OpenAI API Key not configured."

    # 3. AI Guardrails Outbound Scan (Conditional)
    if (
        use_guardrails_outbound
        and openai_response
        and not openai_response.startswith("Error")
        and not openai_response.endswith("configured.")
    ):
        started = time.monotonic()
        guardrails_outbound_result, guardrails_outbound_error = call_guard(
            api_key,
            demo_project_id,
            [{"role": "assistant", "content": openai_response}],
            url=url,
        )
        if guardrails_outbound_error is not None:
            # Fail closed: an unscanned model response is withheld.
            message = (
                "AI Guardrails outbound scan failed (%s). The model response was withheld."
                % guardrails_outbound_error["message"]
            )
            _store(None, error=message)
            return (
                jsonify(
                    {
                        "error": message,
                        "prompt": prompt,
                        "guardrails_result": guardrails_result,
                        "guardrails_outbound_result": None,
                        "guardrails_error": None,
                        "guardrails_outbound_error": guardrails_outbound_error,
                        "openai_response": None,
                        "flagged": guardrails_flagged,
                    }
                ),
                502,
            )
        logging.info(
            "Guardrails outbound scan ok flagged=%s detected=%s ms=%d response_len=%d",
            bool(guardrails_outbound_result.get("flagged", False)),
            _clean_log_text(",".join(_detected_types(guardrails_outbound_result)) or "-", 200),
            int((time.monotonic() - started) * 1000),
            len(openai_response),
        )

    # 4. Log and Return
    _store(openai_response)

    return jsonify(
        {
            "prompt": prompt,
            "guardrails_result": guardrails_result,
            "guardrails_outbound_result": guardrails_outbound_result,
            "guardrails_error": None,
            "guardrails_outbound_error": None,
            "openai_response": openai_response,
            "flagged": guardrails_flagged,
        }
    )


@app.route("/api/logs", methods=["GET"])
def get_logs():
    """
    Get paginated logs.
    ---
    tags:
      - Logs
    parameters:
      - name: start_date
        in: query
        type: string
        format: date
        description: Start date (YYYY-MM-DD)
      - name: end_date
        in: query
        type: string
        format: date
        description: End date (YYYY-MM-DD)
      - name: page
        in: query
        type: integer
        default: 1
      - name: per_page
        in: query
        type: integer
        default: 20
    responses:
      200:
        description: List of logs and pagination info
    """
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))

    query = Log.query
    try:
        if start_date:
            query = query.filter(
                Log.timestamp >= datetime.strptime(start_date, "%Y-%m-%d")
            )
        if end_date:
            query = query.filter(
                Log.timestamp
                <= datetime.strptime(end_date + " 23:59:59", "%Y-%m-%d %H:%M:%S")
            )

        # Get total count before pagination
        total_logs = query.count()
        total_pages = (total_logs + per_page - 1) // per_page  # Ceiling division

        # Apply pagination
        logs = (
            query.order_by(Log.timestamp.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )

        return jsonify(
            {
                "logs": [log.to_dict() for log in logs],
                "pagination": {
                    "current_page": page,
                    "per_page": per_page,
                    "total_logs": total_logs,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1,
                },
            }
        )
    except Exception as e:
        logging.error(f"Failed to fetch logs from DB: {e}")
        return jsonify(
            {
                "logs": [],
                "pagination": {
                    "current_page": 1,
                    "per_page": per_page,
                    "total_logs": 0,
                    "total_pages": 0,
                    "has_next": False,
                    "has_prev": False,
                },
            }
        )


@app.route("/api/logs/<log_id>", methods=["DELETE"])
def delete_log(log_id):
    """
    Delete a specific log entry.
    ---
    tags:
      - Logs
    parameters:
      - name: log_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Log deleted successfully
    """
    Log.query.filter_by(uuid=log_id).delete()
    db.session.commit()
    global analysis_logs
    analysis_logs = [log for log in analysis_logs if log["id"] != log_id]
    return jsonify({"success": True})


@app.route("/api/logs", methods=["DELETE"])
def clear_logs():
    """
    Clear all logs.
    ---
    tags:
      - Logs
    responses:
      200:
        description: All logs cleared successfully
    """
    db.session.query(Log).delete()
    db.session.commit()
    global analysis_logs
    analysis_logs = []
    return jsonify({"success": True})


@app.route("/api/logs/export/json", methods=["GET"])
def export_logs_json():
    """
    Export logs as JSON.
    ---
    tags:
      - Logs
    parameters:
      - name: start_date
        in: query
        type: string
        format: date
      - name: end_date
        in: query
        type: string
        format: date
    responses:
      200:
        description: JSON file download
    """
    from flask import make_response

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    query = Log.query
    try:
        if start_date:
            query = query.filter(
                Log.timestamp >= datetime.strptime(start_date, "%Y-%m-%d")
            )
        if end_date:
            query = query.filter(
                Log.timestamp
                <= datetime.strptime(end_date + " 23:59:59", "%Y-%m-%d %H:%M:%S")
            )
        logs = [log.to_dict() for log in query.order_by(Log.timestamp.desc()).all()]
    except Exception as e:
        logging.error(f"Export JSON failed: {e}")
        logs = []

    json_data = json.dumps(logs, indent=2)
    filename = f"guardrails_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    response = make_response(json_data)
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-Type"] = "application/json"
    return response


CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe_cell(value):
    """Neutralise spreadsheet formula injection: prefix risky cells with a quote."""
    if value is None:
        return ""
    text = str(value)
    if text.startswith(CSV_FORMULA_PREFIXES):
        return "'" + text
    return text


@app.route("/api/logs/export/csv", methods=["GET"])
def export_logs_csv():
    """
    Export logs as CSV.
    ---
    tags:
      - Logs
    parameters:
      - name: start_date
        in: query
        type: string
        format: date
      - name: end_date
        in: query
        type: string
        format: date
    responses:
      200:
        description: CSV file download
    """
    from flask import make_response
    import csv, io

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    query = Log.query
    try:
        if start_date:
            query = query.filter(
                Log.timestamp >= datetime.strptime(start_date, "%Y-%m-%d")
            )
        if end_date:
            query = query.filter(
                Log.timestamp
                <= datetime.strptime(end_date + " 23:59:59", "%Y-%m-%d %H:%M:%S")
            )
        logs = query.order_by(Log.timestamp.desc()).all()
    except Exception as e:
        logging.error(f"Export CSV failed: {e}")
        logs = []

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["Timestamp", "Prompt", "Status", "Attack Vectors", "Flagged", "Error"]
    )
    cell = csv_safe_cell
    for log in logs:
        status = "Error" if log.error else "Success"
        flagged = (
            "Yes" if (log.result_json and log.result_json.get("flagged")) else "No"
        )
        attack_vectors = ", ".join(log.attack_vectors or [])
        error = log.error or ""
        writer.writerow(
            [
                cell(log.timestamp.strftime("%Y-%m-%d %H:%M:%S")),
                cell(log.prompt),
                cell(status),
                cell(attack_vectors),
                cell(flagged),
                cell(error),
            ]
        )

    csv_data = buffer.getvalue()
    filename = f"guardrails_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    response = make_response(csv_data)
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@app.route("/api/triggers", methods=["GET"])
def get_triggers():
    """
    Get list of attack triggers.
    ---
    tags:
      - Triggers
    responses:
      200:
        description: List of attack triggers
    """
    try:
        with open("data/triggers.json", "r") as f:
            triggers = json.load(f)
        return jsonify(triggers)
    except FileNotFoundError:
        return jsonify([])
    except Exception as e:
        logging.error(f"Failed to load triggers: {e}")
        return jsonify([])


@app.route("/api/analytics", methods=["GET"])
def get_analytics():
    """
    Get dashboard analytics data.
    ---
    tags:
      - Analytics
    parameters:
      - name: range
        in: query
        type: string
        enum: ['1h', '24h', '7d']
        default: '24h'
    responses:
      200:
        description: Analytics data
    """
    range_param = request.args.get("range", "24h")
    now = datetime.now()
    if range_param == "1h":
        cutoff = now - timedelta(hours=1)
    elif range_param == "7d":
        cutoff = now - timedelta(days=7)
    else:
        cutoff = now - timedelta(hours=24)
    # Use in‑memory logs for timeline calculations
    filtered_logs = [
        log
        for log in analysis_logs
        if datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S") > cutoff
    ]
    total_scans = len(filtered_logs)
    threats_blocked = sum(
        1
        for log in filtered_logs
        if (log.get("result") or {}).get("flagged")
        or (
            (log.get("result") or {}).get("results")
            and any(
                r.get("flagged") for r in (log.get("result") or {}).get("results", [])
            )
        )
    )
    threat_categories = {}
    for log in filtered_logs:
        if log.get("attack_vectors"):
            for vector in log["attack_vectors"]:
                threat_categories[vector] = threat_categories.get(vector, 0) + 1
    attack_vector_distribution = {}
    for log in filtered_logs:
        if log.get("attack_vectors"):
            for vector in log["attack_vectors"]:
                attack_vector_distribution[vector] = (
                    attack_vector_distribution.get(vector, 0) + 1
                )
    timeline = {}
    for log in filtered_logs:
        timestamp = log["timestamp"]
        if range_param == "1h":
            key = timestamp[11:16]
        elif range_param == "7d":
            key = timestamp[:10]
        else:
            key = timestamp[:13]
        timeline[key] = timeline.get(key, 0) + 1
    return jsonify(
        {
            "total_scans": total_scans,
            "threats_blocked": threats_blocked,
            "success_rate": round(
                (threats_blocked / total_scans * 100) if total_scans > 0 else 0, 1
            ),
            "threat_distribution": threat_categories,
            "attack_vector_distribution": attack_vector_distribution,
            "timeline": timeline,
            "recent_logs": analysis_logs[:10],
        }
    )


@app.route("/api/scan/guardrails", methods=["POST"])
def scan_guardrails_endpoint():
    data = _json_body()
    if data is None:
        return _json_body_required()
    prompt = data.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        return jsonify({"error": "No prompt provided"}), 400
    if len(prompt) > PROMPT_MAX_CHARS:
        return jsonify({"error": "Prompt is too long (max %d characters)" % PROMPT_MAX_CHARS}), 413

    _gc_key, _gc_project = guard_credentials()
    guardrails_config = {
        "api_key": _gc_key,
        "project_id": _gc_project,
        "url": guard_api_url(),
    }

    if not guardrails_config["api_key"]:
        return jsonify({"error": "AI Guardrails API key not configured"}), 400

    result = scan_guardrails_wrapper(prompt, guardrails_config)
    return jsonify(result)


@app.route("/api/scan/azure", methods=["POST"])
def scan_azure_endpoint():
    data = _json_body()
    if data is None:
        return _json_body_required()
    prompt = data.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        return jsonify({"error": "No prompt provided"}), 400
    if len(prompt) > PROMPT_MAX_CHARS:
        return jsonify({"error": "Prompt is too long (max %d characters)" % PROMPT_MAX_CHARS}), 413

    azure_config = {
        "endpoint": keyed_endpoint("AZURE_CONTENT_SAFETY_ENDPOINT"),
        "key": get_setting("AZURE_CONTENT_SAFETY_KEY")
        or os.getenv("AZURE_CONTENT_SAFETY_KEY"),
    }

    if not azure_config["key"] or not azure_config["endpoint"]:
        return jsonify({"error": "Azure Content Safety not configured"}), 400

    result = scan_with_azure(prompt, azure_config)
    return jsonify(result)


@app.route("/api/scan/llmguard", methods=["POST"])
def scan_llmguard_endpoint():
    data = _json_body()
    if data is None:
        return _json_body_required()
    prompt = data.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        return jsonify({"error": "No prompt provided"}), 400
    if len(prompt) > PROMPT_MAX_CHARS:
        return jsonify({"error": "Prompt is too long (max %d characters)" % PROMPT_MAX_CHARS}), 413

    # LLM Guard is local, no config needed usually
    result = scan_with_llm_guard(prompt, {})
    return jsonify(result)


@app.route("/api/compare", methods=["POST"])
@limiter.limit("10 per minute")
def compare():
    # ... keep existing compare implementation for backward compatibility or direct API use ...
    data = _json_body()
    if data is None:
        return _json_body_required()
    prompt = data.get("prompt")
    use_azure = data.get("use_azure", True)
    use_llm_guard = data.get("use_llm_guard", True)

    if not isinstance(prompt, str) or not prompt.strip():
        return jsonify({"error": "No prompt provided"}), 400
    if len(prompt) > PROMPT_MAX_CHARS:
        return jsonify({"error": "Prompt is too long (max %d characters)" % PROMPT_MAX_CHARS}), 413

    _gc_key, _gc_project = guard_credentials()
    guardrails_config = {
        "api_key": _gc_key,
        "project_id": _gc_project,
        "url": guard_api_url(),
    }

    azure_config = {
        "endpoint": keyed_endpoint("AZURE_CONTENT_SAFETY_ENDPOINT"),
        "key": get_setting("AZURE_CONTENT_SAFETY_KEY")
        or os.getenv("AZURE_CONTENT_SAFETY_KEY"),
    }

    # Execute scans in parallel
    results = []
    logging.info("Compare API: Launching parallel tasks")
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_guardrails = executor.submit(scan_guardrails_wrapper, prompt, guardrails_config)

            futures = {"AI Guardrails": future_guardrails}
            if use_azure and azure_config["key"]:
                futures["Azure"] = executor.submit(
                    scan_with_azure, prompt, azure_config
                )
            if use_llm_guard:
                futures["LLM Guard"] = executor.submit(scan_with_llm_guard, prompt, {})

            # Collect results
            for name, future in futures.items():
                try:
                    # Individual timeouts
                    timeout = 300 if name == "LLM Guard" else 15
                    res = future.result(timeout=timeout)
                    results.append(res)
                except Exception as e:
                    logging.error("%s thread error: %s", name, _clean_log_text(e))
                    results.append(
                        {
                            "vendor": (
                                name
                                if "LLM" in name
                                else (
                                    "Azure AI"
                                    if "Azure" in name
                                    else "AI Guardrails Demo (Security Partner)"
                                )
                            ),
                            "score": 0,
                            "flagged": False,
                            "error": str(e),
                            "execution_time": 0,
                        }
                    )

        # Log benchmark results to DB
        log_entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "prompt": prompt,
            "result": {"results": results, "multi_vendor": True},
            "attack_vectors": list(
                set(
                    [
                        v.split(": ")[0].replace("⚠️ ", "").replace("✓ ", "")
                        for r in results
                        for v in r.get("details", [])
                    ]
                )
            ),
            "request": data,
        }
        try:
            save_log_to_db(log_entry)
            # Also insert into in-memory logs for dashboard
            analysis_logs.insert(0, log_entry)
            if len(analysis_logs) > 100:
                analysis_logs.pop()
        except Exception as e:
            logging.error("Failed to log benchmark: %s", _clean_log_text(e))

    except Exception as e:
        logging.error("Parallel Execution Error: %s", _clean_log_text(e))
        return jsonify({"error": f"Internal parallel scan error: {str(e)}"}), 500

    return jsonify(
        {
            "prompt": prompt,
            "results": results,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    )


@app.route("/api/benchmark/history", methods=["GET"])
def get_benchmark_history():
    """
    Get recent benchmark runs from the database.
    """
    try:
        # SQLite doesn't always handle .contains() on JSON columns the same as Postgres
        # We fetch recent logs and filter in Python for robustness,
        # as benchmark volumes are typically low (limit 50 is safe)
        all_recent = Log.query.order_by(Log.timestamp.desc()).limit(50).all()
        benchmarks = [
            b for b in all_recent if b.result_json and "results" in b.result_json
        ]
        return jsonify([b.to_dict() for b in benchmarks[:20]])
    except Exception as e:
        logging.error(f"Failed to fetch benchmark history: {e}")
        return jsonify({"error": str(e)}), 500


BENCHMARK_PROMPT_MAX = 20000
BENCHMARK_RESULTS_MAX = 20
BENCHMARK_DETAILS_MAX = 50
BENCHMARK_DETAIL_CHARS = 200
BENCHMARK_BLOB_CHARS = 50000
_BENCHMARK_BLOB_KEYS = ("raw_response", "breakdown", "guardrails_error")


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate_benchmark_payload(data):
    """Return (prompt, clean_results, None) or (None, None, error message)."""
    if not isinstance(data, dict):
        return None, None, "A JSON object body is required"
    prompt = data.get("prompt")
    results = data.get("results")
    if not isinstance(prompt, str) or not prompt.strip():
        return None, None, "prompt must be a non-empty string"
    if len(prompt) > BENCHMARK_PROMPT_MAX:
        return None, None, "prompt must be at most %d characters" % BENCHMARK_PROMPT_MAX
    if not isinstance(results, list) or not results:
        return None, None, "results must be a non-empty list"
    if len(results) > BENCHMARK_RESULTS_MAX:
        return None, None, "results must have at most %d items" % BENCHMARK_RESULTS_MAX

    clean = []
    for index, item in enumerate(results):
        where = "results[%d]" % index
        if not isinstance(item, dict):
            return None, None, "%s must be an object" % where
        vendor = item.get("vendor", "")
        if vendor is None:
            vendor = ""
        if not isinstance(vendor, str) or len(vendor) > 100:
            return None, None, "%s.vendor must be a string of at most 100 characters" % where
        flagged = item.get("flagged", False)
        if not isinstance(flagged, bool):
            return None, None, "%s.flagged must be true or false" % where
        details = item.get("details", [])
        if details is None:
            details = []
        if not isinstance(details, list) or len(details) > BENCHMARK_DETAILS_MAX:
            return None, None, "%s.details must be a list of at most %d strings" % (
                where,
                BENCHMARK_DETAILS_MAX,
            )
        for detail in details:
            if not isinstance(detail, str) or len(detail) > BENCHMARK_DETAIL_CHARS:
                return None, None, "%s.details items must be strings of at most %d characters" % (
                    where,
                    BENCHMARK_DETAIL_CHARS,
                )
        entry = {"vendor": vendor, "flagged": flagged, "details": list(details)}
        for key in ("score", "execution_time"):
            if key in item and item[key] is not None:
                if not _is_number(item[key]):
                    return None, None, "%s.%s must be a number" % (where, key)
                entry[key] = item[key]
        error = item.get("error")
        if error is not None:
            if not isinstance(error, str):
                return None, None, "%s.error must be a string" % where
            entry["error"] = error[:1000]
        for key in ("method", "model"):
            value = item.get(key)
            if isinstance(value, str):
                entry[key] = value[:200]
        for key in _BENCHMARK_BLOB_KEYS:
            if key in item and item[key] is not None:
                try:
                    size = len(json.dumps(item[key]))
                except (TypeError, ValueError):
                    return None, None, "%s.%s is not valid JSON" % (where, key)
                entry[key] = item[key] if size <= BENCHMARK_BLOB_CHARS else "[omitted: too large]"
        clean.append(entry)
    return prompt, clean, None


@app.route("/api/benchmark/log", methods=["POST"])
def log_benchmark_result():
    """
    Log a consolidated benchmark result from the frontend.
    """
    data = _json_body()
    if data is None:
        return _json_body_required()
    prompt, results, problem = validate_benchmark_payload(data)
    if problem:
        return jsonify({"error": problem}), 400

    # Collect attack vectors from all results
    attack_vectors = list(
        set(
            [
                v.split(": ")[0].replace("⚠️ ", "").replace("✓ ", "")
                for r in results
                for v in r.get("details", [])
            ]
        )
    )

    # Calculate overall flagged status
    flagged = any(r.get("flagged", False) for r in results)

    log_entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "prompt": prompt,
        "result": {"results": results, "multi_vendor": True, "flagged": flagged},
        "attack_vectors": attack_vectors,
        "request": {"prompt": prompt, "results": results},
    }

    try:
        save_log_to_db(log_entry)
        # Sync in-memory logs
        with _ANALYSIS_LOGS_LOCK:
            analysis_logs.insert(0, log_entry)
            if len(analysis_logs) > 100:
                analysis_logs.pop()

        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        logging.error("Failed to save benchmark log: %s", _clean_log_text(e, 200))
        return jsonify({"error": "Failed to save benchmark log"}), 500


@app.route("/api/benchmark/clear", methods=["POST"])
def clear_benchmark():
    try:
        # We only clear benchmark logs (those contain "results" in result_json)
        # However, for simplicity and to match the 'Clear All' button,
        # let's just clear all Logs if we want a fresh start,
        # OR just filter by results as originally intended.
        # Let's clear all Logs for a truly fresh start.
        db.session.query(Log).delete()
        db.session.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/api/benchmark/stats")
def benchmark_stats():
    """
    Returns aggregated stats for the hero section of the benchmarking page.
    """
    try:
        logs = Log.query.all()
        # Filter for benchmark logs that have 'results'
        benchmarks = [l for l in logs if l.result_json and "results" in l.result_json]

        total_scans = len(benchmarks)
        threats_found = 0
        total_time = 0.0
        time_count = 0

        for b in benchmarks:
            results = b.result_json.get("results", [])
            if any(r.get("flagged") for r in results):
                threats_found += 1

            for r in results:
                exec_time = r.get("execution_time")
                if exec_time is not None:
                    total_time += float(exec_time)
                    time_count += 1

        avg_time = total_time / time_count if time_count > 0 else 0

        return jsonify(
            {
                "total_scans": total_scans,
                "threats_found": threats_found,
                "avg_response_time": f"{avg_time:.2f}s",
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.getenv("APP_PORT", 9000))
    # Werkzeug debug (interactive debugger + reloader) only with FLASK_DEBUG=1/true.
    app.run(debug=debug_enabled(), host="0.0.0.0", port=port)
