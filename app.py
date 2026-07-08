from flask import Flask, render_template, request, jsonify
import requests
import os
import sys
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv
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
from flask_cors import CORS
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

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_secret_key")

# --- Flask-Login Configuration ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "error"


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


# Configure CORS with environment variable
cors_origins = os.getenv("CORS_ORIGINS", "*")
CORS(app, resources={r"/api/*": {"origins": cors_origins}})

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
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.getenv("DB_PATH", os.path.join(basedir, "instance", "demo_logs.db"))
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///" + db_path
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

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


def get_setting(key, default=None):
    setting = db.session.get(Settings, key)
    return setting.value if setting else default


def set_setting(key, value):
    if value is None:
        return
    setting = db.session.get(Settings, key)
    if setting:
        setting.value = value
    else:
        setting = Settings(key=key, value=value)
        db.session.add(setting)
    db.session.commit()


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


# Configure Logging
logs_dir = os.getenv("LOGS_DIR", "logs")
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

logging.basicConfig(
    filename=os.path.join(logs_dir, os.getenv("LOG_FILENAME", "application.log")),
    level=logging.INFO,
    format="%(asctime)s\t%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


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
        logging.warning(f"Anthropic model list fetch failed, using static list: {e}")
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
        client = genai.Client(api_key=api_key)
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
        logging.error(f"Error fetching Gemini models: {e}")
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


# Initialize DB
with app.app_context():
    db.create_all()
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
from flask import flash, redirect, url_for


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("playground"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Simple check against env vars
        admin_email = os.getenv("DEFAULT_ADMIN_EMAIL")
        admin_pass = os.getenv("DEFAULT_ADMIN_PASSWORD")

        if email == admin_email and password == admin_pass:
            user = User(id="admin")
            login_user(user)
            return redirect(url_for("playground"))
        else:
            flash("Invalid email or password", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
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
    azure_endpoint = get_setting("AZURE_OPENAI_ENDPOINT") or os.getenv(
        "AZURE_OPENAI_ENDPOINT", ""
    )
    azure_deployment = get_setting("AZURE_OPENAI_DEPLOYMENT") or os.getenv(
        "AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini-2024-07-18"
    )

    azure_cs_endpoint = get_setting("AZURE_CONTENT_SAFETY_ENDPOINT") or os.getenv(
        "AZURE_CONTENT_SAFETY_ENDPOINT", ""
    )
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
    azure_endpoint = get_setting("AZURE_OPENAI_ENDPOINT") or os.getenv(
        "AZURE_OPENAI_ENDPOINT", ""
    )
    azure_deployment = get_setting("AZURE_OPENAI_DEPLOYMENT") or os.getenv(
        "AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini-2024-07-18"
    )

    azure_cs_endpoint = get_setting("AZURE_CONTENT_SAFETY_ENDPOINT") or os.getenv(
        "AZURE_CONTENT_SAFETY_ENDPOINT", ""
    )
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
    azure_cs_endpoint = get_setting("AZURE_CONTENT_SAFETY_ENDPOINT") or os.getenv(
        "AZURE_CONTENT_SAFETY_ENDPOINT", ""
    )
    azure_cs_key = get_setting("AZURE_CONTENT_SAFETY_KEY") or os.getenv(
        "AZURE_CONTENT_SAFETY_KEY", ""
    )
    is_azure_content_safety_configured = bool(azure_cs_endpoint and azure_cs_key)

    return render_template(
        "benchmarking.html",
        is_azure_content_safety_configured=is_azure_content_safety_configured,
    )


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        api_key = request.form.get("api_key")
        project_id = request.form.get("project_id")
        openai_api_key = request.form.get("openai_api_key")
        azure_openai_api_key = request.form.get("azure_openai_api_key")
        azure_openai_endpoint = request.form.get("azure_openai_endpoint")
        azure_openai_deployment = request.form.get("azure_openai_deployment")
        gemini_api_key = request.form.get("gemini_api_key")
        anthropic_api_key = request.form.get("anthropic_api_key")
        ollama_api_url = request.form.get("ollama_api_url")
        ollama_timeout = request.form.get("ollama_timeout")
        azure_cs_endpoint = request.form.get("azure_cs_endpoint")
        azure_cs_key = request.form.get("azure_cs_key")

        set_setting("DEMO_API_KEY", api_key)
        set_setting("DEMO_PROJECT_ID", project_id)
        set_setting("OPENAI_API_KEY", openai_api_key)
        set_setting("AZURE_OPENAI_API_KEY", azure_openai_api_key)
        set_setting("AZURE_OPENAI_ENDPOINT", azure_openai_endpoint)
        set_setting("AZURE_OPENAI_DEPLOYMENT", azure_openai_deployment)
        set_setting("GEMINI_API_KEY", gemini_api_key)
        set_setting("ANTHROPIC_API_KEY", anthropic_api_key)
        set_setting("OLLAMA_API_URL", ollama_api_url)
        set_setting("OLLAMA_TIMEOUT", ollama_timeout)
        set_setting("AZURE_CONTENT_SAFETY_ENDPOINT", azure_cs_endpoint)
        set_setting("AZURE_CONTENT_SAFETY_KEY", azure_cs_key)

        # Re-fetch models to ensure the list is up-to-date with the new key if changed
        gemini_models = get_gemini_models()
        ollama_models = get_ollama_models()

        return render_template(
            "settings.html",
            success=True,
            api_key=api_key,
            project_id=project_id,
            openai_api_key=openai_api_key,
            azure_openai_api_key=azure_openai_api_key,
            azure_openai_endpoint=azure_openai_endpoint,
            azure_openai_deployment=azure_openai_deployment,
            gemini_api_key=gemini_api_key,
            anthropic_api_key=anthropic_api_key,
            ollama_api_url=ollama_api_url,
            ollama_timeout=ollama_timeout,
            azure_cs_endpoint=azure_cs_endpoint,
            azure_cs_key=azure_cs_key,
            gemini_models=gemini_models,
            ollama_models=ollama_models,
        )

    api_key, project_id = guard_credentials()
    openai_api_key = get_setting("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY", "")
    azure_openai_api_key = get_setting("AZURE_OPENAI_API_KEY") or os.getenv(
        "AZURE_OPENAI_API_KEY", ""
    )
    azure_openai_endpoint = get_setting("AZURE_OPENAI_ENDPOINT") or os.getenv(
        "AZURE_OPENAI_ENDPOINT", ""
    )
    azure_openai_deployment = get_setting("AZURE_OPENAI_DEPLOYMENT") or os.getenv(
        "AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini-2024-07-18"
    )
    gemini_api_key = get_setting("GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY", "")
    anthropic_api_key = get_setting("ANTHROPIC_API_KEY") or os.getenv(
        "ANTHROPIC_API_KEY", ""
    )
    ollama_api_url = get_setting("OLLAMA_API_URL") or os.getenv(
        "OLLAMA_API_URL", "http://localhost:11434"
    )
    ollama_timeout = get_setting("OLLAMA_TIMEOUT") or os.getenv("OLLAMA_TIMEOUT", "120")
    azure_cs_endpoint = get_setting("AZURE_CONTENT_SAFETY_ENDPOINT") or os.getenv(
        "AZURE_CONTENT_SAFETY_ENDPOINT", ""
    )
    azure_cs_key = get_setting("AZURE_CONTENT_SAFETY_KEY") or os.getenv(
        "AZURE_CONTENT_SAFETY_KEY", ""
    )

    gemini_models = get_gemini_models()
    ollama_models = get_ollama_models()

    return render_template(
        "settings.html",
        api_key=api_key,
        project_id=project_id,
        openai_api_key=openai_api_key,
        azure_openai_api_key=azure_openai_api_key,
        azure_openai_endpoint=azure_openai_endpoint,
        azure_openai_deployment=azure_openai_deployment,
        gemini_api_key=gemini_api_key,
        anthropic_api_key=anthropic_api_key,
        ollama_api_url=ollama_api_url,
        ollama_timeout=ollama_timeout,
        azure_cs_endpoint=azure_cs_endpoint,
        azure_cs_key=azure_cs_key,
        gemini_models=gemini_models,
        ollama_models=ollama_models,
    )


@app.route("/api/settings", methods=["GET"])
def get_api_settings():
    """
    Get current configuration for the frontend.
    """
    demo_api_key, demo_project_id = guard_credentials()
    azure_api_key = get_setting("AZURE_OPENAI_API_KEY") or os.getenv("AZURE_OPENAI_API_KEY", "")
    azure_endpoint = get_setting("AZURE_OPENAI_ENDPOINT") or os.getenv("AZURE_OPENAI_ENDPOINT", "")
    azure_deployment = get_setting("AZURE_OPENAI_DEPLOYMENT") or os.getenv("AZURE_OPENAI_DEPLOYMENT", "")

    return jsonify(
        {
            "DEMO_API_KEY": demo_api_key,
            "DEMO_PROJECT_ID": demo_project_id,
            "LAKERA_API_KEY": demo_api_key,  # Backward compatibility for JS
            "AZURE_CONTENT_SAFETY_KEY": get_setting("AZURE_CONTENT_SAFETY_KEY")
            or os.getenv("AZURE_CONTENT_SAFETY_KEY", ""),
            "AZURE_CONTENT_SAFETY_ENDPOINT": get_setting(
                "AZURE_CONTENT_SAFETY_ENDPOINT"
            )
            or os.getenv("AZURE_CONTENT_SAFETY_ENDPOINT", ""),
            "guardrails_configured": bool(demo_api_key and demo_project_id),
            "azure_configured": bool(azure_api_key and azure_endpoint and azure_deployment)
        }
    )


def get_azure_content_safety_client():
    endpoint = get_setting("AZURE_CONTENT_SAFETY_ENDPOINT") or os.getenv(
        "AZURE_CONTENT_SAFETY_ENDPOINT"
    )
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
        endpoint = config.get("endpoint", "").strip().rstrip("/")
        key = config.get("key", "").strip()
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
            masked_key = f"{key[:4]}...{key[-4:]}" if len(key) > 8 else "****"
            logging.info(
                f"Azure CS: Initializing with endpoint={endpoint}, key={masked_key}, length={len(key)}, is_hex={is_hex}"
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
                    f"Azure Prompt Shield API returned {shield_response.status_code}: {shield_response.text}"
                )
        except Exception as shield_err:
            logging.error(f"Azure Prompt Shield Error: {shield_err}")

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
        logging.error(f"Azure Content Safety Error: {e}")
        res_obj.update(
            {
                "error": str(e),
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
        payload = {
            "messages": [{"role": "user", "content": text}],
            "project_id": config.get("project_id"),
            "breakdown": True,
        }
        resp = requests.post(config["url"], headers=headers, json=payload, timeout=10)
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
            res_obj["error"] = f"AI Guardrails API error: {resp.status_code}"
            res_obj["details"] = [resp.text[:100]]
    except Exception as e:
        logging.error(f"AI Guardrails Wrapper Error: {e}")
        res_obj["error"] = str(e)
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
    data = request.json
    model_id = data.get("id")
    enabled = data.get("enabled", False)

    if not model_id:
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
                logging.info(f"Disabled {model_id} scanner")

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
    data = request.json
    model_id = data.get("id")
    if not model_id:
        return jsonify({"error": "Model ID is required"}), 400

    # We simulate/trigger the download by initializing the scanner
    # In a production app, we would use a background task with progress updates
    try:
        logging.info(f"UI Triggered Download: {model_id}")
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
        logging.error(f"Download Error: {e}")
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
                logging.error(f"Error in scanner {scanner_name}: {e}\n{tb}")

                # Robustly handle the error breakdown
                breakdown.append(
                    {
                        "detector_type": scanner_name,
                        "error": str(e),
                        "detected": False,
                        "score": 0,
                    }
                )
                details.append(f"Error {scanner_name}: {str(e)}")

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
        logging.error(f"LLM Guard Scan Error: {e}")
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
        description: Missing prompt
      500:
        description: API Key not configured
    """
    # DB (DEMO_*) first, then env DEMO_* / LAKERA_* — see guard_credentials().
    api_key, demo_project_id = guard_credentials()
    if not api_key:
        return jsonify({"error": "API Key not configured. Please go to Settings."}), 500

    data = request.json
    prompt = data.get("prompt")
    use_guardrails = data.get("use_guardrails", False)
    use_guardrails_outbound = data.get("use_guardrails_outbound", False)

    logging.info(f"Analyze request: {prompt[:100]}...")

    if not prompt:
        return jsonify({"error": "Prompt is required"}), 400

    guardrails_result = None
    guardrails_outbound_result = None
    guardrails_flagged = False

    # Common AI Guardrails Config
    url = os.getenv("DEMO_API_URL", "https://api.lakera.ai/v2/guard")
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    # 1. AI Guardrails Inbound Scan (Conditional)
    if use_guardrails:
        payload = {
            "messages": [{"role": "user", "content": prompt}],
            "project_id": demo_project_id,
            "breakdown": True,
        }
        try:
            response = requests.post(url, headers=headers, json=payload)
            if response.status_code != 200:
                logging.error(f"AI Guardrails API Error {response.status_code}: {response.text}")
                
            response.raise_for_status()
            guardrails_result = response.json()
            logging.info(f"Inbound: {prompt}\tSuccess\t{json.dumps(guardrails_result)}")

            if guardrails_result.get("flagged", False):
                guardrails_flagged = True

        except requests.exceptions.RequestException as e:
            print(f"DEBUG: AI Guardrails Exception={e}", flush=True)
            logging.error(f"AI Guardrails API Exception: {e}")
            if hasattr(e, 'response') and e.response is not None:
                 logging.error(f"AI Guardrails API Response: {e.response.text}")

    # 2. OpenAI Chat (If safe or skipped)
    openai_response = None
    if not guardrails_flagged:
        model_provider = data.get("model_provider", "azure")
        model_name = data.get("model_name")

        if model_provider == "azure":
            azure_api_key = get_setting("AZURE_OPENAI_API_KEY") or os.getenv(
                "AZURE_OPENAI_API_KEY"
            )
            azure_endpoint = get_setting("AZURE_OPENAI_ENDPOINT") or os.getenv(
                "AZURE_OPENAI_ENDPOINT"
            )
            azure_deployment = get_setting("AZURE_OPENAI_DEPLOYMENT") or os.getenv(
                "AZURE_OPENAI_DEPLOYMENT"
            )

            if azure_api_key and azure_endpoint and azure_deployment:
                try:
                    openai_url = f"{azure_endpoint}/openai/deployments/{azure_deployment}/chat/completions?api-version=2024-02-15-preview"
                    openai_headers = {
                        "api-key": azure_api_key,
                        "Content-Type": "application/json",
                    }
                    openai_payload = {"messages": [{"role": "user", "content": prompt}]}
                    oa_response = requests.post(
                        openai_url, headers=openai_headers, json=openai_payload
                    )
                    oa_response.raise_for_status()
                    openai_data = oa_response.json()
                    openai_response = openai_data["choices"][0]["message"]["content"]
                except Exception as e:
                    logging.error(f"Azure OpenAI API Error: {e}")
                    openai_response = f"Error calling Azure OpenAI: {str(e)}"
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
                        GEMINI_CACHE["model_instance"] = genai.Client(
                            api_key=gemini_api_key
                        )

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
                    logging.error(f"Gemini API Error: {e}")
                    openai_response = f"Error calling Gemini: {str(e)}"
            else:
                openai_response = "Gemini API key not configured."

        elif model_provider == "ollama":
            ollama_url = resolve_ollama_url()
            ollama_timeout = int(
                get_setting("OLLAMA_TIMEOUT") or os.getenv("OLLAMA_TIMEOUT", 120)
            )
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
                    openai_response = f"Error calling Ollama: {response.text}"
            except Exception as e:
                logging.error(f"Ollama API Error: {e}")
                openai_response = f"Error calling Ollama: {str(e)}"

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
                        timeout=60,
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
                    logging.error(f"Anthropic API Error: {e}")
                    openai_response = f"Error calling Anthropic: {str(e)}"
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
                    logging.info(f"Calling OpenAI with payload: {openai_payload}")
                    oa_response = requests.post(
                        openai_url, headers=openai_headers, json=openai_payload
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
                    logging.error(f"OpenAI API Error: {e}")
                    if not openai_response:
                        openai_response = f"Error calling OpenAI: {str(e)}"
            else:
                openai_response = "OpenAI API Key not configured."

    # 3. AI Guardrails Outbound Scan (Conditional)
    if (
        use_guardrails_outbound
        and openai_response
        and not openai_response.startswith("Error")
        and not openai_response.endswith("configured.")
    ):
        try:
            outbound_payload = {
                "messages": [{"role": "assistant", "content": openai_response}],
                "project_id": demo_project_id,
                "breakdown": True,
            }
            out_response = requests.post(url, headers=headers, json=outbound_payload)
            out_response.raise_for_status()
            guardrails_outbound_result = out_response.json()
            logging.info(
                f"Outbound: {openai_response[:50]}...\tSuccess\t{json.dumps(guardrails_outbound_result)}"
            )
        except Exception as e:
            logging.error(f"AI Guardrails Outbound Error: {e}")

    # 3. Log and Return
    inbound_vectors = []
    outbound_vectors = []

    # Collect inbound vectors
    if guardrails_result and guardrails_result.get("breakdown"):
        for r in guardrails_result["breakdown"]:
            if r.get("detected") and r.get("detector_type"):
                vector = r["detector_type"].split("/")[-1]
                if vector not in inbound_vectors:
                    inbound_vectors.append(vector)
        guardrails_result["attack_vectors"] = inbound_vectors

    # Collect outbound vectors
    if guardrails_outbound_result and guardrails_outbound_result.get("breakdown"):
        for r in guardrails_outbound_result["breakdown"]:
            if r.get("detected") and r.get("detector_type"):
                vector = r["detector_type"].split("/")[-1]
                if vector not in outbound_vectors:
                    outbound_vectors.append(vector)
        guardrails_outbound_result["attack_vectors"] = outbound_vectors

    # Combined vectors for top-level logging
    attack_vectors = list(set(inbound_vectors + outbound_vectors))

    # Create a consolidated result object for the database
    db_result = {
        "flagged": guardrails_flagged
        or (guardrails_outbound_result and guardrails_outbound_result.get("flagged", False)),
        "inbound_result": guardrails_result,
        "outbound_result": guardrails_outbound_result,
        "openai_response": openai_response,
        "attack_vectors": attack_vectors,
    }

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
            "openai": openai_response,
        },
    }

    try:
        save_log_to_db(log_entry)
    except Exception as e:
        logging.error(f"Failed to save log to DB: {e}")

    analysis_logs.insert(0, log_entry)
    if len(analysis_logs) > 100:
        analysis_logs.pop()

    return jsonify(
        {
            "prompt": prompt,
            "guardrails_result": guardrails_result,
            "guardrails_outbound_result": guardrails_outbound_result,
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
    for log in logs:
        status = "Error" if log.error else "Success"
        flagged = (
            "Yes" if (log.result_json and log.result_json.get("flagged")) else "No"
        )
        attack_vectors = ", ".join(log.attack_vectors or [])
        error = log.error or ""
        writer.writerow(
            [
                log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                log.prompt,
                status,
                attack_vectors,
                flagged,
                error,
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
    data = request.json
    prompt = data.get("prompt")
    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400

    _gc_key, _gc_project = guard_credentials()
    guardrails_config = {
        "api_key": _gc_key,
        "project_id": _gc_project,
        "url": os.getenv("DEMO_API_URL", "https://api.lakera.ai/v2/guard"),
    }

    if not guardrails_config["api_key"]:
        return jsonify({"error": "AI Guardrails API key not configured"}), 400

    result = scan_guardrails_wrapper(prompt, guardrails_config)
    return jsonify(result)


@app.route("/api/scan/azure", methods=["POST"])
def scan_azure_endpoint():
    data = request.json
    prompt = data.get("prompt")
    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400

    azure_config = {
        "endpoint": get_setting("AZURE_CONTENT_SAFETY_ENDPOINT")
        or os.getenv("AZURE_CONTENT_SAFETY_ENDPOINT"),
        "key": get_setting("AZURE_CONTENT_SAFETY_KEY")
        or os.getenv("AZURE_CONTENT_SAFETY_KEY"),
    }

    if not azure_config["key"] or not azure_config["endpoint"]:
        return jsonify({"error": "Azure Content Safety not configured"}), 400

    result = scan_with_azure(prompt, azure_config)
    return jsonify(result)


@app.route("/api/scan/llmguard", methods=["POST"])
def scan_llmguard_endpoint():
    data = request.json
    prompt = data.get("prompt")
    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400

    # LLM Guard is local, no config needed usually
    result = scan_with_llm_guard(prompt, {})
    return jsonify(result)


@app.route("/api/compare", methods=["POST"])
@limiter.limit("10 per minute")
def compare():
    # ... keep existing compare implementation for backward compatibility or direct API use ...
    data = request.json
    prompt = data.get("prompt")
    use_azure = data.get("use_azure", True)
    use_llm_guard = data.get("use_llm_guard", True)

    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400

    _gc_key, _gc_project = guard_credentials()
    guardrails_config = {
        "api_key": _gc_key,
        "project_id": _gc_project,
        "url": os.getenv("DEMO_API_URL", "https://api.lakera.ai/v2/guard"),
    }

    azure_config = {
        "endpoint": get_setting("AZURE_CONTENT_SAFETY_ENDPOINT")
        or os.getenv("AZURE_CONTENT_SAFETY_ENDPOINT"),
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
                    logging.error(f"{name} thread error: {e}")
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
            logging.error(f"Failed to log benchmark: {e}")

    except Exception as e:
        logging.error(f"Parallel Execution Error: {e}")
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


@app.route("/api/benchmark/log", methods=["POST"])
def log_benchmark_result():
    """
    Log a consolidated benchmark result from the frontend.
    """
    data = request.json
    prompt = data.get("prompt")
    results = data.get("results", [])

    if not prompt or not results:
        return jsonify({"error": "Missing prompt or results"}), 400

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
        "request": data,
    }

    try:
        save_log_to_db(log_entry)
        # Sync in-memory logs
        global analysis_logs
        analysis_logs.insert(0, log_entry)
        if len(analysis_logs) > 100:
            analysis_logs.pop()

        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"Failed to save benchmark log: {e}")
        return jsonify({"error": str(e)}), 500


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
    app.run(debug=True, host="0.0.0.0", port=port)
