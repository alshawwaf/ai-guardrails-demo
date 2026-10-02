"""Gateway Mode web console: pages and JSON API (spec 9.2).

Pages (all extend base.html): ``/gateway/`` (redirects to the current step),
``/gateway/connect``, ``/preflight``, ``/configure``, ``/install``, ``/demo``,
``/diagnostics``.

JSON API under ``/gateway/api/`` (login required; POST bodies must be JSON objects,
anything else gets 415; same-origin is enforced app-wide by app.py):

* ``POST connect`` {server, port, server_type, domain, auth, api_key | user+password,
  ca_pem?, clear_ca?, server_name?} -> {connect, warnings, discover_error, status}
* ``GET  status`` -> Session.status() + {"job", "web", "defaults"}
* ``POST gateway`` {name} ; ``POST preflight`` {package?} -> job
* ``POST lakera`` {api_key | use_saved, project_id, direct_check?} -> {lakera}
* ``POST plan`` {options} | {template: "https-inspection", add_rule} -> {plan}
* ``POST apply`` {plan_id, typed: "APPROVE", acknowledge: true, confirm?} -> job
* ``POST rollback`` {rollback_id?, install?} -> job
* ``POST prompt`` {text, provider, expect, prompt_id?} -> {result, diagnosis, summary}
* ``POST scene`` {scene_id, provider} -> job
* ``GET  jobs/<id>`` -> job dict ; ``GET log?level=&component=&n=`` -> RunLog.tail
* ``GET  scenes`` ; ``GET report`` ; ``POST disconnect``
* additions: ``POST domain`` {domain} (MDS, same login), ``POST correlate`` (look for the
  gateway logs again), ``POST outbound-ca`` {ca_pem | clear | from_management} (trust the
  gateway's outbound CA for the prompts this server sends; ``from_management`` reads the
  public certificate with show-outbound-inspection-certificate), ``POST tls-check``
  {provider} (TLS handshake towards a provider, no prompt), ``POST discard`` (drop this
  session's unpublished changes).

Every JSON response passes through ``aiguard.redact.redact_obj``; secrets are never
returned or rendered (only masked hints such as ``****abcd``). It then passes through
:func:`gateway_mode.webtext.webify`: the engine's CLI wording in fix steps, states and
diagnoses becomes the console's own (fields and buttons), and errors get ``actions``
(rollback, HTTPS Inspection fix, outbound CA) the pages render as buttons. The run log
(``GET log``) and the report are returned verbatim.

``POST connect``, ``domain``, ``lakera`` and ``apply`` are rate limited per signed-in user
and client address (:data:`RATE_LIMITS`) through the app's Flask-Limiter storage when it
is registered in ``current_app.extensions["limiter"]`` (an in-process window otherwise).

Defaults from the environment (:mod:`aiguard.envdefaults`, written to ``.env`` by the lab
installer): the Connect page is pre-filled with them and ``status`` carries a display-safe
``defaults`` object (no secrets, the CA file by name only). ``connect`` uses
``AIGUARD_MGMT_CA_FILE`` when the request has no ``ca_pem`` / ``clear_ca`` and this browser
uploaded no management CA (read in place: never copied into the per-session CA folder and
never deleted), and ``AIGUARD_MGMT_SERVER_NAME`` when the request has no ``server_name``
and the server is ``AIGUARD_MGMT_SERVER``.
"""

from __future__ import annotations

import hashlib
import inspect
import ipaddress
import re
import secrets
import threading
import time
import weakref
from collections import deque
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Hashable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from flask import Blueprint, current_app, g, jsonify, redirect, render_template, request
from flask import session as flask_session
from flask import url_for
from flask_login import current_user, login_required

from aiguard import envdefaults as _envdefaults
from aiguard import probe as _probe
from aiguard import redact as _redact
from aiguard import scenes as _scenes
from aiguard.errors import (AiguardError, ConnectError, MgmtApiError, TlsTrustError)
from aiguard.plan import THREAT_TRACKS, PlanOptions
from aiguard.preflight import CHECK_IDS, TITLES

from . import store as _store
from . import webtext as _webtext
from .jobs import JobFailure, JobRegistry, error_dict

__all__ = ["bp", "GatewayContext", "EXT_KEY", "STEPS", "BadInput"]

EXT_KEY = "gateway_mode"
MAX_BODY_BYTES = 256 * 1024
PROMPT_MAX_CHARS = 20000
IDLE_MINUTES = int(_store.IDLE_SECONDS // 60)
# Attempts per minute, per signed-in user and client address (each opens connections to
# a management server or the AI Guardrails cloud, or changes the policy).
RATE_LIMITS: Dict[str, int] = {"connect": 10, "domain": 10, "lakera": 10, "apply": 10}
SHUTDOWN_WAIT_SECONDS = 8.0     # docker stop waits 10 s before SIGKILL
SYSTEM_DATA = "system data"

STEPS: List[Tuple[str, str]] = [
    ("connect", "Connect"),
    ("preflight", "Preflight"),
    ("configure", "Configure"),
    ("install", "Approve and install"),
    ("demo", "Run the demo"),
    ("diagnostics", "Logs and report"),
]
_STEP_IDS = [s for s, _ in STEPS]

# Settings keys (decrypted by app.get_setting) and environment fallbacks.
PROVIDER_SETTINGS: Dict[str, Tuple[str, ...]] = {
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY",),
    "gemini": ("GEMINI_API_KEY",),
    "azure": ("AZURE_OPENAI_API_KEY",),
}
LAKERA_KEY_SETTING = ("DEMO_API_KEY", "LAKERA_API_KEY")
LAKERA_PROJECT_SETTING = ("DEMO_PROJECT_ID", "LAKERA_PROJECT_ID")

_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]%]+$")
_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_FILTER_RE = re.compile(r"^[A-Za-z_,\-]{0,100}$")
_JOB_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_GW_SID_RE = re.compile(r"^[A-Za-z0-9_\-]{16,64}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_CTRL_MULTILINE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

bp = Blueprint("gateway", __name__, url_prefix="/gateway")

Key = Tuple[str, str]


# --------------------------------------------------------------------------- errors


class BadInput(Exception):
    """A request the console refuses before anything is sent anywhere."""

    def __init__(self, what: str, *, why: Optional[str] = None,
                 fix: Optional[Sequence[str]] = None, field: Optional[str] = None,
                 status: int = 400, code: str = "web.invalid",
                 state: str = "Nothing was changed.", details: Optional[Dict[str, Any]] = None,
                 headers: Optional[Dict[str, str]] = None) -> None:
        super().__init__(what)
        self.what = what
        self.why = why
        self.fix = list(fix or [])
        self.field = field
        self.status = status
        self.code = code
        self.state = state
        self.details = dict(details or {})
        self.headers = dict(headers or {})

    def to_dict(self) -> Dict[str, Any]:
        return {"type": "BadInput", "code": self.code, "what": self.what, "server_said": None,
                "why": self.why, "fix": self.fix, "state": self.state,
                "details": dict(self.details), "field": self.field, "log_line": None}


def _not_connected() -> BadInput:
    return BadInput("Not connected to a management server", code="web.not_connected",
                    status=409, why="This step needs a Management API session.",
                    fix=["Open Connect, sign in to the management server and pick a gateway"])


def _no_gateway() -> BadInput:
    return BadInput("No gateway was chosen", code="web.no_gateway", status=409,
                    why="Preflight, the plan and the demo work on one gateway.",
                    fix=["Open Connect and pick the gateway your demo traffic goes through"])


def _job_running(what: str = "Another operation is still running", *,
                 fix: str = "Wait for it to finish, then try again",
                 why: Optional[str] = None) -> BadInput:
    return BadInput(what, code="web.job_running", status=409, why=why, fix=[fix])


def _session_closed() -> BadInput:
    return BadInput("The web session was closed while this request was running",
                    code="web.session_closed", status=409,
                    why="Disconnect was pressed (or the session expired) before the management "
                        "server answered.",
                    fix=["Connect again"],
                    state="Anything that logged in late was logged out again. Nothing was "
                          "changed.")


_STATUS_BY_CODE = {
    "engine.busy": 409, "web.job_running": 409, "engine.not_connected": 409,
    "engine.no_gateway": 409, "engine.no_plan": 409,
}


def _http_status(exc: AiguardError) -> int:
    if exc.code in _STATUS_BY_CODE:
        return _STATUS_BY_CODE[exc.code]
    if isinstance(exc, (ConnectError, TlsTrustError, MgmtApiError)):
        return 502
    return 400


def _safe_json(payload: Any, status: int = 200, *, raw: bool = False,
               headers: Optional[Dict[str, str]] = None):
    """JSON response: redacted, then (unless ``raw``) reworded for the web console."""
    data = _redact.redact_obj(payload)
    if not raw:
        data = _webtext.webify(data)
    resp = jsonify(data)
    resp.status_code = status
    resp.headers["Cache-Control"] = "no-store"
    for name, value in (headers or {}).items():
        resp.headers[name] = value
    return resp


def _error_response(err: Dict[str, Any], status: int, headers: Optional[Dict[str, str]] = None):
    return _safe_json({"ok": False, "error": err, "message": err.get("what")}, status,
                      headers=headers)


def _ok(payload: Optional[Dict[str, Any]] = None, status: int = 200):
    body = {"ok": True}
    body.update(payload or {})
    return _safe_json(body, status)


# --------------------------------------------------------------------------- context


def _setting_value(get_setting: Optional[Callable[..., Any]], names: Sequence[str]) -> str:
    import os

    for i, name in enumerate(names):
        value = None
        if get_setting is not None and i == 0:
            try:
                value = get_setting(name)
            except Exception:  # noqa: BLE001 - settings are optional for gateway mode
                value = None
        if not value:
            value = os.environ.get(name)
        if value and str(value).strip():
            return str(value).strip()
    return ""


def mask_hint(value: Optional[str]) -> str:
    """Display hint for a saved secret: ``****`` + last 4 (``****`` when short)."""
    if not value:
        return ""
    value = str(value)
    if len(value) < 8:
        return "****"
    return "****" + value[-4:]


class GatewayContext(object):
    """Per-app state: settings access, the session store and the job registry."""

    def __init__(self, *, home: Path, ca_dir: Path,
                 get_setting: Optional[Callable[..., Any]] = None,
                 record_log: Optional[Callable[[dict], Any]] = None) -> None:
        self.home = Path(home)
        self.ca_dir = Path(ca_dir)
        self.get_setting = get_setting
        self.record_log = record_log
        self.jobs = JobRegistry()
        self.store = _store.SessionStore(home=self.home, ca_dir=self.ca_dir,
                                         is_busy=self.jobs.is_busy, on_create=self.load_settings,
                                         protected=self.protected_paths)
        self._stop = threading.Event()
        self._shut = False
        self._reaper: Optional[threading.Thread] = None
        # Which Settings keys each engine Session already got (sha256 only, never the key).
        self._applied: "weakref.WeakKeyDictionary[Any, Dict[str, str]]" = weakref.WeakKeyDictionary()
        # sha256 of the AI key + project last set in each engine Session (a change makes the
        # plan built with the old one stale).
        self.lakera_digest: "weakref.WeakKeyDictionary[Any, str]" = weakref.WeakKeyDictionary()

    # ------------------------------------------------------------------ settings

    def setting(self, *names: str) -> str:
        return _setting_value(self.get_setting, names)

    def saved_lakera_key(self) -> str:
        return self.setting(*LAKERA_KEY_SETTING)

    def saved_project_id(self) -> str:
        return self.setting(*LAKERA_PROJECT_SETTING)

    def _azure_endpoint(self) -> Optional[str]:
        endpoint = self.setting("AZURE_OPENAI_ENDPOINT")
        if not endpoint:
            return None
        try:
            parts = urlsplit(endpoint)
        except ValueError:
            return None
        if parts.scheme != "https" or not parts.hostname:
            return None
        return "https://%s" % parts.netloc

    def provider_keys(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for name, names in PROVIDER_SETTINGS.items():
            if name == "azure" and not self._azure_endpoint():
                continue
            value = self.setting(*names)
            if value:
                out[name] = value
        return out

    def refresh_provider_keys(self, sess: Any) -> None:
        """Give the engine the LLM keys saved in Settings (memory only); clear removed ones."""
        keys = self.provider_keys()
        endpoint = self._azure_endpoint()
        if endpoint:
            try:
                sess.provider_base_urls["azure"] = endpoint
                deployment = self.setting("AZURE_OPENAI_DEPLOYMENT")
                if deployment and not _CTRL_RE.search(deployment):
                    sess.models["azure"] = deployment
            except (AttributeError, TypeError):
                pass
        try:
            applied = self._applied.setdefault(sess, {})
        except TypeError:   # not weak-referenceable: always apply
            applied = {}
        for name in PROVIDER_SETTINGS:
            if name == "azure" and not endpoint:
                continue
            value = keys.get(name) or ""
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""
            if applied.get(name, "") == digest:
                continue
            sess.set_provider_key(name, value)
            applied[name] = digest

    def load_settings(self, sess: Any) -> None:
        """Called once per new engine Session: provider keys + the direct Lakera key
        (used only to label blocked prompts with a category)."""
        self.refresh_provider_keys(sess)
        key = self.saved_lakera_key()
        if key and hasattr(sess, "set_direct_lakera"):
            import os

            url = ((os.environ.get("DEMO_API_URL") or "").strip()
                   or (os.environ.get("LAKERA_API_URL") or "").strip() or None)
            if url:
                try:
                    if urlsplit(url).scheme != "https":
                        url = None
                except ValueError:
                    url = None
            try:
                sess.set_direct_lakera(key, self.saved_project_id() or None, url=url, check=False)
            except AiguardError as exc:
                sess.log.warn("web", "the Lakera key saved in Settings was not used",
                              error=exc.what)

    def providers(self) -> List[Dict[str, Any]]:
        keys = self.provider_keys()
        out = []
        for name in _probe.STANDARD_PROVIDERS + ("azure",):
            p = _probe.PROVIDERS.get(name) or {}
            if name == "azure" and "azure" not in keys:
                continue
            out.append({"name": name, "label": p.get("label", name), "model": p.get("model"),
                        "host": p.get("host"), "key": "saved" if name in keys else "dummy"})
        return out

    # ------------------------------------------------------------------ environment

    def env_defaults(self) -> "_envdefaults.Defaults":
        """The connection defaults from the environment, read now (see envdefaults)."""
        return _envdefaults.from_env()

    def protected_paths(self) -> List[str]:
        """Files the session store must never delete: the installer's management CA."""
        path = self.env_defaults().ca_file
        return [path] if path else []

    def env_ca(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """(facts, problem) for ``AIGUARD_MGMT_CA_FILE``: facts (path, name, sha1,
        subject_cn) when it is a readable certificate file without a private key, else the
        reason it is not used (None, None when the variable is not set)."""
        path = self.env_defaults().ca_file
        if not path:
            return None, None
        try:
            return _envdefaults.inspect_ca_file(path), None
        except _envdefaults.CaFileError as exc:
            return None, str(exc)

    def defaults_view(self) -> Dict[str, Any]:
        """Display-safe defaults for the pages and ``status`` (none of them is a secret;
        the CA file is named without its directory)."""
        d = self.env_defaults()
        ca: Optional[Dict[str, Any]] = None
        note = None
        if d.ca_file:
            info, problem = self.env_ca()
            ca = {"file_name": Path(d.ca_file).name or d.ca_file, "usable": info is not None,
                  "subject_cn": (info or {}).get("subject_cn"), "sha1": (info or {}).get("sha1"),
                  "problem": problem}
            if info is not None:
                note = "Management certificate provided by the installer: %s, SHA-1 %s" % (
                    info.get("subject_cn") or ca["file_name"], info.get("sha1"))
        seen = None
        if d.fingerprint_sha1 and not (ca and ca.get("sha1") == d.fingerprint_sha1):
            seen = ("The installer saw the management certificate with SHA-1 %s. Compare it "
                    "with api fingerprint on the server." % d.fingerprint_sha1)
        return {"server": d.server, "port": d.port, "server_type": d.server_type,
                "domain": d.domain, "server_name": d.server_name, "gateway": d.gateway,
                "fingerprint_sha1": d.fingerprint_sha1, "ca": ca, "ca_note": note,
                "fingerprint_note": seen, "problems": list(d.problems)}

    # ------------------------------------------------------------------ demo log

    def record(self, rd: Dict[str, Any], *, gateway: Optional[str], kind: str,
               user: Optional[str], diagnosis: Optional[List[str]] = None,
               log: Any = None) -> None:
        """Send one prompt result to the app's Logs / Dashboard (record_gateway_log)."""
        if self.record_log is None or not isinstance(rd, dict):
            return
        try:
            verdict = str(rd.get("verdict") or "")
            blocked = verdict == "BLOCKED"
            cat = rd.get("category") or None
            vectors = [cat] if (blocked and cat) else (["AI Agent Security"] if blocked else [])
            err = rd.get("error") if isinstance(rd.get("error"), dict) else {}
            entry = {
                "timestamp": rd.get("sent_at"),
                "prompt": rd.get("prompt") or "",
                "verdict": verdict,
                "category": cat if blocked else None,
                "attack_vectors": vectors,
                "result": {
                    "flagged": blocked, "verdict": verdict, "expect": rd.get("expect"),
                    "matched": rd.get("matched"), "evidence": rd.get("evidence"),
                    "reason": rd.get("reason"), "category": cat,
                    "category_source": rd.get("category_source"),
                    "confidence_label": rd.get("confidence_label"),
                    "provider": rd.get("provider"), "host": rd.get("host"),
                    "http_status": rd.get("http_status"), "content_type": rd.get("content_type"),
                    "ms": rd.get("ms"), "inspected": rd.get("inspected"),
                    "issuer": rd.get("issuer"), "gateway": gateway,
                    "log_match": rd.get("log_match"), "prompt_id": rd.get("prompt_id"),
                    "result_id": rd.get("id"), "diagnosis": list(diagnosis or []),
                },
                "request": {
                    "mode": "gateway", "kind": kind, "provider": rd.get("provider"),
                    "model": rd.get("model"), "prompt_id": rd.get("prompt_id"),
                    "expect": rd.get("expect"), "gateway": gateway, "user": user,
                },
                "error": (err.get("what") if verdict == "ERROR" else None),
            }
            self.record_log(_redact.redact_obj(entry))
        except Exception as exc:  # noqa: BLE001 - the demo result stands without the app log
            if log is not None:
                try:
                    log.warn("web", "could not add the result to the app's Logs",
                             error=type(exc).__name__)
                except Exception:  # noqa: BLE001
                    pass

    # ------------------------------------------------------------------ lifecycle

    def start_reaper(self, interval: float = 60.0) -> None:
        if self._reaper is not None:
            return

        def loop() -> None:
            while not self._stop.wait(interval):
                try:
                    self.store.sweep()
                    # The Management API ends idle sessions after its timeout (10 minutes
                    # by default); the console keeps them for its own idle time instead.
                    self.store.keepalive_all()
                except Exception:  # noqa: BLE001 - keep sweeping
                    pass

        self._reaper = threading.Thread(target=loop, name="aiguard-web-reaper", daemon=True)
        self._reaper.start()

    def shutdown(self, wait: float = SHUTDOWN_WAIT_SECONDS) -> None:
        """Stop the reaper, give running jobs ``wait`` seconds to finish, then close every
        session (a session still in the middle of an operation first discards what it has
        not published). Runs once (atexit; SIGTERM raises SystemExit so atexit runs)."""
        if self._shut:
            return
        self._shut = True
        self._stop.set()
        try:
            self.jobs.wait_all(wait)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.store.close_all(discard_busy=True)
        except Exception:  # noqa: BLE001
            pass


def _ctx() -> GatewayContext:
    return current_app.extensions[EXT_KEY]


def _user() -> str:
    try:
        return str(current_user.get_id())
    except Exception:  # noqa: BLE001
        return "unknown"


def _owner(create: bool = False) -> Optional[Key]:
    """(user id, random browser id) for the signed-in user; None when there is none."""
    if not current_user.is_authenticated:
        return None
    sid = flask_session.get("gw_sid")
    if not isinstance(sid, str) or not _GW_SID_RE.match(sid):
        if not create:
            return None
        sid = secrets.token_urlsafe(24)
        flask_session["gw_sid"] = sid
    return (_user(), sid)


def _entry(*, create: bool = False) -> Tuple[Key, _store.Entry]:
    ctx = _ctx()
    owner = _owner(create=create)
    entry = ctx.store.get(owner) if owner else None
    if entry is None:
        if not create or owner is None:
            raise _not_connected()
        entry = ctx.store.create(owner)
    return owner, entry  # type: ignore[return-value]


def _connected(sess: Any) -> bool:
    """Logged in, or the server ended the session and the engine can log in again with the
    same credentials on the next operation."""
    client = getattr(sess, "client", None)
    if client is None:
        return False
    if getattr(client, "logged_in", False):
        return True
    relogin = getattr(client, "can_relogin", None)
    try:
        return bool(getattr(client, "session_expired", False) and callable(relogin)
                    and relogin())
    except Exception:  # noqa: BLE001 - informational
        return False


def _correlate(sess: Any) -> Optional[str]:
    """Match the results to the gateway logs; the reason it failed, or None."""
    try:
        failure = sess.correlate()
    except AiguardError as exc:
        return exc.what
    if isinstance(failure, dict) and failure.get("what"):
        return str(failure["what"])
    return None


def _need_connected(sess: Any) -> None:
    if not _connected(sess):
        raise _not_connected()


def _need_gateway(sess: Any) -> None:
    _need_connected(sess)
    if getattr(sess, "gateway", None) is None:
        raise _no_gateway()


def _log_path(entry: Optional[_store.Entry]) -> Optional[str]:
    if entry is None:
        return None
    return entry.log_paths().get("log_path")


def _need_idle(owner: Optional[Key], sess: Any, what: str) -> None:
    """Refuse while a job of this browser, or an engine operation, is running."""
    if owner is not None and _ctx().jobs.is_busy(owner):
        raise _job_running(fix="Wait for it to finish, then %s" % what)
    busy = _store.session_busy(sess) if sess is not None else None
    if busy:
        raise _job_running("Another operation is still running (%s)" % busy,
                           fix="Wait for it to finish, then %s" % what)


def _closed_while_running(entry: _store.Entry) -> None:
    """The entry was closed (Disconnect, expiry) while this request was talking to the
    server: log out whatever the request logged in, then refuse."""
    if not entry.closed:
        return
    try:
        entry.session.close()
    except Exception:  # noqa: BLE001 - close never raises by contract
        pass
    raise _session_closed()


def _web_connection(conn: Any) -> Any:
    """Connection dict for the pages: an MDS login without a domain works in "System Data",
    which is not a domain with gateways: ``domain`` None plus ``system_data`` True."""
    if not isinstance(conn, dict):
        return conn
    out = dict(conn)
    dom = out.get("domain")
    # The engine already says so (domain None, system_data True); older engines name it.
    is_sd = bool(out.get("system_data")) or (
        isinstance(dom, str) and dom.strip().lower() == SYSTEM_DATA)
    if is_sd:
        out["domain"] = None
    out["system_data"] = is_sd
    return out


def _plan_published(plan: Any, plan_dict: Optional[Dict[str, Any]] = None) -> bool:
    """True when this plan was published once (apply_plan refuses it again)."""
    if plan is None:
        return False
    if getattr(plan, "_published", False):
        return True
    d = plan_dict if isinstance(plan_dict, dict) else {}
    return bool(d.get("published") or d.get("applied"))


def _accepts(fn: Any, name: str) -> bool:
    try:
        return name in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


# --------------------------------------------------------------------------- rate limits


class _LocalWindow(object):
    """Sliding one-minute window per key (used when the app has no Flask-Limiter)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: Dict[Tuple[str, str], "deque[float]"] = {}

    def hit(self, name: str, key: str, limit: int, window: float = 60.0) -> Tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 5000:
                self._hits = {k: v for k, v in self._hits.items() if v and v[-1] > now - window}
            q = self._hits.setdefault((name, key), deque())
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False, max(1, int(q[0] + window - now) + 1)
            q.append(now)
            return True, 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


_LOCAL_WINDOW = _LocalWindow()


def _app_limiter() -> Tuple[bool, Any]:
    """(enabled, Flask-Limiter instance or None) from ``current_app.extensions``."""
    exts = current_app.extensions.get("limiter")
    items = list(exts) if isinstance(exts, (set, frozenset, list, tuple)) else (
        [exts] if exts is not None else [])
    for lim in items:
        if getattr(lim, "enabled", True) is False:
            return False, None
        if getattr(lim, "limiter", None) is not None:
            return True, lim
    return True, None


def _hit(name: str, key: str, limit: int) -> Tuple[bool, int]:
    enabled, lim = _app_limiter()
    if not enabled:
        return True, 0
    if lim is not None:
        try:
            from limits import RateLimitItemPerMinute

            item = RateLimitItemPerMinute(limit)
            ids = ("aiguard-gateway", name, key)
            strategy = lim.limiter
            if strategy.hit(item, *ids):
                return True, 0
            try:
                reset = strategy.get_window_stats(item, *ids).reset_time
                retry = max(1, int(reset - time.time()) + 1)
            except Exception:  # noqa: BLE001 - the refusal stands without the exact time
                retry = 60
            return False, retry
        except Exception:  # noqa: BLE001 - storage problem: fall back to this process
            pass
    return _LOCAL_WINDOW.hit(name, key, limit)


def _rate_limit(name: str, what: str) -> None:
    """Refuse (429) the ``name`` request beyond :data:`RATE_LIMITS` per minute for this
    user and client address."""
    limit = RATE_LIMITS.get(name)
    if not limit:
        return
    key = "%s|%s" % (_user(), request.remote_addr or "-")
    ok, retry = _hit(name, key, limit)
    if ok:
        return
    raise BadInput("Too many %s attempts: wait %d seconds and try again" % (what, retry),
                   code="web.rate_limited", status=429,
                   why="The console allows %d %s attempts per minute for each user and client."
                       % (limit, what),
                   fix=["Wait a minute, check the values, then try again"],
                   state="Nothing was sent.", details={"retry_after": retry},
                   headers={"Retry-After": str(retry)})


_EMPTY_STATUS: Dict[str, Any] = {
    "connected": False, "connection": None, "gateways": [], "gateway": None,
    "local_ip": None, "preflight": None, "plan": None, "last_apply": None,
    "lakera": {"project_id": None, "validated": False, "validated_by": None, "message": "",
               "masked_key": "", "format_ok": False, "warnings": []},
    "direct_lakera": {"configured": False}, "provider_keys": {}, "moderation_enabled": None,
    "enforcement": None, "results": [], "summary": {"total": 0}, "rollbacks": [],
    "busy": None, "step": "connect", "log_path": None, "report_path": None,
}


def _status_payload(owner: Optional[Key], entry: Optional[_store.Entry]) -> Dict[str, Any]:
    ctx = _ctx()
    if entry is not None:
        st = dict(entry.session.status())
    else:
        st = {k: (dict(v) if isinstance(v, dict) else list(v) if isinstance(v, list) else v)
              for k, v in _EMPTY_STATUS.items()}
    job = ctx.jobs.latest(owner) if owner else None
    hist = ctx.store.history(owner)
    sess = entry.session if entry is not None else None
    st["connection"] = _web_connection(st.get("connection"))
    st["job"] = job.to_dict() if job is not None else None
    moderation_on = bool(st.get("moderation_enabled"))
    if sess is not None and hasattr(sess, "moderation_on"):
        try:
            moderation_on = bool(sess.moderation_on())
        except Exception:  # noqa: BLE001 - informational only
            pass
    plan_dict = st.get("plan") if isinstance(st.get("plan"), dict) else None
    st["web"] = {
        "session": entry is not None,
        "mgmt_ca": bool(entry is not None and entry.mgmt_ca),
        "outbound_ca": bool(entry is not None and entry.outbound_ca),
        "last_error": (entry.last_error if entry is not None else None) or hist.get("last_error"),
        "log_path": st.get("log_path") or hist.get("log_path"),
        "idle_minutes": IDLE_MINUTES,
        "user": _user(),
        "plan_applied": _plan_published(getattr(sess, "plan", None), plan_dict),
        "moderation_on": moderation_on,
        "engine_busy": _store.session_busy(sess) if sess is not None else None,
    }
    st["defaults"] = ctx.defaults_view()
    # Published and installed, with only an optional step (content moderation) left to do
    # by hand: the demo policy is live, so the demo is the next step.
    la = st.get("last_apply") if isinstance(st.get("last_apply"), dict) else {}
    if (st.get("step") == "install" and la.get("installed") and la.get("kind", "apply") == "apply"
            and plan_dict and la.get("plan_id") == plan_dict.get("plan_id")):
        st["step"] = "demo"
    return st


# --------------------------------------------------------------------------- input helpers


def _body() -> Dict[str, Any]:
    return getattr(g, "gw_body", None) or {}


def _ip(data: Dict[str, Any], name: str, *, label: str) -> Optional[str]:
    value = _text(data, name, label=label, max_len=45)
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise BadInput("%s must be an IP address such as 10.1.1.20" % label, field=name) from None


def _text(data: Dict[str, Any], name: str, *, label: str, required: bool = False,
          max_len: int = 200, default: Optional[str] = None,
          pattern: Optional["re.Pattern[str]"] = None, multiline: bool = False) -> Optional[str]:
    value = data.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise BadInput("%s is required" % label, field=name)
        return default
    if not isinstance(value, str):
        raise BadInput("%s must be text" % label, field=name)
    value = value if multiline else value.strip()
    if len(value) > max_len:
        raise BadInput("%s is too long (at most %d characters)" % (label, max_len), field=name)
    bad = _CTRL_MULTILINE_RE if multiline else _CTRL_RE
    if bad.search(value):
        raise BadInput("%s contains control characters" % label, field=name)
    if pattern is not None and not pattern.match(value):
        raise BadInput("%s is not valid" % label, field=name)
    return value


def _secret(data: Dict[str, Any], name: str, *, label: str, required: bool = True,
            max_len: int = 1024) -> Optional[str]:
    """A secret field. Error messages never contain the value."""
    value = data.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise BadInput("%s is required" % label, field=name)
        return None
    if not isinstance(value, str):
        raise BadInput("%s must be text" % label, field=name)
    value = value.strip()
    if len(value) > max_len:
        raise BadInput("%s is too long" % label, field=name)
    if _CTRL_RE.search(value):
        raise BadInput("%s contains line breaks or control characters" % label, field=name,
                       fix=["Copy it again without spaces or line breaks"])
    return value


def _choice(data: Dict[str, Any], name: str, choices: Sequence[str], *, label: str,
            default: str) -> str:
    value = data.get(name)
    if value is None or value == "":
        return default
    if not isinstance(value, str):
        raise BadInput("%s must be one of: %s" % (label, ", ".join(choices)), field=name)
    for c in choices:
        if value.strip().lower() == c.lower():
            return c
    raise BadInput("%s must be one of: %s" % (label, ", ".join(choices)), field=name)


def _bool(data: Dict[str, Any], name: str, *, default: bool = False) -> bool:
    value = data.get(name, default)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    raise BadInput("%s must be true or false" % name, field=name)


def _int(data: Dict[str, Any], name: str, *, label: str, default: int, lo: int, hi: int) -> int:
    value = data.get(name, default)
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise BadInput("%s must be a number" % label, field=name)
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise BadInput("%s must be a number" % label, field=name) from None
    if not lo <= number <= hi:
        raise BadInput("%s must be between %d and %d" % (label, lo, hi), field=name)
    return number


def _provider(data: Dict[str, Any]) -> str:
    name = _text(data, "provider", label="The provider", max_len=40, default="openai") or "openai"
    name = name.lower()
    allowed = [p["name"] for p in _ctx().providers()]
    if name not in allowed:
        raise BadInput("Unknown provider '%s'" % name[:40], field="provider",
                       fix=["Pick one of: %s" % ", ".join(allowed)])
    return name


def _pem(data: Dict[str, Any], name: str = "ca_pem") -> Optional[str]:
    value = data.get(name)
    if value is None or value == "":
        return None
    try:
        return _store.normalize_ca_pem(value)
    except _store.CaPemError as exc:
        raise BadInput(str(exc), field=name,
                       fix=["Export the certificate as PEM (Base-64) and paste it, or pick the "
                            ".pem / .crt file again"]) from None


# --------------------------------------------------------------------------- decorator


def api(fn: Callable[..., Any]) -> Callable[..., Any]:
    """JSON API wrapper: JSON-object bodies for POST (415/413/400 otherwise), five-field
    errors for refused input and AiguardError, remembers the last error for Diagnostics."""

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        if request.method == "POST":
            if not request.is_json:
                return _error_response(BadInput(
                    "Send the request as JSON (Content-Type: application/json)",
                    code="web.unsupported_media_type", status=415).to_dict(), 415)
            length = request.content_length
            if length is not None and length > MAX_BODY_BYTES:
                return _error_response(BadInput("The request is too large",
                                                code="web.too_large", status=413).to_dict(), 413)
            raw = request.get_data(cache=True)
            if len(raw) > MAX_BODY_BYTES:
                return _error_response(BadInput("The request is too large",
                                                code="web.too_large", status=413).to_dict(), 413)
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return _error_response(BadInput("The request body must be a JSON object",
                                                code="web.bad_json").to_dict(), 400)
            g.gw_body = data
        try:
            return fn(*args, **kwargs)
        except _store.SessionClosed:
            exc = _session_closed()
            return _error_response(exc.to_dict(), exc.status)
        except BadInput as exc:
            return _error_response(exc.to_dict(), exc.status, headers=exc.headers)
        except AiguardError as exc:
            owner = _owner()
            entry = _ctx().store.get(owner, touch=False) if owner else None
            err = error_dict(exc, log_path=_log_path(entry))
            _ctx().store.remember_error(owner, err)
            return _error_response(err, _http_status(exc))
        except Exception as exc:  # noqa: BLE001 - JSON five-field error, details in the run log
            owner = _owner()
            entry = _ctx().store.get(owner, touch=False) if owner else None
            if entry is not None:
                try:
                    import traceback

                    entry.session.log.error("web", "unexpected error in %s" % request.path,
                                            type=type(exc).__name__)
                    entry.session.log.debug("web", "traceback", traceback="".join(
                        traceback.format_exception(type(exc), exc, exc.__traceback__)).rstrip())
                except Exception:  # noqa: BLE001
                    pass
            err = error_dict(exc, log_path=_log_path(entry))
            _ctx().store.remember_error(owner, err)
            return _error_response(err, 500)

    return wrapper


def _start_job(owner: Key, entry: _store.Entry, kind: str, fn: Callable[..., Any], *,
               steps: Optional[List[dict]] = None, label: str = ""):
    ctx = _ctx()
    job = ctx.jobs.start(kind, owner, fn, steps=steps, log_path=_log_path(entry),
                         label=label or kind,
                         on_error=lambda err: ctx.store.remember_error(owner, err))
    return _ok({"job": job.to_dict()}, 202)


# --------------------------------------------------------------------------- pages


def _page_context(step: str) -> Dict[str, Any]:
    ctx = _ctx()
    key = ctx.saved_lakera_key()
    number = _STEP_IDS.index(step) + 1 if step in _STEP_IDS else 1
    return {
        "gw_steps": STEPS,
        "gw_step": step,
        "gw_step_no": number,
        "gw_step_total": len(STEPS),
        "gw_saved": {"project_id": ctx.saved_project_id(), "key_saved": bool(key),
                     "key_hint": mask_hint(key)},
        "gw_tracks": THREAT_TRACKS,
        "gw_idle_minutes": IDLE_MINUTES,
        "gw_defaults": ctx.defaults_view(),
    }


@bp.route("/")
@login_required
def index():
    owner = _owner()
    entry = _ctx().store.get(owner) if owner else None
    step = "connect"
    if entry is not None:
        step = str(_status_payload(owner, entry).get("step") or "connect")
    if step not in _STEP_IDS:
        step = "connect"
    return redirect(url_for("gateway.%s" % step))


def _make_page(step: str) -> Callable[[], Any]:
    def view():
        owner = _owner()
        if owner is not None:
            _ctx().store.get(owner)          # a page view is activity (idle timer restarts)
        return render_template("gateway/%s.html" % step, **_page_context(step))

    view.__name__ = "page_%s" % step
    return login_required(view)


for _step_id, _title in STEPS:
    bp.add_url_rule("/%s" % _step_id, endpoint=_step_id, view_func=_make_page(_step_id))


# --------------------------------------------------------------------------- API: session


@bp.route("/api/status", methods=["GET"])
@login_required
@api
def api_status():
    owner = _owner()
    # Polling is not activity: an open tab must not keep a session alive forever.
    entry = _ctx().store.get(owner, touch=False) if owner else None
    return _ok(_status_payload(owner, entry))


@bp.route("/api/connect", methods=["POST"])
@login_required
@api
def api_connect():
    ctx = _ctx()
    data = _body()
    server = _text(data, "server", label="The management server address", required=True,
                   max_len=253, pattern=_HOST_RE)
    port = _int(data, "port", label="The port", default=443, lo=1, hi=65535)
    server_type = _choice(data, "server_type", ("SMS", "MDS"), label="Server type",
                          default="SMS")
    domain = _text(data, "domain", label="The domain", max_len=128)
    auth = _choice(data, "auth", ("api-key", "password"), label="Sign in with",
                   default="api-key")
    api_key = user = password = None
    if auth == "api-key":
        api_key = _secret(data, "api_key", label="The API key", max_len=512)
    else:
        user = _text(data, "user", label="The username", required=True, max_len=128)
        password = _secret(data, "password", label="The password", max_len=512)
    server_name = _text(data, "server_name", label="The certificate name", max_len=253,
                        pattern=_HOST_RE)
    pem = _pem(data, "ca_pem")
    clear_ca = _bool(data, "clear_ca")
    local_ip = _ip(data, "local_ip", label="This server's IP address")
    defaults = ctx.env_defaults()
    env_server = bool(defaults.server) and defaults.applies_to(server)
    if server_name is None and env_server and defaults.server_name:
        server_name = defaults.server_name

    owner = _owner(create=True)
    if owner is None:
        raise _not_connected()
    if ctx.jobs.is_busy(owner):
        raise _job_running(fix="Wait for it to finish, then connect again")
    _rate_limit("connect", "connect")
    entry = ctx.store.create(owner)
    sess = entry.session
    busy = _store.session_busy(sess)
    if busy:
        raise _job_running("Another operation is still running (%s)" % busy,
                           fix="Wait for it to finish, then connect again")
    if pem:
        ctx.store.save_ca(entry, pem, "mgmt")
    elif clear_ca:
        ctx.store.clear_ca(entry, "mgmt")
    if local_ip:
        sess.local_ip = local_ip
        sess.log.info("web", "local IP set by the user", local_ip=local_ip)
    warnings: List[str] = []
    ca_file = str(entry.mgmt_ca) if entry.mgmt_ca else None
    ca_source = "upload" if ca_file else None
    if ca_file is None and not pem and not clear_ca:
        # The installer's CA, read in place: never copied to the per-session CA folder,
        # never deleted (SessionStore.protected).
        env_ca, problem = ctx.env_ca()
        if env_ca is not None:
            ca_file = str(env_ca["path"])
            ca_source = "installer"
            sess.log.info("web", "using the management CA provided by the installer",
                          ca_file=ca_file, sha1=env_ca.get("sha1"))
        elif problem:
            warnings.append("The management certificate provided by the installer (%s) was "
                            "not used: %s." % (_envdefaults.ENV_CA_FILE, problem))
            sess.log.warn("web", "the installer's management CA was not used", reason=problem)
    previous = _last_connection(sess)
    extra: Dict[str, Any] = {}
    if ca_file and _accepts(sess.connect, "remember_ca"):
        extra["remember_ca"] = False
    info = sess.connect(server, port=port, api_key=api_key, user=user, password=password,
                        domain=domain, ca_file=ca_file, server_name=server_name, **extra)
    _closed_while_running(entry)
    if ca_file and not extra:
        _forget_web_ca(sess, server, previous, ctx.ca_dir)
    info = _web_connection(info)
    detected = str(info.get("server_type") or "unknown")
    seen = str(info.get("fingerprint_sha1") or "").upper()
    if (defaults.fingerprint_sha1 and defaults.applies_to(server) and seen
            and seen != defaults.fingerprint_sha1):
        warnings.append("The certificate's SHA-1 (%s) differs from the one the installer saw "
                        "(%s). Compare it with api fingerprint on the server."
                        % (seen, defaults.fingerprint_sha1))
    if server_type == "MDS" and detected == "SMS":
        warnings.append("This is a Security Management Server, not a Multi-Domain Server."
                        + (" The domain was ignored." if domain else ""))
    discover_error = None
    if detected == "MDS" and not info.get("domain"):
        warnings.append("Connected to the Multi-Domain Server (System Data). Pick the domain "
                        "that manages your gateway to see its gateways.")
    else:
        try:
            sess.discover()
        except AiguardError as exc:
            discover_error = error_dict(exc, log_path=_log_path(entry))
            ctx.store.remember_error(owner, discover_error)
    payload = _status_payload(owner, entry)
    payload.update({"connect": info, "warnings": warnings, "discover_error": discover_error,
                    "ca_source": ca_source})
    return _ok(payload)


def _last_connection(sess: Any) -> Dict[str, Any]:
    try:
        last = sess.state.last()
        return dict(last) if isinstance(last, dict) else {}
    except Exception:  # noqa: BLE001 - informational only
        return {}


def _inside(path: Any, directory: Path) -> bool:
    try:
        return Path(str(path)).resolve().parent == Path(directory).resolve()
    except (OSError, ValueError):
        return False


def _forget_web_ca(sess: Any, server: str, previous: Dict[str, Any], ca_dir: Path) -> None:
    """The engine remembers ``last.ca_file`` for the CLI. A CA uploaded here lives only as
    long as this web session, so put back what was there for this server (or nothing)."""
    try:
        keep = previous.get("ca_file") if str(previous.get("server") or "") == server else None
        if keep and _inside(keep, ca_dir):
            keep = None
        sess.state.set_last(ca_file=keep)
    except Exception as exc:  # noqa: BLE001 - the connection stands without it
        try:
            sess.log.warn("web", "could not reset the remembered CA file", error=type(exc).__name__)
        except Exception:  # noqa: BLE001
            pass


@bp.route("/api/domain", methods=["POST"])
@login_required
@api
def api_domain():
    ctx = _ctx()
    data = _body()
    domain = _text(data, "domain", label="The domain", required=True, max_len=128)
    owner, entry = _entry()
    sess = entry.session
    _need_connected(sess)
    _need_idle(owner, sess, "pick the domain again")
    _rate_limit("domain", "domain switch")
    info = _web_connection(sess.select_domain(domain))
    _closed_while_running(entry)
    discover_error = None
    try:
        sess.discover()
    except AiguardError as exc:
        discover_error = error_dict(exc, log_path=_log_path(entry))
        ctx.store.remember_error(owner, discover_error)
    return _ok({"connect": info, "discover_error": discover_error,
                "status": _status_payload(owner, entry)})


@bp.route("/api/disconnect", methods=["POST"])
@login_required
@api
def api_disconnect():
    ctx = _ctx()
    owner = _owner()
    if owner is not None and ctx.jobs.is_busy(owner):
        raise BadInput("An operation is still running", code="web.job_running", status=409,
                       why="Disconnecting now would log out in the middle of it.",
                       fix=["Wait for it to finish, then disconnect"])
    entry = ctx.store.get(owner, touch=False) if owner else None
    busy = _store.session_busy(entry.session) if entry is not None else None
    if busy:
        # A synchronous request (connect, domain, plan, prompt...) is talking to a server.
        raise BadInput("An operation is still running (%s)" % busy, code="web.job_running",
                       status=409, why="Disconnecting now would log out in the middle of it.",
                       fix=["Wait for it to finish (a login can take up to a minute), then "
                            "disconnect"])
    dropped = ctx.store.drop(owner) if owner else False
    return _ok({"connected": False, "dropped": dropped, "status": _status_payload(owner, None)})


@bp.route("/api/gateway", methods=["POST"])
@login_required
@api
def api_gateway():
    data = _body()
    name = _text(data, "name", label="The gateway name", required=True, max_len=128)
    owner, entry = _entry()
    sess = entry.session
    _need_connected(sess)
    gw = sess.select_gateway(name)
    return _ok({"gateway": gw.to_dict(), "status": _status_payload(owner, entry)})


@bp.route("/api/outbound-ca", methods=["POST"])
@login_required
@api
def api_outbound_ca():
    ctx = _ctx()
    data = _body()
    clear = _bool(data, "clear")
    from_mgmt = not clear and _bool(data, "from_management")
    pem = None if (clear or from_mgmt) else _pem(data, "ca_pem")
    if not clear and not from_mgmt and not pem:
        raise BadInput("Paste the gateway's outbound CA certificate (PEM)", field="ca_pem")
    owner, entry = _entry(create=not from_mgmt)
    sess = entry.session
    # A running preflight or scene reads the current file: change it only when idle.
    _need_idle(owner, sess, "set the outbound CA again")
    cert: Optional[Dict[str, Any]] = None
    if from_mgmt:
        _need_connected(sess)
        pem, cert = _outbound_ca_from_management(sess)
    if clear:
        # the engine first (it can refuse while an operation runs), then the file
        _set_provider_ca(sess, None)
        ctx.store.clear_ca(entry, "outbound")
    else:
        previous = entry.outbound_ca
        try:
            path = ctx.store.save_ca(entry, pem or "", "outbound")
        except _store.CaPemError as exc:
            raise BadInput("The outbound CA from the management server could not be used: %s"
                           % exc, code="web.outbound_ca_invalid",
                           fix=["Export it in SmartConsole (gateway > HTTPS Inspection > Step 2: "
                                "Export Certificate) and paste the PEM instead"]) from None
        try:
            _set_provider_ca(sess, str(path))
        except AiguardError:
            # e.g. engine.busy: the engine keeps the old CA, so the console does too
            ctx.store.restore_ca(entry, "outbound", previous, path)
            raise
    sess.log.info("web", "outbound CA for provider traffic %s" % (
        "cleared" if clear else "read from the management server" if from_mgmt else "set"),
        name=(cert or {}).get("name"))
    return _ok({"outbound_ca": not clear, "source": "management" if from_mgmt else
                ("cleared" if clear else "upload"), "certificate": cert,
                "status": _status_payload(owner, entry)})


def _set_provider_ca(sess: Any, path: Optional[str]) -> None:
    setter = getattr(sess, "set_provider_ca_file", None)
    if callable(setter):
        setter(path)   # under the engine's operation lock
    else:
        sess.provider_ca_file = path


def _outbound_ca_from_management(sess: Any) -> Tuple[str, Dict[str, Any]]:
    """(PEM, display facts) of the gateway's outbound CA, read with the Management API."""
    manual = ["SmartConsole > Security Policies > HTTPS Inspection > Outbound Policy > Outbound "
              "Certificates: select the CA and export it (or gateway > HTTPS Inspection > "
              "Step 2: Export Certificate)",
              "Paste the PEM (or pick the file) in the outbound CA panel on Preflight"]
    reader = getattr(sess, "outbound_ca", None)
    if not callable(reader):
        raise BadInput("This engine cannot read the outbound CA from the management server",
                       code="web.unsupported", status=501, fix=manual)
    info = reader()
    pem = info.get("pem") if isinstance(info, dict) else None
    cert = {k: info.get(k) for k in ("name", "issued-by", "subject", "valid-from", "valid-to",
                                     "is-default")} if isinstance(info, dict) else {}
    if not pem:
        pkcs12 = bool(isinstance(info, dict) and info.get("pkcs12_only"))
        raise BadInput(
            "The management server did not return the outbound CA as a certificate",
            code="web.outbound_ca_pkcs12" if pkcs12 else "web.outbound_ca_missing", status=409,
            why=("This Management API version (1.9.x) returns the outbound CA only as a "
                 "PKCS#12 file, which can hold its private key; AI Guard does not use it."
                 if pkcs12 else "The reply had no public certificate."),
            fix=manual, details={"certificate": cert})
    return str(pem), cert


# --------------------------------------------------------------------------- API: preflight


@bp.route("/api/preflight", methods=["POST"])
@login_required
@api
def api_preflight():
    data = _body()
    package = _text(data, "package", label="The policy package", max_len=128)
    owner, entry = _entry()
    sess = entry.session
    _need_gateway(sess)

    def run(job):
        report = sess.run_preflight(package=package, progress_cb=job.preflight_cb)
        return {"preflight": report.to_dict()}

    steps = [{"id": cid, "title": TITLES.get(cid, cid)} for cid in CHECK_IDS]
    return _start_job(owner, entry, "preflight", run, steps=steps, label="preflight")


# --------------------------------------------------------------------------- API: configure


@bp.route("/api/lakera", methods=["POST"])
@login_required
@api
def api_lakera():
    ctx = _ctx()
    data = _body()
    use_saved = _bool(data, "use_saved")
    if use_saved:
        key = ctx.saved_lakera_key()
        if not key:
            raise BadInput("No key is saved in Settings", field="use_saved",
                           fix=["Enter the Guard API key here, or save it in Settings > AI "
                                "Guardrails first"])
    else:
        key = _secret(data, "api_key", label="The Guard API key", max_len=512) or ""
    project_id = _text(data, "project_id", label="The project ID", required=True, max_len=200)
    direct = _bool(data, "direct_check")
    owner, entry = _entry(create=True)
    sess = entry.session
    _need_idle(owner, sess, "check the key again")
    _rate_limit("lakera", "key check")
    digest = hashlib.sha256(("%s\n%s" % (key, project_id or "")).encode("utf-8")).hexdigest()
    try:
        before = ctx.lakera_digest.get(sess)
    except TypeError:
        before = None
    result = sess.set_lakera(key, project_id or "", direct_check=direct)
    try:
        ctx.lakera_digest[sess] = digest
    except TypeError:
        pass
    # A plan built with another key / project would install that one: build it again.
    plan = getattr(sess, "plan", None)
    plan_cleared = bool(plan is not None and before != digest and
                        (getattr(plan, "template", None) or "ai-agent-security") ==
                        "ai-agent-security")
    if plan_cleared:
        sess.plan = None
        sess.log.info("web", "the plan was cleared: the AI key or project changed",
                      plan_id=getattr(plan, "plan_id", None))
    return _ok({"lakera": result, "plan_cleared": plan_cleared,
                "status": _status_payload(owner, entry)})


@bp.route("/api/plan", methods=["POST"])
@login_required
@api
def api_plan():
    data = _body()
    template = _choice(data, "template", ("ai-agent-security", "https-inspection"),
                       label="The template", default="ai-agent-security")
    owner, entry = _entry()
    sess = entry.session
    _need_gateway(sess)
    if template == "https-inspection":
        plan = sess.build_https_plan(add_rule=_bool(data, "add_rule"))
    else:
        opts = data.get("options")
        if opts is None:
            opts = {}
        if not isinstance(opts, dict):
            raise BadInput("options must be an object", field="options")
        options = PlanOptions(
            gateway=sess.gateway.name,
            package=_text(opts, "package", label="The policy package", max_len=128),
            profile_name=_text(opts, "profile_name", label="The threat profile name",
                               max_len=100, default="AIGuard-Demo") or "AIGuard-Demo",
            rule_name=_text(opts, "rule_name", label="The threat rule name", max_len=100,
                            default="AI Guard Demo") or "AI Guard Demo",
            track=_choice(opts, "track", THREAT_TRACKS, label="Track", default="Log"),
            scope=_text(opts, "scope", label="The protected scope", max_len=128,
                        default="client") or "client",
            moderation=_bool(opts, "moderation"),
            lakera_project_id=_text(opts, "lakera_project_id", label="The project ID",
                                    max_len=200),
            install=_bool(opts, "install", default=True),
        )
        plan = sess.build_plan(options)
    return _ok({"plan": plan.to_dict(), "status": _status_payload(owner, entry)})


# --------------------------------------------------------------------------- API: apply


@bp.route("/api/apply", methods=["POST"])
@login_required
@api
def api_apply():
    ctx = _ctx()
    data = _body()
    plan_id = _text(data, "plan_id", label="The plan id", required=True, max_len=64,
                    pattern=_ID_RE)
    typed = data.get("typed")
    acknowledge = data.get("acknowledge")
    confirm = _bool(data, "confirm", default=True)
    provider = _provider(data) if data.get("provider") else "openai"
    owner, entry = _entry()
    sess = entry.session
    _need_connected(sess)
    plan = sess.plan
    if plan is None:
        raise BadInput("There is no plan to approve", code="web.no_plan", status=409,
                       fix=["Build the plan on Configure, review it, then approve it here"])
    if plan_id != plan.plan_id:
        raise BadInput("The plan changed since you reviewed it (approved %s, current %s)"
                       % (plan_id, plan.plan_id), code="web.plan_mismatch", field="plan_id",
                       why="Approval is tied to the exact plan you saw.",
                       fix=["Review the plan shown on this page and approve it again"])
    if not isinstance(typed, str) or typed.strip() != "APPROVE":
        raise BadInput("Type APPROVE (in capitals) to confirm", code="web.not_approved",
                       field="typed", fix=["Type APPROVE in the box, tick the checkbox, then "
                                           "press Approve and install"])
    if acknowledge is not True:
        raise BadInput("Tick the box to confirm you understand what will change",
                       code="web.not_acknowledged", field="acknowledge")
    plan_dict = plan.to_dict()
    if _plan_published(plan, plan_dict):
        raise BadInput("Plan %s was already applied" % plan.plan_id, code="web.plan_applied",
                       status=409,
                       why="An approved plan runs once. Its changes were published (and may "
                           "have been rolled back since), so this plan cannot run again.",
                       fix=["Build a new plan on Configure (it updates the objects that exist "
                            "now), review it, then approve it here"])
    _need_idle(owner, sess, "approve the plan again")
    _rate_limit("apply", "approval")
    user = _user()
    template = plan_dict.get("template") or "ai-agent-security"
    do_confirm = bool(confirm and template == "ai-agent-security"
                      and any(s.get("kind") == "install" for s in plan_dict.get("steps") or []))
    gw_name = plan_dict.get("gateway")
    # the plan's own options (not the display copy, which is redacted)
    options = dict(getattr(plan, "options", None) or plan_dict.get("options") or {})

    def run(job):
        import datetime as _dt

        approved_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sess.log.info("approval", "plan approved in the web console", plan_id=plan_id,
                      approved_by=user, template=template, gateway=gw_name)
        _verify_plan(job, sess, plan_id, options)
        res = sess.apply(plan_id, progress_cb=job.progress_cb)
        out = res.to_dict()
        out["approved_by"] = user
        out["approved_at"] = approved_at
        # Published and installed, but an optional step (a gateway script such as content
        # moderation) needs to be done by hand: the policy is live, so check enforcement.
        partial = (not res.ok) and bool(res.installed)
        if not res.ok and not partial:
            err = res.error.to_dict() if res.error is not None else {
                "what": res.message or "The change did not complete", "server_said": None,
                "why": None, "fix": [], "state": out.get("state"), "code": "plan.failed",
                "log_line": None}
            if do_confirm:
                job.update("confirm", "skipped", None,
                           "Not run: the policy was not installed" if res.published else
                           "Not run: nothing was published")
            raise JobFailure(err, {"apply": out})
        if partial:
            out["partial"] = True
            sess.log.warn("web", "published and installed; one step needs attention",
                          plan_id=plan_id, error=(res.error.what if res.error else None))
        if do_confirm and res.installed:
            job.update("confirm", "running", None, "Sending one test prompt, expecting a block")
            try:
                ctx.refresh_provider_keys(sess)
                r = sess.confirm_enforcement(provider)
                rd = r.to_dict()
                diag = sess.diagnose(r)
                ctx.record(rd, gateway=gw_name, kind="enforcement", user=user,
                           diagnosis=diag, log=sess.log)
                ok = r.verdict == "BLOCKED"
                out["enforcement"] = {"confirmed": ok, "result": rd, "diagnosis": diag}
                job.update("confirm", "done" if ok else "warning", 100,
                           "Blocked as expected" if ok else
                           "Not blocked (%s): see the reasons below" % r.verdict)
            except AiguardError as exc:
                out["enforcement"] = {"confirmed": False,
                                      "error": error_dict(exc, log_path=_log_path(entry))}
                job.update("confirm", "failed", None, exc.what)
        elif do_confirm:
            job.update("confirm", "skipped", None, "Not run: policy was not installed")
        return {"apply": out}

    steps = [{"id": "verify", "title": "Check the plan against the server again (read-only)"}]
    steps += [{"id": s.get("id"), "title": s.get("describe") or s.get("id")}
              for s in plan_dict.get("steps") or []]
    if do_confirm:
        steps.append({"id": "confirm", "title": "Confirm enforcement: send one test prompt, "
                                                "expect a block"})
    return _start_job(owner, entry, "apply", run, steps=steps,
                      label="install" if template == "ai-agent-security" else "HTTPS fix")


def _verify_plan(job: Any, sess: Any, plan_id: str, options: Dict[str, Any]) -> None:
    """Build the plan again (read-only) right before applying it, so what runs is decided
    on what the server holds now (who owns each object, what exists, the current key).
    A different plan id refuses the approval: the user reviews the new plan."""
    fields = getattr(PlanOptions, "__dataclass_fields__", {})
    opts = {k: v for k, v in options.items() if k in fields}
    if not opts.get("gateway"):
        job.update("verify", "skipped", 100, "Not checked: the plan has no options to rebuild it")
        return
    job.update("verify", "running", None, "Reading the objects again (read-only)")
    try:
        fresh = sess.build_plan(PlanOptions(**opts))
    except AiguardError as exc:
        job.update("verify", "failed", None, exc.what)
        raise
    if fresh.plan_id == plan_id:
        job.update("verify", "done", 100, "The server still matches the plan you approved")
        return
    job.update("verify", "failed", None, "The plan is now %s" % fresh.plan_id)
    sess.log.warn("approval", "the plan changed between review and approval: nothing applied",
                  approved=plan_id, now=fresh.plan_id)
    raise JobFailure({
        "type": "BadInput", "code": "web.plan_mismatch",
        "what": "The server changed since you reviewed the plan (approved %s, now %s)"
                % (plan_id, fresh.plan_id),
        "server_said": None,
        "why": "Approval is tied to the exact plan you saw. Read again just now, an object was "
               "added, changed or removed on the management server, or the key or options "
               "changed.",
        "fix": ["Review the new plan on this page and approve it if it is what you want"],
        "state": "Nothing was changed.", "details": {"approved": plan_id, "now": fresh.plan_id},
        "log_line": None}, {"plan": fresh.to_dict()})


@bp.route("/api/rollback", methods=["POST"])
@login_required
@api
def api_rollback():
    data = _body()
    rid = _text(data, "rollback_id", label="The rollback id", max_len=64, pattern=_ID_RE)
    install = _bool(data, "install", default=True)
    owner, entry = _entry()
    sess = entry.session
    _need_connected(sess)

    def run(job):
        res = sess.rollback(rid or None, progress_cb=job.progress_cb, install=install)
        out = res.to_dict()
        if not res.ok:
            err = res.error.to_dict() if res.error is not None else {
                "what": res.message or "The rollback did not complete", "server_said": None,
                "why": None, "fix": [], "state": out.get("state"), "code": "plan.failed",
                "log_line": None}
            raise JobFailure(err, {"rollback": out})
        return {"rollback": out}

    return _start_job(owner, entry, "rollback", run, label="rollback")


# --------------------------------------------------------------------------- API: demo


def _result_payload(sess: Any, results: Sequence[Any]) -> List[Dict[str, Any]]:
    out = []
    for r in results:
        rd = r.to_dict()
        rd["diagnosis"] = sess.diagnose(r)
        out.append(rd)
    return out


def _gateway_name(sess: Any) -> Optional[str]:
    gw = getattr(sess, "gateway", None)
    return getattr(gw, "name", None) if gw is not None else None


@bp.route("/api/prompt", methods=["POST"])
@login_required
@api
def api_prompt():
    ctx = _ctx()
    data = _body()
    text = _text(data, "text", label="The prompt", required=True, max_len=PROMPT_MAX_CHARS,
                 multiline=True) or ""
    if not text.strip():
        raise BadInput("The prompt is required", field="text")
    provider = _provider(data)
    expect = _choice(data, "expect", ("block", "allow"), label="Expected result",
                     default="block")
    prompt_id = _text(data, "prompt_id", label="The prompt id", max_len=64,
                      pattern=_ID_RE) or "custom"
    if prompt_id != "custom":
        try:
            _scenes.get_prompt(prompt_id)
        except AiguardError:
            prompt_id = "custom"
    owner, entry = _entry(create=True)
    sess = entry.session
    if ctx.jobs.is_busy(owner):
        raise BadInput("Another operation is still running", code="web.job_running",
                       status=409, fix=["Wait for it to finish, then send the prompt"])
    ctx.refresh_provider_keys(sess)
    result = sess.run_prompt(text, provider=provider, expect=expect, prompt_id=prompt_id)
    warnings: List[str] = []
    if _connected(sess):
        failure = _correlate(sess)
        if failure:
            warnings.append(failure if failure.startswith("Could not read the gateway logs")
                            else "Could not read the gateway logs: %s" % failure)
    rd = result.to_dict()
    diag = sess.diagnose(result)
    rd["diagnosis"] = diag
    ctx.record(rd, gateway=_gateway_name(sess), kind="prompt", user=_user(), diagnosis=diag,
               log=sess.log)
    return _ok({"result": rd, "diagnosis": diag, "warnings": warnings,
                "summary": sess.summary(), "gateway": _gateway_name(sess),
                "connected": _connected(sess), "local_ip": getattr(sess, "local_ip", None)})


@bp.route("/api/scene", methods=["POST"])
@login_required
@api
def api_scene():
    ctx = _ctx()
    data = _body()
    scene_id = _text(data, "scene_id", label="The scene", required=True, max_len=64,
                     pattern=_ID_RE) or ""
    scene = _scenes.get_scene(scene_id)
    if not scene.prompts:
        raise BadInput("This scene is for a prompt you type yourself",
                       fix=["Type your prompt in the box and press Send"])
    provider = _provider(data)
    owner, entry = _entry(create=True)
    sess = entry.session
    user = _user()

    def run(job):
        ctx.refresh_provider_keys(sess)
        results = sess.run_scene(scene.id, provider=provider, progress_cb=job.progress_cb)
        job.update("correlate", "running", None, "Looking for the matching gateway logs")
        if _connected(sess):
            failure = _correlate(sess)
            if failure:
                job.update("correlate", "warning", 100,
                           failure if failure.startswith("Could not read the gateway logs")
                           else "Could not read the gateway logs: %s" % failure)
            else:
                job.update("correlate", "done", 100, "Gateway logs checked")
        else:
            job.update("correlate", "skipped", 100, "Not connected: gateway logs not checked")
        out = _result_payload(sess, results)
        gw_name = _gateway_name(sess)
        for rd in out:
            ctx.record(rd, gateway=gw_name, kind="scene:%s" % scene.id, user=user,
                       diagnosis=rd.get("diagnosis"), log=sess.log)
        return {"scene": scene.to_dict(), "results": out, "summary": sess.summary()}

    steps = [{"id": p.id, "title": p.text if len(p.text) <= 90 else p.text[:87].rstrip() + "..."}
             for p in scene.prompts]
    steps.append({"id": "correlate", "title": "Find the gateway logs (SmartConsole)"})
    return _start_job(owner, entry, "scene", run, steps=steps, label="scene %s" % scene.id)


@bp.route("/api/correlate", methods=["POST"])
@login_required
@api
def api_correlate():
    owner, entry = _entry()
    sess = entry.session
    _need_connected(sess)
    failure = _correlate(sess)
    return _ok({"results": _result_payload(sess, list(sess.results)),
                "summary": sess.summary(), "warnings": [failure] if failure else [],
                "correlate_error": getattr(sess, "correlate_error", None)})


@bp.route("/api/tls-check", methods=["POST"])
@login_required
@api
def api_tls_check():
    """TLS handshake towards a provider through the gateway (no prompt is sent)."""
    data = _body()
    provider = _provider(data)
    owner, entry = _entry(create=True)
    sess = entry.session
    if _ctx().jobs.is_busy(owner):
        raise _job_running(fix="Wait for it to finish, then check again")
    check = getattr(sess, "tls_check", None)
    if not callable(check):
        raise BadInput("This engine has no TLS check", code="web.unsupported", status=501)
    return _ok({"tls": check(provider), "provider": provider})


@bp.route("/api/discard", methods=["POST"])
@login_required
@api
def api_discard():
    """Discard the unpublished changes of this browser's management session."""
    owner, entry = _entry()
    sess = entry.session
    _need_connected(sess)
    _need_idle(owner, sess, "discard")
    discard = getattr(sess, "discard", None)
    if not callable(discard):
        raise BadInput("This engine cannot discard changes", code="web.unsupported", status=501)
    done = bool(discard())
    return _ok({"discarded": done, "status": _status_payload(owner, entry)})


@bp.route("/api/scenes", methods=["GET"])
@login_required
@api
def api_scenes():
    return _ok({"scenes": _scenes.list_scenes(), "providers": _ctx().providers()})


# --------------------------------------------------------------------------- API: jobs, logs


@bp.route("/api/jobs/<job_id>", methods=["GET"])
@login_required
@api
def api_job(job_id: str):
    owner = _owner()
    job = _ctx().jobs.get(job_id, owner) if (owner and _JOB_ID_RE.match(job_id or "")) else None
    if job is None:
        raise BadInput("This job was not found", code="web.job_not_found", status=404,
                       why="Jobs belong to the browser session that started them.")
    return _safe_json(job.to_dict())


@bp.route("/api/log", methods=["GET"])
@login_required
@api
def api_log():
    ctx = _ctx()
    level = (request.args.get("level") or "").strip()
    component = (request.args.get("component") or "").strip()
    if not _FILTER_RE.match(level) or not _FILTER_RE.match(component):
        raise BadInput("Invalid log filter", fix=["Use level=ERROR,WARN and component=mgmt"])
    n = _int(request.args.to_dict(), "n", label="n", default=200, lo=1, hi=2000)
    owner = _owner()
    entry = ctx.store.get(owner, touch=False) if owner else None
    hist = ctx.store.history(owner)
    if entry is not None:
        log = entry.session.log
        records = log.tail(n, level=level or None, component=component or None)
        everything = log.tail(5000)
        path = str(getattr(log, "path", "") or "") or None
    else:
        jsonl = hist.get("jsonl_path")
        records = _store.read_jsonl_tail(Path(jsonl), n, level or None,
                                         component or None) if jsonl else []
        everything = _store.read_jsonl_tail(Path(jsonl), 5000) if jsonl else []
        path = hist.get("log_path")
    components = sorted({str(r.get("component") or "") for r in everything} - {""})
    counts: Dict[str, int] = {}
    for r in everything:
        lvl = str(r.get("level") or "").upper()
        counts[lvl] = counts.get(lvl, 0) + 1
    # Log lines are returned exactly as written (no web rewording).
    return _safe_json({"ok": True, "records": records, "log_path": path,
                       "components": components, "counts": counts, "live": entry is not None},
                      raw=True)


@bp.route("/api/report", methods=["GET"])
@login_required
@api
def api_report():
    from aiguard import report as _report

    owner = _owner()
    entry = _ctx().store.get(owner, touch=False) if owner else None
    if entry is None:
        return _ok({"report": None})
    return _safe_json({"ok": True, "report": _report.build_report(entry.session)}, raw=True)
