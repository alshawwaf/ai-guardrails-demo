"""Send prompts to LLM developer APIs through the gateway and judge the result (spec 5.1).

Ported from ``ai_guard_test.py`` and extended:

* :data:`PROVIDERS` -- the developer endpoints AI Agent Security protects (same
  hosts, paths, models and auth headers as ``ai_guard_test.py``), plus an
  optional ``azure`` entry that needs an endpoint (``base_url``).
* :func:`send_prompt` -- one HTTPS request with the stdlib ``http.client``
  (through :mod:`aiguard.tlsutil`: verification always on, TLS 1.2+), an
  explicit timeout and **no redirect following**. The TLS handshake tells us
  who issued the certificate (re-signed by HTTPS Inspection or not), the source
  address the gateway sees and the remote address.
* :func:`classify_http` -- BLOCKED / ALLOWED / UNKNOWN from an HTTP reply.
* :func:`tls_probe` -- handshake only: is this host inspected from here?
* :func:`local_ip_for` -- the source IP this computer uses towards a host
  (UDP ``connect`` trick; no packet is sent to the host).

Verdicts (spec section 10):

* ``BLOCKED`` -- a 3xx whose ``Location`` contains ``/UserCheck/``, a non-JSON
  block page (UserCheck / Check Point markers), or the connection was reset,
  aborted or closed after the prompt was sent ("connection terminated by the
  network").
* ``ALLOWED`` -- a JSON reply from the provider, whatever the status: a 401
  with the provider's JSON error still means the prompt crossed the gateway.
* ``UNKNOWN`` -- no reply before the timeout (a silent drop is possible;
  ``correlate`` may upgrade it with a gateway log), or a reply that is neither
  JSON nor a block page.
* ``ERROR`` -- the prompt was never sent: cannot connect, TLS handshake or
  certificate verification failed (the result carries the five-field error).

Keys come from the ``api_key`` argument, then the provider's environment
variable, else the dummy ``sk-dummy-aiguard`` (``dummy_key=True``: the request
still crosses the gateway, the provider answers 401). Real keys are registered
with :func:`aiguard.redact.register_secret`; they never appear in results,
snippets or logs.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import time
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import quote, urlsplit

from . import __version__
from . import redact as _redact
from . import tlsutil
from .errors import AiguardError, ConnectError

__all__ = [
    "PROVIDERS",
    "STANDARD_PROVIDERS",
    "DUMMY_KEY",
    "VERDICTS",
    "ProbeResult",
    "provider_info",
    "resolve_key",
    "send_prompt",
    "classify_http",
    "tls_probe",
    "local_ip_for",
]

DUMMY_KEY = "sk-dummy-aiguard"
VERDICTS = ("BLOCKED", "ALLOWED", "UNKNOWN", "ERROR")
USER_AGENT = "aiguard/%s (AI Guard Demo Kit)" % __version__

SNIPPET_CHARS = 300
MAX_READ = 64 * 1024              # bytes of the reply we read and scan
MAX_PROMPT_BYTES = 512 * 1024     # AI Agent Security inspects text prompts up to 512 KB
MAX_TIMEOUT = 300.0

# --------------------------------------------------------------------------- providers


def _chat_body(model: str, prompt: str) -> Dict[str, Any]:
    return {"model": model, "max_tokens": 64,
            "messages": [{"role": "user", "content": prompt}]}


def _gemini_body(model: str, prompt: str) -> Dict[str, Any]:
    return {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}


def _bearer(key: str) -> Dict[str, str]:
    return {"Authorization": "Bearer %s" % key}


PROVIDERS: Dict[str, Dict[str, Any]] = {
    "openai": {
        "label": "OpenAI", "host": "api.openai.com", "path": "/v1/chat/completions",
        "env": "OPENAI_API_KEY", "model": "gpt-4o-mini",
        "headers": _bearer, "body": _chat_body,
    },
    "anthropic": {
        "label": "Anthropic", "host": "api.anthropic.com", "path": "/v1/messages",
        "env": "ANTHROPIC_API_KEY", "model": "claude-sonnet-4-5",
        "headers": lambda k: {"x-api-key": k, "anthropic-version": "2023-06-01"},
        "body": _chat_body,
    },
    "gemini": {
        "label": "Google Gemini", "host": "generativelanguage.googleapis.com",
        "path": "/v1beta/models/{model}:generateContent",
        "env": "GEMINI_API_KEY", "model": "gemini-2.0-flash",
        "headers": lambda k: {"x-goog-api-key": k},
        "body": _gemini_body,
    },
    "groq": {
        "label": "Groq", "host": "api.groq.com", "path": "/openai/v1/chat/completions",
        "env": "GROQ_API_KEY", "model": "llama-3.1-8b-instant",
        "headers": _bearer, "body": _chat_body,
    },
    "mistral": {
        "label": "Mistral", "host": "api.mistral.ai", "path": "/v1/chat/completions",
        "env": "MISTRAL_API_KEY", "model": "mistral-small-latest",
        "headers": _bearer, "body": _chat_body,
    },
    "together": {
        "label": "Together AI", "host": "api.together.xyz", "path": "/v1/chat/completions",
        "env": "TOGETHER_API_KEY", "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "headers": _bearer, "body": _chat_body,
    },
    "fireworks": {
        "label": "Fireworks AI", "host": "api.fireworks.ai",
        "path": "/inference/v1/chat/completions",
        "env": "FIREWORKS_API_KEY", "model": "accounts/fireworks/models/llama-v3p1-8b-instruct",
        "headers": _bearer, "body": _chat_body,
    },
    "cohere": {
        "label": "Cohere", "host": "api.cohere.com", "path": "/v2/chat",
        "env": "COHERE_API_KEY", "model": "command-r",
        "headers": _bearer, "body": _chat_body,
    },
    "perplexity": {
        "label": "Perplexity", "host": "api.perplexity.ai", "path": "/chat/completions",
        "env": "PERPLEXITY_API_KEY", "model": "sonar",
        "headers": _bearer, "body": _chat_body,
    },
    # Optional: the host is per resource, so it needs base_url (or AZURE_OPENAI_ENDPOINT).
    # "model" is the deployment name.
    "azure": {
        "label": "Azure OpenAI", "host": None,
        "path": "/openai/deployments/{model}/chat/completions?api-version=2024-10-21",
        "env": "AZURE_OPENAI_API_KEY", "model": "gpt-4o-mini",
        "model_env": "AZURE_OPENAI_DEPLOYMENT", "endpoint_env": "AZURE_OPENAI_ENDPOINT",
        "optional": True,
        "headers": lambda k: {"api-key": k}, "body": _chat_body,
    },
}

# The providers that work without extra configuration (what "all" means in a UI).
STANDARD_PROVIDERS: Tuple[str, ...] = tuple(
    name for name, p in PROVIDERS.items() if not p.get("optional"))


def provider_info(name: Optional[str] = None) -> Any:
    """Display-safe provider facts (no callables, no key values).

    ``provider_info()`` -> list of dicts for every provider; ``provider_info("openai")``
    -> one dict. Each: name, label, host, path, env, model, optional, key_configured.
    """
    if name is not None:
        p = _provider(name)
        return {
            "name": name, "label": p.get("label", name), "host": p.get("host"),
            "path": p["path"], "env": p["env"], "model": p["model"],
            "optional": bool(p.get("optional")),
            "key_configured": bool(os.environ.get(p["env"], "").strip()),
        }
    return [provider_info(n) for n in PROVIDERS]


def _provider(name: str) -> Dict[str, Any]:
    key = (name or "").strip().lower()
    if key not in PROVIDERS:
        raise AiguardError(
            "Unknown provider '%s'" % name,
            code="probe.unknown_provider",
            why="aiguard knows these AI developer APIs: %s." % ", ".join(PROVIDERS),
            fix=["Pick one of: %s" % ", ".join(PROVIDERS)],
            state="Nothing was sent.",
        )
    return PROVIDERS[key]


def resolve_key(provider: str, api_key: Optional[str] = None) -> Tuple[str, str]:
    """``(key, source)`` with source ``"explicit"``, ``"env"`` or ``"dummy"``.

    Real keys are registered with :func:`aiguard.redact.register_secret`.
    """
    p = _provider(provider)
    if api_key is not None and str(api_key).strip():
        key, source = str(api_key).strip(), "explicit"
    else:
        env_value = os.environ.get(p["env"], "").strip()
        if env_value:
            key, source = env_value, "env"
        else:
            return DUMMY_KEY, "dummy"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in key):
        raise AiguardError(
            "The %s API key contains control characters" % p.get("label", provider),
            code="probe.bad_key",
            why="A key with line breaks or control characters cannot be sent in an HTTP header.",
            fix=["Copy the key again without spaces or line breaks"],
            state="Nothing was sent.",
        )
    _redact.register_secret(key)
    return key, source


# --------------------------------------------------------------------------- result


@dataclasses.dataclass
class ProbeResult:
    """One prompt sent through the gateway.

    ``id`` is unique per call (``<prompt_id>-<provider>-<6 hex>``) so results of the
    same prompt on several providers can be told apart (correlate keys on it);
    ``prompt_id`` is the scene prompt id (``inj-override``, ``custom`` ...).
    """

    id: str
    provider: str
    host: str
    prompt: str
    expect: str                      # "block" | "allow"
    verdict: str                     # BLOCKED | ALLOWED | UNKNOWN | ERROR
    reason: str
    http_status: Optional[int]
    content_type: str
    ms: int
    inspected: Optional[bool]
    issuer: str
    local_ip: str
    remote_ip: str
    sent_at: str                     # ISO 8601 UTC
    snippet: str                     # redacted, <= 300 chars
    dummy_key: bool
    evidence: str                    # why we called it that
    category: Optional[str] = None
    confidence: Optional[float] = None
    category_source: Optional[str] = None   # "gateway log" | "lakera" | None
    log_match: Optional[dict] = None
    # additions (all display-safe)
    prompt_id: str = "custom"
    model: str = ""
    url: str = ""                    # https://host[:port]/path (never carries a key)
    location: Optional[str] = None   # Location header of a 3xx (redacted)
    key_source: str = "dummy"        # explicit | env | dummy
    sent_epoch: float = 0.0          # same instant as sent_at, seconds since the epoch
    confidence_label: Optional[str] = None  # e.g. "confident" (Lakera levels), never a %
    error: Optional[dict] = None     # AiguardError.to_dict() when verdict is ERROR
    tls: Optional[dict] = None       # issuer/subject/sha256/tls_version/cipher/not_after

    @property
    def matched(self) -> bool:
        want = "BLOCKED" if self.expect == "block" else "ALLOWED"
        return self.verdict == want

    def to_dict(self) -> dict:
        data = dataclasses.asdict(self)
        data["matched"] = self.matched
        return _redact.redact_obj(data)

    @classmethod
    def from_dict(cls, data: dict) -> "ProbeResult":
        """Rebuild from :meth:`to_dict` output (unknown keys such as ``matched`` ignored)."""
        names = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in dict(data).items() if k in names})


# --------------------------------------------------------------------------- classification

_STRONG_MARKERS = ("usercheck", "check point", "checkpoint")
_GENERIC_MARKERS = ("request was blocked", "has been blocked", "blocked by", "access denied",
                    "blocked")
# Block pages of other services in the path: blocked, but not by the gateway.
_THIRD_PARTY = (("cloudflare", "Cloudflare"), ("akamai", "Akamai"), ("incapsula", "Imperva"),
                ("imperva", "Imperva"), ("zscaler", "Zscaler"), ("sucuri", "Sucuri"),
                ("netskope", "Netskope"), ("forcepoint", "Forcepoint"))


def _looks_json(content_type: str, body: bytes) -> bool:
    stripped = body.lstrip()[:1]
    if stripped in (b"{", b"["):
        try:
            json.loads(body.decode("utf-8", "replace"))
            return True
        except ValueError:
            # Truncated reads still look like JSON when the type says so.
            return "json" in content_type
    return "json" in content_type and not body.strip()


def classify_http(status: int, content_type: str, body: bytes, *,
                  location: Optional[str] = None) -> Tuple[str, str]:
    """``(verdict, evidence)`` for an HTTP reply that arrived.

    ``location`` is the ``Location`` header of a 3xx (redirects are never followed).
    """
    ctype = (content_type or "").lower()
    raw = body or b""
    text = raw[:MAX_READ].decode("utf-8", "replace").lower()
    loc = location or ""
    if 300 <= int(status) < 400 and "/usercheck/" in loc.lower():
        return "BLOCKED", "UserCheck redirect (HTTP %d to %s)" % (status, _redact.redact(loc))
    if _looks_json(ctype, raw):
        if int(status) >= 400 and "usercheck" in text:
            return "BLOCKED", "gateway JSON block reply (HTTP %d, marker 'usercheck')" % status
        return "ALLOWED", "JSON reply from the provider (HTTP %d): the prompt reached it" % status
    for marker in _STRONG_MARKERS:
        if marker in text:
            return "BLOCKED", "gateway block page (HTTP %d, marker '%s')" % (status, marker)
    generic = next((m for m in _GENERIC_MARKERS if m in text), None)
    if generic:
        vendor = next((label for needle, label in _THIRD_PARTY if needle in text), None)
        if vendor:
            return "UNKNOWN", ("block page from %s, not the gateway (HTTP %d, marker '%s')"
                               % (vendor, status, generic))
        return "BLOCKED", "block page (HTTP %d, marker '%s')" % (status, generic)
    if 300 <= int(status) < 400:
        where = _redact.redact(loc) if loc else "no Location header"
        return "UNKNOWN", "HTTP %d redirect to %s (not followed)" % (status, where)
    return "UNKNOWN", ("HTTP %d %s reply without JSON or block markers"
                       % (status, content_type or "(no content type)"))


# --------------------------------------------------------------------------- connection


class _ProbeConnection(tlsutil.VerifiedHTTPSConnection):
    """VerifiedHTTPSConnection that remembers whether TCP connected (so a failure can be
    told apart: unreachable vs TLS handshake) and the addresses of the TCP socket."""

    def __init__(self, host: str, port: int, *, context: ssl.SSLContext,
                 timeout: float) -> None:
        super().__init__(host, port, context=context, timeout=timeout)
        self.tcp_ok = False
        self.tcp_local: Optional[str] = None
        self.tcp_remote: Optional[str] = None
        create = getattr(self, "_create_connection", socket.create_connection)

        def _create(address: Any, *args: Any, **kwargs: Any) -> socket.socket:
            sock = create(address, *args, **kwargs)
            self.tcp_ok = True
            try:
                self.tcp_local = sock.getsockname()[0]
                self.tcp_remote = sock.getpeername()[0]
            except (OSError, IndexError):
                pass
            return sock

        self._create_connection = _create


def local_ip_for(host: str, port: int = 443) -> Optional[str]:
    """Source IP this computer would use to reach ``host`` (``None`` if unknown).

    Uses a UDP socket ``connect()``: the OS picks the route and source address but no
    packet is sent to ``host`` (resolving a name may still query DNS).
    """
    name = (host or "").strip().strip("[]")
    if not name:
        return None
    try:
        infos = socket.getaddrinfo(name, int(port or 443), 0, socket.SOCK_DGRAM)
    except (OSError, UnicodeError, ValueError):
        return None
    for family, socktype, proto, _canon, addr in infos:
        try:
            with socket.socket(family, socktype, proto) as s:
                s.connect(addr)
                ip = s.getsockname()[0]
        except OSError:
            continue
        if ip and ip not in ("0.0.0.0", "::"):
            return ip.split("%", 1)[0]
    return None


def _issuer_text(peer: Dict[str, Any]) -> str:
    cn = peer.get("issuer_cn") or ""
    org = peer.get("issuer_org") or ""
    return ("%s / %s" % (cn, org)).strip(" /")


def _tls_view(peer: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not peer:
        return None
    keys = ("issuer_org", "issuer_cn", "subject_cn", "san", "not_after", "sha256",
            "tls_version", "cipher")
    return {k: peer.get(k) for k in keys}


def _connect_error(exc: BaseException, host: str, port: int, *, tcp_ok: bool,
                   timeout: float) -> ConnectError:
    kind = type(exc).__name__
    said = str(exc) or kind
    details = {"host": host, "port": port, "error": "%s: %s" % (kind, said),
               "tcp_connected": tcp_ok}
    if tcp_ok:
        timed_out = isinstance(exc, (socket.timeout, TimeoutError))
        return ConnectError(
            "TLS handshake with %s:%d %s" % (host, port,
                                              "timed out" if timed_out else "failed"),
            code="probe.tls_handshake",
            server_said=said,
            why=("TCP connected, but the TLS handshake did not complete, so the prompt was "
                 "never sent. A proxy or a firewall rule (URL Filtering / Application "
                 "Control) may be closing connections to %s, or the server does not speak "
                 "TLS 1.2+." % host),
            fix=["Check SmartConsole Logs for %s from this computer (Drop / Block / Reject)"
                 % host,
                 "Check proxy settings on this computer (HTTPS_PROXY)",
                 "Try again: openssl s_client -connect %s:%d -servername %s </dev/null"
                 % (host, port, host)],
            state="The prompt was not sent.",
            details=details,
        )
    if isinstance(exc, socket.gaierror):
        what = "Cannot resolve %s (DNS)" % host
        why = "This computer could not look up the address of %s." % host
        fix = ["Check DNS on this computer: nslookup %s" % host,
               "Check proxy settings (HTTPS_PROXY) if the network only allows a proxy"]
    elif isinstance(exc, (socket.timeout, TimeoutError)):
        what = "Cannot reach %s:%d from this computer (no answer in %gs)" % (host, port, timeout)
        why = ("TCP connection attempts got no answer. A firewall may be dropping them, or "
               "there is no route to the internet from here.")
        fix = ["Check the route from this computer to %s:%d (default gateway, proxy)"
               % (host, port),
               "Check SmartConsole Logs for Drop entries from this computer to %s" % host]
    elif isinstance(exc, ConnectionRefusedError):
        what = "Connection to %s:%d was refused" % (host, port)
        why = "Something answered with a TCP reset: nothing listens there, or a device refused it."
        fix = ["Check the address and port",
               "Check proxy settings (HTTPS_PROXY) and firewalls between this computer and %s"
               % host]
    else:
        what = "Cannot reach %s:%d from this computer" % (host, port)
        why = "The TCP connection failed (see the message)."
        fix = ["Check the network route, proxy (HTTPS_PROXY) and DNS for %s" % host]
    return ConnectError(what, code="probe.connect", server_said=said, why=why, fix=fix,
                        state="The prompt was not sent.", details=details)


# --------------------------------------------------------------------------- target


def _parse_base_url(base_url: str) -> Tuple[str, int, str]:
    text = str(base_url or "").strip()
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise AiguardError("Invalid base URL: %s" % _redact.redact(text),
                           code="probe.bad_url", server_said=str(exc),
                           fix=["Use https://host[:port][/path]"],
                           state="Nothing was sent.") from exc
    if parts.scheme.lower() != "https":
        raise AiguardError(
            "The base URL must start with https://",
            code="probe.bad_url",
            why="Prompts are only sent over verified TLS (HTTPS Inspection needs HTTPS too).",
            fix=["Use https://host[:port][/path]"],
            state="Nothing was sent.",
        )
    if not parts.hostname:
        raise AiguardError("The base URL has no host name", code="probe.bad_url",
                           fix=["Use https://host[:port][/path]"], state="Nothing was sent.")
    if parts.username or parts.password or "@" in parts.netloc:
        raise AiguardError(
            "The base URL must not contain credentials",
            code="probe.bad_url",
            why="Keys are sent in headers only, never in URLs.",
            fix=["Remove user:password@ from the URL and pass the key separately"],
            state="Nothing was sent.",
        )
    if parts.query or parts.fragment:
        raise AiguardError("The base URL must not have a query string or fragment",
                           code="probe.bad_url", fix=["Use https://host[:port][/path]"],
                           state="Nothing was sent.")
    return parts.hostname, int(port or 443), parts.path.rstrip("/")


def _target(p: Dict[str, Any], model: str, base_url: Optional[str]) -> Tuple[str, int, str]:
    path = p["path"].replace("{model}", quote(model, safe="-._~"))
    if base_url is None and p.get("endpoint_env"):
        base_url = os.environ.get(p["endpoint_env"], "").strip() or None
    if base_url:
        host, port, prefix = _parse_base_url(base_url)
        if prefix and not (path == prefix or path.startswith(prefix + "/")):
            # SDK-style base URLs often end in the API version (".../v1"): don't repeat it.
            path = prefix + path
        return host, port, path
    if not p.get("host"):
        raise AiguardError(
            "%s needs an endpoint" % p.get("label", "This provider"),
            code="probe.no_endpoint",
            why="The host name is specific to your resource.",
            fix=["Pass base_url https://<resource>.openai.azure.com",
                 "or set %s" % p.get("endpoint_env", "the endpoint")],
            state="Nothing was sent.",
        )
    return p["host"], 443, path


def _url(host: str, port: int, path: str) -> str:
    h = "[%s]" % host if ":" in host else host
    return "https://%s%s%s" % (h, "" if port == 443 else ":%d" % port, path)


# --------------------------------------------------------------------------- helpers


def _now() -> Tuple[str, float]:
    now = _dt.datetime.now(_dt.timezone.utc)
    return now.isoformat(timespec="milliseconds"), now.timestamp()


def _snippet(body: bytes) -> str:
    # Redact first (on a wider window) so a secret straddling the cut is still masked.
    text = body[:4096].decode("utf-8", "replace").replace("\r\n", "\n").replace("\x00", "")
    return _redact.redact(text)[:SNIPPET_CHARS]


def _log(log: Any, level: str, msg: str, **fields: Any) -> Optional[int]:
    if log is None:
        return None
    fn: Optional[Callable[..., int]] = getattr(log, level, None)
    if fn is None:
        return None
    try:
        return fn("probe", msg, **fields)
    except Exception:  # noqa: BLE001 - logging must never break a probe
        return None


def _log_exception(log: Any, err: AiguardError) -> None:
    if log is None or not hasattr(log, "exception"):
        return
    try:
        log.exception(err, "probe")
    except Exception:  # noqa: BLE001
        pass


def _check_timeout(timeout: Any) -> float:
    try:
        value = float(timeout)
    except (TypeError, ValueError):
        value = -1.0
    if not (0 < value <= MAX_TIMEOUT):
        raise AiguardError("Timeout must be between 0 and %d seconds" % MAX_TIMEOUT,
                           code="probe.bad_timeout", state="Nothing was sent.")
    return value


_TERMINATED = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError,
               http.client.RemoteDisconnected, http.client.IncompleteRead,
               ssl.SSLEOFError, ssl.SSLZeroReturnError)


# --------------------------------------------------------------------------- send_prompt


def send_prompt(provider: str, prompt: str, *, prompt_id: str = "custom", expect: str = "block",
                api_key: Optional[str] = None, model: Optional[str] = None,
                ca_file: Optional[str] = None, timeout: float = 30,
                base_url: Optional[str] = None, log: Any = None) -> ProbeResult:
    """Send ``prompt`` to ``provider`` and return the verdict.

    Network outcomes never raise: they become BLOCKED / UNKNOWN / ERROR results.
    Invalid arguments (unknown provider, empty prompt, non-https ``base_url``, bad
    ``ca_file``) raise :class:`~aiguard.errors.AiguardError` before anything is sent.
    ``base_url`` (``https://host[:port][/prefix]``) replaces the provider host, e.g. a
    test server or a custom endpoint; its path is prefixed to the provider path.
    """
    name = (provider or "").strip().lower()
    p = _provider(name)
    if expect not in ("block", "allow"):
        raise AiguardError("expect must be 'block' or 'allow' (got %r)" % (expect,),
                           code="probe.bad_expect", state="Nothing was sent.")
    if not isinstance(prompt, str) or not prompt.strip():
        raise AiguardError("The prompt is empty", code="probe.empty_prompt",
                           fix=["Type a prompt to send"], state="Nothing was sent.")
    size = len(prompt.encode("utf-8"))
    if size > MAX_PROMPT_BYTES:
        raise AiguardError(
            "The prompt is too long (%d KB)" % (size // 1024),
            code="probe.prompt_too_long",
            why="AI Agent Security inspects text prompts up to 512 KB.",
            fix=["Send a shorter prompt"], state="Nothing was sent.")
    timeout = _check_timeout(timeout)
    model_name = (model or "").strip()
    if not model_name and p.get("model_env"):
        model_name = os.environ.get(p["model_env"], "").strip()
    model_name = model_name or p["model"]
    if len(model_name) > 200 or any(ord(ch) < 0x21 for ch in model_name):
        raise AiguardError("Invalid model name", code="probe.bad_model",
                           fix=["Use the provider's model id, e.g. %s" % p["model"]],
                           state="Nothing was sent.")
    host, port, path = _target(p, model_name, base_url)
    key, key_source = resolve_key(name, api_key)
    ctx = tlsutil.make_context(ca_file)   # raises TlsTrustError for a bad CA file

    pid = str(prompt_id or "custom")
    rid = "%s-%s-%s" % (pid, name, secrets.token_hex(3))
    url = _url(host, port, path)
    body = json.dumps(p["body"](model_name, prompt)).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "User-Agent": USER_AGENT, "Connection": "close"}
    headers.update(p["headers"](key))

    sent_at, sent_epoch = _now()
    result = ProbeResult(
        id=rid, provider=name, host=host, prompt=prompt, expect=expect, verdict="ERROR",
        reason="", http_status=None, content_type="", ms=0, inspected=None, issuer="",
        local_ip="", remote_ip="", sent_at=sent_at, snippet="",
        dummy_key=(key_source == "dummy"), evidence="", prompt_id=pid, model=model_name,
        url=url, key_source=key_source, sent_epoch=sent_epoch,
    )
    digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:12]
    _log(log, "info", "send", id=rid, provider=name, url=url, model=model_name,
         prompt_id=pid, expect=expect, prompt_len=len(prompt), prompt_sha256=digest,
         prompt_head=_redact.redact(prompt[:60]), key=key_source, timeout=timeout)

    t0 = time.monotonic()
    conn = _ProbeConnection(host, port, context=ctx, timeout=timeout)
    try:
        # ---- TCP + TLS handshake
        try:
            conn.connect()
        except ssl.SSLCertVerificationError as exc:
            err = tlsutil.trust_error(exc, host, "provider", port=port, ca_file=ca_file)
            _log_exception(log, err)
            category = err.details.get("category")
            result.inspected = True if category == "untrusted" else None
            result.verdict, result.reason = "ERROR", err.what
            result.evidence = "TLS verification failed: %s" % (err.server_said or "")
            result.error = err.to_dict()
            return result
        except (OSError, ssl.SSLError, ValueError) as exc:
            err = _connect_error(exc, host, port, tcp_ok=conn.tcp_ok, timeout=timeout)
            _log_exception(log, err)
            result.verdict, result.reason = "ERROR", err.what
            result.evidence = "%s: %s" % (type(exc).__name__, exc)
            result.error = err.to_dict()
            return result
        finally:
            result.local_ip = conn.tcp_local or local_ip_for(host, port) or ""
            result.remote_ip = conn.tcp_remote or ""

        peer = conn.peer or {}
        result.local_ip = peer.get("local_ip") or result.local_ip
        result.remote_ip = peer.get("peer_ip") or result.remote_ip
        result.issuer = _issuer_text(peer)
        result.tls = _tls_view(peer)
        if peer:
            result.inspected = not tlsutil.is_public_issuer(peer.get("issuer_org"),
                                                            peer.get("issuer_cn"))

        # ---- request / response (no redirects are followed)
        try:
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            result.http_status = resp.status
            result.content_type = resp.getheader("Content-Type", "") or ""
            location = resp.getheader("Location")
            if location:
                result.location = _redact.redact(location)[:500]
            raw = resp.read(MAX_READ)
        except (socket.timeout, TimeoutError):
            result.verdict = "UNKNOWN"
            result.evidence = "timeout"
            if result.http_status is None:
                result.reason = "no response in %gs; a silent drop is possible" % timeout
            else:
                result.reason = ("the reply (HTTP %d) stopped arriving for %gs; a silent drop "
                                 "is possible" % (result.http_status, timeout))
            return result
        except _TERMINATED as exc:
            result.verdict = "BLOCKED"
            result.evidence = "connection terminated by the network (%s)" % type(exc).__name__
            result.reason = ("The connection was closed after the prompt was sent (%s). The "
                             "gateway ends blocked requests this way." % type(exc).__name__)
            return result
        except ssl.SSLError as exc:
            result.verdict = "BLOCKED"
            result.evidence = "connection terminated by the network (TLS alert: %s)" % (
                getattr(exc, "reason", None) or type(exc).__name__)
            result.reason = ("The TLS session was aborted after the prompt was sent (%s)."
                             % _redact.redact(str(exc))[:160])
            return result
        except http.client.HTTPException as exc:
            result.verdict = "UNKNOWN"
            result.evidence = "malformed HTTP reply (%s)" % type(exc).__name__
            result.reason = "The reply was not valid HTTP (%s)." % type(exc).__name__
            return result
        except OSError as exc:
            # The handshake succeeded; the network failed while sending or reading (route
            # lost, VPN down ...). Not a trust problem, and not a block.
            result.verdict = "ERROR"
            result.evidence = "%s: %s" % (type(exc).__name__, exc)
            result.reason = "Sending the prompt failed: %s" % _redact.redact(str(exc))[:200]
            err = ConnectError(
                "The connection to %s:%d failed while the prompt was being sent" % (host, port),
                code="probe.send_failed", server_said="%s: %s" % (type(exc).__name__, exc),
                why=("The TLS handshake worked, then the network failed before the reply arrived "
                     "(for example a lost route or a VPN that went down). This is not a block "
                     "by the gateway."),
                fix=["Check this computer's network connection (route, VPN, proxy) to %s" % host,
                     "Send the prompt again"],
                state="The prompt may or may not have reached the provider.",
                details={"host": host, "port": port, "error": "%s: %s" % (type(exc).__name__, exc)})
            _log_exception(log, err)
            result.error = err.to_dict()
            return result

        result.snippet = _snippet(raw)
        verdict, evidence = classify_http(resp.status, result.content_type, raw,
                                          location=location)
        result.verdict, result.evidence = verdict, evidence
        result.reason = _reason(verdict, evidence, result)
        return result
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        result.ms = int((time.monotonic() - t0) * 1000)
        _log(log, "info" if result.verdict != "ERROR" else "warn", "result",
             id=result.id, verdict=result.verdict, expect=result.expect,
             matched=result.matched, status=result.http_status,
             content_type=result.content_type, ms=result.ms, evidence=result.evidence,
             inspected=result.inspected, issuer=result.issuer, local_ip=result.local_ip,
             remote_ip=result.remote_ip, location=result.location,
             snippet=result.snippet or None, dummy_key=result.dummy_key)


def _reason(verdict: str, evidence: str, r: ProbeResult) -> str:
    if verdict == "ALLOWED":
        status = r.http_status or 0
        if r.dummy_key and status in (401, 403):
            return ("The provider answered (HTTP %d, dummy key): the prompt crossed the "
                    "gateway and reached the provider." % status)
        return "The provider answered (HTTP %d): the prompt reached the provider." % status
    if verdict == "BLOCKED":
        return "Blocked before the provider: %s." % evidence
    return "Not conclusive: %s." % evidence


# --------------------------------------------------------------------------- tls_probe


def tls_probe(host: str, port: int = 443, *, ca_file: Optional[str] = None,
              timeout: float = 10) -> dict:
    """TLS handshake only (no HTTP request): who issued ``host``'s certificate?

    Returns ``{ok, inspected, issuer, issuer_org, sha256, verify_error, local_ip,
    remote_ip}`` plus ``host, port, status, issuer_cn, subject_cn, not_after,
    tls_version, category, connect_error, error (five-field dict), ms``.

    ``status``: ``inspected`` (issuer not a public CA), ``not_inspected`` (public CA),
    ``untrusted`` (verification failed: self-signed / unknown issuer -> inspected by a
    CA this computer does not trust), ``tls_error`` (other verification or handshake
    failure) or ``connect_error``. A bad ``ca_file`` raises TlsTrustError.
    """
    name = (host or "").strip().strip("[]")
    if not name:
        raise AiguardError("No host given", code="probe.bad_host")
    port = int(port or 443)
    timeout = _check_timeout(timeout)
    ctx = tlsutil.make_context(ca_file)
    out: Dict[str, Any] = {
        "ok": False, "inspected": None, "issuer": "", "issuer_org": "", "issuer_cn": "",
        "subject_cn": "", "sha256": "", "not_after": None, "tls_version": None,
        "verify_error": None, "category": None, "connect_error": None, "error": None,
        "local_ip": "", "remote_ip": "", "host": name, "port": port, "status": "tls_error",
        "ms": 0,
    }
    t0 = time.monotonic()
    conn = _ProbeConnection(name, port, context=ctx, timeout=timeout)
    try:
        conn.connect()
    except ssl.SSLCertVerificationError as exc:
        err = tlsutil.trust_error(exc, name, "provider", port=port, ca_file=ca_file)
        category = err.details.get("category")
        out["verify_error"] = err.server_said
        out["category"] = category
        out["inspected"] = True if category == "untrusted" else None
        out["status"] = "untrusted" if category == "untrusted" else "tls_error"
        out["error"] = err.to_dict()
    except (OSError, ssl.SSLError, ValueError) as exc:
        err = _connect_error(exc, name, port, tcp_ok=conn.tcp_ok, timeout=timeout)
        if conn.tcp_ok:
            out["status"] = "tls_error"
        else:
            out["status"] = "connect_error"
            out["connect_error"] = "%s: %s" % (type(exc).__name__, exc)
        out["error"] = err.to_dict()
    else:
        peer = conn.peer or {}
        out.update({
            "ok": True,
            "issuer": _issuer_text(peer),
            "issuer_org": peer.get("issuer_org") or "",
            "issuer_cn": peer.get("issuer_cn") or "",
            "subject_cn": peer.get("subject_cn") or "",
            "sha256": peer.get("sha256") or "",
            "not_after": peer.get("not_after"),
            "tls_version": peer.get("tls_version"),
        })
        public = tlsutil.is_public_issuer(out["issuer_org"], out["issuer_cn"])
        out["inspected"] = not public
        out["status"] = "not_inspected" if public else "inspected"
        out["local_ip"] = peer.get("local_ip") or ""
        out["remote_ip"] = peer.get("peer_ip") or ""
    finally:
        out["local_ip"] = out["local_ip"] or conn.tcp_local or local_ip_for(name, port) or ""
        out["remote_ip"] = out["remote_ip"] or conn.tcp_remote or ""
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        out["ms"] = int((time.monotonic() - t0) * 1000)
    return out
