"""Check Point Management API client (spec 3.1 - 3.3, section 10).

* :class:`MgmtClient` -- JSON over verified HTTPS (``tlsutil.VerifiedHTTPSConnection``),
  one connection per call. Every call is logged to the :class:`~aiguard.runlog.RunLog`
  with command, milliseconds and HTTP status; payloads go through
  :func:`aiguard.redact.redact_obj` and the API key, password and ``sid`` are
  registered with :func:`aiguard.redact.register_secret` before anything is logged.
* :func:`explain_api_error` -- turns a failed reply (JSON error body or the Apache
  HTML page a blocked client IP gets) into a :class:`~aiguard.errors.MgmtApiError`
  with ``what`` / ``server_said`` / ``why`` / ``fix``.
* Transport problems become :class:`~aiguard.errors.ConnectError`; certificate
  problems become :class:`~aiguard.errors.TlsTrustError` via
  :func:`aiguard.tlsutil.trust_error` (purpose ``"management"``). Certificate
  verification is never turned off.

Login strategy (the server allows only 3 remote logins per minute per admin and
domain): one ``login`` without a domain, then ``show-domains`` on that session
tells MDS (it works in System Data) from SMS (it does not). A domain is entered
with ``login-to-domain`` from the System Data session, so listing domains and
switching domain cost no extra login.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import errno
import html
import http.client
import json
import re
import socket
import ssl
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union
from urllib.parse import urlsplit

from . import __version__
from . import redact as _redact
from . import tlsutil
from .errors import AiguardError, ConnectError, MgmtApiError

__all__ = [
    "MgmtClient",
    "explain_api_error",
    "task_messages",
    "API_RELEASES",
    "release_for_api",
    "api_version_tuple",
    "FORBIDDEN_IP_FIX",
    "TASK_OK",
    "TASK_FAILED",
    "show_outbound_certificate",
    "outbound_certificate_info",
    "failing_rule",
    "REQUESTED_SESSION_TIMEOUT",
    "api_date_posix",
    "api_date_text",
    "task_start_posix",
]

# Release for each Management API version (section 10). 1.6-1.8.1 are older
# releases kept for friendlier messages.
API_RELEASES: Dict[str, str] = {
    "1.6": "R80.40",
    "1.6.1": "R80.40 JHF",
    "1.7": "R81",
    "1.7.1": "R81 JHF",
    "1.8": "R81.10",
    "1.8.1": "R81.10 JHF",
    "1.9": "R81.20",
    "1.9.1": "R81.20 JHF T43+",
    "2": "R82",
    "2.0.1": "R82 JHF T41+",
    "2.1": "R82.10",
    "2.2": "R82.20",
}

TASK_OK = ("succeeded", "succeeded with warnings")
TASK_FAILED = ("failed", "partially succeeded")

FORBIDDEN_IP_FIX = [
    "SmartConsole > Manage & Settings > Blades > Management API > Advanced Settings > "
    "Accept API calls from: All IP addresses that can be used for GUI clients (or All IP addresses)",
    "Publish, then on the management server run: api restart",
    "Check with: api status",
]

_API_LOGIN_PERMISSION = (
    "SmartConsole > Manage & Settings > Permissions & Administrators > Permission Profiles > "
    "(profile) > Management: Management API Login; Access Control / Threat Prevention: Edit; "
    "Install Policy")

_CHECK_LOG = "Check the log line for the full request and reply (secrets are masked)"

# Commands whose success is logged at DEBUG (polled often).
_QUIET_COMMANDS = frozenset({"show-task", "keepalive"})
# Commands whose payload carries credentials: the payload is never logged nor attached to
# an error (only the session options are logged).
_CREDENTIAL_COMMANDS = frozenset({"login", "login-to-domain"})
_CREDENTIAL_FIELDS = frozenset({"user", "password", "api-key", "new-password"})

# Asked for at login (the server default is 600 s). The web console keeps a session for
# an hour; the engine also sends keepalive before an operation after a long pause.
REQUESTED_SESSION_TIMEOUT = 3600
_INVALID_PARAMETER_CODES = frozenset({"generic_err_invalid_parameter",
                                      "generic_err_invalid_parameter_name",
                                      "generic_err_bad_parameter"})


def _loggable_payload(command: str, payload: Optional[dict]) -> Dict[str, Any]:
    """The payload as it may be logged: redacted, and without credentials for login."""
    if command in _CREDENTIAL_COMMANDS:
        return _redact.redact_obj({k: v for k, v in (payload or {}).items()
                                   if k not in _CREDENTIAL_FIELDS
                                   and not _redact.is_sensitive_key(k)})
    return _redact.redact_obj(payload or {})

_MAX_PAGES = 1000


# --------------------------------------------------------------------------- helpers


def api_version_tuple(version: Any) -> Tuple[int, ...]:
    """``"2.0.1"`` -> ``(2, 0, 1)``; ``"2"`` -> ``(2,)``; junk -> ``()``."""
    if version is None:
        return ()
    parts = re.findall(r"\d+", str(version))
    return tuple(int(p) for p in parts[:4])


def release_for_api(version: Any) -> Optional[str]:
    """Check Point release name for a Management API version (``"2.2"`` -> ``"R82.20"``)."""
    if version is None:
        return None
    text = str(version).strip()
    if text in API_RELEASES:
        return API_RELEASES[text]
    vt = api_version_tuple(text)
    for key, rel in API_RELEASES.items():
        if api_version_tuple(key) == vt or api_version_tuple(key) + (0,) == vt:
            return rel
    return None


OUTBOUND_CERT_COMMAND = "show-outbound-inspection-certificate"
OUTBOUND_CERTS_COMMAND = "show-outbound-inspection-certificates"
# Codes a server may use when it wants an identifier for the singular show command.
_OUTBOUND_NEEDS_NAME = frozenset({"generic_err_missing_required_parameters",
                                  "generic_err_missing_parameter",
                                  "generic_err_invalid_parameter"})


def show_outbound_certificate(client: Any) -> Optional[Dict[str, Any]]:
    """The outbound (HTTPS Inspection) certificate object, or ``None`` when there is none.

    Read-only. ``show-outbound-inspection-certificate`` without an identifier returns the
    default certificate (documented for API 2). When the server wants a name instead, or
    reports no default, the plural listing (API 2+) supplies the name. The raw reply may
    hold ``base64-certificate`` (a PKCS#12 that can carry the CA's encrypted private key):
    show it to nobody, use :func:`outbound_certificate_info` for anything displayed.
    """
    not_found = "generic_err_object_not_found"
    try:
        reply = client.call(OUTBOUND_CERT_COMMAND, {})
        return reply if isinstance(reply, dict) else {}
    except MgmtApiError as exc:
        if exc.api_code not in _OUTBOUND_NEEDS_NAME and exc.api_code != not_found:
            raise
    has = getattr(client, "has", None)
    cmds = client.commands() if callable(getattr(client, "commands", None)) else set()
    if not cmds or OUTBOUND_CERTS_COMMAND not in cmds or (callable(has) and not has(
            OUTBOUND_CERTS_COMMAND)):
        return None
    try:
        # details-level full: the objects carry is-default (standard has name/uid only)
        objs = client.show_all(OUTBOUND_CERTS_COMMAND, {"details-level": "full"},
                               key="objects")
    except MgmtApiError as exc:
        if exc.api_code in (not_found, "generic_err_command_not_found",
                            "generic_err_not_implemented"):
            return None
        raise
    names: List[str] = []
    defaults: List[str] = []
    marked = False      # at least one listed object says whether it is the default
    for o in objs or []:
        ident = (o.get("name") or o.get("uid")) if isinstance(o, dict) else o
        if not ident or str(ident) in names:
            continue
        names.append(str(ident))
        if isinstance(o, dict) and "is-default" in o:
            marked = True
            if o.get("is-default") is True:
                defaults.append(str(ident))
    if not names:
        return None
    log = getattr(client, "log", None)

    def show(name: str) -> Optional[Dict[str, Any]]:
        try:
            r = client.call(OUTBOUND_CERT_COMMAND, {"name": name})
        except MgmtApiError as exc:
            if exc.api_code == not_found:
                return None
            raise
        return r if isinstance(r, dict) else {}

    if defaults:
        return show(defaults[0])
    first: Optional[Dict[str, Any]] = None
    if not marked:
        # The listing did not say which one is the default: ask for each (a lab has few).
        for name in names[:10]:
            reply = show(name)
            if reply is None:
                continue
            if first is None:
                first = reply
            if reply.get("is-default") is True:
                return reply
    if first is None:
        first = show(names[0])
    if first is not None and len(names) > 1 and log is not None:
        try:
            log.warn("mgmt", "no outbound certificate is marked as the default; using the "
                     "first one", name=first.get("name") or names[0], certificates=names)
        except Exception:  # noqa: BLE001 - logging must not hide the answer
            pass
    return first


def outbound_certificate_info(reply: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Display-safe facts about an outbound certificate reply: name, uid, issued-by,
    subject, valid-from, valid-to, is-default, ``pem`` (the public certificate, API 2+,
    or None) and ``pkcs12_only`` (API 1.9.x: only the PKCS#12 blob was returned).
    ``base64-certificate`` itself is never copied."""
    reply = reply if isinstance(reply, dict) else {}
    pem = reply.get("base64-public-certificate")
    pem_text: Optional[str] = None
    if isinstance(pem, str) and pem.strip():
        text = pem.strip()
        if "-----BEGIN" not in text:
            try:
                decoded = base64.b64decode(text, validate=False).decode("ascii", "strict")
                if "-----BEGIN CERTIFICATE-----" in decoded:
                    text = decoded.strip()
            except (binascii.Error, ValueError, UnicodeDecodeError):
                pass
        if "PRIVATE KEY" not in text.upper():
            pem_text = text.replace("\r\n", "\n").replace("\r", "\n") + "\n"
    out: Dict[str, Any] = {}
    for key in ("name", "uid", "issued-by", "subject", "valid-from", "valid-to", "is-default",
                "public-key-algorithm"):
        if reply.get(key) is not None:
            out[key] = reply.get(key)
    out["pem"] = pem_text
    out["base64-public-certificate"] = pem_text
    out["pkcs12_only"] = bool(pem_text is None and reply.get("base64-certificate"))
    return out


class _NullLog(object):
    """Stand-in when no RunLog is given (never writes anything)."""

    path = None

    def event(self, *a: Any, **k: Any) -> int:
        return 0

    debug = info = warn = warning = error = hint = event

    def exception(self, err: BaseException, component: str) -> int:
        return 0


def _is_read_only_command(command: str) -> bool:
    return command.startswith("show-") or command in ("keepalive",)


def _parse_server(server: str, port: int) -> Tuple[str, int, str]:
    """Accept ``host``, ``host:port``, ``[v6]:port`` or ``https://host[:port][/prefix]``.

    Returns (host, port, path prefix). The prefix is for Smart-1 Cloud
    (``https://<tenant>/<cloud-mgmt-id>/``); normally "".
    """
    text = str(server or "").strip()
    if not text:
        raise ConnectError(
            "No management server address was given",
            code="connect.no_server",
            why="aiguard needs the IP address or name of the Security Management Server "
                "(or Multi-Domain Server).",
            fix=["Pass --server <address> (web console: the Server field)"],
            state="No connection was made.")
    prefix = ""
    if "://" not in text and (text.count(":") == 1 or text.startswith("[")):
        text = "https://" + text
    if "://" in text:
        parts = urlsplit(text)
        host = parts.hostname or ""
        try:
            if parts.port:
                port = parts.port
        except ValueError:
            pass
        path = (parts.path or "").rstrip("/")
        if path.endswith("/web_api"):
            path = path[: -len("/web_api")]
        prefix = path
    else:
        host = text
    host = host.strip().strip("[]")
    return host, int(port or 443), prefix


def _decode_body(data: Any) -> Any:
    """bytes/str -> parsed JSON (dict/list) when possible, else text."""
    if isinstance(data, (dict, list)):
        return data
    if isinstance(data, (bytes, bytearray)):
        text = bytes(data).decode("utf-8", "replace")
    else:
        text = "" if data is None else str(data)
    stripped = text.strip()
    if stripped[:1] in ("{", "["):
        try:
            return json.loads(stripped)
        except ValueError:
            return text
    return text


def _item_messages(items: Any) -> List[str]:
    out: List[str] = []
    if items is None:
        return out
    if isinstance(items, (str, dict)):
        items = [items]
    for item in items if isinstance(items, (list, tuple)) else [items]:
        if isinstance(item, dict):
            msg = item.get("message")
            if msg is None:
                msg = item.get("text") or item.get("description")
            if msg:
                out.append(str(msg))
        elif item is not None and str(item).strip():
            out.append(str(item))
    return out


def _html_text(text: str, limit: int = 500) -> str:
    """Visible text of an HTML error page (the <body> when there is one)."""
    m = re.search(r"(?is)<body[^>]*>(.*?)(?:</body>|\Z)", text)
    body = m.group(1) if m else text
    body = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", body)
    body = re.sub(r"(?s)<[^>]+>", " ", body)
    body = html.unescape(body)
    body = re.sub(r"\s+", " ", body).strip()
    if not body:
        m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
        body = html.unescape(m.group(1)).strip() if m else text.strip()
    return body[:limit]


_FAILING_RULE_RE = re.compile(
    r"Layer\s+'(?P<layer>[^']+)'\s*:\s*Rule\s+(?P<number>[0-9.]+)\s*(?:\((?P<name>[^)]*)\))?",
    re.IGNORECASE)


def failing_rule(text: Any) -> Optional[Dict[str, str]]:
    """``{"layer", "number", "name"}`` from a verification message such as
    "Layer 'Network': Rule 2 (AI) - The following Data Types are not supported ...",
    or None."""
    m = _FAILING_RULE_RE.search(str(text or ""))
    if not m:
        return None
    return {"layer": m.group("layer").strip(), "number": m.group("number").strip(),
            "name": (m.group("name") or "").strip()}


def _uniq(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for it in items:
        key = it.strip()
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:] if text else text


def _truncate(obj: Any, limit: int = 2000) -> Any:
    """Keep error bodies in logs readable."""
    if isinstance(obj, str) and len(obj) > limit:
        return obj[:limit] + "...(%d more characters)" % (len(obj) - limit)
    return obj


# --------------------------------------------------------------------------- error mapping


def explain_api_error(command: str, http_status: Optional[int], body: Any, *,
                      client_ip: Optional[str] = None, domain: Optional[str] = None,
                      server: Optional[str] = None, port: Optional[int] = None,
                      payload: Optional[dict] = None,
                      api_version: Optional[str] = None) -> MgmtApiError:
    """Map a failed Management API reply to a :class:`MgmtApiError`.

    ``body`` is the parsed JSON error object (``{code, message, errors[], warnings[],
    blocking-errors[]}``) or the raw text/bytes (e.g. the Apache 403 page). The extra
    keyword arguments only make the text more precise. ``server_said`` is the server's
    text verbatim, passed through :func:`aiguard.redact.redact` (a session id the
    server echoes back is masked).
    """
    err = _explain(command, http_status, body, client_ip=client_ip, domain=domain,
                   server=server, port=port, payload=payload, api_version=api_version)
    if err.server_said is not None:
        err.server_said = _redact.redact(err.server_said)
    err.what = _redact.redact(err.what)
    return err


def _explain(command: str, http_status: Optional[int], body: Any, *,
             client_ip: Optional[str], domain: Optional[str], server: Optional[str],
             port: Optional[int], payload: Optional[dict],
             api_version: Optional[str]) -> MgmtApiError:
    command = str(command or "request")
    parsed = _decode_body(body)
    status = int(http_status) if http_status is not None else None
    where = ("%s:%s" % (server, port)) if server else "the management server"
    common = dict(command=command, http_status=status)

    if not isinstance(parsed, dict):
        text = parsed if isinstance(parsed, str) else json.dumps(parsed)[:2000]
        said = _html_text(text) if "<" in text else text.strip()[:500]
        low = text.lower()
        details = {"body": _truncate(text), "server": server, "port": port}
        if status == 403 or "permission to access" in low or "access to the api server is forbidden" in low:
            return _forbidden_error(command, status, said, client_ip, details)
        if status == 404:
            return MgmtApiError(
                "No Management API at https://%s/web_api (HTTP 404)" % where.replace(
                    "the management server", "<server>"),
                code="mgmt.http_404", server_said=said or None,
                why="The web server answered, but not with the Management API. The address or "
                    "port may point at another web service.",
                fix=["Check the address and port: the Management API uses the Gaia portal port "
                     "(443 by default; see the url in `api status`)",
                     "On the management server run: api status (expect 'Overall API Status: Started')"],
                details=details, **common)
        if status is not None and status >= 500:
            return _server_error(command, status, said, details)
        return MgmtApiError(
            "%s failed (HTTP %s)" % (command, status),
            code="mgmt.http_error", server_said=said or None,
            why="The management server replied with something that is not a Management API "
                "JSON reply.",
            fix=["On the management server run: api status", _CHECK_LOG],
            details=details, **common)

    code = str(parsed.get("code") or "")
    message = str(parsed.get("message") or "")
    errors = _item_messages(parsed.get("errors"))
    warnings = _item_messages(parsed.get("warnings"))
    blocking = _item_messages(parsed.get("blocking-errors"))
    all_msgs = _uniq(blocking + errors + warnings)
    common.update(api_code=code or None, errors=parsed.get("errors") or [],
                  warnings=parsed.get("warnings") or [],
                  blocking_errors=parsed.get("blocking-errors") or [])
    details: Dict[str, Any] = {"body": parsed, "server": server, "port": port}
    low = (message + " " + " ".join(all_msgs)).lower()
    said_all = "\n".join(_uniq([message] + all_msgs)) or None

    if code == "err_login_failed" or (command == "login" and "authentication to server failed" in low):
        why = "The management server did not accept the API key or the username and password."
        fix = ["Check the API key, or the username and password (SmartConsole > Manage & Settings > "
               "Permissions & Administrators > Administrators > (administrator) > Authentication "
               "Method)",
               "Make sure the administrator's permission profile allows the API: " + _API_LOGIN_PERMISSION]
        if domain:
            why += (" On a Multi-Domain Server the same error is returned when the domain '%s' "
                    "does not exist or this administrator may not log in to it (a wrong domain "
                    "is a common cause)." % domain)
            fix.insert(1, "Check the domain '%s': use the domain name as SmartConsole shows it "
                          "(not the Domain Server's name or IP). Connect without a domain to list "
                          "the domains" % domain)
        fix.append("Failed attempts count against the login limit (3 per minute): wait a minute "
                   "before trying again")
        return MgmtApiError("Wrong API key or username/password", code="mgmt.login_failed",
                            server_said=said_all, why=why, fix=fix,
                            state="Not logged in. Nothing was changed.", details=details, **common)

    if code == "err_too_many_requests" or "too many requests" in low:
        return MgmtApiError(
            "Too many logins to the management server (limit: 3 per minute)",
            code="mgmt.rate_limited", server_said=said_all,
            why="Since R81 the Management API accepts at most 3 remote logins per minute for "
                "each administrator and domain.",
            fix=["Wait one minute, then try again",
                 "Do not run several aiguard sessions or scripts with this administrator at the "
                 "same time: aiguard reuses one session per run"],
            state="Not logged in. Nothing was changed." if command == "login" else None,
            details=details, **common)

    if status == 403 and command == "login" and (
            "not accessible" in low or "access denied" in low or "forbidden" in low):
        return _forbidden_error(command, status, said_all, client_ip, details, extra=common)

    if code == "generic_err_object_locked" or "locked by another session" in low \
            or "is locked by" in low:
        who = None
        for text in [message] + all_msgs:
            m = re.search(r"locked by (?:another session|session|the session)?\s*\(([^)]+)\)", text,
                          re.IGNORECASE) or re.search(r"\(([^()]+)\)\s*\.?\s*$", text)
            if m:
                who = m.group(1).strip()
                break
        what = "Objects are locked by another session" + (" (%s)" % who if who else "")
        return MgmtApiError(
            what, code="mgmt.object_locked", server_said=said_all,
            why="Another administrator session changed these objects and has not published or "
                "discarded yet, so the management server keeps them locked.",
            fix=["Publish or discard that session in SmartConsole (Manage & Settings > Sessions > "
                 "View Sessions%s), then retry" % (": " + who if who else ""),
                 "If it is your own SmartConsole session, publish or discard your changes there "
                 "first"],
            details=details, **common)

    if code == "generic_err_object_not_found":
        name = None
        if isinstance(payload, dict):
            for key in ("name", "uid", "task-id", "layer", "policy-package", "domain"):
                if payload.get(key):
                    name = str(payload.get(key))
                    break
        if name is None:
            m = re.search(r"\[([^\]]+)\]", message)
            name = m.group(1) if m else None
        what = ("Object '%s' was not found (%s)" % (name, command) if name
                else "Object not found (%s)" % command)
        return MgmtApiError(
            what, code="mgmt.not_found", server_said=said_all,
            why="The management server has no object with that name or UID in this domain, or "
                "this administrator is not allowed to see it.",
            fix=["Check the name (as shown in SmartConsole)",
                 "If you just created it in SmartConsole, publish that session first",
                 "On a Multi-Domain Server, check that you are connected to the right domain"],
            details=details, **common)

    if code in ("err_validation_failed", "generic_err_validation_failed") or (
            code == "generic_error" and (errors or blocking or "validation failed" in low)):
        said = "\n".join(_uniq(blocking + errors + warnings)) or message or None
        warn_only = bool(warnings) and not (errors or blocking)
        return MgmtApiError(
            "%s was rejected: validation failed" % command,
            code="mgmt.validation", server_said=said,
            why=("The management server refused the change because of the warnings it lists."
                 if warn_only else
                 "The management server checked the request and refused it for the reasons it "
                 "lists."),
            fix=["Fix what the server lists (see Server said) and try again", _CHECK_LOG],
            details=details, **common)

    if code in ("generic_err_invalid_parameter", "generic_err_invalid_parameter_name",
                "generic_err_missing_required_parameters", "generic_err_invalid_syntax",
                "generic_err_missing_parameter", "generic_err_bad_parameter"):
        said = "\n".join(_uniq([message] + blocking + errors)) or None
        if code == "generic_err_invalid_parameter_name":
            why = ("This management server does not accept a parameter that aiguard sent. Its "
                   "Management API version%s may be older than this step needs."
                   % (" (%s)" % api_version if api_version else ""))
            fix = ["Check the management version: AI Agent Security needs R82.20 management "
                   "(Management API 2.2)", _CHECK_LOG]
        else:
            why = "The management server did not accept a value in the request (see Server said)."
            fix = ["Correct the value the server names and try again", _CHECK_LOG]
        return MgmtApiError("%s was rejected: invalid parameter" % command,
                            code="mgmt.invalid_parameter", server_said=said, why=why, fix=fix,
                            details=details, **common)

    if code == "generic_err_permission_denied" or (status == 403 and "permission" in low):
        if "read-only" in low or "read only" in low:
            fix = ["This session is read-only: use an administrator whose permission profile is "
                   "Read/Write (SmartConsole > Manage & Settings > Permissions & Administrators "
                   "> Permission Profiles)",
                   "If this is the Standby server of Management High Availability, connect to "
                   "the Active server",
                   "Then connect again"]
            why = ("This session is read-only, so the management server refuses changes "
                   "(a read-only permission profile, a Standby management server, or a "
                   "background upgrade).")
        elif command == "run-script" or "script" in low:
            fix = ["SmartConsole > Manage & Settings > Permissions & Administrators > Permission "
                   "Profiles > (profile) > Gateways: Run One Time Script",
                   "Publish, then connect again",
                   "Or run the gateway commands by hand (aiguard shows them)"]
            why = "The administrator's permission profile does not allow running scripts on gateways."
        else:
            fix = [_API_LOGIN_PERMISSION, "Publish, then connect again"]
            why = "The administrator's permission profile does not allow %s." % command
        return MgmtApiError("Permission denied: %s" % command, code="mgmt.permission_denied",
                            server_said=said_all, why=why, fix=fix, details=details, **common)

    if code == "generic_err_command_not_found" or (status == 404 and "unknown command" in low):
        return MgmtApiError(
            "This management version does not support %s" % command,
            code="mgmt.command_not_found", server_said=said_all,
            why="The Management API on this server%s has no '%s' command."
                % (" (version %s)" % api_version if api_version else "", command),
            fix=["Check the management version: AI Agent Security needs R82.20 management "
                 "(Management API 2.2)",
                 "Upgrade the management server, or do this step in SmartConsole"],
            details=details, **common)

    if code == "generic_err_wrong_session_id":
        return MgmtApiError(
            "The management session is no longer valid",
            code="mgmt.session_expired", server_said=said_all,
            why="A session ends after its timeout without calls (600 seconds by default), on "
                "logout, or when an administrator disconnects it in SmartConsole.",
            fix=["Connect again",
                 "Unpublished changes stay in the old session until it is discarded: "
                 "SmartConsole > Manage & Settings > Sessions > View Sessions"],
            details=details, **common)

    if code == "generic_err_invalid_api_version":
        return MgmtApiError(
            "This management server does not support the requested API version",
            code="mgmt.api_version", server_said=said_all,
            why="The request asked for a Management API version this server does not have.",
            fix=["Check the management version with `aiguard status`", _CHECK_LOG],
            details=details, **common)

    if status is not None and status >= 500:
        return _server_error(command, status, said_all, details, extra=common)

    return MgmtApiError(
        "%s failed" % command, code="mgmt.error", server_said=said_all,
        why="The management server returned %s (HTTP %s)." % (code or "an error", status),
        fix=[_CHECK_LOG], details=details, **common)


def _forbidden_error(command: str, status: Optional[int], said: Optional[str],
                     client_ip: Optional[str], details: dict,
                     extra: Optional[dict] = None) -> MgmtApiError:
    kw = dict(extra or {})
    kw.setdefault("command", command)
    kw.setdefault("http_status", status)
    who = ("This computer (%s) is not one of them." % client_ip) if client_ip else \
        "This computer is not one of them."
    what = ("Login refused by management (HTTP 403)" if command == "login"
            else "%s refused by management (HTTP 403)" % command)
    return MgmtApiError(
        what, code="mgmt.forbidden_ip", server_said=said or None,
        why="The Management API only accepts calls from the addresses set in 'Accept API calls "
            "from' (by default only the management server itself). " + who +
            " 'All IP addresses that can be used for GUI clients' allows the Trusted Clients "
            "defined in SmartConsole.",
        fix=list(FORBIDDEN_IP_FIX),
        state="Not logged in. Nothing was changed." if command == "login" else None,
        details=details, **kw)


def _server_error(command: str, status: int, said: Optional[str], details: dict,
                  extra: Optional[dict] = None) -> MgmtApiError:
    kw = dict(extra or {})
    kw.setdefault("command", command)
    kw.setdefault("http_status", status)
    return MgmtApiError(
        "%s failed on the management server (HTTP %s)" % (command, status),
        code="mgmt.server_error", server_said=said or None,
        why="The management server had an internal error while handling the request.",
        fix=["Try again in a minute",
             "On the management server run: api status (the API log is $FWDIR/log/api.elg)",
             _CHECK_LOG],
        details=details, **kw)


# --------------------------------------------------------------------------- task messages

_B64_RE = re.compile(r"^[A-Za-z0-9+/\r\n]+={0,2}$")


def _maybe_b64(text: Any) -> str:
    """run-script puts gateway output in responseMessage as base64."""
    if text is None:
        return ""
    value = str(text).strip()
    if not value:
        return ""
    compact = re.sub(r"\s+", "", value)
    if len(compact) >= 4 and len(compact) % 4 == 0 and _B64_RE.match(compact):
        try:
            decoded = base64.b64decode(compact, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return value
        printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\r\n\t")
        if decoded and printable >= 0.9 * len(decoded):
            return decoded.strip()
    return value


def _level_for(kind: Any) -> str:
    k = str(kind or "").strip().lower()
    if k in ("err", "error", "fatal", "failed", "failure"):
        return "error"
    if k in ("warn", "warning", "warnings"):
        return "warning"
    return "info"


def api_date_posix(value: Any) -> Optional[int]:
    """Milliseconds since the epoch from an ApiDateReply (``{posix, iso-8601}``), a
    number, or an ISO 8601 text; None when it cannot be read."""
    if isinstance(value, dict):
        posix = value.get("posix")
        if isinstance(posix, (int, float)) and not isinstance(posix, bool):
            return int(posix)
        value = value.get("iso-8601")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    if isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        m = re.match(r"^(.*[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)([+-]\d{2})(\d{2})$", text)
        if m:   # Check Point writes "+0300"
            text = "%s%s:%s" % m.groups()
        try:
            ts = _dt.datetime.fromisoformat(text)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=_dt.timezone.utc)
            return int(ts.timestamp() * 1000)
        except ValueError:
            return None
    return None


def api_date_text(value: Any) -> Optional[str]:
    """Display text for an ApiDateReply: its ``iso-8601`` text, else built from posix."""
    if isinstance(value, dict) and isinstance(value.get("iso-8601"), str) and value["iso-8601"]:
        return str(value["iso-8601"])
    if isinstance(value, str) and value.strip():
        return value.strip()
    posix = api_date_posix(value)
    if posix is None:
        return None
    return _dt.datetime.fromtimestamp(posix / 1000.0, _dt.timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC")


def task_start_posix(task: Any) -> Optional[int]:
    """When a task started (ms since the epoch), or None."""
    if not isinstance(task, dict):
        return None
    return api_date_posix(task.get("start-time"))


def task_messages(task: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Messages from a ``show-task`` entry (details-level full), in order.

    Each item: ``{"level": "error"|"warning"|"info", "text": str, "target": str|None,
    "source": str}``. Looks at ``comments`` and, inside ``task-details[]`` (not in the
    official schema, so parsed defensively): ``statusDescription``, ``messages[]``,
    ``stagesInfo[].messages[]`` (``{type, message}``), ``responseMessage`` (base64 for
    run-script) and ``responseError``.
    """
    out: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    status = str(task.get("status") or "").lower()
    failed = status in TASK_FAILED

    def add(level: str, text: Any, target: Optional[str], source: str) -> None:
        if text is None:
            return
        if isinstance(text, (dict, list)):
            text = json.dumps(text, ensure_ascii=False)
        value = str(text).strip()
        if not value:
            return
        key = (level, value)
        if key in seen:
            return
        seen.add(key)
        out.append({"level": level, "text": value, "target": target, "source": source})

    add("error" if failed else "info", task.get("comments"), None, "comments")
    details = task.get("task-details") or []
    if isinstance(details, dict):
        details = [details]
    for det in details if isinstance(details, list) else []:
        if not isinstance(det, dict):
            add("error" if failed else "info", det, None, "task-details")
            continue
        target = None
        for key in ("gatewayName", "target", "gateway-name", "targetName", "name"):
            if det.get(key):
                target = str(det.get(key))
                break
        det_status = str(det.get("statusCode") or det.get("status") or "").lower()
        det_failed = det_status in ("failed", "failure", "error", "partially succeeded")
        det_level = "error" if det_failed else ("error" if failed and not det_status else "info")
        add(det_level, det.get("statusDescription"), target, "statusDescription")
        for m in det.get("messages") or []:
            if isinstance(m, dict):
                add(_level_for(m.get("type")) if m.get("type") else det_level,
                    m.get("message") or m.get("text"), target, "messages")
            else:
                add(det_level, m, target, "messages")
        for stage in det.get("stagesInfo") or []:
            if not isinstance(stage, dict):
                continue
            for m in stage.get("messages") or []:
                if isinstance(m, dict):
                    add(_level_for(m.get("type")), m.get("message") or m.get("text"), target,
                        "stagesInfo")
                else:
                    add("info", m, target, "stagesInfo")
        if det.get("responseError"):
            add("error", _maybe_b64(det.get("responseError")), target, "responseError")
        if det.get("responseMessage"):
            add("error" if det_failed else "info", _maybe_b64(det.get("responseMessage")), target,
                "responseMessage")
    return out


# --------------------------------------------------------------------------- client


class MgmtClient(object):
    """Management API session for one server (and one domain at a time).

    Attributes after :meth:`login`: ``sid`` (secret, registered for redaction),
    ``uid``, ``api_version`` (``"2.2"``), ``release`` (``"R82.20"``), ``server_type``
    (``"SMS"`` | ``"MDS"`` | ``"unknown"``), ``domain``, ``read_only``,
    ``fingerprint`` (= ``fingerprint_sha256``), ``fingerprint_sha1`` (compare with
    ``api fingerprint`` on the server), ``cert`` (:func:`tlsutil.peer_summary`),
    ``local_ip`` (this computer's address on the connection), ``session_timeout``,
    ``reported_port`` (port from the login reply ``url``).

    ``task_poll`` (seconds, default 2.0) is used by :meth:`publish`,
    :meth:`install_policy` and :meth:`wait_task` when no ``poll`` is given.
    """

    def __init__(self, server: str, port: int = 443, *, ca_file: Optional[str] = None,
                 server_name: Optional[str] = None, timeout: float = 60,
                 log: Any = None) -> None:
        host, real_port, prefix = _parse_server(server, port)
        self.server: str = host
        self.port: int = real_port
        self.base_path: str = prefix + "/web_api"
        self.ca_file: Optional[str] = str(ca_file) if ca_file else None
        self.server_name: Optional[str] = (server_name or "").strip() or None
        self.timeout: float = float(timeout or 60)
        self.log = log if log is not None else _NullLog()
        self.task_poll: float = 2.0
        try:
            self._context: ssl.SSLContext = tlsutil.make_context(self.ca_file)
        except AiguardError as err:
            err.log_line = self.log.exception(err, "mgmt")
            raise
        self._lock = threading.RLock()

        self.sid: Optional[str] = None
        self.uid: Optional[str] = None
        self.api_version: Optional[str] = None
        self.release: Optional[str] = None
        self.server_type: str = "unknown"
        self.domain: Optional[str] = None
        self.read_only: bool = False
        self.standby: Optional[bool] = None
        self.session_timeout: Optional[int] = None
        self.fingerprint: Optional[str] = None
        self.fingerprint_sha1: Optional[str] = None
        self.fingerprint_sha256: Optional[str] = None
        self.cert: Optional[Dict[str, Any]] = None
        self.local_ip: Optional[str] = None
        self.peer_ip: Optional[str] = None
        self.session_ip: Optional[str] = None   # this computer's IP as the server saw it (MDS)
        self.reported_url: Optional[str] = None
        self.reported_port: Optional[int] = None
        self.user: Optional[str] = None
        self.auth: Optional[str] = None
        self.login_ms: Optional[int] = None
        self.last_call_at: Optional[float] = None
        self.session_expired: bool = False   # the server dropped the session (see _call)
        self.requested_session_timeout: Optional[int] = REQUESTED_SESSION_TIMEOUT

        self._commands: Optional[Set[str]] = None
        self._system_commands: Optional[Set[str]] = None
        self._domains: Optional[List[Dict[str, Any]]] = None
        self._system_sid: Optional[str] = None
        self._creds: Dict[str, Any] = {}
        self._registered: List[str] = []   # every secret registered, kept for forget_secrets()
        self._session_opts: Dict[str, Any] = {}

    # ------------------------------------------------------------------ properties

    @property
    def logged_in(self) -> bool:
        return bool(self.sid)

    def __repr__(self) -> str:
        return "MgmtClient(%s:%d, type=%s, api=%s, domain=%r, logged_in=%s)" % (
            self.server, self.port, self.server_type, self.api_version, self.domain, self.logged_in)

    def summary(self) -> Dict[str, Any]:
        """Display-safe connection facts (no secrets). An MDS session in "System Data"
        (no domain chosen yet) has ``domain`` None and ``system_data`` True."""
        system_data = bool(self.server_type == "MDS" and isinstance(self.domain, str)
                           and self.domain.strip().lower() == "system data")
        return {
            "server": self.server, "port": self.port, "server_type": self.server_type,
            "api_version": self.api_version, "release": self.release,
            "domain": None if system_data else self.domain, "system_data": system_data,
            "fingerprint_sha1": self.fingerprint_sha1, "fingerprint_sha256": self.fingerprint_sha256,
            "read_only": self.read_only, "logged_in": self.logged_in, "user": self.user,
            "auth": self.auth, "local_ip": self.local_ip, "session_timeout": self.session_timeout,
            "reported_port": self.reported_port,
        }

    # ------------------------------------------------------------------ transport

    def _connect_error(self, kind: str, exc: BaseException, timeout: float) -> ConnectError:
        target = "%s:%d" % (self.server, self.port)
        port_step = ("Check the address and port %d: the Management API uses the Gaia portal "
                     "web port (443 by default; some servers use 4434, see the url in "
                     "`api status`)" % self.port)
        api_step = ("On the management server run: api status (expect 'Overall API Status: "
                    "Started'); if it is stopped: api start")
        fw_step = ("Check that firewalls between this computer and the management server allow "
                   "TCP %d" % self.port)
        state = "No connection was made. Nothing was changed."
        said = "%s: %s" % (type(exc).__name__, exc)
        details = {"server": self.server, "port": self.port, "error": said}
        if kind == "refused":
            return ConnectError(
                "Cannot connect to the management server at %s (connection refused)" % target,
                code="connect.refused", server_said=said,
                why="Nothing accepted the connection on port %d. The Management API may be "
                    "stopped, or the port is wrong." % self.port,
                fix=[port_step, api_step, fw_step], state=state, details=details)
        if kind == "timeout":
            return ConnectError(
                "The management server at %s did not answer within %gs" % (target, timeout),
                code="connect.timeout", server_said=said,
                why="No reply arrived in time. A firewall may be dropping the connection, the "
                    "address may be wrong, or the server is busy.",
                fix=[port_step, fw_step, api_step], state=state, details=details)
        if kind == "dns":
            return ConnectError(
                "Cannot resolve the management server name '%s'" % self.server,
                code="connect.dns", server_said=said,
                why="This computer's DNS does not know that name.",
                fix=["Check the spelling of the server name",
                     "Or connect by IP address and add --server-name <name in the certificate>",
                     "Check this computer's DNS settings (nslookup %s)" % self.server],
                state=state, details=details)
        if kind == "unreachable":
            return ConnectError(
                "No network route to the management server %s" % target,
                code="connect.unreachable", server_said=said,
                why="This computer has no route to that address (wrong network, VPN down, or "
                    "the address is wrong).",
                fix=[port_step, "Check this computer's network connection and VPN", fw_step],
                state=state, details=details)
        if kind == "reset":
            return ConnectError(
                "The management server %s closed the connection" % target,
                code="connect.reset", server_said=said,
                why="The connection was closed before a full reply arrived.",
                fix=[api_step, fw_step, "Try again"],
                state="The request may or may not have been processed; nothing else was sent.",
                details=details)
        return ConnectError(
            "Cannot talk to the management server at %s" % target,
            code="connect.error", server_said=said,
            why="A network error stopped the request.",
            fix=[port_step, api_step, fw_step], state=state, details=details)

    def _note_peer(self, conn: tlsutil.VerifiedHTTPSConnection) -> None:
        peer = getattr(conn, "peer", None)
        if not peer:
            return
        sha256 = peer.get("sha256") or None
        if self.fingerprint_sha256 and sha256 and sha256 != self.fingerprint_sha256:
            self.log.warn("mgmt", "management certificate changed during the session",
                          old_sha256=self.fingerprint_sha256, new_sha256=sha256)
        self.cert = dict(peer)
        self.fingerprint_sha256 = sha256
        self.fingerprint = sha256
        self.fingerprint_sha1 = peer.get("sha1") or None
        self.local_ip = peer.get("local_ip") or self.local_ip
        self.peer_ip = peer.get("peer_ip") or self.peer_ip

    def _log_error(self, err: AiguardError, level: Optional[str], **fields: Any) -> None:
        """ERROR (all fields, via RunLog.exception) unless a quieter level is asked for."""
        if level and level.upper() != "ERROR":
            err.log_line = self.log.event(level.upper(), "mgmt", err.what, code=err.code,
                                          server_said=err.server_said, **fields)
        else:
            err.log_line = self.log.exception(err, "mgmt")

    def _post(self, command: str, payload: Optional[dict], *, sid: Optional[str],
              timeout: Optional[float], error_level: Optional[str] = None
              ) -> Tuple[int, bytes, str, int]:
        """One HTTPS POST. Returns (status, body, content_type, ms). Raises
        ConnectError / TlsTrustError (already logged)."""
        t = float(timeout or self.timeout)
        body = json.dumps(payload if payload is not None else {}).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": "aiguard/%s" % __version__}
        if sid:
            headers["X-chkp-sid"] = sid
        path = "%s/%s" % (self.base_path, command)
        attempts = 2 if _is_read_only_command(command) else 1
        for attempt in range(attempts):
            t0 = time.monotonic()
            conn = tlsutil.VerifiedHTTPSConnection(self.server, self.port, context=self._context,
                                                   server_hostname=self.server_name, timeout=t)
            phase = "connect"
            err: Optional[AiguardError] = None
            retry = False
            try:
                conn.connect()
                self._note_peer(conn)
                phase = "request"
                conn.request("POST", path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                ms = int((time.monotonic() - t0) * 1000)
                ctype = resp.getheader("Content-Type", "") or ""
                self.last_call_at = time.time()
                return int(resp.status), data, ctype, ms
            except ssl.SSLCertVerificationError as exc:
                err = tlsutil.trust_error(exc, self.server, "management", port=self.port,
                                          ca_file=self.ca_file, server_name=self.server_name)
            except ssl.SSLError as exc:
                eof = isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError))
                if eof and attempt + 1 < attempts:
                    retry = True
                elif phase == "connect":
                    err = tlsutil.trust_error(exc, self.server, "management", port=self.port,
                                              ca_file=self.ca_file, server_name=self.server_name)
                else:
                    err = self._connect_error("reset", exc, t)
            except socket.gaierror as exc:
                err = self._connect_error("dns", exc, t)
            except (socket.timeout, TimeoutError) as exc:
                err = self._connect_error("timeout", exc, t)
            except ConnectionRefusedError as exc:
                err = self._connect_error("refused", exc, t)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError,
                    http.client.RemoteDisconnected, http.client.IncompleteRead) as exc:
                if attempt + 1 < attempts:
                    retry = True
                else:
                    err = self._connect_error("reset", exc, t)
            except OSError as exc:
                unreachable = {getattr(errno, n, None) for n in
                               ("EHOSTUNREACH", "ENETUNREACH", "EHOSTDOWN", "ENETDOWN",
                                "WSAEHOSTUNREACH", "WSAENETUNREACH")} - {None}
                kind = "unreachable" if exc.errno in unreachable else "other"
                err = self._connect_error(kind, exc, t)
            except http.client.HTTPException as exc:
                err = self._connect_error("other", exc, t)
            finally:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001 - closing must not mask the real error
                    pass
            if retry:
                self.log.warn("mgmt", "%s: connection reset, retrying once" % command)
                continue
            assert err is not None
            err.details.setdefault("command", command)
            self._log_error(err, error_level, command=command)
            raise err
        raise AssertionError("unreachable")  # pragma: no cover

    def _call(self, command: str, payload: Optional[dict] = None, *, sid: Optional[str],
              timeout: Optional[float] = None, expect_json: bool = True,
              error_level: Optional[str] = None) -> Dict[str, Any]:
        # error_level: "WARN" marks a best-effort call (logout, discard, keepalive of a
        # second session): every failure is logged at WARN. "INFO" marks a probe whose API
        # error is an expected answer: API errors at INFO, transport errors stay ERROR.
        transport_level = error_level if (error_level or "").upper() == "WARN" else None
        status, data, ctype, ms = self._post(command, payload, sid=sid, timeout=timeout,
                                             error_level=transport_level)
        safe_payload = _loggable_payload(command, payload)
        parsed = _decode_body(data)
        if 200 <= status < 300:
            if isinstance(parsed, dict):
                level = "DEBUG" if command in _QUIET_COMMANDS else "INFO"
                self.log.event(level, "mgmt", "%s ok" % command, ms=ms, status=status,
                               payload=safe_payload)
                return parsed
            if not expect_json:
                self.log.info("mgmt", "%s ok" % command, ms=ms, status=status,
                              payload=safe_payload, content_type=ctype)
                return {"status": status, "content_type": ctype,
                        "text": parsed if isinstance(parsed, str) else json.dumps(parsed)}
            err = MgmtApiError(
                "Unexpected reply to %s (not a JSON object)" % command,
                command=command, http_status=status, code="mgmt.bad_reply",
                server_said=(_html_text(parsed) if isinstance(parsed, str) else str(parsed))[:300],
                why="The server answered with HTTP %d but the body is not a Management API JSON "
                    "object." % status,
                fix=["Check the address and port point at the Management API", _CHECK_LOG],
                details={"content_type": ctype})
            err.log_line = self.log.exception(err, "mgmt")
            raise err
        err = explain_api_error(command, status, parsed, client_ip=self.local_ip,
                                domain=self.domain or self._session_opts.get("domain"),
                                server=self.server, port=self.port, payload=payload,
                                api_version=self.api_version)
        if err.api_code == "generic_err_wrong_session_id" and sid and sid == self.sid:
            # The server dropped this session (timeout, logout, disconnected by an admin):
            # the client is no longer logged in, so status and the UIs say so.
            with self._lock:
                self.sid = None
                if self._system_sid == sid:
                    self._system_sid = None
                self.session_expired = True
            err.state = err.state or "Not logged in any more. Connect again."
        if err.code == "mgmt.permission_denied" and self.standby:
            err.fix = ["This management server is the Standby member of Management High "
                       "Availability, where sessions are read-only: connect to the Active "
                       "server"] + list(err.fix)
        level = error_level
        if (level is None and command.startswith("show-") and command != "show-task"
                and err.api_code == "generic_err_object_not_found"):
            level = "INFO"  # existence probes: "absent" is a normal answer
        if level and level.upper() != "ERROR":
            line = self.log.event(level.upper(), "mgmt", "%s: %s" % (command, err.what), ms=ms,
                                  status=status, api_code=err.api_code, payload=safe_payload,
                                  server_said=err.server_said)
            err.log_line = line
        else:
            err.details.setdefault("ms", ms)
            if command not in _CREDENTIAL_COMMANDS:
                err.details.setdefault("payload", safe_payload)
            err.log_line = self.log.exception(err, "mgmt")
        raise err

    def call(self, command: str, payload: Optional[dict] = None, *, timeout: Optional[float] = None,
             expect_json: bool = True) -> Dict[str, Any]:
        """``POST /web_api/<command>`` with the session id. Returns the JSON reply.

        Non-2xx replies raise :class:`MgmtApiError` (from :func:`explain_api_error`);
        transport problems raise :class:`ConnectError` / :class:`TlsTrustError`.
        """
        if command == "login":
            raise ValueError("use MgmtClient.login() to log in")
        if not self.sid and self.session_expired:
            err = MgmtApiError(
                "The management session is no longer valid", command=command,
                code="mgmt.session_expired", api_code="generic_err_wrong_session_id",
                why="The management server ended the session (after its timeout without calls, "
                    "on logout, or when an administrator disconnected it in SmartConsole).",
                fix=["Connect again",
                     "Unpublished changes stay in the old session until it is discarded: "
                     "SmartConsole > Manage & Settings > Sessions > View Sessions"],
                state="Not logged in any more. Nothing was sent.")
            err.log_line = self.log.exception(err, "mgmt")
            raise err
        if not self.sid:
            err = MgmtApiError(
                "Not logged in to the management server", command=command,
                code="mgmt.not_logged_in",
                why="%s needs a Management API session." % command,
                fix=["Connect first (aiguard setup, or Connect in the web console)"])
            err.log_line = self.log.exception(err, "mgmt")
            raise err
        return self._call(command, payload, sid=self.sid, timeout=timeout, expect_json=expect_json)

    # ------------------------------------------------------------------ login

    def login(self, *, api_key: Optional[str] = None, user: Optional[str] = None,
              password: Optional[str] = None, domain: Optional[str] = None,
              read_only: bool = False, session_name: str = "aiguard-demo",
              session_description: str = "AI Guard Demo Kit") -> Dict[str, Any]:
        """Log in (SMS or MDS) and return a display-safe summary.

        Keys: server, port, server_type, api_version, release, domain, domains (names,
        MDS only), fingerprint_sha1, fingerprint_sha256, ms, read_only, uid, url,
        reported_port, session_timeout, local_ip, auth, user.
        """
        api_key = api_key if api_key else None
        if not api_key and not (user and password):
            err = MgmtApiError(
                "No management credentials were given", command="login",
                code="mgmt.no_credentials",
                why="Log in needs an API key, or a username and password.",
                fix=["CLI: --api-key-env <VARIABLE> (or --user; the password is asked for)",
                     "Web console: fill in API key, or username and password"],
                state="Not logged in. Nothing was changed.")
            err.log_line = self.log.exception(err, "mgmt")
            raise err
        self._register(api_key)
        self._register(password, keep_tail=False)
        domain = (domain or "").strip() or None
        creds: Dict[str, Any] = {"api-key": api_key} if api_key else {"user": user, "password": password}
        with self._lock:
            self._creds = dict(creds)
            self._session_opts = {"read_only": bool(read_only), "session_name": session_name,
                                  "session_description": session_description, "domain": domain,
                                  "session_timeout": self.requested_session_timeout}
            self.user = user if not api_key else None
            self.auth = "api-key" if api_key else "password"
            self.session_expired = False
        self._commands = None
        self._domains = None
        t0 = time.monotonic()
        try:
            reply = self._login_call(domain=None, error_level="INFO" if domain else None)
        except AiguardError as exc:
            if not (domain and isinstance(exc, MgmtApiError) and exc.api_code == "err_login_failed"):
                if domain and isinstance(exc, MgmtApiError):
                    exc.log_line = self.log.exception(exc, "mgmt")  # was logged at INFO
                raise
            # Perhaps an administrator that may only log in to this domain: one more login.
            self.log.info("mgmt", "login without a domain was refused; trying the domain directly",
                          domain=domain)
            reply = self._login_call(domain=domain)
            self._apply_login(reply, domain=domain)
            if domain.lower() not in ("smc user", "system data"):
                self.server_type = "MDS"
            self.login_ms = int((time.monotonic() - t0) * 1000)
            return self._login_summary()
        self._apply_login(reply, domain=None)
        self._detect_server_type()
        if domain:
            if self.server_type == "MDS":
                if domain.lower() not in ("system data", "mds"):
                    self._enter_domain(domain)
            elif domain.lower() == "smc user":
                self.domain = "SMC User"
            elif self.server_type == "SMS" and domain.lower() != "system data":
                self.logout()
                err = MgmtApiError(
                    "%s is a Security Management Server: it has no domain '%s'" % (self.server, domain),
                    command="login", code="mgmt.not_mds",
                    why="Domains exist only on a Multi-Domain Server (MDS).",
                    fix=["Leave the domain empty for a Security Management Server",
                         "Or connect to the Multi-Domain Server's address"],
                    state="Logged out again. Nothing was changed.")
                err.log_line = self.log.exception(err, "mgmt")
                raise err
            else:
                self._relogin(domain)
        self.login_ms = int((time.monotonic() - t0) * 1000)
        return self._login_summary()

    def _login_payload(self, *, domain: Optional[str]) -> Dict[str, Any]:
        opts = self._session_opts
        payload: Dict[str, Any] = dict(self._creds)
        if domain:
            payload["domain"] = domain
        if opts.get("read_only"):
            payload["read-only"] = True
        if opts.get("session_name"):
            payload["session-name"] = opts["session_name"]
        if opts.get("session_description"):
            payload["session-description"] = opts["session_description"]
        if opts.get("session_timeout"):
            payload["session-timeout"] = int(opts["session_timeout"])
        return payload

    def _login_call(self, *, domain: Optional[str], error_level: Optional[str] = None
                    ) -> Dict[str, Any]:
        """``login`` with the session options. A server that refuses the requested
        ``session-timeout`` value is asked again without it (default 600 s; the engine
        then keeps the session alive with keepalive)."""
        try:
            return self._call("login", self._login_payload(domain=domain), sid=None,
                              error_level=error_level)
        except MgmtApiError as exc:
            said = " ".join(str(x or "") for x in (exc.server_said, exc.what)).lower()
            if not (self._session_opts.get("session_timeout")
                    and exc.api_code in _INVALID_PARAMETER_CODES and "session-timeout" in said):
                raise
            self.log.warn("mgmt", "the server refused session-timeout; logging in with its "
                          "default timeout", requested=self._session_opts.get("session_timeout"))
            self._session_opts["session_timeout"] = None
            return self._call("login", self._login_payload(domain=domain), sid=None,
                              error_level=error_level)

    def _apply_login(self, reply: Dict[str, Any], *, domain: Optional[str]) -> None:
        sid = reply.get("sid")
        if not sid:
            err = MgmtApiError("The login reply has no session id", command="login",
                               code="mgmt.bad_reply",
                               why="The server accepted the login but sent no 'sid'.",
                               fix=["On the management server run: api status", _CHECK_LOG])
            err.log_line = self.log.exception(err, "mgmt")
            raise err
        self._register(str(sid))
        with self._lock:
            self.sid = str(sid)
            self.session_expired = False
            self.uid = reply.get("uid") or self.uid
            version = reply.get("api-server-version")
            if version:
                self.api_version = str(version)
            self.read_only = bool(reply.get("read-only", self._session_opts.get("read_only", False)))
            self.standby = reply.get("standby")
            if reply.get("session-timeout") is not None:
                try:
                    self.session_timeout = int(reply.get("session-timeout"))
                except (TypeError, ValueError):
                    pass
            self.domain = domain
            url = reply.get("url")
        if url:
            self.reported_url = str(url)
            try:
                reported = urlsplit(str(url)).port
            except ValueError:
                reported = None
            if reported is None and str(url).lower().startswith("https://"):
                reported = 443
            self.reported_port = reported
            if reported and reported != self.port:
                self.log.hint("mgmt", "the login reply names another port", reported_port=reported,
                              connected_port=self.port, url=str(url))
        if not self.api_version:
            try:
                versions = self._call("show-api-versions", {}, sid=self.sid, error_level="WARN")
                if versions.get("current-version"):
                    self.api_version = str(versions["current-version"])
            except AiguardError:
                pass
        self.release = release_for_api(self.api_version)
        self.log.info("mgmt", "logged in", server=self.server, port=self.port,
                      api_version=self.api_version, release=self.release, domain=domain,
                      read_only=self.read_only, session_uid=self.uid,
                      session_timeout=self.session_timeout, fingerprint_sha1=self.fingerprint_sha1,
                      standby=self.standby)

    def _detect_server_type(self) -> None:
        """show-domains works only in an MDS System Data session."""
        try:
            doms = self._show_all_sid("show-domains", {"details-level": "standard"}, sid=self.sid,
                                      error_level="INFO")
        except MgmtApiError as exc:
            if exc.api_code == "generic_err_command_not_found":
                self.server_type = "SMS"
            else:
                cmds = self.commands()
                if "login-to-domain" in cmds or "show-domains" in cmds:
                    self.server_type = "MDS"
                    self._system_sid = self.sid
                    self.domain = "System Data"
                else:
                    self.server_type = "SMS" if cmds else "unknown"
            self.log.info("mgmt", "server type", server_type=self.server_type)
            return
        # show-domains answered: an MDS System Data session -- unless the session says it is
        # in the SMS's own domain ("SMC User").
        is_mds = True
        try:
            sess = self._call("show-session", {}, sid=self.sid, error_level="INFO")
            dom = sess.get("domain") if isinstance(sess.get("domain"), dict) else {}
            if str(dom.get("name") or "") == "SMC User":
                is_mds = False
            self.session_ip = sess.get("ip-address") or None
        except MgmtApiError:
            pass
        if is_mds and not doms:
            try:
                mdss = self._call("show-mdss", {"limit": 1}, sid=self.sid, error_level="INFO")
                is_mds = bool(mdss.get("objects"))
            except MgmtApiError:
                is_mds = False
        if not is_mds:
            self.server_type = "SMS"
            self.log.info("mgmt", "server type", server_type=self.server_type)
            return
        self.server_type = "MDS"
        self._system_sid = self.sid
        self.domain = "System Data"
        self._domains = [self._norm_domain(d) for d in doms if self._norm_domain(d)]
        self.log.info("mgmt", "server type", server_type="MDS",
                      domains=[d["name"] for d in self._domains])

    @staticmethod
    def _norm_domain(d: Any) -> Optional[Dict[str, Any]]:
        if isinstance(d, str):
            return {"name": d, "uid": None, "type": "domain"}
        if isinstance(d, dict) and d.get("name"):
            out = {"name": str(d.get("name")), "uid": d.get("uid"), "type": d.get("type") or "domain"}
            if d.get("domain-type"):
                out["domain-type"] = d.get("domain-type")
            if isinstance(d.get("servers"), list):
                out["servers"] = [s.get("name") for s in d["servers"] if isinstance(s, dict)]
            return out
        return None

    def _enter_domain(self, domain: str, *, switching_from: Optional[str] = None) -> None:
        # switching_from: the domain the client still works in when this is a domain switch
        # (the error then says so instead of "System Data only").
        stay = ("Still working in domain %s. Nothing was changed." % switching_from
                if switching_from else "Logged in to System Data only. Nothing was changed.")
        match = None
        if self._domains is not None:
            for d in self._domains:
                if str(d.get("name", "")).lower() == domain.lower() or (d.get("uid") and d.get("uid") == domain):
                    match = d
                    break
            if match is None:
                names = [d["name"] for d in self._domains]
                err = MgmtApiError(
                    "Domain '%s' was not found on this MDS" % domain, command="login",
                    code="mgmt.domain_not_found",
                    why="The Multi-Domain Server lists %s." % (
                        ("these domains: " + ", ".join(names)) if names else "no domains for this administrator"),
                    fix=(["Use one of: " + ", ".join(names)] if names else []) + [
                        "Use the domain name as SmartConsole shows it (not the Domain Server's "
                        "name or IP address)"],
                    state=stay,
                    details={"domains": names})
                err.log_line = self.log.exception(err, "mgmt")
                raise err
        target = match["name"] if match else domain
        system_cmds = self.commands_for_system() if self._system_sid else set()
        if self._system_sid and (not system_cmds or "login-to-domain" in system_cmds):
            payload: Dict[str, Any] = {"domain": target}
            if self._session_opts.get("read_only"):
                payload["read-only"] = True
            try:
                reply = self._call("login-to-domain", payload, sid=self._system_sid,
                                   error_level="INFO")
            except MgmtApiError as exc:
                if exc.api_code in ("generic_err_command_not_found", "generic_err_wrong_session_id"):
                    # no login-to-domain here, or the System Data session is gone
                    if exc.api_code == "generic_err_wrong_session_id":
                        self._system_sid = None
                    self._relogin(target)
                    return
                if exc.api_code != "generic_err_object_not_found":
                    exc.log_line = self.log.exception(exc, "mgmt")
                    raise
                err = MgmtApiError(
                    "Domain '%s' was not found on this MDS" % domain, command="login-to-domain",
                    code="mgmt.domain_not_found", http_status=exc.http_status,
                    api_code=exc.api_code, server_said=exc.server_said,
                    why="The Multi-Domain Server has no domain with that name that this "
                        "administrator can open.",
                    fix=["Use the domain name as SmartConsole shows it (not the Domain Server's "
                         "name or IP address)", "Connect without a domain to list the domains"],
                    state=stay)
                err.log_line = self.log.exception(err, "mgmt")
                raise err
            old = self.sid
            self._apply_login(reply, domain=target)
            if old and old not in (self._system_sid, self.sid):
                self._logout_sid(old)
            self._commands = None
            return
        self._relogin(target)

    def commands_for_system(self) -> Set[str]:
        """Commands of the System Data session (cached like :meth:`commands`)."""
        if self._system_commands is not None:
            return set(self._system_commands)
        if self.sid == self._system_sid:
            names = self.commands()
            if names:
                self._system_commands = set(names)
            return names
        try:
            data = self._call("show-commands", {}, sid=self._system_sid, error_level="WARN")
        except MgmtApiError:
            return set()
        names = self._command_names(data)
        self._system_commands = names
        return set(names)

    def _relogin(self, domain: str) -> None:
        """A new login straight into ``domain`` (costs one login)."""
        old = self.sid
        reply = self._login_call(domain=domain)
        self._apply_login(reply, domain=domain)
        self._commands = None
        if old and old not in (self._system_sid, self.sid):
            self._logout_sid(old)
        if domain.lower() not in ("smc user", "system data"):
            self.server_type = "MDS"

    def switch_domain(self, domain: str) -> Dict[str, Any]:
        """Work in another MDS domain: ``login-to-domain`` from the System Data session
        when possible (no extra login), else a new login with ``domain``."""
        domain = (domain or "").strip()
        if not domain:
            raise ValueError("domain is required")
        if self.server_type != "MDS":
            raise MgmtApiError(
                "%s is not a Multi-Domain Server" % self.server, command="login-to-domain",
                code="mgmt.not_mds", why="Domains exist only on a Multi-Domain Server (MDS).",
                fix=["Leave the domain empty for a Security Management Server"])
        if self.domain and self.domain.lower() == domain.lower():
            return self._login_summary()
        previous = self._session_opts.get("domain")
        current = self.domain
        self._session_opts["domain"] = domain
        try:
            self._enter_domain(domain, switching_from=current
                               if current and current.lower() != "system data" else None)
        except AiguardError:
            if self.domain == current:
                self._session_opts["domain"] = previous   # still in the old domain
            raise
        return self._login_summary()

    def _login_summary(self) -> Dict[str, Any]:
        doms = [d["name"] for d in self._domains] if self._domains else []
        return {
            "server": self.server, "port": self.port, "server_type": self.server_type,
            "api_version": self.api_version, "release": self.release, "domain": self.domain,
            "domains": doms, "fingerprint_sha1": self.fingerprint_sha1,
            "fingerprint_sha256": self.fingerprint_sha256, "ms": self.login_ms,
            "read_only": self.read_only, "uid": self.uid, "url": self.reported_url,
            "reported_port": self.reported_port, "session_timeout": self.session_timeout,
            "local_ip": self.local_ip, "auth": self.auth, "user": self.user,
            "standby": self.standby,
        }

    # ------------------------------------------------------------------ discovery

    @staticmethod
    def _command_names(data: Dict[str, Any]) -> Set[str]:
        names: Set[str] = set()
        for c in data.get("commands") or []:
            if isinstance(c, dict) and c.get("name"):
                names.add(str(c["name"]))
            elif isinstance(c, str):
                names.add(c)
        return names

    def commands(self) -> Set[str]:
        """Command names from ``show-commands`` (cached). Empty set when unknown."""
        with self._lock:
            if self._commands is not None:
                return set(self._commands)
        if not self.sid:
            return set()
        try:
            data = self._call("show-commands", {}, sid=self.sid, error_level="WARN")
        except MgmtApiError as exc:
            if exc.api_code == "generic_err_command_not_found":
                with self._lock:
                    self._commands = set()
            return set()
        names = self._command_names(data)
        with self._lock:
            self._commands = names
        self.log.info("mgmt", "commands", count=len(names),
                      ai=sorted(n for n in names if "ai-" in n or n.startswith("test-ai")))
        return set(names)

    def has(self, command: str) -> bool:
        """True if the server lists ``command`` (or the list is unknown)."""
        cmds = self.commands()
        return (not cmds) or command in cmds

    def _show_all_sid(self, command: str, payload: Optional[dict], *, sid: Optional[str],
                      key: str = "objects", limit: int = 50,
                      error_level: Optional[str] = None) -> List[Any]:
        items: List[Any] = []
        offset = 0
        limit = max(1, int(limit))
        for _page in range(_MAX_PAGES):
            p = dict(payload or {})
            p["limit"] = limit
            p["offset"] = offset
            data = self._call(command, p, sid=sid, error_level=error_level)
            chunk = data.get(key) or []
            if not isinstance(chunk, list):
                chunk = [chunk]
            items.extend(chunk)
            if not chunk:
                break
            offset += len(chunk)
            total = data.get("total")
            if isinstance(total, int) and not isinstance(total, bool):
                if offset >= total:
                    break
            elif len(chunk) < limit:
                break
        else:
            self.log.warn("mgmt", "%s: stopped after %d pages" % (command, _MAX_PAGES))
        return items

    def show_all(self, command: str, payload: Optional[dict] = None, key: str = "objects",
                 limit: int = 50) -> List[dict]:
        """All pages of a ``show-*`` listing (``limit``/``offset`` paging)."""
        if not self.sid:
            self.call(command, payload)  # raises "Not logged in"
        return self._show_all_sid(command, payload, sid=self.sid, key=key, limit=limit)

    def list_domains(self) -> List[dict]:
        """Domains of an MDS (``show-domains`` on the System Data session); ``[]`` on SMS."""
        if self.server_type != "MDS":
            return []
        if self._domains is None and self._system_sid:
            try:
                doms = self._show_all_sid("show-domains", {"details-level": "standard"},
                                          sid=self._system_sid, error_level="WARN")
                self._domains = [x for x in (self._norm_domain(d) for d in doms) if x]
            except MgmtApiError:
                return []
        return [dict(d) for d in (self._domains or [])]

    # ------------------------------------------------------------------ tasks

    def wait_task(self, task_id: Union[str, List[str]], *, what: str,
                  progress_cb: Optional[Callable[[int, str, str], None]] = None,
                  timeout: float = 1200, poll: Optional[float] = None,
                  fix: Union[None, List[str], Callable[[str], List[str]]] = None,
                  state: Optional[str] = None, command: Optional[str] = None) -> Dict[str, Any]:
        """Poll ``show-task`` (details-level full) until the task(s) finish.

        Returns the task dict plus ``messages`` (list of str), ``warnings`` (list of str)
        and ``message_details`` (see :func:`task_messages`). ``failed`` / ``partially
        succeeded`` raise :class:`MgmtApiError` with the task's messages as
        ``server_said``; "succeeded with warnings" is OK (warnings are logged).
        ``poll`` defaults to :attr:`task_poll`. ``fix`` (a list, or a function of the
        server text returning one), ``state`` and ``command`` (the command that started
        the task) refine the error.
        """
        interval = self.task_poll if poll is None else float(poll)
        ids = list(task_id) if isinstance(task_id, (list, tuple)) else [task_id]
        ids = [str(i) for i in ids if i]
        if not ids:
            raise ValueError("task_id is required")
        payload: Dict[str, Any] = {"task-id": ids[0] if len(ids) == 1 else ids,
                                   "details-level": "full"}
        deadline = time.monotonic() + float(timeout)
        last: Optional[Tuple[int, str, str]] = None
        tasks: List[Dict[str, Any]] = []
        self.log.info("mgmt", "waiting for task", what=what, task_id=ids)
        transient = 0
        while True:
            try:
                data = self.call("show-task", payload)
                transient = 0
            except ConnectError:
                # The server can be slow to answer while it publishes / installs.
                transient += 1
                if transient > 3 or time.monotonic() >= deadline:
                    raise
                self.log.warn("mgmt", "show-task did not answer; polling again", what=what,
                              attempt=transient)
                time.sleep(max(0.0, min(max(interval, 1.0), deadline - time.monotonic())))
                continue
            tasks = [t for t in (data.get("tasks") or []) if isinstance(t, dict)]
            statuses = [str(t.get("status") or "").lower() for t in tasks]
            pct_values = []
            for t in tasks:
                try:
                    pct_values.append(int(float(t.get("progress-percentage") or 0)))
                except (TypeError, ValueError):
                    pct_values.append(0)
            pct = min(pct_values) if pct_values else 0
            done = bool(tasks) and all(s in TASK_OK + TASK_FAILED for s in statuses)
            if done:
                overall = ("failed" if "failed" in statuses else
                           "partially succeeded" if "partially succeeded" in statuses else
                           "succeeded with warnings" if "succeeded with warnings" in statuses else
                           "succeeded")
            else:
                overall = "in progress"
            message = ""
            for t in tasks:
                message = str(t.get("progress-description") or t.get("task-name") or message)
            key = (pct, overall, message)
            if key != last:
                last = key
                self.log.info("mgmt", "task %s: %s %d%%" % (what, overall, pct), message=message)
                if progress_cb is not None:
                    try:
                        progress_cb(pct, overall, message)
                    except Exception as exc:  # noqa: BLE001 - a UI callback must not break the task
                        self.log.debug("mgmt", "progress callback failed", error=repr(exc))
            if done:
                break
            if time.monotonic() >= deadline:
                err = MgmtApiError(
                    "%s did not finish within %gs" % (_cap(what), float(timeout)),
                    command=command or "show-task", code="mgmt.task_timeout", task_id=ids[0],
                    why="The management server still reports the task as running.",
                    fix=["Check the task in SmartConsole (Tasks, at the bottom left)",
                         "Wait for it to finish, then run the step again if needed"],
                    state=state or "The task may still be running on the management server.",
                    details={"task_id": ids, "last_status": overall, "progress": pct})
                err.log_line = self.log.exception(err, "mgmt")
                raise err
            time.sleep(max(0.0, min(interval, deadline - time.monotonic())))

        details: List[Dict[str, Any]] = []
        for t in tasks:
            details.extend(task_messages(t))
        texts = _uniq(d["text"] for d in details)
        warns = _uniq(d["text"] for d in details if d["level"] == "warning")
        result = dict(tasks[0]) if len(tasks) == 1 else {
            "task-id": ids, "status": overall, "progress-percentage": 100, "tasks": tasks}
        result["messages"] = texts
        result["warnings"] = warns
        result["message_details"] = details
        if overall in TASK_FAILED:
            errs = _uniq(d["text"] for d in details if d["level"] == "error")
            said = _redact.redact("\n".join(errs or warns or texts) or "Task status: %s" % overall)
            fix_list = fix(said) if callable(fix) else fix
            err = MgmtApiError(
                "%s failed" % _cap(what) if overall == "failed" else "%s partially succeeded" % _cap(what),
                command=command or "show-task", code="mgmt.task_failed", task_id=ids[0],
                server_said=said,
                why=("The management server reported the task as '%s'." % overall),
                fix=fix_list or ["Read the server messages above (Server said)",
                                 "SmartConsole shows the full report: Tasks (bottom left) > "
                                 "double-click the task"],
                state=state, errors=errs, warnings=warns,
                details={"task_id": ids, "status": overall, "messages": texts,
                         "message_details": details,
                         "start_posix": task_start_posix(tasks[0]) if tasks else None})
            err.log_line = self.log.exception(err, "mgmt")
            raise err
        if warns:
            self.log.warn("mgmt", "task %s finished with warnings" % what, warnings=warns)
        else:
            self.log.info("mgmt", "task %s finished" % what, status=overall, messages=texts)
        return result

    def publish(self, progress_cb: Optional[Callable[[int, str, str], None]] = None) -> Dict[str, Any]:
        """``publish`` -> task-id -> :meth:`wait_task` (what="publish")."""
        data = self.call("publish", {})
        tid = data.get("task-id")
        if not tid:
            return data
        try:
            return self.wait_task(
                tid, what="publish", progress_cb=progress_cb, command="publish",
                fix=["Read the server messages above (Server said)",
                     "SmartConsole > Manage & Settings > Sessions > View Sessions shows this "
                     "session (%s) and its changes"
                     % (self._session_opts.get("session_name") or "aiguard-demo"),
                     "Fix the object the server names, then publish again (or discard the "
                     "session)"],
                state="Nothing was published. The changes are still in this session.")
        except AiguardError as exc:
            # The server accepted the publish and runs it on its own: unless the task itself
            # ended as failed, the outcome is unknown to this client.
            exc.details.setdefault("task_id", tid)
            exc.details["publish_submitted"] = True
            raise

    def discard(self) -> bool:
        """Discard this session's unpublished changes. Best effort, never raises. True when
        the server confirmed it (False: not logged in any more, or the call failed)."""
        if not self.sid:
            return False
        try:
            data = self._call("discard", {}, sid=self.sid, timeout=min(self.timeout, 30),
                              error_level="WARN")
            self.log.info("mgmt", "discarded", changes=data.get("number-of-discarded-changes"))
            return True
        except Exception as exc:  # noqa: BLE001 - best effort by contract
            self.log.warn("mgmt", "discard failed", error="%s: %s" % (type(exc).__name__, exc))
            return False

    def install_policy(self, package: str, targets: Union[str, List[str]], *, access: bool = False,
                       threat_prevention: bool = True,
                       progress_cb: Optional[Callable[[int, str, str], None]] = None) -> Dict[str, Any]:
        """``install-policy`` -> task-id -> :meth:`wait_task`. Only the parts asked for are
        installed (``desktop-security`` and ``qos`` are sent as false)."""
        tlist = [targets] if isinstance(targets, str) else [str(t) for t in (targets or [])]
        payload: Dict[str, Any] = {"policy-package": package, "targets": tlist,
                                   "access": bool(access), "threat-prevention": bool(threat_prevention),
                                   "desktop-security": False, "qos": False}
        parts = [p for p, on in (("Access Control", access), ("Threat Prevention", threat_prevention)) if on]
        what = "install policy %s (%s) on %s" % (package, " + ".join(parts) or "nothing",
                                                   ", ".join(tlist) or "all targets")
        data = self.call("install-policy", payload)
        tid = data.get("task-id")
        if not tid:
            return data
        try:
            return self.wait_task(tid, what=what, progress_cb=progress_cb,
                                  command="install-policy",
                                  fix=lambda said: self._install_fix(said, tlist, package),
                                  state="The policy was not installed on %s. Published changes "
                                        "stay published." % (", ".join(tlist) or "the targets"))
        except AiguardError as exc:
            exc.details.setdefault("task_id", tid)
            exc.details["install_submitted"] = True
            exc.details["install"] = {"package": package, "targets": tlist,
                                      "access": bool(access),
                                      "threat_prevention": bool(threat_prevention)}
            if str(exc.details.get("status") or "") == "partially succeeded":
                exc.state = ("Part of the policy was installed on %s and part was not (see "
                             "Server said). Published changes stay published."
                             % (", ".join(tlist) or "the targets"))
            raise

    @staticmethod
    def _install_fix(said: str, targets: List[str], package: str) -> List[str]:
        low = said.lower()
        gw = ", ".join(targets) or "the gateway"
        fix: List[str] = []
        failing = failing_rule(said)
        if ("data types are not supported" in low or "sk116272" in low
                or ("data type" in low and "not supported" in low)):
            where = ("rule %s (%s) in layer %s" % (failing["number"], failing["name"],
                                                   failing["layer"]) if failing else "the rule")
            fix.append("Remove the data types the server lists from %s (Workforce AI Security "
                       "rules do not accept every classic data type, see sk116272), publish, "
                       "then install again" % where)
        elif re.search(r"not supported by the (?:software|version) on|requires (?:gateway )?"
                       r"version|is not supported on (?:this|the) (?:gateway|version)|"
                       r"(?:gateway|software) version", low):
            fix.append("AI Agent Security needs R82.20 on the gateway: check the version of %s "
                       "(SmartConsole > Gateways & Servers) and upgrade it, or pick an R82.20 "
                       "gateway" % gw)
        if "sic" in low or "communicat" in low or "connect" in low:
            fix.append("Check SIC with the gateway: SmartConsole > %s > General Properties > "
                       "Communication > Test SIC Status" % gw)
        if "license" in low or "contract" in low:
            fix.append("Check the gateway's licenses and contracts: SmartConsole > Gateways & "
                       "Servers > %s > Licenses (AI Agent Security needs the AI Guardrails license)"
                       % gw)
        fix.extend([
            "Read the gateway messages above (Server said): they name the rule or object that failed",
            "SmartConsole > Security Policies > Install Policy (%s on %s) shows the same "
            "verification errors" % (package, gw),
            "Fix what it names, publish, then install again",
        ])
        return fix

    # ------------------------------------------------------------------ logs

    def show_logs(self, filter_text: str, *, time_frame: str = "last-hour",
                  max_logs: int = 100) -> List[dict]:
        """``show-logs`` new query (type logs), newest first. Pages with ``query-id``
        when ``max_logs`` > 100."""
        max_logs = max(1, int(max_logs))
        per = min(100, max_logs)
        query: Dict[str, Any] = {"filter": filter_text or "", "time-frame": time_frame,
                                 "max-logs-per-request": per, "type": "logs"}
        data = self.call("show-logs", {"new-query": query}, timeout=max(self.timeout, 120))
        logs = [x for x in (data.get("logs") or []) if isinstance(x, dict)]
        qid = data.get("query-id")
        while qid and len(logs) < max_logs:
            page_n = len(data.get("logs") or [])
            if page_n < per:
                break
            data = self.call("show-logs", {"query-id": qid}, timeout=max(self.timeout, 120))
            page = [x for x in (data.get("logs") or []) if isinstance(x, dict)]
            if not page:
                break
            logs.extend(page)
            qid = data.get("query-id") or qid
        self.log.info("mgmt", "show-logs returned %d logs" % len(logs), filter=filter_text,
                      time_frame=time_frame)
        return logs[:max_logs]

    # ------------------------------------------------------------------ session end

    def keepalive(self) -> None:
        """Keep the session (and the MDS System Data session) alive."""
        self.call("keepalive", {})
        if self._system_sid and self._system_sid != self.sid:
            try:
                self._call("keepalive", {}, sid=self._system_sid, error_level="WARN")
            except AiguardError:
                self._system_sid = None

    def idle_seconds(self) -> Optional[float]:
        """Seconds since the last reply from the management server (None: never)."""
        last = self.last_call_at
        return None if last is None else max(0.0, time.time() - last)

    def can_relogin(self) -> bool:
        """True when the credentials of the last login are still in memory."""
        return bool(self._creds)

    def relogin(self) -> Dict[str, Any]:
        """Log in again with the credentials of the last login (same domain, same session
        options). Used when the server dropped an idle session; costs one login."""
        creds = dict(self._creds)
        if not creds:
            err = MgmtApiError(
                "The management session is no longer valid", command="login",
                code="mgmt.session_expired",
                why="The server ended the session, and the credentials are no longer in memory.",
                fix=["Connect again"], state="Not logged in. Nothing was changed.")
            err.log_line = self.log.exception(err, "mgmt")
            raise err
        opts = dict(self._session_opts)
        old_system = self._system_sid
        with self._lock:
            self.sid = None
            self._system_sid = None
        if old_system:
            self._logout_sid(old_system)
        self.log.info("mgmt", "logging in again (the session had ended)",
                      domain=opts.get("domain"))
        return self.login(api_key=creds.get("api-key"), user=creds.get("user"),
                          password=creds.get("password"), domain=opts.get("domain"),
                          read_only=bool(opts.get("read_only")),
                          session_name=opts.get("session_name") or "aiguard-demo",
                          session_description=opts.get("session_description")
                          or "AI Guard Demo Kit")

    def _logout_sid(self, sid: str) -> None:
        try:
            self._call("logout", {}, sid=sid, timeout=min(self.timeout, 10), error_level="WARN")
        except Exception:  # noqa: BLE001 - logout never raises
            pass
        try:
            _redact.forget_secret(sid)
        except Exception:  # noqa: BLE001 - logout never raises
            pass

    def logout(self) -> None:
        """Log out of every session this client opened. Never raises."""
        try:
            sids = []
            for sid in (self.sid, self._system_sid):
                if sid and sid not in sids:
                    sids.append(sid)
            for sid in sids:
                self._logout_sid(sid)
            if sids:
                self.log.info("mgmt", "logged out", sessions=len(sids))
        except Exception:  # noqa: BLE001 - logout never raises
            pass
        finally:
            with self._lock:
                self.sid = None
                self._system_sid = None
                self._creds = {}
                self._commands = None
                self._system_commands = None
                self.session_expired = False   # an explicit logout, not an expiry

    def _register(self, value: Optional[str], *, keep_tail: bool = True) -> None:
        if not value:
            return
        text = str(value)
        _redact.register_secret(text, keep_tail=keep_tail)
        with self._lock:
            if text not in self._registered:
                self._registered.append(text)

    def forget_secrets(self) -> None:
        """Forget the credentials (and sids) this client registered for redaction.

        Call after :meth:`logout` when the run ends (logout clears the credentials but
        this list is kept for exactly this call). A value that an engine session still
        holds (``register_secret(owner=...)``) stays masked until that session lets go.
        """
        with self._lock:
            values = list(self._registered) + list(self._creds.values()) + [
                self.sid, self._system_sid]
            self._registered = []
            self._creds = {}
        for value in values:
            if value:
                try:
                    _redact.forget_secret(value)
                except Exception:  # noqa: BLE001 - never raises
                    pass

    close = logout

    def __enter__(self) -> "MgmtClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.logout()
