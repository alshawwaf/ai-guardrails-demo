"""Direct Lakera Guard (Check Point AI Guardrails) calls (spec 5.3 + section 10).

* :func:`validate` -- is this key + project usable? ``POST /v2/policies/health``
  (documented, creates no screening log); only if that endpoint answers 404 we fall
  back to one benign ``POST /v2/guard`` screening.
* :func:`classify` -- screen a text with ``breakdown: true`` and name the top
  detector category. ``flagged`` from the API is always false in Detect mode, so
  a detection is read from ``breakdown[].detected``.

Confidence is reported as Lakera's level labels (``l1_confident`` -> "confident" ...),
never as an invented percentage.

HTTP goes through :mod:`aiguard.tlsutil` (verification on, TLS 1.2+, optional
``ca_file``), with an explicit timeout and no redirects. The key is registered with
:func:`aiguard.redact.register_secret` and never appears in results, errors or logs.
Every failure raises :class:`~aiguard.errors.LakeraError` (what / why / fix).
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from . import __version__
from . import redact as _redact
from . import tlsutil
from .errors import LakeraError, TlsTrustError

__all__ = [
    "DEFAULT_URL",
    "BENIGN_TEXT",
    "CONFIDENCE_LABELS",
    "CATEGORY_LABELS",
    "LakeraTlsError",
    "confidence_label",
    "category_label",
    "top_category",
    "endpoints",
    "validate",
    "classify",
]

DEFAULT_URL = "https://api.lakera.ai/v2/guard"
BENIGN_TEXT = "Hello. This is a connectivity check from the AI Guard Demo Kit."
USER_AGENT = "aiguard/%s (AI Guard Demo Kit)" % __version__
MAX_TEXT_BYTES = 512 * 1024
MAX_READ = 1024 * 1024

KEY_FIX = [
    "Check the key: Check Point Portal > AI Security > AI Guardrails > Settings > API Access "
    "(platform.lakera.ai > API Access). Create a Guard API key if needed and copy it again",
    "Use a Guard API key, not a Platform API key",
    "If your organisation restricts processing regions, use the matching regional URL "
    "(https://eu.api.lakera.ai/v2/guard or https://us.api.lakera.ai/v2/guard)",
]
PROJECT_FIX = [
    "Check Point Portal > AI Security > AI Guardrails > Projects: copy the project ID "
    "(it looks like project-XXXXXXXXXX)",
    "Make sure the key and the project belong to the same organisation",
    "Make sure a policy is assigned to the project (the default policy is fine)",
]

CONFIDENCE_LABELS: Dict[str, str] = {
    "l1_confident": "confident",
    "l2_very_likely": "very likely",
    "l3_likely": "likely",
    "l4_less_likely": "less likely",
    "l5_unlikely": "unlikely",
}
_LEVEL_RANK = {"l1_confident": 1, "l2_very_likely": 2, "l3_likely": 3, "l4_less_likely": 4,
               "l5_unlikely": 5}

CATEGORY_LABELS: Dict[str, str] = {
    "prompt_attack": "Prompt attack",
    "moderated_content": "Moderated content",
    "moderated_content/crime": "Crime",
    "moderated_content/hate": "Hate",
    "moderated_content/profanity": "Profanity",
    "moderated_content/sexual": "Sexual content",
    "moderated_content/violence": "Violence",
    "moderated_content/weapons": "Weapons",
    "moderated_content/self-harm": "Self-harm",
    "moderated_content/self_harm": "Self-harm",
    "moderated_content/custom": "Custom moderation",
    "pii": "Personal data",
    "pii/name": "Name",
    "pii/phone_number": "Phone number",
    "pii/email": "Email address",
    "pii/ip_address": "IP address",
    "pii/address": "Postal address",
    "pii/credit_card": "Credit card number",
    "pii/iban_code": "IBAN",
    "pii/us_social_security_number": "US social security number",
    "pii/custom": "Custom personal data",
    "unknown_links": "Unknown links",
}


class LakeraTlsError(LakeraError, TlsTrustError):
    """Certificate verification of the Lakera endpoint failed (both a LakeraError and a
    TlsTrustError)."""

    default_code = "lakera.tls"


def confidence_label(result: Optional[str]) -> Optional[str]:
    """``"l1_confident"`` -> ``"confident"`` ...; ``no_level`` / unknown -> ``None``."""
    return CONFIDENCE_LABELS.get(str(result or "").strip().lower())


def category_label(detector_type: Optional[str]) -> str:
    """Display name for a detector type (falls back to the type itself)."""
    if not detector_type:
        return ""
    text = str(detector_type)
    if text in CATEGORY_LABELS:
        return CATEGORY_LABELS[text]
    tail = text.rsplit("/", 1)[-1].replace("_", " ").replace("-", " ")
    return tail[:1].upper() + tail[1:]


def _group_rank(detector_type: str) -> int:
    t = detector_type.lower()
    if t == "moderated_content" or t.startswith("moderated_content/"):
        return 0
    if t == "prompt_attack":
        return 1
    if t == "pii" or t.startswith("pii/"):
        return 2
    if t == "unknown_links":
        return 3
    return 4


def top_category(detections: List[Dict[str, Any]]) -> Optional[str]:
    """First detected type in priority order: moderated_content/*, prompt_attack, pii/*,
    unknown_links, anything else; ties -> higher confidence, then breakdown order."""
    ranked = []
    for index, d in enumerate(detections or []):
        if not d.get("detected"):
            continue
        dtype = str(d.get("detector_type") or "")
        if not dtype:
            continue
        ranked.append((_group_rank(dtype), _LEVEL_RANK.get(str(d.get("result") or ""), 9),
                       index, dtype))
    if not ranked:
        return None
    return min(ranked)[3]


# --------------------------------------------------------------------------- endpoints


def endpoints(url: str = DEFAULT_URL) -> Dict[str, Any]:
    """``{host, port, guard_path, health_path}`` for a Lakera URL.

    Accepts the guard URL (``https://api.lakera.ai/v2/guard``, the app's
    ``DEMO_API_URL`` format), a ``.../v2`` URL or a bare base URL. ``health_path`` is
    ``None`` when it cannot be derived (then :func:`validate` uses the guard call).
    """
    text = str(url or DEFAULT_URL).strip()
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise LakeraError("Invalid Lakera URL", code="lakera.bad_url", server_said=str(exc),
                          fix=["Use https://api.lakera.ai/v2/guard (or a regional URL)"],
                          state="Nothing was sent.") from exc
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise LakeraError("The Lakera URL must be https://<host>/v2/guard",
                          code="lakera.bad_url",
                          fix=["Use https://api.lakera.ai/v2/guard (or a regional URL)"],
                          state="Nothing was sent.")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise LakeraError("The Lakera URL must not carry credentials or a query string",
                          code="lakera.bad_url",
                          fix=["Use https://api.lakera.ai/v2/guard; the key is sent as a header"],
                          state="Nothing was sent.")
    path = parts.path.rstrip("/")
    health: Optional[str]
    if path in ("",):
        guard, health = "/v2/guard", "/v2/policies/health"
    elif path.endswith("/v2/guard"):
        guard, health = path, path[: -len("/guard")] + "/policies/health"
    elif path.endswith("/v2"):
        guard, health = path + "/guard", path + "/policies/health"
    else:
        guard, health = path, None
    return {"host": parts.hostname, "port": int(port or 443), "guard_path": guard,
            "health_path": health}


# --------------------------------------------------------------------------- HTTP


def _post(ep: Dict[str, Any], path: str, payload: Dict[str, Any], api_key: str,
          ca_file: Optional[str], timeout: float) -> Tuple[int, str, bytes, Any, int]:
    """POST JSON; returns (status, content_type, raw, parsed-or-None, ms)."""
    host, port = ep["host"], ep["port"]
    ctx = tlsutil.make_context(ca_file)
    conn = tlsutil.VerifiedHTTPSConnection(host, port, context=ctx, timeout=timeout)
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "Authorization": "Bearer %s" % api_key, "User-Agent": USER_AGENT,
               "Connection": "close"}
    t0 = time.monotonic()
    try:
        try:
            conn.connect()
        except ssl.SSLCertVerificationError as exc:
            err = tlsutil.trust_error(exc, host, "provider", port=port, ca_file=ca_file)
            raise LakeraTlsError(
                err.what, code="lakera.tls", server_said=err.server_said,
                why=err.why + (" (In gateway mode the call to %s itself crosses the gateway.)"
                               % host),
                fix=err.fix, state="Nothing was validated.", details=err.details) from exc
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(MAX_READ)
        status = resp.status
        ctype = resp.getheader("Content-Type", "") or ""
    except LakeraError:
        raise
    except (socket.timeout, TimeoutError) as exc:
        raise LakeraError(
            "Lakera did not answer within %gs (%s)" % (timeout, host),
            code="lakera.timeout", server_said=str(exc) or "timed out",
            why="The Lakera API did not answer in time. A firewall or proxy may be dropping "
                "the connection.",
            fix=["Check that this computer can reach %s:%d" % (host, port),
                 "Try again in a moment"],
            state="Nothing was validated.", details={"host": host, "port": port}) from exc
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        raise LakeraError(
            "Cannot reach Lakera at %s:%d" % (host, port),
            code="lakera.connect", server_said="%s: %s" % (type(exc).__name__, exc),
            why="The connection to the Lakera API failed before a reply arrived.",
            fix=["Check DNS, proxy (HTTPS_PROXY) and firewall rules for %s" % host,
                 "In gateway mode, check SmartConsole Logs for drops of %s from this computer"
                 % host],
            state="Nothing was validated.", details={"host": host, "port": port}) from exc
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
    ms = int((time.monotonic() - t0) * 1000)
    parsed: Any = None
    if raw.strip()[:1] in (b"{", b"["):
        try:
            parsed = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            parsed = None
    return status, ctype, raw, parsed, ms


def _server_text(parsed: Any, raw: bytes) -> Tuple[str, Optional[str]]:
    """(message, request_id) from a Lakera error body."""
    request_id = None
    if isinstance(parsed, dict):
        request_id = parsed.get("request_id")
        msg = parsed.get("error") or parsed.get("message") or parsed.get("detail")
        if isinstance(msg, (dict, list)):
            msg = json.dumps(msg)
        text = str(msg) if msg else json.dumps(parsed)
    else:
        text = raw[:600].decode("utf-8", "replace")
    text = _redact.redact(text).strip()[:300]
    if request_id:
        text = "%s (request_id %s)" % (text, request_id)
    return text, (str(request_id) if request_id else None)


def _mentions_project(text: str) -> bool:
    return "project" in (text or "").lower()


def _error_for(status: int, ctype: str, parsed: Any, raw: bytes, *, project_id: str,
               host: str, command: str) -> LakeraError:
    said, request_id = _server_text(parsed, raw)
    details = {"http_status": status, "request_id": request_id, "host": host,
               "endpoint": command, "project_id": project_id or None}
    if parsed is None and status < 500:
        # Not the Lakera API's JSON: a block page, proxy or captive portal answered.
        low = raw[:4096].decode("utf-8", "replace").lower()
        blocked = any(m in low for m in ("usercheck", "check point", "checkpoint"))
        return LakeraError(
            "Unexpected reply from %s (HTTP %d %s)" % (host, status, ctype or "no type"),
            code="lakera.unexpected", server_said=said,
            why=("The gateway answered instead of Lakera (block page): the call to %s was "
                 "blocked on the way." % host if blocked else
                 "The reply is not the Lakera API's JSON. A proxy or captive portal may be "
                 "in the path, or the URL is wrong."),
            fix=["Check the Lakera URL (default %s)" % DEFAULT_URL,
                 "Check proxies, HTTPS Inspection and Threat Prevention rules for %s" % host],
            state="Nothing was validated.", details=details)
    if status in (401, 403):
        return LakeraError(
            "Lakera rejected the API key", code="lakera.bad_key",
            server_said="HTTP %d: %s" % (status, said),
            why="The key is wrong, revoked, or not a Guard API key for this organisation.",
            fix=list(KEY_FIX), state="Nothing was validated.", details=details)
    if status in (400, 404, 422) and _mentions_project(said):
        return LakeraError(
            "Lakera project %s was not found for this key" % (project_id or "(none)"),
            code="lakera.project_not_found", server_said=said,
            why="The key works, but Lakera has no project with this ID and a policy for "
                "the key's organisation.",
            fix=list(PROJECT_FIX), state="Nothing was validated.", details=details)
    if status == 429:
        return LakeraError(
            "Lakera rate limit reached (HTTP 429)", code="lakera.rate_limited",
            server_said=said,
            why="Too many requests for this key or organisation (the community tier allows "
                "10,000 requests a month).",
            fix=["Wait a minute and try again",
                 "Check the plan's request quota in the AI Guardrails dashboard"],
            state="Nothing was validated.", details=details)
    if status >= 500:
        return LakeraError(
            "Lakera service error (HTTP %d)" % status, code="lakera.service",
            server_said=said, why="The Lakera API had an internal problem.",
            fix=["Try again in a few minutes",
                 "If it persists, contact support with the request_id%s"
                 % (" " + request_id if request_id else "")],
            state="Nothing was validated.", details=details)
    return LakeraError(
        "Lakera refused the request (HTTP %d)" % status, code="lakera.request",
        server_said=said, why="The Lakera API did not accept the request (see the message).",
        fix=["Check the project ID and the URL", "Try again; if it persists, send the log"],
        state="Nothing was validated.", details=details)


def _check_inputs(api_key: Optional[str], project_id: Optional[str], *,
                  need_project: bool) -> Tuple[str, str]:
    key = str(api_key or "").strip()
    if not key:
        raise LakeraError("No Lakera API key given", code="lakera.no_key",
                          fix=list(KEY_FIX[:2]), state="Nothing was validated.")
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in key):
        raise LakeraError("The Lakera API key contains spaces or control characters",
                          code="lakera.bad_key_format",
                          fix=["Copy the key again without spaces or line breaks"],
                          state="Nothing was validated.")
    _redact.register_secret(key)
    pid = str(project_id or "").strip()
    if need_project and not pid:
        raise LakeraError("A Lakera project ID is required", code="lakera.no_project",
                          why="Check Point AI Agent Security uses the project's policy.",
                          fix=list(PROJECT_FIX[:1]), state="Nothing was validated.")
    if len(pid) > 200 or any(ord(ch) < 0x21 for ch in pid):
        raise LakeraError("Invalid Lakera project ID", code="lakera.bad_project",
                          fix=list(PROJECT_FIX[:1]), state="Nothing was validated.")
    return key, pid


def _log(log: Any, level: str, msg: str, **fields: Any) -> None:
    fn = getattr(log, level, None) if log is not None else None
    if fn is None:
        return
    try:
        fn("lakera", msg, **fields)
    except Exception:  # noqa: BLE001 - logging never breaks a call
        pass


def _detections(breakdown: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in breakdown if isinstance(breakdown, list) else []:
        if not isinstance(item, dict):
            continue
        result = item.get("result")
        out.append({
            "detector_type": str(item.get("detector_type") or ""),
            "detected": bool(item.get("detected")),
            "result": result,
            "label": confidence_label(result),
            "detector_id": item.get("detector_id"),
            "policy_id": item.get("policy_id"),
            "project_id": item.get("project_id"),
        })
    return out


# --------------------------------------------------------------------------- validate


def validate(api_key: str, project_id: str, *, url: str = DEFAULT_URL,
             ca_file: Optional[str] = None, timeout: float = 15, log: Any = None) -> dict:
    """Check a Guard API key and project without screening anything.

    Returns ``{"ok": True, "ms", "project_id", "detectors": [...], "method"
    ("policies/health" | "guard"), "is_default", "message", "warnings", "masked_key",
    "host"}``. ``detectors`` is only known after the guard fallback (the health endpoint
    does not list them). Raises :class:`LakeraError` (bad key, unknown project, rate
    limit, service error, network / TLS problem).
    """
    key, pid = _check_inputs(api_key, project_id, need_project=True)
    ep = endpoints(url)
    host = ep["host"]
    timeout = float(timeout)
    base = {"ok": True, "project_id": pid, "masked_key": _redact.mask_secret(key),
            "host": host, "detectors": [], "is_default": None, "message": "",
            "warnings": []}

    if ep["health_path"]:
        status, ctype, raw, parsed, ms = _post(ep, ep["health_path"], {"project_id": pid},
                                               key, ca_file, timeout)
        said, _rid = _server_text(parsed, raw) if status != 200 else ("", None)
        if status == 200 and isinstance(parsed, dict):
            if str(parsed.get("status") or "").lower() == "error":
                msg = _redact.redact(str(parsed.get("message") or "")).strip()
                details = {"http_status": 200, "host": host, "endpoint": "policies/health",
                           "project_id": pid}
                if not msg or _mentions_project(msg):
                    err = LakeraError(
                        "Lakera project %s was not found for this key" % pid,
                        code="lakera.project_not_found", server_said=msg or None,
                        why="Lakera has no project with this ID and a policy for the key's "
                            "organisation.",
                        fix=list(PROJECT_FIX), state="Nothing was validated.", details=details)
                else:
                    err = LakeraError(
                        "Lakera reports a problem with project %s's policy" % pid,
                        code="lakera.policy_error", server_said=msg,
                        why="The project exists but its policy is not healthy.",
                        fix=["Check Point Portal > AI Security > AI Guardrails > Policies: fix "
                             "the policy assigned to the project"],
                        state="Nothing was validated.", details=details)
                _log(log, "warn", "validate failed", code=err.code, method="policies/health",
                     ms=ms, server_said=err.server_said)
                raise err
            out = dict(base)
            out.update({"ms": ms, "method": "policies/health",
                        "is_default": parsed.get("is_default"),
                        "message": _redact.redact(str(parsed.get("message") or ""))})
            lint = parsed.get("lint")
            if isinstance(lint, dict):
                for item in lint.get("errors") or []:
                    if isinstance(item, dict) and item.get("message"):
                        out["warnings"].append("%s: %s" % (item.get("severity") or "lint",
                                                           _redact.redact(str(item["message"]))))
            if out["is_default"]:
                out["warnings"].append("The project uses the AI Guardrails Default Policy")
            _log(log, "info", "validate ok", method="policies/health", ms=ms, project_id=pid,
                 host=host, is_default=out["is_default"], warnings=out["warnings"] or None)
            return out
        if not (status == 404 and not _mentions_project(said)):
            err = _error_for(status, ctype, parsed, raw, project_id=pid, host=host,
                             command="policies/health")
            _log(log, "warn", "validate failed", code=err.code, http_status=status,
                 method="policies/health", ms=ms, server_said=err.server_said)
            raise err
        _log(log, "info", "policies/health not available (HTTP 404); using one guard call",
             host=host)

    # Fallback: one benign screening (this one is logged by Lakera as a request).
    status, ctype, raw, parsed, ms = _post(
        ep, ep["guard_path"],
        {"messages": [{"role": "user", "content": BENIGN_TEXT}], "project_id": pid,
         "breakdown": True},
        key, ca_file, timeout)
    if status != 200 or not isinstance(parsed, dict):
        err = _error_for(status, ctype, parsed, raw, project_id=pid, host=host, command="guard")
        _log(log, "warn", "validate failed", code=err.code, http_status=status,
             method="guard", ms=ms, server_said=err.server_said)
        raise err
    detections = _detections(parsed.get("breakdown"))
    out = dict(base)
    out.update({"ms": ms, "method": "guard",
                "detectors": [d["detector_type"] for d in detections if d["detector_type"]],
                "action": parsed.get("action")})
    other = sorted({d["project_id"] for d in detections
                    if d.get("project_id") and d["project_id"] != pid})
    if other:
        out["warnings"].append("Lakera answered for project(s) %s, not %s"
                               % (", ".join(other), pid))
    if not detections:
        out["warnings"].append("The project's policy returned no detectors")
    _log(log, "info", "validate ok", method="guard", ms=ms, project_id=pid, host=host,
         detectors=len(out["detectors"]), warnings=out["warnings"] or None)
    return out


# --------------------------------------------------------------------------- classify


def classify(text: str, api_key: str, project_id: str, *, url: str = DEFAULT_URL,
             ca_file: Optional[str] = None, timeout: float = 15, log: Any = None) -> dict:
    """Screen ``text`` (as a user message) and summarise the detections.

    Returns ``{"flagged", "detections": [{detector_type, detected, result, label,
    detector_id, policy_id, project_id}], "top_category", "ms"}`` plus ``detected``
    (detected types), ``top_label`` (display name), ``confidence_label`` (of the top
    category), ``result`` (its level), ``action`` ("detect" | "enforce"),
    ``lakera_flagged`` (the API's own flag) and ``request_uuid``.
    ``flagged`` is True when Lakera flagged it *or* any detector fired (Detect mode
    never sets the API flag). ``project_id`` may be empty (Lakera's default policy).
    """
    if not isinstance(text, str) or not text.strip():
        raise LakeraError("Nothing to classify (empty text)", code="lakera.empty_text",
                          state="Nothing was sent.")
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise LakeraError("The text is too long to classify (over 512 KB)",
                          code="lakera.text_too_long", state="Nothing was sent.")
    key, pid = _check_inputs(api_key, project_id, need_project=False)
    ep = endpoints(url)
    payload: Dict[str, Any] = {"messages": [{"role": "user", "content": text}],
                               "breakdown": True}
    if pid:
        payload["project_id"] = pid
    status, ctype, raw, parsed, ms = _post(ep, ep["guard_path"], payload, key, ca_file,
                                           float(timeout))
    if status != 200 or not isinstance(parsed, dict):
        err = _error_for(status, ctype, parsed, raw, project_id=pid, host=ep["host"],
                         command="guard")
        err.state = "The text was not classified."
        _log(log, "warn", "classify failed", code=err.code, http_status=status, ms=ms,
             server_said=err.server_said)
        raise err
    detections = _detections(parsed.get("breakdown"))
    detected = [d["detector_type"] for d in detections if d["detected"] and d["detector_type"]]
    top = top_category(detections)
    top_item = next((d for d in detections if d["detected"] and d["detector_type"] == top), None)
    api_flagged = bool(parsed.get("flagged"))
    metadata = parsed.get("metadata") if isinstance(parsed.get("metadata"), dict) else {}
    out = {
        "flagged": api_flagged or bool(detected),
        "detections": detections,
        "top_category": top,
        "ms": ms,
        "detected": detected,
        "top_label": category_label(top) if top else None,
        "confidence_label": top_item["label"] if top_item else None,
        "result": top_item["result"] if top_item else None,
        "action": parsed.get("action"),
        "lakera_flagged": api_flagged,
        "request_uuid": metadata.get("request_uuid"),
    }
    _log(log, "info", "classify", ms=ms, flagged=out["flagged"], top=top,
         confidence=out["confidence_label"], action=out["action"],
         text_len=len(text), request_uuid=out["request_uuid"])
    return out
