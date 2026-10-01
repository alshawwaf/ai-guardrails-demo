"""Change plans: build (read-only), apply (with approval), roll back (spec 4.1, 4.2).

A plan is built from a data-driven template (:mod:`aiguard.templates`):

* :func:`build_plan` resolves the gateway, policy package, threat / HTTPS layer and the
  protected scope, detects the AI Agent Security field names the server uses, probes
  every object it would create (``show-*`` only -- building a plan never changes
  anything) and renders the template into :class:`PlanStep` objects. An object that
  already exists and was created by the kit (``comments`` contain "AI Guard Demo Kit")
  is updated; one that belongs to someone else stops the plan (name conflict). A step
  whose command the server does not have becomes a "You do this" manual step.
* :func:`apply_plan` runs an approved plan: changes -> rollback point -> publish ->
  install -> gateway scripts (content moderation). Any failure before publish discards
  the session ("Nothing was changed."), unless the server had already accepted the
  publish (lost connection, timeout, an error while polling its task): then the outcome
  is unknown and the rollback point stays usable (status ``publish-unknown``). The
  rollback point (object UIDs + undo commands, no secrets) is written to
  :class:`~aiguard.state.State` *before* publish, and a gateway script's undo is recorded
  *before* the script runs. A failed or uncertain install reports, per policy type, what
  the gateway still enforces (``ApplyResult.install_status``). A gateway script the user
  has to finish by hand is a warning (``ApplyResult.notices``), not a failed apply.
* :func:`rollback` undoes a rollback point in reverse order, publishes and installs.
  Objects that are already gone are skipped with a note, so running it twice is safe.

Template rendering: ``{var}`` inside a string is replaced by the variable's text; a
string that is exactly ``"{var}"`` is replaced by the value itself (list, bool, dict).
Dict keys may be templated too (``"{ai.enable}"``). ``{secret:name}`` takes the value
from the ``secrets`` dict: the real value goes into ``PlanStep.payload`` (memory only),
``display_payload`` shows ``mask_secret(value)`` and the value is registered with
:func:`aiguard.redact.register_secret`. Unknown variables raise :class:`PlanError`.

Everything displayable (:meth:`Plan.to_dict`, :meth:`Plan.api_calls`, log lines, state)
is built from display payloads and passed through :func:`aiguard.redact.redact_obj`.
"""

from __future__ import annotations

import copy
import datetime as _dt
import hashlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from . import gateways as _gateways
from . import redact as _redact
from .errors import AiguardError, ApprovalError, ConnectError, MgmtApiError, PlanError
from .mgmt import api_version_tuple, failing_rule, release_for_api, show_outbound_certificate
from .templates import MARKER, load_template

__all__ = [
    "PlanOptions",
    "PlanStep",
    "Plan",
    "ApplyResult",
    "build_plan",
    "apply_plan",
    "rollback",
    "compute_plan_id",
    "client_host_name",
    "render_value",
    "THREAT_TRACKS",
    "MARKER",
]

THREAT_TRACKS = ("None", "Log", "Alert", "Mail", "SNMP trap", "User Alert 1", "User Alert 2",
                 "User Alert 3")

_NOT_FOUND = "generic_err_object_not_found"
_COMMAND_NOT_FOUND = "generic_err_command_not_found"
_VALIDATION_CODES = ("err_validation_failed", "generic_err_validation_failed", "generic_error")
_IN_USE_RE = re.compile(r"(?i)\b(in use|is used by|used in|is referenced|still referenced)\b")

_RUN_SCRIPT_PERMISSION = ("SmartConsole > Manage & Settings > Permissions & Administrators > "
                          "Permission Profiles > (profile) > Gateways: Run One Time Script")

_INSTALL_DETAILS_HINT = ("In SmartConsole > Install Policy details, both Access Control and "
                         "Threat Prevention must say Succeeded")


def _read_only_fix(client: Any) -> List[str]:
    fix = ["Use an administrator whose permission profile is Read/Write and may edit and "
           "install the policy (SmartConsole > Manage & Settings > Permissions & "
           "Administrators > Permission Profiles), then connect again"]
    standby = ("This management server is the Standby member of Management High Availability "
               "(its sessions are read-only): connect to the Active server")
    if getattr(client, "standby", None) is True:
        return [standby] + fix
    return fix + ["If this is the Standby server of Management High Availability, connect to "
                  "the Active server"]

ProgressCb = Callable[[str, str, Optional[int], str], None]


# --------------------------------------------------------------------------- data classes


@dataclass
class PlanOptions:
    """What to build. ``scope``: ``"client"`` (host object for ``client_ip``; the
    default, limits the demo to this computer), ``"any"`` or an existing object name."""

    gateway: str
    package: Optional[str] = None
    template: str = "ai-agent-security"
    profile_name: str = "AIGuard-Demo"
    rule_name: str = "AI Guard Demo"
    track: str = "Log"
    scope: str = "client"
    client_ip: Optional[str] = None
    moderation: bool = False
    lakera_project_id: Optional[str] = None
    install: bool = True
    add_https_rule: bool = False


@dataclass
class PlanStep:
    """One step. ``payload`` holds real secret values (memory only, never shown or
    logged); everything user-facing uses ``display_payload``.

    ``action``: ``"add"`` | ``"update"`` | ``"manual"`` | ``"publish"`` | ``"install"``,
    plus ``"script"`` (a gateway script that will run), ``"none"`` (already in place,
    nothing to do) and, in rollbacks, ``"delete"``.
    ``status``: ``"pending"`` -> ``"running"`` -> ``"done"`` | ``"failed"`` |
    ``"skipped"`` | ``"manual"`` (manual steps are never reported as done).
    """

    id: str
    kind: str
    command: Optional[str]
    describe: str
    payload: dict = field(repr=False)
    display_payload: dict
    rollback: Optional[dict]
    manual_steps: List[str]
    action: str
    status: str = "pending"
    message: str = ""
    ms: int = 0
    result_uid: Optional[str] = None
    existing_uid: Optional[str] = None      # uid of the object found by the exists probe
    exists: Optional[dict] = None           # rendered read-only probe {"command", "payload"}
    secret_keys: List[str] = field(default_factory=list)   # names of secrets in payload

    def to_dict(self) -> dict:
        """Display-safe (no secrets)."""
        rb = None
        if self.rollback:
            rb = {"command": self.rollback.get("command"),
                  "payload": self.rollback.get("payload"),
                  "describe": self.rollback.get("describe")}
        return _redact.redact_obj({
            "id": self.id, "kind": self.kind, "command": self.command, "describe": self.describe,
            "action": self.action, "display_payload": self.display_payload, "rollback": rb,
            "manual_steps": list(self.manual_steps), "status": self.status,
            "message": self.message, "ms": self.ms, "result_uid": self.result_uid,
            "existing_uid": self.existing_uid, "secret_keys": list(self.secret_keys),
        })


@dataclass
class Plan:
    """A rendered, reviewable plan. ``plan_id`` is the first 12 hex characters of the
    sha256 of the canonical JSON of server, domain, gateway, package, template and each
    step's id / kind / action / command / display payload (see :func:`compute_plan_id`)."""

    plan_id: str
    server: str
    domain: Optional[str]
    gateway: str
    package: str
    threat_layer: Optional[str]
    steps: List[PlanStep]
    warnings: List[str]
    created_at: str
    template: str = "ai-agent-security"
    title: str = ""
    https_layer: Optional[str] = None
    protected_scope: Optional[str] = None
    client_host_name: Optional[str] = None
    field_variant: Optional[str] = None
    is_cluster: bool = False
    install_access: bool = False
    install_threat_prevention: bool = True
    options: Dict[str, Any] = field(default_factory=dict)

    def step(self, step_id: str) -> Optional[PlanStep]:
        for s in self.steps:
            if s.id == step_id:
                return s
        return None

    def api_calls(self) -> List[dict]:
        """The calls :func:`apply_plan` will make, display-safe:
        ``[{"step", "command", "payload"}]`` (manual and already-in-place steps are left out)."""
        out = []
        for s in self.steps:
            if not s.command or s.action in ("manual", "none"):
                continue
            out.append({"step": s.id, "command": s.command, "payload": s.display_payload})
        return _redact.redact_obj(out)

    @property
    def published(self) -> bool:
        """True once :func:`apply_plan` published this plan (it then refuses to run it
        again: build a new plan)."""
        return bool(getattr(self, "_published", False))

    def to_dict(self) -> dict:
        """Display-safe (no secrets). ``published``: see :attr:`published`."""
        counts: Dict[str, int] = {}
        for s in self.steps:
            counts[s.action] = counts.get(s.action, 0) + 1
        return _redact.redact_obj({
            "plan_id": self.plan_id, "published": self.published,
            "server": self.server, "domain": self.domain,
            "gateway": self.gateway, "package": self.package, "threat_layer": self.threat_layer,
            "https_layer": self.https_layer, "template": self.template, "title": self.title,
            "protected_scope": self.protected_scope, "client_host_name": self.client_host_name,
            "field_variant": self.field_variant, "is_cluster": self.is_cluster,
            "created_at": self.created_at, "warnings": list(self.warnings),
            "options": self.options, "counts": counts,
            "steps": [s.to_dict() for s in self.steps], "api_calls": self.api_calls(),
        })


@dataclass
class ApplyResult:
    """Outcome of :func:`apply_plan` or :func:`rollback`. ``error`` carries the five
    user-facing fields; ``message`` is a one-line summary (also when ``ok``)."""

    ok: bool
    plan_id: str
    rollback_id: Optional[str]
    steps: List[PlanStep]
    error: Optional[AiguardError]
    published: bool
    installed: bool
    message: str = ""
    warnings: List[str] = field(default_factory=list)
    moderation_enabled: Optional[bool] = None
    kind: str = "apply"   # "apply" | "rollback"
    # Per policy type after an install attempt: {"access"|"threat_prevention":
    # "installed" | "not installed" | "unknown"} (only the parts that were installed).
    install_status: Optional[Dict[str, str]] = None
    # Steps the user must finish by hand (e.g. a gateway script the administrator may not
    # run): five-field error dicts, shown as warnings; they do not make ``ok`` False.
    notices: List[dict] = field(default_factory=list)

    @property
    def state_text(self) -> str:
        """What changed / what is left (the error's ``state`` when there is one)."""
        if self.error is not None and self.error.state:
            return self.error.state
        return self.message

    def to_dict(self) -> dict:
        return _redact.redact_obj({
            "ok": self.ok, "kind": self.kind, "plan_id": self.plan_id,
            "rollback_id": self.rollback_id, "published": self.published,
            "installed": self.installed, "message": self.message,
            "state": self.state_text, "warnings": list(self.warnings),
            "moderation_enabled": self.moderation_enabled,
            "install_status": dict(self.install_status) if self.install_status else None,
            "notices": [dict(n) for n in self.notices],
            "steps": [s.to_dict() for s in self.steps],
            "error": self.error.to_dict() if self.error is not None else None,
        })


# --------------------------------------------------------------------------- helpers


class _NullLog(object):
    path = None

    def event(self, *a: Any, **k: Any) -> int:
        return 0

    debug = info = warn = error = hint = event

    def exception(self, err: BaseException, component: str) -> int:
        return 0


def _log_of(client: Any, log: Any) -> Any:
    if log is not None:
        return log
    return getattr(client, "log", None) or _NullLog()


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log_err(log: Any, err: BaseException) -> None:
    """Log an error with all its fields (``RunLog.exception`` sets ``err.log_line``)."""
    try:
        log.exception(err, "plan")
    except Exception:  # noqa: BLE001 - logging must not hide the real error
        pass


def _emit(cb: Optional[ProgressCb], log: Any, step_id: str, status: str,
          pct: Optional[int], message: str) -> None:
    if cb is None:
        return
    try:
        cb(step_id, status, pct, _redact.redact(message or ""))
    except Exception as exc:  # noqa: BLE001 - a UI callback must not break the apply
        try:
            log.debug("plan", "progress callback failed", error=repr(exc))
        except Exception:  # noqa: BLE001
            pass


def client_host_name(ip: str) -> str:
    """``"10.1.1.50"`` -> ``"aiguard-client-10-1-1-50"`` (IPv6 ``:`` become ``-`` too)."""
    return "aiguard-client-" + str(ip).strip().replace(".", "-").replace(":", "-")


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def compute_plan_id(plan: Plan) -> str:
    """sha256 of the canonical JSON of what the plan will do, first 12 hex characters."""
    data = {
        "server": plan.server, "domain": plan.domain, "gateway": plan.gateway,
        "package": plan.package, "template": plan.template,
        "steps": [{"id": s.id, "kind": s.kind, "action": s.action, "command": s.command,
                   "payload": s.display_payload} for s in plan.steps],
    }
    return hashlib.sha256(_canonical(data).encode("utf-8")).hexdigest()[:12]


def _ident(value: Any) -> Optional[str]:
    """Name (or uid) of an API object reference (dict or string)."""
    if isinstance(value, dict):
        for key in ("name", "uid"):
            if value.get(key):
                return str(value[key])
        return None
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _is_ours(obj: Any) -> bool:
    return isinstance(obj, dict) and MARKER in str(obj.get("comments") or "")


def _task_ids(resp: Any) -> List[str]:
    """``task-id`` (string or list) and ``tasks[]`` (strings or ``{"task-id": ...}``)."""
    out: List[str] = []
    if not isinstance(resp, dict):
        return out

    def add(value: Any) -> None:
        if isinstance(value, str) and value and value not in out:
            out.append(value)

    tid = resp.get("task-id")
    if isinstance(tid, list):
        for t in tid:
            add(t)
    else:
        add(tid)
    tasks = resp.get("tasks")
    if isinstance(tasks, list):
        for t in tasks:
            if isinstance(t, dict):
                add(t.get("task-id"))
            else:
                add(t)
    return out


def _short(text: str, limit: int = 80) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


# --------------------------------------------------------------------------- rendering


_VAR_RE = re.compile(r"\{(secret:[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*"
                     r"(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\}")

# Friendly errors for variables / secrets that are missing (value None or empty).
_VAR_HELP: Dict[str, Tuple[str, str, List[str]]] = {
    "lakera_project_id": (
        "The AI Guardrails project ID is required",
        "The threat profile tells the gateway which AI Guardrails project (policy) to use.",
        ["Check Point Portal > AI Security > AI Guardrails > Projects: open the project (or "
         "New Project with the default policy) and copy its project ID",
         "CLI: aiguard setup asks for it; web console: Configure > Project ID"]),
    "client_ip": (
        "This computer's IP address is unknown",
        "With scope 'client' the rule is limited to a host object for this computer's IP "
        "address, and the address could not be determined.",
        ["Run the plan from the computer that sends the demo prompts (aiguard finds its "
         "address automatically)",
         "Or choose another scope: --scope any, or --scope <existing object name>"]),
}
# The host name and the protected scope are derived from the client IP.
_VAR_HELP["client_host_name"] = _VAR_HELP["client_ip"]
_VAR_HELP["protected_scope"] = _VAR_HELP["client_ip"]
_SECRET_HELP: Dict[str, Tuple[str, str, List[str]]] = {
    "lakera_api_key": (
        "The AI Agent Security (Guard) API key is required",
        "The threat profile needs the Guard API key so the gateway can call the AI Guardrails "
        "service.",
        ["Check Point Portal > AI Security > AI Guardrails > Settings > API Access > Guard API "
         "keys > Create (64 hex characters; a Platform API key will not work)",
         "CLI: aiguard setup asks for it (hidden input) or --lakera-key-env <VARIABLE>; web "
         "console: Configure > API key"]),
}


class _Context(object):
    """Template variables; resolvers run on first use (so a layer is looked up only
    when an included step needs it) and their result is cached."""

    def __init__(self) -> None:
        self.values: Dict[str, Any] = {}
        self.resolvers: Dict[str, Callable[[], Any]] = {}

    def set(self, name: str, value: Any) -> None:
        self.values[name] = value
        self.resolvers.pop(name, None)

    def lazy(self, name: str, fn: Callable[[], Any]) -> None:
        self.values.pop(name, None)
        self.resolvers[name] = fn

    def has(self, name: str) -> bool:
        return name in self.values or name in self.resolvers

    def peek(self, name: str) -> Any:
        """The value if already known/resolved (never runs a resolver)."""
        return self.values.get(name)

    def get(self, name: str) -> Any:
        if name in self.values:
            return self.values[name]
        fn = self.resolvers.pop(name, None)
        if fn is None:
            raise KeyError(name)
        value = fn()
        self.values[name] = value
        return value


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return ", ".join(_text(v) for v in value)
    if isinstance(value, dict):
        return _canonical(value)
    return str(value)


class _Renderer(object):
    def __init__(self, ctx: _Context, secrets: Dict[str, str], where: str) -> None:
        self.ctx = ctx
        self.secrets = secrets
        self.where = where
        self.used_secrets: List[str] = []

    def _lookup(self, name: str, display: bool) -> Any:
        if name.startswith("secret:"):
            key = name[len("secret:"):]
            value = self.secrets.get(key)
            if not value:
                what, why, fix = _SECRET_HELP.get(key, (
                    "The secret '%s' is required for this plan" % key,
                    "The template step '%s' needs it." % self.where,
                    ["Enter it, then build the plan again"]))
                raise PlanError(what, code="plan.missing_secret", why=why, fix=fix,
                                state="Nothing was changed.", details={"step": self.where})
            if key not in self.used_secrets:
                self.used_secrets.append(key)
            _redact.register_secret(value)
            return _redact.mask_secret(value) if display else value
        try:
            value = self.ctx.get(name)
        except KeyError:
            raise PlanError("The template uses an unknown variable {%s}" % name,
                            code="plan.template",
                            why="Step '%s' refers to a variable that aiguard does not define."
                                % self.where,
                            fix=["Check the template: known variables are %s"
                                 % ", ".join(sorted(set(self.ctx.values) | set(self.ctx.resolvers)))],
                            state="Nothing was changed.") from None
        if value is None or (isinstance(value, str) and not value.strip()):
            what, why, fix = _VAR_HELP.get(name, (
                "No value for {%s}" % name,
                "Step '%s' needs it, and it could not be determined." % self.where,
                ["Check the plan options and try again"]))
            raise PlanError(what, code="plan.missing_value", why=why, fix=fix,
                            state="Nothing was changed.", details={"variable": name})
        return copy.deepcopy(value)

    def render(self, obj: Any, display: bool = False) -> Any:
        if isinstance(obj, str):
            m = _VAR_RE.fullmatch(obj)
            if m:
                return self._lookup(m.group(1), display)
            return _VAR_RE.sub(lambda mm: _text(self._lookup(mm.group(1), display)), obj)
        if isinstance(obj, dict):
            out: Dict[str, Any] = {}
            for k, v in obj.items():
                key = self.render_key(k)
                out[key] = self.render(v, display)
            return out
        if isinstance(obj, list):
            return [self.render(v, display) for v in obj]
        return copy.deepcopy(obj)

    def render_key(self, key: Any) -> str:
        if not isinstance(key, str):
            return str(key)
        if "{secret:" in key:
            raise PlanError("A template key may not contain a secret", code="plan.template",
                            why="Step '%s' uses {secret:...} in a field name." % self.where,
                            state="Nothing was changed.")
        value = self.render(key)
        return value if isinstance(value, str) else _text(value)


def render_value(obj: Any, variables: Dict[str, Any], secrets: Optional[Dict[str, str]] = None,
                 *, display: bool = False) -> Any:
    """Render a template fragment with plain ``variables`` (for tests and tools)."""
    ctx = _Context()
    for k, v in (variables or {}).items():
        ctx.set(k, v)
    return _Renderer(ctx, dict(secrets or {}), "value").render(obj, display)


def _when_ok(when: Any, flags: Dict[str, bool]) -> bool:
    if when is None:
        return True
    items = when if isinstance(when, list) else [when]
    for w in items:
        neg = w.startswith("!")
        value = bool(flags.get(w.lstrip("!")))
        if value == neg:
            return False
    return True


# --------------------------------------------------------------------------- build helpers


def _no_ai_error(client: Any, commands: Iterable[str] = ()) -> PlanError:
    have = getattr(client, "api_version", None)
    release = release_for_api(have) if have else None
    shown = (have or "unknown") + (" (%s)" % release if release else "")
    why = "Needs R82.20 management (API 2.2); server reports API %s." % shown
    names = [c for c in commands if c]
    if have and api_version_tuple(have) >= (2, 2) and names:
        why += (" It does not list any of the AI Agent Security commands (%s)."
                % ", ".join(names))
    return PlanError(
        "This management server has no AI Agent Security support",
        code="plan.ai_unsupported",
        why=why,
        fix=["Upgrade the management server to R82.20 (Management API 2.2), or connect to one",
             "Check the version with: aiguard status (or api status on the management server)"],
        state="Nothing was changed.", details={"api_version": have})


def _check_api_version(client: Any, tpl: dict) -> None:
    need = tpl.get("min_api_version")
    have = getattr(client, "api_version", None)
    if not need or not have:
        return
    if api_version_tuple(have) >= api_version_tuple(need):
        return
    if tpl.get("field_variants"):
        raise _no_ai_error(client)
    release = release_for_api(need)
    raise PlanError(
        "This management server's API is too old for '%s'" % tpl.get("id"),
        code="plan.api_version",
        why="Needs Management API %s%s; server reports API %s%s." % (
            need, " (%s)" % release if release else "", have,
            " (%s)" % release_for_api(have) if release_for_api(have) else ""),
        fix=["Upgrade the management server, or do this change in SmartConsole"],
        state="Nothing was changed.")


def _detect_variant(client: Any, tpl: dict) -> Optional[Tuple[str, Dict[str, Any]]]:
    variants = tpl.get("field_variants")
    if not variants:
        return None
    for name, variant in variants.items():
        if client.has(variant["detect_command"]):
            return name, variant
    raise _no_ai_error(client, [v["detect_command"] for v in variants.values()])


def _find_gateway(client: Any, name: str, gateway_info: Any, log: Any) -> Any:
    wanted = (name or "").strip()
    if gateway_info is not None and (not wanted or gateway_info.name.lower() == wanted.lower()):
        return gateway_info
    if not wanted:
        raise PlanError("No gateway was chosen", code="plan.no_gateway",
                        why="The plan changes the policy of one gateway.",
                        fix=["Pick a gateway: --gateway <name> (aiguard setup lists them)"],
                        state="Nothing was changed.")
    gws = _gateways.discover(client, log=log)
    match = [g for g in gws if g.name == wanted] or [g for g in gws if g.name.lower() == wanted.lower()]
    if not match:
        names = ", ".join(g.name for g in gws) or "none"
        raise PlanError("Gateway '%s' was not found" % wanted, code="plan.gateway_not_found",
                        why="The management server (this domain) lists these gateways and "
                            "clusters: %s." % names,
                        fix=["Pick one of: %s" % names,
                             "On a Multi-Domain Server, check that you are connected to the "
                             "domain that manages the gateway"],
                        state="Nothing was changed.")
    return match[0]


def _check_gateway_version(gw: Any, tpl: dict, warnings: List[str]) -> None:
    need_text = tpl.get("min_gateway_version")
    if not need_text:
        return
    need = _gateways.version_tuple(need_text)
    have = gw.version_tuple() if hasattr(gw, "version_tuple") else _gateways.version_tuple(gw.version)
    if need is None:
        return
    if have is None:
        warnings.append("The software version of %s is unknown; this change needs %s on the "
                        "gateway." % (gw.name, need_text))
        return
    if have < need:
        shown = getattr(gw, "release", None) or gw.version
        raise PlanError(
            "%s runs %s; this change needs %s on the gateway" % (gw.name, shown, need_text),
            code="plan.gateway_version",
            why="AI Agent Security runs on %s gateways and later; installing the policy on an "
                "older gateway fails." % need_text,
            fix=["Upgrade %s to %s (SmartConsole > Gateways & Servers shows the version)"
                 % (gw.name, need_text), "Or pick a %s gateway" % need_text],
            state="Nothing was changed.")


def _probe(client: Any, probe: Dict[str, Any], warnings: Optional[List[str]] = None) -> Optional[dict]:
    """Read-only existence check: the object, or ``None`` when absent."""
    command = probe["command"]
    if not client.has(command):
        if warnings is not None:
            warnings.append("This management server has no %s command, so aiguard could not "
                            "check whether the object already exists." % command)
        return None
    try:
        reply = client.call(command, probe.get("payload") or {})
    except MgmtApiError as exc:
        if exc.api_code == _NOT_FOUND:
            return None
        if exc.api_code == _COMMAND_NOT_FOUND:
            if warnings is not None:
                warnings.append("%s is not available on this server; existence not checked."
                                % command)
            return None
        raise
    return reply if isinstance(reply, dict) else None


def _resolve_package(client: Any, options: PlanOptions, gw: Any,
                     warnings: List[str]) -> Tuple[str, dict]:
    name = (options.package or "").strip() or None
    if name and gw.policy_package and gw.policy_package.lower() != name.lower():
        warnings.append("%s has policy package %s installed; this plan changes and installs %s."
                        % (gw.name, gw.policy_package, name))
    if not name and gw.policy_package:
        name = gw.policy_package
    if not name:
        pkgs = client.show_all("show-packages", {"details-level": "standard"}, key="packages")
        names = [str(p.get("name")) for p in pkgs if isinstance(p, dict) and p.get("name")]
        if len(names) == 1:
            name = names[0]
        else:
            shown = ", ".join(names) or "none"
            raise PlanError(
                "Cannot tell which policy package to change for %s" % gw.name,
                code="plan.package_unknown",
                why="The gateway reports no installed policy and the management server has %d "
                    "packages (%s)." % (len(names), shown),
                fix=["Choose the package: --package <name> (one of: %s)" % shown,
                     "Or install a policy on %s first (SmartConsole > Install Policy)" % gw.name],
                state="Nothing was changed.")
    try:
        pkg = client.call("show-package", {"name": name, "details-level": "full"})
    except MgmtApiError as exc:
        if exc.api_code != _NOT_FOUND:
            raise
        raise PlanError("Policy package '%s' was not found" % name, code="plan.package_not_found",
                        server_said=exc.server_said,
                        why="The management server has no policy package with that name in "
                            "this domain.",
                        fix=["Check the name in SmartConsole > Security Policies "
                             "(Manage policies and layers)", "Then pass --package <name>"],
                        state="Nothing was changed.") from None
    return str(pkg.get("name") or name), pkg


def _threat_layer(client: Any, pkg: dict, package: str) -> str:
    layers = pkg.get("threat-layers")
    if isinstance(layers, list) and layers:
        names = [n for n in (_ident(x) for x in layers) if n]
        for n in names:
            if n.endswith("Threat Prevention"):
                return n
        if names:
            return names[0]
    no_tp = PlanError(
        "Policy package %s has no Threat Prevention policy" % package,
        code="plan.no_threat_layer",
        why="AI Agent Security is enforced by a Threat Prevention rule, so the package needs a "
            "Threat Prevention layer.",
        fix=["SmartConsole > Security Policies > Manage policies and layers > %s > Edit: select "
             "Threat Prevention" % package, "Publish, then build the plan again"],
        state="Nothing was changed.")
    if pkg.get("threat-prevention") is False or isinstance(layers, list):
        raise no_tp
    # The reply did not list layers at all: look for "<package> Threat Prevention".
    found = client.show_all("show-threat-layers", {"details-level": "standard"}, key="threat-layers")
    names = [n for n in (_ident(x) for x in found) if n]
    preferred = "%s Threat Prevention" % package
    for n in names:
        if n.lower() == preferred.lower():
            return n
    if len(names) == 1:
        return names[0]
    raise no_tp


def _https_layer(pkg: dict, package: str) -> str:
    multi = pkg.get("https-inspection-layers")            # API v2 and later
    if isinstance(multi, dict):
        name = _ident(multi.get("outbound-https-layer"))
        if name:
            return name
    name = _ident(pkg.get("https-inspection-layer"))      # API v1.9.1 (R81.20)
    if name:
        return name
    raise PlanError(
        "Policy package %s has no HTTPS Inspection policy" % package,
        code="plan.no_https_layer",
        why="The inspect rule goes at the top of the package's outbound HTTPS Inspection layer.",
        fix=["SmartConsole > Security Policies > Manage policies and layers > %s > Edit: select "
             "HTTPS Inspection" % package, "Publish, then build the plan again"],
        state="Nothing was changed.")


def _check_outbound_certificate(client: Any, gw: Any, warnings: List[str]) -> None:
    command = "show-outbound-inspection-certificate"
    if not client.has(command):
        warnings.append("This management server has no %s command, so aiguard could not check "
                        "for an outbound inspection certificate." % command)
        return
    try:
        found = show_outbound_certificate(client)
    except MgmtApiError as exc:
        if exc.api_code != _NOT_FOUND:
            raise
        found = None
    if found is None:
        raise PlanError(
            "No outbound inspection certificate",
            code="plan.no_outbound_ca",
            why="HTTPS Inspection can be turned on only after an outbound CA certificate exists, "
                "and this management server has none.",
            fix=["SmartConsole > %s > HTTPS Inspection > Step 1: create or import the outbound CA"
                 % gw.name,
                 "Step 2: deploy that CA to the demo computers (aiguard trust-ca shows how)",
                 "Publish, then run aiguard fix https-inspection again"],
            state="Nothing was changed.",
            details={"action": [
                {"id": "https-inspection", "label": "Turn on HTTPS Inspection again (asks for "
                 "approval)", "cli": "aiguard fix https-inspection"},
                {"id": "outbound-ca", "label": "Trust the outbound CA for the demo traffic",
                 "cli": "aiguard trust-ca"}]}) from None


_SCOPE_PROBES = ("show-host", "show-network", "show-group", "show-address-range",
                 "show-group-with-exclusion", "show-security-zone", "show-dynamic-object")


def _scope_object(client: Any, name: str, warnings: List[str]) -> str:
    """Check that ``name`` is an existing network object (read-only)."""
    probed = 0
    for command in _SCOPE_PROBES:
        if not client.has(command):
            continue
        try:
            obj = client.call(command, {"name": name})
        except MgmtApiError as exc:
            if exc.api_code == _NOT_FOUND:
                probed += 1
                continue
            warnings.append("Could not confirm that an object named '%s' exists (%s: %s); the "
                            "rule will fail when applied if it does not." % (name, command, exc.what))
            return name
        return str(obj.get("name") or name) if isinstance(obj, dict) else name
    if probed == 0:
        warnings.append("Could not check that an object named '%s' exists." % name)
        return name
    raise PlanError(
        "No object named '%s' was found" % name, code="plan.scope_not_found",
        why="The rule's protected scope must be an existing host, network or group.",
        fix=["Check the name in SmartConsole > Objects (names are case-sensitive)",
             "Or use --scope client (only this computer) or --scope any"],
        state="Nothing was changed.")


def _host_with_ip(client: Any, ip: str, own_name: str, log: Any) -> Optional[str]:
    """Name of an existing host object (not the kit's own ``own_name``) whose address is
    ``ip``, or None. Read-only (``show-objects`` IP search). The server refuses a second
    host with the same address (a validation warning), so the plan reuses this one."""
    if not client.has("show-objects"):
        return None
    try:
        reply = client.call("show-objects", {"type": "host", "filter": ip, "ip-only": True,
                                             "details-level": "standard", "limit": 50})
    except MgmtApiError as exc:
        log.info("plan", "could not search for a host with this computer's address",
                 ip=ip, error=exc.what)
        return None
    found: List[str] = []
    for obj in (reply or {}).get("objects") or []:
        if not isinstance(obj, dict) or not obj.get("name"):
            continue
        if str(obj.get("type") or "host") != "host":
            continue
        addrs = [obj.get("ipv4-address"), obj.get("ipv6-address")]
        if any(addrs) and ip not in addrs:
            continue      # a range or network that contains the address, not a host for it
        if str(obj["name"]).lower() == own_name.lower():
            return None   # the kit's own host already exists: the normal update path
        found.append(str(obj["name"]))
    return sorted(found, key=str.lower)[0] if found else None


def _same_ip_warning(err: Any) -> bool:
    text = " ".join(str(x or "") for x in (getattr(err, "server_said", None),
                                           getattr(err, "what", None))).lower()
    return "same ip address" in text or "same ip" in text


def _clean_name(value: Any, what: str, flag: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 128 or any(ord(c) < 32 for c in text):
        raise PlanError("'%s' is not a valid %s" % (_short(text, 40), what),
                        code="plan.bad_option",
                        why="Names must be 1 to 128 printable characters.",
                        fix=["Choose another name: %s <name>" % flag],
                        state="Nothing was changed.")
    return text


def _clean_track(value: Any) -> str:
    text = str(value or "").strip()
    for t in THREAT_TRACKS:
        if t.lower() == text.lower():
            return t
    raise PlanError("Unknown track '%s'" % _short(text, 40), code="plan.bad_option",
                    why="Threat Prevention rules accept these tracks: %s." % ", ".join(THREAT_TRACKS),
                    fix=["Use one of: %s" % ", ".join(THREAT_TRACKS)],
                    state="Nothing was changed.")


def _option(options: PlanOptions, tpl_vars: Dict[str, Any], name: str) -> Any:
    """An option the user changed wins; otherwise the template's default; otherwise the
    option's default (so a lab can rename things in its template file)."""
    value = getattr(options, name)
    default = PlanOptions.__dataclass_fields__[name].default
    if value != default:
        return value
    if tpl_vars.get(name) not in (None, ""):
        return tpl_vars[name]
    return value


def _merge(base: dict, extra: dict) -> dict:
    """Deep merge (``extra`` wins) for nested payload fields."""
    out = dict(base)
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _api_at_least(client: Any, version: Any) -> Optional[bool]:
    have = getattr(client, "api_version", None)
    if not version:
        return True
    if not have:
        return None
    return api_version_tuple(have) >= api_version_tuple(version)


def _update_payload(payload: dict) -> dict:
    """For set-* commands: ``name`` stays the identifier; position-type fields go."""
    out = dict(payload)
    for key in ("position", "set-if-exists"):
        out.pop(key, None)
    return out


def _already_set(current: dict, payload: dict, _top: bool = True) -> bool:
    for key, value in payload.items():
        if _top and key in ("name", "uid", "layer"):
            continue
        if isinstance(value, dict):
            sub = current.get(key) if isinstance(current, dict) else None
            if not isinstance(sub, dict) or not _already_set(sub, value, False):
                return False
            continue
        if isinstance(value, list):
            return False
        if not isinstance(current, dict) or current.get(key) != value:
            return False
    return True


def _options_dict(options: PlanOptions) -> Dict[str, Any]:
    return {k: getattr(options, k) for k in PlanOptions.__dataclass_fields__}


# --------------------------------------------------------------------------- build


def build_plan(client: Any, options: PlanOptions, *, secrets: Optional[Dict[str, str]] = None,
               log: Any = None, gateway_info: Any = None, home: Any = None) -> Plan:
    """Build a plan. Makes read-only calls only (``show-*``).

    ``secrets``: ``{"lakera_api_key": "..."}`` when the template needs it.
    ``gateway_info``: the :class:`~aiguard.gateways.GatewayInfo` the caller already has
    (saves a discovery call); otherwise the gateway is looked up by ``options.gateway``.
    ``home``: aiguard home for lab template overrides (``<home>/templates``).
    """
    log = _log_of(client, log)
    t0 = time.monotonic()
    secrets = {str(k): str(v) for k, v in (secrets or {}).items() if v}
    for value in secrets.values():
        _redact.register_secret(value)
    tpl = load_template(options.template or "ai-agent-security", home=home)
    tpl_vars = dict(tpl.get("variables") or {})
    warnings: List[str] = []

    _check_api_version(client, tpl)
    variant = _detect_variant(client, tpl)
    gw = _find_gateway(client, options.gateway, gateway_info, log)
    _check_gateway_version(gw, tpl, warnings)
    if getattr(client, "read_only", False):
        warnings.append("This session is read-only: you can review the plan, but applying it "
                        "needs a read-write login.")
    for check in tpl.get("checks") or []:
        if check == "outbound_certificate":
            _check_outbound_certificate(client, gw, warnings)
        else:
            raise PlanError("Template '%s' asks for an unknown check '%s'" % (tpl["id"], check),
                            code="plan.template", state="Nothing was changed.")

    package, pkg = _resolve_package(client, options, gw, warnings)

    scope = (options.scope or "client").strip() or "client"
    scope_low = scope.lower()
    client_ip: Optional[str] = None
    if options.client_ip:
        try:
            client_ip = str(ipaddress.ip_address(str(options.client_ip).strip()))
        except ValueError:
            raise PlanError("'%s' is not an IP address" % _short(str(options.client_ip), 60),
                            code="plan.bad_option",
                            fix=["Give this computer's IPv4 address, or use --scope any"],
                            state="Nothing was changed.") from None
    flags = {
        "moderation": bool(options.moderation),
        "install": bool(options.install),
        "add_https_rule": bool(options.add_https_rule),
        "scope_is_client": scope_low == "client",
    }
    existing_host: Optional[str] = None
    if flags["scope_is_client"] and client_ip and any(
            s.get("command") == "add-host" and _when_ok(s.get("when"), flags)
            for s in tpl["steps"]):
        existing_host = _host_with_ip(client, client_ip, client_host_name(client_ip), log)
        if existing_host:
            # Another host object already has this address: the server would refuse a second
            # one, so the rule uses it (it is not created, changed or deleted by the kit).
            flags["scope_is_client"] = False
            warnings.append("Host object %s already has this computer's address %s: the rule "
                            "uses it as the protected scope (no new host object; rollback "
                            "leaves it alone)." % (existing_host, client_ip))

    ctx = _Context()
    for key, value in tpl_vars.items():
        ctx.set(str(key), value)
    ctx.set("profile_name", _clean_name(_option(options, tpl_vars, "profile_name"),
                                        "profile name", "--profile-name"))
    ctx.set("rule_name", _clean_name(_option(options, tpl_vars, "rule_name"),
                                     "rule name", "--rule-name"))
    ctx.set("track", _clean_track(_option(options, tpl_vars, "track")))
    ctx.set("gateway", gw.name)
    ctx.set("package", package)
    ctx.set("client_ip", client_ip)
    ctx.set("scope", scope)
    ctx.set("lakera_project_id", (options.lakera_project_id or "").strip() or None)
    targets = gw.script_targets()
    if gw.is_cluster and not gw.cluster_members:
        warnings.append("The members of cluster %s are unknown; gateway scripts are sent to the "
                        "cluster object." % gw.name)
    ctx.set("script_targets", targets)
    ctx.set("gateway_set_command", "set-simple-cluster" if gw.is_cluster else "set-simple-gateway")
    ctx.set("gateway_show_command", "show-simple-cluster" if gw.is_cluster else "show-simple-gateway")
    ctx.set("client_host_name", client_host_name(client_ip) if client_ip else None)

    def protected_scope() -> Optional[str]:
        if scope_low == "client" and existing_host:
            return existing_host
        if scope_low == "client":
            # None -> the renderer raises the friendly "IP address is unknown" error.
            return client_host_name(client_ip) if client_ip else None
        if scope_low == "any":
            return "Any"
        return _scope_object(client, scope, warnings)

    ctx.lazy("protected_scope", protected_scope)
    ctx.lazy("threat_layer", lambda: _threat_layer(client, pkg, package))
    ctx.lazy("https_layer", lambda: _https_layer(pkg, package))
    if variant is not None:
        vname, vdata = variant
        ctx.set("ai.variant", vname)
        for key, value in vdata.items():
            ctx.set("ai." + key, value)

    install_def = next((s for s in tpl["steps"] if s.get("kind") == "install"), None) or {}
    steps: List[PlanStep] = []
    for raw in tpl["steps"]:
        if not _when_ok(raw.get("when"), flags):
            continue
        steps.append(_build_step(client, raw, ctx, secrets, package, gw, warnings))

    used = []
    for s in steps:
        for k in s.secret_keys:
            if k not in used:
                used.append(k)
    plan = Plan(
        plan_id="", server=str(getattr(client, "server", "") or ""),
        domain=getattr(client, "domain", None), gateway=gw.name, package=package,
        threat_layer=ctx.peek("threat_layer"), steps=steps, warnings=warnings,
        created_at=_now(), template=tpl["id"], title=str(tpl.get("title") or tpl["id"]),
        https_layer=ctx.peek("https_layer"), protected_scope=ctx.peek("protected_scope"),
        client_host_name=ctx.peek("client_host_name") if flags["scope_is_client"] else None,
        field_variant=variant[0] if variant else None, is_cluster=bool(gw.is_cluster),
        install_access=bool(install_def.get("access", False)),
        install_threat_prevention=bool(install_def.get("threat_prevention", True)),
        options=_options_dict(options),
    )
    plan.plan_id = compute_plan_id(plan)
    plan._secrets = {k: secrets[k] for k in used}  # type: ignore[attr-defined]  # not a field
    log.info("plan", "plan %s ready" % plan.plan_id, template=plan.template, gateway=plan.gateway,
             package=plan.package, threat_layer=plan.threat_layer, https_layer=plan.https_layer,
             protected_scope=plan.protected_scope, variant=plan.field_variant,
             steps=["%s:%s" % (s.id, s.action) for s in steps], warnings=warnings,
             ms=int((time.monotonic() - t0) * 1000))
    log.debug("plan", "api calls", plan_id=plan.plan_id, calls=plan.api_calls())
    for w in warnings:
        log.warn("plan", w)
    return plan


def _build_step(client: Any, raw: dict, ctx: _Context, secrets: Dict[str, str], package: str,
                gw: Any, warnings: List[str]) -> PlanStep:
    sid = raw["id"]
    kind = raw["kind"]
    r = _Renderer(ctx, secrets, sid)
    describe = r.render(raw.get("describe") or "") if raw.get("describe") else ""

    if kind == "publish":
        return PlanStep(id=sid, kind=kind, command="publish", describe=describe or "Publish the session",
                        payload={}, display_payload={}, rollback=None, manual_steps=[],
                        action="publish")
    if kind == "install":
        payload = {"policy-package": package, "targets": [gw.name],
                   "access": bool(raw.get("access", False)),
                   "threat-prevention": bool(raw.get("threat_prevention", True))}
        parts = [p for p, on in (("Access Control", payload["access"]),
                                 ("Threat Prevention", payload["threat-prevention"])) if on]
        return PlanStep(id=sid, kind=kind, command="install-policy",
                        describe=describe or "Install %s (%s) on %s" % (package, " + ".join(parts),
                                                                       gw.name),
                        payload=payload, display_payload=copy.deepcopy(payload), rollback=None,
                        manual_steps=[], action="install")
    manual = [str(x) for x in r.render(raw.get("manual_steps") or [])]
    if kind == "manual":
        return PlanStep(id=sid, kind=kind, command=None, describe=describe, payload={},
                        display_payload={}, rollback=None, manual_steps=manual, action="manual")

    command = r.render(raw["command"])
    payload = r.render(raw.get("payload") or {}, display=False)
    display = r.render(raw.get("payload") or {}, display=True)
    for version, extra in sorted((raw.get("api_payload") or {}).items(),
                                 key=lambda kv: api_version_tuple(kv[0])):
        if _api_at_least(client, version):      # fields only newer APIs accept
            payload = _merge(payload, r.render(extra, display=False))
            display = _merge(display, r.render(extra, display=True))
    secret_keys = list(r.used_secrets)

    rollback_def = None
    if raw.get("rollback"):
        rr = _Renderer(ctx, {}, sid + " rollback")
        rb = raw["rollback"]
        rollback_def = {
            "command": rr.render(rb["command"]),
            "payload": rr.render(rb.get("payload") or {}),
            "describe": rr.render(rb["describe"]) if rb.get("describe") else "Undo: " + (describe or sid),
            "manual_steps": [str(x) for x in rr.render(rb.get("manual_steps") or [])],
        }
    exists = None
    if raw.get("exists"):
        er = _Renderer(ctx, {}, sid + " exists")
        exists = {"command": er.render(raw["exists"]["command"]),
                  "payload": er.render(raw["exists"].get("payload") or {})}

    step = PlanStep(id=sid, kind=kind, command=command, describe=describe, payload=payload,
                    display_payload=display, rollback=rollback_def, manual_steps=manual,
                    action="add" if kind == "add" else ("script" if kind == "script" else "update"),
                    exists=exists, secret_keys=secret_keys)

    if not client.has(command):
        step.action = "manual"
        if not step.manual_steps:
            step.manual_steps = ["This management server has no '%s' command. Do this step in "
                                 "SmartConsole: %s" % (command, describe or sid)]
        warnings.append("Step '%s' must be done by hand: this management server has no %s "
                        "command." % (sid, command))
        return step
    need = raw.get("min_api_version")
    if need and _api_at_least(client, need) is False:
        # e.g. HTTPS rules by name exist from API 2 (v1.9.1 identifies them by uid or number)
        step.action = "manual"
        step.exists = None
        if not step.manual_steps:
            step.manual_steps = ["Do this step in SmartConsole: %s" % (describe or sid)]
        have = getattr(client, "api_version", None)
        warnings.append("Step '%s' must be done by hand: it needs Management API %s%s and this "
                        "server has API %s%s." % (
                            sid, need, " (%s)" % release_for_api(need) if release_for_api(need)
                            else "", have, " (%s)" % release_for_api(have)
                            if release_for_api(have) else ""))
        return step
    if kind == "script":
        return step

    current = _probe(client, exists, warnings) if exists else None
    if kind == "add":
        if current is None:
            return step
        name = str(payload.get("name") or (exists or {}).get("payload", {}).get("name") or sid)
        if not _is_ours(current):
            fix = [str(x) for x in r.render(raw.get("conflict_fix") or [])] or [
                "Pick another name with --profile-name / --rule-name"]
            raise PlanError(
                "An object named %s already exists" % name, code="plan.name_conflict",
                why="'%s' already exists on the management server and was not created by AI Guard "
                    "Demo Kit (its comments do not say so), so aiguard will not change it." % name,
                fix=fix, state="Nothing was changed.",
                details={"step": sid, "command": (exists or {}).get("command"),
                         "uid": current.get("uid"), "type": current.get("type")})
        step.existing_uid = str(current.get("uid")) if current.get("uid") else None
        update = r.render(raw["update_command"]) if raw.get("update_command") else None
        if update and client.has(update):
            step.command = update
            step.action = "update"
            step.payload = _update_payload(step.payload)
            step.display_payload = _update_payload(step.display_payload)
        else:
            step.action = "none"
            step.message = "Already exists (created by AI Guard Demo Kit); kept as it is"
        return step
    # kind == "set"
    if exists and current is None:
        target = str(payload.get("name") or sid)
        raise PlanError("'%s' was not found" % target, code="plan.object_not_found",
                        why="Step '%s' changes an existing object, and the management server "
                            "has none with that name." % sid,
                        fix=["Check the name in SmartConsole"], state="Nothing was changed.")
    if current is not None and not secret_keys and _already_set(current, payload):
        step.action = "none"
        step.message = "Already in place"
    return step


# --------------------------------------------------------------------------- apply


def _call_and_wait(client: Any, command: str, payload: dict, *, what: str,
                   on_progress: Optional[Callable[[int, str, str], None]] = None) -> Tuple[dict, Optional[dict]]:
    resp = client.call(command, payload)
    tids = _task_ids(resp)
    task = None
    if tids:
        try:
            task = client.wait_task(tids[0] if len(tids) == 1 else tids, what=what,
                                    progress_cb=on_progress, command=command)
        except AiguardError as exc:
            # The server accepted the command and runs it on its own: unless the task ended
            # as failed, its outcome is unknown to this client.
            exc.details.setdefault("task_id", tids[0])
            exc.details["task_submitted"] = True
            raise
    return (resp if isinstance(resp, dict) else {}), task


def _outcome_unknown(exc: BaseException) -> bool:
    """True when a command the server accepted may still have completed: a lost
    connection, a timeout or another error while waiting for its task. False when the
    task itself ended as failed, or the server refused the command."""
    if not isinstance(exc, AiguardError):
        return True
    if getattr(exc, "code", None) == "mgmt.task_failed":
        return False
    details = getattr(exc, "details", None) or {}
    submitted = bool(details.get("publish_submitted") or details.get("task_submitted")
                     or details.get("install_submitted"))
    if isinstance(exc, ConnectError):
        # refused / unknown name / no route: the request never reached the server
        return submitted or exc.code not in ("connect.refused", "connect.dns",
                                             "connect.unreachable")
    if getattr(exc, "code", None) == "mgmt.task_timeout":
        return True
    return submitted


def _undo_entry(plan: Plan, step: PlanStep) -> Optional[dict]:
    if not step.rollback:
        return None
    payload = step.payload if step.payload else step.display_payload
    entry = {
        "step": step.id, "kind": step.kind, "action": step.action, "command": step.command,
        "name": payload.get("name") if isinstance(payload, dict) else None,
        "uid": step.result_uid or step.existing_uid,
        "describe": step.rollback.get("describe") or ("Undo " + step.id),
        "rollback": {"command": step.rollback["command"],
                     "payload": copy.deepcopy(step.rollback.get("payload") or {})},
        "probe": copy.deepcopy(step.exists) if step.exists else None,
        "manual_steps": list(step.rollback.get("manual_steps") or []),
    }
    return entry


def _wants_undo(step: PlanStep) -> bool:
    if step.status == "done" and step.action in ("add", "update", "script"):
        return True
    # An object of ours that existed and was kept as it is: rollback still removes it.
    return step.kind == "add" and step.action == "none"


def _point(plan: Plan, objects: List[dict]) -> dict:
    return {
        "kind": "plan", "template": plan.template, "plan_id": plan.plan_id,
        "summary": "%s on %s" % (plan.title or plan.template, plan.gateway),
        "server": plan.server, "domain": plan.domain, "gateway": plan.gateway,
        "package": plan.package, "threat_layer": plan.threat_layer, "https_layer": plan.https_layer,
        "install": {"access": bool(plan.install_access),
                    "threat_prevention": bool(plan.install_threat_prevention)},
        "objects": objects,
    }


def _notify_point(cb: Optional[Callable[[str], None]], rid: Optional[str], log: Any) -> None:
    if cb is None or not rid:
        return
    try:
        cb(rid)
    except Exception as exc:  # noqa: BLE001 - a caller's hook must not break the apply
        try:
            log.debug("plan", "rollback point callback failed", error=repr(exc))
        except Exception:  # noqa: BLE001
            pass


def _state_or_default(state: Any) -> Any:
    if state is not None:
        return state
    from .state import State
    return State()


def apply_plan(client: Any, plan: Plan, *, approved_plan_id: str,
               secrets: Optional[Dict[str, str]] = None, progress_cb: Optional[ProgressCb] = None,
               log: Any = None, state: Any = None,
               on_rollback_point: Optional[Callable[[str], None]] = None,
               should_stop: Optional[Callable[[], bool]] = None) -> ApplyResult:
    """Apply an approved plan. ``approved_plan_id`` must equal ``plan.plan_id`` (and the
    plan must not have changed since its id was computed), else :class:`ApprovalError`.

    Order: object changes -> rollback point saved -> publish -> install -> scripts.
    ``progress_cb(step_id, status, pct, message)``; status is ``running`` / ``done`` /
    ``failed`` / ``skipped`` / ``manual``. Failures are returned in ``ApplyResult.error``
    (never raised), except approval problems. A gateway script that did not run (no
    permission, failed, result unknown) after a successful install leaves ``ok`` True and
    is reported in ``ApplyResult.notices`` (five-field dicts) and ``warnings``.

    ``on_rollback_point(rid)`` is called as soon as the rollback point is saved (before
    publish), so a caller can mark it when the run is cut short. ``should_stop()`` is
    asked before every change and before publish: True stops the run there (the session
    is discarded, nothing is published; ``plan.stopped``), e.g. because the session was
    discarded from another thread at shutdown.
    """
    log = _log_of(client, log)
    state = _state_or_default(state)
    approved = str(approved_plan_id or "").strip().lower()
    if approved != plan.plan_id:
        err = ApprovalError(
            "The approved plan id does not match this plan",
            why="Plan %s is ready, but approval was given for %s." % (plan.plan_id, approved or "(none)"),
            fix=["Review the plan again and approve plan %s" % plan.plan_id],
            state="Nothing was changed.",
            details={"plan_id": plan.plan_id, "approved": approved})
        _log_err(log, err)
        raise err
    actual = compute_plan_id(plan)
    if actual != plan.plan_id:
        err = ApprovalError(
            "The plan changed after it was approved",
            why="Its content no longer matches plan %s." % plan.plan_id,
            fix=["Build the plan again, review it and approve the new plan id"],
            state="Nothing was changed.", details={"plan_id": plan.plan_id, "now": actual})
        _log_err(log, err)
        raise err
    if getattr(plan, "_published", False):
        err = PlanError("Plan %s was already applied" % plan.plan_id, code="plan.already_applied",
                        fix=["Build a new plan (it will update the existing objects) and approve it"],
                        state="Nothing was changed by this attempt.")
        _log_err(log, err)
        raise err

    for value in list((getattr(plan, "_secrets", None) or {}).values()) + \
            [v for v in (secrets or {}).values() if v]:
        _redact.register_secret(value)
    for s in plan.steps:
        s.status, s.message, s.ms, s.result_uid = "pending", (s.message if s.action == "none" else ""), 0, None

    result = ApplyResult(ok=False, plan_id=plan.plan_id, rollback_id=None, steps=plan.steps,
                         error=None, published=False, installed=False)
    log.info("plan", "applying plan %s" % plan.plan_id, gateway=plan.gateway, package=plan.package,
             steps=["%s:%s" % (s.id, s.action) for s in plan.steps])

    if getattr(client, "read_only", False):
        err = PlanError("This session is read-only", code="plan.read_only",
                        why="The plan can be reviewed in a read-only session, but not applied.",
                        fix=_read_only_fix(client), state="Nothing was changed.")
        _log_err(log, err)
        result.error = err
        result.message = err.state or ""
        return result

    pre = [s for s in plan.steps if s.kind in ("add", "set", "manual")]
    publish_step = plan.step("publish") or next((s for s in plan.steps if s.kind == "publish"), None)
    install_step = next((s for s in plan.steps if s.kind == "install"), None)
    scripts = [s for s in plan.steps if s.kind == "script"]

    rid: Optional[str] = None
    objects: List[dict] = []
    changed: List[PlanStep] = []
    current: Optional[PlanStep] = None

    def stop_here(before: str) -> None:
        try:
            stop = bool(should_stop()) if should_stop is not None else False
        except Exception:  # noqa: BLE001 - a broken probe does not stop an approved run
            stop = False
        if stop:
            raise PlanError(
                "The apply was stopped before %s" % before, code="plan.stopped",
                why="The demo session was discarded or closed while the plan was being "
                    "applied (for example, the web console was shutting down).",
                fix=["Build the plan again, review it and approve it"])

    try:
        for step in pre:
            current = None
            stop_here(step.command or step.id)
            current = step
            _apply_change(client, step, progress_cb, log)
            if step.status == "done":
                changed.append(step)
        current = None
        for step in pre:
            if _wants_undo(step):
                entry = _undo_entry(plan, step)
                if entry:
                    objects.append(entry)
        if objects:
            try:
                rid = state.add_rollback(_point(plan, objects))
            except (ValueError, TypeError, OSError) as exc:
                raise PlanError("Could not save the rollback point", code="plan.state",
                                why="aiguard saves how to undo the change before publishing it, "
                                    "and saving failed: %s" % exc,
                                fix=["Check that the aiguard home folder is writable (%s)"
                                     % getattr(state, "path", "state.json"),
                                     "Then apply the plan again"]) from None
            result.rollback_id = rid
            log.info("plan", "rollback point %s saved" % rid, objects=len(objects))
            _notify_point(on_rollback_point, rid, log)
        if publish_step is not None:
            if changed:
                stop_here("publish")
            current = publish_step
            if changed:
                _emit(progress_cb, log, publish_step.id, "running", 0, "Publishing")
                t0 = time.monotonic()
                publish_step.status = "running"
                pub = client.publish(progress_cb=lambda pct, st, msg: _emit(
                    progress_cb, log, publish_step.id, "running", pct, msg or st))
                publish_step.ms = int((time.monotonic() - t0) * 1000)
                publish_step.status = "done"
                publish_step.message = "Published %d change%s" % (len(changed), "" if len(changed) == 1 else "s")
                pub_warnings = pub.get("warnings") if isinstance(pub, dict) else None
                for w in pub_warnings or []:
                    result.warnings.append("Publish warning: %s" % w)
                plan._published = True  # type: ignore[attr-defined]
                result.published = True
            else:
                publish_step.status = "skipped"
                publish_step.message = "Nothing to publish"
            _emit(progress_cb, log, publish_step.id, publish_step.status, 100, publish_step.message)
            current = None
    except BaseException as exc:  # noqa: BLE001 - discard on any failure before publish
        # A publish the server accepted but whose task did not end as failed (lost connection,
        # timeout, an error while polling) may still complete on the server: keep the rollback
        # point usable instead of calling it discarded.
        uncertain = current is publish_step and publish_step is not None and _outcome_unknown(exc)
        discarded = client.discard() is not False
        if rid and not uncertain:
            _mark(state, log, rid, status="discarded", note="Publish did not complete; the "
                  "session was discarded")
            result.rollback_id = None
        elif rid:
            _mark(state, log, rid, status="publish-unknown",
                  note="Publish result unknown (connection, timeout or task polling error)")
        if not isinstance(exc, Exception):
            raise
        if not isinstance(exc, AiguardError):
            _log_err(log, exc)  # type and traceback
        err = exc if isinstance(exc, AiguardError) else AiguardError(
            "Unexpected error while applying the plan", code="aiguard.internal",
            why="%s: %s" % (type(exc).__name__, exc),
            fix=["Send the log file to the demo owner"])
        if uncertain and rid:
            err.state = ("The publish may or may not have completed. aiguard discarded what was "
                         "still unpublished. Check SmartConsole (Manage & Settings > Sessions); "
                         "if the changes were published, undo them with: aiguard rollback %s" % rid)
            err.details["action"] = {"id": "rollback", "rollback_id": rid,
                                     "cli": "aiguard rollback %s" % rid}
        elif changed and not discarded:
            # The session is gone (expired, logged out): its changes could not be discarded
            # and stay in it, locked, until someone discards that session.
            err.state = ("Nothing was published. aiguard could not discard this session's "
                         "unpublished changes (%s) because the management session ended: "
                         "SmartConsole > Manage & Settings > Sessions > View Sessions: discard "
                         "the session %s." % (", ".join(s.id for s in changed),
                                              getattr(client, "_session_opts", {}).get(
                                                  "session_name") or "aiguard-demo"))
        else:
            err.state = ("Nothing was changed. aiguard discarded this session's unpublished "
                         "changes (%s)." % ", ".join(s.id for s in changed) if changed else
                         "Nothing was changed.")
            if changed:
                err.fix = _after_discard_fix(err.fix, "apply the plan again")
        if (current is not None and current.command == "add-host"
                and getattr(err, "code", None) == "mgmt.validation" and _same_ip_warning(err)):
            err.fix = ["Another host object already has this IP address: use it as the rule's "
                       "protected scope (CLI: --scope <its name>; web console: Configure > "
                       "Protected scope), then build the plan again"] + list(err.fix)
        if current is not None:
            current.status = "failed"
            current.message = err.what
            _emit(progress_cb, log, current.id, "failed", None, err.what)
        _skip_rest(plan.steps, progress_cb, log, "Not run: an earlier step failed")
        _log_err(log, err)
        result.error = err
        result.message = err.state
        return result

    if rid:
        _mark(state, log, rid, status="published" if result.published else "recorded",
              published_at=_now() if result.published else None)
    n = len(changed)
    undo = (" Undo: aiguard rollback %s" % rid) if rid else ""

    if install_step is not None:
        ok, task = _apply_install(client, plan, install_step, progress_cb, log)
        for w in (task or {}).get("warnings") or []:
            result.warnings.append("Install warning: %s" % w)
        if isinstance(ok, AiguardError):
            err = ok
            status, text = _install_outcome(client, plan.gateway, install_step, err, log,
                                            access_carries_https=plan.template == "https-inspection")
            result.install_status = status
            if result.published:
                err.state = "Published %d object%s. %s%s" % (n, "" if n == 1 else "s", text, undo)
            else:
                err.state = "Nothing was published by this run. %s" % text
            _not_ours_fix(err, plan, rid)
            if rid:
                if not any("aiguard rollback %s" % rid in f for f in err.fix):
                    err.fix = list(err.fix) + ["To undo the published changes: aiguard rollback %s"
                                               % rid]
                err.details["action"] = {"id": "rollback", "rollback_id": rid,
                                         "cli": "aiguard rollback %s" % rid}
                _mark(state, log, rid, install_error=_short(err.what, 200),
                      install_status=status or None)
            _skip_rest(plan.steps, progress_cb, log, "Not run: install failed")
            _log_err(log, err)
            result.error = err
            result.message = err.state
            return result
        result.installed = True
        result.install_status = {k: "installed" for k, on in (
            ("access", install_step.payload.get("access")),
            ("threat_prevention", install_step.payload.get("threat-prevention", True))) if on}
        if rid:
            _mark(state, log, rid, status="installed", installed_at=_now())

    for step in scripts:
        if step.action == "manual":
            step.status = "manual"
            step.message = "You do this (see the steps)"
            _emit(progress_cb, log, step.id, "manual", None, step.message)
            if step.id == "moderation":
                result.moderation_enabled = False
            continue
        # Record how to undo the script before it runs (the gateway changes at once and
        # cannot be discarded): an interrupted or uncertain run can still be rolled back.
        entry = _undo_entry(plan, step)
        if entry:
            entry["pending"] = True
            objects.append(entry)
            try:
                if rid:
                    _mark(state, log, rid, objects=objects)
                else:
                    rid = state.add_rollback(_point(plan, objects))
                    result.rollback_id = rid
                    undo = " Undo: aiguard rollback %s" % rid
                    _notify_point(on_rollback_point, rid, log)
            except (ValueError, TypeError, OSError) as exc:
                result.warnings.append("Could not record how to undo step %s: %s" % (step.id, exc))
        err2 = _apply_script(client, step, progress_cb, log)
        unknown = err2 is not None and _outcome_unknown(err2) and not _is_permission_error(err2)
        if entry:
            if err2 is None or unknown:
                entry.pop("pending", None)
                if unknown:
                    entry["uncertain"] = True
            else:
                objects.remove(entry)   # the script definitely did not run
            if rid and not objects:
                # The point held only this script: nothing is left to undo.
                _mark(state, log, rid, objects=objects, status="discarded",
                      note="The gateway script did not run; nothing to undo")
                rid = None
                result.rollback_id = None
                undo = ""
            elif rid:
                _mark(state, log, rid, objects=objects, scripts_applied=True if err2 is None else None)
        if err2 is None:
            if step.id == "moderation":
                result.moderation_enabled = True
            continue
        if step.id == "moderation":
            result.moderation_enabled = None if unknown else False
        _manual_if_denied(step, err2, progress_cb, log)
        err = _script_error(plan, step, err2, rid, installed=result.installed, unknown=unknown)
        _log_err(log, err)
        # A gateway setting the user finishes by hand (or that may already be on) does not
        # undo the published and installed policy: report it as a warning with its fix.
        result.notices.append(err.to_dict())
        result.warnings.append("%s. %s%s" % (err.what.rstrip("."), (err.why or "").strip(),
                                             (" Fix: " + "; ".join(err.fix)) if err.fix else ""))

    for s in plan.steps:
        if s.action == "manual" and s.status == "pending":
            s.status = "manual"
    manual = [s.id for s in plan.steps if s.status == "manual"]
    if manual:
        result.warnings.append("Do these steps by hand: %s" % ", ".join(manual))
    result.warnings.extend(plan.warnings)
    if result.error is None:
        result.ok = True
        bits = []
        if result.published:
            bits.append("Published %d change%s" % (n, "" if n == 1 else "s"))
        else:
            bits.append("Nothing needed publishing")
        if result.installed:
            bits.append("installed the policy on %s" % plan.gateway)
        elif install_step is None and result.published:
            bits.append("did not install the policy (install was turned off; install it in "
                        "SmartConsole when ready)")
        result.message = " and ".join(bits) + "." + undo
        if result.notices:
            result.message += " Still to do: %s." % "; ".join(
                str(nt.get("what") or "") for nt in result.notices)
    else:
        result.message = result.error.state or ""
    log.info("plan", "plan %s %s" % (plan.plan_id, "applied" if result.ok else "applied with errors"),
             rollback_id=rid, published=result.published, installed=result.installed,
             steps=["%s:%s" % (s.id, s.status) for s in plan.steps])
    return result


def _after_discard_fix(fix: Iterable[str], again: str) -> List[str]:
    """Fix steps after aiguard discarded the session: steps that speak of the still-open
    session ("publish again", "View Sessions shows this session") no longer apply."""
    out = [f for f in fix if not re.search(r"(?i)publish again|shows this session|discard the "
                                            r"session", f)]
    out.append("Then %s: aiguard discarded this session's unpublished changes, so nothing is "
               "left to publish" % again)
    return out


_PART_LABEL = {"access": "Access Control", "threat_prevention": "Threat Prevention"}


def _install_outcome(client: Any, gateway: str, step: PlanStep, err: AiguardError, log: Any, *,
                     access_carries_https: bool = False) -> Tuple[Dict[str, str], str]:
    """Per policy type, what a failed / uncertain install left on the gateway, and the
    sentence that says so. The gateway's installation dates (``show-gateways-and-servers``)
    are compared with the task's start time; when they cannot be read the status is
    ``unknown``."""
    parts = [k for k, on in (("access", step.payload.get("access")),
                             ("threat_prevention", step.payload.get("threat-prevention", True)))
             if on]
    details = getattr(err, "details", None) or {}
    start = details.get("start_posix")
    code = getattr(err, "code", None)
    status: Dict[str, str] = {k: "unknown" for k in parts}
    facts: Dict[str, Any] = {}
    if code == "mgmt.task_failed" and getattr(client, "logged_in", True):
        try:
            pol = _gateways.policy_state(client, gateway, log=log)
        except AiguardError as exc:
            pol = None
            log.info("plan", "could not re-read the installed policy", gateway=gateway,
                     error=exc.what)
        if pol is not None:
            facts = _gateways.policy_facts(pol)
            for k in parts:
                at = facts.get("%s_policy_installed_at" % ("threat" if k == "threat_prevention"
                                                            else "access"))
                if at is not None and start is not None:
                    status[k] = "installed" if at >= start else "not installed"
    access_note = " (which carries the HTTPS Inspection settings)" if access_carries_https else ""

    def previous(k: str) -> str:
        kind = "threat" if k == "threat_prevention" else "access"
        date = facts.get("%s_policy_installation_date" % kind)
        return "its previous %s policy%s%s" % (_PART_LABEL[k], access_note if k == "access" else "",
                                               " (installed %s)" % date if date else "")

    if code == "mgmt.task_timeout":
        text = ("The install on %s was still running when aiguard stopped waiting: it may still "
                "finish. Check SmartConsole > Tasks (bottom left) and the Install Policy details."
                % gateway)
    elif _outcome_unknown(err) and code != "mgmt.task_failed":
        text = ("The connection was lost while the policy was being installed on %s: it may or "
                "may not have been installed. Check SmartConsole > Tasks (bottom left)." % gateway)
    elif code == "mgmt.task_failed":
        done = [k for k in parts if status[k] == "installed"]
        missing = [k for k in parts if status[k] == "not installed"]
        if done and missing:
            text = ("%s was installed on %s; %s was NOT installed: the gateway keeps enforcing %s "
                    "until an install succeeds. %s." % (
                        " and ".join(_PART_LABEL[k] for k in done), gateway,
                        " and ".join(_PART_LABEL[k] for k in missing),
                        " and ".join(previous(k) for k in missing), _INSTALL_DETAILS_HINT))
        elif missing and not done:
            text = ("Nothing was installed on %s: the gateway keeps enforcing %s until an install "
                    "succeeds." % (gateway, " and ".join(previous(k) for k in missing)))
        elif done and not missing and len(done) == len(parts):
            text = ("The install task on %s reported a failure, but the gateway shows the policy "
                    "as installed; check the Install Policy details in SmartConsole." % gateway)
        elif str(details.get("status") or "") == "partially succeeded":
            text = ("Part of the policy may be installed on %s (the task partially succeeded): "
                    "the gateway may still enforce its previous policy for the part that failed. "
                    "%s." % (gateway, _INSTALL_DETAILS_HINT))
        else:
            text = ("The policy was not installed on %s: the gateway keeps enforcing its previous "
                    "policy until an install succeeds." % gateway)
    else:
        text = "The policy was not installed on %s." % gateway
    return status, text


def _not_ours_fix(err: AiguardError, plan: Plan, rid: Optional[str]) -> None:
    """When install verification names a rule the kit did not create, say so: rolling the
    demo back would hit the same error."""
    rule = failing_rule(err.server_said)
    if not rule:
        return
    ours = {str(s.payload.get("name") or "").lower() for s in plan.steps
            if s.command in ("add-threat-rule", "set-threat-rule", "add-https-rule", "set-https-rule")
            and isinstance(s.payload, dict)}
    if rule["name"] and rule["name"].lower() in ours:
        return
    what = "rule %s%s in layer %s" % (rule["number"], " (%s)" % rule["name"] if rule["name"] else "",
                                      rule["layer"])
    err.fix = ["The failing %s was not created by AI Guard Demo Kit: it is an existing rule in "
               "that layer. Fix it in SmartConsole > Security Policies, publish, then install "
               "again" % what] + [f for f in err.fix]
    if rid:
        err.fix.append("Rolling back the demo (aiguard rollback %s) removes the demo objects but "
                       "does not fix %s" % (rid, what))


def _skip_rest(steps: Iterable[PlanStep], cb: Optional[ProgressCb], log: Any, why: str) -> None:
    for s in steps:
        if s.status == "pending":
            s.status = "skipped"
            s.message = why
            _emit(cb, log, s.id, "skipped", None, why)


def _mark(state: Any, log: Any, rid: str, **kw: Any) -> None:
    try:
        state.mark_rollback(rid, **{k: v for k, v in kw.items() if v is not None})
    except (ValueError, TypeError, OSError) as exc:
        log.warn("plan", "could not update rollback point %s" % rid, error=str(exc))


def _apply_change(client: Any, step: PlanStep, cb: Optional[ProgressCb], log: Any) -> None:
    if step.action == "manual":
        step.status = "manual"
        step.message = "You do this (see the steps)"
        _emit(cb, log, step.id, "manual", None, step.message)
        return
    if step.action == "none":
        step.status = "skipped"
        step.message = step.message or "Already in place"
        _emit(cb, log, step.id, "skipped", None, step.message)
        return
    t0 = time.monotonic()
    step.status = "running"
    _emit(cb, log, step.id, "running", None, step.describe)
    name = step.payload.get("name") if isinstance(step.payload, dict) else None
    what = "%s %s" % (step.command, name) if name else str(step.command)
    resp, _task = _call_and_wait(client, str(step.command), step.payload, what=what,
                                 on_progress=lambda pct, st, msg: _emit(cb, log, step.id, "running",
                                                                        pct, msg or st))
    uid = resp.get("uid") if isinstance(resp.get("uid"), str) else None
    if not uid and step.action == "update":
        uid = step.existing_uid
    if not uid and step.exists:
        try:
            obj = _probe(client, step.exists)
            if obj and obj.get("uid"):
                uid = str(obj["uid"])
        except AiguardError as exc:
            log.warn("plan", "could not read the uid of %s" % step.id, error=exc.what)
    step.result_uid = uid
    step.ms = int((time.monotonic() - t0) * 1000)
    step.status = "done"
    step.message = "Created" if step.action == "add" else "Updated"
    log.info("plan", "step %s done" % step.id, command=step.command, uid=uid, ms=step.ms)
    _emit(cb, log, step.id, "done", 100, step.message)


def _apply_install(client: Any, plan: Plan, step: PlanStep, cb: Optional[ProgressCb],
                   log: Any) -> Tuple[Optional[AiguardError], Optional[dict]]:
    """Install; returns (error or None, the finished task dict or None)."""
    t0 = time.monotonic()
    step.status = "running"
    _emit(cb, log, step.id, "running", 0, step.describe)
    try:
        task = client.install_policy(plan.package, list(step.payload.get("targets") or [plan.gateway]),
                                     access=bool(step.payload.get("access")),
                                     threat_prevention=bool(step.payload.get("threat-prevention", True)),
                                     progress_cb=lambda pct, st, msg: _emit(cb, log, step.id, "running",
                                                                            pct, msg or st))
    except AiguardError as exc:
        step.status = "failed"
        step.message = exc.what
        step.ms = int((time.monotonic() - t0) * 1000)
        _emit(cb, log, step.id, "failed", None, exc.what)
        return exc, None
    step.ms = int((time.monotonic() - t0) * 1000)
    step.status = "done"
    step.message = "Installed on %s" % ", ".join(step.payload.get("targets") or [plan.gateway])
    warns = (task or {}).get("warnings") if isinstance(task, dict) else None
    if warns:
        step.message += " (with %d warning%s)" % (len(warns), "" if len(warns) == 1 else "s")
    _emit(cb, log, step.id, "done", 100, step.message)
    return None, (task if isinstance(task, dict) else None)


def _apply_script(client: Any, step: PlanStep, cb: Optional[ProgressCb], log: Any) -> Optional[AiguardError]:
    t0 = time.monotonic()
    step.status = "running"
    _emit(cb, log, step.id, "running", None, step.describe)
    targets = step.payload.get("targets")
    what = "%s on %s" % (step.payload.get("script-name") or "script",
                         ", ".join(targets) if isinstance(targets, list) else targets)
    try:
        _resp, task = _call_and_wait(client, str(step.command), step.payload, what=what,
                                     on_progress=lambda pct, st, msg: _emit(cb, log, step.id,
                                                                            "running", pct, msg or st))
    except AiguardError as exc:
        step.status = "failed"
        step.message = exc.what
        step.ms = int((time.monotonic() - t0) * 1000)
        _emit(cb, log, step.id, "failed", None, exc.what)
        return exc
    step.ms = int((time.monotonic() - t0) * 1000)
    step.status = "done"
    out = "; ".join((task or {}).get("messages") or [])[:300]
    step.message = "Done" + (": " + out if out else "")
    log.info("plan", "script %s done" % step.id, targets=targets, output=out, ms=step.ms)
    _emit(cb, log, step.id, "done", 100, "Done")
    return None


def _manual_if_denied(step: PlanStep, exc: AiguardError, cb: Optional[ProgressCb], log: Any) -> None:
    """A script the administrator may not run is shown as "You do this", never as done."""
    if _is_permission_error(exc):
        step.status = "manual"
        step.message = ("You do this: this administrator may not run scripts on gateways "
                        "(Run One Time Script)")
        _emit(cb, log, step.id, "manual", None, step.message)


def _is_permission_error(exc: AiguardError) -> bool:
    if isinstance(exc, MgmtApiError) and (exc.api_code == "generic_err_permission_denied"
                                          or exc.code == "mgmt.permission_denied"):
        return True
    text = " ".join(str(x or "") for x in (exc.what, exc.server_said, exc.why)).lower()
    return "permission" in text or "not authorized" in text or "not allowed" in text


def _script_error(plan: Plan, step: PlanStep, exc: AiguardError, rid: Optional[str], *,
                  installed: bool, undoing: bool = False, unknown: bool = False) -> PlanError:
    perm = _is_permission_error(exc)
    moderation = step.id.endswith("moderation")
    if undoing:
        what = ("Content moderation is still on" if moderation
                else "Could not undo: %s" % (step.describe or step.id))
    elif unknown:
        what = ("Content moderation may or may not be on (the script result is unknown)"
                if moderation else "%s: result unknown" % (step.describe or step.id))
    else:
        what = ("Content moderation was not turned on" if moderation
                else "%s did not complete" % (step.describe or step.id))
    if perm:
        why = ("The administrator's permission profile does not allow running scripts on gateways "
               "(Run One Time Script), so the management server refused run-script.")
        fix = [_RUN_SCRIPT_PERMISSION, "Publish, then run this step again"]
    else:
        why = "The gateway script did not finish. " + (exc.why or "")
        fix = [f for f in exc.fix if f]
    if step.manual_steps:
        fix.append("Or do it by hand:")
        fix.extend(step.manual_steps)
    if undoing:
        state = "The other undo steps ran; only this gateway setting is left."
    elif unknown:
        state = ("Everything else was applied%s. The gateway script was sent but its result is "
                 "unknown; the rollback point includes turning it off again."
                 % (" and installed on %s" % plan.gateway if installed else ""))
        if rid:
            state += " Undo everything: aiguard rollback %s" % rid
    else:
        state = ("Everything else was applied%s; only this gateway setting is missing."
                 % (" and installed on %s" % plan.gateway if installed else ""))
        if rid:
            state += " Undo everything: aiguard rollback %s" % rid
    return PlanError(what.strip(), code="plan.script_permission" if perm else "plan.script_failed",
                     server_said=exc.server_said or exc.what, why=why.strip(), fix=fix, state=state,
                     details={"step": step.id, "cause_code": exc.code,
                              "api_code": getattr(exc, "api_code", None)})


# --------------------------------------------------------------------------- rollback


def rollback(client: Any, rollback_id: str, *, install: bool = True,
             progress_cb: Optional[ProgressCb] = None, log: Any = None,
             state: Any = None) -> ApplyResult:
    """Undo a rollback point: scripts (e.g. moderation off) and object changes in reverse
    order, publish, then install (Threat Prevention; plus Access Control when the plan
    installed it). Objects already gone are skipped with a note. On success the point is
    marked ``rolled-back``; running it again does nothing."""
    log = _log_of(client, log)
    state = _state_or_default(state)
    point = state.get_rollback(rollback_id)
    if point is None:
        known = [r.get("id") for r in state.list_rollbacks()]
        err = PlanError("No rollback point '%s'" % _short(str(rollback_id or ""), 20),
                        code="plan.rollback_not_found",
                        why="Rollback points are kept in %s; known ids: %s."
                            % (getattr(state, "path", "state.json"), ", ".join(map(str, known)) or "none"),
                        fix=["aiguard rollback without an id undoes the latest change on this server",
                             "Or remove the objects by hand in SmartConsole (their comments say "
                             "\"Created by AI Guard Demo Kit\")"],
                        state="Nothing was changed.")
        _log_err(log, err)
        raise err
    rid = str(point.get("id"))
    plan_id = str(point.get("plan_id") or "")
    status = str(point.get("status") or "")
    if status in ("rolled-back", "discarded"):
        msg = ("Rollback point %s was already rolled back%s. Nothing to do." % (
            rid, " on %s" % point.get("rolled_back_at") if point.get("rolled_back_at") else "")
            if status == "rolled-back" else
            "Nothing to roll back: the changes of %s were discarded and never published." % rid)
        log.info("plan", msg)
        return ApplyResult(ok=True, plan_id=plan_id, rollback_id=rid, steps=[], error=None,
                           published=False, installed=False, message=msg, kind="rollback")
    p_server = str(point.get("server") or "")
    c_server = str(getattr(client, "server", "") or "")
    p_dom = (point.get("domain") or "").lower() or None
    c_dom = (getattr(client, "domain", None) or "").lower() or None
    if (p_server and c_server and p_server.lower() != c_server.lower()) or (p_dom and p_dom != c_dom):
        err = PlanError("Rollback point %s belongs to another management server" % rid,
                        code="plan.rollback_wrong_server",
                        why="It was made on %s%s; this session is connected to %s%s." % (
                            p_server, " (domain %s)" % point.get("domain") if p_dom else "",
                            c_server, " (domain %s)" % getattr(client, "domain", None) if c_dom else ""),
                        fix=["Connect to %s%s and run the rollback again" % (
                            p_server, " domain %s" % point.get("domain") if p_dom else "")],
                        state="Nothing was changed.")
        _log_err(log, err)
        raise err

    entries = [e for e in reversed(point.get("objects") or []) if isinstance(e, dict)]
    steps: List[PlanStep] = []
    for e in entries:
        rb = e.get("rollback") or {}
        cmd = str(rb.get("command") or "")
        payload = copy.deepcopy(rb.get("payload") or {})
        if cmd.startswith("delete-") and e.get("uid"):
            payload.pop("name", None)
            payload["uid"] = e["uid"]
        action = ("script" if e.get("kind") == "script" else
                  "delete" if cmd.startswith("delete-") else "update")
        steps.append(PlanStep(id="undo-%s" % e.get("step"), kind=str(e.get("kind") or ""),
                              command=cmd, describe=str(e.get("describe") or "Undo %s" % e.get("step")),
                              payload=payload, display_payload=copy.deepcopy(payload), rollback=None,
                              manual_steps=list(e.get("manual_steps") or []), action=action,
                              exists=e.get("probe")))
    inst_def = point.get("install") or {}
    publish_step = PlanStep(id="publish", kind="publish", command="publish",
                            describe="Publish the session", payload={}, display_payload={},
                            rollback=None, manual_steps=[], action="publish")
    steps.append(publish_step)
    install_step = None
    package = point.get("package")
    gateway = point.get("gateway")
    if install and package and gateway:
        ipayload = {"policy-package": package, "targets": [gateway],
                    "access": bool(inst_def.get("access", False)),
                    "threat-prevention": bool(inst_def.get("threat_prevention", True))}
        install_step = PlanStep(id="install", kind="install", command="install-policy",
                                describe="Install the policy of %s on %s" % (package, gateway),
                                payload=ipayload, display_payload=copy.deepcopy(ipayload),
                                rollback=None, manual_steps=[], action="install")
        steps.append(install_step)

    result = ApplyResult(ok=False, plan_id=plan_id, rollback_id=rid, steps=steps, error=None,
                         published=False, installed=False, kind="rollback")
    log.info("plan", "rolling back %s" % rid, server=p_server, gateway=gateway,
             steps=[s.id for s in steps])
    if getattr(client, "read_only", False):
        err = PlanError("This session is read-only", code="plan.read_only",
                        fix=_read_only_fix(client), state="Nothing was changed.")
        _log_err(log, err)
        result.error = err
        result.message = err.state or ""
        return result

    changed = 0
    script_errors: List[PlanError] = []
    scripts_done: List[str] = []
    current: Optional[PlanStep] = None
    try:
        for step in steps:
            if step is publish_step:
                break
            current = step
            if step.action == "script":
                err2 = _apply_script(client, step, progress_cb, log)
                if err2 is None:
                    scripts_done.append(step.id)
                else:
                    _manual_if_denied(step, err2, progress_cb, log)
                    script_errors.append(_script_error(None, step, err2, rid,  # type: ignore[arg-type]
                                                       installed=False, undoing=True))
                continue
            _undo_one(client, step, progress_cb, log, result.warnings)
            if step.status == "done":
                changed += 1
        current = publish_step
        if changed:
            _emit(progress_cb, log, publish_step.id, "running", 0, "Publishing")
            t0 = time.monotonic()
            client.publish(progress_cb=lambda pct, st, msg: _emit(progress_cb, log, "publish",
                                                                  "running", pct, msg or st))
            publish_step.ms = int((time.monotonic() - t0) * 1000)
            publish_step.status = "done"
            publish_step.message = "Published %d change%s" % (changed, "" if changed == 1 else "s")
            result.published = True
        else:
            publish_step.status = "skipped"
            publish_step.message = "Nothing to publish"
        _emit(progress_cb, log, publish_step.id, publish_step.status, 100, publish_step.message)
        current = None
    except BaseException as exc:  # noqa: BLE001
        client.discard()
        if not isinstance(exc, Exception):
            raise
        if not isinstance(exc, AiguardError):
            _log_err(log, exc)  # type and traceback
        err = exc if isinstance(exc, AiguardError) else AiguardError(
            "Unexpected error during rollback", code="aiguard.internal",
            why="%s: %s" % (type(exc).__name__, exc), fix=["Send the log file to the demo owner"])
        uncertain = current is publish_step and _outcome_unknown(exc)
        if uncertain:
            left = ("The rollback publish may or may not have completed (connection lost, "
                    "timeout or task polling error).")
        else:
            left = "Nothing was changed by the rollback; the demo objects are still in place."
            if changed:
                err.fix = _after_discard_fix(err.fix, "run aiguard rollback %s again" % rid)
        if scripts_done:
            left += " The gateway script(s) %s already ran." % ", ".join(scripts_done)
        err.state = left + " Fix the problem, then run aiguard rollback %s again." % rid
        if current is not None:
            current.status = "failed"
            current.message = err.what
            _emit(progress_cb, log, current.id, "failed", None, err.what)
        _skip_rest(steps, progress_cb, log, "Not run: an earlier step failed")
        _log_err(log, err)
        result.error = err
        result.message = err.state
        return result

    _mark(state, log, rid, status="rollback-published" if result.published else status,
          rollback_published_at=_now() if result.published else None)
    if install_step is not None:
        fake_plan = Plan(plan_id=plan_id, server=p_server, domain=point.get("domain"),
                         gateway=str(gateway), package=str(package), threat_layer=None, steps=[],
                         warnings=[], created_at="")
        err3, task3 = _apply_install(client, fake_plan, install_step, progress_cb, log)
        for w in (task3 or {}).get("warnings") or []:
            result.warnings.append("Install warning: %s" % w)
        if err3 is not None:
            status3, text3 = _install_outcome(
                client, str(gateway), install_step, err3, log,
                access_carries_https=str(point.get("template") or "") == "https-inspection")
            result.install_status = status3
            err3.state = ("The demo objects were removed%s. %s Run aiguard rollback %s again (it "
                          "skips what is gone), or install the policy in SmartConsole."
                          % (" and published" if result.published else "", text3, rid))
            err3.details["action"] = {"id": "rollback", "rollback_id": rid,
                                      "cli": "aiguard rollback %s" % rid}
            _mark(state, log, rid, install_error=_short(err3.what, 200),
                  install_status=status3 or None)
            _skip_rest(steps, progress_cb, log, "Not run: install failed")
            _log_err(log, err3)
            result.error = err3
            result.message = err3.state
            return result
        result.installed = True
        result.install_status = {k: "installed" for k, on in (
            ("access", ipayload.get("access")),
            ("threat_prevention", ipayload.get("threat-prevention", True))) if on}
    if script_errors:
        err4 = script_errors[0]
        err4.state = ("The demo objects were removed%s. Only this gateway setting is left; run the "
                      "commands under Fix, or run aiguard rollback %s again."
                      % (" and the policy installed" if result.installed else "", rid))
        _log_err(log, err4)
        result.error = err4
        result.message = err4.state
        _mark(state, log, rid, status="rollback-incomplete", script_error=_short(err4.what, 200))
        return result
    _mark(state, log, rid, status="rolled-back", rolled_back_at=_now(),
          rollback_installed=bool(result.installed))
    result.ok = True
    skipped = [s.id for s in steps if s.status == "skipped" and s.kind not in ("publish", "install")]
    result.message = "Rolled back %s: removed %d change%s%s%s%s." % (
        rid, changed, "" if changed == 1 else "s",
        ", ran %d gateway script%s" % (len(scripts_done), "" if len(scripts_done) == 1 else "s")
        if scripts_done else "",
        ", installed the policy on %s" % gateway if result.installed else "",
        (" (skipped: %s)" % ", ".join(skipped)) if skipped else "")
    log.info("plan", result.message, steps=["%s:%s" % (s.id, s.status) for s in steps])
    return result


def _undo_one(client: Any, step: PlanStep, cb: Optional[ProgressCb], log: Any,
              warnings: List[str]) -> None:
    t0 = time.monotonic()
    step.status = "running"
    _emit(cb, log, step.id, "running", None, step.describe)
    cmd = str(step.command)
    if cmd.startswith("delete-") and "uid" not in step.payload and step.exists:
        # No uid recorded: delete by name only if the object is still ours.
        obj = _probe(client, step.exists)
        if obj is None:
            step.status, step.message = "skipped", "Already gone"
            _emit(cb, log, step.id, "skipped", None, step.message)
            return
        if not _is_ours(obj):
            step.status = "skipped"
            step.message = "Kept: this object was not created by AI Guard Demo Kit"
            warnings.append("%s: %s" % (step.describe, step.message))
            _emit(cb, log, step.id, "skipped", None, step.message)
            return
    try:
        _call_and_wait(client, cmd, step.payload, what=step.describe or cmd,
                       on_progress=lambda pct, st, msg: _emit(cb, log, step.id, "running", pct,
                                                              msg or st))
    except MgmtApiError as exc:
        if exc.api_code == _NOT_FOUND:
            step.status, step.message = "skipped", "Already gone"
            step.ms = int((time.monotonic() - t0) * 1000)
            log.info("plan", "%s: already gone" % step.id, command=cmd)
            _emit(cb, log, step.id, "skipped", None, step.message)
            return
        said = " ".join(str(x or "") for x in (exc.server_said, exc.what))
        if cmd.startswith("delete-") and exc.api_code in _VALIDATION_CODES and _IN_USE_RE.search(said):
            step.status = "skipped"
            step.message = "Kept: still in use (%s)" % _short(exc.server_said or exc.what, 160)
            warnings.append("%s: %s" % (step.describe, step.message))
            _emit(cb, log, step.id, "skipped", None, step.message)
            return
        raise
    step.ms = int((time.monotonic() - t0) * 1000)
    step.status = "done"
    step.message = "Deleted" if cmd.startswith("delete-") else "Done"
    log.info("plan", "undo %s done" % step.id, command=cmd, ms=step.ms)
    _emit(cb, log, step.id, "done", 100, step.message)
