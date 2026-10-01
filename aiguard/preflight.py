"""Preflight checks before the demo (spec 6).

:func:`run_preflight` runs twelve read-only checks, always in this order (the ids are
fixed: the CLI and the web console key on them):

 1. ``api_write``     the login is read-write and the server has the commands the plan
                      uses (the permission profile itself is checked when applying)
 2. ``api_version``   Management API 2.2 (R82.20) or later
 3. ``ai_support``    the server has the AI Agent Security key test command
 4. ``gw_version``    the gateway runs R82.20 or later
 5. ``tp_mode``       Custom (not Autonomous) Threat Prevention
 6. ``https_gw``      HTTPS Inspection is on, in Full mode (fixable by
                      ``aiguard fix https-inspection``)
 7. ``outbound_ca``   an outbound inspection CA exists
 8. ``tls_path``      provider hosts are re-signed by the gateway (TLS handshake only)
 9. ``client_path``   this computer is on a network attached to the gateway
10. ``package``       policy package and threat layer resolved
11. ``last_install``  the last policy installation on the gateway succeeded for both
                      Access Control and Threat Prevention (``show-tasks``, last 48 hours,
                      and the gateway's installed-policy dates); never blocking
12. ``workforce_ai``  Workforce AI Security state (information only)

Every non-pass result carries exact fix steps. ``CheckResult.action`` names, in a
machine-readable way, what a UI can offer as a button for the fix (the fix text keeps
the CLI command). ``CheckResult.server_said`` carries server text verbatim (for
``last_install``: the install task's verification messages). Nothing here changes
anything: the management calls are ``show-*`` only and ``tls_path`` stops after the
TLS handshake.

Testing / labs: ``probe_endpoints`` maps a probe host to the address actually
connected to, e.g. ``{"api.openai.com": ("127.0.0.1", 8443)}`` or
``{"api.openai.com": "https://127.0.0.1:8443"}``. The certificate is then verified
against that address (verification is never turned off); results are still reported
under the original host name.
"""

from __future__ import annotations

import copy
import dataclasses
import datetime as _dt
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from . import gateways as _gateways
from . import probe as _probe
from . import redact as _redact
from .errors import AiguardError, MgmtApiError
from . import mgmt as _mgmt
from .mgmt import api_version_tuple, release_for_api

__all__ = [
    "CheckResult",
    "PreflightReport",
    "run_preflight",
    "check_last_install",
    "CHECK_IDS",
    "DEFAULT_PROBE_HOSTS",
    "API_WRITE_FIX",
    "MGMT_UPGRADE_FIX",
    "HTTPS_FIX",
    "TRUST_CA_FIX",
    "NAT_HINT",
    "LAST_INSTALL_WINDOW_HOURS",
    "action",
]

CHECK_IDS: Tuple[str, ...] = (
    "api_write", "api_version", "ai_support", "gw_version", "tp_mode", "https_gw",
    "outbound_ca", "tls_path", "client_path", "package", "last_install", "workforce_ai",
)

TITLES: Dict[str, str] = {
    "api_write": "Management API login is read-write",
    "api_version": "Management API version (R82.20 / API 2.2)",
    "ai_support": "AI Agent Security support on the management server",
    "gw_version": "Gateway version (R82.20 or later)",
    "tp_mode": "Threat Prevention mode (Custom)",
    "https_gw": "HTTPS Inspection on the gateway",
    "outbound_ca": "Outbound inspection certificate (CA)",
    "tls_path": "AI provider traffic is inspected",
    "client_path": "This computer's traffic goes through the gateway",
    "package": "Policy package and threat layer",
    "last_install": "Last policy installation on the gateway",
    "workforce_ai": "Workforce AI Security (information)",
}

#: How far back ``last_install`` looks for policy installation tasks.
LAST_INSTALL_WINDOW_HOURS = 48

DEFAULT_PROBE_HOSTS: Tuple[str, ...] = ("api.openai.com", "api.anthropic.com")

AI_TEST_COMMANDS: Tuple[str, ...] = ("test-ai-agent-security-api-key", "test-ai-guard-api-key")

API_WRITE_FIX: List[str] = [
    "SmartConsole > Manage & Settings > Permissions & Administrators > Permission Profiles > "
    "(profile) > Management: Management API Login; Access Control / Threat Prevention: Edit; "
    "Install Policy",
]

MGMT_UPGRADE_FIX: List[str] = [
    "Upgrade the management server to R82.20 (Management API 2.2), or connect to an R82.20 "
    "management server",
    "Check the version on the management server: api status (or aiguard status)",
]

TRUST_CA_FIX: List[str] = [
    "aiguard trust-ca  (shows how to trust it)",
    "or pass --outbound-ca <outbound-ca.pem>",
]

_STATUSES = ("pass", "fail", "warn", "skip")
_LEVEL = {"pass": "INFO", "skip": "INFO", "warn": "WARN", "fail": "ERROR"}
_NOT_FOUND = "generic_err_object_not_found"
_COMMAND_NOT_FOUND = "generic_err_command_not_found"


def HTTPS_FIX(gw_name: str) -> List[str]:
    """Fix steps for HTTPS Inspection being off (spec 6, check 6)."""
    return [
        "aiguard fix https-inspection  (asks for approval)",
        "Or SmartConsole > %s > HTTPS Inspection > Step 1 create/import the outbound CA > "
        "Step 2 deploy it to clients > Step 3 enable HTTPS Inspection (Deployment Mode: Full "
        "inspection), then install the Access Control policy" % gw_name,
    ]


def action(action_id: str, label: str, cli: str, **options: Any) -> Dict[str, Any]:
    """A machine-readable fix a UI can offer as a button: ``{"id", "label", "cli",
    "options"}``. ``id``: ``https-inspection`` (turn HTTPS Inspection on / Full mode),
    ``https-rule`` (add an Inspect rule for this computer), ``outbound-ca`` (trust the
    outbound CA for the demo traffic)."""
    return {"id": action_id, "label": label, "cli": cli, "options": dict(options)}


def _https_action(gw_name: str) -> Dict[str, Any]:
    return action("https-inspection", "Turn on HTTPS Inspection on %s (asks for approval)"
                  % gw_name, "aiguard fix https-inspection", add_rule=False)


def _rule_action(gw_name: str) -> Dict[str, Any]:
    return action("https-rule", "Add an Inspect rule for this computer on %s (asks for "
                  "approval)" % gw_name, "aiguard fix https-inspection --add-rule",
                  add_rule=True)


def _ca_action() -> Dict[str, Any]:
    return action("outbound-ca", "Trust the outbound CA for the demo traffic",
                  "aiguard trust-ca")


# --------------------------------------------------------------------------- results


@dataclass
class CheckResult:
    """One preflight check. ``status``: pass | fail | warn | skip. ``fixable`` names
    what aiguard can fix itself (``"https-inspection"``, ``"https-rule"``); ``action``
    is the same as a dict a UI can turn into a button (see :func:`action`).
    ``server_said``: server text verbatim (redacted), e.g. install verification errors."""

    id: str
    title: str
    status: str
    blocking: bool
    detail: str
    evidence: Dict[str, str] = field(default_factory=dict)
    fix: List[str] = field(default_factory=list)
    log_line: Optional[int] = None
    fixable: Optional[str] = None
    server_said: Optional[str] = None
    action: Optional[Dict[str, Any]] = None

    @property
    def ok(self) -> bool:
        return self.status in ("pass", "skip")

    @property
    def failed_blocking(self) -> bool:
        return self.status == "fail" and self.blocking

    def to_dict(self) -> dict:
        data = dataclasses.asdict(self)
        return _redact.redact_obj(data)


@dataclass
class PreflightReport:
    """All checks for one gateway. ``ok`` is True when no blocking check failed."""

    gateway: str
    checks: List[CheckResult]
    created_at: str = ""
    local_ip: Optional[str] = None
    probe_hosts: List[str] = field(default_factory=list)
    ms: int = 0

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == "pass")

    @property
    def failed_blocking(self) -> int:
        return sum(1 for c in self.checks if c.status == "fail" and c.blocking)

    @property
    def warnings(self) -> int:
        return sum(1 for c in self.checks if c.status == "warn"
                   or (c.status == "fail" and not c.blocking))

    @property
    def skipped(self) -> int:
        return sum(1 for c in self.checks if c.status == "skip")

    @property
    def ok(self) -> bool:
        return self.failed_blocking == 0

    def check(self, check_id: str) -> Optional[CheckResult]:
        for c in self.checks:
            if c.id == check_id:
                return c
        return None

    def blocking(self) -> List[CheckResult]:
        """The failed blocking checks, in order."""
        return [c for c in self.checks if c.status == "fail" and c.blocking]

    def fixable(self) -> List[str]:
        """What aiguard can fix itself (e.g. ``["https-inspection"]``, ``"https-rule"``)."""
        out: List[str] = []
        for c in self.checks:
            if c.fixable and c.status in ("fail", "warn") and c.fixable not in out:
                out.append(c.fixable)
        return out

    def summary_line(self) -> str:
        return "%d passed, %d blocking, %d warning%s" % (
            self.passed, self.failed_blocking, self.warnings, "" if self.warnings == 1 else "s")

    def to_dict(self) -> dict:
        return _redact.redact_obj({
            "gateway": self.gateway, "ok": self.ok, "passed": self.passed,
            "failed_blocking": self.failed_blocking, "warnings": self.warnings,
            "skipped": self.skipped, "created_at": self.created_at, "local_ip": self.local_ip,
            "probe_hosts": list(self.probe_hosts), "ms": self.ms,
            "summary": self.summary_line(), "fixable": self.fixable(),
            "checks": [c.to_dict() for c in self.checks],
        })


# --------------------------------------------------------------------------- helpers


class _NullLog(object):
    path = None

    def event(self, *a: Any, **k: Any) -> int:
        return 0

    debug = info = warn = error = hint = event

    def exception(self, err: BaseException, component: str) -> int:
        return 0


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _s(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_s(v) for v in value)
    return _redact.redact(str(value))


def _evidence(**kw: Any) -> Dict[str, str]:
    return {k: _s(v) for k, v in kw.items() if v is not None and v != ""}


def _result(cid: str, status: str, detail: str, *, blocking: bool = False,
            evidence: Optional[Dict[str, str]] = None, fix: Optional[List[str]] = None,
            fixable: Optional[str] = None, title: Optional[str] = None,
            server_said: Optional[str] = None,
            action: Optional[Dict[str, Any]] = None) -> CheckResult:
    if status not in _STATUSES:  # pragma: no cover - programming error
        raise ValueError("bad status %r" % status)
    return CheckResult(id=cid, title=title or TITLES.get(cid, cid), status=status,
                       blocking=bool(blocking and status == "fail"), detail=detail,
                       evidence=dict(evidence or {}), fix=list(fix or []), fixable=fixable,
                       server_said=_redact.redact(server_said) if server_said else None,
                       action=dict(action) if action else None)


def _uniq(items: Iterable[str]) -> List[str]:
    out: List[str] = []
    for item in items:
        if item and item not in out:
            out.append(item)
    return out


def _ident(value: Any) -> Optional[str]:
    if isinstance(value, dict):
        name = value.get("name") or value.get("uid")
        return str(name) if name else None
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _commands(client: Any) -> set:
    fn = getattr(client, "commands", None)
    if not callable(fn):
        return set()
    try:
        return set(fn() or ())
    except AiguardError:
        return set()


def _has(client: Any, cmds: set, command: str) -> Optional[bool]:
    """True / False when the command list is known, None when it is not."""
    if not cmds:
        return None
    return command in cmds


def _api_text(version: Optional[str]) -> str:
    if not version:
        return "unknown"
    release = release_for_api(version)
    return "%s (%s)" % (version, release or "unknown release")


def _split_host(host: str) -> Tuple[str, int]:
    """``"api.openai.com"`` -> ``("api.openai.com", 443)``; ``"h:8443"`` -> ``("h", 8443)``."""
    name = str(host or "").strip()
    port = 443
    if name.count(":") == 1 and not name.startswith("["):
        base, _, p = name.partition(":")
        if p.isdigit():
            name, port = base, int(p)
    return name, port


def _endpoint(host: str, overrides: Optional[Mapping[str, Any]]) -> Tuple[str, str, int]:
    """(display host, connect host, connect port) for one probe host."""
    name, port = _split_host(host)
    target, tport = name, port
    if overrides:
        value = overrides.get(name)
        if value is None:
            value = overrides.get(str(host))
        if isinstance(value, str) and value.strip():
            text = value.strip()
            if "://" not in text:
                text = "https://" + text
            parts = urlsplit(text)
            if parts.hostname:
                target = parts.hostname
                tport = int(parts.port or 443)
        elif isinstance(value, (tuple, list)) and value:
            target = str(value[0])
            if len(value) > 1 and value[1]:
                tport = int(value[1])
    return name, target, tport


# --------------------------------------------------------------------------- checks


def _check_api_write(client: Any, cmds: set) -> CheckResult:
    if getattr(client, "read_only", False):
        standby = getattr(client, "standby", None) is True
        fix = (["This management server is the Standby member of Management High "
                "Availability (its sessions are read-only): connect to the Active server"]
               if standby else
               ["Use an administrator whose permission profile is Read/Write and may edit "
                "and install the policy, then connect again"]) + API_WRITE_FIX
        return _result("api_write", "fail",
                       "This login is read-only%s: aiguard can look, but cannot add the threat "
                       "rule or install the policy." % (
                           " (the server is the Standby management server)" if standby else ""),
                       blocking=True, evidence=_evidence(read_only=True,
                                                         standby=True if standby else None),
                       fix=fix)
    missing = [c for c in ("add-threat-rule", "install-policy") if _has(client, cmds, c) is False]
    if missing:
        return _result("api_write", "fail",
                       "This login cannot use %s." % " and ".join(missing),
                       blocking=True, evidence=_evidence(read_only=False, missing=missing),
                       fix=list(API_WRITE_FIX))
    if not cmds:
        return _result("api_write", "warn",
                       "The login is read-write, but the server did not list its commands, so "
                       "add-threat-rule and install-policy could not be confirmed.",
                       evidence=_evidence(read_only=False),
                       fix=["If applying the plan fails with a permission error: "
                            + API_WRITE_FIX[0]])
    return _result("api_write", "pass",
                   "Read-write login; the server has add-threat-rule and install-policy. The "
                   "administrator's permission profile is not checked here (show-commands "
                   "lists every command): a missing permission shows up when the plan is "
                   "applied.",
                   evidence=_evidence(read_only=False, commands="add-threat-rule, install-policy",
                                      permissions="not checked"))


def _check_api_version(client: Any) -> CheckResult:
    version = getattr(client, "api_version", None)
    if not version:
        return _result("api_version", "warn",
                       "The server did not report its Management API version.",
                       evidence=_evidence(api_version="unknown"),
                       fix=["Check the version on the management server: api status"])
    vt = api_version_tuple(version)
    if vt >= (2, 2):
        return _result("api_version", "pass",
                       "Management API %s." % _api_text(version),
                       evidence=_evidence(api_version=version, release=release_for_api(version)))
    return _result("api_version", "fail",
                   "AI Agent Security needs R82.20 management (Management API 2.2). This server "
                   "reports API %s." % _api_text(version),
                   blocking=True,
                   evidence=_evidence(api_version=version,
                                      release=release_for_api(version) or "unknown"),
                   fix=list(MGMT_UPGRADE_FIX))


def _check_ai_support(client: Any, cmds: set) -> CheckResult:
    if not cmds:
        return _result("ai_support", "warn",
                       "The server did not list its commands, so AI Agent Security support "
                       "could not be confirmed.",
                       evidence=_evidence(api_version=getattr(client, "api_version", None)),
                       fix=list(MGMT_UPGRADE_FIX))
    found = [c for c in AI_TEST_COMMANDS if c in cmds]
    if found:
        return _result("ai_support", "pass", "The server has %s." % found[0],
                       evidence=_evidence(command=found[0]))
    version = getattr(client, "api_version", None)
    return _result("ai_support", "fail",
                   "This management server has no AI Agent Security support (no %s). "
                   "AI Agent Security needs R82.20 management (Management API 2.2). This "
                   "server reports API %s." % (" or ".join(AI_TEST_COMMANDS), _api_text(version)),
                   blocking=True, evidence=_evidence(api_version=version or "unknown"),
                   fix=list(MGMT_UPGRADE_FIX))


def _check_gw_version(gw: Any) -> CheckResult:
    vt = gw.version_tuple() if hasattr(gw, "version_tuple") else _gateways.version_tuple(gw.version)
    shown = getattr(gw, "release", None) or getattr(gw, "version", None)
    need = "R%d.%d" % _gateways.AI_SECURITY_MIN_VERSION
    if vt is None:
        return _result("gw_version", "warn",
                       "The software version of %s is unknown; AI Agent Security needs %s."
                       % (gw.name, need),
                       evidence=_evidence(version=getattr(gw, "version", None) or "unknown"),
                       fix=["Check the version of %s in SmartConsole > Gateways & Servers "
                            "(Version column)" % gw.name])
    if vt < _gateways.AI_SECURITY_MIN_VERSION:
        return _result("gw_version", "fail",
                       "%s runs %s; AI Agent Security needs %s or later on the gateway."
                       % (gw.name, shown, need),
                       blocking=True, evidence=_evidence(version=shown),
                       fix=["Upgrade %s to %s (SmartConsole > Gateways & Servers shows the "
                            "version)" % (gw.name, need), "Or pick an %s gateway" % need])
    return _result("gw_version", "pass", "%s runs %s." % (gw.name, shown),
                   evidence=_evidence(version=shown))


def _check_tp_mode(gw: Any) -> CheckResult:
    mode = getattr(gw, "threat_prevention_mode", None)
    if not mode:
        why = getattr(gw, "detail_error", None)
        return _result("tp_mode", "skip",
                       "The gateway object does not report a Threat Prevention mode%s."
                       % ((" (%s)" % why) if why else ""))
    mode = str(mode).lower()
    if mode == "custom":
        return _result("tp_mode", "pass", "%s uses Custom Threat Prevention." % gw.name,
                       evidence=_evidence(mode=mode))
    fix = ["SmartConsole > Gateways & Servers > %s (double-click) > General Properties > "
           "Threat Prevention tab: select Custom Threat Prevention" % gw.name,
           "Publish and install the policy, then run preflight again"]
    if mode == "autonomous":
        return _result("tp_mode", "warn",
                       "Custom threat profiles apply only when the gateway uses Custom Threat "
                       "Prevention. %s uses Autonomous Threat Prevention." % gw.name,
                       evidence=_evidence(mode=mode), fix=fix)
    return _result("tp_mode", "warn",
                   "%s reports Threat Prevention mode '%s'. Custom threat profiles apply only "
                   "when the gateway uses Custom Threat Prevention." % (gw.name, mode),
                   evidence=_evidence(mode=mode), fix=fix)


def _check_https_gw(gw: Any) -> CheckResult:
    on = getattr(gw, "https_inspection", None)
    if on is None:
        why = getattr(gw, "detail_error", None)
        return _result("https_gw", "skip",
                       "The gateway object does not report whether HTTPS Inspection is on%s."
                       % ((" (%s)" % why) if why else ""))
    mode = getattr(gw, "https_deployment_mode", None)
    if on and str(mode or "").lower() == "learning":
        return _result("https_gw", "fail",
                       "HTTPS Inspection on %s is in Learning mode: the gateway inspects only a "
                       "small part of the traffic, so most prompts pass through unseen. AI "
                       "Agent Security needs Full mode." % gw.name,
                       blocking=True,
                       evidence=_evidence(enable_https_inspection=True, deployment_mode=mode),
                       fix=["aiguard fix https-inspection  (asks for approval; sets Full mode)",
                            "Or SmartConsole > %s > HTTPS Inspection > Deployment Mode: Full "
                            "inspection, then install the Access Control policy" % gw.name],
                       fixable="https-inspection", action=_https_action(gw.name))
    if on:
        return _result("https_gw", "pass", "HTTPS Inspection is on for %s%s." % (
            gw.name, " (Full mode)" if str(mode or "").lower() == "full" else ""),
                       evidence=_evidence(enable_https_inspection=True, deployment_mode=mode))
    return _result("https_gw", "fail",
                   "HTTPS Inspection is off on %s: the gateway cannot read prompts inside TLS, "
                   "so AI Agent Security never sees them." % gw.name,
                   blocking=True, evidence=_evidence(enable_https_inspection=False),
                   fix=HTTPS_FIX(gw.name), fixable="https-inspection",
                   action=_https_action(gw.name))


def _show_outbound(client: Any) -> Optional[dict]:
    """The outbound certificate object, or None when there is none (raw reply: use
    :func:`aiguard.mgmt.outbound_certificate_info` before showing any of it)."""
    return _mgmt.show_outbound_certificate(client)


def _check_outbound_ca(client: Any, gw: Any, cmds: set) -> CheckResult:
    command = "show-outbound-inspection-certificate"
    if _has(client, cmds, command) is False:
        return _result("outbound_ca", "skip",
                       "This management server has no %s command." % command)
    cert = _show_outbound(client)
    if cert is None:
        return _result("outbound_ca", "warn",
                       "No outbound inspection certificate. It is needed before HTTPS "
                       "Inspection can be enabled.",
                       fix=["SmartConsole > %s > HTTPS Inspection > Step 1: create or import "
                            "the outbound CA" % gw.name,
                            "Step 2: deploy it to the demo computers (aiguard trust-ca shows "
                            "how)",
                            "Publish, then run preflight again"])
    issued = cert.get("issued-by") or cert.get("subject")
    return _result("outbound_ca", "pass",
                   "Outbound inspection certificate %s%s." % (
                       cert.get("name") or "found",
                       (", issued by %s" % issued) if issued else ""),
                   evidence=_evidence(**{"name": cert.get("name"), "issued-by": issued,
                                         "valid-to": cert.get("valid-to")}))


def _check_tls_path(hosts: Sequence[str], *, ca_file: Optional[str], timeout: float,
                    overrides: Optional[Mapping[str, Any]], https_on: bool, gw: Any,
                    local_ip: Optional[str], log: Any) -> CheckResult:
    sentences: List[str] = []
    fix: List[str] = []
    evidence: Dict[str, str] = {}
    worst = "pass"
    order = {"pass": 0, "warn": 1, "fail": 2}
    inspected_by: List[str] = []
    bypassed = False
    untrusted = False
    for host in hosts:
        name, logical_port = _split_host(host)
        _name, target, port = _endpoint(host, overrides)
        try:
            r = _probe.tls_probe(target, port, ca_file=ca_file, timeout=timeout)
        except AiguardError as exc:  # bad --ca-file
            err = exc.to_dict()
            sentences.append("%s: %s" % (name, err.get("what")))
            fix.extend(err.get("fix") or [])
            evidence[name] = "not tested: %s" % err.get("what")
            worst = "fail"
            continue
        if target != name or port != logical_port:
            evidence["%s via" % name] = "%s:%d" % (target, port)
        status = r.get("status")
        issuer = r.get("issuer") or r.get("issuer_org") or ""
        log.debug("preflight", "tls probe", host=name, target="%s:%d" % (target, port),
                  status=status, issuer=issuer, ms=r.get("ms"),
                  verify_error=r.get("verify_error"), sha256=r.get("sha256") or None)
        if status == "inspected":
            evidence[name] = "inspected by %s" % issuer
            inspected_by.append(issuer)
            continue
        if status == "not_inspected":
            worst = "fail"
            evidence[name] = "public CA: %s" % issuer
            evidence.setdefault("issuer", issuer)
            text = ("%s: the certificate is issued by %s (a public CA), so HTTPS Inspection "
                    "did not decrypt it and prompts would pass through unseen" % (name, issuer))
            if https_on:
                bypassed = True
                text += (". HTTPS Inspection is on for the gateway, but this traffic was not "
                         "decrypted: the Access Control policy that carries the HTTPS "
                         "Inspection settings may not be installed yet (see the last policy "
                         "installation check), or a Bypass rule or category in the HTTPS "
                         "Inspection policy matches %s, or the Inspect rule's source does not "
                         "include this computer" % name)
                fix.extend([
                    "aiguard fix https-inspection --add-rule  (asks for approval; adds an "
                    "Inspect rule for this computer at the top of the HTTPS Inspection policy)",
                    "Or SmartConsole > Security Policies > HTTPS Inspection: find the Bypass "
                    "rule or bypassed category that matches %s and put an Inspect rule for "
                    "this computer above it" % name,
                    "Make sure the Inspect rule's Source includes this computer (%s)"
                    % (local_ip or "its IP address"),
                    "Install the Access Control policy (HTTPS Inspection is installed with it) "
                    "and check that Install Policy Details shows Succeeded, then run preflight "
                    "again",
                ])
            else:
                fix.extend(HTTPS_FIX(getattr(gw, "name", "the gateway")) + [
                    "Make sure this computer's internet traffic goes through %s"
                    % getattr(gw, "name", "the gateway"),
                    "Then run preflight again",
                ])
            sentences.append(text)
            continue
        if status == "untrusted":
            if order[worst] < order["warn"]:
                worst = "warn"
            msg = r.get("verify_error") or ""
            evidence[name] = "untrusted chain: %s" % msg
            evidence.setdefault("verify_message", msg)
            sentences.append("%s: Traffic is being inspected, but this computer does not trust "
                             "the gateway's outbound CA. Apps will fail with certificate "
                             "errors." % name)
            fix.extend(TRUST_CA_FIX)
            untrusted = True
            continue
        err = r.get("error") or {}
        if status == "connect_error":
            worst = "fail"
            evidence[name] = "cannot connect: %s" % (r.get("connect_error") or err.get("what") or "")
            sentences.append("Cannot reach %s:%d from this computer" % (name, logical_port))
            fix.extend((err.get("fix") or []) + [
                "Check proxy settings (HTTPS_PROXY), DNS and the route from this computer to "
                "the internet through %s" % getattr(gw, "name", "the gateway")])
            continue
        # tls_error: a verification problem other than an unknown CA, or a handshake failure.
        if r.get("verify_error"):
            if order[worst] < order["warn"]:
                worst = "warn"
            evidence[name] = "certificate problem: %s" % r.get("verify_error")
            evidence.setdefault("verify_message", str(r.get("verify_error")))
        else:
            worst = "fail"
            evidence[name] = "TLS handshake failed: %s" % (err.get("server_said") or "")
        sentences.append("%s: %s" % (name, err.get("what") or "TLS handshake failed"))
        fix.extend(err.get("fix") or [])
    if worst == "pass":
        issuers = _uniq(inspected_by)
        detail = "%s: inspected by %s." % (", ".join(_split_host(h)[0] for h in hosts),
                                           " / ".join(issuers) or "the gateway")
        if issuers:
            evidence.setdefault("issuer", issuers[0])
        return _result("tls_path", "pass", detail, evidence=evidence)
    detail = ". ".join(s.rstrip(".") for s in sentences) + "."
    gw_name = getattr(gw, "name", "the gateway")
    fixable = act = None
    if bypassed:
        fixable, act = "https-rule", _rule_action(gw_name)
    elif untrusted and worst == "warn":
        act = _ca_action()
    return _result("tls_path", worst, detail, blocking=(worst == "fail"), evidence=evidence,
                   fix=_uniq(fix), fixable=fixable, action=act)


def _check_client_path(gw: Any, local_ip: Optional[str]) -> CheckResult:
    nets = gw.networks() if hasattr(gw, "networks") else []
    if not nets:
        return _result("client_path", "skip",
                       "The gateway's interfaces (networks) are unknown.",
                       evidence=_evidence(local_ip=local_ip))
    if not local_ip:
        return _result("client_path", "skip",
                       "This computer's IP address towards the AI providers is unknown.",
                       evidence=_evidence(networks=[str(n) for n in nets]))
    inside = gw.contains_ip(local_ip)
    shown = [str(n) for n in nets]
    if inside:
        net = next((str(n) for n in nets if _in(local_ip, n)), "")
        return _result("client_path", "pass",
                       "%s is on %s, directly attached to %s." % (local_ip, net or "a network",
                                                                  gw.name),
                       evidence=_evidence(local_ip=local_ip, network=net))
    return _result("client_path", "warn",
                   "%s is not on a network directly attached to %s; make sure its traffic to "
                   "the internet goes through %s" % (local_ip, gw.name, gw.name),
                   evidence=_evidence(local_ip=local_ip, networks=shown),
                   fix=["Check this computer's default gateway / route to the internet: it must "
                        "pass through %s (traceroute api.openai.com)" % gw.name,
                        "If a router sits between them, that is fine as long as the traffic "
                        "crosses %s" % gw.name,
                        NAT_HINT % {"ip": local_ip}])


NAT_HINT = ("If this computer is behind NAT or runs in Docker, %(ip)s is not the address the "
            "gateway sees: set the address the gateway sees (web console: Connect > Network "
            "address translation; CLI: --local-ip IP or AIGUARD_LOCAL_IP), or use scope any or an "
            "existing network object")


def _in(ip: str, net: Any) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _check_package(client: Any, gw: Any, package: Optional[str]) -> CheckResult:
    name = (package or "").strip() or getattr(gw, "policy_package", None)
    if not name:
        pkgs = client.show_all("show-packages", {"details-level": "standard"}, key="packages")
        names = [str(p.get("name")) for p in pkgs if isinstance(p, dict) and p.get("name")]
        if len(names) == 1:
            name = names[0]
        else:
            shown = ", ".join(names) or "none"
            return _result("package", "fail",
                           "Cannot tell which policy package to change for %s: the gateway "
                           "reports no installed policy and the server has %d packages (%s)."
                           % (gw.name, len(names), shown),
                           blocking=True, evidence=_evidence(packages=names),
                           fix=["Choose the package: --package <name> (one of: %s)" % shown,
                                "Or install a policy on %s first (SmartConsole > Install Policy)"
                                % gw.name])
    try:
        pkg = client.call("show-package", {"name": name, "details-level": "full"})
    except MgmtApiError as exc:
        if exc.api_code != _NOT_FOUND:
            raise
        return _result("package", "fail", "Policy package '%s' was not found." % name,
                       blocking=True, evidence=_evidence(package=name),
                       fix=["Check the name in SmartConsole > Security Policies (Manage policies "
                            "and layers)", "Then pass --package <name>"])
    real = str(pkg.get("name") or name)
    layers = pkg.get("threat-layers")
    names = [n for n in (_ident(x) for x in layers)] if isinstance(layers, list) else []
    names = [n for n in names if n]
    layer = next((n for n in names if n.endswith("Threat Prevention")), names[0] if names else None)
    if not layer:
        return _result("package", "fail",
                       "Policy package %s has no Threat Prevention policy (threat layer)." % real,
                       blocking=True, evidence=_evidence(package=real),
                       fix=["SmartConsole > Security Policies > Manage policies and layers > %s "
                            "> Edit: select Threat Prevention" % real,
                            "Publish, then run preflight again"])
    return _result("package", "pass", "Package %s, threat layer %s." % (real, layer),
                   evidence=_evidence(package=real, threat_layer=layer))


# --------------------------------------------------------------------------- last install

_TYPES = (("access", "Access Control"), ("threat", "Threat Prevention"))
_INSTALL_RETRY_FIX = ("Install policy again and check that Install Policy Details shows "
                      "Succeeded for both Access Control and Threat Prevention")


def _tasks_since(hours: int) -> str:
    # The documented example has no time zone ("the Management server's time zone is used"):
    # the window is wide enough for any offset.
    then = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=hours)
    return then.strftime("%Y-%m-%dT%H:%M:%S")


def _task_text(task: Dict[str, Any]) -> str:
    return " ".join(str(task.get(k) or "") for k in ("task-name", "progress-description", "name"))


def _is_install_task(task: Dict[str, Any]) -> bool:
    text = _task_text(task).lower()
    if "uninstall" in text:
        return False
    return ("install" in text and "polic" in text) or "policy installation" in text


def _detail_targets(task: Dict[str, Any]) -> List[Tuple[str, str]]:
    """``[(target name, status)]`` of the per-gateway entries in task-details."""
    out: List[Tuple[str, str]] = []
    details = task.get("task-details") or []
    if isinstance(details, dict):
        details = [details]
    for det in details if isinstance(details, list) else []:
        if not isinstance(det, dict):
            continue
        for key in ("gatewayName", "target", "gateway-name", "targetName"):
            if det.get(key):
                out.append((str(det.get(key)),
                            str(det.get("statusCode") or det.get("status") or "").lower()))
                break
    return out


def _mentions(task: Dict[str, Any], gw_name: str, package: Optional[str]) -> bool:
    name = str(gw_name or "").strip()
    if not name:
        return False
    targets = _detail_targets(task)
    if targets:
        return any(t.lower() == name.lower() for t, _st in targets)
    pat = re.compile(r"(?<![A-Za-z0-9_.-])%s(?![A-Za-z0-9_-])" % re.escape(name), re.IGNORECASE)
    text = _task_text(task) + " " + str(task.get("comments") or "")
    try:
        text += " " + json.dumps(task.get("task-details") or [], ensure_ascii=False)
    except (TypeError, ValueError):
        pass
    if pat.search(text):
        return True
    # No gateway names at all ("Policy installation - Standard"): the gateway's own package.
    if package:
        ppat = re.compile(r"(?<![A-Za-z0-9_.-])%s(?![A-Za-z0-9_-])" % re.escape(package),
                          re.IGNORECASE)
        return bool(ppat.search(_task_text(task)))
    return False


def _status_for(task: Dict[str, Any], gw_name: str) -> str:
    """The task's status for this gateway (its own task-details entry when there is one)."""
    status = str(task.get("status") or "").lower()
    mine = [st for t, st in _detail_targets(task) if t.lower() == gw_name.lower() and st]
    if mine:
        if any(st in ("failed", "failure", "error") for st in mine):
            return "failed"
        if any(st == "partially succeeded" for st in mine):
            return "partially succeeded"
        if all(st in ("succeeded", "succeeded with warnings", "success") for st in mine) \
                and status in _mgmt.TASK_FAILED:
            return "succeeded"   # another target failed, this gateway did not
    return status


def _task_errors(task: Dict[str, Any], gw_name: str) -> List[str]:
    msgs = _mgmt.task_messages(task)
    mine = [m for m in msgs if m.get("target") in (None, "") or
            str(m.get("target")).lower() == gw_name.lower()]
    # The verification messages (stage / gateway messages) first; the generic status lines
    # ("Policy installation failed on GW") only when there is nothing else.
    errs = _uniq(m["text"] for m in mine if m.get("level") == "error"
                 and m.get("source") in ("stagesInfo", "messages", "responseError"))
    if not errs:
        errs = _uniq(m["text"] for m in mine if m.get("level") == "error")
    if not errs:
        errs = _uniq(m["text"] for m in mine if m.get("level") == "warning")
    return errs


def _installed_since(gw: Any, kind: str, start: Optional[int]) -> Optional[bool]:
    at = getattr(gw, "%s_policy_installed_at" % kind, None)
    if at is None or start is None:
        return None
    return at >= start


def _check_last_install(client: Any, gw: Any, cmds: set, *,
                        hours: int = LAST_INSTALL_WINDOW_HOURS) -> CheckResult:
    """Did the last policy installation on the gateway succeed for both policy types?

    Reads the gateway's installed-policy facts (``show-gateways-and-servers`` policy
    object, refreshed here) and the policy installation tasks of the last ``hours`` hours
    (``show-tasks``). A failed task whose start is newer than the installation date of one
    policy type, while the other type was installed at or after it, is a partial install:
    the gateway keeps enforcing the older policy of the failed type."""
    name = gw.name
    try:
        g = dataclasses.replace(gw)
    except TypeError:
        g = copy.copy(gw)
    if callable(getattr(client, "show_all", None)) and callable(getattr(g, "apply_policy", None)):
        try:
            pol = _gateways.policy_state(client, name)
            if pol is not None:
                g.apply_policy(pol)
        except AiguardError:
            pass   # keep what the gateway listing said when the gateway was selected
    package = getattr(g, "policy_package", None)
    evidence = _evidence(**{
        "access-policy": getattr(g, "access_policy", None),
        "access-policy-installed": getattr(g, "access_policy_installed", None),
        "access-policy-installation-date": getattr(g, "access_policy_installation_date", None),
        "threat-policy": getattr(g, "threat_policy", None),
        "threat-policy-installed": getattr(g, "threat_policy_installed", None),
        "threat-policy-installation-date": getattr(g, "threat_policy_installation_date", None),
    })
    missing = [label for kind, label in _TYPES
               if getattr(g, "%s_policy_installed" % kind, None) is False]
    not_installed: Optional[CheckResult] = None
    if missing:
        not_installed = _result(
            "last_install", "warn",
            "%s: no %s policy installed." % (name, " and no ".join(missing)),
            title="No %s policy installed on %s" % (" or ".join(missing), name),
            evidence=evidence,
            fix=["SmartConsole > Security Policies > Install Policy: install %s on %s with %s"
                 % (package or "the policy package", name, " and ".join(missing)),
                 _INSTALL_RETRY_FIX])

    def skip(text: str) -> CheckResult:
        return not_installed or _result("last_install", "skip", text, evidence=evidence)

    if _has(client, cmds, "show-tasks") is False:
        return skip("This management server has no show-tasks command, so the last policy "
                    "installation on %s could not be checked." % name)
    payload = {"status": "all", "from-date": _tasks_since(hours), "details-level": "full",
               "limit": 50}
    try:
        reply = client.call("show-tasks", payload)
    except MgmtApiError as exc:
        return skip("Could not read the task list (show-tasks: %s), so the last policy "
                    "installation on %s was not checked." % (exc.what, name))
    raw_tasks = reply.get("tasks") if isinstance(reply, dict) else None
    tasks = [t for t in (raw_tasks if isinstance(raw_tasks, list) else []) if isinstance(t, dict)]
    tasks = [t for t in tasks if _is_install_task(t) and _mentions(t, name, package)]
    tasks.sort(key=lambda t: (_mgmt.task_start_posix(t) or 0,
                              _mgmt.api_date_posix(t.get("last-update-time")) or 0),
               reverse=True)
    if not tasks:
        return skip("No policy installation on %s in the last %d hours (show-tasks)."
                    % (name, hours))
    newest = tasks[0]
    evidence["task"] = _s(newest.get("task-name") or newest.get("task-id"))
    evidence["task-status"] = _s(_status_for(newest, name))
    when = _mgmt.api_date_text(newest.get("start-time"))
    if when:
        evidence["task-start"] = _s(when)
    failed = next((t for t in tasks if _status_for(t, name) in _mgmt.TASK_FAILED), None)
    if failed is None:
        if _status_for(newest, name) == "in progress":
            return not_installed or _result(
                "last_install", "warn",
                "A policy installation on %s is still running (started %s)." % (name, when or "?"),
                title="Policy installation on %s is still running" % name, evidence=evidence,
                fix=["Wait for it to finish (SmartConsole > Tasks), then run preflight again"])
        return not_installed or _result(
            "last_install", "pass",
            "The last policy installation on %s succeeded%s." % (
                name, " (%s)" % when if when else ""), evidence=evidence)

    start = _mgmt.task_start_posix(failed)
    f_status = _status_for(failed, name)
    f_when = _mgmt.api_date_text(failed.get("start-time")) or "?"
    said = "\n".join(_task_errors(failed, name)) or None
    outcome = {kind: _installed_since(g, kind, start) for kind, _label in _TYPES}
    ok = [label for kind, label in _TYPES if outcome[kind] is True]
    bad = [(kind, label) for kind, label in _TYPES if outcome[kind] is False]
    evidence["failed-task"] = _s(failed.get("task-name") or failed.get("task-id"))
    evidence["failed-task-start"] = _s(f_when)
    evidence["failed-task-status"] = _s(f_status)
    fix = ["Fix the rule named in the message (for unsupported Workforce AI data types see "
           "sk116272)", _INSTALL_RETRY_FIX]
    if ok and bad:
        kind, label = bad[0]
        date = getattr(g, "%s_policy_installation_date" % kind, None) or "an earlier date"
        evidence["not-installed"] = label
        return _result(
            "last_install", "fail",
            "%s installed but %s did not. The gateway is still enforcing the %s policy "
            "installed on %s; rule changes made since then are not live."
            % (" and ".join(ok), label, label, date),
            title="Last policy install on %s partly failed" % name, blocking=False,
            evidence=evidence, fix=fix, server_said=said)
    if bad:
        dates = ["the %s policy installed on %s" % (
            label, getattr(g, "%s_policy_installation_date" % kind, None) or "an earlier date")
            for kind, label in bad]
        evidence["not-installed"] = ", ".join(label for _k, label in bad)
        return _result(
            "last_install", "fail",
            "The policy installation on %s started %s ended as '%s' and installed nothing. "
            "The gateway is still enforcing %s; rule changes made since then are not live."
            % (name, f_when, f_status, " and ".join(dates)),
            title="Last policy install on %s failed" % name, blocking=False,
            evidence=evidence, fix=fix, server_said=said)
    if len(ok) == len(_TYPES):
        return not_installed or _result(
            "last_install", "pass",
            "A policy installation on %s failed (%s), but both policies were installed again "
            "afterwards." % (name, f_when), evidence=evidence)
    # The installation dates are unknown: say what the task says.
    if failed is newest:
        return _result(
            "last_install", "fail",
            "The last policy installation on %s (started %s) ended as '%s': part or all of the "
            "policy was not installed, so the gateway may still be enforcing an older policy; "
            "rule changes made since then may not be live." % (name, f_when, f_status),
            title="Last policy install on %s %s" % (
                name, "partly failed" if f_status == "partially succeeded" else "failed"),
            blocking=False, evidence=evidence, fix=fix, server_said=said)
    return not_installed or _result(
        "last_install", "pass",
        "The last policy installation on %s succeeded%s (an earlier one, started %s, failed)."
        % (name, " (%s)" % when if when else "", f_when), evidence=evidence)


_WORKFORCE_NOTE = ("Workforce AI Security (Access Control, web AI apps) is separate from AI "
                   "Agent Security (developer APIs, this demo)")


def _check_workforce(gw: Any) -> CheckResult:
    on = getattr(gw, "workforce_ai", None)
    if on is None:
        return _result("workforce_ai", "skip",
                       "The gateway does not report Workforce AI Security. %s." % _WORKFORCE_NOTE)
    if on:
        return _result("workforce_ai", "pass",
                       "Workforce AI Security is on. %s." % _WORKFORCE_NOTE,
                       evidence=_evidence(workforce_ai=True))
    return _result("workforce_ai", "warn",
                   "Workforce AI Security is off. %s; this demo does not need it." % _WORKFORCE_NOTE,
                   evidence=_evidence(workforce_ai=False),
                   fix=["Optional, not needed for this demo: SmartConsole > %s > General "
                        "Properties > Network Security > Workforce AI Security (needs Content "
                        "Awareness)" % gw.name])


# --------------------------------------------------------------------------- run


def _link_install_and_tls(checks: List[CheckResult], gw: Any) -> None:
    """A failed Access Control install explains traffic that is not decrypted although
    HTTPS Inspection is on (it is installed with the Access Control policy)."""
    li = next((c for c in checks if c.id == "last_install"), None)
    tls = next((c for c in checks if c.id == "tls_path"), None)
    if li is None or tls is None or li.status != "fail" or tls.fixable != "https-rule":
        return
    if "Access Control" not in (li.evidence.get("not-installed") or "Access Control"):
        return
    tls.fix = _uniq(["The last Access Control policy installation on %s did not succeed (see "
                     "'%s'): HTTPS Inspection changes are installed with the Access Control "
                     "policy, so they are not active yet. Fix that install first"
                     % (getattr(gw, "name", "the gateway"), li.title)] + list(tls.fix))


def _error_result(cid: str, err: AiguardError, *, blocking: bool) -> CheckResult:
    data = err.to_dict()
    detail = "Could not run this check: %s" % data.get("what")
    if data.get("server_said"):
        detail += " (server said: %s)" % data["server_said"]
    return _result(cid, "fail" if blocking else "warn", detail, blocking=blocking,
                   evidence=_evidence(code=data.get("code")),
                   fix=list(data.get("fix") or []) or ["Check the log line for details"])


def check_last_install(client: Any, gw: Any, *, log: Any = None) -> CheckResult:
    """Only the ``last_install`` check (read-only), e.g. right before a demo run: the same
    result :func:`run_preflight` gives for it. Never raises for a failed check (a
    management error becomes a warning); the result is logged."""
    log = log if log is not None else (getattr(client, "log", None) or _NullLog())
    try:
        res = _check_last_install(client, gw, _commands(client))
    except AiguardError as exc:
        res = _error_result("last_install", exc, blocking=False)
        if exc.log_line is not None:
            res.log_line = exc.log_line
    line = log.event(_LEVEL.get(res.status, "INFO"), "preflight", "%s %s" % (res.id, res.status),
                     detail=res.detail, evidence=res.evidence or None, fix=res.fix or None,
                     server_said=res.server_said)
    if res.log_line is None:
        res.log_line = line or None
    return res


def run_preflight(client: Any, gw: Any, *, probe_hosts: Sequence[str] = DEFAULT_PROBE_HOSTS,
                  ca_file: Optional[str] = None, local_ip: Optional[str] = None,
                  log: Any = None, probe_endpoints: Optional[Mapping[str, Any]] = None,
                  package: Optional[str] = None, timeout: float = 10,
                  progress_cb: Optional[Callable[[str, str, str], None]] = None
                  ) -> PreflightReport:
    """Run the twelve checks for gateway ``gw`` (a :class:`~aiguard.gateways.GatewayInfo`).

    ``probe_hosts``: provider hosts for ``tls_path`` (``host`` or ``host:port``).
    ``ca_file``: extra CA (PEM) trusted for the provider handshake (the gateway's
    outbound CA). ``local_ip``: this computer's source IP towards the providers.
    ``probe_endpoints``: optional ``{host: (ip, port)}`` / ``{host: "https://ip:port"}``
    overrides (labs, tests). ``package``: policy package to check instead of the
    gateway's own. ``progress_cb(check_id, status, detail)`` after each check.

    Never raises for a failed check; only programming errors escape (the engine wraps
    them). Each check is logged; ``CheckResult.log_line`` points at its line.
    """
    log = log if log is not None else (getattr(client, "log", None) or _NullLog())
    t0 = time.monotonic()
    hosts = [str(h).strip() for h in (probe_hosts or DEFAULT_PROBE_HOSTS) if str(h).strip()]
    log.info("preflight", "start", gateway=gw.name, probe_hosts=hosts, local_ip=local_ip,
             ca_file=str(ca_file) if ca_file else None)
    if not getattr(gw, "detailed", False) and not getattr(gw, "detail_error", None):
        try:
            gw = _gateways.detail(client, gw, log=log)
        except AiguardError as exc:
            log.warn("preflight", "could not read gateway details", gateway=gw.name,
                     error=exc.what)
    cmds = _commands(client)
    checks: List[CheckResult] = []

    def run(cid: str, fn: Callable[[], CheckResult], *, blocking_on_error: bool = False) -> None:
        try:
            res = fn()
        except AiguardError as exc:
            res = _error_result(cid, exc, blocking=blocking_on_error)
            if exc.log_line is not None:
                res.log_line = exc.log_line
        line = log.event(_LEVEL.get(res.status, "INFO"), "preflight",
                         "%s %s" % (res.id, res.status), detail=res.detail,
                         blocking=res.blocking if res.status == "fail" else None,
                         evidence=res.evidence or None, fix=res.fix or None,
                         fixable=res.fixable)
        if res.log_line is None:
            res.log_line = line or None
        checks.append(res)
        if progress_cb is not None:
            try:
                progress_cb(res.id, res.status, res.detail)
            except Exception as cb_exc:  # noqa: BLE001 - a UI callback must not break preflight
                log.debug("preflight", "progress callback failed", error=repr(cb_exc))

    run("api_write", lambda: _check_api_write(client, cmds))
    run("api_version", lambda: _check_api_version(client))
    run("ai_support", lambda: _check_ai_support(client, cmds))
    run("gw_version", lambda: _check_gw_version(gw))
    run("tp_mode", lambda: _check_tp_mode(gw))
    run("https_gw", lambda: _check_https_gw(gw))
    run("outbound_ca", lambda: _check_outbound_ca(client, gw, cmds))
    https_on = any(c.id == "https_gw" and c.status == "pass" for c in checks)
    run("tls_path", lambda: _check_tls_path(hosts, ca_file=ca_file, timeout=timeout,
                                            overrides=probe_endpoints, https_on=https_on,
                                            gw=gw, local_ip=local_ip, log=log),
        blocking_on_error=True)
    run("client_path", lambda: _check_client_path(gw, local_ip))
    run("package", lambda: _check_package(client, gw, package), blocking_on_error=True)
    run("last_install", lambda: _check_last_install(client, gw, cmds))
    run("workforce_ai", lambda: _check_workforce(gw))
    _link_install_and_tls(checks, gw)

    report = PreflightReport(gateway=gw.name, checks=checks, created_at=_now(),
                             local_ip=local_ip, probe_hosts=hosts,
                             ms=int((time.monotonic() - t0) * 1000))
    log.event("INFO" if report.ok else "WARN", "preflight", "done: %s" % report.summary_line(),
              gateway=gw.name, ok=report.ok,
              blocking=[c.id for c in report.blocking()] or None,
              fixable=report.fixable() or None, ms=report.ms)
    return report
