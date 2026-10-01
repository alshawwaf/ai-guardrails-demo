"""Shared orchestration for the CLI and the web console (spec 8).

A :class:`Session` holds one demo run: the Management API connection, the chosen
gateway, preflight, plan / apply / rollback, the AI Agent Security key, and the
prompts sent through the gateway with their verdicts.

Rules every method follows:

* Everything is logged to ``Session.log`` (a :class:`~aiguard.runlog.RunLog`).
* Only :class:`~aiguard.errors.AiguardError` (and subclasses) are raised. Anything
  unexpected is logged with its traceback at DEBUG and re-raised as
  ``AiguardError(code="aiguard.internal")``. ``KeyboardInterrupt`` passes through so
  the CLI can discard the open session and exit 130.
* One operation at a time: a re-entrant lock serialises the methods that talk to a
  server; a second thread gets ``AiguardError(code="engine.busy")`` after
  ``busy_timeout`` seconds instead of piling up. :meth:`Session.status`,
  :meth:`Session.summary` and :meth:`Session.diagnose` never take the lock (a web
  page can poll them while a job runs) and never raise. :meth:`Session.close` called
  while another thread runs an operation does not log out under it: the close is
  done when that operation ends. :attr:`Session.busy` names the running operation.
* An apply cut short from another thread (:meth:`Session.discard` at shutdown stops it
  before its next change or its publish; :meth:`Session.close` waits for it) marks its
  rollback point "publish-unknown" while it is still "recorded", so a process that dies
  then leaves an honest, still undoable status. The apply overwrites it when it finishes.
* The Management API session is kept alive: before an operation that needs it, a
  session idle for more than ``keepalive_after`` seconds gets a ``keepalive``; a session
  the server already dropped is logged in again with the same credentials (no change is
  ever pending between operations). :meth:`Session.keepalive` does the same for a
  timer (the web console's reaper) and never raises.
* Secrets (Management API key / password / sid, the AI Agent Security key, provider
  keys) live in memory only, are registered with :mod:`aiguard.redact`, and are
  forgotten again by :meth:`Session.close`. :meth:`Session.status` and every dict
  returned are display-safe.

Optional constructor arguments beyond the spec (all keyword-only, all optional):
``provider_ca_file`` (outbound CA for the provider / Lakera TLS checks),
``provider_base_urls`` (``{"openai": "https://host:port"}``: send prompts somewhere
else, e.g. a test server), ``probe_endpoints`` (``{host: (ip, port)}`` for preflight's
``tls_path``; derived from ``provider_base_urls`` when not given), ``probe_hosts``,
``local_ip`` (pin this computer's source IP as the gateway sees it, e.g. behind NAT or in
Docker; default: the ``AIGUARD_LOCAL_IP`` environment variable, else detected),
``lakera_url`` / ``lakera_ca_file``
(direct Lakera calls), ``mgmt_timeout``, ``probe_timeout``, ``tls_timeout``,
``task_poll`` (seconds between ``show-task`` polls), ``correlate_window_s``,
``busy_timeout``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import ipaddress
import os
import re
import threading
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

from . import __version__
from . import correlate as _correlate
from . import gateways as _gateways
from . import lakera as _lakera
from . import mgmt as _mgmt
from . import paths as _paths
from . import plan as _plan
from . import preflight as _preflight
from . import probe as _probe
from . import redact as _redact
from . import report as _report
from . import scenes as _scenes
from .errors import AiguardError, ConnectError, LakeraError, MgmtApiError, PlanError
from .gateways import GatewayInfo
from .mgmt import MgmtClient, release_for_api
from .plan import ApplyResult, Plan, PlanOptions
from .preflight import PreflightReport
from .probe import ProbeResult
from .runlog import RunLog
from .state import State

__all__ = ["Session", "GUARD_KEY_RE", "GUARD_KEY_WARNING", "PORTAL_FIX"]

GUARD_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
GUARD_KEY_WARNING = ("Check Point expects the Guard API key (64 hex characters) from Check Point "
                     "Portal > AI Security > AI Guardrails > Settings > API Access. A Platform "
                     "API key will not work.")
PORTAL_FIX = [
    "Check Point Portal > AI Security > AI Guardrails > Settings > API Access > Guard API keys: "
    "create a Guard API key and copy it (64 hex characters; a Platform API key will not work)",
    "Check Point Portal > AI Security > AI Guardrails > Projects: copy the project ID of a "
    "project that has a policy assigned (the default policy is fine)",
    "The management server must reach the internet and be connected to the Check Point Portal",
]
PORTAL_CONNECTIVITY_FIX = [
    "The management server must reach the internet and be connected to the Check Point Portal: "
    "SmartConsole > Manage & Settings > Integrations & Services (Infinity Portal connection), "
    "and check the management server's proxy / DNS settings",
    "Then set the key again",
]
_CONNECTIVITY_RE = re.compile(r"(?i)\b(connect\w*|portal|cloud|timeout|timed out|unreachable|"
                              r"resolve|dns|proxy|network|internet)\b")
LOGS_PERMISSION_FIX = [
    "SmartConsole > Manage & Settings > Permissions & Administrators > Permission Profiles > "
    "(profile) > Monitoring and Logging: allow Logs (read the logs of the gateways)",
    "Publish, then connect again",
]
KEEPALIVE_AFTER = 240.0   # seconds without a management call before a keepalive is sent
AI_TEST_COMMANDS = _preflight.AI_TEST_COMMANDS
WILL_VALIDATE_LATER = "Will be validated after the profile is created"
# Section 10: UNKNOWN (no conclusive reply) becomes BLOCKED only with one of these logs.
UPGRADE_ACTIONS = frozenset({"prevent", "prevented", "drop", "dropped", "block", "blocked"})

ProgressCb = Callable[[str, str, Optional[int], str], None]


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_provider(provider: Any) -> str:
    return str(provider or "openai").strip().lower()


LOCAL_IP_ENV = "AIGUARD_LOCAL_IP"


def _valid_ip(value: Any, log: Optional[RunLog] = None) -> Optional[str]:
    """An IP address as text, or None (a bad value is logged and ignored)."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        if log is not None:
            log.warn("engine", "ignoring an invalid local IP address",
                     value=_redact.redact(text)[:60], hint="set %s to this computer's IP as "
                     "the gateway sees it" % LOCAL_IP_ENV)
        return None


class Session(object):
    """One demo run shared by the CLI and the web console. See the module docstring."""

    def __init__(self, *, log: Optional[RunLog] = None, home: Optional[Union[str, Path]] = None,
                 state: Optional[State] = None, provider_ca_file: Optional[str] = None,
                 provider_base_urls: Optional[Mapping[str, str]] = None,
                 probe_endpoints: Optional[Mapping[str, Any]] = None,
                 probe_hosts: Optional[Sequence[str]] = None, local_ip: Optional[str] = None,
                 lakera_url: Optional[str] = None, lakera_ca_file: Optional[str] = None,
                 mgmt_timeout: float = 60, probe_timeout: float = 30, tls_timeout: float = 10,
                 task_poll: Optional[float] = None, correlate_window_s: int = 180,
                 busy_timeout: float = 2.0) -> None:
        self.home: Path = _paths.aiguard_home(home if home is not None else
                                              (getattr(log, "home", None) if log is not None else None))
        self._own_log = log is None
        self.log: RunLog = log if log is not None else RunLog(home=self.home)
        self.state: State = state if state is not None else State(_paths.state_path(self.home))

        self.client: Optional[MgmtClient] = None
        self.gateways: List[GatewayInfo] = []
        self.gateway: Optional[GatewayInfo] = None
        self.preflight: Optional[PreflightReport] = None
        self.plan: Optional[Plan] = None
        self.last_apply: Optional[ApplyResult] = None
        self.results: List[ProbeResult] = []
        self.lakera: Dict[str, Any] = self._empty_lakera()
        self.moderation_enabled: Optional[bool] = None
        self.local_ip: Optional[str] = _valid_ip(local_ip if local_ip else
                                                 os.environ.get(LOCAL_IP_ENV), self.log)
        # Pinned (argument or AIGUARD_LOCAL_IP): the address the gateway sees, which can
        # differ from a probe's own source address behind NAT or in Docker.
        self.local_ip_pinned: bool = self.local_ip is not None
        self.correlate_error: Optional[Dict[str, Any]] = None   # last log-matching failure
        self.keepalive_after: float = KEEPALIVE_AFTER
        self.enforcement: Optional[Dict[str, Any]] = None
        self.report_path: Optional[Path] = None
        self.report_json_path: Optional[Path] = None

        # configuration (public attributes; the CLI / web may set them directly)
        self.provider_ca_file: Optional[str] = str(provider_ca_file) if provider_ca_file else None
        self.provider_base_urls: Dict[str, str] = {
            _norm_provider(k): str(v) for k, v in dict(provider_base_urls or {}).items() if v}
        self.probe_endpoints: Dict[str, Any] = dict(probe_endpoints or {})
        self.probe_hosts: Tuple[str, ...] = tuple(probe_hosts or _preflight.DEFAULT_PROBE_HOSTS)
        self.lakera_url: str = lakera_url or _lakera.DEFAULT_URL
        self.lakera_ca_file: Optional[str] = str(lakera_ca_file) if lakera_ca_file else None
        self.models: Dict[str, str] = {}
        self.mgmt_timeout = float(mgmt_timeout)
        self.probe_timeout = float(probe_timeout)
        self.tls_timeout = float(tls_timeout)
        self.task_poll = task_poll
        self.correlate_window_s = int(correlate_window_s)
        self.busy_timeout = float(busy_timeout)

        # secrets: memory only
        self._lakera_key: Optional[str] = None
        self._provider_keys: Dict[str, str] = {}
        self._direct: Optional[Dict[str, Any]] = None   # {"key", "project_id", "url", "ca_file"}
        self._secrets: List[str] = []
        self._secret_owner = object()   # holds this session's secrets in aiguard.redact

        self._lock = threading.RLock()
        self._busy: Optional[str] = None
        self._depth = 0                 # nesting of _operation in the thread holding the lock
        self._close_pending = False     # close() was called while an operation ran
        # The apply in progress: its rollback point id (once saved) and a stop flag that
        # discard() sets, so a discarded session is not published afterwards.
        self._apply_rid: Optional[str] = None
        self._applying = False
        self._stop_apply = threading.Event()
        self._correlated: set = set()
        self._diag_logged: Dict[str, Tuple[str, ...]] = {}
        self.log.info("engine", "session ready", home=str(self.home), state=str(self.state.path))

    # ------------------------------------------------------------------ plumbing

    @staticmethod
    def _empty_lakera() -> Dict[str, Any]:
        return {"project_id": None, "validated": False, "validated_by": None, "message": "",
                "masked_key": "", "format_ok": False, "warnings": []}

    @contextlib.contextmanager
    def _operation(self, name: str) -> Iterator[None]:
        if not self._lock.acquire(timeout=max(0.0, self.busy_timeout)):
            err = AiguardError(
                "Another operation is still running (%s)" % (self._busy or "busy"),
                code="engine.busy",
                why="The demo session runs one operation at a time.",
                fix=["Wait for it to finish, then try again"],
                state="Nothing was started.", details={"requested": name, "running": self._busy})
            err.log_line = self.log.event("WARN", "engine", err.what, requested=name)
            raise err
        previous = self._busy
        self._busy = name
        self._depth += 1
        try:
            yield
        except AiguardError as err:
            if err.log_line is None:
                err.log_line = self.log.exception(err, "engine")
            raise
        except Exception as exc:  # noqa: BLE001 - spec 8: only AiguardError leaves the engine
            self.log.debug("engine", "unexpected error during %s" % name,
                           traceback="".join(traceback.format_exception(
                               type(exc), exc, exc.__traceback__)).rstrip())
            err = AiguardError(
                "Unexpected error during %s" % name, code="aiguard.internal",
                why="%s: %s" % (type(exc).__name__, _redact.redact(str(exc))[:300]),
                fix=["Send the log file %s to the demo owner" % self.log.path],
                state="The operation stopped. See the log for what was done before the error.",
                details={"operation": name, "type": type(exc).__name__})
            err.log_line = self.log.exception(err, "engine")
            raise err from exc
        finally:
            self._depth -= 1
            self._busy = previous
            pending = self._close_pending and self._depth == 0
            if pending:
                self._close_pending = False
                try:
                    self._close_now()   # a close() that came while this operation ran
                except Exception:  # noqa: BLE001 - close never raises
                    pass
            self._lock.release()

    @property
    def busy(self) -> Optional[str]:
        """Name of the operation running right now (``"apply"``, ``"connect"`` ...), or
        None. Read-only and lock-free (for a web page or a store that polls it)."""
        return self._busy

    def _remember_secret(self, value: Optional[str], *, keep_tail: bool = True) -> None:
        if value:
            text = str(value)
            _redact.register_secret(text, owner=self._secret_owner, keep_tail=keep_tail)
            if text not in self._secrets:
                self._secrets.append(text)

    def _need_client(self) -> MgmtClient:
        client = self.client
        if client is not None and not client.logged_in and getattr(client, "session_expired",
                                                                   False):
            self._renew(client)
        elif client is not None and client.logged_in:
            self._keepalive_if_idle(client)
        if client is not None and not client.logged_in and getattr(client, "session_expired",
                                                                   False):
            raise AiguardError(
                "The management session ended", code="mgmt.session_expired",
                why="The management server ended the session (idle for too long, logged out, "
                    "or disconnected by an administrator in SmartConsole), and aiguard could "
                    "not log in again.",
                fix=["Connect again: aiguard setup (web console: Connect)"],
                state="Not connected. Nothing was changed.")
        if self.client is None or not self.client.logged_in:
            raise AiguardError(
                "Not connected to a management server", code="engine.not_connected",
                why="This step needs a Management API session.",
                fix=["Connect first: aiguard setup (web console: Connect)"],
                state="Nothing was changed.")
        return self.client

    def _keepalive_if_idle(self, client: MgmtClient) -> None:
        idle = client.idle_seconds() if callable(getattr(client, "idle_seconds", None)) else None
        if idle is None or idle < self.keepalive_after:
            return
        try:
            client.keepalive()
            self.log.debug("engine", "keepalive sent", idle_s=int(idle))
        except MgmtApiError as exc:
            if exc.code == "mgmt.session_expired":
                self._renew(client)
            else:
                self.log.warn("engine", "keepalive failed", error=exc.what, code=exc.code)
        except AiguardError as exc:
            self.log.warn("engine", "keepalive failed", error=exc.what, code=exc.code)

    def _renew(self, client: MgmtClient) -> None:
        """The server dropped the session (between operations: nothing is pending). Log in
        again with the same credentials, or leave the session disconnected."""
        if not (callable(getattr(client, "can_relogin", None)) and client.can_relogin()):
            return
        self.log.info("engine", "the management session had ended; logging in again",
                      server=client.server, domain=client.domain)
        try:
            client.relogin()
        except AiguardError as exc:
            self.log.warn("engine", "could not log in again; connect again", error=exc.what,
                          code=exc.code)
            return
        self._remember_secret(client.sid)

    def keepalive(self) -> bool:
        """Keep the management session alive (for a timer, e.g. the web console's reaper).
        Never raises and never waits for a running operation (which keeps the session busy
        anyway). True when the session is alive afterwards."""
        if not self._lock.acquire(blocking=False):
            return bool(self.client is not None and self.client.logged_in)
        try:
            client = self.client
            if client is None:
                return False
            if client.logged_in:
                self._keepalive_if_idle(client)
            elif getattr(client, "session_expired", False):
                self._renew(client)
            return bool(self.client is not None and self.client.logged_in)
        except Exception as exc:  # noqa: BLE001 - a timer helper never raises
            self.log.debug("engine", "keepalive failed", error=repr(exc))
            return False
        finally:
            self._lock.release()

    def _need_gateway(self) -> GatewayInfo:
        if self.gateway is None:
            raise AiguardError(
                "No gateway was chosen", code="engine.no_gateway",
                why="Preflight, the plan and the demo work on one gateway.",
                fix=["Pick a gateway: aiguard setup or --gateway <name> (web console: Connect > "
                     "Gateway)"],
                state="Nothing was changed.")
        return self.gateway

    def _reset_gateway_state(self) -> None:
        self.gateways = []
        self.gateway = None
        self.preflight = None
        self.plan = None
        self.last_apply = None
        self.enforcement = None

    def _endpoints(self) -> Dict[str, Any]:
        """Preflight ``probe_endpoints``: explicit ones, plus the provider base URLs."""
        out: Dict[str, Any] = {}
        for provider, url in self.provider_base_urls.items():
            host = (_probe.PROVIDERS.get(provider) or {}).get("host")
            if not host:
                continue
            try:
                parts = urlsplit(url)
                if parts.hostname:
                    out[host] = (parts.hostname, int(parts.port or 443))
            except ValueError:
                continue
        out.update(self.probe_endpoints)
        return out

    def _local_ip(self) -> Optional[str]:
        """This computer's source IP towards the providers (UDP connect, no packet sent)."""
        if self.local_ip:
            return self.local_ip
        hosts = list(self.probe_hosts) or list(_preflight.DEFAULT_PROBE_HOSTS)
        _name, target, port = _preflight._endpoint(hosts[0], self._endpoints())
        ip = _probe.local_ip_for(target, port)
        if ip:
            self.local_ip = ip
            self.log.info("engine", "local address towards the providers", local_ip=ip,
                          via="%s:%d" % (target, port))
        return ip

    # ------------------------------------------------------------------ connection

    def _connection_info(self, summary: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        c = self.client
        s = dict(summary or (c.summary() if c is not None else {}))
        api = s.get("api_version") or (c.api_version if c else None)
        domains = list(s.get("domains") or [])
        if c is not None and c.server_type == "MDS" and not domains:
            domains = [str(d.get("name")) for d in c.list_domains() if d.get("name")]
        server_type = s.get("server_type") or (c.server_type if c else "unknown")
        domain = s.get("domain") if "domain" in s else (c.domain if c else None)
        # An MDS login without a domain works in "System Data", which is not a domain with
        # gateways: domain None plus system_data True.
        system_data = bool(s.get("system_data")) or (
            isinstance(domain, str) and domain.strip().lower() == "system data")
        if system_data:
            domain = None
        out = {
            "server": s.get("server") or (c.server if c else None),
            "port": s.get("port") or (c.port if c else None),
            "server_type": server_type,
            "api_version": api,
            "release": s.get("release") or release_for_api(api),
            "domain": domain,
            "system_data": system_data,
            "fingerprint_sha1": s.get("fingerprint_sha1"),
            "fingerprint_sha256": s.get("fingerprint_sha256"),
            "ms": s.get("ms"),
            "read_only": bool(s.get("read_only")),
            "domains": domains,
            "user": s.get("user"),
            "auth": s.get("auth"),
            "local_ip": s.get("local_ip"),
            "reported_port": s.get("reported_port"),
            "session_timeout": s.get("session_timeout"),
        }
        return _redact.redact_obj(out)

    def connect(self, server: str, *, port: int = 443, api_key: Optional[str] = None,
                user: Optional[str] = None, password: Optional[str] = None,
                domain: Optional[str] = None, ca_file: Optional[str] = None,
                server_name: Optional[str] = None, remember_ca: bool = True) -> dict:
        """Log in to the management server. Returns server_type, api_version, release,
        domain (None plus ``system_data`` True for an MDS login in System Data),
        fingerprint_sha1, fingerprint_sha256, ms, read_only, domains (MDS) plus server,
        port, user, auth.

        ``remember_ca`` False: do not save ``ca_file`` as the last-used CA file (a
        temporary file, e.g. one the web console uploaded); the CA file remembered for
        this server is kept, and forgotten when the server changes."""
        with self._operation("connect"):
            address = str(server or "").strip()
            if not address:
                raise ConnectError("No management server address was given",
                                   code="connect.no_server",
                                   fix=["Enter the management server's IP address or name"],
                                   state="No connection was made.")
            try:
                port_n = int(port or 443)
                if not 0 < port_n < 65536:
                    raise ValueError
            except (TypeError, ValueError):
                raise ConnectError("Invalid port '%s'" % _redact.redact(str(port))[:20],
                                   code="connect.bad_port",
                                   fix=["Use the Gaia portal port (443 by default)"],
                                   state="No connection was made.") from None
            self._remember_secret(api_key)
            self._remember_secret(password, keep_tail=False)
            old = self.client
            if old is not None:
                old.logout()
                self.client = None
            self.log.info("engine", "connecting", server=address, port=port_n,
                          auth="api-key" if api_key else "password", user=user, domain=domain,
                          ca_file=str(ca_file) if ca_file else None, server_name=server_name)
            client = MgmtClient(address, port_n, ca_file=ca_file, server_name=server_name,
                                timeout=self.mgmt_timeout, log=self.log)
            if self.task_poll is not None:
                client.task_poll = float(self.task_poll)
            try:
                summary = client.login(api_key=api_key or None, user=user or None,
                                       password=password or None, domain=domain or None)
            except AiguardError as exc:
                # A login that got half way (e.g. System Data, then an unknown MDS domain)
                # must not leave a session open on the server: this client is not kept.
                if client.logged_in:
                    client.logout()
                    exc.state = "Logged out again. Nothing was changed."
                client.forget_secrets()
                raise
            self._remember_secret(client.sid)
            if old is None or old.server != client.server or old.domain != client.domain:
                self._reset_gateway_state()
            self.client = client
            try:
                last: Dict[str, Any] = {
                    "server": address, "port": port_n, "domain": client.domain,
                    "server_name": server_name or None,
                    "auth": "api-key" if api_key else "password",
                    "user": None if api_key else user}
                if remember_ca:
                    last["ca_file"] = str(ca_file) if ca_file else None
                elif str(self.state.last().get("server") or "") != address:
                    last["ca_file"] = None   # the remembered CA belongs to another server
                self.state.set_last(**last)
            except (ValueError, TypeError, OSError) as exc:
                self.log.warn("engine", "could not save the last-used connection", error=str(exc))
            out = self._connection_info(summary)
            self.log.info("engine", "connected", server_type=out["server_type"],
                          api_version=out["api_version"], release=out["release"],
                          domain=out["domain"], read_only=out["read_only"])
            return out

    def select_domain(self, domain: str) -> dict:
        """MDS: work in another domain with the same login (no extra login when the
        server supports ``login-to-domain``). Returns the same dict as :meth:`connect`."""
        with self._operation("select domain"):
            client = self._need_client()
            client.switch_domain(str(domain or "").strip())
            self._remember_secret(client.sid)
            self._reset_gateway_state()
            try:
                self.state.set_last(domain=client.domain)
            except (ValueError, TypeError, OSError) as exc:
                self.log.warn("engine", "could not save the last-used domain", error=str(exc))
            return self._connection_info()

    def list_domains(self) -> List[str]:
        """Domain names on an MDS (``[]`` on a Security Management Server)."""
        with self._operation("list domains"):
            client = self._need_client()
            return [str(d.get("name")) for d in client.list_domains() if d.get("name")]

    def discover(self) -> List[GatewayInfo]:
        """Security gateways and clusters in the current domain."""
        with self._operation("discover"):
            client = self._need_client()
            self.gateways = _gateways.discover(client, log=self.log)
            return list(self.gateways)

    def select_gateway(self, name: str) -> GatewayInfo:
        """Choose the demo gateway (by name, case-insensitive) and read its details."""
        with self._operation("select gateway"):
            client = self._need_client()
            wanted = str(name or "").strip()
            if not self.gateways:
                self.gateways = _gateways.discover(client, log=self.log)
            match = ([g for g in self.gateways if g.name == wanted]
                     or [g for g in self.gateways if g.name.lower() == wanted.lower()])
            if not wanted or not match:
                names = ", ".join(g.name for g in self.gateways) or "none"
                raise AiguardError(
                    "Gateway '%s' was not found" % wanted if wanted else "No gateway was chosen",
                    code="engine.gateway_not_found",
                    why="The management server (this domain) lists these gateways and clusters: "
                        "%s." % names,
                    fix=["Pick one of: %s" % names,
                         "On a Multi-Domain Server, connect to the domain that manages the "
                         "gateway"],
                    state="Nothing was changed.")
            gw = _gateways.detail(client, match[0], log=self.log)
            if self.gateway is None or self.gateway.name != gw.name:
                self.preflight = None
                self.plan = None
                self.last_apply = None
                self.enforcement = None
            self.gateway = gw
            self.gateways = [gw if g.name == gw.name else g for g in self.gateways]
            try:
                self.state.set_last(gateway=gw.name)
            except (ValueError, TypeError, OSError) as exc:
                self.log.warn("engine", "could not save the last-used gateway", error=str(exc))
            self.log.info("engine", "gateway selected", gateway=gw.name, version=gw.version,
                          https_inspection=gw.https_inspection,
                          threat_prevention_mode=gw.threat_prevention_mode)
            return gw

    # ------------------------------------------------------------------ preflight

    def run_preflight(self, probe_hosts: Optional[Sequence[str]] = None, *,
                      package: Optional[str] = None,
                      progress_cb: Optional[Callable[[str, str, str], None]] = None
                      ) -> PreflightReport:
        """Run the preflight checks for the chosen gateway (spec 6)."""
        with self._operation("preflight"):
            client = self._need_client()
            gw = self._need_gateway()
            report = _preflight.run_preflight(
                client, gw, probe_hosts=tuple(probe_hosts or self.probe_hosts),
                ca_file=self.provider_ca_file, local_ip=self._local_ip(), log=self.log,
                probe_endpoints=self._endpoints(), package=package, timeout=self.tls_timeout,
                progress_cb=progress_cb)
            self.preflight = report
            return report

    def check_last_install(self) -> _preflight.CheckResult:
        """Run only preflight's ``last_install`` check for the chosen gateway (read-only),
        e.g. right before a demo run or after an install: a partial install (Access Control
        failed, Threat Prevention installed) leaves the gateway on an older policy without
        saying so. The result also replaces that check in :attr:`preflight` when a report
        exists. Raises only when not connected or no gateway was chosen."""
        with self._operation("check the last policy install"):
            client = self._need_client()
            gw = self._need_gateway()
            res = _preflight.check_last_install(client, gw, log=self.log)
            report = self.preflight
            if report is not None:
                report.checks = [res if c.id == res.id else c for c in report.checks]
            return res

    # ------------------------------------------------------------------ keys

    def _ai_test_command(self, client: MgmtClient) -> Optional[str]:
        cmds = client.commands()
        if not cmds:
            return AI_TEST_COMMANDS[0]   # unknown list: try the documented name
        return next((c for c in AI_TEST_COMMANDS if c in cmds), None)

    def set_lakera(self, api_key: str, project_id: str, *, direct_check: bool = False) -> dict:
        """Set the AI Agent Security (Guard) API key and project, and validate them.

        1. Format: 64 hex characters (else a warning, not an error).
        2. Connected and the server has the AI key test command: the management server
           tests the key and project. ``success: false`` raises :class:`LakeraError`;
           a server that rejects the ``api-key`` parameter keeps the key unvalidated
           ("Will be validated after the profile is created").
        3. ``direct_check``: :func:`aiguard.lakera.validate` against the Lakera API;
           problems become warnings. Success also enables Lakera categories for
           blocked prompts (``run_prompt(annotate=True)``).

        Returns ``Session.lakera`` (display-safe). On error the previous key is kept.
        """
        with self._operation("set AI key"):
            key = str(api_key or "").strip()
            pid = str(project_id or "").strip()
            if not key:
                raise LakeraError("No AI Agent Security key was given", code="lakera.no_key",
                                  fix=list(PORTAL_FIX[:1]), state="Nothing was changed.")
            if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in key):
                raise LakeraError("The AI Agent Security key contains spaces or control "
                                  "characters", code="lakera.bad_key_format",
                                  fix=["Copy the key again without spaces or line breaks"],
                                  state="Nothing was changed.")
            if not pid:
                raise LakeraError("A project ID is required", code="lakera.no_project",
                                  why="The threat profile tells the gateway which AI Guardrails "
                                      "project (policy) to use.",
                                  fix=list(PORTAL_FIX[1:2]), state="Nothing was changed.")
            if len(pid) > 200 or any(ord(ch) < 0x21 for ch in pid):
                raise LakeraError("Invalid project ID", code="lakera.bad_project",
                                  fix=list(PORTAL_FIX[1:2]), state="Nothing was changed.")
            self._remember_secret(key)
            info: Dict[str, Any] = self._empty_lakera()
            info.update({"project_id": pid, "masked_key": _redact.mask_secret(key),
                         "format_ok": bool(GUARD_KEY_RE.match(key))})
            if not info["format_ok"]:
                info["warnings"].append(GUARD_KEY_WARNING)
                self.log.warn("engine", "AI key format", warning=GUARD_KEY_WARNING,
                              masked_key=info["masked_key"], length=len(key))

            client = self.client if (self.client is not None and self.client.logged_in) else None
            if client is None:
                info["message"] = ("Not validated yet: connect to the management server and "
                                   "set the key again, or it is checked when the profile is "
                                   "created")
            else:
                command = self._ai_test_command(client)
                if command is None:
                    info["message"] = ("This management server has no AI Agent Security key "
                                       "test (needs R82.20 / Management API 2.2)")
                else:
                    self._test_key_with_management(client, command, key, pid, info)

            direct_ok = False
            if direct_check:
                try:
                    res = _lakera.validate(key, pid, url=self.lakera_url,
                                           ca_file=self.lakera_ca_file or self.provider_ca_file,
                                           log=self.log)
                    direct_ok = True
                    info["direct"] = {"ok": True, "ms": res.get("ms"), "method": res.get("method"),
                                      "detectors": res.get("detectors") or [],
                                      "host": res.get("host")}
                    info["warnings"].extend(res.get("warnings") or [])
                    if not info["validated"]:
                        info["validated"] = True
                        info["validated_by"] = "lakera"
                        info["message"] = "Lakera accepted the key and project"
                except LakeraError as exc:
                    info["direct"] = {"ok": False, "error": exc.what}
                    info["warnings"].append("Direct Lakera check: %s" % exc.what)
                    self.log.warn("engine", "direct Lakera check failed (not blocking)",
                                  error=exc.what, code=exc.code)
            self._lakera_key = key
            if direct_ok:
                # ca_file None: use the session's CA at call time (it can be set later)
                self._direct = {"key": key, "project_id": pid, "url": self.lakera_url,
                                "ca_file": None}
            self.lakera = info
            self.log.info("engine", "AI key set", masked_key=info["masked_key"], project_id=pid,
                          validated=info["validated"], validated_by=info["validated_by"],
                          message=info["message"], format_ok=info["format_ok"])
            return _redact.redact_obj(dict(info))

    def _test_key_with_management(self, client: MgmtClient, command: str, key: str, pid: str,
                                  info: Dict[str, Any]) -> None:
        try:
            reply = client.call(command, {"api-key": key, "project-id": pid})
        except MgmtApiError as exc:
            said = exc.server_said or ""
            low = said.lower()
            if exc.api_code == "generic_err_command_not_found":
                info["message"] = ("This management server has no AI Agent Security key test "
                                   "(needs R82.20 / Management API 2.2)")
                return
            if exc.api_code == "generic_err_invalid_parameter_name" or (
                    "unrecognized parameter" in low and "api-key" in low):
                info["message"] = WILL_VALIDATE_LATER
                self.log.info("engine", "the AI key test does not take api-key; the key is "
                              "checked after the profile is created", command=command)
                return
            if exc.api_code == "generic_err_invalid_parameter" and "api-key" in low:
                raise LakeraError(
                    "Check Point could not validate this AI Agent Security key",
                    code="lakera.rejected_format", server_said=said,
                    why=GUARD_KEY_WARNING, fix=list(PORTAL_FIX),
                    state="The key was not saved. Nothing was changed.") from None
            raise
        if not isinstance(reply, dict) or reply.get("success") is not True:
            message = str((reply or {}).get("message") or "The server reported success: false")
            if _CONNECTIVITY_RE.search(message) and not re.search(
                    r"(?i)invalid|not valid|does not belong|refused|rejected|unauthori", message):
                why = ("The management server could not check the key with the AI Agent Security "
                       "cloud (see Server said): the problem is the connection to the Check Point "
                       "Portal, not necessarily the key.")
                fix = list(PORTAL_CONNECTIVITY_FIX) + list(PORTAL_FIX[:2])
            else:
                why = ("The management server asked the AI Agent Security cloud and the key or "
                       "the project was refused.")
                fix = list(PORTAL_FIX)
            raise LakeraError(
                "Check Point could not validate this AI Agent Security key",
                code="lakera.rejected", server_said=_redact.redact(message),
                why=why, fix=fix, state="The key was not saved. Nothing was changed.",
                details={"command": command, "project_id": pid})
        info["validated"] = True
        info["validated_by"] = "management"
        info["message"] = _redact.redact(str(reply.get("message") or "API key is valid."))

    def set_direct_lakera(self, api_key: Optional[str], project_id: Optional[str] = None, *,
                          url: Optional[str] = None, ca_file: Optional[str] = None,
                          check: bool = False) -> dict:
        """Configure a direct Lakera key (the web console's Settings key) used only to
        label blocked prompts with a category. ``api_key`` empty clears it. ``check``
        validates it first (raises :class:`LakeraError`)."""
        with self._operation("set Lakera key"):
            key = str(api_key or "").strip()
            if not key:
                self._direct = None
                return {"configured": False}
            self._remember_secret(key)
            pid = str(project_id or "").strip()
            target = url or self.lakera_url
            ca = ca_file or self.lakera_ca_file or self.provider_ca_file
            if check:
                if pid:
                    _lakera.validate(key, pid, url=target, ca_file=ca, log=self.log)
                else:
                    _lakera.classify(_lakera.BENIGN_TEXT, key, "", url=target, ca_file=ca,
                                     log=self.log)
            # Only an explicit ca_file is pinned; otherwise the session's CA at call time
            # (the outbound CA is often given after the key, e.g. on the web Preflight page).
            self._direct = {"key": key, "project_id": pid, "url": target, "ca_file": ca_file}
            self.log.info("engine", "direct Lakera key set", masked_key=_redact.mask_secret(key),
                          project_id=pid or None, checked=check)
            return {"configured": True, "masked_key": _redact.mask_secret(key),
                    "project_id": pid or None, "url": target}

    def set_provider_key(self, provider: str, api_key: Optional[str]) -> None:
        """Remember an LLM provider key for this session (memory only). Empty clears it."""
        with self._operation("set provider key"):
            name = _norm_provider(provider)
            _probe.provider_info(name)   # raises AiguardError for an unknown provider
            key = str(api_key or "").strip()
            if not key:
                self._provider_keys.pop(name, None)
                self.log.info("engine", "provider key cleared", provider=name)
                return
            if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in key):
                raise AiguardError("The %s key contains control characters" % name,
                                   code="probe.bad_key",
                                   fix=["Copy the key again without spaces or line breaks"],
                                   state="Nothing was changed.")
            self._remember_secret(key)
            self._provider_keys[name] = key
            self.log.info("engine", "provider key set", provider=name,
                          masked_key=_redact.mask_secret(key))

    def set_provider_ca_file(self, path: Optional[str]) -> None:
        """Trust ``path`` (PEM, e.g. the gateway's outbound CA) for the provider and Lakera
        connections from now on; None stops using it. Takes the operation lock (a running
        preflight or scene reads the current file, so it is never swapped under them:
        ``engine.busy`` after ``busy_timeout``). A direct Lakera key that used the old file
        follows the new one."""
        with self._operation("set the outbound CA"):
            new = str(path) if path else None
            old = self.provider_ca_file
            self.provider_ca_file = new
            direct = self._direct
            if direct is not None and old and direct.get("ca_file") == old:
                direct["ca_file"] = new
            self.log.info("engine", "outbound CA for provider traffic %s" % (
                "set" if new else "cleared"), ca_file=new)

    # ------------------------------------------------------------------ plans

    def build_plan(self, options: PlanOptions) -> Plan:
        """Build (read-only) the change plan. Fills the gateway, ``client_ip`` (for scope
        "client") and the project ID from the session; passes the AI key as a secret."""
        with self._operation("build plan"):
            client = self._need_client()
            opts = dataclasses.replace(options)
            if not (opts.gateway or "").strip() and self.gateway is not None:
                opts.gateway = self.gateway.name
            if (opts.scope or "client").strip().lower() == "client" and not opts.client_ip:
                opts.client_ip = self._local_ip()
            if not opts.lakera_project_id and self.lakera.get("project_id"):
                opts.lakera_project_id = self.lakera["project_id"]
            secrets: Dict[str, str] = {}
            if self._lakera_key:
                secrets["lakera_api_key"] = self._lakera_key
            gw = self.gateway if (self.gateway is not None and
                                  self.gateway.name.lower() == (opts.gateway or "").lower()) else None
            plan = _plan.build_plan(client, opts, secrets=secrets, log=self.log, gateway_info=gw,
                                    home=self.home)
            self.plan = plan
            return plan

    def build_https_plan(self, add_rule: bool = False) -> Plan:
        """Plan for the ``https-inspection`` template (turn HTTPS Inspection on, optional
        inspect rule for this computer)."""
        with self._operation("build HTTPS Inspection plan"):
            client = self._need_client()
            gw = self._need_gateway()
            ip = self._local_ip()
            opts = PlanOptions(gateway=gw.name, template="https-inspection",
                               add_https_rule=bool(add_rule), client_ip=ip,
                               scope="client" if (ip or not add_rule) else "any")
            plan = _plan.build_plan(client, opts, secrets={}, log=self.log, gateway_info=gw,
                                    home=self.home)
            self.plan = plan
            return plan

    def apply(self, approved_plan_id: str, progress_cb: Optional[ProgressCb] = None) -> ApplyResult:
        """Apply the current plan (approval = its plan id). Sets ``moderation_enabled``
        when the moderation step succeeds."""
        with self._operation("apply"):
            client = self._need_client()
            plan = self.plan
            if plan is None:
                raise PlanError("There is no plan to apply", code="engine.no_plan",
                                fix=["Build the plan first (aiguard plan, or Configure in the "
                                     "web console), review it, then approve its id"],
                                state="Nothing was changed.")
            secrets = {"lakera_api_key": self._lakera_key} if self._lakera_key else {}
            self._stop_apply.clear()
            self._apply_rid = None
            self._applying = True
            try:
                res = _plan.apply_plan(client, plan, approved_plan_id=approved_plan_id,
                                       secrets=secrets, progress_cb=progress_cb, log=self.log,
                                       state=self.state, on_rollback_point=self._note_point,
                                       should_stop=self._stop_apply.is_set)
            finally:
                self._applying = False
                self._apply_rid = None
            self.last_apply = res
            if res.moderation_enabled is not None:
                self.moderation_enabled = bool(res.moderation_enabled)
            if plan.template == "https-inspection" and res.published and self.gateway is not None:
                try:
                    self.gateway = _gateways.detail(client, self.gateway, log=self.log)
                except AiguardError as exc:
                    self.log.warn("engine", "could not re-read the gateway", error=exc.what)
                self.preflight = None
            if (plan.template == "ai-agent-security" and res.published
                    and not self.lakera.get("validated")):
                self._validate_saved_profile(client, plan, res)
            return res

    def _validate_saved_profile(self, client: MgmtClient, plan: Plan, res: ApplyResult) -> None:
        step = plan.step("profile")
        if step is None or step.status != "done":
            return
        command = self._ai_test_command(client)
        pid = self.lakera.get("project_id")
        if not command or not pid:
            return
        profile = (plan.options or {}).get("profile_name") or (step.payload or {}).get("name")
        try:
            reply = client.call(command, {"profile-name": profile, "project-id": pid})
        except AiguardError as exc:
            res.warnings.append("The saved AI Agent Security key could not be tested: %s" % exc.what)
            return
        if isinstance(reply, dict) and reply.get("success") is True:
            self.lakera["validated"] = True
            self.lakera["validated_by"] = "management"
            self.lakera["message"] = _redact.redact(str(reply.get("message") or "API key is valid."))
            self.log.info("engine", "saved AI key validated by the management server",
                          profile=profile)
        else:
            msg = _redact.redact(str((reply or {}).get("message") or "success: false"))
            self.lakera["message"] = msg
            res.warnings.append("Check Point could not validate the saved AI Agent Security key: "
                                "%s" % msg)
            self.log.warn("engine", "saved AI key was not validated", profile=profile,
                          server_said=msg)

    def rollback(self, rollback_id: Optional[str] = None,
                 progress_cb: Optional[ProgressCb] = None, *, install: bool = True) -> ApplyResult:
        """Undo a rollback point (default: the latest one for this server)."""
        with self._operation("rollback"):
            client = self._need_client()
            rid = (rollback_id or "").strip() or None
            if rid is None:
                point = self.state.latest_rollback(server=client.server, domain=client.domain)
                if point is None:
                    raise PlanError(
                        "There is nothing to roll back on %s" % client.server,
                        code="plan.rollback_not_found",
                        why="No rollback point for this server is recorded in %s."
                            % self.state.path,
                        fix=["Pass the id shown after apply: aiguard rollback <id>",
                             "Or remove the objects in SmartConsole (their comments say "
                             "\"Created by AI Guard Demo Kit\")"],
                        state="Nothing was changed.")
                rid = str(point.get("id"))
            point = self.state.get_rollback(rid) or {}
            res = _plan.rollback(client, rid, install=install, progress_cb=progress_cb,
                                 log=self.log, state=self.state)
            if res.ok and any((o or {}).get("step") == "moderation"
                              for o in point.get("objects") or []):
                self.moderation_enabled = False
            if res.ok and res.steps:
                # The demo policy of this point is gone: the confirmed enforcement no longer
                # holds, and its plan (already applied) has to be built again.
                self.enforcement = None
                if self.plan is not None and self.plan.plan_id == str(point.get("plan_id") or ""):
                    self.plan = None
            self.last_apply = res
            return res

    # ------------------------------------------------------------------ demo traffic

    def run_prompt(self, text: str, *, provider: str = "openai", expect: str = "block",
                   prompt_id: str = "custom", annotate: bool = True,
                   model: Optional[str] = None) -> ProbeResult:
        """Send one prompt through the gateway. ``annotate``: when a direct Lakera key is
        configured and the prompt was BLOCKED, label it with Lakera's category."""
        with self._operation("prompt"):
            name = _norm_provider(provider)
            result = _probe.send_prompt(
                name, text, prompt_id=prompt_id or "custom", expect=expect,
                api_key=self._provider_keys.get(name), model=model or self.models.get(name),
                ca_file=self.provider_ca_file, timeout=self.probe_timeout,
                base_url=self.provider_base_urls.get(name), log=self.log)
            if not self.local_ip and result.local_ip:
                self.local_ip = result.local_ip
            if annotate and result.verdict == "BLOCKED" and self._direct:
                self._annotate(result, text)
            self.results.append(result)
            return result

    def _annotate(self, result: ProbeResult, text: str) -> None:
        d = self._direct or {}
        try:
            cls = _lakera.classify(text, d["key"], d.get("project_id") or "",
                                   url=d.get("url") or self.lakera_url,
                                   ca_file=(d.get("ca_file") or self.lakera_ca_file
                                            or self.provider_ca_file),
                                   log=self.log)
        except AiguardError as exc:
            # A label is a convenience: a Lakera, TLS (TlsTrustError, e.g. the outbound CA
            # was just replaced) or network problem must not turn a BLOCKED result into an
            # error.
            self.log.warn("engine", "Lakera classification failed (the verdict stands)",
                          id=result.id, error=exc.what, code=exc.code)
            return
        top = cls.get("top_category")
        if top:
            result.category = top
            result.category_source = "lakera"
            result.confidence_label = cls.get("confidence_label")
            self.log.info("engine", "category from Lakera", id=result.id, category=top,
                          confidence=result.confidence_label)

    def run_scene(self, scene_id: str, *, provider: str = "openai",
                  progress_cb: Optional[ProgressCb] = None) -> List[ProbeResult]:
        """Send every prompt of a guided scene. ``progress_cb(prompt_id, status, pct,
        message)`` with status ``warning`` / ``running`` / ``done``."""
        with self._operation("scene"):
            scene = _scenes.get_scene(scene_id)
            if not scene.prompts:
                raise AiguardError(
                    "Scene '%s' has no prompts" % scene.id, code="scene.interactive",
                    why="This scene is for a prompt you type yourself.",
                    fix=["Send your own prompt (aiguard demo --prompt TEXT, or the prompt box "
                         "in the web console)"],
                    state="Nothing was sent.")
            self.log.info("engine", "scene %s" % scene.id, title=scene.title,
                          prompts=[p.id for p in scene.prompts], provider=provider)
            if scene.requires == "moderation" and not self._moderation_on():
                warning = ("Content moderation was not turned on in this session and was not "
                           "found in a rollback point: the moderation prompts will probably go "
                           "through (aiguard setup --moderation)")
                self.log.warn("engine", warning, scene=scene.id)
                self._emit(progress_cb, "moderation", "warning", 0, warning)
            out: List[ProbeResult] = []
            total = len(scene.prompts)
            for i, p in enumerate(scene.prompts):
                self._emit(progress_cb, p.id, "running", int(i * 100 / total), "Sending %s" % p.id)
                r = self.run_prompt(p.text, provider=provider, expect=p.expect, prompt_id=p.id)
                out.append(r)
                self._emit(progress_cb, p.id, "done", int((i + 1) * 100 / total),
                           "%s (%s)" % (r.verdict, "as expected" if r.matched else "unexpected"))
            return out

    def _emit(self, cb: Optional[ProgressCb], step: str, status: str, pct: Optional[int],
              message: str) -> None:
        if cb is None:
            return
        try:
            cb(step, status, pct, _redact.redact(message))
        except Exception as exc:  # noqa: BLE001 - a UI callback must not break the run
            self.log.debug("engine", "progress callback failed", error=repr(exc))

    def _moderation_on(self) -> bool:
        if self.moderation_enabled:
            return True
        if self.moderation_enabled is False:
            return False
        client, gw = self.client, self.gateway
        try:
            points = self.state.list_rollbacks()
        except Exception:  # noqa: BLE001 - informational only
            return False
        for p in reversed(points):
            if client is not None and p.get("server") != client.server:
                continue
            if gw is not None and p.get("gateway") != gw.name:
                continue
            if p.get("status") in ("rolled-back", "discarded"):
                continue
            if any((o or {}).get("step") == "moderation" for o in p.get("objects") or []):
                return True
        return False

    def confirm_enforcement(self, provider: str = "openai") -> ProbeResult:
        """Send ``inj-override`` once and expect BLOCKED; otherwise diagnose why."""
        with self._operation("confirm enforcement"):
            p = _scenes.get_prompt("inj-override")
            r = self.run_prompt(p.text, provider=provider, expect="block", prompt_id=p.id,
                                annotate=False)
            reasons: List[str] = []
            if r.verdict != "BLOCKED" and self.client is not None and self.client.logged_in:
                self._correlate_results([r])
            if r.verdict != "BLOCKED":
                reasons = self.diagnose(r)
            confirmed = r.verdict == "BLOCKED"
            self.enforcement = _redact.redact_obj({
                "confirmed": confirmed, "result_id": r.id, "provider": r.provider,
                "verdict": r.verdict, "evidence": r.evidence, "diagnosis": reasons, "at": _now()})
            self.log.event("INFO" if confirmed else "WARN", "engine",
                           "enforcement %s" % ("confirmed" if confirmed else "NOT confirmed"),
                           id=r.id, verdict=r.verdict, evidence=r.evidence,
                           diagnosis=reasons or None)
            return r

    def clear_results(self) -> None:
        """Forget the prompts sent so far (start a fresh demo with the same setup)."""
        with self._operation("clear results"):
            self.results = []
            self._correlated = set()
            self._diag_logged = {}
            self.enforcement = None
            self.log.info("engine", "results cleared")

    def moderation_on(self) -> bool:
        """True when content moderation was turned on in this session, or a rollback point
        for this server / gateway that is still in place includes the moderation step."""
        try:
            return self._moderation_on()
        except Exception:  # noqa: BLE001 - informational, never raises
            return False

    def tls_check(self, provider: Optional[str] = None) -> dict:
        """TLS handshake towards a provider (through the gateway) without sending a prompt
        (``provider`` None: openai).

        Returns :func:`aiguard.probe.tls_probe`'s dict plus ``provider``, ``host`` (the
        provider host name) and ``target`` / ``port`` (the address actually connected to,
        e.g. a test endpoint from ``provider_base_urls``). ``status`` is ``inspected``,
        ``not_inspected``, ``untrusted``, ``tls_error`` or ``connect_error``.
        """
        with self._operation("TLS check"):
            name = _norm_provider(provider)
            _probe.provider_info(name)   # raises AiguardError for an unknown provider
            info = _probe.PROVIDERS.get(name) or {}
            host = str(info.get("host") or "")
            target, port = host, 443
            base = self.provider_base_urls.get(name)
            if not base and info.get("endpoint_env"):
                base = os.environ.get(str(info["endpoint_env"])) or None
            if base:
                try:
                    parts = urlsplit(base)
                    if parts.hostname:
                        target, port = parts.hostname, int(parts.port or 443)
                except ValueError:
                    pass
            endpoints = self._endpoints()
            if host and host in endpoints:
                _n, target, port = _preflight._endpoint(host, endpoints)
            host = host or target
            if not target:
                raise AiguardError(
                    "No address for the %s provider" % name, code="probe.no_endpoint",
                    why="This provider has no fixed host name; it needs its endpoint URL.",
                    fix=["Set %s to the endpoint (https://<resource>.openai.azure.com)"
                         % (info.get("endpoint_env") or "the endpoint variable")],
                    state="Nothing was sent.")
            res = dict(_probe.tls_probe(target, port, ca_file=self.provider_ca_file,
                                        timeout=self.tls_timeout))
            res.update({"provider": name, "host": host, "target": target, "port": port})
            self.log.info("engine", "TLS check", provider=name, host=host, target=target,
                          port=port, status=res.get("status"), issuer=res.get("issuer"))
            return _redact.redact_obj(res)

    def outbound_ca(self) -> dict:
        """The gateway's outbound (HTTPS Inspection) CA, display-safe: name, uid,
        issued-by, subject, valid-from, valid-to, is-default (also as issued_by, valid_from,
        valid_to, is_default), ``pem`` (public certificate, Management API 2+; None on 1.9.x),
        ``base64-public-certificate`` (same PEM) and ``pkcs12_only``. The PKCS#12 blob (it
        can carry the CA's private key) is never returned. Read-only; raises PlanError
        ``plan.no_outbound_ca`` when there is none. When several certificates exist, the
        default one is used."""
        with self._operation("read the outbound CA"):
            client = self._need_client()
            reply = _mgmt.show_outbound_certificate(client)
            if reply is None:
                gw = self.gateway.name if self.gateway is not None else "<gateway>"
                raise PlanError(
                    "No outbound inspection certificate", code="plan.no_outbound_ca",
                    why="HTTPS Inspection re-signs the traffic with the gateway's outbound CA, "
                        "and none exists yet.",
                    fix=["SmartConsole > %s > HTTPS Inspection > Step 1: create or import the "
                         "outbound CA" % gw, "Publish, then run aiguard trust-ca again"],
                    state="Nothing was changed.",
                    details={"action": {"id": "outbound-ca", "label": "Read the outbound CA "
                                        "again", "cli": "aiguard trust-ca"}})
            info = _mgmt.outbound_certificate_info(reply)
            self.log.info("engine", "outbound CA read", name=info.get("name"),
                          issued_by=info.get("issued-by"), valid_to=info.get("valid-to"),
                          pem=bool(info.get("pem")), pkcs12_only=info.get("pkcs12_only"))
            pem = info.pop("pem", None)
            info.pop("base64-public-certificate", None)
            out = _redact.redact_obj(info)
            for key in ("issued-by", "valid-from", "valid-to", "is-default"):
                if key in out:
                    out[key.replace("-", "_")] = out[key]
            out["pem"] = pem
            out["base64-public-certificate"] = pem
            return out

    def _note_point(self, rid: str) -> None:
        """apply_plan saved the rollback point of the apply in progress."""
        self._apply_rid = str(rid)

    def _interrupt_apply(self, why: str, *, stop: bool = True) -> None:
        """An apply is running while the session is discarded (``stop``: the apply stops
        before its next change or its publish) or closed (the close waits for it) from
        another thread, e.g. at shutdown. Its rollback point, while still "recorded", is
        marked "publish-unknown" (still undoable); the apply overwrites that with its final
        status if it gets to finish, and a process that dies first leaves an honest status
        instead of "recorded"."""
        if not self._applying:
            return
        if stop:
            self._stop_apply.set()
        rid = self._apply_rid
        if not rid:
            return
        try:
            marked = self.state.mark_rollback_if(
                rid, "recorded", status="publish-unknown",
                note="%s while the plan was being applied; the publish may not have "
                     "completed" % why)
            if marked is not None:
                self.log.warn("engine", "apply interrupted: rollback point marked "
                              "publish-unknown", rollback_id=rid, reason=why)
        except Exception as exc:  # noqa: BLE001 - best effort, never raises
            try:
                self.log.debug("engine", "could not mark the rollback point", error=repr(exc))
            except Exception:  # noqa: BLE001
                pass

    def discard(self) -> bool:
        """Discard the unpublished changes of the open management session (best effort:
        never raises, never waits for a running job). True when the server confirmed it.

        During an apply (another thread, e.g. at shutdown) the apply is also told to stop
        before its next change or its publish, and its rollback point is marked
        "publish-unknown" (see :meth:`_interrupt_apply`)."""
        self._interrupt_apply("The session was discarded")
        client = self.client
        if client is None or not getattr(client, "logged_in", False):
            return False
        try:
            ok = client.discard() is not False
            if ok:
                self.log.info("engine", "unpublished changes discarded")
            return ok
        except Exception as exc:  # noqa: BLE001 - best effort by contract
            try:
                self.log.debug("engine", "discard failed", error=repr(exc))
            except Exception:  # noqa: BLE001
                pass
            return False

    # ------------------------------------------------------------------ logs

    def correlate(self) -> Optional[Dict[str, Any]]:
        """Match the results to gateway logs (``show-logs``). Fills ``log_match`` and
        category, and upgrades UNKNOWN to BLOCKED when a matching Prevent/Drop/Block log
        exists (spec 10). Failures are not raised: they are logged and kept in
        :attr:`correlate_error` (five-field dict, also in :meth:`status` and
        :meth:`summary`), which is also returned (None when the logs were read)."""
        with self._operation("correlate"):
            results = list(self.results)
            if not results:
                return None
            if self.client is None or not self.client.logged_in:
                self.log.warn("engine", "not connected: results are not matched to gateway logs")
                return None
            self._correlate_results(results)
            return self.correlate_error

    def _correlate_results(self, results: List[ProbeResult]) -> bool:
        client = self.client
        if client is None:
            return False
        ip = self.local_ip or next((r.local_ip for r in results if r.local_ip), None)
        try:
            matches = _correlate.correlate(client, results, client_ip=ip,
                                           window_s=self.correlate_window_s, log=self.log)
        except AiguardError as exc:
            self.correlate_error = self._correlate_failure(exc)
            self.log.warn("engine", "could not read the gateway logs; results are not matched",
                          error=exc.what, code=exc.code)
            return False
        self.correlate_error = None
        claimed = {str((m or {}).get("log_id")): rid for rid, m in matches.items()
                   if m and (m or {}).get("log_id")}
        for r in list(self.results):
            # A log this pass gave to another result is no longer this one's (a verdict that
            # was upgraded by that log keeps it).
            old = r.log_match
            if (old and old.get("log_id") and r.evidence != "gateway log"
                    and claimed.get(str(old.get("log_id")), r.id) != r.id):
                r.log_match = None
                if r.category_source == "gateway log":
                    r.category = None
                    r.category_source = None
        for r in results:
            self._correlated.add(r.id)
            m = matches.get(r.id)
            if not m:
                continue   # keep an earlier match (it may have left the time frame)
            r.log_match = m
            if m.get("category"):
                r.category = str(m["category"])
                r.category_source = "gateway log"
            action = str(m.get("action") or "").strip().lower()
            if r.verdict == "UNKNOWN" and m.get("blocking") and action in UPGRADE_ACTIONS:
                old = r.evidence
                r.verdict = "BLOCKED"
                r.evidence = "gateway log"
                r.category_source = "gateway log"
                if not r.category:
                    r.category = m.get("protection") or m.get("blade")
                r.reason = ("No conclusive reply (%s), but the gateway logged %s for this "
                            "request%s." % (old or "no reply", m.get("action") or "a block",
                                            (" (%s)" % m["blade"]) if m.get("blade") else ""))
                self.log.info("engine", "verdict upgraded from UNKNOWN to BLOCKED by a gateway "
                              "log", id=r.id, action=m.get("action"), log_id=m.get("log_id"))
        return True

    def _correlate_failure(self, exc: AiguardError) -> Dict[str, Any]:
        data = exc.to_dict()
        code = str(data.get("code") or "")
        api_code = str(data.get("api_code") or "")
        if code == "mgmt.permission_denied" or api_code == "generic_err_permission_denied":
            data["why"] = ("The administrator may not read the gateway logs, so the results "
                           "cannot be matched to SmartConsole logs.")
            data["fix"] = list(LOGS_PERMISSION_FIX)
        data["what"] = "Could not read the gateway logs: %s" % (exc.what or "show-logs failed")
        data["state"] = "The results are not matched to gateway logs. Nothing was changed."
        return _redact.redact_obj(data)

    # ------------------------------------------------------------------ explanations

    @staticmethod
    def _is_moderation_prompt(result: ProbeResult) -> bool:
        pid = str(getattr(result, "prompt_id", "") or "")
        if pid.startswith("mod-"):
            return True
        try:
            return _scenes.get_prompt(pid).category == "moderation"
        except AiguardError:
            return False

    def diagnose(self, result: ProbeResult) -> List[str]:
        """Plain-language reasons for an unexpected result (``[]`` when it matched)."""
        try:
            return self._diagnose(result)
        except Exception as exc:  # noqa: BLE001 - explanations must never break a UI
            self.log.debug("engine", "diagnose failed", error=repr(exc))
            return []

    def _scope_ip(self, result: ProbeResult) -> str:
        if self.local_ip_pinned and self.local_ip:
            return self.local_ip
        return result.local_ip or self.local_ip or "this computer's IP"

    def _policy_reasons(self) -> List[str]:
        """Known session facts that explain prompts going through."""
        out: List[str] = []
        gw = self.gateway
        mode = str(getattr(gw, "threat_prevention_mode", "") or "").lower() if gw else ""
        if mode == "autonomous":
            out.append("%s uses Autonomous Threat Prevention, so the AI Guard profile and rule do "
                       "not apply (SmartConsole > Gateways & Servers > %s > General Properties > "
                       "Threat Prevention tab: Custom Threat Prevention, then install the policy)"
                       % (gw.name, gw.name))
        la = self.last_apply
        plan = self.plan
        if la is None:
            if plan is not None and plan.template == "ai-agent-security":
                out.append("the demo plan was built but not applied in this session")
        elif la.kind == "rollback" and la.ok and la.steps:
            out.append("the demo policy was rolled back in this session")
        elif la.kind == "apply" and not la.ok:
            out.append("the last apply did not finish: %s" % (
                (la.error.what if la.error is not None else "") or la.message or "see the log"))
        elif la.kind == "apply" and la.ok and not la.installed:
            out.append("the demo policy was published but not installed on the gateway (install "
                       "the Threat Prevention policy)")
        return out

    def _diagnose(self, result: ProbeResult) -> List[str]:
        if result is None or result.matched:
            return []
        out: List[str] = []
        verdict = str(result.verdict or "").upper()
        err = result.error or {}
        lm = result.log_match
        correlated = result.id in self._correlated
        connected = self.client is not None and self.client.logged_in
        if result.expect == "allow" and verdict == "BLOCKED":
            terminated = str(result.evidence or "").startswith("connection terminated")
            if result.inspected is False:
                out.append("the connection was ended after the prompt was sent, but HTTPS "
                           "Inspection did not decrypt it (issuer %s), so the gateway could not "
                           "have read the prompt: retry, and check the network between this "
                           "computer and %s" % (result.issuer or "a public CA", result.host))
            elif terminated and lm is None and correlated:
                out.append("the connection was reset, but no gateway log matches it: it may not "
                           "have been the gateway (a proxy, NAT timeout or the provider). Retry, "
                           "and check SmartConsole Logs")
            elif terminated and lm is None:
                out.append("the connection was reset after the prompt was sent; no gateway log "
                           "was checked, so it may not have been the gateway. Retry, and check "
                           "SmartConsole Logs")
            else:
                what = (lm or {}).get("protection") or (lm or {}).get("category") or result.category
                out.append("the gateway blocked a prompt that should go through%s: check the "
                           "project's policy in Check Point Portal > AI Security > AI Guardrails"
                           % ((" (%s)" % what) if what else ""))
            return self._log_diagnosis(result, out)
        if result.inspected is False:
            out.append("HTTPS Inspection did not decrypt this connection (issuer %s)"
                       % (result.issuer or "a public CA"))
            gw = self.gateway
            if gw is not None and str(getattr(gw, "https_deployment_mode", "") or "").lower() \
                    == "learning":
                out.append("HTTPS Inspection on %s is in Learning mode, which inspects only a "
                           "small part of the traffic: set Deployment Mode to Full inspection "
                           "(aiguard fix https-inspection), then install the Access Control "
                           "policy" % gw.name)
        elif err.get("code") == "tls.untrusted":
            out.append("this computer does not trust the outbound CA")
        elif verdict == "ERROR":
            out.append("the prompt was not sent: %s" % (result.reason or err.get("what")
                                                         or "see the log"))
        if verdict == "UNKNOWN":
            out.append("the reply was not conclusive: %s" % (result.reason or result.evidence))
        if verdict in ("ALLOWED", "UNKNOWN"):
            out.extend(self._policy_reasons())
        if lm and (lm.get("detect") or _correlate.action_class(lm.get("action")) == "detect"):
            out.append("the gateway detected it but the profile action is Detect")
        elif (lm is None and correlated and verdict != "ERROR"
              and result.inspected is not False):
            ip = self._scope_ip(result)
            out.append("no gateway log for this request: check the rule's protected scope "
                       "includes %s, the policy was installed, the key/project are valid, and "
                       "the gateway can reach the Check Point cloud. If this computer is behind "
                       "NAT or runs in Docker, %s may not be the address the gateway sees: set "
                       "it (web console: Connect > Network address translation; CLI: --local-ip "
                       "or AIGUARD_LOCAL_IP)" % (ip, ip))
        elif lm is None and verdict in ("ALLOWED", "UNKNOWN") and not correlated:
            if self.correlate_error:
                out.append("gateway logs were not checked: %s" % self.correlate_error.get("what"))
            elif not connected:
                out.append("gateway logs were not checked (not connected to management)")
        if verdict == "ALLOWED" and result.dummy_key:
            out.append("the provider answered 401 quickly; re-test with a real key")
        if verdict == "ALLOWED" and self._is_moderation_prompt(result) and not self._moderation_on():
            out.append("content moderation is not turned on (aiguard setup --moderation)")
        return self._log_diagnosis(result, out)

    def _log_diagnosis(self, result: ProbeResult, reasons: List[str]) -> List[str]:
        key = tuple(reasons)
        if reasons and self._diag_logged.get(result.id) != key:
            self._diag_logged[result.id] = key
            for reason in reasons:
                self.log.hint("diagnose", reason, id=result.id, verdict=result.verdict,
                              expect=result.expect)
        return list(reasons)

    # ------------------------------------------------------------------ results

    def summary(self) -> dict:
        """Counts, matched, unexpected (with reasons), blocked_by {category: n}, paths."""
        try:
            results = list(self.results)
            counts = {"blocked": 0, "allowed": 0, "unknown": 0, "error": 0}
            blocked_by: Dict[str, int] = {}
            for r in results:
                key = str(r.verdict or "").lower()
                counts[key] = counts.get(key, 0) + 1
                if r.verdict == "BLOCKED":
                    cat = r.category or "uncategorised"
                    blocked_by[cat] = blocked_by.get(cat, 0) + 1
            unexpected = [{"id": r.id, "prompt_id": r.prompt_id, "provider": r.provider,
                           "expect": r.expect, "verdict": r.verdict, "evidence": r.evidence,
                           "reasons": self.diagnose(r)}
                          for r in results if not r.matched]
            out = {
                "total": len(results), **counts,
                "matched": sum(1 for r in results if r.matched),
                "unexpected": unexpected,
                "blocked_by": blocked_by,
                "with_log": sum(1 for r in results if r.log_match),
                "gateway": self.gateway.name if self.gateway is not None else None,
                "server": self.client.server if self.client is not None else None,
                "moderation_enabled": self.moderation_enabled,
                "moderation_on": self.moderation_on(),
                "correlate_error": self.correlate_error,
                "enforcement_confirmed": (self.enforcement or {}).get("confirmed"),
                "log_path": str(self.log.path),
                "report_path": str(self.report_path) if self.report_path else None,
                "report_json_path": str(self.report_json_path) if self.report_json_path else None,
            }
            return _redact.redact_obj(out)
        except Exception as exc:  # noqa: BLE001 - display helper, never raises
            self.log.debug("engine", "summary failed", error=repr(exc))
            return {"total": len(self.results), "error": "summary unavailable"}

    def write_report(self) -> Path:
        """Write the JSON + HTML report under ``<home>/reports``; returns the HTML path."""
        with self._operation("report"):
            data = _report.build_report(self)
            json_path, html_path = _report.write_report(data, home=self.home)
            self.report_path = html_path
            self.report_json_path = json_path
            self.log.info("engine", "report written", html=str(html_path), json=str(json_path))
            return html_path

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        """Log out, forget every secret this session registered. Never raises.

        When another thread is still running an operation (an apply waiting for its publish
        task, a scene ...), the session is not logged out under it: the close is done as
        soon as that operation ends."""
        got = self._lock.acquire(timeout=max(0.0, self.busy_timeout))
        if not got:
            self._close_pending = True
            self._interrupt_apply("The session was closed", stop=False)
            try:
                self.log.info("engine", "close requested while an operation runs; closing when "
                              "it ends", running=self._busy)
            except Exception:  # noqa: BLE001 - close never raises
                pass
            return
        try:
            self._close_now()
        except Exception:  # noqa: BLE001 - close never raises
            pass
        finally:
            self._lock.release()

    def _close_now(self) -> None:
        """The close itself (the caller holds the operation lock)."""
        try:
            client, self.client = self.client, None
            if client is not None:
                try:
                    client.logout()
                except Exception:  # noqa: BLE001 - logout never raises by contract
                    pass
                try:
                    client.forget_secrets()   # values another session holds stay masked
                except Exception:  # noqa: BLE001
                    pass
            self.log.info("engine", "session closed", results=len(self.results))
            for value in list(self._secrets):
                try:
                    _redact.forget_secret(value, owner=self._secret_owner)
                except Exception:  # noqa: BLE001
                    pass
            self._secrets = []
            self._lakera_key = None
            self._provider_keys = {}
            self._direct = None
            if self._own_log:
                try:
                    self.log.close()
                except Exception:  # noqa: BLE001
                    pass
        except Exception:  # noqa: BLE001 - close never raises
            pass

    @property
    def closing(self) -> bool:
        """True when close() was called and waits for the running operation."""
        return bool(self._close_pending)

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------ status

    def _step(self) -> str:
        client = self.client
        renewable = bool(client is not None and getattr(client, "session_expired", False)
                         and callable(getattr(client, "can_relogin", None)) and client.can_relogin())
        if client is None or (not client.logged_in and not renewable) or self.gateway is None:
            return "connect"
        if self.preflight is None:
            return "preflight"
        plan = self.plan
        if plan is None or (getattr(plan, "template", None) or "ai-agent-security") != \
                "ai-agent-security":
            # the HTTPS Inspection fix is not the demo policy: Configure is still to do
            return "configure"
        la = self.last_apply
        if (la is None or la.kind != "apply" or not la.ok or la.plan_id != plan.plan_id
                or not la.installed):
            # a rollback, a failed apply, or a publish-only apply: the policy is not in place
            return "install"
        return "demo"

    def status(self) -> dict:
        """Display-safe snapshot for the UIs (no secrets). Never raises, never blocks."""
        try:
            client = self.client
            gw = self.gateway
            results = list(self.results)
            direct = self._direct
            points = []
            if client is not None:
                try:
                    for p in self.state.list_rollbacks()[-10:]:
                        if p.get("server") != client.server:
                            continue
                        points.append({k: p.get(k) for k in ("id", "created_at", "status",
                                                              "summary", "gateway", "plan_id")})
                except Exception:  # noqa: BLE001 - informational only
                    points = []
            out = {
                "version": __version__,
                "connected": bool(client is not None and client.logged_in),
                "connection": client.summary() if client is not None else None,
                "gateways": [{"name": g.name, "type": g.type, "ipv4": g.ipv4,
                              "version": g.version, "release": g.release,
                              "policy_package": g.policy_package, "is_cluster": g.is_cluster,
                              "https_inspection": g.blade("https_inspection"),
                              "ai_security": g.blade("ai_security")}
                             for g in list(self.gateways)],
                "gateway": gw.to_dict() if gw is not None else None,
                "local_ip": self.local_ip,
                "local_ip_pinned": self.local_ip_pinned,
                "preflight": self.preflight.to_dict() if self.preflight is not None else None,
                "plan": self.plan.to_dict() if self.plan is not None else None,
                "last_apply": self.last_apply.to_dict() if self.last_apply is not None else None,
                "lakera": dict(self.lakera),
                "direct_lakera": ({"configured": True,
                                   "masked_key": _redact.mask_secret(direct.get("key")),
                                   "project_id": direct.get("project_id") or None}
                                  if direct else {"configured": False}),
                "provider_keys": {p: _redact.mask_secret(k)
                                  for p, k in dict(self._provider_keys).items()},
                "moderation_enabled": self.moderation_enabled,
                "moderation_on": self.moderation_on(),
                "session_expired": bool(client is not None and not client.logged_in
                                        and getattr(client, "session_expired", False)),
                "correlate_error": self.correlate_error,
                "enforcement": self.enforcement,
                "results": [r.to_dict() for r in results],
                "summary": self.summary(),
                "rollbacks": points,
                "busy": self._busy,
                "step": self._step(),
                "log_path": str(self.log.path),
                "report_path": str(self.report_path) if self.report_path else None,
            }
            return _redact.redact_obj(out)
        except Exception as exc:  # noqa: BLE001 - display helper, never raises
            try:
                self.log.debug("engine", "status failed", error=repr(exc))
            except Exception:  # noqa: BLE001
                pass
            return {"version": __version__, "connected": False, "busy": self._busy,
                    "error": "status unavailable (%s)" % type(exc).__name__}
