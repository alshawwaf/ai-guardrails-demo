"""Gateway discovery (spec 3.4, section 10).

* :func:`discover` -- ``show-gateways-and-servers`` (details-level full, paged): security
  gateways and clusters only (cluster members, management and log servers are left
  out). Blades come from ``network-security-blades``, the installed package from
  ``policy{threat-policy-name, access-policy-name}``.
* :func:`detail` -- ``show-simple-gateway`` / ``show-simple-cluster``: blade booleans,
  ``threat-prevention-mode``, ``enable-https-inspection`` and
  ``https-inspection.deployment-mode`` (API 2+), ``workforce-ai`` (API 2.2), interfaces
  (clusters: up to ``limit-interfaces`` = 500) and cluster members.
* :func:`policy_state` -- the installed policy of one gateway from
  ``show-gateways-and-servers`` ``policy`` (name, installed, installation date and
  revision for Access Control and Threat Prevention).

A blade whose state the API did not report is ``None`` ("unknown"), never ``False``.
"""

from __future__ import annotations

import copy
import dataclasses
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import redact as _redact
from .errors import MgmtApiError
from .mgmt import api_date_posix, api_date_text

__all__ = [
    "GatewayInfo",
    "discover",
    "detail",
    "version_tuple",
    "normalize_release",
    "BLADE_KEYS",
    "GATEWAY_TYPES",
    "CLUSTER_TYPES",
    "EXCLUDED_TYPES",
    "AI_SECURITY_MIN_VERSION",
    "policy_state",
    "policy_facts",
    "CLUSTER_INTERFACE_LIMIT",
]

# Keys every GatewayInfo.blades dict has (spec 3.4) ...
BLADE_KEYS: Tuple[str, ...] = (
    "firewall", "application_control", "url_filtering", "content_awareness", "ips",
    "anti_bot", "anti_virus", "threat_emulation", "https_inspection", "ai_security",
)
# ... plus these, when the API reports them.
EXTRA_BLADE_KEYS: Tuple[str, ...] = (
    "threat_extraction", "zero_phishing", "identity_awareness", "data_loss_prevention",
    "workforce_ai",
)

# API field name (show-simple-gateway / network-security-blades) -> normalized key
_API_BLADES: Dict[str, str] = {
    "firewall": "firewall",
    "application-control": "application_control",
    "url-filtering": "url_filtering",
    "content-awareness": "content_awareness",
    "ips": "ips",
    "anti-bot": "anti_bot",
    "anti-virus": "anti_virus",
    "threat-emulation": "threat_emulation",
    "threat-extraction": "threat_extraction",
    "zero-phishing": "zero_phishing",
    "identity-awareness": "identity_awareness",
    "data-loss-prevention": "data_loss_prevention",
}

GATEWAY_TYPES = frozenset({"simple-gateway", "CpmiGatewayPlain"})
CLUSTER_TYPES = frozenset({"simple-cluster", "CpmiGatewayCluster"})
EXCLUDED_TYPES = frozenset({"CpmiClusterMember", "cluster-member", "checkpoint-host",
                            "CpmiHostCkp"})

AI_SECURITY_MIN_VERSION = (82, 20)

# show-simple-cluster pages its interfaces ("limit-interfaces", default 50).
CLUSTER_INTERFACE_LIMIT = 500


# --------------------------------------------------------------------------- versions


def version_tuple(version: Any) -> Optional[Tuple[int, int]]:
    """``"R82.20"`` -> ``(82, 20)``; ``"R82"`` -> ``(82, 0)``; ``"R81.20"`` -> ``(81, 20)``.

    ``None`` when the text has no release number.
    """
    if version is None:
        return None
    m = re.search(r"(?i)(?:^|[^0-9.])R?\s*(\d{2,3})(?:\.(\d{1,2}))?(?![0-9])", " " + str(version))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2) or 0)


def normalize_release(version: Any) -> Optional[str]:
    """``"R82.20"`` / ``"r82.20"`` / ``"82.20"`` -> ``"R82.20"``; ``"R82"`` -> ``"R82"``."""
    vt = version_tuple(version)
    if vt is None:
        return None
    return "R%d" % vt[0] if vt[1] == 0 else "R%d.%d" % vt


def _ai_security_from_release(release: Optional[str]) -> Optional[bool]:
    """AI Agent Security has no gateway flag in the API: it is turned on in a threat
    profile. A gateway older than R82.20 cannot run it (False); otherwise unknown."""
    vt = version_tuple(release)
    if vt is not None and vt < AI_SECURITY_MIN_VERSION:
        return False
    return None


def _norm_blade_key(key: str) -> str:
    k = str(key or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {"appi": "application_control", "app_control": "application_control",
               "urlf": "url_filtering", "av": "anti_virus", "ab": "anti_bot",
               "te": "threat_emulation", "https": "https_inspection",
               "ai_agent_security": "ai_security", "ai": "ai_security"}
    return aliases.get(k, k)


# --------------------------------------------------------------------------- model


@dataclass
class GatewayInfo:
    """One security gateway or cluster."""

    name: str
    uid: str = ""
    type: str = "simple-gateway"
    ipv4: Optional[str] = None
    version: Optional[str] = None
    policy_package: Optional[str] = None          # threat-policy-name, else access-policy-name
    blades: Dict[str, Optional[bool]] = field(default_factory=dict)
    interfaces: List[Tuple[str, int]] = field(default_factory=list)   # (ipv4, mask length)
    is_cluster: bool = False
    raw: dict = field(default_factory=dict)       # redacted listing object (for the log)
    threat_prevention_mode: Optional[str] = None  # "custom" | "autonomous" | None
    workforce_ai: Optional[bool] = None
    https_inspection: Optional[bool] = None       # enable-https-inspection
    cluster_members: List[str] = field(default_factory=list)
    release: Optional[str] = None                 # "R82.20"
    access_policy: Optional[str] = None           # policy.access-policy-name
    threat_policy: Optional[str] = None           # policy.threat-policy-name
    access_policy_installed: Optional[bool] = None
    threat_policy_installed: Optional[bool] = None
    # policy.*-installation-date (display text, and ms since the epoch) and *-revision
    access_policy_installation_date: Optional[str] = None
    access_policy_installed_at: Optional[int] = None
    access_policy_revision: Optional[str] = None
    threat_policy_installation_date: Optional[str] = None
    threat_policy_installed_at: Optional[int] = None
    threat_policy_revision: Optional[str] = None
    https_deployment_mode: Optional[str] = None   # https-inspection.deployment-mode: full | learning
    interfaces_total: Optional[int] = None        # clusters: total the server reported
    sic_state: Optional[str] = None
    detailed: bool = False                        # detail() filled it from show-simple-*
    detail_error: Optional[str] = None            # why detail() could not read the object
    raw_detail: dict = field(default_factory=dict)  # redacted show-simple-* reply

    def __post_init__(self) -> None:
        blades = {_norm_blade_key(k): v for k, v in dict(self.blades or {}).items()}
        for key in BLADE_KEYS:
            blades.setdefault(key, None)
        self.blades = blades
        if self.release is None and self.version:
            self.release = normalize_release(self.version)
        self.interfaces = [(str(ip), int(mask)) for ip, mask in (self.interfaces or [])]

    def blade(self, key: str) -> Optional[bool]:
        """``True``/``False`` when known, ``None`` = unknown (show "unknown", not "off")."""
        k = _norm_blade_key(key)
        if k == "https_inspection" and self.https_inspection is not None:
            return self.https_inspection
        if k == "workforce_ai" and self.workforce_ai is not None:
            return self.workforce_ai
        return self.blades.get(k)

    def version_tuple(self) -> Optional[Tuple[int, int]]:
        return version_tuple(self.release or self.version)

    def networks(self) -> List[ipaddress.IPv4Network]:
        """Networks directly attached to the gateway (from its interfaces)."""
        out: List[ipaddress.IPv4Network] = []
        for ip, mask in self.interfaces:
            try:
                net = ipaddress.ip_network("%s/%d" % (ip, mask), strict=False)
            except ValueError:
                continue
            if isinstance(net, ipaddress.IPv4Network) and net not in out:
                out.append(net)
        return out

    def contains_ip(self, ip: Optional[str]) -> Optional[bool]:
        """Is ``ip`` on a network attached to this gateway? ``None`` if unknown."""
        nets = self.networks()
        if not nets or not ip:
            return None
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return None
        return any(addr in n for n in nets)

    @property
    def access_policy_name(self) -> Optional[str]:
        return self.access_policy

    @property
    def threat_policy_name(self) -> Optional[str]:
        return self.threat_policy

    def policy_dict(self) -> Dict[str, Any]:
        """The installed-policy facts as the API names them (display-safe)."""
        return {
            "access-policy-name": self.access_policy,
            "access-policy-installed": self.access_policy_installed,
            "access-policy-installation-date": self.access_policy_installation_date,
            "access-policy-revision": self.access_policy_revision,
            "threat-policy-name": self.threat_policy,
            "threat-policy-installed": self.threat_policy_installed,
            "threat-policy-installation-date": self.threat_policy_installation_date,
            "threat-policy-revision": self.threat_policy_revision,
        }

    def apply_policy(self, pol: Optional[Dict[str, Any]]) -> None:
        """Take the policy facts of a ``show-gateways-and-servers`` ``policy`` object."""
        facts = policy_facts(pol)
        for key, value in facts.items():
            setattr(self, key, value)
        if facts.get("threat_policy") or facts.get("access_policy"):
            self.policy_package = facts.get("threat_policy") or facts.get("access_policy")

    def script_targets(self) -> List[str]:
        """``run-script`` targets: the cluster members of a cluster, else the gateway."""
        if self.is_cluster and self.cluster_members:
            return list(self.cluster_members)
        return [self.name]

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        """Display-safe dict (JSON types)."""
        data = dataclasses.asdict(self)
        data["interfaces"] = [[ip, mask] for ip, mask in self.interfaces]
        data["blades"] = {k: self.blade(k) for k in self.blades}
        if not include_raw:
            data.pop("raw", None)
            data.pop("raw_detail", None)
        return _redact.redact_obj(data)


# --------------------------------------------------------------------------- parsing


def _as_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def _mask_len(iface: Dict[str, Any]) -> Optional[int]:
    for key in ("ipv4-mask-length", "mask-length", "ipv4-mask-len"):
        value = iface.get(key)
        if value is None or isinstance(value, bool):
            continue
        try:
            n = int(str(value).strip())
        except ValueError:
            continue
        if 0 <= n <= 32:
            return n
    for key in ("ipv4-network-mask", "network-mask", "subnet-mask", "netmask"):
        value = iface.get(key)
        if not value:
            continue
        try:
            return ipaddress.IPv4Network("0.0.0.0/%s" % str(value).strip()).prefixlen
        except ValueError:
            continue
    return None


def _revision_text(value: Any) -> Optional[str]:
    if isinstance(value, dict):
        for key in ("name", "uid"):
            if value.get(key):
                return str(value[key])
        return None
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def policy_facts(pol: Any) -> Dict[str, Any]:
    """GatewayInfo attribute values from a ``policy`` (GatewayServerPolicyReply) object."""
    pol = pol if isinstance(pol, dict) else {}
    out: Dict[str, Any] = {}
    for kind in ("access", "threat"):
        out["%s_policy" % kind] = pol.get("%s-policy-name" % kind) or None
        out["%s_policy_installed" % kind] = _as_bool(pol.get("%s-policy-installed" % kind))
        date = pol.get("%s-policy-installation-date" % kind)
        out["%s_policy_installation_date" % kind] = api_date_text(date) if date else None
        out["%s_policy_installed_at" % kind] = api_date_posix(date) if date else None
        out["%s_policy_revision" % kind] = _revision_text(pol.get("%s-policy-revision" % kind))
    return out


def _parse_interfaces(value: Any) -> List[Tuple[str, int]]:
    """Interfaces as a list, or as a paged object ``{objects: [...]}`` (clusters)."""
    if isinstance(value, dict):
        value = value.get("objects") or value.get("interfaces") or []
    out: List[Tuple[str, int]] = []
    if not isinstance(value, list):
        return out
    for iface in value:
        if not isinstance(iface, dict):
            continue
        ip = iface.get("ipv4-address") or iface.get("ip-address")
        if not ip or not isinstance(ip, str):
            continue
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            continue
        if not isinstance(addr, ipaddress.IPv4Address) or addr.is_unspecified:
            continue
        mask = _mask_len(iface)
        if mask is None:
            continue
        item = (str(addr), mask)
        if item not in out:
            out.append(item)
    return out


def _listing_blades(value: Any) -> Dict[str, Optional[bool]]:
    """``network-security-blades`` lists enabled blades (the official example of a
    firewall-only gateway is ``{"firewall": true}``). A non-empty object therefore means
    "absent = off"; an empty or missing one means unknown."""
    blades: Dict[str, Optional[bool]] = {}
    if not isinstance(value, dict) or not value:
        return blades
    for api_key, norm in _API_BLADES.items():
        b = _as_bool(value.get(api_key))
        blades[norm] = b if b is not None else False
    return blades


def _is_gateway_type(gtype: str) -> bool:
    return gtype in GATEWAY_TYPES or gtype in CLUSTER_TYPES


def _from_listing(obj: Dict[str, Any]) -> GatewayInfo:
    gtype = str(obj.get("type") or "")
    is_cluster = gtype in CLUSTER_TYPES
    pol = obj.get("policy") if isinstance(obj.get("policy"), dict) else {}
    access = pol.get("access-policy-name") or None
    threat = pol.get("threat-policy-name") or None
    version = obj.get("version")
    version = str(version) if version not in (None, "") else None
    release = normalize_release(version)
    blades = _listing_blades(obj.get("network-security-blades"))
    blades["ai_security"] = _ai_security_from_release(release)
    members = obj.get("cluster-member-names")
    members = [str(m) for m in members] if isinstance(members, list) else []
    facts = policy_facts(pol)
    return GatewayInfo(
        name=str(obj.get("name") or ""),
        uid=str(obj.get("uid") or ""),
        type=gtype,
        ipv4=obj.get("ipv4-address") or None,
        version=version,
        policy_package=threat or access,
        blades=blades,
        interfaces=_parse_interfaces(obj.get("interfaces")),
        is_cluster=is_cluster,
        raw=_redact.redact_obj(obj),
        cluster_members=members,
        release=release,
        access_policy=access,
        threat_policy=threat,
        access_policy_installed=facts["access_policy_installed"],
        threat_policy_installed=facts["threat_policy_installed"],
        access_policy_installation_date=facts["access_policy_installation_date"],
        access_policy_installed_at=facts["access_policy_installed_at"],
        access_policy_revision=facts["access_policy_revision"],
        threat_policy_installation_date=facts["threat_policy_installation_date"],
        threat_policy_installed_at=facts["threat_policy_installed_at"],
        threat_policy_revision=facts["threat_policy_revision"],
        sic_state=obj.get("sic-status") or obj.get("sic-state") or None,
    )


def _client_log(client: Any, log: Any) -> Any:
    if log is not None:
        return log
    return getattr(client, "log", None)


def _log(log: Any, level: str, msg: str, **fields: Any) -> None:
    if log is None:
        return
    try:
        log.event(level, "gateways", msg, **fields)
    except Exception:  # noqa: BLE001 - logging must not break discovery
        pass


# --------------------------------------------------------------------------- API


def discover(client: Any, *, log: Any = None) -> List[GatewayInfo]:
    """Security gateways and clusters visible in the current domain.

    ``show-gateways-and-servers`` (details-level full, all pages). Cluster members
    (``CpmiClusterMember``) and management/log servers (``CpmiHostCkp``,
    ``checkpoint-host``) are left out. Sorted by name.
    """
    log = _client_log(client, log)
    objs = client.show_all("show-gateways-and-servers", {"details-level": "full"},
                           key="objects", limit=50)
    out: List[GatewayInfo] = []
    skipped: Dict[str, int] = {}
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        gtype = str(obj.get("type") or "")
        if gtype in EXCLUDED_TYPES or not _is_gateway_type(gtype):
            skipped[gtype or "?"] = skipped.get(gtype or "?", 0) + 1
            continue
        gw = _from_listing(obj)
        if not gw.name:
            continue
        out.append(gw)
    out.sort(key=lambda g: g.name.lower())
    if skipped:
        _log(log, "DEBUG", "skipped objects that are not gateways", types=skipped)
    _log(log, "INFO", "found %d gateway(s)" % len(out),
         gateways=[{"name": g.name, "type": g.type, "ipv4": g.ipv4, "version": g.version,
                    "package": g.policy_package, "cluster_members": g.cluster_members}
                   for g in out])
    return out


_DETAIL_SOFT_ERRORS = frozenset({
    "generic_err_object_not_found", "generic_err_command_not_found",
    "generic_err_invalid_parameter", "generic_err_invalid_parameter_name",
    "generic_err_object_type_wrong", "generic_err_invalid_object_type",
})


def detail(client: Any, gw: GatewayInfo, *, log: Any = None) -> GatewayInfo:
    """A copy of ``gw`` completed from ``show-simple-gateway`` / ``show-simple-cluster``.

    When the object cannot be read that way (not a "simple" gateway, command missing)
    the copy keeps the listing data and ``detail_error`` says why. Transport and
    authentication errors are raised.
    """
    log = _client_log(client, log)
    new = dataclasses.replace(gw, blades=dict(gw.blades), interfaces=list(gw.interfaces),
                              cluster_members=list(gw.cluster_members), raw=copy.deepcopy(gw.raw),
                              raw_detail=copy.deepcopy(gw.raw_detail))
    command = "show-simple-cluster" if gw.is_cluster else "show-simple-gateway"
    has = getattr(client, "has", None)
    if callable(has) and not has(command):
        new.detail_error = "This management version does not support %s" % command
        _log(log, "WARN", "cannot read gateway details", gateway=gw.name, reason=new.detail_error)
        return new
    payload: Dict[str, Any] = {"name": gw.name, "details-level": "full"}
    if command == "show-simple-cluster":
        payload["limit-interfaces"] = CLUSTER_INTERFACE_LIMIT
    try:
        d = client.call(command, payload)
    except MgmtApiError as exc:
        if exc.api_code not in _DETAIL_SOFT_ERRORS:
            raise
        new.detail_error = exc.what
        _log(log, "WARN", "cannot read gateway details", gateway=gw.name, command=command,
             reason=exc.what, api_code=exc.api_code)
        return new
    if not isinstance(d, dict):
        new.detail_error = "Unexpected reply to %s" % command
        return new
    _merge_detail(new, d)
    shown = len(new.interfaces)
    if new.interfaces_total is not None and new.interfaces_total > shown:
        _log(log, "WARN", "the server listed only part of the cluster's interfaces",
             gateway=new.name, listed=shown, total=new.interfaces_total,
             hint="networks on the other interfaces are not known to preflight")
    _log(log, "INFO", "gateway details", gateway=new.name, version=new.version,
         threat_prevention_mode=new.threat_prevention_mode,
         https_inspection=new.https_inspection, https_mode=new.https_deployment_mode,
         workforce_ai=new.workforce_ai,
         interfaces=["%s/%d" % i for i in new.interfaces],
         blades={k: v for k, v in new.blades.items() if v is not None},
         cluster_members=new.cluster_members)
    return new


def _merge_detail(gw: GatewayInfo, d: Dict[str, Any]) -> None:
    for api_key, norm in _API_BLADES.items():
        b = _as_bool(d.get(api_key))
        if b is not None:
            gw.blades[norm] = b
    https = _as_bool(d.get("enable-https-inspection"))
    if https is not None:
        gw.https_inspection = https
        gw.blades["https_inspection"] = https
    hi = d.get("https-inspection")
    if isinstance(hi, dict):
        mode = hi.get("deployment-mode")
        if isinstance(mode, str) and mode.strip():
            gw.https_deployment_mode = mode.strip().lower()
    mode = d.get("threat-prevention-mode")
    if isinstance(mode, str) and mode.strip():
        gw.threat_prevention_mode = mode.strip().lower()
    wf = _as_bool(d.get("workforce-ai"))
    if wf is not None:
        gw.workforce_ai = wf
        gw.blades["workforce_ai"] = wf
    version = d.get("version")
    if version:
        gw.version = str(version)
        gw.release = normalize_release(gw.version) or gw.release
    if d.get("ipv4-address"):
        gw.ipv4 = str(d["ipv4-address"])
    if d.get("uid") and not gw.uid:
        gw.uid = str(d["uid"])
    if d.get("sic-state"):
        gw.sic_state = str(d["sic-state"])
    ifaces = _parse_interfaces(d.get("interfaces"))
    raw_ifaces = d.get("interfaces")
    if isinstance(raw_ifaces, dict):
        total = raw_ifaces.get("total")
        if isinstance(total, int) and not isinstance(total, bool):
            gw.interfaces_total = total
    members = d.get("cluster-members")
    if isinstance(members, list):
        names = [str(m.get("name")) for m in members if isinstance(m, dict) and m.get("name")]
        if names and not gw.cluster_members:
            gw.cluster_members = names
        if not ifaces:
            for m in members:
                if isinstance(m, dict):
                    for item in _parse_interfaces(m.get("interfaces")):
                        if item not in ifaces:
                            ifaces.append(item)
    if ifaces:
        gw.interfaces = ifaces
    if str(d.get("type") or "") in CLUSTER_TYPES:
        gw.is_cluster = True
    gw.blades["ai_security"] = _ai_security_from_release(gw.release)
    gw.raw_detail = _redact.redact_obj(d)
    gw.detailed = True
    gw.detail_error = None


def policy_state(client: Any, name: str, *, log: Any = None) -> Optional[Dict[str, Any]]:
    """The ``policy`` object (installed Access Control / Threat Prevention policy: name,
    installed, installation date, revision) of gateway ``name`` from
    ``show-gateways-and-servers``, or None when the gateway is not listed. Read-only;
    API errors are raised."""
    log = _client_log(client, log)
    wanted = str(name or "").strip().lower()
    objs = client.show_all("show-gateways-and-servers", {"details-level": "full"},
                           key="objects", limit=50)
    for obj in objs:
        if isinstance(obj, dict) and str(obj.get("name") or "").lower() == wanted:
            pol = obj.get("policy") if isinstance(obj.get("policy"), dict) else {}
            _log(log, "DEBUG", "installed policy", gateway=obj.get("name"),
                 policy=_redact.redact_obj(pol))
            return dict(pol)
    return None
