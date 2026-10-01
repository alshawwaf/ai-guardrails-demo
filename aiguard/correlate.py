"""Match demo prompts to gateway logs (spec 5.4, section 10).

One ``show-logs`` query (``src:<client ip>``, time-frame last-hour) and local matching:
for every probe result, the closest log within ``window_s`` seconds of ``sent_at``
whose destination / resource names the provider host (or the IP the probe connected
to) and whose action fits the verdict:

* BLOCKED / UNKNOWN / ERROR -> a blocking action (Prevent, Drop, Block, Reject, ...);
  the caller may upgrade UNKNOWN to BLOCKED when ``match["blocking"]`` is true;
* ALLOWED -> a Detect-type action only (the profile only detected it); a blocking log is
  never proof for a prompt that reached the provider.

Logs from a blade whose name contains "AI" are preferred. Each log is used for one
result at most. The AI Agent Security log ``product`` name is not documented, so the
distinct ``product`` values seen are logged at INFO for the lab.
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from . import redact as _redact
from .errors import MgmtApiError

__all__ = ["correlate", "BLOCK_ACTIONS", "DETECT_ACTIONS", "log_time", "action_class"]

BLOCK_ACTIONS = frozenset({"prevent", "drop", "block", "reject", "deny", "redirect",
                           "blocked", "prevented", "dropped", "rejected"})
DETECT_ACTIONS = frozenset({"detect", "ask user", "inform user", "ask", "inform", "detected"})

# Errors that mean "we cannot talk to the server as this admin" -> raised to the caller.
_AUTH_CODES = frozenset({"mgmt.not_logged_in", "mgmt.session_expired", "mgmt.forbidden_ip",
                         "mgmt.permission_denied", "mgmt.login_failed", "mgmt.rate_limited"})
_AUTH_API_CODES = frozenset({"generic_err_wrong_session_id", "generic_err_permission_denied",
                             "err_login_failed", "err_too_many_requests"})

_CATEGORY_FIELDS = ("category", "ai_category", "detected_category", "threat_category",
                    "attack_category", "attack", "attack_info", "detection_category",
                    "matched_category", "prompt_category")


# --------------------------------------------------------------------------- helpers


class _NullLog(object):
    def event(self, *a: Any, **k: Any) -> int:
        return 0

    info = warn = debug = error = hint = event


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _parse_iso(text: str) -> Optional[_dt.datetime]:
    value = text.strip()
    if not value:
        return None
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    # +0000 -> +00:00 (Python 3.8 fromisoformat needs the colon)
    value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value)
    # more than 6 fractional digits
    value = re.sub(r"(\.\d{6})\d+", r"\1", value)
    # 1-5 fractional digits are fine for 3.11+, pad for 3.8-3.10
    m = re.search(r"\.(\d{1,5})(?=[+-]|$)", value)
    if m:
        value = value[:m.start(1)] + m.group(1).ljust(6, "0") + value[m.end(1):]
    value = value.replace(" ", "T", 1) if re.match(r"^\d{4}-\d{2}-\d{2} \d", value) else value
    try:
        ts = _dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    return ts.astimezone(_dt.timezone.utc)


def _parse_time(value: Any) -> Optional[_dt.datetime]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, _dt.datetime):
        return (value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)).astimezone(
            _dt.timezone.utc)
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,14}(\.\d+)?", value.strip())):
        try:
            num = float(value)
        except (TypeError, ValueError):
            return None
        if num <= 0:
            return None
        if num > 1e11:  # milliseconds
            num /= 1000.0
        try:
            return _dt.datetime.fromtimestamp(num, _dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, dict):
        return _parse_time(value.get("posix") or value.get("iso-8601"))
    if isinstance(value, str):
        return _parse_iso(value)
    return None


def log_time(entry: Dict[str, Any]) -> Optional[_dt.datetime]:
    """Time of a show-logs entry (``time``; else ``lastUpdateTime`` / ``index_time``)."""
    for key in ("time", "lastUpdateTime", "index_time", "start_time"):
        ts = _parse_time(entry.get(key))
        if ts is not None:
            return ts
    return None


def action_class(action: Any) -> Optional[str]:
    """``"block"`` | ``"detect"`` | ``None`` (accept, bypass, unknown)."""
    a = str(action or "").strip().lower()
    if not a:
        return None
    if a in BLOCK_ACTIONS:
        return "block"
    if a in DETECT_ACTIONS:
        return "detect"
    return None


def _host_of(text: Any) -> Optional[str]:
    if not text:
        return None
    value = str(text).strip()
    if "://" not in value:
        value = "https://" + value.lstrip("/")
    try:
        return (urlsplit(value).hostname or "").lower() or None
    except ValueError:
        return None


def _log_hosts(entry: Dict[str, Any]) -> Tuple[Set[str], List[str]]:
    """(names/IPs the log is about, raw resource strings)."""
    hosts: Set[str] = set()
    resources: List[str] = []
    for key in ("dst", "destination", "dst_ip", "server_name", "sni", "site", "host",
                "hostname", "url_host", "dst_machine_name"):
        v = entry.get(key)
        if isinstance(v, str) and v.strip():
            hosts.add(v.strip().lower())
    for attr in entry.get("dst_attr") or []:
        if isinstance(attr, dict) and attr.get("resolved"):
            hosts.add(str(attr["resolved"]).strip().lower())
    for key in ("resource", "url", "uri"):
        v = entry.get(key)
        if isinstance(v, str) and v.strip():
            resources.append(v)
            h = _host_of(v)
            if h:
                hosts.add(h)
    for item in entry.get("resource_table") or []:
        if isinstance(item, dict) and item.get("resource"):
            resources.append(str(item["resource"]))
            h = _host_of(item["resource"])
            if h:
                hosts.add(h)
    return hosts, resources


def _host_matches(hosts: Set[str], resources: Sequence[str], host: Optional[str],
                  remote_ip: Optional[str]) -> Optional[str]:
    """How the log matches: "dst" | "ip" | "resource" | None."""
    h = (host or "").strip().lower()
    if h:
        if h in hosts:
            return "dst"
        if any(x.endswith("." + h) for x in hosts):
            return "dst"
        if any(h in r.lower() for r in resources):
            return "resource"
    ip = (remote_ip or "").strip().lower()
    if ip and ip in hosts:
        return "ip"
    return None


def _first(entry: Dict[str, Any], *keys: str) -> Optional[str]:
    for key in keys:
        v = entry.get(key)
        if v not in (None, "", [], {}):
            return str(v)
    return None


def _table_value(entry: Dict[str, Any], table: str, key: str) -> Optional[str]:
    rows = entry.get(table)
    if isinstance(rows, dict):
        rows = [rows]
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict) and row.get(key):
                return str(row[key])
    return None


def _match_dict(entry: Dict[str, Any], ts: Optional[_dt.datetime], delta: float, how: str,
                cls: str) -> Dict[str, Any]:
    product = _first(entry, "product", "blade", "product_family")
    protection = _first(entry, "protection_name", "protection", "attack_name")
    category = _first(entry, *_CATEGORY_FIELDS) or protection
    rule = (_first(entry, "rule_name", "rule") or _table_value(entry, "match_table", "rule_name")
            or _table_value(entry, "TP_match_table", "rule_name"))
    profile = (_first(entry, "smartdefense_profile", "profile")
               or _table_value(entry, "TP_match_table", "smartdefense_profile"))
    layer = (_table_value(entry, "TP_match_table", "layer_name")
             or _table_value(entry, "match_table", "layer_name") or _first(entry, "layer_name"))
    out = {
        "time": entry.get("time") if entry.get("time") else (ts.isoformat() if ts else None),
        "action": _first(entry, "action"),
        "blade": product,
        "rule": rule,
        "protection": protection,
        "category": category,
        "log_id": _first(entry, "id", "log_uid", "loguid", "log_id"),
        "product": product,
        "protection_type": _first(entry, "protection_type"),
        "severity": _first(entry, "severity"),
        "confidence": _first(entry, "confidence_level", "confidence"),
        "profile": profile,
        "layer": layer,
        "dst": _first(entry, "dst"),
        "resource": _first(entry, "resource"),
        "description": _first(entry, "description", "calc_desc"),
        "gateway": _first(entry, "orig", "origin"),
        "delta_s": round(delta, 1),
        "matched_on": how,
        "blocking": cls == "block",
        "detect": cls == "detect",
        "source": "gateway log",
    }
    return _redact.redact_obj(out)


def _sent_time(result: Any) -> Optional[_dt.datetime]:
    epoch = _get(result, "sent_epoch")
    if isinstance(epoch, (int, float)) and not isinstance(epoch, bool) and epoch > 0:
        ts = _parse_time(float(epoch))
        if ts is not None:
            return ts
    return _parse_time(_get(result, "sent_at"))


def _delta(log_ts: _dt.datetime, sent: _dt.datetime, ms: Any) -> float:
    try:
        dur = max(0.0, float(ms or 0) / 1000.0)
    except (TypeError, ValueError):
        dur = 0.0
    end = sent + _dt.timedelta(seconds=dur)
    if sent <= log_ts <= end:
        return 0.0
    return min(abs((log_ts - sent).total_seconds()), abs((log_ts - end).total_seconds()))


def _is_auth_or_transport(err: MgmtApiError) -> bool:
    return (err.code in _AUTH_CODES or (err.api_code or "") in _AUTH_API_CODES
            or err.http_status in (401,))


def _assign(candidates: List[Tuple[Tuple[int, int, float], int, int, str]],
            items: Sequence[Any]) -> List[Tuple[int, int, Tuple[int, int, float], str]]:
    """One log per result, as many results matched as possible.

    Gateway log times have one-second precision, so several prompts sent in the same
    second can all be close to the same logs. A greedy "closest pair first" pass can then
    leave a result without a log although another assignment matches every result. This
    is a maximum bipartite matching (augmenting paths, Kuhn) that keeps the preferences:
    results are placed in order of their best candidate (UNKNOWN / ERROR first on a tie,
    they need the log most), and each tries its logs from the best rank down; an earlier
    result moves to its next-best log only when that lets another result be matched.
    """
    by_result: Dict[int, List[Tuple[Tuple[int, int, float], int, str]]] = {}
    for rank, ri, li, how in candidates:
        by_result.setdefault(ri, []).append((rank, li, how))
    for opts in by_result.values():
        opts.sort(key=lambda o: (o[0], o[1]))

    def need(ri: int) -> int:
        verdict = str(_get(items[ri], "verdict") or "").upper()
        return 0 if verdict in ("UNKNOWN", "ERROR") else 1

    order = sorted(by_result, key=lambda ri: (by_result[ri][0][0], need(ri), ri))
    owner: Dict[int, int] = {}            # log index -> result index

    def place(ri: int, seen: Set[int]) -> bool:
        opts = by_result[ri]
        for _rank, li, _how in opts:          # the best free log, if any
            if li not in owner and li not in seen:
                seen.add(li)
                owner[li] = ri
                return True
        for _rank, li, _how in opts:          # else move the owner of a taken one
            if li in seen:
                continue
            seen.add(li)
            if place(owner[li], seen):
                owner[li] = ri
                return True
        return False

    for ri in order:
        place(ri, set())
    out: List[Tuple[int, int, Tuple[int, int, float], str]] = []
    for li, ri in owner.items():
        rank, _li, how = next(o for o in by_result[ri] if o[1] == li)
        out.append((ri, li, rank, how))
    out.sort(key=lambda x: x[0])
    return out


# --------------------------------------------------------------------------- API


def correlate(client: Any, results: Sequence[Any], *, client_ip: Optional[str],
              window_s: int = 180, log: Any = None, max_logs: int = 300,
              time_frame: str = "last-hour",
              filter_text: Optional[str] = None) -> Dict[str, Optional[dict]]:
    """Return ``{result.id: match or None}`` for every result.

    A match is ``{"time", "action", "blade", "rule", "protection", "category", "log_id"}``
    plus ``product``, ``severity``, ``confidence``, ``profile``, ``layer``, ``dst``,
    ``resource``, ``description``, ``gateway``, ``delta_s``, ``matched_on``,
    ``blocking`` (blocking action: the caller may upgrade UNKNOWN to BLOCKED),
    ``detect`` and ``source`` ("gateway log").

    Never raises for "no logs" or for a query the server rejects (those are logged at
    WARN); raises for transport, TLS and authentication errors.
    """
    log = log if log is not None else (getattr(client, "log", None) or _NullLog())
    out: Dict[str, Optional[dict]] = {}
    items = [r for r in (results or []) if _get(r, "id") is not None]
    for r in items:
        out[str(_get(r, "id"))] = None
    if not items:
        return out

    ip = (client_ip or "").strip()
    if not ip:
        for r in items:
            if _get(r, "local_ip"):
                ip = str(_get(r, "local_ip")).strip()
                break
    flt = filter_text if filter_text is not None else ("src:%s" % ip if ip else "")

    has = getattr(client, "has", None)
    if callable(has) and not has("show-logs"):
        log.warn("correlate", "this management server has no show-logs; skipping log matching")
        return out
    try:
        logs = client.show_logs(flt, time_frame=time_frame, max_logs=max_logs)
    except MgmtApiError as exc:
        if _is_auth_or_transport(exc):
            raise
        log.warn("correlate", "show-logs failed; results are not matched to gateway logs",
                 error=exc.what, api_code=exc.api_code, filter=flt)
        return out
    logs = [e for e in (logs or []) if isinstance(e, dict)]

    products: Dict[str, int] = {}
    actions: Dict[str, int] = {}
    parsed: List[Tuple[Dict[str, Any], Optional[_dt.datetime], Optional[str], Set[str], List[str], bool]] = []
    for entry in logs:
        product = str(entry.get("product") or entry.get("blade") or "")
        if product:
            products[product] = products.get(product, 0) + 1
        action = str(entry.get("action") or "")
        if action:
            actions[action] = actions.get(action, 0) + 1
        hosts, resources = _log_hosts(entry)
        blade_text = " ".join(str(entry.get(k) or "") for k in ("product", "blade", "protection_type"))
        is_ai = bool(re.search(r"(?<![A-Za-z])AI(?![a-z])", blade_text)) or "lakera" in blade_text.lower()
        parsed.append((entry, log_time(entry), action_class(action), hosts, resources, is_ai))
    log.info("correlate", "gateway logs", count=len(logs), filter=flt, time_frame=time_frame,
             products=sorted(products), product_counts=products, actions=actions)

    candidates: List[Tuple[Tuple[int, int, float], int, int, str]] = []
    nearest: Dict[int, float] = {}
    for ri, r in enumerate(items):
        sent = _sent_time(r)
        if sent is None:
            log.debug("correlate", "result has no usable sent_at", id=_get(r, "id"))
            continue
        verdict = str(_get(r, "verdict") or "").upper()
        # A prompt that reached the provider can only match a Detect log: a leftover
        # Prevent/Drop log (an earlier run, another prompt) would be false proof.
        wanted = ("detect",) if verdict == "ALLOWED" else ("block",)
        host = _get(r, "host")
        rip = _get(r, "remote_ip")
        for li, (entry, ts, cls, hosts, resources, is_ai) in enumerate(parsed):
            if cls not in wanted or ts is None:
                continue
            how = _host_matches(hosts, resources, host, rip)
            if how is None:
                continue
            delta = _delta(ts, sent, _get(r, "ms"))
            if delta > window_s:
                nearest[ri] = min(nearest.get(ri, delta), delta)
                continue
            rank = (wanted.index(cls), 0 if is_ai else 1, delta)
            candidates.append((rank, ri, li, how))
    for ri, li, rank, how in _assign(candidates, items):
        entry, ts, cls, _h, _res, _ai = parsed[li]
        out[str(_get(items[ri], "id"))] = _match_dict(entry, ts, rank[2], how, cls or "")

    for ri, r in enumerate(items):
        rid = str(_get(r, "id"))
        m = out.get(rid)
        if m is not None:
            log.info("correlate", "matched %s" % rid, verdict=_get(r, "verdict"),
                     action=m.get("action"), blade=m.get("blade"), protection=m.get("protection"),
                     delta_s=m.get("delta_s"), log_id=m.get("log_id"))
        elif ri in nearest:
            log.info("correlate", "no log for %s inside the time window" % rid,
                     verdict=_get(r, "verdict"), host=_get(r, "host"), window_s=window_s,
                     closest_s=round(nearest[ri], 1),
                     hint="check the clock of this computer and of the management server")
    log.info("correlate", "matched %d of %d result(s)" % (sum(1 for v in out.values() if v),
                                                          len(out)))
    return out
