"""Demo report: JSON + one self-contained HTML page (no secrets).

* :func:`build_report` -- a display-safe dict from an engine
  :class:`~aiguard.engine.Session` (duck-typed: anything with the same attributes works).
* :func:`render_html` -- that dict as a standalone HTML page: inline CSS, no scripts,
  no external resources (a Content-Security-Policy forbids loading any), every text
  passed through :func:`aiguard.redact.redact` and :func:`html.escape`.
* :func:`write_report` -- writes ``<home>/reports/report_<YYYY-MM-DD_HHMMSS>[_n].json``
  and the matching ``.html`` (mode 0600) and returns both paths.

Prompts are shortened to 300 characters (plus length and a sha256 prefix): the report
shows what was sent without becoming a copy of everything typed during the demo.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import html
import json
import os
from pathlib import Path
from typing import IO, Any, Dict, List, Optional, Tuple, Union

from . import __version__
from . import paths as _paths
from . import redact as _redact

__all__ = ["build_report", "render_html", "write_report", "PROMPT_CHARS"]

PROMPT_CHARS = 300


# --------------------------------------------------------------------------- data


def _now_iso() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _call(obj: Any, name: str, *args: Any, default: Any = None, **kw: Any) -> Any:
    fn = getattr(obj, name, None)
    if not callable(fn):
        return default
    try:
        return fn(*args, **kw)
    except Exception:  # noqa: BLE001 - a report must not fail because one part did
        return default


def _to_dict(obj: Any) -> Optional[dict]:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return dict(obj)
    data = _call(obj, "to_dict")
    return data if isinstance(data, dict) else None


def _short_prompt(text: Any) -> Dict[str, Any]:
    value = "" if text is None else str(text)
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    shown = value if len(value) <= PROMPT_CHARS else value[:PROMPT_CHARS] + "..."
    return {"prompt": _redact.redact(shown), "prompt_len": len(value), "prompt_sha256": digest}


def _result_row(session: Any, r: Any) -> Dict[str, Any]:
    data = _to_dict(r) or {}
    data.update(_short_prompt(getattr(r, "prompt", data.get("prompt"))))
    reasons = _call(session, "diagnose", r, default=[]) or []
    data["diagnosis"] = [str(x) for x in reasons]
    return data


def _plan_summary(plan: Any) -> Optional[Dict[str, Any]]:
    data = _to_dict(plan)
    if not data:
        return None
    steps = []
    for s in data.get("steps") or []:
        steps.append({k: s.get(k) for k in ("id", "kind", "action", "command", "describe",
                                             "status", "message", "manual_steps")})
    keep = ("plan_id", "template", "title", "server", "domain", "gateway", "package",
            "threat_layer", "https_layer", "protected_scope", "field_variant", "created_at",
            "warnings", "counts")
    out = {k: data.get(k) for k in keep}
    out["steps"] = steps
    return out


def _apply_summary(res: Any) -> Optional[Dict[str, Any]]:
    data = _to_dict(res)
    if not data:
        return None
    keep = ("ok", "kind", "plan_id", "rollback_id", "published", "installed", "message",
            "state", "warnings", "moderation_enabled", "error")
    out = {k: data.get(k) for k in keep}
    out["steps"] = [{k: s.get(k) for k in ("id", "action", "status", "message", "ms")}
                    for s in data.get("steps") or []]
    return out


def build_report(session: Any) -> Dict[str, Any]:
    """Everything the report shows, display-safe (passed through ``redact_obj``)."""
    client = getattr(session, "client", None)
    conn = _call(client, "summary", default=None) if client is not None else None
    gw = getattr(session, "gateway", None)
    gw_data = None
    if gw is not None:
        full = _to_dict(gw) or {}
        gw_data = {k: full.get(k) for k in (
            "name", "type", "ipv4", "version", "release", "policy_package", "is_cluster",
            "https_inspection", "threat_prevention_mode", "workforce_ai", "cluster_members")}
    results = list(getattr(session, "results", None) or [])
    log = getattr(session, "log", None)
    summary = _call(session, "summary", default={}) or {}
    data: Dict[str, Any] = {
        "kind": "aiguard-demo-report",
        "version": __version__,
        "generated_at": _now_iso(),
        "connection": conn,
        "gateway": gw_data,
        "local_ip": getattr(session, "local_ip", None),
        "lakera": dict(getattr(session, "lakera", None) or {}),
        "moderation_enabled": getattr(session, "moderation_enabled", None),
        "enforcement": getattr(session, "enforcement", None),
        "preflight": _to_dict(getattr(session, "preflight", None)),
        "plan": _plan_summary(getattr(session, "plan", None)),
        "apply": _apply_summary(getattr(session, "last_apply", None)),
        "summary": summary,
        "results": [_result_row(session, r) for r in results],
        "log_path": str(getattr(log, "path", "") or "") or None,
        "log_jsonl_path": str(getattr(log, "jsonl_path", "") or "") or None,
        "report_json": None,
        "report_html": None,
    }
    return _redact.redact_obj(data)


# --------------------------------------------------------------------------- HTML

_CSS = """
:root{--bg:#f6f7f9;--card:#ffffff;--text:#1d2330;--muted:#5c6577;--line:#dfe3ea;
--ok-bg:#e3f4ea;--ok:#17633a;--bad-bg:#fbe6e6;--bad:#9b1c1c;--warn-bg:#fdf1d8;--warn:#7a4b00;
--info-bg:#e6eefb;--info:#1f4a8a;--skip-bg:#eceef2;--skip:#4a5262}
@media (prefers-color-scheme: dark){:root{--bg:#14171c;--card:#1d2128;--text:#e6e9ef;
--muted:#9aa3b2;--line:#2e343e;--ok-bg:#163b27;--ok:#8fe0b0;--bad-bg:#4a1d1d;--bad:#ffb4b4;
--warn-bg:#46340f;--warn:#ffd88a;--info-bg:#1b2c48;--info:#a9c7ff;--skip-bg:#2a2f37;--skip:#c3cad6}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1120px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 10px}
.muted{color:var(--muted)}.small{font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:12px 0}
.tiles{display:flex;flex-wrap:wrap;gap:12px}
.tile{flex:1 1 140px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:26px;line-height:1.2}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;vertical-align:top;padding:8px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:13px}
.scroll{overflow-x:auto}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.b-ok{background:var(--ok-bg);color:var(--ok)}.b-bad{background:var(--bad-bg);color:var(--bad)}
.b-warn{background:var(--warn-bg);color:var(--warn)}.b-info{background:var(--info-bg);color:var(--info)}
.b-skip{background:var(--skip-bg);color:var(--skip)}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
pre{white-space:pre-wrap;word-break:break-word;margin:6px 0;padding:8px;background:var(--bg);
border:1px solid var(--line);border-radius:6px}
ul{margin:4px 0;padding-left:20px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}
dt{color:var(--muted)}dd{margin:0;word-break:break-word}
details summary{cursor:pointer;color:var(--info)}
"""


def _t(value: Any) -> str:
    """Redacted, HTML-escaped text."""
    if value is None:
        return ""
    if isinstance(value, bool):
        value = "yes" if value else "no"
    return html.escape(_redact.redact(str(value)), quote=True)


def _badge(text: str, kind: str) -> str:
    return '<span class="badge b-%s">%s</span>' % (kind, _t(text))


_VERDICT_KIND = {"BLOCKED": "info", "ALLOWED": "skip", "UNKNOWN": "warn", "ERROR": "bad"}
_CHECK_KIND = {"pass": "ok", "fail": "bad", "warn": "warn", "skip": "skip"}


def _dl(pairs: List[Tuple[str, Any]]) -> str:
    rows = "".join("<dt>%s</dt><dd>%s</dd>" % (_t(k), _t(v)) for k, v in pairs
                   if v not in (None, "", [], {}))
    return "<dl>%s</dl>" % rows if rows else '<p class="muted">Nothing recorded.</p>'


def _list(items: Any) -> str:
    items = [x for x in (items or []) if x not in (None, "")]
    if not items:
        return ""
    return "<ul>%s</ul>" % "".join("<li>%s</li>" % _t(x) for x in items)


def _log_match_html(m: Optional[dict]) -> str:
    if not m:
        return '<span class="muted">none</span>'
    parts = [("time", m.get("time")), ("action", m.get("action")), ("blade", m.get("blade")),
             ("rule", m.get("rule")), ("protection", m.get("protection")),
             ("log id", m.get("log_id"))]
    return "<br>".join("%s: %s" % (_t(k), _t(v)) for k, v in parts if v)


def _results_html(results: List[dict]) -> str:
    if not results:
        return '<p class="muted">No prompts were sent in this session.</p>'
    rows = []
    for r in results:
        verdict = str(r.get("verdict") or "")
        matched = bool(r.get("matched"))
        expect_text = "expected %s" % ("block" if r.get("expect") == "block" else "allow")
        cat = r.get("category")
        cat_html = _t(cat) if cat else '<span class="muted">-</span>'
        if cat and r.get("category_source"):
            cat_html += '<br><span class="muted small">from %s</span>' % _t(r["category_source"])
        if r.get("confidence_label"):
            cat_html += '<br><span class="muted small">%s</span>' % _t(r["confidence_label"])
        extra = []
        if r.get("diagnosis"):
            extra.append("<b>Why:</b>%s" % _list(r["diagnosis"]))
        detail_pairs = [("Reason", r.get("reason")), ("HTTP status", r.get("http_status")),
                        ("Content type", r.get("content_type")), ("Issuer", r.get("issuer")),
                        ("Inspected", r.get("inspected")), ("Source IP", r.get("local_ip")),
                        ("Remote IP", r.get("remote_ip")), ("URL", r.get("url")),
                        ("Model", r.get("model")), ("Key", r.get("key_source")),
                        ("Sent at", r.get("sent_at")), ("Prompt length", r.get("prompt_len")),
                        ("Prompt sha256", r.get("prompt_sha256"))]
        snippet = r.get("snippet")
        details = ("<details><summary>Details</summary>%s%s</details>"
                   % (_dl(detail_pairs),
                      ("<div class=\"small muted\">Reply (first bytes, redacted)</div><pre>%s</pre>"
                       % _t(snippet)) if snippet else ""))
        rows.append(
            "<tr><td><code>%s</code><br><span class=\"muted small\">%s</span></td>"
            "<td>%s</td><td>%s<br><span class=\"muted small\">%s</span></td>"
            "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (_t(r.get("prompt_id") or r.get("id")), _t(r.get("provider")),
               "<pre>%s</pre>" % _t(r.get("prompt")),
               _badge(verdict or "?", _VERDICT_KIND.get(verdict, "skip")), _t(expect_text),
               _badge("as expected", "ok") if matched else _badge("unexpected", "bad"),
               _t(r.get("evidence")), cat_html, _log_match_html(r.get("log_match")),
               "%s%s" % ("".join(extra), details)))
    head = ("<tr><th>Prompt</th><th>Text</th><th>Verdict</th><th>Result</th><th>Evidence</th>"
            "<th>Category</th><th>Gateway log</th><th>More</th></tr>")
    return '<div class="card scroll"><table>%s%s</table></div>' % (head, "".join(rows))


def _preflight_html(pf: Optional[dict]) -> str:
    if not pf:
        return '<p class="muted">Preflight was not run in this session.</p>'
    rows = []
    for c in pf.get("checks") or []:
        status = str(c.get("status") or "")
        label = status if not (status == "fail" and c.get("blocking")) else "fail (blocking)"
        ev = c.get("evidence") or {}
        ev_html = "<br>".join("%s: %s" % (_t(k), _t(v)) for k, v in ev.items())
        said = c.get("server_said")
        said_html = ('<div class="small">Server said: <code>%s</code></div>' % _t(said)
                     if said else "")
        rows.append("<tr><td><code>%s</code><br>%s</td><td>%s</td><td>%s%s%s</td><td>%s</td></tr>"
                    % (_t(c.get("id")), _t(c.get("title")),
                       _badge(label, _CHECK_KIND.get(status, "skip")), _t(c.get("detail")),
                       said_html,
                       ("<div class=\"small muted\">%s</div>" % ev_html) if ev_html else "",
                       _list(c.get("fix"))))
    head = "<tr><th>Check</th><th>Status</th><th>Detail</th><th>Fix</th></tr>"
    return ('<p>%s <span class="muted">(gateway %s, %s)</span></p>'
            '<div class="card scroll"><table>%s%s</table></div>'
            % (_t(pf.get("summary")), _t(pf.get("gateway")), _t(pf.get("created_at")),
               head, "".join(rows)))


def _plan_html(plan: Optional[dict], apply: Optional[dict]) -> str:
    if not plan and not apply:
        return '<p class="muted">No change plan in this session.</p>'
    out = []
    if plan:
        out.append(_dl([("Plan id", plan.get("plan_id")), ("Template", plan.get("title")
                                                           or plan.get("template")),
                        ("Package", plan.get("package")), ("Threat layer", plan.get("threat_layer")),
                        ("Protected scope", plan.get("protected_scope")),
                        ("Created", plan.get("created_at"))]))
        rows = "".join("<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>"
                       % (_t(s.get("id")), _t(s.get("action")), _t(s.get("describe")),
                          _t(s.get("status")))
                       for s in plan.get("steps") or [])
        out.append('<div class="scroll"><table><tr><th>Step</th><th>Action</th><th>What</th>'
                   '<th>Status</th></tr>%s</table></div>' % rows)
        if plan.get("warnings"):
            out.append("<p><b>Warnings</b></p>%s" % _list(plan.get("warnings")))
    if apply:
        out.append("<p><b>Apply:</b> %s %s</p>" % (
            _badge("ok" if apply.get("ok") else "failed", "ok" if apply.get("ok") else "bad"),
            _t(apply.get("message") or apply.get("state"))))
        if apply.get("rollback_id"):
            out.append("<p>Undo with: <code>aiguard rollback %s</code></p>" % _t(apply["rollback_id"]))
        err = apply.get("error")
        if err:
            out.append(_dl([("What failed", err.get("what")), ("Server said", err.get("server_said")),
                            ("Why", err.get("why")), ("State", err.get("state"))]))
            out.append(_list(err.get("fix")))
    return '<div class="card">%s</div>' % "".join(out)


def render_html(data: Dict[str, Any]) -> str:
    """The report as one standalone HTML document (no scripts, no external resources)."""
    data = _redact.redact_obj(data or {})
    s = data.get("summary") or {}
    conn = data.get("connection") or {}
    gw = data.get("gateway") or {}
    lakera = data.get("lakera") or {}
    tiles = [("Prompts", s.get("total", 0)), ("Blocked", s.get("blocked", 0)),
             ("Allowed", s.get("allowed", 0)), ("As expected", s.get("matched", 0)),
             ("Unexpected", len(s.get("unexpected") or []))]
    tiles_html = "".join('<div class="tile"><span class="muted small">%s</span><b>%s</b></div>'
                         % (_t(k), _t(v)) for k, v in tiles)
    blocked_by = s.get("blocked_by") or {}
    by_html = ("<p><b>Blocked by category:</b> %s</p>" % ", ".join(
        "%s (%s)" % (_t(k), _t(v)) for k, v in blocked_by.items())) if blocked_by else ""
    setup = _dl([
        ("Management server", conn.get("server")), ("Server type", conn.get("server_type")),
        ("Management API", "%s %s" % (conn.get("api_version") or "",
                                      ("(%s)" % conn["release"]) if conn.get("release") else "")),
        ("Domain", conn.get("domain") or ("System Data" if conn.get("system_data") else None)),
        ("Certificate SHA-256", conn.get("fingerprint_sha256")),
        ("Gateway", gw.get("name")), ("Gateway version", gw.get("release") or gw.get("version")),
        ("Policy package", gw.get("policy_package")),
        ("HTTPS Inspection", gw.get("https_inspection")),
        ("This computer", data.get("local_ip")),
        ("AI Agent Security key", lakera.get("masked_key")),
        ("Project", lakera.get("project_id")),
        ("Key validated", ("yes (by %s)" % lakera.get("validated_by")) if lakera.get("validated")
         else ("no" if lakera else None)),
        ("Content moderation", "on" if data.get("moderation_enabled") else
         ("off" if data.get("moderation_enabled") is False else "not changed in this session")),
    ])
    files = _dl([("Run log", data.get("log_path")), ("Structured log", data.get("log_jsonl_path")),
                 ("This report (JSON)", data.get("report_json")),
                 ("This report (HTML)", data.get("report_html"))])
    title = "AI Guard demo report"
    return "".join([
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'\">",
        "<meta name=\"referrer\" content=\"no-referrer\">",
        "<title>%s</title><style>%s</style></head><body><main>" % (_t(title), _CSS),
        "<h1>%s</h1><p class=\"muted\">Generated %s by AI Guard Demo Kit %s</p>"
        % (_t(title), _t(data.get("generated_at")), _t(data.get("version"))),
        "<div class=\"tiles\">%s</div>%s" % (tiles_html, by_html),
        "<h2>Setup</h2><div class=\"card\">%s</div>" % setup,
        "<h2>Prompts and verdicts</h2>%s" % _results_html(data.get("results") or []),
        "<h2>Preflight</h2>%s" % _preflight_html(data.get("preflight")),
        "<h2>Change plan</h2>%s" % _plan_html(data.get("plan"), data.get("apply")),
        "<h2>Files</h2><div class=\"card\">%s</div>" % files,
        "<p class=\"muted small\">Secrets are never written to this report: keys are shown "
        "masked (prefix****last4). Prompts are shortened to %d characters.</p>" % PROMPT_CHARS,
        "</main></body></html>\n",
    ])


# --------------------------------------------------------------------------- files


def _create_exclusive(path: Path) -> IO[str]:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8", newline="\n")


def write_report(data: Union[Dict[str, Any], Any], *, home: Optional[Union[str, Path]] = None,
                 directory: Optional[Union[str, Path]] = None,
                 prefix: str = "report") -> Tuple[Path, Path]:
    """Write the JSON and HTML report; returns ``(json_path, html_path)``.

    ``data`` is a :func:`build_report` dict, or a session (then it is built here).
    Files go to ``directory`` or ``<home>/reports``; names never overwrite existing ones.
    """
    if not isinstance(data, dict):
        data = build_report(data)
    out_dir = Path(directory) if directory is not None else _paths.reports_dir(home)
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    n = 1
    while True:
        stem = "%s_%s" % (prefix, stamp) if n == 1 else "%s_%s_%d" % (prefix, stamp, n)
        n += 1
        json_path = out_dir / (stem + ".json")
        html_path = out_dir / (stem + ".html")
        if json_path.exists() or html_path.exists():
            continue
        try:
            jf = _create_exclusive(json_path)
        except FileExistsError:
            continue
        try:
            hf = _create_exclusive(html_path)
        except FileExistsError:
            jf.close()
            try:
                json_path.unlink()
            except OSError:
                pass
            continue
        break
    data = dict(data)
    data["report_json"] = str(json_path)
    data["report_html"] = str(html_path)
    safe = _redact.redact_obj(data)
    with jf:
        jf.write(json.dumps(safe, indent=2, ensure_ascii=False, default=str) + "\n")
    with hf:
        hf.write(render_html(safe))
    return json_path, html_path
