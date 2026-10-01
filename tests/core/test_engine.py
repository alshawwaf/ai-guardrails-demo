"""End-to-end tests for aiguard.engine.Session (spec 8) and aiguard.report.

FakeMgmtServer (Management API), FakeProviderServer (an LLM API behind a "gateway" that
blocks some prompts) and FakeLakeraServer (Lakera Guard) run on 127.0.0.1 over TLS that
is verified against a CA generated at test time. Every key is a random value generated
here; the tests assert that none of them reaches a log, the state file or a report.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
import re
import secrets
import sys
import threading
from pathlib import Path

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from fakes import (FakeLakeraServer, FakeMgmtServer, FakeProviderServer,  # noqa: E402
                   make_gateway, make_log, make_test_pki)

from aiguard import engine as engine_mod  # noqa: E402
from aiguard import report as report_mod  # noqa: E402
from aiguard.engine import GUARD_KEY_WARNING, WILL_VALIDATE_LATER, Session  # noqa: E402
from aiguard.errors import AiguardError, ApprovalError, LakeraError  # noqa: E402
from aiguard.plan import PlanOptions  # noqa: E402
from aiguard.probe import ProbeResult  # noqa: E402

PROVIDER_ENV = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY")
RULES = [
    ("ignore all previous instructions", "usercheck"),   # inj-override
    ("you are dan", "reset"),                            # jb-dan
    ("attacker.example", "timeout"),                     # inj-indirect: silent drop
]


def lab_gateway(**kw):
    kw.setdefault("interfaces", [("eth0", "10.1.1.111", 24), ("eth1", "198.51.100.111", 24),
                                 ("eth2", "127.0.0.1", 8)])
    return make_gateway("HQ-GW", "10.1.1.111", **kw)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return make_test_pki(tmp_path_factory.mktemp("engine-pki"))


@pytest.fixture(scope="module")
def provider(pki):
    srv = FakeProviderServer(pki, rules=RULES, timeout_cap=3.0).start()
    yield srv
    srv.stop()


@pytest.fixture(scope="module")
def lakera_srv(pki):
    srv = FakeLakeraServer(pki).start()
    yield srv
    srv.stop()


@pytest.fixture(autouse=True)
def _no_provider_env(monkeypatch):
    for name in PROVIDER_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def mgmt(pki):
    servers = []

    def start(**kw):
        kw.setdefault("gateways", [lab_gateway()])
        srv = FakeMgmtServer(pki, **kw).start()
        servers.append(srv)
        return srv

    yield start
    for s in servers:
        assert s.errors == [], s.errors[0]
        s.stop()


@pytest.fixture
def make_session(aiguard_home, pki, provider, lakera_srv):
    sessions = []

    def make(**kw):
        kw.setdefault("home", aiguard_home)
        kw.setdefault("provider_ca_file", pki.ca_pem_path)
        kw.setdefault("provider_base_urls", {"openai": provider.base_url,
                                             "anthropic": provider.base_url})
        kw.setdefault("lakera_url", lakera_srv.url("/v2/guard"))
        kw.setdefault("task_poll", 0.01)
        kw.setdefault("probe_timeout", 1.5)
        kw.setdefault("tls_timeout", 5)
        kw.setdefault("mgmt_timeout", 10)
        s = Session(**kw)
        sessions.append(s)
        return s

    yield make
    for s in sessions:
        s.close()


def mgmt_key() -> str:
    return "fake-mgmt-" + secrets.token_hex(16)


def connect(session, srv, pki, key=None):
    return session.connect("127.0.0.1", port=srv.port, api_key=key or mgmt_key(),
                           ca_file=pki.ca_pem_path)


def ready(session, srv, pki, key=None):
    connect(session, srv, pki, key)
    session.discover()
    return session.select_gateway("HQ-GW")


def all_text(home: Path) -> str:
    chunks = []
    for p in sorted(Path(home).rglob("*")):
        if p.is_file():
            chunks.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def at(result: ProbeResult, seconds: float = 0.0) -> dt.datetime:
    return dt.datetime.fromtimestamp(result.sent_epoch, dt.timezone.utc) + dt.timedelta(seconds=seconds)


def fake_result(**kw) -> ProbeResult:
    base = dict(id="r-" + secrets.token_hex(3), provider="openai", host="api.openai.com",
                prompt="test", expect="block", verdict="ALLOWED", reason="", http_status=200,
                content_type="application/json", ms=40, inspected=True,
                issuer="AI Guard Test Outbound CA / AI Guard Test", local_ip="127.0.0.1",
                remote_ip="127.0.0.1", sent_at="2026-09-30T10:00:00.000+00:00", snippet="",
                dummy_key=False, evidence="JSON reply from the provider")
    base.update(kw)
    return ProbeResult(**base)


# --------------------------------------------------------------------------- end to end


def test_end_to_end_demo_flow(make_session, mgmt, pki, provider, lakera_srv, aiguard_home):
    srv = mgmt()
    session = make_session()
    key = mgmt_key()
    provider_key = "sk-test-" + secrets.token_hex(16)
    guard_key = lakera_srv.valid_key        # 64 hex, generated by the fake at start-up
    project = lakera_srv.project_id
    assert re.fullmatch(r"[0-9a-f]{64}", guard_key)

    st = session.status()
    assert st["connected"] is False and st["step"] == "connect"

    info = connect(session, srv, pki, key)
    assert info["server_type"] == "SMS" and info["api_version"] == "2.2"
    assert info["release"] == "R82.20" and info["read_only"] is False
    assert info["fingerprint_sha256"] == pki.server_sha256
    assert info["fingerprint_sha1"] == pki.server_sha1
    assert info["domains"] == [] and session.list_domains() == []
    sid = session.client.sid
    assert sid

    gws = session.discover()
    assert [g.name for g in gws] == ["HQ-GW"]
    gw = session.select_gateway("hq-gw")
    assert gw.detailed and gw.https_inspection is True and session.gateway is gw

    pf = session.run_preflight()
    assert pf.ok and [c.status for c in pf.checks] == ["pass"] * 12, \
        [(c.id, c.status, c.detail) for c in pf.checks if c.status != "pass"]
    assert session.local_ip == "127.0.0.1"
    assert session.status()["step"] == "configure"

    lk = session.set_lakera(guard_key, project, direct_check=True)
    assert lk["validated"] is True and lk["validated_by"] == "management"
    assert lk["format_ok"] is True and lk["project_id"] == project
    assert lk["masked_key"] == "****" + guard_key[-4:]
    assert lk["direct"]["ok"] is True
    assert srv.last_call("test-ai-agent-security-api-key") == {"api-key": guard_key,
                                                               "project-id": project}
    session.set_provider_key("openai", provider_key)

    plan = session.build_plan(PlanOptions(gateway="", moderation=True))
    assert plan.gateway == "HQ-GW" and plan.package == "Standard"
    assert [s.id for s in plan.steps] == ["client_host", "profile", "rule", "publish", "install",
                                          "moderation"]
    assert plan.client_host_name == "aiguard-client-127-0-0-1"
    assert guard_key not in json.dumps(plan.to_dict())
    assert session.status()["step"] == "install"

    with pytest.raises(ApprovalError):
        session.apply("000000000000")
    steps_seen = []
    res = session.apply(plan.plan_id, progress_cb=lambda *a: steps_seen.append(a[0]))
    assert res.ok, res.error and res.error.to_dict()
    assert res.published and res.installed and res.rollback_id
    assert session.moderation_enabled is True and srv.state.moderation == {"HQ-GW": True}
    assert "moderation" in steps_seen and "publish" in steps_seen
    assert srv.find("threat-profile", "AIGuard-Demo")["_secret"] == guard_key
    assert session.status()["step"] == "demo"

    # enforcement check: the "gateway" answers inj-override with a UserCheck page
    r = session.confirm_enforcement()
    assert r.verdict == "BLOCKED" and r.matched and r.prompt_id == "inj-override"
    assert session.enforcement["confirmed"] is True
    assert r.dummy_key is False and r.key_source == "explicit"
    sent_auth = provider.requests[-1]["headers"].get("Authorization")
    assert sent_auth == "Bearer " + provider_key

    progress = []
    scene = session.run_scene("injection", progress_cb=lambda *a: progress.append(a))
    assert [x.prompt_id for x in scene] == ["inj-override", "jb-dan", "inj-indirect"]
    assert [x.verdict for x in scene] == ["BLOCKED", "BLOCKED", "UNKNOWN"]
    assert scene[0].category == "prompt_attack" and scene[0].category_source == "lakera"
    assert scene[0].confidence_label == "confident"
    assert "connection terminated" in scene[1].evidence
    assert scene[2].evidence == "timeout"
    assert [p[1] for p in progress] == ["running", "done"] * 3

    # one gateway log per prompt sent (same source IP, same time, dst = host). Log times
    # have one-second precision, so which log pairs with which prompt may vary; every
    # prompt gets one.
    for x in [r] + scene:
        srv.add_log(make_log(src=x.local_ip, host=x.host, time_=at(x, 0.2)))
    session.correlate()
    for x in [r] + scene:
        assert x.log_match is not None, x.prompt_id
        assert x.log_match["action"] == "Prevent" and x.log_match["blade"] == "AI Agent Security"
        assert x.category == "Prompt Injection" and x.category_source == "gateway log"
    # UNKNOWN -> BLOCKED only because a matching Prevent log exists (section 10)
    assert scene[2].verdict == "BLOCKED" and scene[2].evidence == "gateway log"
    assert "gateway logged Prevent" in scene[2].reason
    assert len({x.log_match["log_id"] for x in [r] + scene}) == 4

    summary = session.summary()
    assert summary["total"] == 4 and summary["blocked"] == 4 and summary["matched"] == 4
    assert summary["unexpected"] == []
    assert summary["blocked_by"] == {"Prompt Injection": 4}
    assert summary["with_log"] == 4 and summary["enforcement_confirmed"] is True

    html_path = session.write_report()
    json_path = session.report_json_path
    assert html_path.exists() and json_path.exists()
    assert html_path.parent == aiguard_home / "reports"
    html = html_path.read_text(encoding="utf-8")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["summary"]["total"] == 4 and len(data["results"]) == 4
    assert data["preflight"]["ok"] is True and data["plan"]["plan_id"] == plan.plan_id
    assert data["log_path"] == str(session.log.path)
    assert data["report_html"] == str(html_path)
    for needle in ("inj-indirect", "BLOCKED", "Prompt Injection", "gateway log",
                   str(session.log.path), plan.plan_id, "12 passed, 0 blocking, 0 warnings",
                   "AI Agent Security"):
        assert needle in html, needle
    # self-contained: no scripts, no external resources
    assert "<script" not in html.lower() and "<link" not in html.lower()
    assert not re.search(r"""(?:src|href)\s*=""", html, re.I)
    assert "default-src 'none'" in html
    assert session.summary()["report_path"] == str(html_path)

    rb = session.rollback()
    assert rb.ok and session.moderation_enabled is False
    assert srv.find("threat-profile", "AIGuard-Demo") is None
    assert srv.state.moderation == {"HQ-GW": False}

    st = session.status()
    json.dumps(st)   # JSON-serialisable
    assert st["connected"] is True and st["gateway"]["name"] == "HQ-GW"
    assert st["provider_keys"] == {"openai": "sk-****" + provider_key[-4:]}
    assert st["direct_lakera"]["configured"] is True
    assert len(st["results"]) == 4 and st["busy"] is None

    session.close()
    assert session.client is None
    assert "logout" in srv.call_names()
    text = all_text(aiguard_home)
    for secret in (key, provider_key, guard_key, sid):
        assert secret not in text
        assert secret not in json.dumps(st)
    assert "****" in text
    assert (aiguard_home / "state.json").exists()


# --------------------------------------------------------------------------- preflight


@pytest.mark.parametrize("scenario,check,status,blocking", [
    ("https_off", "https_gw", "fail", True),
    ("autonomous", "tp_mode", "warn", False),
    ("old_version", "api_version", "fail", True),
])
def test_session_preflight_scenarios(make_session, mgmt, pki, scenario, check, status, blocking):
    srv = mgmt(scenario=scenario)
    session = make_session()
    ready(session, srv, pki)
    report = session.run_preflight()
    c = report.check(check)
    assert c.status == status and c.blocking is blocking
    assert session.preflight is report
    if scenario == "https_off":
        assert c.fixable == "https-inspection" and report.fixable() == ["https-inspection"]
        assert c.fix[0] == "aiguard fix https-inspection  (asks for approval)"
        assert not report.ok
        with pytest.raises(AiguardError) as ei:     # no outbound CA yet: the fix stops early
            session.build_https_plan()
        assert "outbound inspection certificate" in ei.value.what.lower()
    if scenario == "autonomous":
        assert report.ok
    if scenario == "old_version":
        assert "This server reports API 2 (R82)" in c.detail
        assert report.check("ai_support").status == "fail"


def test_https_fix_plan_turns_inspection_on(make_session, mgmt, pki):
    srv = mgmt()
    srv.gateway("HQ-GW")["enable-https-inspection"] = False
    session = make_session()
    ready(session, srv, pki)
    assert session.run_preflight().check("https_gw").status == "fail"
    plan = session.build_https_plan()
    assert plan.template == "https-inspection"
    res = session.apply(plan.plan_id)
    assert res.ok and res.installed
    assert session.gateway.https_inspection is True and session.preflight is None
    assert session.run_preflight().check("https_gw").status == "pass"


# --------------------------------------------------------------------------- AI key


def test_set_lakera_bad_ai_key_raises_and_keeps_previous(make_session, mgmt, pki, aiguard_home):
    srv = mgmt(scenario="bad_ai_key")
    session = make_session()
    ready(session, srv, pki)
    key = secrets.token_hex(32)
    with pytest.raises(LakeraError) as ei:
        session.set_lakera(key, "project-1234567890")
    err = ei.value
    assert err.what == "Check Point could not validate this AI Agent Security key"
    assert err.server_said == "Invalid API key"
    assert err.fix[-1] == ("The management server must reach the internet and be connected to "
                           "the Check Point Portal")
    assert any("Check Point Portal > AI Security > AI Guardrails" in f for f in err.fix)
    assert err.log_line
    assert session.lakera["validated"] is False and session.lakera["masked_key"] == ""
    with pytest.raises(AiguardError) as ei2:   # no key -> the plan cannot be built
        session.build_plan(PlanOptions(gateway="HQ-GW", lakera_project_id="project-1"))
    assert ei2.value.code == "plan.missing_secret"
    assert key not in all_text(aiguard_home)


def test_set_lakera_format_warning_and_rejection(make_session, mgmt, pki, aiguard_home):
    session = make_session()
    platform_key = "lk_platform_" + secrets.token_hex(12)
    info = session.set_lakera(platform_key, "project-1")   # not connected: format warning only
    assert info["format_ok"] is False and GUARD_KEY_WARNING in info["warnings"]
    assert info["validated"] is False and "Not validated yet" in info["message"]
    srv = mgmt()
    ready(session, srv, pki)
    with pytest.raises(LakeraError) as ei:                 # the server rejects the format
        session.set_lakera(platform_key, "project-1")
    assert "64-character hex" in (ei.value.server_said or "")
    assert ei.value.code == "lakera.rejected_format"
    with pytest.raises(LakeraError):
        session.set_lakera(secrets.token_hex(32), "")
    assert platform_key not in all_text(aiguard_home)


def test_key_param_rejected_is_validated_after_profile(make_session, mgmt, pki):
    srv = mgmt(scenario="ai_key_param_rejected")
    session = make_session()
    ready(session, srv, pki)
    key = secrets.token_hex(32)
    info = session.set_lakera(key, "project-777")
    assert info["validated"] is False and info["message"] == WILL_VALIDATE_LATER
    plan = session.build_plan(PlanOptions(gateway="HQ-GW"))
    res = session.apply(plan.plan_id)
    assert res.ok
    assert session.lakera["validated"] is True and session.lakera["validated_by"] == "management"
    assert srv.last_call("test-ai-agent-security-api-key") == {"profile-name": "AIGuard-Demo",
                                                               "project-id": "project-777"}


# --------------------------------------------------------------------------- diagnose


def test_diagnose_messages(make_session, mgmt, pki):
    session = make_session()
    ok = fake_result(expect="allow")
    assert session.diagnose(ok) == []

    public = fake_result(inspected=False, issuer="DigiCert Global G2 / DigiCert Inc")
    assert session.diagnose(public)[0] == ("HTTPS Inspection did not decrypt this connection "
                                           "(issuer DigiCert Global G2 / DigiCert Inc)")

    untrusted = fake_result(verdict="ERROR", inspected=True, http_status=None,
                            error={"code": "tls.untrusted", "what": "not trusted"})
    assert session.diagnose(untrusted)[0] == "this computer does not trust the outbound CA"

    detect = fake_result(log_match={"action": "Detect", "detect": True, "blocking": False})
    assert "the gateway detected it but the profile action is Detect" in session.diagnose(detect)

    not_checked = "gateway logs were not checked (not connected to management)"
    dummy = fake_result(dummy_key=True, http_status=401)
    assert session.diagnose(dummy) == [
        not_checked, "the provider answered 401 quickly; re-test with a real key"]

    session.moderation_enabled = False
    mod = fake_result(prompt_id="mod-threat")
    assert session.diagnose(mod) == [
        not_checked, "content moderation is not turned on (aiguard setup --moderation)"]
    session.moderation_enabled = True
    assert session.diagnose(mod) == [not_checked]   # never an empty explanation

    false_positive = fake_result(expect="allow", verdict="BLOCKED")
    assert "should go through" in session.diagnose(false_positive)[0]

    # "no log at all" needs a correlation that found nothing for this request
    srv = mgmt()
    connect(session, srv, pki)
    nolog = fake_result(sent_epoch=dt.datetime.now(dt.timezone.utc).timestamp())
    session.results.append(nolog)
    session.correlate()
    assert session.diagnose(nolog) == [
        "no gateway log for this request: check the rule's protected scope includes 127.0.0.1, "
        "the policy was installed, the key/project are valid, and the gateway can reach the "
        "Check Point cloud. If this computer is behind NAT or runs in Docker, 127.0.0.1 may not "
        "be the address the gateway sees: set it (web console: Connect > Network address "
        "translation; CLI: --local-ip or AIGUARD_LOCAL_IP)"]
    hints = session.log.tail(50, level="HINT")
    assert any("no gateway log" in h["msg"] for h in hints)


def test_unknown_is_upgraded_only_by_prevent_drop_block(make_session, mgmt, pki):
    srv = mgmt()
    session = make_session()
    connect(session, srv, pki)
    now = dt.datetime.now(dt.timezone.utc)
    a = fake_result(verdict="UNKNOWN", evidence="timeout", http_status=None, ms=1500,
                    sent_epoch=now.timestamp(), sent_at=now.isoformat())
    b = fake_result(verdict="UNKNOWN", evidence="timeout", http_status=None, ms=1500,
                    host="api.anthropic.com", remote_ip="127.0.0.2",
                    sent_epoch=now.timestamp(), sent_at=now.isoformat())
    session.results.extend([a, b])
    srv.add_log(make_log(src="127.0.0.1", host="api.openai.com", action="Drop", time_=now))
    srv.add_log(make_log(src="127.0.0.1", host="api.anthropic.com", action="Reject", time_=now))
    session.correlate()
    assert a.verdict == "BLOCKED" and a.evidence == "gateway log"
    assert a.category_source == "gateway log"
    assert b.log_match and b.log_match["action"] == "Reject"
    assert b.verdict == "UNKNOWN"     # matched, but Reject is not Prevent/Drop/Block


def test_detect_log_explains_allowed_prompt(make_session, mgmt, pki, provider):
    srv = mgmt()
    session = make_session()
    ready(session, srv, pki)
    r = session.run_prompt("Please summarise the quarterly numbers.", expect="block",
                           prompt_id="custom")
    assert r.verdict == "ALLOWED" and not r.matched and r.dummy_key
    srv.add_log(make_log(src=r.local_ip, host=r.host, action="Detect", time_=at(r, 0.1)))
    session.correlate()
    assert r.log_match and r.log_match["action"] == "Detect"
    reasons = session.diagnose(r)
    assert reasons == ["the gateway detected it but the profile action is Detect",
                       "the provider answered 401 quickly; re-test with a real key"]
    assert session.summary()["unexpected"][0]["reasons"] == reasons


def test_confirm_enforcement_not_blocked_is_diagnosed(make_session, mgmt, pki, provider):
    srv = mgmt()
    session = make_session(provider_base_urls={"anthropic": provider.base_url})
    ready(session, srv, pki)
    provider.default_behavior = "allow"
    try:
        r = session.confirm_enforcement(provider="anthropic")
    finally:
        provider.default_behavior = None
    assert r.verdict == "ALLOWED"
    assert session.enforcement["confirmed"] is False
    assert any("no gateway log" in x for x in session.enforcement["diagnosis"])


def test_moderation_scene_warns_when_not_enabled(make_session, mgmt, pki):
    srv = mgmt()
    session = make_session()
    ready(session, srv, pki)
    seen = []
    results = session.run_scene("moderation", progress_cb=lambda *a: seen.append(a))
    assert seen[0][0] == "moderation" and seen[0][1] == "warning"
    assert [r.verdict for r in results] == ["ALLOWED"] * 4
    reasons = session.diagnose(results[0])
    assert reasons[-1] == "content moderation is not turned on (aiguard setup --moderation)"
    assert results[3].matched   # mod-edge is expected to go through
    with pytest.raises(AiguardError) as ei:
        session.run_scene("custom")
    assert ei.value.code == "scene.interactive"


# --------------------------------------------------------------------------- engine rules


def test_errors_are_aiguard_errors(make_session, monkeypatch):
    session = make_session()
    with pytest.raises(AiguardError) as ei:
        session.discover()
    assert ei.value.code == "engine.not_connected" and ei.value.log_line
    with pytest.raises(AiguardError) as ei:
        session.run_preflight()
    assert ei.value.code == "engine.not_connected"
    with pytest.raises(AiguardError):
        session.set_provider_key("nope", "x" * 20)

    def boom(*a, **k):
        raise ValueError("kaput")

    session.client = type("C", (), {"logged_in": True, "server": "x"})()
    monkeypatch.setattr(engine_mod._gateways, "discover", boom)
    with pytest.raises(AiguardError) as ei:
        session.discover()
    err = ei.value
    assert err.code == "aiguard.internal" and isinstance(err.__cause__, ValueError)
    assert str(session.log.path) in err.fix[0]
    debug = [r for r in session.log.tail(50, level="DEBUG") if "unexpected" in r["msg"]]
    assert debug and "ValueError" in debug[-1]["fields"]["traceback"]
    session.client = None


def test_one_operation_at_a_time(make_session):
    session = make_session(busy_timeout=0.05)
    holding = threading.Event()
    release = threading.Event()

    def hold():
        with session._operation("long job"):
            holding.set()
            release.wait(5)

    t = threading.Thread(target=hold)
    t.start()
    try:
        assert holding.wait(5)
        with pytest.raises(AiguardError) as ei:
            session.discover()
        assert ei.value.code == "engine.busy" and "long job" in ei.value.what
        st = session.status()             # status never blocks
        assert st["busy"] == "long job"
    finally:
        release.set()
        t.join(5)
    assert session.status()["busy"] is None


def test_report_escapes_and_redacts(tmp_path):
    secret = "sk-ant-" + secrets.token_hex(20)
    r = fake_result(prompt="<script>alert(1)</script> key=%s" % secret, verdict="BLOCKED",
                    evidence="<b>page</b>", category="<i>x</i>")
    fake_session = type("S", (), {})()
    fake_session.results = [r]
    fake_session.lakera = {"masked_key": "****abcd"}
    data = report_mod.build_report(fake_session)
    json_path, html_path = report_mod.write_report(data, directory=tmp_path)
    html = html_path.read_text(encoding="utf-8")
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "&lt;b&gt;page&lt;/b&gt;" in html
    assert secret not in html and secret not in json_path.read_text(encoding="utf-8")
    assert oct(json_path.stat().st_mode & 0o777) == oct(0o600)
    j2, h2 = report_mod.write_report(data, directory=tmp_path)
    assert j2 != json_path and h2 != html_path       # never overwrites


def test_options_are_not_mutated_and_plan_uses_session_values(make_session, mgmt, pki):
    srv = mgmt()
    session = make_session()
    ready(session, srv, pki)
    session.set_lakera(secrets.token_hex(32), "project-42")
    opts = PlanOptions(gateway="HQ-GW")
    plan = session.build_plan(opts)
    assert opts.client_ip is None and opts.lakera_project_id is None
    assert plan.options["client_ip"] == "127.0.0.1"
    assert plan.options["lakera_project_id"] == "project-42"
    assert dataclasses.asdict(opts)["gateway"] == "HQ-GW"


# --------------------------------------------------------------------------- review fixes


def apply_demo(session, srv, pki, **plan_kw):
    """connect, gateway, key, plan, apply (installed); returns the ApplyResult."""
    ready(session, srv, pki)
    session.run_preflight()
    session.set_lakera(secrets.token_hex(32), "project-42")
    plan = session.build_plan(PlanOptions(gateway="HQ-GW", **plan_kw))
    return session.apply(plan.plan_id)


def test_wrong_mds_domain_leaves_no_session_open(make_session, mgmt, pki):
    srv = mgmt(server_type="MDS")
    session = make_session()
    with pytest.raises(AiguardError) as ei:
        session.connect("127.0.0.1", port=srv.port, api_key=mgmt_key(), ca_file=pki.ca_pem_path,
                        domain="Nope")
    assert ei.value.code == "mgmt.domain_not_found"
    assert ei.value.state == "Logged out again. Nothing was changed."
    assert srv.state.sessions == {}                     # the System Data session was closed
    assert session.status()["connected"] is False
    # in a domain, a wrong switch says the truth: still in the old domain
    connect_kw = dict(port=srv.port, api_key=mgmt_key(), ca_file=pki.ca_pem_path, domain="Lab")
    session.connect("127.0.0.1", **connect_kw)
    with pytest.raises(AiguardError) as ei:
        session.select_domain("Nope")
    assert ei.value.state == "Still working in domain Lab. Nothing was changed."
    st = session.status()
    assert st["connected"] is True and st["connection"]["domain"] == "Lab"
    session.close()
    assert srv.state.sessions == {}


def test_login_asks_for_a_longer_session_and_keeps_it_alive(make_session, mgmt, pki):
    import time as _time

    srv = mgmt()
    session = make_session()
    ready(session, srv, pki)
    assert srv.calls_for("login")[-1]["session-timeout"] == 3600
    assert session.client.session_timeout == 3600
    # idle for a long time: the next operation sends keepalive first
    session.client.last_call_at = _time.time() - 1000
    session.discover()
    assert "keepalive" in srv.call_names()
    # the server dropped the session: the next operation logs in again transparently
    logins = srv.state.logins
    srv.state.sessions.clear()
    session.client.last_call_at = _time.time() - 1000
    assert [g.name for g in session.discover()] == ["HQ-GW"]
    assert srv.state.logins == logins + 1 and session.client.logged_in
    # the timer helper (web reaper) never raises and reports the session state
    srv.state.sessions.clear()
    session.client.last_call_at = _time.time() - 1000
    assert session.keepalive() is True and srv.state.logins == logins + 2


def test_expired_session_is_shown_and_refused_session_timeout_is_retried(make_session, mgmt, pki):
    srv = mgmt()
    real_login = srv._c_login

    def picky_login(ctx, p):
        if "session-timeout" in p:
            from fakes import _ApiError
            raise _ApiError(400, "generic_err_invalid_parameter",
                            "Invalid parameter for [session-timeout]. The value must be between "
                            "10 and 1800")
        return real_login(ctx, p)

    srv._c_login = picky_login
    session = make_session()
    ready(session, srv, pki)
    assert "session-timeout" not in srv.calls_for("login")[-1]
    assert session.client.session_timeout == 600
    session.client._creds = {}          # credentials gone: cannot log in again
    srv.state.sessions.clear()
    with pytest.raises(AiguardError):
        session.client.call("show-session", {})
    st = session.status()
    assert st["connected"] is False and st["session_expired"] is True


def test_correlate_error_is_kept_and_explained(make_session, mgmt, pki):
    from fakes import _ApiError

    srv = mgmt()

    def denied(ctx, p):
        raise _ApiError(403, "generic_err_permission_denied", "Permission denied: show-logs")

    srv._c_show_logs = denied
    session = make_session()
    ready(session, srv, pki)
    r = fake_result(sent_epoch=dt.datetime.now(dt.timezone.utc).timestamp())
    session.results.append(r)
    err = session.correlate()
    assert err is not None and session.correlate_error == err
    assert err["what"].startswith("Could not read the gateway logs")
    assert err["fix"][0].startswith("SmartConsole > Manage & Settings > Permissions & "
                                    "Administrators > Permission Profiles") and "Logs" in err["fix"][0]
    assert session.status()["correlate_error"]["what"] == err["what"]
    assert session.summary()["correlate_error"]["what"] == err["what"]
    reasons = session.diagnose(r)
    assert any(x.startswith("gateway logs were not checked: Could not read the gateway logs")
               for x in reasons)
    srv._c_show_logs = type(srv)._c_show_logs.__get__(srv)
    assert session.correlate() is None and session.correlate_error is None


def test_diagnose_names_autonomous_mode_and_missing_install(make_session, mgmt, pki):
    srv = mgmt(scenario="autonomous")
    session = make_session()
    ready(session, srv, pki)
    r = fake_result()
    reasons = session.diagnose(r)
    assert any("Autonomous Threat Prevention" in x and "Custom Threat Prevention" in x
               for x in reasons)
    srv2 = mgmt()
    s2 = make_session()
    res = apply_demo(s2, srv2, pki, install=False)
    assert res.ok and not res.installed
    assert s2.status()["step"] == "install"            # published only: not ready
    assert any("published but not installed" in x for x in s2.diagnose(fake_result()))


def test_diagnose_send_failure_and_reset_without_log(make_session, mgmt, pki):
    session = make_session()
    failed = fake_result(verdict="ERROR", inspected=True, http_status=None,
                         reason="Sending the prompt failed: [Errno 65] No route to host",
                         error={"code": "probe.send_failed", "what": "connection failed"})
    reasons = session.diagnose(failed)
    assert reasons[0] == "the prompt was not sent: Sending the prompt failed: [Errno 65] No route to host"
    assert not any("does not trust" in x for x in reasons)
    srv = mgmt()
    connect(session, srv, pki)
    reset = fake_result(expect="allow", verdict="BLOCKED",
                        evidence="connection terminated by the network (ConnectionResetError)",
                        sent_epoch=dt.datetime.now(dt.timezone.utc).timestamp())
    session.results.append(reset)
    session.correlate()
    reasons = session.diagnose(reset)
    assert reasons[0].startswith("the connection was reset, but no gateway log matches it")
    assert not any("Check Point Portal" in x for x in reasons)
    public = fake_result(expect="allow", verdict="BLOCKED", inspected=False, issuer="DigiCert",
                         evidence="connection terminated by the network (ConnectionResetError)")
    assert "could not have read the prompt" in session.diagnose(public)[0]


def test_key_test_connectivity_problem_is_not_called_a_bad_key(make_session, mgmt, pki):
    srv = mgmt()

    def offline(ctx, p):
        return {"success": False, "message": "The management server is not connected to the "
                                             "Infinity Portal (connection timed out)"}

    srv._c_test_ai_agent_security_api_key = offline
    session = make_session()
    ready(session, srv, pki)
    with pytest.raises(LakeraError) as ei:
        session.set_lakera(secrets.token_hex(32), "project-42")
    err = ei.value
    assert "connection to the Check Point Portal" in err.why
    assert err.fix[0] == engine_mod.PORTAL_CONNECTIVITY_FIX[0]
    srv._c_test_ai_agent_security_api_key = lambda ctx, p: {"success": False,
                                                            "message": "Invalid API key"}
    with pytest.raises(LakeraError) as ei:
        session.set_lakera(secrets.token_hex(32), "project-42")
    assert "was refused" in ei.value.why and ei.value.fix == engine_mod.PORTAL_FIX


def test_step_after_rollback_and_script_warning(make_session, mgmt, pki):
    srv = mgmt(scenario="script_denied")
    session = make_session()
    res = apply_demo(session, srv, pki, moderation=True)
    assert res.ok and res.installed and res.notices         # a "You do this" step only
    assert session.status()["step"] == "demo"
    session.confirm_enforcement()
    rb = session.rollback(res.rollback_id)
    assert rb.ok and srv.find("threat-profile", "AIGuard-Demo") is None
    st = session.status()
    assert st["step"] == "configure" and st["enforcement"] is None
    assert st["summary"]["enforcement_confirmed"] is None
    assert session.plan is None                          # rebuild: the objects are gone
    plan = session.build_plan(PlanOptions(gateway="HQ-GW"))
    assert session.apply(plan.plan_id).ok


def test_rollback_without_id_skips_a_discarded_point(make_session, mgmt, pki):
    srv = mgmt()
    session = make_session()
    first = apply_demo(session, srv, pki)
    assert first.ok
    srv.scenarios.add("publish_fails")
    plan = session.build_plan(PlanOptions(gateway="HQ-GW", track="Alert"))
    second = session.apply(plan.plan_id)
    assert not second.ok
    points = session.state.list_rollbacks()
    assert points[-1]["status"] == "discarded"
    srv.scenarios.discard("publish_fails")
    rb = session.rollback()
    assert rb.ok and rb.rollback_id == first.rollback_id
    assert srv.find("threat-profile", "AIGuard-Demo") is None


def test_status_reports_moderation_from_rollback_points(make_session, mgmt, pki, aiguard_home):
    srv = mgmt()
    session = make_session()
    res = apply_demo(session, srv, pki, moderation=True)
    assert res.ok and session.status()["moderation_on"] is True
    fresh = make_session()                               # e.g. after the web session expired
    ready(fresh, srv, pki)
    st = fresh.status()
    assert st["moderation_enabled"] is None and st["moderation_on"] is True


def test_direct_lakera_key_uses_the_current_ca(make_session, monkeypatch):
    session = make_session(provider_ca_file=None)
    seen = {}

    def classify(text, key, project, *, url=None, ca_file=None, log=None):
        seen["ca_file"] = ca_file
        return {"top_category": "prompt_attack"}

    monkeypatch.setattr(engine_mod._lakera, "classify", classify)
    session.set_direct_lakera("lk_" + secrets.token_hex(16), "proj")
    session.provider_ca_file = "/tmp/outbound-ca.pem"     # uploaded later (web Preflight page)
    session._annotate(fake_result(verdict="BLOCKED"), "ignore all previous instructions")
    assert seen["ca_file"] == "/tmp/outbound-ca.pem"


def test_close_during_an_operation_waits_for_it(make_session, mgmt, pki):
    srv = mgmt()
    session = make_session(busy_timeout=0.05)
    ready(session, srv, pki)
    client = session.client
    holding, release = threading.Event(), threading.Event()

    def job():
        with session._operation("apply"):
            holding.set()
            release.wait(5)
            assert client.logged_in          # not logged out under the running job

    t = threading.Thread(target=job)
    t.start()
    assert holding.wait(5)
    session.close()                          # like SessionStore.close_all at shutdown
    assert client.logged_in and session.closing and "logout" not in srv.call_names()
    release.set()
    t.join(5)
    assert not client.logged_in and session.client is None and "logout" in srv.call_names()
    assert not session.closing


def test_pinned_local_ip_is_used_in_explanations(make_session, mgmt, pki):
    srv = mgmt()
    session = make_session(local_ip="203.0.113.7")
    connect(session, srv, pki)
    r = fake_result(local_ip="172.17.0.2", sent_epoch=dt.datetime.now(dt.timezone.utc).timestamp())
    session.results.append(r)
    session.correlate()
    q = srv.state.log_queries[-1]
    assert q["filter"] == "src:203.0.113.7"
    assert any("includes 203.0.113.7" in x for x in session.diagnose(r))


def test_stale_log_match_is_dropped_when_the_log_goes_to_another_result(make_session, mgmt, pki):
    srv = mgmt()
    session = make_session()
    connect(session, srv, pki)
    now = dt.datetime.now(dt.timezone.utc)
    a = fake_result(verdict="BLOCKED", evidence="UserCheck page", sent_epoch=now.timestamp(),
                    sent_at=now.isoformat())
    session.results.append(a)
    log = srv.add_log(make_log(src="127.0.0.1", host="api.openai.com", action="Prevent", time_=now))
    session.correlate()
    assert a.log_match and a.log_match["log_id"] == log["id"]
    b = fake_result(verdict="BLOCKED", evidence="UserCheck page", sent_epoch=now.timestamp() + 0.2,
                    sent_at=(now + dt.timedelta(milliseconds=200)).isoformat())
    a.sent_epoch = now.timestamp() - 170          # a moves away; b is now the closer match
    session.results.append(b)
    session.correlate()
    owners = [r.id for r in (a, b) if r.log_match and r.log_match.get("log_id") == log["id"]]
    assert len(owners) == 1                       # never claimed by two results


def test_diagnose_names_learning_mode(make_session, mgmt, pki):
    srv = mgmt(scenario="https_learning")
    session = make_session()
    ready(session, srv, pki)
    reasons = session.diagnose(fake_result(inspected=False, issuer="DigiCert"))
    assert reasons[0].startswith("HTTPS Inspection did not decrypt this connection")
    assert any("Learning mode" in x and "Full inspection" in x for x in reasons)


# --------------------------------------------------------------------------- integration round


def test_busy_property_and_provider_ca_setter(make_session, monkeypatch, tmp_path):
    from aiguard.errors import TlsTrustError

    session = make_session(busy_timeout=0.05)
    assert session.busy is None
    holding, release = threading.Event(), threading.Event()

    def job():
        with session._operation("apply"):
            holding.set()
            release.wait(5)

    t = threading.Thread(target=job)
    t.start()
    assert holding.wait(5)
    assert session.busy == "apply"
    with pytest.raises(AiguardError) as ei:            # never swapped under a running job
        session.set_provider_ca_file(str(tmp_path / "new.pem"))
    assert ei.value.code == "engine.busy"
    release.set()
    t.join(5)
    assert session.busy is None

    old = session.provider_ca_file
    session.set_direct_lakera("lk_" + secrets.token_hex(16), "proj", ca_file=old)
    session.set_provider_ca_file(str(tmp_path / "new.pem"))
    assert session.provider_ca_file == str(tmp_path / "new.pem")
    assert session._direct["ca_file"] == str(tmp_path / "new.pem")   # followed the swap
    session.set_provider_ca_file(None)
    assert session.provider_ca_file is None

    def broken(*a, **k):
        raise TlsTrustError("This computer does not trust the certificate", code="tls.untrusted")

    monkeypatch.setattr(engine_mod._lakera, "classify", broken)
    r = fake_result(verdict="BLOCKED")
    session._annotate(r, "ignore all previous instructions")   # must not raise
    assert r.verdict == "BLOCKED" and r.category_source != "lakera"


def test_connect_can_leave_the_remembered_ca_file_alone(make_session, mgmt, pki, aiguard_home,
                                                        tmp_path):
    srv = mgmt()
    first = make_session()
    connect(first, srv, pki)
    assert first.state.last()["ca_file"] == str(pki.ca_pem_path)
    temp_ca = tmp_path / "uploaded.pem"
    temp_ca.write_text(Path(pki.ca_pem_path).read_text(encoding="ascii"), encoding="ascii")
    second = make_session()
    second.connect("127.0.0.1", port=srv.port, api_key=mgmt_key(), ca_file=str(temp_ca),
                   remember_ca=False)
    assert second.state.last()["ca_file"] == str(pki.ca_pem_path)   # the CLI's stays
    # a remembered CA of another server is not kept for this one
    second.state.set_last(server="10.9.9.9", ca_file="/elsewhere/ca.pem")
    third = make_session()
    third.connect("127.0.0.1", port=srv.port, api_key=mgmt_key(), ca_file=str(temp_ca),
                  remember_ca=False)
    last = third.state.last()
    assert last["server"] == "127.0.0.1" and "ca_file" not in last


def test_mds_system_data_login_has_no_domain(make_session, mgmt, pki):
    srv = mgmt(server_type="MDS")
    session = make_session()
    info = connect(session, srv, pki)
    assert info["server_type"] == "MDS"
    assert info["domain"] is None and info["system_data"] is True
    conn = session.status()["connection"]
    assert conn["domain"] is None and conn["system_data"] is True
    info = session.select_domain("Lab")
    assert info["domain"] == "Lab" and info["system_data"] is False


def test_plan_dict_says_when_it_was_published(make_session, mgmt, pki):
    srv = mgmt()
    session = make_session()
    ready(session, srv, pki)
    session.set_lakera(secrets.token_hex(32), "project-42")
    plan = session.build_plan(PlanOptions(gateway="HQ-GW"))
    assert plan.to_dict()["published"] is False and plan.published is False
    assert session.apply(plan.plan_id).ok
    assert plan.to_dict()["published"] is True
    assert session.status()["plan"]["published"] is True


def test_close_during_apply_marks_the_rollback_point_until_the_apply_finishes(make_session,
                                                                              mgmt, pki):
    srv = mgmt()
    session = make_session(busy_timeout=0.05)
    ready(session, srv, pki)
    session.set_lakera(secrets.token_hex(32), "project-42")
    plan = session.build_plan(PlanOptions(gateway="HQ-GW"))
    seen = {}

    def progress(step, status, pct, message):
        if step == "publish" and status == "running" and "status" not in seen:
            # another thread closes the session (web console shutdown) mid-apply
            t = threading.Thread(target=session.close)
            t.start()
            t.join(5)
            rid = session._apply_rid
            seen["status"] = session.state.get_rollback(rid)["status"]
            seen["rid"] = rid

    res = session.apply(plan.plan_id, progress_cb=progress)
    assert seen["status"] == "publish-unknown"           # what a process exit would leave
    assert res.ok and res.rollback_id == seen["rid"]
    assert session.state.get_rollback(res.rollback_id)["status"] == "installed"   # overwritten
    assert session.client is None                        # the deferred close ran at the end


def test_discard_during_apply_stops_it_before_publish(make_session, mgmt, pki):
    srv = mgmt()
    session = make_session()
    ready(session, srv, pki)
    session.set_lakera(secrets.token_hex(32), "project-42")
    plan = session.build_plan(PlanOptions(gateway="HQ-GW"))

    def progress(step, status, pct, message):
        if step == "client_host" and status == "done":
            assert session.discard() is True              # e.g. shutdown, from another thread

    res = session.apply(plan.plan_id, progress_cb=progress)
    assert not res.ok and res.error.code == "plan.stopped" and not res.published
    assert srv.state.publish_count == 0
    assert srv.find("host", "aiguard-client-127-0-0-1") is None
    assert srv.find("threat-profile", "AIGuard-Demo") is None
    assert plan.published is False
    # the next apply is not stopped by the old request
    again = session.build_plan(PlanOptions(gateway="HQ-GW"))
    assert session.apply(again.plan_id).ok


def test_check_last_install_before_a_demo(make_session, mgmt, pki):
    srv = mgmt(scenario="partial_install_failed")
    session = make_session()
    ready(session, srv, pki)
    report = session.run_preflight()
    assert report.check("last_install").status == "fail"
    res = session.check_last_install()
    assert res.status == "fail" and not res.blocking
    assert res.title == "Last policy install on HQ-GW partly failed"
    assert "sk116272" in (res.server_said or "")
    assert res.evidence.get("not-installed") == "Access Control"
    assert session.preflight.check("last_install") is res     # the report shows the new one
    assert session.status()["preflight"]["checks"][10]["id"] == "last_install"


def test_errors_carry_machine_readable_actions(make_session, mgmt, pki):
    from aiguard import tlsutil

    err = tlsutil.trust_error(Exception("certificate verify failed: unable to get local issuer "
                                        "certificate"), "api.openai.com", "provider")
    assert err.code == "tls.untrusted" and err.details["action"]["id"] == "outbound-ca"
    mgmt_err = tlsutil.trust_error(Exception("certificate verify failed: unable to get local "
                                             "issuer certificate"), "10.1.1.1", "management")
    assert "action" not in mgmt_err.details
    srv = mgmt(scenario="https_off")
    session = make_session()
    ready(session, srv, pki)
    with pytest.raises(AiguardError) as ei:
        session.build_https_plan()
    assert ei.value.code == "plan.no_outbound_ca"
    assert [a["id"] for a in ei.value.details["action"]] == ["https-inspection", "outbound-ca"]
    with pytest.raises(AiguardError) as ei:
        session.outbound_ca()
    assert ei.value.code == "plan.no_outbound_ca"
    assert ei.value.details["action"]["id"] == "outbound-ca"
