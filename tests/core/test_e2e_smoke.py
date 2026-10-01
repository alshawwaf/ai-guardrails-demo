"""End-to-end smoke test of the AI Guard Demo Kit, without internet.

Three in-process fakes on 127.0.0.1 (tests/core/fakes.py), every connection TLS-verified
against a CA generated at test time:

* FakeMgmtServer: the Check Point Management API (R82.20, API 2.2);
* FakeProviderServer: an LLM provider "behind the gateway" (UserCheck page / reset for
  the injection prompts, provider JSON for everything else);
* FakeLakeraServer: the Lakera Guard API (key check and category labels).

(a) The CLI: ``aiguard setup`` with scripted answers (moderation on, typed APPROVE), then
    ``aiguard demo --scene injection --no-pause`` with gateway logs to match.
(b) The web console: the Flask test client through the Gateway Mode JSON API (connect,
    preflight job, AI key, plan, apply job, scene job, log, report, rollback, disconnect).
(c) The 2026-09-30 lab case (``partial_install_failed``: the last install failed on Access
    Control with the sk116272 data-type error while Threat Prevention installed): the
    ``last_install`` preflight check in the CLI (``setup`` and before ``demo`` runs) and in
    the web console's preflight job, with the server's message verbatim.

Both check the outcome on the fake servers and that no generated secret (Management API
key, management session ids, AI Agent Security key, provider key) appears in any HTTP
response body, CLI output, run log, state file or report.
"""
from __future__ import annotations

import io
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from fakes import (LAB_DATA_TYPES_ERROR, FakeLakeraServer, FakeMgmtServer,  # noqa: E402
                   FakeProviderServer, make_gateway, make_log, make_test_pki)

from aiguard import cli  # noqa: E402
from aiguard.engine import Session  # noqa: E402

PROVIDER_RULES = [
    ("ignore all previous instructions", "usercheck"),   # inj-override -> UserCheck page
    ("you are dan", "reset"),                            # jb-dan -> connection reset
    ("attacker.example", "usercheck"),                   # inj-indirect
]
PROVIDER_ENV = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY",
                "AIGUARD_LOCAL_IP")
CLIENT_IP = "127.0.0.1"   # the fakes run here, so this is the address the "gateway" sees


# --------------------------------------------------------------------------- helpers


class ScriptedConsole(cli.Console):
    """Answers come from a list; hidden prompts must not be reached (keys come from env)."""

    def __init__(self, answers=()):
        self.buf = io.StringIO()
        super().__init__(stdout=self.buf, stdin=io.StringIO(""), color=False, unicode=True,
                         width=120)
        self.answers = list(answers)

    @property
    def interactive(self):
        return True

    def input(self, prompt=""):
        self.write(prompt)
        if not self.answers:
            self.write("<EOF>\n")
            raise EOFError
        answer = self.answers.pop(0)
        self.write(answer + "\n")
        return answer

    def secret(self, prompt=""):
        self.write(prompt + "<no hidden answer scripted>\n")
        raise EOFError

    @property
    def text(self):
        return self.buf.getvalue()


def lab_gateway():
    return make_gateway("HQ-GW", "10.1.1.111",
                        interfaces=[("eth0", "10.1.1.111", 24), ("eth1", "198.51.100.111", 24),
                                    ("eth2", "127.0.0.1", 8)])


def files_text(*roots):
    """Every file under the given folders (logs, .jsonl, state.json, reports ...), or the
    given files. Binary files (SQLite) are read as text with replacement characters, so
    a secret stored in plain text would still show up."""
    chunks = []
    for root in roots:
        if not root:
            continue
        root = Path(root)
        if root.is_file():
            chunks.append(root.read_text(encoding="utf-8", errors="replace"))
            continue
        if not root.exists():
            continue
        for p in sorted(root.rglob("*")):
            if p.is_file():
                chunks.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def sqlite_path():
    url = os.environ.get("DATABASE_URL", "")
    return url[len("sqlite:///"):] if url.startswith("sqlite:///") else None


def session_ids(srv):
    return {str(h.get("X-chkp-sid")) for (_c, _p, h) in srv.calls if h.get("X-chkp-sid")}


def assert_no_secrets(secret_values, texts):
    assert secret_values, "nothing to look for"
    for name, value in secret_values.items():
        assert value and len(value) >= 8, name
        for label, text in texts.items():
            assert value not in text, "%s leaked into %s" % (name, label)


def add_block_logs(srv, n):
    for _ in range(n):
        srv.add_log(make_log(src=CLIENT_IP, host="127.0.0.1"))


# --------------------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return make_test_pki(tmp_path_factory.mktemp("e2e-pki"))


@pytest.fixture(scope="module")
def provider(pki):
    srv = FakeProviderServer(pki, rules=PROVIDER_RULES, timeout_cap=3.0).start()
    yield srv
    srv.stop()


@pytest.fixture(scope="module")
def lakera_srv(pki):
    srv = FakeLakeraServer(pki).start()
    yield srv
    srv.stop()


@pytest.fixture
def mgmt(pki):
    srv = FakeMgmtServer(pki, gateways=[lab_gateway()]).start()
    yield srv
    assert srv.errors == [], srv.errors[0]
    srv.stop()


@pytest.fixture
def clean_env(monkeypatch):
    for name in PROVIDER_ENV:
        monkeypatch.delenv(name, raising=False)


# --------------------------------------------------------------------------- (a) CLI


def test_cli_setup_then_demo(mgmt, pki, provider, lakera_srv, aiguard_home, monkeypatch,
                             clean_env):
    keys = {
        "management API key": "fake-mgmt-" + secrets.token_hex(16),
        "AI Agent Security key": lakera_srv.valid_key,
        "provider key": "sk-test-" + secrets.token_hex(16),
    }
    monkeypatch.setenv("E2E_MGMT_KEY", keys["management API key"])
    monkeypatch.setenv("E2E_GUARD_KEY", keys["AI Agent Security key"])
    monkeypatch.setenv("E2E_OPENAI_KEY", keys["provider key"])
    sessions = []

    def factory(**kw):
        kw.setdefault("provider_ca_file", pki.ca_pem_path)
        kw.update(provider_base_urls={"openai": provider.base_url,
                                      "anthropic": provider.base_url},
                  lakera_url=lakera_srv.url("/v2/guard"), lakera_ca_file=pki.ca_pem_path,
                  task_poll=0.01, probe_timeout=2.0, tls_timeout=5, mgmt_timeout=10)
        s = Session(**kw)
        # the web console's "Lakera key saved in Settings": labels blocked prompts
        s.set_direct_lakera(lakera_srv.valid_key, lakera_srv.project_id)
        sessions.append(s)
        return s

    conn = ["--server", "127.0.0.1", "--port", str(mgmt.port), "--ca-file", pki.ca_pem_path,
            "--api-key-env", "E2E_MGMT_KEY", "--local-ip", CLIENT_IP]
    outputs = {}

    # setup: server type, gateway, profile name, content moderation = y, APPROVE
    con = ScriptedConsole(["", "", "", "y", "APPROVE"])
    code = cli.main(["setup"] + conn + ["--lakera-key-env", "E2E_GUARD_KEY",
                                        "--project-id", lakera_srv.project_id,
                                        "--provider-key-env", "E2E_OPENAI_KEY"],
                    console=con, session_factory=factory)
    out = outputs["setup output"] = con.text
    assert code == cli.EXIT_OK, out
    for needle in ("[1/6] Connect to management", "[3/6] Preflight", "12 passed",
                   "Key validated", "+ add-host", "+ add-threat-profile", "+ add-threat-rule",
                   "run-script", "Type APPROVE to publish and install", "✓ publish",
                   "✓ install-policy", "Enforcement check",
                   "Ready. Start the demo with  aiguard demo --guided"):
        assert needle in out, needle
    rid = re.search(r"aiguard rollback ([0-9a-f]{6})", out)
    assert rid, out
    profile = mgmt.find("threat-profile", "AIGuard-Demo")
    assert profile is not None and profile["_secret"] == keys["AI Agent Security key"]
    assert mgmt.find("host", "aiguard-client-127-0-0-1") is not None   # --local-ip
    assert mgmt.state.moderation == {"HQ-GW": True}                   # moderation script ran
    names = mgmt.call_names()
    assert names.count("publish") == 1 and "install-policy" in names and "run-script" in names
    assert provider.requests[-1]["headers"].get("Authorization") == \
        "Bearer " + keys["provider key"]

    # demo: the injection scene, matched to the gateway logs
    add_block_logs(mgmt, 3)
    sent_before = len(provider.requests)
    con = ScriptedConsole([])
    code = cli.main(["demo", "--scene", "injection", "--no-pause", "--gateway", "HQ-GW",
                     "--provider-key-env", "E2E_OPENAI_KEY"] + conn,
                    console=con, session_factory=factory)
    out = outputs["demo output"] = con.text
    assert code == cli.EXIT_OK, out
    assert "TLS to api.openai.com is inspected" in out
    assert "Scene 2  Prompt injection is stopped at the gateway" in out
    assert out.count(" BLOCKED ") == 3
    assert re.search(r"Result\s+3 prompts · 3 blocked · 0 allowed · 0 unexpected", out), out
    assert re.search(r"Proof\s+3 of 3 blocks found in SmartConsole logs", out), out
    assert len(provider.requests) - sent_before == 3
    assert any(r["path"] == "/v2/guard" for r in lakera_srv.requests)   # categories
    reports = sorted((aiguard_home / "reports").glob("*.html"))
    assert reports and str(reports[-1]) in out
    report_json = json.loads(sorted((aiguard_home / "reports").glob("*.json"))[-1].read_text(
        encoding="utf-8"))
    assert [r["verdict"] for r in report_json["results"]] == ["BLOCKED"] * 3

    # the run state remembers the rollback point, never a secret
    state = json.loads((aiguard_home / "state.json").read_text(encoding="utf-8"))
    assert any(p["id"] == rid.group(1) for p in state["rollbacks"])
    assert state["last"]["gateway"] == "HQ-GW"

    secret_values = dict(keys)
    for i, sid in enumerate(sorted(session_ids(mgmt))):
        secret_values["management session id %d" % i] = sid
    assert len(secret_values) >= 5     # at least two management sessions (setup, demo)
    texts = dict(outputs)
    texts["aiguard home (logs, state, reports)"] = files_text(aiguard_home)
    assert_no_secrets(secret_values, texts)
    assert "****" + keys["AI Agent Security key"][-4:] in outputs["setup output"]
    for s in sessions:
        s.close()


# --------------------------------------------------------------------------- (b) web


class Recorder(object):
    """Flask test client wrapper that keeps every response body."""

    def __init__(self, client):
        self.client = client
        self.bodies = []

    def _keep(self, resp):
        self.bodies.append(resp.get_data(as_text=True))
        return resp

    def get(self, url):
        return self._keep(self.client.get(url))

    def post(self, url, payload=None):
        return self._keep(self.client.post(url, json=payload if payload is not None else {}))

    def wait_job(self, job_id, timeout=45.0):
        deadline = time.monotonic() + timeout
        while True:
            resp = self.get("/gateway/api/jobs/%s" % job_id)
            assert resp.status_code == 200, resp.get_data(as_text=True)
            job = resp.get_json()
            if job["status"] != "running":
                return job
            assert time.monotonic() < deadline, "job %s still running" % job_id
            time.sleep(0.05)

    def text(self):
        return "\n".join(self.bodies)


def test_web_console_flow(request, mgmt, pki, provider, lakera_srv, monkeypatch, clean_env):
    pytest.importorskip("flask")
    pytest.importorskip("flask_login")
    app_module = request.getfixturevalue("app_module")
    client = request.getfixturevalue("logged_in_client")
    from gateway_mode import store

    ctx = app_module.app.extensions["gateway_mode"]
    ctx.store.close_all()
    sessions = []

    def factory(*, home):
        s = Session(home=home, provider_ca_file=pki.ca_pem_path,
                    provider_base_urls={"openai": provider.base_url,
                                        "anthropic": provider.base_url},
                    lakera_url=lakera_srv.url("/v2/guard"), lakera_ca_file=pki.ca_pem_path,
                    task_poll=0.01, probe_timeout=2.0, tls_timeout=5, mgmt_timeout=10)
        sessions.append(s)
        return s

    monkeypatch.setattr(store, "session_factory", factory)
    keys = {
        "management API key": "fake-mgmt-" + secrets.token_hex(16),
        "AI Agent Security key": lakera_srv.valid_key,
        "provider key": "sk-test-" + secrets.token_hex(16),
    }
    saved = []

    def put(key, value):
        app_module.set_setting(key, value)
        saved.append(key)

    put("OPENAI_API_KEY", keys["provider key"])
    put("DEMO_API_KEY", keys["AI Agent Security key"])
    put("DEMO_PROJECT_ID", lakera_srv.project_id)
    c = Recorder(client)
    try:
        # connect (CA as PEM text, verification on) with the address the gateway sees
        resp = c.post("/gateway/api/connect", {
            "server": "127.0.0.1", "port": mgmt.port, "server_type": "SMS", "auth": "api-key",
            "api_key": keys["management API key"],
            "ca_pem": Path(pki.ca_pem_path).read_text(encoding="ascii"),
            "local_ip": CLIENT_IP})
        data = resp.get_json()
        assert resp.status_code == 200, data
        assert data["connected"] is True and data["connect"]["release"] == "R82.20"
        assert [g["name"] for g in data["gateways"]] == ["HQ-GW"]
        assert data["local_ip"] == CLIENT_IP
        resp = c.post("/gateway/api/connect", {"server": "127.0.0.1", "api_key": "x" * 20,
                                               "local_ip": "not-an-ip"})
        assert resp.status_code == 400 and resp.get_json()["error"]["field"] == "local_ip"

        resp = c.post("/gateway/api/gateway", {"name": "HQ-GW"})
        assert resp.status_code == 200, resp.get_json()

        # preflight (job)
        resp = c.post("/gateway/api/preflight")
        assert resp.status_code == 202
        job = c.wait_job(resp.get_json()["job"]["id"])
        assert job["status"] == "done", job["error"]
        checks = {ch["id"]: ch["status"] for ch in job["result"]["preflight"]["checks"]}
        assert job["result"]["preflight"]["ok"] is True and len(checks) == 12
        assert checks["tls_path"] == "pass" and checks["client_path"] == "pass"
        assert checks["outbound_ca"] == "pass" and checks["last_install"] == "pass"
        assert c.get("/gateway/api/status").get_json()["step"] == "configure"

        # AI Agent Security key: the one saved in Settings, checked by management + Lakera
        resp = c.post("/gateway/api/lakera", {"use_saved": True,
                                              "project_id": lakera_srv.project_id,
                                              "direct_check": True})
        lk = resp.get_json()
        assert resp.status_code == 200, lk
        assert lk["lakera"]["validated"] is True and lk["lakera"]["validated_by"] == "management"
        assert lk["lakera"]["direct"]["ok"] is True
        assert any(r["path"] == "/v2/policies/health" for r in lakera_srv.requests)

        # plan (read-only) with content moderation
        resp = c.post("/gateway/api/plan", {"options": {"moderation": True, "scope": "client"}})
        plan = resp.get_json()["plan"]
        assert resp.status_code == 200
        assert [s["id"] for s in plan["steps"]] == ["client_host", "profile", "rule", "publish",
                                                    "install", "moderation"]
        host_step = plan["steps"][0]
        assert host_step["display_payload"]["ip-address"] == CLIENT_IP
        assert c.get("/gateway/api/status").get_json()["step"] == "install"
        assert mgmt.state.publish_count == 0

        # apply (job): typed APPROVE + acknowledgement + the exact plan id
        resp = c.post("/gateway/api/apply", {"plan_id": plan["plan_id"], "typed": "APPROVE",
                                             "acknowledge": True})
        assert resp.status_code == 202
        job = c.wait_job(resp.get_json()["job"]["id"])
        assert job["status"] == "done", job["error"]
        applied = job["result"]["apply"]
        assert applied["ok"] and applied["published"] and applied["installed"]
        assert applied["enforcement"]["confirmed"] is True and applied["rollback_id"]
        assert mgmt.find("threat-profile", "AIGuard-Demo")["_secret"] == \
            keys["AI Agent Security key"]
        assert mgmt.state.moderation == {"HQ-GW": True}
        assert c.get("/gateway/api/status").get_json()["step"] == "demo"
        assert provider.requests[-1]["headers"].get("Authorization") == \
            "Bearer " + keys["provider key"]

        # the injection scene (job), matched to the gateway logs; the gateway also logged
        # the enforcement check, which is one of the session's results too
        add_block_logs(mgmt, 1 + 3)
        resp = c.post("/gateway/api/scene", {"scene_id": "injection", "provider": "openai"})
        assert resp.status_code == 202
        job = c.wait_job(resp.get_json()["job"]["id"])
        assert job["status"] == "done", job["error"]
        results = job["result"]["results"]
        assert [r["verdict"] for r in results] == ["BLOCKED"] * 3
        assert all(r["matched"] for r in results)
        assert {s["id"]: s["status"] for s in job["steps"]}["correlate"] == "done"
        status = c.get("/gateway/api/status").get_json()
        scene_results = [r for r in status["results"]
                         if r["prompt_id"] in ("inj-override", "jb-dan", "inj-indirect")
                         and r["id"] in {x["id"] for x in results}]
        assert len(scene_results) == 3 and all(r["log_match"] for r in scene_results)

        # run log and report
        logs = c.get("/gateway/api/log?n=500").get_json()
        assert logs["live"] is True and logs["records"]
        assert {"mgmt", "plan", "probe"} <= set(logs["components"])
        rep = c.get("/gateway/api/report").get_json()["report"]
        assert rep["summary"]["total"] >= 4 and rep["summary"]["blocked"] >= 4

        # undo, then disconnect
        resp = c.post("/gateway/api/rollback", {"rollback_id": applied["rollback_id"]})
        assert resp.status_code == 202
        job = c.wait_job(resp.get_json()["job"]["id"])
        assert job["status"] == "done", job["error"]
        assert mgmt.find("threat-profile", "AIGuard-Demo") is None
        assert mgmt.state.moderation == {"HQ-GW": False}
        web_home = Path(sessions[0].home)
        resp = c.post("/gateway/api/disconnect")
        assert resp.status_code == 200 and resp.get_json()["connected"] is False
        for page in ("connect", "preflight", "configure", "install", "demo", "diagnostics"):
            assert c.get("/gateway/%s" % page).status_code == 200
    finally:
        for key in saved:
            app_module.delete_setting(key)
        ctx.store.close_all()
        for s in sessions:
            s.close()

    secret_values = dict(keys)
    for i, sid in enumerate(sorted(session_ids(mgmt))):
        secret_values["management session id %d" % i] = sid
    texts = {
        "HTTP response bodies": c.text(),
        "Gateway Mode home (run logs, state, reports)": files_text(web_home),
        "app logs folder": files_text(os.environ.get("LOGS_DIR")),
        "instance folder": files_text(app_module.app.instance_path),
        "app database": files_text(sqlite_path()),
    }
    assert texts["Gateway Mode home (run logs, state, reports)"]
    assert_no_secrets(secret_values, texts)
    assert "****" + keys["AI Agent Security key"][-4:] in texts["HTTP response bodies"]


# --------------------------------------------------------------------------- (c) partial install


@pytest.fixture
def partial_mgmt(pki):
    srv = FakeMgmtServer(pki, gateways=[lab_gateway()], scenario="partial_install_failed").start()
    yield srv
    assert srv.errors == [], srv.errors[0]
    srv.stop()


PARTIAL_TITLE = "Last policy install on HQ-GW partly failed"
PARTIAL_DETAIL = "Threat Prevention installed but Access Control did not"


def test_cli_partial_install_is_shown_in_setup_and_before_the_demo(
        partial_mgmt, pki, provider, lakera_srv, aiguard_home, monkeypatch, clean_env):
    mgmt = partial_mgmt
    keys = {
        "management API key": "fake-mgmt-" + secrets.token_hex(16),
        "AI Agent Security key": lakera_srv.valid_key,
        "provider key": "sk-test-" + secrets.token_hex(16),
    }
    monkeypatch.setenv("E2E_MGMT_KEY", keys["management API key"])
    monkeypatch.setenv("E2E_GUARD_KEY", keys["AI Agent Security key"])
    monkeypatch.setenv("E2E_OPENAI_KEY", keys["provider key"])
    sessions = []

    def factory(**kw):
        kw.setdefault("provider_ca_file", pki.ca_pem_path)
        kw.update(provider_base_urls={"openai": provider.base_url,
                                      "anthropic": provider.base_url},
                  lakera_url=lakera_srv.url("/v2/guard"), lakera_ca_file=pki.ca_pem_path,
                  task_poll=0.01, probe_timeout=2.0, tls_timeout=5, mgmt_timeout=10)
        s = Session(**kw)
        sessions.append(s)
        return s

    conn = ["--server", "127.0.0.1", "--port", str(mgmt.port), "--ca-file", pki.ca_pem_path,
            "--api-key-env", "E2E_MGMT_KEY", "--local-ip", CLIENT_IP]
    outputs = {}

    # setup: the partial install is a red, non-blocking preflight result with the server's
    # own message; setup goes on (moderation on, typed APPROVE) and installs Threat Prevention
    con = ScriptedConsole(["", "", "", "y", "APPROVE"])
    code = cli.main(["setup"] + conn + ["--lakera-key-env", "E2E_GUARD_KEY",
                                        "--project-id", lakera_srv.project_id,
                                        "--provider-key-env", "E2E_OPENAI_KEY"],
                    console=con, session_factory=factory)
    out = outputs["setup output"] = con.text
    assert code == cli.EXIT_OK, out
    preflight_part = out.split("[3/6] Preflight", 1)[1].split("[4/6]", 1)[0]
    assert PARTIAL_TITLE in preflight_part and PARTIAL_DETAIL in preflight_part
    assert re.search(r"Said\s+Layer 'Network': Rule 2 \(AI\)", preflight_part), preflight_part
    assert "sk116272" in preflight_part and "not-installed: Access Control" in preflight_part
    assert "11 passed" in preflight_part and "blocking" not in preflight_part.split(
        "Preflight  ", 1)[-1]
    assert "Type APPROVE to publish and install" in out and "✓ install-policy" in out
    assert mgmt.state.moderation == {"HQ-GW": True}
    assert mgmt.state.installs[-1]["access"] is False   # the demo policy: Threat Prevention

    # demo: the partial install (Access Control still the old policy) is shown before the
    # first prompt, and the demo still runs
    add_block_logs(mgmt, 3)
    con = ScriptedConsole([])
    code = cli.main(["demo", "--scene", "injection", "--no-pause", "--gateway", "HQ-GW",
                     "--provider-key-env", "E2E_OPENAI_KEY"] + conn,
                    console=con, session_factory=factory)
    out = outputs["demo output"] = con.text
    assert code == cli.EXIT_OK, out
    before, _, scene = out.partition("Scene 2  Prompt injection is stopped at the gateway")
    assert scene, out
    assert PARTIAL_TITLE in before and PARTIAL_DETAIL in before
    assert re.search(r"Said\s+Layer 'Network': Rule 2 \(AI\)", before), before
    assert scene.count(" BLOCKED ") == 3

    secret_values = dict(keys)
    for i, sid in enumerate(sorted(session_ids(mgmt))):
        secret_values["management session id %d" % i] = sid
    texts = dict(outputs)
    texts["aiguard home (logs, state, reports)"] = files_text(aiguard_home)
    assert_no_secrets(secret_values, texts)
    for s in sessions:
        s.close()


def test_web_preflight_job_reports_the_partial_install(request, partial_mgmt, pki, provider,
                                                        lakera_srv, monkeypatch, clean_env):
    pytest.importorskip("flask")
    pytest.importorskip("flask_login")
    mgmt = partial_mgmt
    app_module = request.getfixturevalue("app_module")
    client = request.getfixturevalue("logged_in_client")
    from gateway_mode import store

    ctx = app_module.app.extensions["gateway_mode"]
    ctx.store.close_all()
    sessions = []

    def factory(*, home):
        s = Session(home=home, provider_ca_file=pki.ca_pem_path,
                    provider_base_urls={"openai": provider.base_url,
                                        "anthropic": provider.base_url},
                    lakera_url=lakera_srv.url("/v2/guard"), lakera_ca_file=pki.ca_pem_path,
                    task_poll=0.01, probe_timeout=2.0, tls_timeout=5, mgmt_timeout=10)
        sessions.append(s)
        return s

    monkeypatch.setattr(store, "session_factory", factory)
    keys = {"management API key": "fake-mgmt-" + secrets.token_hex(16)}
    c = Recorder(client)
    web_home = None
    try:
        resp = c.post("/gateway/api/connect", {
            "server": "127.0.0.1", "port": mgmt.port, "server_type": "SMS", "auth": "api-key",
            "api_key": keys["management API key"],
            "ca_pem": Path(pki.ca_pem_path).read_text(encoding="ascii"), "local_ip": CLIENT_IP})
        assert resp.status_code == 200, resp.get_json()
        assert c.post("/gateway/api/gateway", {"name": "HQ-GW"}).status_code == 200

        resp = c.post("/gateway/api/preflight")
        assert resp.status_code == 202
        job = c.wait_job(resp.get_json()["job"]["id"])
        assert job["status"] == "done", job["error"]
        pf = job["result"]["preflight"]
        checks = {ch["id"]: ch for ch in pf["checks"]}
        li = checks["last_install"]
        assert li["status"] == "fail" and li["blocking"] is False and pf["ok"] is True
        assert li["title"] == PARTIAL_TITLE and PARTIAL_DETAIL in li["detail"]
        assert li["server_said"] == LAB_DATA_TYPES_ERROR          # verbatim, not reworded
        assert li["evidence"]["not-installed"] == "Access Control"
        assert any("sk116272" in f for f in li["fix"])
        assert li["web_action"] is None                           # a SmartConsole fix
        steps = {st["id"]: st["status"] for st in job["steps"]}
        assert steps["last_install"] == "fail"
        # the status the Demo and Diagnostics pages render carries it too
        st = c.get("/gateway/api/status").get_json()
        assert {ch["id"]: ch["status"] for ch in st["preflight"]["checks"]}["last_install"] == \
            "fail"
        assert "show-tasks" in mgmt.call_names()
        writes = [n for n in mgmt.call_names()
                  if n.startswith(("add-", "set-", "delete-", "publish", "install-policy"))]
        assert writes == []                                       # preflight is read-only
        web_home = Path(sessions[0].home)
        assert c.post("/gateway/api/disconnect").status_code == 200
    finally:
        ctx.store.close_all()
        for s in sessions:
            s.close()

    secret_values = dict(keys)
    for i, sid in enumerate(sorted(session_ids(mgmt))):
        secret_values["management session id %d" % i] = sid
    texts = {
        "HTTP response bodies": c.text(),
        "Gateway Mode home (run logs, state, reports)": files_text(web_home),
        "app logs folder": files_text(os.environ.get("LOGS_DIR")),
        "instance folder": files_text(app_module.app.instance_path),
    }
    assert_no_secrets(secret_values, texts)
