"""Tests for the ``aiguard`` command line (aiguard.cli, spec 9.1).

``cli.main([...])`` runs against FakeMgmtServer / FakeProviderServer on 127.0.0.1 over TLS
verified with a CA generated at test time. Answers are scripted with a Console subclass;
``session_factory`` points the engine Session at the fake provider (the same keyword
arguments the engine tests use). Every key is generated at run time and the tests check
that none of them reaches the console, the logs or the state file.
"""
from __future__ import annotations

import io
import json
import os
import re
import runpy
import secrets
import ssl
import sys
from pathlib import Path

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from fakes import FakeMgmtServer, FakeProviderServer, make_gateway, make_log, make_test_pki  # noqa: E402

from aiguard import __version__, cli  # noqa: E402
from aiguard.engine import Session  # noqa: E402
from aiguard.runlog import latest_log  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
PROVIDER_ENV = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY")
RULES = [
    ("ignore all previous instructions", "usercheck"),   # inj-override
    ("you are dan", "reset"),                            # jb-dan
    ("attacker.example", "usercheck"),                   # inj-indirect
]
WRITE_PREFIXES = ("add-", "set-", "delete-", "publish", "install-policy", "run-script")


# --------------------------------------------------------------------------- console


class ScriptedConsole(cli.Console):
    """Answers come from lists; everything printed (and every prompt) is captured.
    Hidden answers are recorded as ``(hidden)``, never as their value."""

    def __init__(self, answers=(), hidden=(), interrupt_on=None):
        self.buf = io.StringIO()
        super().__init__(stdout=self.buf, stdin=io.StringIO(""), color=False, unicode=True,
                         width=120)
        self.answers = list(answers)
        self.hidden = list(hidden)
        self.prompts = []
        self.interrupt_on = interrupt_on

    @property
    def interactive(self):
        return True

    def input(self, prompt=""):
        self.write(prompt)
        self.prompts.append(prompt)
        if self.interrupt_on and self.interrupt_on in prompt:
            raise KeyboardInterrupt
        if not self.answers:
            self.write("<EOF>\n")
            raise EOFError
        answer = self.answers.pop(0)
        self.write(answer + "\n")
        return answer

    def secret(self, prompt=""):
        self.write(prompt)
        self.prompts.append(prompt)
        if not self.hidden:
            self.write("<EOF>\n")
            raise EOFError
        self.write("(hidden)\n")
        return self.hidden.pop(0)

    @property
    def text(self):
        return self.buf.getvalue()


# --------------------------------------------------------------------------- fixtures


def lab_gateway(**kw):
    kw.setdefault("interfaces", [("eth0", "10.1.1.111", 24), ("eth1", "198.51.100.111", 24),
                                 ("eth2", "127.0.0.1", 8)])
    return make_gateway("HQ-GW", "10.1.1.111", **kw)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return make_test_pki(tmp_path_factory.mktemp("cli-pki"))


@pytest.fixture(scope="module")
def provider(pki):
    srv = FakeProviderServer(pki, rules=RULES, timeout_cap=2.0).start()
    yield srv
    srv.stop()


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
        s.stop()


@pytest.fixture
def factory(pki, provider):
    def make(**kw):
        kw.setdefault("provider_ca_file", pki.ca_pem_path)
        kw.setdefault("provider_base_urls", {"openai": provider.base_url,
                                             "anthropic": provider.base_url})
        kw.setdefault("task_poll", 0.01)
        kw.setdefault("probe_timeout", 1.5)
        kw.setdefault("tls_timeout", 5)
        kw.setdefault("mgmt_timeout", 10)
        return Session(**kw)
    return make


@pytest.fixture
def keys(monkeypatch):
    """Fake secrets in environment variables (generated per test)."""
    values = {
        "AIG_TEST_MGMT_KEY": "fake-mgmt-" + secrets.token_hex(16),
        "AIG_TEST_GUARD_KEY": secrets.token_hex(32),
        "AIG_TEST_OPENAI_KEY": "sk-test-" + secrets.token_hex(16),
    }
    for name in PROVIDER_ENV:
        monkeypatch.delenv(name, raising=False)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return values


def conn(srv, pki):
    return ["--server", "127.0.0.1", "--port", str(srv.port), "--ca-file", pki.ca_pem_path,
            "--api-key-env", "AIG_TEST_MGMT_KEY"]


AI_ARGS = ["--lakera-key-env", "AIG_TEST_GUARD_KEY", "--project-id", "project-4242"]


def run(argv, factory, answers=(), hidden=(), **kw):
    console = ScriptedConsole(answers, hidden, **kw)
    code = cli.main(argv, console=console, session_factory=factory)
    return code, console


def all_files_text(home: Path) -> str:
    chunks = []
    for p in sorted(Path(home).rglob("*")):
        if p.is_file():
            chunks.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def assert_no_secrets(keys, *texts):
    for text in texts:
        for name, value in keys.items():
            assert value not in text, "%s leaked" % name


def writes(srv):
    return [c for c in srv.call_names() if c.startswith(WRITE_PREFIXES)]


# --------------------------------------------------------------------------- setup


def test_setup_wizard_happy_path(mgmt, pki, factory, keys, aiguard_home, provider):
    srv = mgmt()
    # server type, gateway, profile name, content moderation, approval
    code, con = run(["setup"] + conn(srv, pki) + AI_ARGS +
                    ["--provider-key-env", "AIG_TEST_OPENAI_KEY"],
                    factory, answers=["", "", "", "n", "APPROVE"])
    out = con.text
    assert code == cli.EXIT_OK, out
    for needle in ("AI Guard Demo Kit", "[1/6] Connect to management", "Security Management Server",
                   "[2/6] Discover gateways", "NAME", "HTTPS INSPECTION", "HQ-GW",
                   "[3/6] Preflight", "12 passed", "[4/6] Build the demo policy",
                   "Key validated", "Planned changes", "+ add-threat-profile", "+ add-threat-rule",
                   "Nothing has been written yet.", "Type APPROVE to publish and install",
                   "[5/6] Publish and install", "✓ add-threat-profile", "✓ publish",
                   "✓ install-policy", "Enforcement check",
                   "Ready. Start the demo with  aiguard demo --guided"):
        assert needle in out, needle
    m = re.search(r"aiguard rollback ([0-9a-f]{6})", out)
    assert m, out
    assert srv.find("threat-profile", "AIGuard-Demo") is not None
    assert srv.find("threat-profile", "AIGuard-Demo")["_secret"] == keys["AIG_TEST_GUARD_KEY"]
    names = srv.call_names()
    assert "add-threat-rule" in names and "publish" in names and "install-policy" in names
    assert "run-script" not in names                     # moderation was answered "n"
    # the enforcement check went through the "gateway" with the real provider key
    assert provider.requests[-1]["headers"].get("Authorization") == \
        "Bearer " + keys["AIG_TEST_OPENAI_KEY"]
    log = latest_log(aiguard_home)
    assert str(log) in out
    assert_no_secrets(keys, out, all_files_text(aiguard_home))
    state = json.loads((aiguard_home / "state.json").read_text(encoding="utf-8"))
    assert state["last"]["gateway"] == "HQ-GW" and state["last"]["project_id"] == "project-4242"
    assert any(p["id"] == m.group(1) for p in state["rollbacks"])

    # rollback --yes undoes it (same remembered server, key from the environment)
    code, con2 = run(["rollback", "--yes", "--api-key-env", "AIG_TEST_MGMT_KEY"], factory)
    assert code == cli.EXIT_OK, con2.text
    assert "Rolled back" in con2.text and m.group(1) in con2.text
    assert srv.find("threat-profile", "AIGuard-Demo") is None
    assert_no_secrets(keys, con2.text, all_files_text(aiguard_home))


def test_setup_cancel_with_n_writes_nothing(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt()
    code, con = run(["setup"] + conn(srv, pki) + AI_ARGS, factory,
                    answers=["", "", "", "y", "D", "approve", "N"])
    out = con.text
    assert code == cli.EXIT_OK, out
    assert "Cancelled. Nothing was changed." in out
    assert writes(srv) == []
    # D printed the API calls (masked), the lowercase answer was refused
    assert "API calls" in out and "1. add-host" in out and "run-script" in out
    assert "****" + keys["AIG_TEST_GUARD_KEY"][-4:] in out
    assert "Type APPROVE in capital letters" in out
    assert srv.find("threat-profile", "AIGuard-Demo") is None
    assert_no_secrets(keys, out, all_files_text(aiguard_home))


def test_setup_offers_https_fix_then_continues(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt()
    srv.gateway("HQ-GW")["enable-https-inspection"] = False
    # type, gateway, fix now? y, APPROVE (https), profile, moderation, APPROVE (demo policy)
    code, con = run(["setup", "--skip-enforcement"] + conn(srv, pki) + AI_ARGS, factory,
                    answers=["", "", "y", "APPROVE", "", "n", "APPROVE"])
    out = con.text
    assert code == cli.EXIT_OK, out
    assert "blocking" in out and "aiguard fix https-inspection" in out
    assert "Fix HTTPS Inspection on HQ-GW now?" in out
    assert "set-simple-gateway" in out and "Preflight again" in out
    assert srv.gateway("HQ-GW")["enable-https-inspection"] is True
    assert srv.find("threat-profile", "AIGuard-Demo") is not None
    assert "Enforcement check" not in out


def test_ctrl_c_discards_and_exits_130(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt()
    code, con = run(["setup"] + conn(srv, pki) + AI_ARGS, factory,
                    answers=["", "", "", "n"], interrupt_on="Type APPROVE")
    assert code == cli.EXIT_INTERRUPTED, con.text
    assert "Interrupted (Ctrl-C)" in con.text
    names = srv.call_names()
    assert "discard" in names and "logout" in names
    assert writes(srv) == []


def test_mds_domain_is_picked_with_one_login(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt(server_type="MDS", domains=("Corp-EMEA", "Lab"))
    code, con = run(["preflight"] + conn(srv, pki), factory, answers=["Lab"])
    out = con.text
    assert code in (cli.EXIT_OK, cli.EXIT_BLOCKED), out
    assert "Multi-Domain Server" in out and "Domains: 1 Corp-EMEA, 2 Lab" in out
    assert re.search(r"Domain\s+Lab", out) and "HQ-GW" in out
    assert srv.call_names().count("login") == 1          # login-to-domain, no second login
    assert json.loads((aiguard_home / "state.json").read_text())["last"]["domain"] == "Lab"


# --------------------------------------------------------------------------- errors


def test_forbidden_ip_error_block(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt(scenario="forbidden_ip")
    code, con = run(["preflight"] + conn(srv, pki), factory)
    out = con.text
    assert code == cli.EXIT_ERROR, out
    assert "FAILED" in out and "connect to 127.0.0.1:%d" % srv.port in out
    for label in ("What failed", "Server said", "Why", "Fix", "State", "Details"):
        assert re.search(r"^  %s\s" % label, out, re.M), label
    assert "Login refused by management (HTTP 403)" in out
    assert "Accept API calls from: All IP addresses that can be used for GUI clients" in out
    assert "api restart" in out and "api status" in out
    m = re.search(r"Details\s+log line (\d+) · (\S+\.log)", out)
    assert m, out
    log_path = Path(m.group(2))
    assert log_path == latest_log(aiguard_home)
    line = log_path.read_text(encoding="utf-8").splitlines()[int(m.group(1)) - 1]
    assert "ERROR" in line and "Login refused" in line
    assert_no_secrets(keys, out, all_files_text(aiguard_home))


def test_blocking_preflight_exit_2(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt(scenario="https_off")
    code, con = run(["preflight"] + conn(srv, pki), factory)
    out = con.text
    assert code == cli.EXIT_BLOCKED, out
    assert "HTTPS Inspection on the gateway" in out and "blocking" in out
    assert "Fix  aiguard fix https-inspection" in out
    assert re.search(r"Preflight\s+\d+ passed", out)
    assert writes(srv) == []


def test_fix_https_inspection(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt()
    srv.gateway("HQ-GW")["enable-https-inspection"] = False
    code, con = run(["fix", "https-inspection"] + conn(srv, pki), factory, answers=["APPROVE"])
    assert code == cli.EXIT_OK, con.text
    assert srv.gateway("HQ-GW")["enable-https-inspection"] is True
    assert "HTTPS Inspection" in con.text and "aiguard trust-ca" in con.text
    # already on: nothing to do
    code, con = run(["fix", "https-inspection"] + conn(srv, pki), factory)
    assert code == cli.EXIT_OK and "already on" in con.text


def test_fix_https_inspection_without_outbound_ca_exits_2(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt(scenario="https_off")
    code, con = run(["fix", "https-inspection"] + conn(srv, pki), factory)
    out = con.text
    assert code == cli.EXIT_BLOCKED, out
    assert "outbound" in out.lower() and "SmartConsole" in out and "What failed" in out
    assert writes(srv) == []


def test_plan_then_apply_with_approve(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt()
    code, con = run(["plan"] + conn(srv, pki) + AI_ARGS + ["--gateway", "HQ-GW"], factory)
    assert code == cli.EXIT_OK, con.text
    m = re.search(r"Plan id ([0-9a-f]{12})", con.text)
    assert m and "aiguard apply --plan-id %s" % m.group(1) in con.text
    plan_id = m.group(1)
    assert writes(srv) == []

    # wrong --approve: refused, nothing written
    code, con = run(["apply", "--plan-id", plan_id, "--approve", "0" * 12] + conn(srv, pki) +
                    AI_ARGS, factory)
    assert code == cli.EXIT_ERROR, con.text
    assert "--approve does not match this plan" in con.text and writes(srv) == []

    # stale --plan-id: refused
    code, con = run(["apply", "--plan-id", "abcdefabcdef"] + conn(srv, pki) + AI_ARGS, factory)
    assert code == cli.EXIT_ERROR and "The plan changed since it was reviewed" in con.text
    assert writes(srv) == []

    # matching --approve: applied without any prompt
    code, con = run(["apply", "--plan-id", plan_id, "--approve", plan_id,
                     "--skip-enforcement"] + conn(srv, pki) + AI_ARGS, factory)
    assert code == cli.EXIT_OK, con.text
    assert con.prompts == []
    assert srv.find("threat-rule", "AI Guard Demo") is not None
    assert_no_secrets(keys, con.text, all_files_text(aiguard_home))


# --------------------------------------------------------------------------- demo


def test_demo_scene_injection_blocked(factory, keys, aiguard_home, provider):
    code, con = run(["demo", "--scene", "injection", "--no-pause",
                     "--provider-key-env", "AIG_TEST_OPENAI_KEY"], factory)
    out = con.text
    assert code == cli.EXIT_OK, out
    assert "TLS to api.openai.com is inspected" in out
    assert "Scene 2  Prompt injection is stopped at the gateway" in out
    assert out.count(" BLOCKED ") == 3
    for pid in ("inj-override", "jb-dan", "inj-indirect"):
        assert pid in out
    assert "evidence" in out and "usercheck" in out.lower()
    assert "connection terminated" in out
    assert re.search(r"Result\s+3 prompts · 3 blocked · 0 allowed · 0 unexpected", out)
    assert "3/3 matched what we expected" in out
    assert "Proof" in out and "not checked" in out
    reports = list((aiguard_home / "reports").glob("*.html"))
    assert reports and str(reports[0]) in out
    assert "say:" not in out                       # presenter lines only with --guided
    assert_no_secrets(keys, out, all_files_text(aiguard_home))


def test_demo_guided_presenter_mode_and_mismatch(factory, keys, aiguard_home):
    # no provider key: dummy key; the fake provider lets the PII prompts through -> unexpected
    code, con = run(["demo", "--guided", "--no-pause"], factory, answers=[""])
    out = con.text
    assert code == cli.EXIT_MISMATCH, out
    assert "[6/6] Live demo" in out and "dummy key" in out
    assert 'say: "A developer asks for help with code. Nothing gets in the way."' in out
    assert " ALLOWED " in out and " BLOCKED " in out
    assert "Scene 4  Content moderation" in out and "skipped: content moderation" in out
    assert "Scene 5  Your own prompt" in out and "Your prompt (Enter to finish)" in out
    assert "unexpected: we expected BLOCKED" in out
    assert "the provider answered 401 quickly; re-test with a real key" in out
    assert "In SmartConsole   Logs & Events" in out


def test_demo_custom_prompt_json_and_exit_1(factory, keys, aiguard_home, tmp_path):
    out_json = tmp_path / "results.json"
    code, con = run(["demo", "--prompt", "What is the capital of France?", "--expect", "block",
                     "--json", str(out_json), "--provider-key-env", "AIG_TEST_OPENAI_KEY"],
                    factory)
    assert code == cli.EXIT_MISMATCH, con.text
    assert " ALLOWED " in con.text and "unexpected" in con.text
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["summary"]["total"] == 1 and data["results"][0]["verdict"] == "ALLOWED"
    assert_no_secrets(keys, con.text, out_json.read_text(encoding="utf-8"))

    code, con = run(["demo", "--prompt", "What is the capital of France?", "--expect", "allow"],
                    factory)
    assert code == cli.EXIT_OK, con.text


def test_demo_matches_gateway_logs(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt()
    # the fake provider is reached at 127.0.0.1, so that is the destination the gateway logs
    for _ in range(3):
        srv.add_log(make_log(src="127.0.0.1", host="127.0.0.1"))
    code, con = run(["demo", "--scene", "injection", "--no-pause", "--gateway", "HQ-GW"] +
                    conn(srv, pki), factory)
    out = con.text
    assert code == cli.EXIT_OK, out
    assert "SmartConsole: Prevent" in out and "AI Agent Security" in out
    assert re.search(r"Proof\s+3 of 3 blocks found in SmartConsole logs", out), out
    assert 'blade:"AI Agent Security" AND src:127.0.0.1' in out
    assert "show-logs" in srv.call_names()
    assert writes(srv) == []
    assert_no_secrets(keys, out, all_files_text(aiguard_home))


def test_demo_stops_when_traffic_is_not_inspected(tmp_path, keys, aiguard_home):
    public = make_test_pki(tmp_path / "public", ca_cn="WE1", ca_org="Google Trust Services")
    srv = FakeProviderServer(public, default_behavior="allow").start()
    try:
        def make(**kw):
            kw["provider_ca_file"] = public.ca_pem_path
            kw["provider_base_urls"] = {"openai": srv.base_url}
            return Session(**kw)
        code, con = run(["demo", "--scene", "injection", "--no-pause"], make)
        out = con.text
        assert code == cli.EXIT_BLOCKED, out
        assert "STOPPED" in out and "Traffic to api.openai.com is not being inspected" in out
        assert "Google Trust Services" in out and "aiguard fix https-inspection" in out
        assert srv.requests == []          # stopped before any prompt was sent
    finally:
        srv.stop()


# --------------------------------------------------------------------------- secrets / argv


@pytest.mark.parametrize("argv", [
    ["setup", "--api-key", "SECRETVALUE-" + "x" * 20],
    ["setup", "--password=SECRETVALUE-" + "y" * 20],
    ["preflight", "--lakera-key", "SECRETVALUE-" + "z" * 20],
])
def test_secret_flags_are_refused(argv, capsys, factory):
    secret = argv[-1].split("=", 1)[-1]
    code, con = run(argv, factory)
    assert code == cli.EXIT_USAGE
    assert "is not accepted" in con.text and "--api-key-env VAR" in con.text
    captured = capsys.readouterr()
    for text in (con.text, captured.out, captured.err):
        assert secret not in text


def test_unknown_flag_value_not_echoed(capsys, factory):
    secret = "SECRETVALUE-" + secrets.token_hex(12)
    code, con = run(["preflight", "--api", secret], factory)
    assert code == cli.EXIT_USAGE
    assert "unrecognized arguments" in con.text
    captured = capsys.readouterr()
    for text in (con.text, captured.out, captured.err):
        assert secret not in text


def test_no_abbreviation_of_env_flags(factory):
    # --api-key-e must not silently become --api-key-env (allow_abbrev is off)
    code, con = run(["preflight", "--api-key-e", "AIG_TEST_MGMT_KEY"], factory)
    assert code == cli.EXIT_USAGE and "unrecognized arguments" in con.text


def test_env_flag_with_a_secret_instead_of_a_name(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt()
    value = "sk-" + secrets.token_hex(20)
    argv = conn(srv, pki)
    argv[argv.index("AIG_TEST_MGMT_KEY")] = value
    code, con = run(["preflight"] + argv, factory)
    assert code == cli.EXIT_ERROR
    assert "--api-key-env needs the name of an environment variable" in con.text
    assert value not in con.text and value not in all_files_text(aiguard_home)
    assert "login" not in srv.call_names()


def test_hidden_prompt_secret_is_masked(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt()
    typed = "typed-mgmt-" + secrets.token_hex(16)
    argv = [a for a in conn(srv, pki) if a not in ("--api-key-env", "AIG_TEST_MGMT_KEY")]
    code, con = run(["preflight"] + argv, factory, hidden=[typed])
    assert code == cli.EXIT_OK, con.text
    assert "(hidden)" in con.text and "****" + typed[-4:] in con.text
    assert typed not in con.text and typed not in all_files_text(aiguard_home)
    login = srv.last_call("login")
    assert login.get("api-key") == typed


# --------------------------------------------------------------------------- trust-ca


def test_trust_ca_exports_pem_and_prints_commands(mgmt, pki, factory, keys, aiguard_home, tmp_path):
    srv = mgmt()
    dest = tmp_path / "out" / "outbound-ca.pem"
    code, con = run(["trust-ca", "--export", str(dest), "--os", "all"] + conn(srv, pki), factory)
    out = con.text
    assert code == cli.EXIT_OK, out
    der = ssl.PEM_cert_to_DER_cert(dest.read_text(encoding="ascii"))
    assert der == pki.ca_der
    assert pki.ca_sha256 in out
    for needle in ("aiguard never changes the trust store", "certutil -addstore -f Root",
                   "Import-Certificate", "security add-trusted-cert -d -r trustRoot -k "
                   "/Library/Keychains/System.keychain",
                   "/usr/local/share/ca-certificates/", "update-ca-certificates",
                   "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"):
        assert needle in out, needle
    assert "show-outbound-inspection-certificate" in srv.call_names()
    assert writes(srv) == []
    # a second run does not overwrite a different file without --force
    dest.write_text("not a certificate\n", encoding="ascii")
    code, con = run(["trust-ca", "--export", str(dest)] + conn(srv, pki), factory)
    assert code == cli.EXIT_ERROR and "already exists" in con.text


def test_trust_ca_from_file_refuses_private_keys(factory, tmp_path, pki):
    bad = tmp_path / "bundle.pem"
    bad.write_text(pki.ca_pem + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
                   encoding="ascii")
    code, con = run(["trust-ca", "--from-file", str(bad)], factory)
    assert code == cli.EXIT_ERROR and "private key" in con.text
    good = tmp_path / "ca.pem"
    good.write_text(pki.ca_pem, encoding="ascii")
    code, con = run(["trust-ca", "--from-file", str(good), "--os", "linux"], factory)
    assert code == cli.EXIT_OK and "update-ca-certificates" in con.text
    assert "certutil" not in con.text


# --------------------------------------------------------------------------- misc commands


def test_logs_and_status(mgmt, pki, factory, keys, aiguard_home):
    good = mgmt()
    assert run(["preflight"] + conn(good, pki), factory)[0] == cli.EXIT_OK
    srv = mgmt(scenario="forbidden_ip")
    assert run(["preflight"] + conn(srv, pki), factory)[0] == cli.EXIT_ERROR
    code, con = run(["logs", "--path"], factory)
    assert code == 0 and con.text.strip() == str(latest_log(aiguard_home))
    code, con = run(["logs", "--errors"], factory)
    assert code == 0 and "ERROR" in con.text and "Login refused" in con.text
    code, con = run(["logs", "--json", "-n", "3"], factory)
    assert code == 0 and all(json.loads(ln) for ln in con.text.strip().splitlines())
    code, con = run(["logs"], factory)
    assert code == 0 and re.search(r"INFO\s+session\s+start host=", con.text)
    code, con = run(["status"], factory)
    assert code == 0 and "127.0.0.1:%d" % good.port in con.text and "HQ-GW" in con.text
    assert_no_secrets(keys, con.text)


def test_version_main_and_python_m(capsys, monkeypatch):
    code, con = run(["version"], None)
    assert code == 0 and __version__ in con.text
    monkeypatch.setattr(sys, "argv", ["aiguard", "version"])
    sys.modules.pop("aiguard.__main__", None)
    with pytest.raises(SystemExit) as ei:
        runpy.run_module("aiguard", run_name="__main__", alter_sys=False)
    assert ei.value.code == 0
    assert "aiguard %s" % __version__ in capsys.readouterr().out


def test_no_command_and_help(capsys):
    code, con = run([], None)
    assert code == cli.EXIT_USAGE and "setup" in con.text
    code, con = run(["--help"], None)
    assert code == 0
    assert "setup" in capsys.readouterr().out


def test_console_ascii_glyphs_on_cp1252():
    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    c = cli.Console(stdout=stream)
    assert c.unicode is False and c.color is False        # not UTF-8, not a terminal
    assert (c.g("ok"), c.g("fail"), c.g("warn"), c.g("arrow"), c.g("full")) == \
        ("OK", "X", "!", ">", "#")
    assert c.style("x", "red") == "x"
    c.print("✓ still printable")                      # never raises
    u = cli.Console(stdout=io.TextIOWrapper(io.BytesIO(), encoding="utf-8"), color=True)
    assert u.g("ok") == "✓" and u.style("x", "red").startswith("\x1b[")


def test_pyproject_packaging():
    tomllib = pytest.importorskip("tomllib")
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    assert project["name"] == "aiguard-demo-kit"
    assert project["requires-python"] == ">=3.8"
    assert project.get("dependencies", []) == []
    assert project["scripts"] == {"aiguard": "aiguard.cli:main"}
    assert data["build-system"]["build-backend"] == "setuptools.build_meta"
    st = data["tool"]["setuptools"]
    assert set(st["packages"]) == {"aiguard", "aiguard.templates"}
    assert st["package-data"]["aiguard.templates"] == ["*.json"]
    assert data["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "aiguard.__version__"}
    assert list((REPO_ROOT / "aiguard" / "templates").glob("*.json"))


def test_cli_source_has_no_banned_calls():
    src = (REPO_ROOT / "aiguard" / "cli.py").read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(", "exec(", "pickle", "verify=False",
                   "CERT_NONE", "check_hostname = False", "_create_unverified_context",
                   "shell=True"):
        assert banned not in src, banned


# --------------------------------------------------------------------------- review fixes


def test_password_prompt_is_masked_without_tail(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt()
    typed = "Winter-" + secrets.token_hex(3) + "-77QZ"
    argv = [a for a in conn(srv, pki) if a not in ("--api-key-env", "AIG_TEST_MGMT_KEY")]
    code, con = run(["preflight", "--user", "aiguard-admin"] + argv, factory, hidden=[typed])
    assert code == cli.EXIT_OK, con.text
    assert "the log shows it as ****" in con.text
    files = all_files_text(aiguard_home)
    for text in (con.text, files):
        assert typed not in text and "77QZ" not in text
    assert srv.last_call("login")["password"] == typed


def test_plan_prints_an_apply_command_that_rebuilds_the_same_plan(mgmt, pki, factory, keys,
                                                                    aiguard_home):
    import shlex as _shlex
    srv = mgmt()
    code, con = run(["--home", str(aiguard_home), "plan"] + conn(srv, pki) + AI_ARGS +
                    ["--gateway", "HQ-GW", "--local-ip", "10.1.1.50"], factory)
    assert code == cli.EXIT_OK, con.text
    line = next(ln.strip() for ln in con.text.splitlines() if ln.strip().startswith("aiguard "))
    argv = _shlex.split(line)
    assert argv[:3] == ["aiguard", "--home", str(aiguard_home)]
    assert "--local-ip" in argv and argv[argv.index("--local-ip") + 1] == "10.1.1.50"
    plan_id = argv[argv.index("--plan-id") + 1]
    code, con = run(argv[1:] + ["--approve", plan_id, "--skip-enforcement"], factory)
    assert code == cli.EXIT_OK, con.text
    assert srv.find("host", "aiguard-client-10-1-1-50") is not None


def test_trust_ca_points_at_outbound_ca_flag(mgmt, pki, factory, keys, aiguard_home, tmp_path):
    srv = mgmt()
    dest = tmp_path / "outbound-ca.pem"
    code, con = run(["trust-ca", "--export", str(dest), "--os", "linux"] + conn(srv, pki), factory)
    assert code == cli.EXIT_OK, con.text
    assert "This kit only:  aiguard demo --outbound-ca" in con.text
    assert "aiguard demo --ca-file" not in con.text


def test_preflight_shows_a_partial_install(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt(scenario="partial_install_failed")
    code, con = run(["preflight"] + conn(srv, pki) + ["--gateway", "HQ-GW"], factory)
    out = con.text
    assert code == cli.EXIT_OK, out                      # never blocking
    assert "Last policy install on HQ-GW partly failed" in out and "warning" in out
    assert "Threat Prevention installed but Access Control did not" in out
    assert re.search(r"Said\s+Layer 'Network': Rule 2 \(AI\)", out), out
    assert "sk116272" in out and "not-installed: Access Control" in out


def test_demo_proof_says_when_logs_could_not_be_read(mgmt, pki, factory, keys, aiguard_home):
    from fakes import _ApiError

    srv = mgmt()

    def denied(ctx, p):
        raise _ApiError(403, "generic_err_permission_denied", "Permission denied: show-logs")

    srv._c_show_logs = denied
    code, con = run(["demo", "--scene", "injection", "--no-pause", "--gateway", "HQ-GW"] +
                    conn(srv, pki), factory)
    out = con.text
    assert re.search(r"Proof\s+not matched: Could not read the gateway logs", out), out
    assert "Monitoring and Logging" in out
    assert "blocks found in SmartConsole logs" not in out


def test_fix_https_inspection_in_learning_mode_sets_full(mgmt, pki, factory, keys, aiguard_home):
    srv = mgmt(scenario="https_learning")
    code, con = run(["fix", "https-inspection"] + conn(srv, pki), factory, answers=["APPROVE"])
    assert code == cli.EXIT_OK, con.text
    assert "already on" not in con.text and "Learning mode" in con.text
    assert srv.gateway("HQ-GW")["https-inspection"]["deployment-mode"] == "full"


def test_apply_with_denied_script_finishes_and_says_what_is_left(mgmt, pki, factory, keys,
                                                                 aiguard_home):
    srv = mgmt(scenario="script_denied")
    code, con = run(["plan"] + conn(srv, pki) + AI_ARGS + ["--gateway", "HQ-GW", "--moderation"],
                    factory)
    plan_id = re.search(r"Plan id ([0-9a-f]{12})", con.text).group(1)
    code, con = run(["apply", "--plan-id", plan_id, "--approve", plan_id, "--moderation"] +
                    conn(srv, pki) + AI_ARGS + ["--gateway", "HQ-GW"], factory)
    out = con.text
    assert code in (cli.EXIT_OK, cli.EXIT_MISMATCH), out     # the policy is installed
    assert "YOU DO THIS" in out and "Content moderation was not turned on" in out
    assert "Run One Time Script" in out and "Enforcement check" in out
    assert "FAILED" not in out


# --------------------------------------------------------------------------- integration round


def test_a_remembered_ca_file_that_is_gone_is_ignored(mgmt, pki, factory, keys, aiguard_home,
                                                      tmp_path):
    srv = mgmt()
    gone = tmp_path / "web-upload.pem"
    gone.write_text(Path(pki.ca_pem_path).read_text(encoding="ascii"), encoding="ascii")
    argv = ["--server", "127.0.0.1", "--port", str(srv.port), "--ca-file", str(gone),
            "--api-key-env", "AIG_TEST_MGMT_KEY", "--gateway", "HQ-GW"]
    assert run(["preflight"] + argv, factory)[0] == cli.EXIT_OK
    gone.unlink()
    code, con = run(["status"], factory)
    assert code == cli.EXIT_OK
    assert re.search(r"CA file\s+%s \(missing\)" % re.escape(str(gone)), con.text), con.text
    # The next run without --ca-file warns and connects without it: here the server's
    # certificate is then not trusted (the test CA is in no trust store), which proves the
    # connection was tried instead of stopping on the missing file.
    code, con = run(["preflight", "--server", "127.0.0.1", "--port", str(srv.port),
                     "--api-key-env", "AIG_TEST_MGMT_KEY", "--gateway", "HQ-GW"], factory)
    out = con.text
    assert "%s no longer exists" % gone in out
    assert "does not trust the management server's certificate" in out, out
    assert "CA file not found" not in out
    log = latest_log(aiguard_home).read_text(encoding="utf-8")
    assert "the remembered CA file no longer exists; ignored" in log


def test_demo_shows_the_last_policy_install_before_the_first_prompt(mgmt, pki, factory, keys,
                                                                    aiguard_home):
    srv = mgmt(scenario="partial_install_failed")
    code, con = run(["demo", "--scene", "injection", "--no-pause", "--gateway", "HQ-GW"] +
                    conn(srv, pki), factory)
    out = con.text
    head, _, rest = out.partition("Scene 2")
    assert rest, out
    assert "Last policy install on HQ-GW partly failed" in head
    assert re.search(r"Said\s+Layer 'Network': Rule 2 \(AI\)", head), head
    assert "results may reflect the older policy" in head
    assert "show-tasks" in srv.call_names() and writes(srv) == []
    assert_no_secrets(keys, out, all_files_text(aiguard_home))
    good = mgmt()
    code, con = run(["demo", "--scene", "injection", "--no-pause", "--gateway", "HQ-GW"] +
                    conn(good, pki), factory)
    assert re.search(r"Last policy install\s+The last policy installation on HQ-GW succeeded",
                     con.text), con.text


# --------------------------------------------------------------------------- environment defaults
# (AIGUARD_MGMT_* / AIGUARD_GATEWAY written to .env by the lab installer, aiguard/envdefaults.py)


def _installer_ca(tmp_path, pki):
    path = tmp_path / "installer" / "mgmt-ca.pem"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(Path(pki.ca_pem_path).read_text(encoding="ascii"), encoding="ascii")
    return path


def _two_gateways():
    return [lab_gateway(), make_gateway("WAN-GW", "10.2.2.2")]


def test_env_defaults_are_used_when_flags_are_not_given(mgmt, pki, factory, keys, aiguard_home,
                                                       monkeypatch, tmp_path):
    srv = mgmt(gateways=_two_gateways())
    ca = _installer_ca(tmp_path, pki)
    monkeypatch.setenv("AIGUARD_MGMT_SERVER", "127.0.0.1")
    monkeypatch.setenv("AIGUARD_MGMT_PORT", str(srv.port))
    monkeypatch.setenv("AIGUARD_MGMT_CA_FILE", str(ca))
    monkeypatch.setenv("AIGUARD_GATEWAY", "WAN-GW")
    code, con = run(["preflight", "--api-key-env", "AIG_TEST_MGMT_KEY"], factory)
    out = con.text
    assert code in (cli.EXIT_OK, cli.EXIT_BLOCKED), out
    assert re.search(r"CA file\s+%s\s+from AIGUARD_MGMT_CA_FILE" % re.escape(str(ca)), out), out
    assert re.search(r"Gateway\s+WAN-GW", out), out
    assert not any("Target gateway" in p for p in con.prompts)   # two gateways, not asked
    last = json.loads((aiguard_home / "state.json").read_text(encoding="utf-8"))["last"]
    assert last["server"] == "127.0.0.1" and last["port"] == srv.port
    log = latest_log(aiguard_home).read_text(encoding="utf-8")
    assert "defaults from the environment" in log and "AIGUARD_MGMT_CA_FILE" in log
    assert_no_secrets(keys, out, all_files_text(aiguard_home))
    # status shows them (and what was ignored)
    monkeypatch.setenv("AIGUARD_MGMT_TYPE", "cloud")
    code, con = run(["status"], factory)
    out = con.text
    assert code == cli.EXIT_OK, out
    assert re.search(r"Defaults from the environment\s+127\.0\.0\.1:%d .*gateway WAN-GW"
                     % srv.port, out), out
    assert re.search(r"CA file \(environment\)\s+%s" % re.escape(str(ca)), out), out
    assert "AIGUARD_MGMT_TYPE must be SMS or MDS: ignored" in out


def test_flags_override_env_defaults(mgmt, pki, factory, keys, aiguard_home, monkeypatch,
                                     tmp_path):
    srv = mgmt(gateways=_two_gateways())
    # every environment value here would fail; the flags must win over each one
    monkeypatch.setenv("AIGUARD_MGMT_SERVER", "127.0.0.1")
    monkeypatch.setenv("AIGUARD_MGMT_PORT", "1")
    monkeypatch.setenv("AIGUARD_MGMT_SERVER_NAME", "mgmt.wrong.example")
    monkeypatch.setenv("AIGUARD_MGMT_CA_FILE", str(tmp_path / "missing.pem"))
    monkeypatch.setenv("AIGUARD_MGMT_DOMAIN", "No-Such-Domain")
    monkeypatch.setenv("AIGUARD_GATEWAY", "WAN-GW")
    code, con = run(["preflight"] + conn(srv, pki) +
                    ["--server-name", "localhost", "--domain", "", "--gateway", "HQ-GW"], factory)
    out = con.text
    assert code in (cli.EXIT_OK, cli.EXIT_BLOCKED), out
    assert re.search(r"Gateway\s+HQ-GW", out) and "AIGUARD_MGMT_CA_FILE" not in out, out
    login = [c for c in srv.calls if c[0] == "login"]
    assert login and "domain" not in (login[0][1] or {})
    # another --server: the port, name and domain of AIGUARD_MGMT_SERVER do not apply
    monkeypatch.setenv("AIGUARD_MGMT_SERVER", "10.9.9.9")
    monkeypatch.delenv("AIGUARD_MGMT_CA_FILE")
    code, con = run(["preflight", "--server", "127.0.0.1", "--port", str(srv.port),
                     "--ca-file", pki.ca_pem_path, "--api-key-env", "AIG_TEST_MGMT_KEY"],
                    factory)
    out = con.text
    assert code in (cli.EXIT_OK, cli.EXIT_BLOCKED), out
    assert re.search(r"Gateway\s+WAN-GW", out), out          # the gateway still applies


@pytest.mark.parametrize("kind, needle", [
    ("missing", "CA file not found"),
    ("directory", "CA file is not a file"),
    ("not-pem", "is not a PEM certificate"),
])
def test_invalid_env_ca_file_is_a_clear_error(kind, needle, mgmt, pki, factory, keys,
                                              aiguard_home, monkeypatch, tmp_path):
    srv = mgmt()
    path = tmp_path / "mgmt-ca.pem"
    if kind == "directory":
        path.mkdir()
    elif kind == "not-pem":
        path.write_text("this is not a certificate\n", encoding="ascii")
    monkeypatch.setenv("AIGUARD_MGMT_CA_FILE", str(path))
    code, con = run(["preflight", "--server", "127.0.0.1", "--port", str(srv.port),
                     "--api-key-env", "AIG_TEST_MGMT_KEY", "--gateway", "HQ-GW"], factory)
    out = con.text
    assert code == cli.EXIT_ERROR, out
    assert "The CA file in AIGUARD_MGMT_CA_FILE cannot be used: " in out, out
    assert needle in out, out
    assert "set in .env by the lab installer" in out
    assert "Or pass --ca-file <file.pem>" in out and "No connection was made." in out
    assert srv.call_names() == []                      # stopped before any request
    assert_no_secrets(keys, out, all_files_text(aiguard_home))
    # --ca-file wins over the broken variable
    code, con = run(["preflight"] + conn(srv, pki) + ["--gateway", "HQ-GW"], factory)
    assert code in (cli.EXIT_OK, cli.EXIT_BLOCKED), con.text


def test_setup_wizard_offers_env_values_as_default_answers(mgmt, pki, factory, keys,
                                                          aiguard_home, monkeypatch, tmp_path):
    srv = mgmt(gateways=_two_gateways())
    ca = _installer_ca(tmp_path, pki)
    monkeypatch.setenv("AIGUARD_MGMT_SERVER", "127.0.0.1")
    monkeypatch.setenv("AIGUARD_MGMT_PORT", str(srv.port))
    monkeypatch.setenv("AIGUARD_MGMT_TYPE", "MDS")
    monkeypatch.setenv("AIGUARD_MGMT_CA_FILE", str(ca))
    monkeypatch.setenv("AIGUARD_GATEWAY", "WAN-GW")
    # Enter on server type, address, port and gateway: the environment's answers
    code, con = run(["setup", "--api-key-env", "AIG_TEST_MGMT_KEY"] + AI_ARGS, factory,
                    answers=["", "", "", ""])
    out = con.text
    prompts = con.prompts
    assert any("Server type" in p and "› MDS" in p for p in prompts), prompts
    assert any("Management address" in p and "[127.0.0.1]" in p for p in prompts), prompts
    assert any("Port" in p and "[%d]" % srv.port in p for p in prompts), prompts
    assert any("Target gateway" in p and "› WAN-GW" in p for p in prompts), prompts
    assert re.search(r"Gateway\s+WAN-GW", out), out
    assert "the server reports SMS" in out              # the answer is checked after login
    assert writes(srv) == []                            # nothing approved
    assert_no_secrets(keys, out, all_files_text(aiguard_home))
    # a flag is not asked again, whatever the environment says
    code, con = run(["setup", "--server-type", "sms", "--gateway", "HQ-GW"] + conn(srv, pki)
                    + AI_ARGS, factory, answers=[])
    assert not any("Server type" in p or "Target gateway" in p for p in con.prompts), con.prompts
    assert re.search(r"Gateway\s+HQ-GW", con.text), con.text
    assert writes(srv) == []
