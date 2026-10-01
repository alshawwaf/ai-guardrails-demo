"""Tests for the integration fixes that join the modules together.

* aiguard.redact: secrets held by an owner (one per engine session) stay masked until
  every owner lets go;
* MgmtClient.forget_secrets() works after logout();
* the outbound certificate lookup (shared by preflight, plan, the engine and the CLI)
  with and without the plural listing, never returning the PKCS#12 blob;
* engine Session: outbound_ca(), discard(), tls_check(), moderation_on(), the
  template-aware status step, and the local IP override (argument / AIGUARD_LOCAL_IP).

All servers are fakes on 127.0.0.1 with TLS verified against a CA generated at test time;
every key is generated here.
"""
from __future__ import annotations

import os
import secrets
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from fakes import FakeMgmtServer, FakeProviderServer, make_gateway, make_test_pki  # noqa: E402

from aiguard import mgmt as mgmt_mod  # noqa: E402
from aiguard import redact  # noqa: E402
from aiguard.engine import LOCAL_IP_ENV, Session  # noqa: E402
from aiguard.errors import PlanError  # noqa: E402
from aiguard.mgmt import MgmtClient, outbound_certificate_info, show_outbound_certificate  # noqa: E402
from aiguard.plan import PlanOptions  # noqa: E402
from aiguard.runlog import RunLog  # noqa: E402


def lab_gateway(**kw):
    kw.setdefault("interfaces", [("eth0", "10.1.1.111", 24), ("eth2", "127.0.0.1", 8)])
    return make_gateway("HQ-GW", "10.1.1.111", **kw)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return make_test_pki(tmp_path_factory.mktemp("integration-pki"))


@pytest.fixture(scope="module")
def provider(pki):
    srv = FakeProviderServer(pki).start()
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
        assert s.errors == [], s.errors[0]
        s.stop()


@pytest.fixture
def make_session(aiguard_home, pki, provider, monkeypatch):
    monkeypatch.delenv(LOCAL_IP_ENV, raising=False)
    made = []

    def make(**kw):
        kw.setdefault("home", aiguard_home)
        kw.setdefault("provider_ca_file", pki.ca_pem_path)
        kw.setdefault("provider_base_urls", {"openai": provider.base_url,
                                             "anthropic": provider.base_url})
        kw.setdefault("task_poll", 0.01)
        kw.setdefault("tls_timeout", 5)
        kw.setdefault("mgmt_timeout", 10)
        s = Session(**kw)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


def key(prefix="fake-mgmt-"):
    return prefix + secrets.token_hex(16)


def connect(session, srv, pki, api_key=None):
    return session.connect("127.0.0.1", port=srv.port, api_key=api_key or key(),
                           ca_file=pki.ca_pem_path)


# --------------------------------------------------------------------------- redact


def test_owned_secret_stays_masked_until_every_owner_lets_go():
    value = "Shared-" + secrets.token_hex(12)
    a, b = object(), object()
    redact.register_secret(value, owner=a)
    redact.register_secret(value, owner=b)
    redact.forget_secret(value)                    # anonymous forget: still held
    assert value not in redact.redact("x %s y" % value)
    redact.forget_secret(value, owner=a)
    assert value not in redact.redact("x %s y" % value)
    redact.forget_secret(value, owner=b)           # last owner: forgotten
    assert redact.redact("x %s y" % value) == "x %s y" % value
    plain = "Plain-" + secrets.token_hex(12)       # unowned values behave as before
    redact.register_secret(plain)
    redact.forget_secret(plain)
    assert redact.redact(plain) == plain


def test_two_engine_sessions_share_a_key(make_session, mgmt, pki):
    srv = mgmt()
    shared = key()
    s1, s2 = make_session(), make_session()
    connect(s1, srv, pki, shared)
    connect(s2, srv, pki, shared)
    s1.close()
    assert shared not in redact.redact("key=%s" % shared)     # s2 still uses it
    s2.log.info("test", "after the first session closed", note="value %s" % shared)
    assert shared not in s2.log.path.read_text(encoding="utf-8")
    s2.close()
    assert redact.redact("key %s" % shared) == "key %s" % shared   # nobody holds it now


def test_mgmt_forget_secrets_after_logout(mgmt, pki, aiguard_home):
    srv = mgmt()
    api_key = key()
    log = RunLog(home=aiguard_home)
    client = MgmtClient("127.0.0.1", srv.port, ca_file=pki.ca_pem_path, timeout=5, log=log)
    client.login(api_key=api_key)
    sid = client.sid
    assert api_key not in redact.redact(api_key) and sid not in redact.redact(sid)
    client.logout()
    client.forget_secrets()
    assert redact.redact("k %s" % api_key) == "k %s" % api_key
    log.close()


# --------------------------------------------------------------------------- outbound CA


@pytest.mark.parametrize("scenario", [None, "outbound_needs_name"])
def test_outbound_certificate_lookup(mgmt, pki, aiguard_home, scenario):
    srv = mgmt(scenario=scenario)
    log = RunLog(home=aiguard_home)
    client = MgmtClient("127.0.0.1", srv.port, ca_file=pki.ca_pem_path, timeout=5, log=log)
    client.login(api_key=key())
    raw = show_outbound_certificate(client)
    assert raw is not None and raw.get("base64-certificate")
    if scenario:
        assert srv.last_call("show-outbound-inspection-certificates") is not None
        assert srv.last_call("show-outbound-inspection-certificate") == {
            "name": "Outbound Certificate"}
    info = outbound_certificate_info(raw)
    assert "base64-certificate" not in info and info["pkcs12_only"] is False
    assert info["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert info["pem"].endswith("-----END CERTIFICATE-----\n") and "\r" not in info["pem"]
    srv.state.outbound_cert = False
    assert show_outbound_certificate(client) is None
    client.logout()
    log.close()


def test_outbound_info_pkcs12_only():
    info = outbound_certificate_info({"name": "Outbound", "base64-certificate": "AAAA"})
    assert info == {"name": "Outbound", "pem": None, "base64-public-certificate": None,
                    "pkcs12_only": True}


def test_preflight_and_https_plan_find_the_certificate_by_name(make_session, mgmt, pki):
    srv = mgmt(scenario="outbound_needs_name")
    srv.gateway("HQ-GW")["enable-https-inspection"] = False
    s = make_session()
    connect(s, srv, pki)
    s.discover()
    s.select_gateway("HQ-GW")
    report = s.run_preflight()
    assert report.check("outbound_ca").status == "pass"
    plan = s.build_https_plan()
    step = plan.step("https_gateway")
    assert plan.template == "https-inspection" and step is not None
    assert step.command == "set-simple-gateway" and step.action != "none"
    srv.state.outbound_cert = False
    with pytest.raises(PlanError) as ei:
        s.build_https_plan()
    assert ei.value.code == "plan.no_outbound_ca"


def test_engine_outbound_ca_is_display_safe(make_session, mgmt, pki):
    srv = mgmt()
    s = make_session()
    connect(s, srv, pki)
    ca = s.outbound_ca()
    assert ca["name"] == "Outbound Certificate" and ca["issued-by"]
    assert ca["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert ca["base64-public-certificate"] == ca["pem"]
    assert "base64-certificate" not in ca and ca["pkcs12_only"] is False
    srv.state.outbound_cert = False
    with pytest.raises(PlanError) as ei:
        s.outbound_ca()
    assert ei.value.code == "plan.no_outbound_ca" and ei.value.fix


# --------------------------------------------------------------------------- engine


def test_discard_is_best_effort(make_session, mgmt, pki):
    srv = mgmt()
    s = make_session()
    assert s.discard() is False                     # not connected: nothing to do
    connect(s, srv, pki)
    assert s.discard() is True and "discard" in srv.call_names()
    srv.state.sessions.clear()                      # the server forgot the session
    assert s.discard() in (True, False)             # never raises


def test_tls_check_uses_the_provider_endpoint(make_session, provider):
    s = make_session()
    res = s.tls_check("openai")
    assert res["status"] == "inspected" and res["host"] == "api.openai.com"
    assert res["target"] == "127.0.0.1" and res["port"] == provider.port
    with pytest.raises(Exception):
        s.tls_check("no-such-provider")


def test_status_step_is_template_aware(make_session, mgmt, pki):
    srv = mgmt()
    srv.gateway("HQ-GW")["enable-https-inspection"] = False
    s = make_session()
    connect(s, srv, pki)
    s.discover()
    s.select_gateway("HQ-GW")
    s.run_preflight()
    assert s.status()["step"] == "configure"
    plan = s.build_https_plan()
    assert s.status()["step"] == "configure"         # the fix is not the demo policy
    res = s.apply(plan.plan_id)
    assert res.ok, res.error
    assert s.status()["step"] == "preflight"         # run preflight again after the fix


def test_moderation_on_reads_rollback_points(make_session, mgmt, pki):
    s = make_session()
    assert s.moderation_on() is False
    s.moderation_enabled = True
    assert s.moderation_on() is True


def test_local_ip_override(make_session, monkeypatch, mgmt, pki):
    monkeypatch.setenv(LOCAL_IP_ENV, "192.0.2.50")
    s = make_session()
    assert s.local_ip == "192.0.2.50"
    s2 = make_session(local_ip="198.51.100.7")       # the argument wins
    assert s2.local_ip == "198.51.100.7"
    monkeypatch.setenv(LOCAL_IP_ENV, "not an ip")
    s3 = make_session()
    assert s3.local_ip is None
    assert any(r["msg"] == "ignoring an invalid local IP address"
               for r in s3.log.tail(50, component="engine"))

    srv = mgmt()
    monkeypatch.setenv(LOCAL_IP_ENV, "192.0.2.50")
    s4 = make_session()
    connect(s4, srv, pki)
    s4.discover()
    s4.select_gateway("HQ-GW")
    s4.set_lakera(secrets.token_hex(32), "project-4242")
    plan = s4.build_plan(PlanOptions(gateway="HQ-GW"))
    host = plan.step("client_host")
    assert host.display_payload["ip-address"] == "192.0.2.50"
    assert host.display_payload["name"] == "aiguard-client-192-0-2-50"


def test_release_map_accepts_both_spellings_of_api_2():
    assert mgmt_mod.release_for_api("2") == mgmt_mod.release_for_api("2.0") == "R82"
    assert mgmt_mod.release_for_api("2.2") == "R82.20"
