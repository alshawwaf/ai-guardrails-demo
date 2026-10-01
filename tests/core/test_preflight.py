"""Tests for aiguard.preflight (spec 6).

Management calls go to FakeMgmtServer and the TLS handshakes of ``tls_path`` go to a
FakeProviderServer through ``probe_endpoints`` (no internet). Every connection is
verified with a CA generated at test time (``ca_file``); nothing relaxes TLS checks.
"""
from __future__ import annotations

import ast
import os
import re
import secrets
import socket
import sys
from pathlib import Path

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import datetime  # noqa: E402

from fakes import (LAB_DATA_TYPES_ERROR, FakeMgmtServer, FakeProviderServer,  # noqa: E402
                   make_gateway, make_install_task, make_test_pki)

from aiguard import gateways  # noqa: E402
from aiguard.mgmt import MgmtClient  # noqa: E402
from aiguard.preflight import (CHECK_IDS, TRUST_CA_FIX, CheckResult,  # noqa: E402
                               PreflightReport, run_preflight)
from aiguard.runlog import RunLog  # noqa: E402

AIGUARD_DIR = Path(__file__).resolve().parents[2] / "aiguard"
HOSTS = ("api.openai.com", "api.anthropic.com")
HTTPS_FIX_0 = "aiguard fix https-inspection  (asks for approval)"
HTTPS_FIX_1 = ("Or SmartConsole > HQ-GW > HTTPS Inspection > Step 1 create/import the outbound "
               "CA > Step 2 deploy it to clients > Step 3 enable HTTPS Inspection (Deployment "
               "Mode: Full inspection), then install the Access Control policy")
API_WRITE_FIX = ("SmartConsole > Manage & Settings > Permissions & Administrators > Permission "
                 "Profiles > (profile) > Management: Management API Login; Access Control / "
                 "Threat Prevention: Edit; Install Policy")


def lab_gateway(**kw):
    """HQ-GW with an extra 127.0.0.0/8 interface so the test client (127.0.0.1) is local."""
    kw.setdefault("interfaces", [("eth0", "10.1.1.111", 24), ("eth1", "198.51.100.111", 24),
                                 ("eth2", "127.0.0.1", 8)])
    return make_gateway("HQ-GW", "10.1.1.111", **kw)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return make_test_pki(tmp_path_factory.mktemp("pf-pki"))


@pytest.fixture(scope="module")
def provider(pki):
    srv = FakeProviderServer(pki).start()
    yield srv
    srv.stop()


@pytest.fixture
def runlog(aiguard_home):
    log = RunLog(home=aiguard_home)
    yield log
    log.close()


@pytest.fixture
def connect(pki, runlog):
    servers = []

    def start(*, read_only=False, gateways_=None, **kw):
        if gateways_ is None:
            gateways_ = [lab_gateway()]
        srv = FakeMgmtServer(pki, gateways=gateways_, **kw).start()
        servers.append(srv)
        client = MgmtClient("127.0.0.1", srv.port, ca_file=pki.ca_pem_path, timeout=5, log=runlog)
        client.login(api_key="fake-" + secrets.token_hex(12), read_only=read_only)
        gws = gateways.discover(client, log=runlog)
        gw = gateways.detail(client, gws[0], log=runlog)
        return srv, client, gw

    yield start
    for s in servers:
        assert s.errors == [], s.errors[0]
        s.stop()


def endpoints(srv):
    return {h: ("127.0.0.1", srv.port) for h in HOSTS}


def run(client, gw, pki, provider, runlog, **kw):
    kw.setdefault("probe_endpoints", endpoints(provider))
    kw.setdefault("local_ip", "127.0.0.1")
    kw.setdefault("ca_file", pki.ca_pem_path)
    return run_preflight(client, gw, probe_hosts=HOSTS, log=runlog, timeout=5, **kw)


def by_id(report: PreflightReport):
    return {c.id: c for c in report.checks}


# --------------------------------------------------------------------------- source rules


def test_owned_modules_are_stdlib_only_py38_and_safe():
    stdlib = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
    banned = re.compile(r"verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False|"
                        r"_create_unverified_context|\beval\(|\bexec\(|subprocess|os\.system|"
                        r"pickle|shell\s*=\s*True")
    for name in ("preflight.py", "report.py", "engine.py"):
        path = AIGUARD_DIR / name
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(path), feature_version=(3, 8))
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module.split(".")[0]]
            for m in mods:
                assert not stdlib or m in stdlib, "%s imports non-stdlib %s" % (name, m)
            assert not isinstance(node, ast.Match), name
        assert not banned.search(src), "%s: %s" % (name, banned.search(src).group(0))


# --------------------------------------------------------------------------- all pass


def test_all_checks_pass_in_order(connect, pki, provider, runlog):
    srv, client, gw = connect()
    report = run(client, gw, pki, provider, runlog)
    assert [c.id for c in report.checks] == list(CHECK_IDS)
    assert len(report.checks) == 12
    assert list(CHECK_IDS).index("last_install") == list(CHECK_IDS).index("package") + 1
    assert CHECK_IDS[-1] == "workforce_ai"
    bad = [(c.id, c.status, c.detail) for c in report.checks if c.status != "pass"]
    assert bad == []
    assert report.ok and report.passed == 12 and report.failed_blocking == 0 and report.warnings == 0
    c = by_id(report)
    assert "inspected by" in c["tls_path"].detail
    assert c["tls_path"].evidence["api.openai.com"].startswith("inspected by")
    assert "AI Guard Test" in c["tls_path"].evidence["issuer"]
    assert c["package"].evidence == {"package": "Standard", "threat_layer": "Standard Threat Prevention"}
    assert c["outbound_ca"].evidence["issued-by"] == pki.ca_issuer_dn
    assert c["outbound_ca"].evidence["valid-to"]
    assert c["client_path"].evidence["network"] == "127.0.0.0/8"
    assert "separate from AI Agent Security" in c["workforce_ai"].detail
    assert c["last_install"].detail.startswith("The last policy installation on HQ-GW succeeded")
    assert c["last_install"].evidence["task-status"] == "succeeded"
    assert c["api_write"].evidence["permissions"] == "not checked"
    assert "permission profile is not checked" in c["api_write"].detail
    assert all(isinstance(c.log_line, int) and c.log_line > 0 for c in report.checks)
    data = report.to_dict()
    assert data["ok"] is True and data["passed"] == 12 and len(data["checks"]) == 12
    assert data["summary"] == "12 passed, 0 blocking, 0 warnings"
    assert {"server_said", "action"} <= set(data["checks"][0])
    # read-only: only show-* / housekeeping calls were made
    assert all(n.startswith("show-") or n in ("login", "keepalive") for n in srv.call_names())
    text = Path(runlog.path).read_text(encoding="utf-8")
    assert "tls_path pass" in text and "preflight" in text


def test_detail_is_fetched_when_gateway_not_detailed(connect, pki, provider, runlog):
    srv, client, gw = connect()
    listing = gateways.discover(client, log=runlog)[0]
    assert listing.detailed is False
    report = run(client, listing, pki, provider, runlog)
    assert by_id(report)["https_gw"].status == "pass"
    assert by_id(report)["tp_mode"].status == "pass"


# --------------------------------------------------------------------------- failures


def test_https_off_is_blocking_and_fixable(connect, pki, provider, runlog):
    srv, client, gw = connect(scenario="https_off")
    report = run(client, gw, pki, provider, runlog)
    c = by_id(report)
    https = c["https_gw"]
    assert https.status == "fail" and https.blocking is True
    assert https.fixable == "https-inspection"
    assert https.fix == [HTTPS_FIX_0, HTTPS_FIX_1]
    assert https.action == {"id": "https-inspection",
                            "label": "Turn on HTTPS Inspection on HQ-GW (asks for approval)",
                            "cli": "aiguard fix https-inspection", "options": {"add_rule": False}}
    assert c["outbound_ca"].status == "warn" and not c["outbound_ca"].blocking
    assert "needed before HTTPS Inspection can be enabled" in c["outbound_ca"].detail
    assert report.ok is False and report.failed_blocking == 1
    assert report.fixable() == ["https-inspection"]
    assert [b.id for b in report.blocking()] == ["https_gw"]


def test_autonomous_mode_warns_not_blocking(connect, pki, provider, runlog):
    srv, client, gw = connect(scenario="autonomous")
    report = run(client, gw, pki, provider, runlog)
    tp = by_id(report)["tp_mode"]
    assert tp.status == "warn" and tp.blocking is False
    assert tp.detail.startswith("Custom threat profiles apply only when the gateway uses Custom "
                                "Threat Prevention.")
    assert tp.fix[0] == ("SmartConsole > Gateways & Servers > HQ-GW (double-click) > General "
                         "Properties > Threat Prevention tab: select Custom Threat Prevention")
    assert report.ok is True and report.warnings == 1


def test_old_api_version_fails(connect, pki, provider, runlog):
    srv, client, gw = connect(scenario="old_version")
    report = run(client, gw, pki, provider, runlog)
    c = by_id(report)
    assert c["api_version"].status == "fail" and c["api_version"].blocking
    assert c["api_version"].detail == ("AI Agent Security needs R82.20 management (Management API "
                                       "2.2). This server reports API 2 (R82).")
    assert c["api_version"].fix and "R82.20" in c["api_version"].fix[0]
    assert c["ai_support"].status == "fail" and c["ai_support"].blocking
    assert c["ai_support"].fix == c["api_version"].fix
    assert c["workforce_ai"].status == "skip"   # API 2 has no workforce-ai
    assert not report.ok


def test_read_only_login_fails_api_write(connect, pki, provider, runlog):
    srv, client, gw = connect(read_only=True)
    report = run(client, gw, pki, provider, runlog)
    w = by_id(report)["api_write"]
    assert w.status == "fail" and w.blocking
    assert API_WRITE_FIX in w.fix


def test_old_and_unknown_gateway_version(connect, pki, provider, runlog):
    srv, client, gw = connect(gateways_=[lab_gateway(version="R81.20")])
    c = by_id(run(client, gw, pki, provider, runlog))["gw_version"]
    assert c.status == "fail" and c.blocking and "R81.20" in c.detail
    gw.version, gw.release = None, None
    c = by_id(run(client, gw, pki, provider, runlog))["gw_version"]
    assert c.status == "warn" and not c.blocking and c.fix


def test_missing_fields_skip_and_workforce_off_warns(connect, pki, provider, runlog):
    srv, client, gw = connect(gateways_=[lab_gateway(threat_prevention_mode=None,
                                                     https_inspection=None, workforce_ai=False)])
    c = by_id(run(client, gw, pki, provider, runlog))
    assert c["tp_mode"].status == "skip" and c["https_gw"].status == "skip"
    assert c["workforce_ai"].status == "warn" and not c["workforce_ai"].blocking
    assert "separate from AI Agent Security" in c["workforce_ai"].detail
    srv2, client2, gw2 = connect(gateways_=[lab_gateway(workforce_ai=None)])
    assert by_id(run(client2, gw2, pki, provider, runlog))["workforce_ai"].status == "skip"


def test_client_path_warn_and_skip(connect, pki, provider, runlog):
    srv, client, gw = connect()
    c = by_id(run(client, gw, pki, provider, runlog, local_ip="192.0.2.10"))["client_path"]
    assert c.status == "warn" and not c.blocking
    assert c.detail == ("192.0.2.10 is not on a network directly attached to HQ-GW; make sure its "
                        "traffic to the internet goes through HQ-GW")
    nat = [f for f in c.fix if "NAT" in f]
    assert nat and "Docker" in nat[0] and "192.0.2.10" in nat[0]
    assert "AIGUARD_LOCAL_IP" in nat[0] and "--local-ip" in nat[0] and "Network address" in nat[0]
    gw.interfaces = []
    c = by_id(run(client, gw, pki, provider, runlog))["client_path"]
    assert c.status == "skip"


def test_package_unresolved_is_blocking(connect, pki, provider, runlog):
    srv, client, gw = connect(gateways_=[lab_gateway(access_policy=None, threat_policy=None)],
                              packages=("Standard", "Lab"))
    c = by_id(run(client, gw, pki, provider, runlog))["package"]
    assert c.status == "fail" and c.blocking
    assert "--package" in c.fix[0]


# --------------------------------------------------------------------------- tls_path


def test_public_ca_means_not_inspected(connect, pki, runlog, tmp_path):
    public = make_test_pki(tmp_path, ca_cn="DigiCert Global G2", ca_org="DigiCert Inc")
    with FakeProviderServer(public) as prov:
        srv, client, gw = connect()
        report = run_preflight(client, gw, probe_hosts=HOSTS, log=runlog, timeout=5,
                               ca_file=public.ca_pem_path, local_ip="127.0.0.1",
                               probe_endpoints=endpoints(prov))
    t = by_id(report)["tls_path"]
    assert t.status == "fail" and t.blocking
    assert "DigiCert" in t.evidence["issuer"]
    assert "prompts would pass through unseen" in t.detail
    # HTTPS Inspection is on (https_gw passed): a stale Access policy, a bypass, or the source
    assert ("HTTPS Inspection is on for the gateway, but this traffic was not decrypted: the "
            "Access Control policy that carries the HTTPS Inspection settings may not be "
            "installed yet (see the last policy installation check), or a Bypass rule or "
            "category in the HTTPS Inspection policy matches api.openai.com, or the Inspect "
            "rule's source does not include this computer") in t.detail
    assert t.fix and any("127.0.0.1" in f for f in t.fix)
    # the promised fix is offered: as a CLI command and as a machine-readable action
    assert t.fixable == "https-rule" and report.fixable() == ["https-rule"]
    assert t.fix[0].startswith("aiguard fix https-inspection --add-rule")
    assert t.action["id"] == "https-rule" and t.action["options"] == {"add_rule": True}
    assert t.action["cli"] == "aiguard fix https-inspection --add-rule"


def test_public_ca_with_https_off_points_at_https_fix(connect, runlog, tmp_path):
    public = make_test_pki(tmp_path, ca_cn="DigiCert Global G2", ca_org="DigiCert Inc")
    with FakeProviderServer(public) as prov:
        srv, client, gw = connect(scenario="https_off")
        report = run_preflight(client, gw, probe_hosts=HOSTS, log=runlog, timeout=5,
                               ca_file=public.ca_pem_path, local_ip="127.0.0.1",
                               probe_endpoints=endpoints(prov))
    t = by_id(report)["tls_path"]
    assert t.status == "fail" and "bypassed" not in t.detail
    assert t.fix[0] == HTTPS_FIX_0


def test_untrusted_chain_warns_with_trust_fix(connect, pki, runlog, tmp_path):
    other = make_test_pki(tmp_path, ca_cn="Gateway Outbound CA", ca_org="Lab Gateway")
    with FakeProviderServer(other) as prov:
        srv, client, gw = connect()
        report = run_preflight(client, gw, probe_hosts=HOSTS, log=runlog, timeout=5,
                               ca_file=pki.ca_pem_path, local_ip="127.0.0.1",
                               probe_endpoints=endpoints(prov))
    t = by_id(report)["tls_path"]
    assert t.status == "warn" and not t.blocking
    assert ("Traffic is being inspected, but this computer does not trust the gateway's "
            "outbound CA. Apps will fail with certificate errors.") in t.detail
    assert t.fix == TRUST_CA_FIX
    assert "--outbound-ca" in TRUST_CA_FIX[1] and "--ca-file" not in " ".join(TRUST_CA_FIX)
    assert t.action and t.action["id"] == "outbound-ca" and t.fixable is None
    assert t.evidence.get("verify_message")
    assert report_ok_except_tls(report)


def report_ok_except_tls(report):
    return all(c.status == "pass" for c in report.checks if c.id != "tls_path")


def test_unreachable_host_is_blocking(connect, pki, provider, runlog):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    closed_port = s.getsockname()[1]
    s.close()
    srv, client, gw = connect()
    report = run(client, gw, pki, provider, runlog,
                 probe_endpoints={"api.openai.com": ("127.0.0.1", closed_port),
                                  "api.anthropic.com": "https://127.0.0.1:%d" % provider.port})
    t = by_id(report)["tls_path"]
    assert t.status == "fail" and t.blocking
    assert "Cannot reach api.openai.com:443 from this computer" in t.detail
    assert t.evidence["api.anthropic.com"].startswith("inspected by")
    assert t.evidence["api.openai.com"].startswith("cannot connect")
    assert t.fix


def test_bad_ca_file_does_not_crash(connect, pki, provider, runlog, tmp_path):
    srv, client, gw = connect()
    report = run(client, gw, pki, provider, runlog, ca_file=str(tmp_path / "missing.pem"))
    t = by_id(report)["tls_path"]
    assert t.status == "fail" and t.blocking and "CA file not found" in t.detail


# --------------------------------------------------------------------------- https mode


def test_learning_mode_is_blocking_and_fixable(connect, pki, provider, runlog):
    srv, client, gw = connect(scenario="https_learning")
    assert gw.https_deployment_mode == "learning"
    h = by_id(run(client, gw, pki, provider, runlog))["https_gw"]
    assert h.status == "fail" and h.blocking and h.fixable == "https-inspection"
    assert "Learning mode" in h.detail and "Full mode" in h.detail
    assert h.evidence["deployment_mode"] == "learning"
    assert h.fix[0].startswith("aiguard fix https-inspection") and "Full" in h.fix[1]
    assert h.action["id"] == "https-inspection"


def test_read_only_on_standby_says_connect_to_active(connect, pki, provider, runlog):
    srv, client, gw = connect(read_only=True)
    client.standby = True
    w = by_id(run(client, gw, pki, provider, runlog))["api_write"]
    assert w.status == "fail" and w.blocking
    assert "Standby" in w.fix[0] and "Active server" in w.fix[0]
    assert not any("without read-only" in f for f in w.fix)


# --------------------------------------------------------------------------- last install


PARTIAL_DETAIL_RE = re.compile(
    r"^Threat Prevention installed but Access Control did not\. The gateway is still enforcing "
    r"the Access Control policy installed on (\S+); rule changes made since then are not live\.$")


def test_last_install_partial_failure_is_reported(connect, pki, provider, runlog):
    srv, client, gw = connect(scenario="partial_install_failed")
    report = run(client, gw, pki, provider, runlog)
    li = by_id(report)["last_install"]
    assert li.status == "fail" and li.blocking is False
    assert li.title == "Last policy install on HQ-GW partly failed"
    m = PARTIAL_DETAIL_RE.match(li.detail)
    assert m, li.detail
    assert m.group(1) == li.evidence["access-policy-installation-date"]
    assert li.server_said == LAB_DATA_TYPES_ERROR      # the verification message, verbatim
    assert li.fix == ["Fix the rule named in the message (for unsupported Workforce AI data types "
                      "see sk116272)",
                      "Install policy again and check that Install Policy Details shows "
                      "Succeeded for both Access Control and Threat Prevention"]
    assert li.evidence["not-installed"] == "Access Control"
    assert report.ok is True and report.warnings == 1      # never blocking
    # show-tasks was asked exactly as documented (status all, last 48 hours, full, 50)
    q = srv.last_call("show-tasks")
    assert q["status"] == "all" and q["details-level"] == "full" and q["limit"] == 50
    since = datetime.datetime.strptime(q["from-date"], "%Y-%m-%dT%H:%M:%S").replace(
        tzinfo=datetime.timezone.utc)
    hours = (datetime.datetime.now(datetime.timezone.utc) - since).total_seconds() / 3600
    assert 47.9 < hours < 48.1
    # the gateway's installed-policy facts were read again (show-gateways-and-servers)
    assert srv.calls_for("show-gateways-and-servers")
    data = li.to_dict()
    assert data["server_said"] == LAB_DATA_TYPES_ERROR and data["title"] == li.title


def test_last_install_partially_succeeded_status(connect, pki, provider, runlog):
    srv, client, gw = connect(scenario="partial_install_failed")
    srv.task_history[-1]["status"] = "partially succeeded"
    srv.task_history[-1]["task-details"][0]["statusCode"] = "partially succeeded"
    li = by_id(run(client, gw, pki, provider, runlog))["last_install"]
    assert li.status == "fail" and not li.blocking and li.title.endswith("partly failed")
    assert li.evidence["failed-task-status"] == "partially succeeded"


def test_last_install_both_failed_and_later_success(connect, pki, provider, runlog):
    srv, client, gw = connect()
    pol = srv.state.policies["HQ-GW"]
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    srv.task_history.append(make_install_task("HQ-GW", status="failed", start=start,
                                              access_ok=False, threat_ok=False))
    li = by_id(run(client, gw, pki, provider, runlog))["last_install"]
    assert li.status == "fail" and not li.blocking
    assert li.title == "Last policy install on HQ-GW failed"
    assert "still enforcing the Access Control policy installed on" in li.detail
    assert "and the Threat Prevention policy installed on" in li.detail
    # both installed again after the failed task: pass
    later = start + datetime.timedelta(minutes=10)
    pol["access"]["at"] = later
    pol["threat"]["at"] = later
    li = by_id(run(client, gw, pki, provider, runlog))["last_install"]
    assert li.status == "pass" and "installed again afterwards" in li.detail


def test_last_install_ignores_other_gateways(connect, pki, provider, runlog):
    srv, client, gw = connect()
    srv.task_history.append(make_install_task("OTHER-GW", status="failed", access_ok=False))
    assert by_id(run(client, gw, pki, provider, runlog))["last_install"].status == "pass"


def test_last_install_skip_and_not_installed_warning(connect, pki, provider, runlog):
    srv, client, gw = connect()
    srv.task_history[:] = []
    li = by_id(run(client, gw, pki, provider, runlog))["last_install"]
    assert li.status == "skip" and "No policy installation on HQ-GW in the last 48 hours" in li.detail
    srv.commands.discard("show-tasks")
    client._commands = None
    li = by_id(run(client, gw, pki, provider, runlog))["last_install"]
    assert li.status == "skip" and "no show-tasks command" in li.detail
    srv.state.policies["HQ-GW"]["access"]["installed"] = False
    li = by_id(run(client, gw, pki, provider, runlog))["last_install"]
    assert li.status == "warn" and not li.blocking
    assert li.detail == "HQ-GW: no Access Control policy installed."
    assert li.title == "No Access Control policy installed on HQ-GW"


def test_partial_install_explains_traffic_that_is_not_decrypted(connect, runlog, tmp_path):
    public = make_test_pki(tmp_path, ca_cn="DigiCert Global G2", ca_org="DigiCert Inc")
    with FakeProviderServer(public) as prov:
        srv, client, gw = connect(scenario="partial_install_failed")
        report = run_preflight(client, gw, probe_hosts=HOSTS, log=runlog, timeout=5,
                               ca_file=public.ca_pem_path, local_ip="127.0.0.1",
                               probe_endpoints=endpoints(prov))
    t = by_id(report)["tls_path"]
    assert t.status == "fail"
    assert t.fix[0].startswith("The last Access Control policy installation on HQ-GW did not "
                               "succeed")
    assert "HTTPS Inspection changes are installed with the Access Control policy" in t.fix[0]


def test_check_result_and_report_to_dict_are_redacted():
    secret = "sk-" + secrets.token_hex(20)
    c = CheckResult(id="x", title="X", status="warn", blocking=False,
                    detail="key %s" % secret, evidence={"token": secret}, fix=[])
    r = PreflightReport(gateway="GW", checks=[c])
    text = repr(r.to_dict())
    assert secret not in text
    assert r.ok and r.warnings == 1 and r.passed == 0
