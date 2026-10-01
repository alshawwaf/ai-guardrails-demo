"""Tests for aiguard.gateways (discover / detail / GatewayInfo).

The fake management server is reached over verified TLS with the generated test CA.
"""
from __future__ import annotations

import json
import os
import secrets
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from fakes import FakeMgmtServer, make_cluster, make_gateway, make_test_pki  # noqa: E402

from aiguard import gateways  # noqa: E402
from aiguard.errors import MgmtApiError  # noqa: E402
from aiguard.gateways import (BLADE_KEYS, GatewayInfo, detail, discover,  # noqa: E402
                              normalize_release, version_tuple)
from aiguard.mgmt import MgmtClient  # noqa: E402
from aiguard.runlog import RunLog  # noqa: E402


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return make_test_pki(tmp_path_factory.mktemp("gw-pki"))


@pytest.fixture
def runlog(aiguard_home):
    log = RunLog(home=aiguard_home)
    yield log
    log.close()


@pytest.fixture
def connect(pki, runlog):
    servers = []

    def start(**kw):
        srv = FakeMgmtServer(pki, **kw).start()
        servers.append(srv)
        client = MgmtClient("127.0.0.1", srv.port, ca_file=pki.ca_pem_path, timeout=5, log=runlog)
        client.login(api_key="fake-" + secrets.token_hex(12))
        return srv, client

    yield start
    for s in servers:
        assert s.errors == [], s.errors[0]
        s.stop()


def test_discover_default_gateway(connect):
    srv, client = connect()
    gws = discover(client)
    assert [g.name for g in gws] == ["HQ-GW"]  # the SMS itself is left out
    gw = gws[0]
    assert gw.type == "simple-gateway" and not gw.is_cluster
    assert gw.ipv4 == "10.1.1.111" and gw.version == "R82.20" and gw.release == "R82.20"
    assert gw.policy_package == "Standard" and gw.threat_policy == "Standard"
    assert gw.access_policy == "Standard" and gw.threat_policy_installed is True
    assert gw.interfaces == [("10.1.1.111", 24), ("198.51.100.111", 24)]
    assert gw.uid == srv.gateway("HQ-GW")["uid"]
    assert set(BLADE_KEYS) <= set(gw.blades)
    assert gw.blade("ips") is True and gw.blade("anti-bot") is True
    assert gw.blade("threat_emulation") is False  # listed blades: absent = off
    assert gw.blade("https_inspection") is None   # not in this listing: unknown
    assert gw.blade("ai_security") is None        # R82.20: decided by the threat profile
    assert gw.https_inspection is None and gw.threat_prevention_mode is None
    assert gw.raw["name"] == "HQ-GW" and not gw.detailed
    assert gw.script_targets() == ["HQ-GW"]


def test_discover_cluster_excludes_members(connect):
    srv, client = connect(with_cluster=True)
    gws = discover(client)
    assert [g.name for g in gws] == ["HQ-GW", "LAB-CL"]
    cl = gws[1]
    assert cl.is_cluster and cl.type == "CpmiGatewayCluster"
    assert cl.cluster_members == ["LAB-CL-m1", "LAB-CL-m2"]
    assert cl.script_targets() == ["LAB-CL-m1", "LAB-CL-m2"]
    assert cl.interfaces == [("10.2.2.100", 24), ("203.0.113.100", 24)]


def test_detail_gateway(connect):
    srv, client = connect()
    gw = discover(client)[0]
    full = detail(client, gw)
    assert full is not gw and gw.threat_prevention_mode is None  # input untouched
    assert full.detailed and full.detail_error is None
    assert full.threat_prevention_mode == "custom"
    assert full.https_inspection is True and full.blade("https_inspection") is True
    assert full.workforce_ai is True and full.blade("workforce_ai") is True
    assert full.blade("ips") is True and full.blade("threat_emulation") is False
    assert full.interfaces == [("10.1.1.111", 24), ("198.51.100.111", 24)]
    assert full.raw_detail["name"] == "HQ-GW"
    assert srv.last_call("show-simple-gateway") == {"name": "HQ-GW", "details-level": "full"}


def test_detail_cluster_reads_paged_interfaces(connect):
    srv, client = connect(with_cluster=True)
    cl = [g for g in discover(client) if g.is_cluster][0]
    full = detail(client, cl)
    assert srv.last_call("show-simple-cluster") == {"name": "LAB-CL", "details-level": "full",
                                                    "limit-interfaces": 500}
    assert full.interfaces == [("10.2.2.100", 24), ("203.0.113.100", 24)]
    assert full.cluster_members == ["LAB-CL-m1", "LAB-CL-m2"]
    assert full.https_inspection is True


def test_older_gateway_and_missing_fields(connect):
    gws = [make_gateway("EDGE-1", "192.0.2.10", version="R81.20", blades={"ips": False},
                        threat_prevention_mode=None, https_inspection=None, workforce_ai=None)]
    srv, client = connect(gateways=gws)
    gw = discover(client)[0]
    assert gw.release == "R81.20" and gw.version_tuple() == (81, 20)
    assert gw.blade("ai_security") is False  # an R81.20 gateway cannot run AI Agent Security
    full = detail(client, gw)
    assert full.threat_prevention_mode is None
    assert full.https_inspection is None and full.blade("https_inspection") is None
    assert full.workforce_ai is None
    assert full.blade("ips") is False


def test_scenarios_autonomous_https_off(connect):
    srv, client = connect(scenario="autonomous https_off")
    full = detail(client, discover(client)[0])
    assert full.threat_prevention_mode == "autonomous"
    assert full.https_inspection is False and full.blade("https_inspection") is False


def test_old_api_has_no_workforce_ai(connect):
    srv, client = connect(scenario="old_version")
    full = detail(client, discover(client)[0])
    assert full.workforce_ai is None and full.blade("workforce_ai") is None


def test_interfaces_with_network_mask_only(connect):
    srv, client = connect()
    for iface in srv.gateway("HQ-GW")["interfaces"]:
        iface.pop("ipv4-mask-length", None)
        iface["ipv4-network-mask"] = "255.255.0.0"
    full = detail(client, discover(client)[0])
    assert full.interfaces == [("10.1.1.111", 16), ("198.51.100.111", 16)]
    assert full.contains_ip("10.1.200.7") is True and full.contains_ip("192.0.2.1") is False


def test_mds_system_data_has_no_gateways(connect):
    srv, client = connect(server_type="MDS")
    assert client.domain == "System Data"
    assert discover(client) == []
    client.switch_domain("Lab")
    assert [g.name for g in discover(client)] == ["HQ-GW"]


def test_detail_of_unreadable_object_keeps_listing(connect):
    srv, client = connect()
    ghost = GatewayInfo(name="Ghost-GW", uid="u-1", type="CpmiGatewayPlain", ipv4="192.0.2.99",
                        version="R82.20")
    out = detail(client, ghost)
    assert out.detail_error and "Ghost-GW" in out.detail_error
    assert not out.detailed and out.ipv4 == "192.0.2.99"


def test_detail_raises_on_session_errors(connect):
    srv, client = connect()
    gw = discover(client)[0]
    srv.state.sessions.clear()
    with pytest.raises(MgmtApiError) as ei:
        detail(client, gw)
    assert ei.value.code == "mgmt.session_expired"


def test_listing_blades_unknown_when_empty():
    gw = gateways._from_listing({"name": "X", "uid": "1", "type": "simple-gateway",
                                 "network-security-blades": {}, "policy": {}})
    assert all(gw.blade(k) is None for k in BLADE_KEYS)
    assert gw.policy_package is None and gw.interfaces == []
    gw = gateways._from_listing({"name": "Y", "type": "simple-gateway", "version": "R80.40",
                                 "network-security-blades": {"firewall": True},
                                 "policy": {"access-policy-name": "Net"},
                                 "interfaces": [{"ipv4-address": "10.0.0.1", "ipv4-mask-length": "24"},
                                                {"ipv4-address": "", "ipv4-mask-length": 24},
                                                {"ipv4-address": "bad", "ipv4-mask-length": 24},
                                                {"ipv4-address": "10.0.1.1"}]})
    assert gw.blade("firewall") is True and gw.blade("ips") is False
    assert gw.blade("ai_security") is False
    assert gw.policy_package == "Net" and gw.interfaces == [("10.0.0.1", 24)]


def test_version_helpers():
    assert version_tuple("R82.20") == (82, 20)
    assert version_tuple("R82") == (82, 0)
    assert version_tuple("R81.20") == (81, 20)
    assert version_tuple("r80.40") == (80, 40)
    assert version_tuple("R82.20 JHF Take 12") == (82, 20)
    assert version_tuple("Gaia R82.10") == (82, 10)
    assert version_tuple("82.20") == (82, 20)
    assert version_tuple(None) is None and version_tuple("") is None
    assert version_tuple("unknown") is None
    assert version_tuple("R82.20") >= gateways.AI_SECURITY_MIN_VERSION > version_tuple("R82.10")
    assert normalize_release("r82.20") == "R82.20" and normalize_release("R82") == "R82"
    assert normalize_release(None) is None


def test_gatewayinfo_construction_and_to_dict():
    gw = GatewayInfo("GW", "uid-1", "simple-gateway", "10.0.0.1", "R82.20", "Standard",
                     {"ips": True, "anti-bot": False}, [("10.0.0.1", 24)], False, {})
    assert gw.blade("ips") is True and gw.blade("anti_bot") is False
    assert gw.blade("url_filtering") is None and gw.release == "R82.20"
    assert gw.contains_ip("10.0.0.77") is True and gw.contains_ip("not-an-ip") is None
    assert GatewayInfo(name="N").contains_ip("10.0.0.1") is None
    d = gw.to_dict()
    assert "raw" not in d and d["interfaces"] == [["10.0.0.1", 24]]
    json.dumps(d)
    assert d["blades"]["ips"] is True and d["blades"]["https_inspection"] is None
    gw.https_inspection = True
    assert gw.blade("https") is True


def test_listing_exposes_installed_policy_facts(connect):
    import datetime as _dt
    srv, client = connect()
    gw = discover(client)[0]
    assert gw.access_policy_name == "Standard" and gw.threat_policy_name == "Standard"
    assert gw.access_policy_installed is True and gw.threat_policy_installed is True
    assert gw.access_policy_installation_date and gw.threat_policy_installation_date
    assert isinstance(gw.access_policy_installed_at, int)
    assert gw.access_policy_revision and gw.threat_policy_revision
    pol = gw.policy_dict()
    assert set(pol) == {"access-policy-name", "access-policy-installed",
                        "access-policy-installation-date", "access-policy-revision",
                        "threat-policy-name", "threat-policy-installed",
                        "threat-policy-installation-date", "threat-policy-revision"}
    srv.state.policies["HQ-GW"]["threat"]["at"] = _dt.datetime.now(_dt.timezone.utc)
    fresh = gateways.policy_state(client, "hq-gw")
    gw.apply_policy(fresh)
    assert gw.threat_policy_installed_at > gw.access_policy_installed_at
    assert gw.to_dict()["access_policy_installation_date"] == gw.access_policy_installation_date


def test_cluster_with_many_interfaces_is_read_in_full(connect):
    from fakes import make_cluster
    ifaces = [("eth%d" % i, "10.20.%d.1" % i, 24) for i in range(80)]
    cl = make_cluster("BIG-CL", "10.20.0.1", [("BIG-m1", "10.20.0.2")], interfaces=ifaces)
    srv, client = connect(gateways=[cl])
    full = detail(client, [g for g in discover(client) if g.is_cluster][0])
    assert len(full.interfaces) == 80 and full.interfaces_total == 80
    assert full.contains_ip("10.20.71.9") is True        # a VLAN after the 50th interface


def test_https_deployment_mode_is_read(connect):
    srv, client = connect(scenario="https_learning")
    gw = detail(client, discover(client)[0])
    assert gw.https_inspection is True and gw.https_deployment_mode == "learning"
