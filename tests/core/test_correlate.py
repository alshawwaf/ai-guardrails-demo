"""Tests for aiguard.correlate (probe results <-> gateway logs via show-logs).

Logs are synthetic entries shaped like the official show-logs examples (fakes.make_log).
"""
from __future__ import annotations

import datetime as dt
import os
import secrets
import sys
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from fakes import FakeMgmtServer, make_log, make_test_pki  # noqa: E402

from aiguard.correlate import action_class, correlate, log_time  # noqa: E402
from aiguard.errors import MgmtApiError  # noqa: E402
from aiguard.mgmt import MgmtClient  # noqa: E402
from aiguard.runlog import RunLog  # noqa: E402

CLIENT_IP = "10.1.1.50"
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(minutes=10)


def result(rid, *, verdict="BLOCKED", host="api.openai.com", at=NOW, ms=800, remote_ip="",
           local_ip=CLIENT_IP, epoch=True):
    return SimpleNamespace(id=rid, verdict=verdict, host=host, sent_at=at.isoformat(), ms=ms,
                           remote_ip=remote_ip, local_ip=local_ip,
                           sent_epoch=at.timestamp() if epoch else 0.0, expect="block")


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return make_test_pki(tmp_path_factory.mktemp("corr-pki"))


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


def test_blocked_result_matches_prevent_log(connect, runlog):
    srv, client = connect()
    entry = srv.add_log(make_log(src=CLIENT_IP, time_=NOW + dt.timedelta(seconds=2)))
    srv.add_log(make_log(src=CLIENT_IP, host="api.anthropic.com", action="Accept",
                         product="Firewall", time_=NOW))
    out = correlate(client, [result("inj-override-openai-1")], client_ip=CLIENT_IP, log=runlog)
    m = out["inj-override-openai-1"]
    assert m is not None
    assert m["action"] == "Prevent" and m["blade"] == "AI Agent Security"
    assert m["protection"] == "Prompt Injection" and m["category"] == "Prompt Injection"
    assert m["rule"] == "AI Guard Demo" and m["profile"] == "AIGuard-Demo"
    assert m["layer"] == "Standard Threat Prevention"
    assert m["log_id"] == entry["id"] and m["time"] == entry["time"]
    assert m["blocking"] is True and m["detect"] is False and m["source"] == "gateway log"
    assert m["delta_s"] <= 2.0 and m["matched_on"] == "dst"
    # exactly one query, the documented shape
    assert srv.state.log_queries == [{"filter": "src:%s" % CLIENT_IP, "time-frame": "last-hour",
                                      "max-logs-per-request": 100, "type": "logs"}]
    recs = [r for r in runlog.tail(100, component="correlate") if r["msg"] == "gateway logs"]
    assert recs and recs[-1]["level"] == "INFO"
    assert recs[-1]["fields"]["products"] == ["AI Agent Security", "Firewall"]


def test_window_host_and_action_filters(connect, runlog):
    srv, client = connect()
    srv.add_log(make_log(src=CLIENT_IP, time_=NOW + dt.timedelta(seconds=600)))      # too late
    srv.add_log(make_log(src=CLIENT_IP, host="api.mistral.ai", time_=NOW))            # other host
    srv.add_log(make_log(src=CLIENT_IP, action="Accept", time_=NOW))                  # not a block
    srv.add_log(make_log(src=CLIENT_IP, action="Detect", time_=NOW))                  # not a block
    out = correlate(client, [result("r1")], client_ip=CLIENT_IP, window_s=180, log=runlog)
    assert out == {"r1": None}
    msgs = [r["msg"] for r in runlog.tail(100, component="correlate")]
    assert "no log for r1 inside the time window" in msgs


def test_allowed_result_prefers_detect_log(connect):
    srv, client = connect()
    srv.add_log(make_log(src=CLIENT_IP, action="Detect", time_=NOW + dt.timedelta(seconds=1)))
    out = correlate(client, [result("a1", verdict="ALLOWED")], client_ip=CLIENT_IP)
    assert out["a1"]["action"] == "Detect" and out["a1"]["detect"] is True
    assert out["a1"]["blocking"] is False


def test_unknown_result_gets_blocking_match_for_upgrade(connect):
    srv, client = connect()
    srv.add_log(make_log(src=CLIENT_IP, action="Drop", time_=NOW + dt.timedelta(seconds=30)))
    out = correlate(client, [result("u1", verdict="UNKNOWN", ms=30000)], client_ip=CLIENT_IP)
    assert out["u1"]["action"] == "Drop" and out["u1"]["blocking"] is True
    assert out["u1"]["delta_s"] == 0.0  # inside the request's own duration


def test_two_prompts_get_distinct_logs(connect):
    srv, client = connect()
    l1 = srv.add_log(make_log(src=CLIENT_IP, time_=NOW + dt.timedelta(seconds=1)))
    l2 = srv.add_log(make_log(src=CLIENT_IP, time_=NOW + dt.timedelta(seconds=11)))
    out = correlate(client, [result("p1", ms=100), result("p2", at=NOW + dt.timedelta(seconds=10), ms=100)],
                    client_ip=CLIENT_IP)
    assert out["p1"]["log_id"] == l1["id"] and out["p2"]["log_id"] == l2["id"]


def test_same_second_prompts_all_get_a_log(connect):
    """Greedy "closest pair first" would give L1 to the BLOCKED prompt and leave the
    timed-out one without a log; the matching moves the BLOCKED prompt to L2 instead."""
    srv, client = connect()
    l1 = srv.add_log(make_log(src=CLIENT_IP, time_=NOW))
    l2 = srv.add_log(make_log(src=CLIENT_IP, time_=NOW + dt.timedelta(seconds=1)))
    blocked = result("b-same", at=NOW, ms=0)
    unknown = result("u-same", verdict="UNKNOWN", at=NOW - dt.timedelta(milliseconds=600), ms=0)
    out = correlate(client, [blocked, unknown], client_ip=CLIENT_IP, window_s=1)
    assert out["u-same"] is not None and out["u-same"]["log_id"] == l1["id"]
    assert out["b-same"] is not None and out["b-same"]["log_id"] == l2["id"]


def test_free_log_is_taken_before_another_result_is_moved(connect):
    srv, client = connect()
    l1 = srv.add_log(make_log(src=CLIENT_IP, time_=NOW))
    srv.add_log(make_log(src=CLIENT_IP, time_=NOW + dt.timedelta(seconds=1)))
    l3 = srv.add_log(make_log(src=CLIENT_IP, time_=NOW - dt.timedelta(seconds=1)))
    first = result("first", at=NOW, ms=0)                                  # L1 0s, L2/L3 1s
    second = result("second", at=NOW - dt.timedelta(milliseconds=400), ms=0)  # L1 .4s, L3 .6s
    out = correlate(client, [first, second], client_ip=CLIENT_IP, window_s=1)
    assert out["first"]["log_id"] == l1["id"] and out["second"]["log_id"] == l3["id"]


def test_matches_by_ip_and_by_resource(connect):
    srv, client = connect()
    # dst is an IP (as in real logs); the probe knows the IP it connected to
    srv.add_log(make_log(src=CLIENT_IP, host="api.anthropic.com", time_=NOW, dst="203.0.113.7",
                         dst_attr=[], resource=""))
    # no dst at all, only the resource URL
    srv.add_log(make_log(src=CLIENT_IP, host="generativelanguage.googleapis.com",
                         time_=NOW + dt.timedelta(seconds=40), dst="", dst_attr=[],
                         resource="https://generativelanguage.googleapis.com/v1beta/models/x:generate"))
    res = [result("ip1", host="api.anthropic.com", remote_ip="203.0.113.7"),
           result("res1", host="generativelanguage.googleapis.com", at=NOW + dt.timedelta(seconds=40))]
    out = correlate(client, res, client_ip=CLIENT_IP)
    assert out["ip1"]["matched_on"] == "ip"
    assert out["res1"]["matched_on"] in ("dst", "resource")


def test_prefers_ai_blade_logs(connect):
    srv, client = connect()
    srv.add_log(make_log(src=CLIENT_IP, product="IPS", protection_name="Generic HTTP",
                         protection_type="IPS", time_=NOW + dt.timedelta(seconds=1)))
    ai = srv.add_log(make_log(src=CLIENT_IP, time_=NOW + dt.timedelta(seconds=5)))
    out = correlate(client, [result("b1", ms=100)], client_ip=CLIENT_IP)
    assert out["b1"]["log_id"] == ai["id"]


def test_robust_to_missing_and_odd_fields(connect):
    srv, client = connect()
    srv.add_log({"src": CLIENT_IP, "action": "Prevent"})                       # no dst / product
    srv.add_log({"src": CLIENT_IP, "dst": "api.openai.com"})                    # no action
    srv.add_log({"src": CLIENT_IP, "dst": "api.openai.com", "action": "Prevent", "time": "garbage"})
    srv.add_log({"src": CLIENT_IP, "dst": "api.openai.com", "action": "Prevent",
                 "time": None, "lastUpdateTime": str(int((NOW.timestamp() + 3) * 1000)),
                 "TP_match_table": "not-a-list", "dst_attr": [None, {"x": 1}]})
    weird = [result("w1"), SimpleNamespace(id="w2", verdict="BLOCKED"),
             {"id": "w3", "verdict": "BLOCKED", "host": "api.openai.com", "sent_at": "bad"}]
    out = correlate(client, weird, client_ip=CLIENT_IP)
    assert set(out) == {"w1", "w2", "w3"}
    assert out["w1"] is not None and out["w1"]["action"] == "Prevent"
    assert out["w1"]["blade"] is None and out["w1"]["rule"] is None
    assert out["w2"] is None and out["w3"] is None


def test_no_logs_and_empty_input(connect):
    srv, client = connect()
    assert correlate(client, [], client_ip=CLIENT_IP) == {}
    assert correlate(client, [result("n1")], client_ip=CLIENT_IP) == {"n1": None}


def test_client_ip_falls_back_to_result_local_ip(connect):
    srv, client = connect()
    srv.add_log(make_log(src=CLIENT_IP, time_=NOW))
    out = correlate(client, [result("f1")], client_ip="")
    assert out["f1"] is not None
    assert srv.state.log_queries[-1]["filter"] == "src:%s" % CLIENT_IP


def test_show_logs_rejected_is_a_warning_not_an_error(connect, runlog):
    srv, client = connect()
    assert client.has("show-logs")  # cached before the server loses the command
    srv.commands.discard("show-logs")
    out = correlate(client, [result("x1")], client_ip=CLIENT_IP, log=runlog)
    assert out == {"x1": None}
    assert any(r["level"] == "WARN" for r in runlog.tail(20, component="correlate"))


def test_no_show_logs_command(connect):
    srv, client = connect(scenario="old_version")
    srv.commands.discard("show-logs")
    client._commands = None
    assert correlate(client, [result("y1")], client_ip=CLIENT_IP) == {"y1": None}
    assert srv.state.log_queries == []


def test_auth_errors_are_raised(connect):
    srv, client = connect()
    srv.state.sessions.clear()
    with pytest.raises(MgmtApiError) as ei:
        correlate(client, [result("z1")], client_ip=CLIENT_IP)
    assert ei.value.code == "mgmt.session_expired"


def test_time_and_action_helpers():
    t = log_time({"time": "2020-03-29T13:47:49Z"})
    assert t == dt.datetime(2020, 3, 29, 13, 47, 49, tzinfo=dt.timezone.utc)
    assert log_time({"time": "2020-03-29T15:47:49+0200"}) == t
    assert log_time({"time": "2020-03-29T13:47:49.5Z"}).microsecond == 500000
    assert log_time({"lastUpdateTime": "1585489669000"}) == dt.datetime(
        2020, 3, 29, 13, 47, 49, tzinfo=dt.timezone.utc)
    assert log_time({"time": "garbage"}) is None and log_time({}) is None
    assert action_class("Prevent") == "block" and action_class("drop") == "block"
    assert action_class("Detect") == "detect" and action_class("Inform User") == "detect"
    assert action_class("Accept") is None and action_class(None) is None
    assert action_class("HTTPS Bypass") is None


def test_allowed_result_never_takes_a_leftover_prevent_log(connect):
    srv, client = connect()
    srv.add_log(make_log(src=CLIENT_IP, action="Prevent", time_=NOW - dt.timedelta(seconds=90)))
    srv.add_log(make_log(src=CLIENT_IP, action="Prevent", time_=NOW + dt.timedelta(seconds=1)))
    out = correlate(client, [result("inj"), result("benign", verdict="ALLOWED",
                                                   at=NOW + dt.timedelta(seconds=5))],
                    client_ip=CLIENT_IP)
    assert out["inj"] is not None and out["inj"]["action"] == "Prevent"
    assert out["benign"] is None          # a Prevent log is no proof for an allowed prompt
