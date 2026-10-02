"""Tests for aiguard.envdefaults: connection defaults a lab installer writes to .env.

Certificates come from the throw-away test CA (tests/core/fakes.py); the expected subject
and SHA-1 are computed by the ``cryptography`` package, the module under test uses the
standard library only.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from fakes import make_server_cert, make_test_pki  # noqa: E402

from aiguard import envdefaults as ed  # noqa: E402


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return make_test_pki(tmp_path_factory.mktemp("envdefaults-pki"))


def test_from_env_parses_every_variable():
    d = ed.from_env({
        "AIGUARD_MGMT_SERVER": " 192.0.2.10 ", "AIGUARD_MGMT_PORT": "4434",
        "AIGUARD_MGMT_SERVER_NAME": "'mgmt.lab.example'", "AIGUARD_MGMT_TYPE": "mds",
        "AIGUARD_MGMT_DOMAIN": '"Lab Domain"', "AIGUARD_MGMT_CA_FILE": "/app/instance/mgmt.pem",
        "AIGUARD_GATEWAY": "HQ-GW", "AIGUARD_MGMT_FINGERPRINT_SHA1": "ab" * 20,
    })
    assert (d.server, d.port, d.server_name, d.server_type, d.domain, d.ca_file, d.gateway) == (
        "192.0.2.10", 4434, "mgmt.lab.example", "MDS", "Lab Domain", "/app/instance/mgmt.pem",
        "HQ-GW")
    assert d.fingerprint_sha1 == ":".join(["AB"] * 20)
    assert d.problems == [] and d.any()
    assert d.applies_to("192.0.2.10") and not d.applies_to("192.0.2.11")
    assert set(d.to_dict()) == set(ed.Defaults.__slots__)


def test_from_env_empty_means_unset():
    d = ed.from_env({name: "  " for name in ed.VARIABLES})
    assert not d.any() and d.problems == []
    assert d.applies_to("anything")          # no server configured: nothing to compare
    assert not ed.from_env({}).any()


def test_from_env_ignores_invalid_values_and_says_why():
    d = ed.from_env({
        "AIGUARD_MGMT_SERVER": "10.1.1.1; rm -rf /", "AIGUARD_MGMT_PORT": "70000",
        "AIGUARD_MGMT_SERVER_NAME": "bad name", "AIGUARD_MGMT_TYPE": "cloud",
        "AIGUARD_MGMT_DOMAIN": "System Data", "AIGUARD_GATEWAY": "GW\x07",
        "AIGUARD_MGMT_FINGERPRINT_SHA1": "not-a-fingerprint",
    })
    assert not d.any()
    text = "\n".join(d.problems)
    for name in ("AIGUARD_MGMT_SERVER", "AIGUARD_MGMT_PORT", "AIGUARD_MGMT_SERVER_NAME",
                 "AIGUARD_MGMT_TYPE", "AIGUARD_GATEWAY", "AIGUARD_MGMT_FINGERPRINT_SHA1"):
        assert name in text, name
    assert "rm -rf" not in text and "cloud" not in text      # never echoes the value
    assert len(d.problems) == 6                               # System Data is no domain


def test_normalize_sha1():
    fp = ":".join(["0A"] * 20)
    assert ed.normalize_sha1("0a" * 20) == fp
    assert ed.normalize_sha1(fp.lower()) == fp
    assert ed.normalize_sha1(" ".join(["0a"] * 20)) == fp
    assert ed.normalize_sha1("0a" * 19) is None and ed.normalize_sha1("") is None


def test_inspect_ca_file_reads_subject_and_sha1(pki, tmp_path):
    info = ed.inspect_ca_file(pki.ca_pem_path)
    assert info["sha1"] == pki.ca_sha1 and info["subject_cn"] == pki.ca_cn
    assert info["name"] == "ca.pem" and info["count"] == 1
    assert info["path"] == str(Path(pki.ca_pem_path))
    # a portal certificate (leaf) works too, and a bundle reports its first certificate
    leaf = make_server_cert(pki, san_ip=False, cn="mgmt.lab.example")
    bundle = tmp_path / "bundle.pem"
    bundle.write_text("comment line\n" + Path(leaf.server_cert_path).read_text(encoding="ascii")
                      + pki.ca_pem, encoding="ascii")
    info = ed.inspect_ca_file(bundle)
    assert info["subject_cn"] == "mgmt.lab.example" and info["sha1"] == leaf.server_sha1
    assert info["count"] == 2


def test_inspect_ca_file_refuses_what_it_cannot_use(pki, tmp_path):
    pem = Path(pki.ca_pem_path).read_text(encoding="ascii")
    cases = []
    keyed = tmp_path / "keyed.pem"
    keyed.write_text(pem + "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
                     encoding="ascii")
    cases.append((keyed, "private key"))
    cases.append((tmp_path / "missing.pem", "does not exist"))
    cases.append((tmp_path, "is not a file"))
    text = tmp_path / "text.pem"
    text.write_text("hello\n", encoding="ascii")
    cases.append((text, "has no certificate"))
    broken = tmp_path / "broken.pem"
    broken.write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
                      encoding="ascii")
    cases.append((broken, "not a readable PEM certificate"))
    big = tmp_path / "big.pem"
    big.write_text(pem + "x" * (64 * 1024), encoding="ascii")
    cases.append((big, "larger than 64 KB"))
    for path, needle in cases:
        with pytest.raises(ed.CaFileError) as ei:
            ed.inspect_ca_file(path)
        message = str(ei.value)
        assert needle in message, (path, message)
        assert str(tmp_path) not in message                 # the file name only
        assert "AAAA" not in message


def test_inspect_ca_file_sees_a_replaced_file(pki, tmp_path):
    path = tmp_path / "mgmt.pem"
    path.write_text(pki.ca_pem, encoding="ascii")
    assert ed.inspect_ca_file(path)["subject_cn"] == pki.ca_cn
    leaf = make_server_cert(pki, cn="replaced.lab.example")
    path.write_text(Path(leaf.server_cert_path).read_text(encoding="ascii") + "\n\n",
                    encoding="ascii")
    assert ed.inspect_ca_file(path)["subject_cn"] == "replaced.lab.example"


def test_subject_cn_is_defensive():
    assert ed.subject_cn(b"") is None
    assert ed.subject_cn(b"\x30\x03\x02\x01\x01") is None
    assert ed.subject_cn(b"\x30\x84\xff\xff\xff\xff") is None
    for _ in range(50):
        ed.subject_cn(os.urandom(64))                       # never raises
