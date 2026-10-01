"""Shared fixtures for the ``aiguard`` core tests (tests/core).

Fixtures
--------
aiguard_home
    A fresh temporary directory, exported as ``AIGUARD_HOME`` for the test.
tls_pki (session)
    A throw-away CA generated at test time (EC P-256, cryptography package)
    plus server certificates signed by it. Attributes: ``ca_file``,
    ``cert_file``/``key_file`` (SAN: IP 127.0.0.1 + DNS localhost),
    ``noip_cert_file``/``noip_key_file`` (CN=127.0.0.1, SAN: DNS localhost only,
    like a management certificate without the IP SAN), ``ca_cert``, and
    ``issue(name, ips=(), dns=(), cn=None) -> IssuedCert`` for more.
https_server
    Factory: ``https_server(handler_cls, cert="default"|"noip"|IssuedCert)``
    starts a threaded HTTPS server on 127.0.0.1 (random port) and returns a
    namespace with ``host``, ``port``, ``url``, ``server``. Servers are stopped
    at teardown. ``handler_cls`` is an ``http.server.BaseHTTPRequestHandler``
    subclass (its request logging is silenced).

Secrets registered with ``aiguard.redact`` during a test are forgotten after it
(autouse), so tests do not mask each other's strings. No fixture touches the
network beyond 127.0.0.1 and no fixture relaxes certificate verification.
"""

from __future__ import annotations

import datetime as _dt
import http.server
import ssl
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable, List, Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# --------------------------------------------------------------------------- home + redaction


@pytest.fixture
def aiguard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Temporary AIGUARD_HOME for one test (the directory exists)."""
    home = tmp_path / "aiguard-home"
    home.mkdir()
    monkeypatch.setenv("AIGUARD_HOME", str(home))
    return home


@pytest.fixture(autouse=True)
def _isolate_redact_registry():
    from aiguard import redact

    snapshot = redact._registry_snapshot()
    yield
    redact._registry_restore(snapshot)


# --------------------------------------------------------------------------- test PKI


class IssuedCert(SimpleNamespace):
    """cert_file, key_file, sha256, sha1 (colon hex upper), cert (x509 object)."""


def _colon_hex(data: bytes) -> str:
    return ":".join("%02X" % b for b in data)


class TestPKI:
    __test__ = False  # not a test class

    def __init__(self, directory: Path) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        self._x509 = x509
        self._hashes = hashes
        self._serialization = serialization
        self._ec = ec
        self._NameOID = NameOID
        self.dir = directory
        now = _dt.datetime.now(_dt.timezone.utc)
        self._not_before = now - _dt.timedelta(days=1)
        self._not_after = now + _dt.timedelta(days=30)

        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AIGuard Test Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, "AIGuard Test Root CA"),
        ])
        ca_ski = x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key())
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self._not_before)
            .not_valid_after(self._not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(ca_ski, critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        self.ca_file = directory / "test-ca.pem"
        self.ca_file.write_bytes(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        default = self.issue("server", ips=("127.0.0.1",), dns=("localhost",), cn="localhost")
        self.cert_file, self.key_file = default.cert_file, default.key_file
        self.default = default
        noip = self.issue("server-noip", dns=("localhost",), cn="127.0.0.1")
        self.noip_cert_file, self.noip_key_file = noip.cert_file, noip.key_file
        self.noip = noip

    def issue(self, name: str, *, ips: Iterable[str] = (), dns: Iterable[str] = (),
              cn: Optional[str] = None) -> IssuedCert:
        import ipaddress

        x509, NameOID, hashes = self._x509, self._NameOID, self._hashes
        serialization, ec = self._serialization, self._ec
        key = ec.generate_private_key(ec.SECP256R1())
        alt: List[Any] = [x509.DNSName(d) for d in dns]
        alt += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AIGuard Test Lab"),
                x509.NameAttribute(NameOID.COMMON_NAME, cn or name),
            ]))
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self._not_before)
            .not_valid_after(self._not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.ca_key.public_key()), critical=False)
        )
        if alt:
            builder = builder.add_extension(x509.SubjectAlternativeName(alt), critical=False)
        cert = builder.sign(self.ca_key, hashes.SHA256())
        cert_file = self.dir / (name + ".pem")
        key_file = self.dir / (name + ".key")
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        key_file.chmod(0o600)
        return IssuedCert(
            cert_file=cert_file, key_file=key_file, cert=cert,
            sha256=_colon_hex(cert.fingerprint(hashes.SHA256())),
            sha1=_colon_hex(cert.fingerprint(hashes.SHA1())),
        )


@pytest.fixture(scope="session")
def tls_pki(tmp_path_factory: pytest.TempPathFactory) -> TestPKI:
    pytest.importorskip("cryptography")
    return TestPKI(tmp_path_factory.mktemp("pki"))


# --------------------------------------------------------------------------- HTTPS servers


class _QuietServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:  # noqa: D401
        # Handshake failures from clients that reject the certificate are expected.
        pass


class OkHandler(http.server.BaseHTTPRequestHandler):
    """Default handler: 200 ``ok`` for GET/POST."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    def _reply(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply


@pytest.fixture
def https_server(tls_pki: TestPKI):
    started: List[Any] = []

    def start(handler_cls: Any = OkHandler, *, cert: Any = "default") -> SimpleNamespace:
        if cert == "default":
            issued = tls_pki.default
        elif cert == "noip":
            issued = tls_pki.noip
        else:
            issued = cert
        if handler_cls is not OkHandler and "log_message" not in vars(handler_cls):
            handler_cls = type(handler_cls.__name__, (handler_cls,),
                               {"log_message": lambda self, *a, **k: None})
        server = _QuietServer(("127.0.0.1", 0), handler_cls)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.minimum_version = ssl.TLSVersion.TLSv1_2
        sctx.load_cert_chain(str(issued.cert_file), str(issued.key_file))
        server.socket = sctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                                  daemon=True)
        thread.start()
        started.append((server, thread))
        host, port = server.server_address[0], server.server_address[1]
        return SimpleNamespace(host=host, port=port, url="https://%s:%d" % (host, port),
                               server=server, cert=issued)

    yield start
    for server, thread in started:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
