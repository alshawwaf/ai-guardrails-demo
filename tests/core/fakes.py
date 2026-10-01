"""In-process fake servers for the AI Guard Demo Kit tests.

Stdlib plus ``cryptography`` (certificates only). Nothing here imports ``aiguard``.

What is in here
---------------
* ``make_test_pki(tmpdir)`` / ``make_server_cert(pki, san_ip=False)``: a throw-away CA
  ("AI Guard Test Outbound CA", O "AI Guard Test") and server certificates for 127.0.0.1 /
  localhost. Every key is generated at run time. Clients trust the CA by loading
  ``pki.ca_pem_path`` (verification stays ON; nothing here disables TLS checks).
* ``FakeMgmtServer``: a Check Point Management API (``POST /web_api/<command>``) with the
  reply shapes of the official v2.2 schema, a small object database, tasks that progress
  over a few ``show-task`` polls, and failure scenarios (see ``FakeMgmtServer.SCENARIOS``).
* ``FakeProviderServer``: an HTTPS endpoint that behaves like an LLM API or like a gateway
  blocking it (UserCheck page, redirect, reset, stall ...).
* ``FakeLakeraServer``: Lakera Guard ``/v2/guard`` and ``/v2/policies/health``.

All servers bind 127.0.0.1 on an ephemeral port, run in a daemon thread, and are usable
as context managers::

    pki = make_test_pki(tmp_path)
    with FakeMgmtServer(pki, scenario="install_fails") as srv:
        ...  # srv.port, srv.base_url, srv.calls, srv.state

Credentials: ``FakeMgmtServer`` accepts any non-empty api-key or user/password unless
``srv.valid_api_key`` / ``srv.valid_user`` / ``srv.valid_password`` are set.
``FakeLakeraServer.valid_key`` is generated at start-up (64 hex characters).
"""
from __future__ import annotations

import base64
import copy
import datetime
import http.server
import ipaddress
import json
import os
import re
import secrets
import select
import socket
import socketserver
import ssl
import struct
import tempfile
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

__all__ = [
    "DEFAULT_CA_CN",
    "DEFAULT_CA_ORG",
    "OLD_API_VERSION",
    "FakePKI",
    "make_test_pki",
    "make_server_cert",
    "client_context",
    "FakeMgmtServer",
    "make_gateway",
    "make_cluster",
    "make_log",
    "make_install_task",
    "LAB_DATA_TYPES_ERROR",
    "FakeProviderServer",
    "PROVIDER_BEHAVIORS",
    "USERCHECK_REDIRECT",
    "GATEWAY_LIKE_RULES",
    "FakeLakeraServer",
    "DEFAULT_LAKERA_RULES",
    "DEFAULT_LAKERA_DETECTORS",
    "Headers",
    "AttrDict",
]

DEFAULT_CA_CN = "AI Guard Test Outbound CA"
DEFAULT_CA_ORG = "AI Guard Test"


# ===========================================================================
# Small helpers
# ===========================================================================

class AttrDict(dict):
    """dict that also allows attribute access (``state.published`` == ``state["published"]``)."""

    def __getattr__(self, key: str) -> Any:
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key) from None

    def __setattr__(self, key: str, value: Any) -> None:
        self[key] = value


class Headers(dict):
    """Request headers as sent, with case-insensitive lookups."""

    def _find(self, key: Any) -> Optional[str]:
        if not isinstance(key, str):
            return None
        if dict.__contains__(self, key):
            return key
        low = key.lower()
        for k in dict.keys(self):
            if k.lower() == low:
                return k
        return None

    def __getitem__(self, key: Any) -> Any:
        k = self._find(key)
        if k is None:
            raise KeyError(key)
        return dict.__getitem__(self, k)

    def get(self, key: Any, default: Any = None) -> Any:
        k = self._find(key)
        return default if k is None else dict.__getitem__(self, k)

    def __contains__(self, key: Any) -> bool:
        return self._find(key) is not None


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _iso_z(ts: Optional[datetime.datetime] = None) -> str:
    return (ts or _now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def _api_date(ts: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    ts = ts or _now()
    return {"posix": int(ts.timestamp() * 1000), "iso-8601": ts.strftime("%Y-%m-%dT%H:%M%z")}


def _vt(version: Any) -> Tuple[int, int, int]:
    parts = [int(x) for x in re.findall(r"\d+", str(version))][:3]
    while len(parts) < 3:
        parts.append(0)
    return (parts[0], parts[1], parts[2])


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _uid() -> str:
    return str(uuid.uuid4())


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _fp(der: bytes, algo: Any) -> str:
    h = hashes.Hash(algo)
    h.update(der)
    return h.finalize().hex(":").upper()


def _same(a: Any, b: Any) -> bool:
    """Constant-time comparison that also accepts non-ASCII text."""
    return secrets.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


def _collect_strings(obj: Any, skip_keys: Sequence[str] = ("model", "role")) -> List[str]:
    out: List[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k in skip_keys:
                continue
            out.extend(_collect_strings(v, skip_keys))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_collect_strings(v, skip_keys))
    return out


# ===========================================================================
# PKI
# ===========================================================================

class FakePKI:
    """A test CA plus one server certificate, written as PEM files under ``directory``.

    Attributes: ``directory``, ``ca_cn``, ``ca_org``, ``ca_pem_path``, ``ca_pem`` (text),
    ``ca_der``, ``ca_cert``, ``ca_key`` (in memory only), ``ca_sha256``, ``ca_sha1``,
    ``server_cert_path``, ``server_key_path``, ``server_cert``, ``server_cn``,
    ``server_san`` (list of "DNS:x" / "IP:x"), ``server_sha256``, ``server_sha1``
    (fingerprints are upper-case hex with colons, like ``api fingerprint``).
    """

    def __init__(self, directory: Path, ca_cn: str, ca_org: str, ca_key: Any, ca_cert: x509.Certificate):
        self.directory = Path(directory)
        self.ca_cn = ca_cn
        self.ca_org = ca_org
        self.ca_key = ca_key
        self.ca_cert = ca_cert
        self.ca_der = ca_cert.public_bytes(serialization.Encoding.DER)
        self.ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        self.ca_sha256 = _fp(self.ca_der, hashes.SHA256())
        self.ca_sha1 = _fp(self.ca_der, hashes.SHA1())
        self.ca_pem_path = ""
        self.server_cert_path = ""
        self.server_key_path = ""
        self.server_cert: Optional[x509.Certificate] = None
        self.server_cn = ""
        self.server_san: List[str] = []
        self.server_sha256 = ""
        self.server_sha1 = ""

    @property
    def ca_issuer_dn(self) -> str:
        return "CN=%s,O=%s" % (self.ca_cn, self.ca_org)

    def __repr__(self) -> str:
        return "FakePKI(ca_cn=%r, server=%r, san=%r)" % (self.ca_cn, self.server_cn, self.server_san)


def make_test_pki(tmpdir: Union[str, Path], *, ca_cn: str = DEFAULT_CA_CN, ca_org: str = DEFAULT_CA_ORG,
                  days: int = 30) -> FakePKI:
    """Create a CA and a server certificate (SAN IP 127.0.0.1 + DNS localhost) in a fresh
    sub-directory of ``tmpdir``. Pass ``ca_org="DigiCert Inc"`` (for example) to imitate a
    public issuer when a test needs a "not inspected" certificate."""
    base = Path(tmpdir)
    base.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="pki-", dir=str(base)))
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ca_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_org),
    ])
    now = _now()
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=max(days, 2) * 12))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
        .sign(key, hashes.SHA256())
    )
    pki = FakePKI(directory, ca_cn, ca_org, key, cert)
    ca_path = directory / "ca.pem"
    ca_path.write_text(pki.ca_pem, encoding="ascii")
    pki.ca_pem_path = str(ca_path)
    default = make_server_cert(pki, days=days, _tag="server")
    for attr in ("server_cert_path", "server_key_path", "server_cert", "server_cn", "server_san",
                 "server_sha256", "server_sha1"):
        setattr(pki, attr, getattr(default, attr))
    return pki


def make_server_cert(pki: FakePKI, *, san_ip: bool = True, san_dns: bool = True, ip: str = "127.0.0.1",
                     dns_names: Sequence[str] = ("localhost",), cn: Optional[str] = None, days: int = 30,
                     _tag: Optional[str] = None) -> FakePKI:
    """Issue another server certificate from ``pki``'s CA and return a copy of ``pki``
    whose ``server_cert_path`` / ``server_key_path`` point at it (pass it to any fake server).

    ``make_server_cert(pki, san_ip=False)`` -> SAN has DNS localhost only, so connecting to
    127.0.0.1 fails hostname verification while ``server_hostname="localhost"`` succeeds.
    ``make_server_cert(pki, san_ip=False, san_dns=False, cn="127.0.0.1")`` -> no SAN at all,
    like the default Gaia portal certificate (CN = management IP)."""
    key = ec.generate_private_key(ec.SECP256R1())
    sans: List[x509.GeneralName] = []
    san_text: List[str] = []
    if san_dns:
        for n in dns_names:
            sans.append(x509.DNSName(n))
            san_text.append("DNS:" + n)
    if san_ip and ip:
        sans.append(x509.IPAddress(ipaddress.ip_address(ip)))
        san_text.append("IP:" + ip)
    if cn is None:
        cn = dns_names[0] if (san_dns and dns_names) else ip
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, pki.ca_org),
    ])
    now = _now()
    ca_ski = pki.ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(pki.ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(pki.ca_key, hashes.SHA256())
    tag = _tag or "server-%s-%s" % ("ip" if san_ip else "noip", secrets.token_hex(4))
    cert_path = pki.directory / (tag + ".pem")
    key_path = pki.directory / (tag + ".key")
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_private(key_path, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    new = copy.copy(pki)
    new.server_cert_path = str(cert_path)
    new.server_key_path = str(key_path)
    new.server_cert = cert
    new.server_cn = cn
    new.server_san = san_text
    der = cert.public_bytes(serialization.Encoding.DER)
    new.server_sha256 = _fp(der, hashes.SHA256())
    new.server_sha1 = _fp(der, hashes.SHA1())
    return new


def client_context(pki_or_cafile: Union[FakePKI, str, None] = None) -> ssl.SSLContext:
    """Verifying client context (TLS 1.2+) that trusts the test CA. For tests only."""
    cafile = pki_or_cafile.ca_pem_path if isinstance(pki_or_cafile, FakePKI) else pki_or_cafile
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


# ===========================================================================
# Threaded HTTPS server plumbing
# ===========================================================================

class _Request(object):
    __slots__ = ("method", "path", "headers", "body", "client_ip")

    def __init__(self, method: str, path: str, headers: Headers, body: bytes, client_ip: str):
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body
        self.client_ip = client_ip

    def json(self) -> Any:
        if not self.body.strip():
            return {}
        return json.loads(self.body.decode("utf-8"))


class _Reply(object):
    def __init__(self, status: int = 200, body: bytes = b"", content_type: str = "application/json",
                 headers: Optional[List[Tuple[str, str]]] = None, action: Optional[str] = None,
                 close: bool = False, wait: float = 0.0):
        self.status = status
        self.body = body
        self.content_type = content_type
        self.headers = list(headers or [])
        self.action = action      # None | "reset" | "timeout"
        self.close = close
        self.wait = wait


def _json_reply(status: int, obj: Any, headers: Optional[List[Tuple[str, str]]] = None,
                close: bool = False) -> _Reply:
    return _Reply(status, json.dumps(obj).encode("utf-8"), "application/json", headers, close=close)


def _html_reply(status: int, html: str, headers: Optional[List[Tuple[str, str]]] = None,
                close: bool = False) -> _Reply:
    return _Reply(status, html.encode("utf-8"), "text/html; charset=utf-8", headers, close=close)


_MAX_BODY = 8 * 1024 * 1024


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return self.server.fake.server_header  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - keep test output quiet
        return

    def do_POST(self) -> None:
        self._serve()

    do_GET = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_POST

    def _read_body(self) -> bytes:
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            chunks = []
            total = 0
            while True:
                line = self.rfile.readline(65537)
                size = int(line.split(b";", 1)[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline(65537) not in (b"\r\n", b"\n", b""):
                        pass
                    break
                total += size
                if total > _MAX_BODY:
                    raise ValueError("body too large")
                chunks.append(self.rfile.read(size))
                self.rfile.readline(65537)
            return b"".join(chunks)
        length = int(self.headers.get("Content-Length") or 0)
        if length < 0 or length > _MAX_BODY:
            raise ValueError("bad Content-Length")
        return self.rfile.read(length) if length else b""

    def _serve(self) -> None:
        fake = self.server.fake  # type: ignore[attr-defined]
        try:
            body = self._read_body()
        except (ValueError, OSError):
            self.close_connection = True
            return
        headers = Headers(self.headers.items())
        req = _Request(self.command, self.path, headers, body, self.client_address[0])
        try:
            reply = fake._dispatch(req)
        except Exception:  # a bug in the fake itself: fail loudly but keep serving
            fake.errors.append(traceback.format_exc())
            reply = _json_reply(500, {"code": "fake_internal_error", "message": "fake server error (see server.errors)"})
        if reply.action == "reset":
            self._reset()
            return
        if reply.action == "timeout":
            self._stall(reply.wait)
            return
        self.send_response(reply.status)
        for k, v in reply.headers:
            self.send_header(k, v)
        self.send_header("Content-Type", reply.content_type)
        self.send_header("Content-Length", str(len(reply.body)))
        if reply.close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(reply.body)

    def _reset(self) -> None:
        """Abort the connection: SO_LINGER 0 makes the final close() send a TCP RST."""
        self.close_connection = True
        try:
            # struct linger is two ints on POSIX and two u_shorts on Windows
            linger = struct.pack("HH", 1, 0) if os.name == "nt" else struct.pack("ii", 1, 0)
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        except OSError:
            pass

    def _stall(self, cap: float) -> None:
        """Send nothing until the client hangs up, the server stops, or ``cap`` seconds pass."""
        fake = self.server.fake  # type: ignore[attr-defined]
        self.close_connection = True
        conn = self.connection
        deadline = time.monotonic() + max(0.0, cap)
        try:
            conn.setblocking(False)
        except OSError:
            return
        while not fake._stop.is_set() and time.monotonic() < deadline:
            try:
                readable, _, _ = select.select([conn], [], [], 0.05)
            except (OSError, ValueError):
                break
            if not readable:
                continue
            try:
                data = conn.recv(4096)
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
                continue
            except OSError:
                break
            if not data:
                break


class _TLSHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr: Tuple[str, int], ssl_ctx: ssl.SSLContext, fake: "_FakeServerBase"):
        self.ssl_ctx = ssl_ctx
        self.fake = fake
        http.server.HTTPServer.__init__(self, addr, _Handler)

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)

    def finish_request(self, request: Any, client_address: Any) -> None:
        # The TLS handshake runs here, in the per-connection thread, so a stuck client
        # never blocks the accept loop.
        request.settimeout(self.fake.io_timeout)
        try:
            conn = self.ssl_ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            self.fake.tls_errors.append("%s: %s" % (type(exc).__name__, exc))
            return
        try:
            _Handler(conn, client_address, self)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def handle_error(self, request: Any, client_address: Any) -> None:
        self.fake.errors.append(traceback.format_exc())


class _FakeServerBase(object):
    server_header = "FakeServer/1.0"

    def __init__(self, pki: FakePKI, *, host: str = "127.0.0.1"):
        if not getattr(pki, "server_cert_path", None):
            raise ValueError("pki has no server certificate; use make_test_pki()")
        self.pki = pki
        self.host = host
        self.lock = threading.RLock()
        self.errors: List[str] = []       # tracebacks raised inside the fake (should stay empty)
        self.tls_errors: List[str] = []   # failed server-side handshakes (client rejected us, etc.)
        self.io_timeout = 10.0
        self._stop = threading.Event()
        self._httpd: Optional[_TLSHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._port: Optional[int] = None

    def _ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.pki.server_cert_path, self.pki.server_key_path)
        return ctx

    def start(self):  # returns self
        if self._httpd is not None:
            return self
        self._stop.clear()
        self._httpd = _TLSHTTPServer((self.host, 0), self._ssl_context(), self)
        self._port = int(self._httpd.server_address[1])
        self._thread = threading.Thread(target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05},
                                        name=type(self).__name__, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        httpd, self._httpd = self._httpd, None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    close = stop

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    @property
    def port(self) -> Optional[int]:
        return self._port

    @property
    def base_url(self) -> str:
        return "https://%s:%s" % (self.host, self._port)

    def url(self, path: str = "/") -> str:
        return self.base_url + (path if path.startswith("/") else "/" + path)

    def _dispatch(self, req: _Request) -> _Reply:  # pragma: no cover - overridden
        raise NotImplementedError


# ===========================================================================
# Fake Check Point Management API
# ===========================================================================

class _ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, *, errors: Iterable[Any] = (),
                 warnings: Iterable[Any] = (), blocking: Iterable[Any] = ()):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.errors = list(errors)
        self.warnings = list(warnings)
        self.blocking = list(blocking)

    def body(self) -> Dict[str, Any]:
        def items(xs: List[Any]) -> List[Any]:
            return [{"message": x, "current-session": True} if isinstance(x, str) else x for x in xs]
        return {"code": self.code, "message": self.message, "errors": items(self.errors),
                "warnings": items(self.warnings), "blocking-errors": items(self.blocking)}

    def reply(self) -> _Reply:
        return _json_reply(self.status, self.body())


def _not_found(what: Any) -> _ApiError:
    return _ApiError(404, "generic_err_object_not_found", "Requested object [%s] not found" % (what,))


def _missing(param: str) -> _ApiError:
    return _ApiError(400, "generic_err_missing_required_parameters", "Missing parameter: [%s]" % param)


def _invalid(message: str) -> _ApiError:
    return _ApiError(400, "generic_err_invalid_parameter", message)


def _validation(*messages: str) -> _ApiError:
    n = len(messages)
    return _ApiError(400, "err_validation_failed",
                     "Validation failed with %d error%s" % (n, "" if n == 1 else "s"), errors=list(messages))


def _validation_warning(*messages: str) -> _ApiError:
    """Warnings only: the real server refuses the change unless ``ignore-warnings`` is true."""
    n = len(messages)
    return _ApiError(400, "err_validation_failed",
                     "Validation failed with %d warning%s" % (n, "" if n == 1 else "s"),
                     warnings=list(messages))


# The verification error from the 2026-09-30 lab (Access Control install of a Workforce AI rule).
LAB_DATA_TYPES_ERROR = (
    "Layer 'Network': Rule 2 (AI) - The following Data Types are not supported: 'PCI - Credit Card "
    "Numbers - 20 or more', 'PCI - Credit Card Numbers - 5 or more', 'Credit Card Numbers or IBAN' "
    "group, which includes the unsupported data type 'PCI - Credit Card Numbers - 5 or more'. Please "
    "remove them from the rule or refer to sk116272. Policy verification failed.")


def make_install_task(gateway: str = "HQ-GW", *, package: str = "Standard", status: str = "succeeded",
                      start: Optional[datetime.datetime] = None, access: bool = True,
                      threat_prevention: bool = True, access_ok: Optional[bool] = None,
                      threat_ok: Optional[bool] = None, error: str = LAB_DATA_TYPES_ERROR,
                      gateway_uid: str = "") -> Dict[str, Any]:
    """A finished policy installation task as show-tasks (details-level full) returns it, for
    ``FakeMgmtServer.task_history``. ``access_ok`` / ``threat_ok`` (default: the task status)
    decide the per-policy stage messages; the task-details shape is not in the official schema
    (parsed defensively by the client)."""
    start = start or (_now() - datetime.timedelta(hours=2))
    ok = status in ("succeeded", "succeeded with warnings")
    access_ok = ok if access_ok is None else access_ok
    threat_ok = ok if threat_ok is None else threat_ok
    stages = []
    if access:
        stages.append({"stage": "Access Control", "messages": (
            [{"type": "info", "message": "Access Control policy installed successfully"}] if access_ok
            else [{"type": "err", "message": error}])})
    if threat_prevention:
        stages.append({"stage": "Threat Prevention", "messages": (
            [{"type": "info", "message": "Threat Prevention policy installed successfully"}] if threat_ok
            else [{"type": "err", "message": error}])})
    gw_ok = (access_ok or not access) and (threat_ok or not threat_prevention)
    tid = _uid()
    return {"uid": tid, "type": "task", "task-id": tid, "task-name": "Policy installation - %s" % package,
            "status": status, "progress-percentage": 100,
            "progress-description": "Installing policy %s on %s" % (package, gateway),
            "suppressed": False, "start-time": _api_date(start),
            "last-update-time": _api_date(start + datetime.timedelta(seconds=40)),
            "comments": "" if ok else "Policy installation failed on %s" % gateway, "color": "black",
            "task-details": [{"gatewayName": gateway, "gatewayId": gateway_uid,
                              "statusCode": "succeeded" if gw_ok else "failed",
                              "statusDescription": "Policy installation %s on %s" % (
                                  "succeeded" if gw_ok else "failed", gateway),
                              "stagesInfo": stages}]}


def _apache_403(path: str) -> _Reply:
    html = (
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
        "<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\n"
        "<p>You don't have permission to access %s on this server.</p>\n</body></html>\n" % path
    )
    return _html_reply(403, html)


_MGMT_PATH = re.compile(r"^/web_api/(?:v(\d+(?:\.\d+)*)/)?([A-Za-z0-9][A-Za-z0-9\-]*)/?$")

_SUPPORTED_VERSIONS = ["1", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.6.1", "1.7", "1.7.1", "1.8",
                       "1.8.1", "1.9", "1.9.1", "2", "2.0.1", "2.1", "2.2"]
OLD_API_VERSION = "2"   # what an R82 management server reports ("old_version" scenario)

_AI_COMMANDS = frozenset({"test-ai-agent-security-api-key", "test-ai-guard-api-key"})
_MDS_ONLY = frozenset({"show-domains", "show-domain", "login-to-domain", "login-to-system-domain", "show-mdss",
                       "show-mds", "add-domain", "set-domain", "delete-domain", "clone-domain", "add-mds",
                       "set-mds", "delete-mds", "show-global-domain", "set-global-domain"})
_READONLY_ALLOWED = frozenset({"login", "logout", "keepalive", "discard", "login-to-domain"})

_PREDEFINED_PROFILES = ("Optimized", "Strict", "Basic")
_BUILTIN_REFS = {"any": "CpmiAnyObject", "policy targets": "Global", "all_internet": "CpmiAnyObject",
                 "internalzone": "security-zone", "externalzone": "security-zone", "dmzzone": "security-zone",
                 "wirelesszone": "security-zone"}
_BUILTIN_CANON = {"any": "Any", "policy targets": "Policy Targets", "all_internet": "All_Internet",
                  "internalzone": "InternalZone", "externalzone": "ExternalZone", "dmzzone": "DMZZone",
                  "wirelesszone": "WirelessZone"}
_THREAT_TRACKS = ("None", "Log", "Alert", "Mail", "SNMP trap", "User Alert 1", "User Alert 2", "User Alert 3")
_CONFIDENCE = ("Inactive", "Ask", "Prevent", "Detect")
_PERF_IMPACT = ("high", "medium", "low", "very_low")
_SEVERITY = ("Critical", "High", "Medium or above", "Low or above")
_HTTPS_BLADES = ("Anti Bot", "Anti Virus", "Application Control", "Data Awareness", "DLP", "IPS",
                 "Threat Emulation", "Url Filtering", "Zero Phishing", "Threat Extraction")
_HTTPS_ACTIONS = ("Inspect", "Bypass")
_TIME_FRAMES = ("last-7-days", "last-hour", "today", "last-24-hours", "yesterday", "this-week", "this-month",
                "last-30-days", "all-time", "custom")
_DETAILS_LEVELS = ("uid", "standard", "full")

_API_BLADES = ("firewall", "application-control", "url-filtering", "content-awareness", "ips", "anti-bot",
               "anti-virus", "threat-emulation", "threat-extraction", "zero-phishing", "identity-awareness",
               "data-loss-prevention", "vpn", "qos", "mobile-access", "anti-spam-and-email-security",
               "icap-server", "legacy-url-filtering", "monitoring")
_DEFAULT_BLADES = {b: False for b in _API_BLADES}
_DEFAULT_BLADES.update({"firewall": True, "application-control": True, "url-filtering": True,
                        "content-awareness": True, "ips": True, "anti-bot": True, "anti-virus": True})
# show-gateways-and-servers "network-security-blades" key for each show-simple-gateway blade
_LISTING_BLADE = {"firewall": "firewall", "application-control": "application-control",
                  "url-filtering": "url-filtering", "content-awareness": "content-awareness", "ips": "ips",
                  "anti-bot": "anti-bot", "anti-virus": "anti-virus", "threat-emulation": "threat-emulation",
                  "threat-extraction": "threat-extraction", "zero-phishing": "zero-phishing",
                  "identity-awareness": "identity-awareness", "data-loss-prevention": "data-loss-prevention",
                  "vpn": "site-to-site-vpn", "qos": "qos", "mobile-access": "mobile-access",
                  "anti-spam-and-email-security": "anti-spam", "monitoring": "monitoring"}

_LOG_FILTER_FIELDS = {"blade": ("product",), "product": ("product",), "src": ("src",), "source": ("src",),
                      "dst": ("dst",), "destination": ("dst",), "action": ("action",), "service": ("service",),
                      "origin": ("orig",), "orig": ("orig",), "rule": ("rule_name", "rule"),
                      "protection": ("protection_name",), "severity": ("severity",), "type": ("type",)}


def _norm_scenarios(scenario: Union[None, str, Iterable[str]]) -> Set[str]:
    if scenario is None:
        return set()
    if isinstance(scenario, str):
        return {s.strip() for s in re.split(r"[,\s]+", scenario) if s.strip()}
    return {str(s) for s in scenario}


def _mask_str(length: int) -> str:
    return str(ipaddress.IPv4Network("0.0.0.0/%d" % int(length)).netmask)


def _norm_ifaces(interfaces: Iterable[Any]) -> List[Tuple[str, str, int, str]]:
    """Accept ("ip", mask), ("eth0", "ip", mask[, topology]) or "ip/mask" and return
    (name, ip, mask, topology) tuples. The first interface is internal, others external."""
    out: List[Tuple[str, str, int, str]] = []
    for i, item in enumerate(interfaces):
        topo = "internal" if i == 0 else "external"
        if isinstance(item, str):
            ip, _, mask = item.partition("/")
            name, mask_i = "eth%d" % i, int(mask or 24)
        elif len(item) == 2:
            name, ip, mask_i = "eth%d" % i, item[0], int(item[1])
        else:
            name, ip, mask_i = item[0], item[1], int(item[2])
            if len(item) > 3:
                topo = item[3]
        out.append((str(name), str(ip), mask_i, topo))
    return out


def make_gateway(name: str, ipv4: str, *, version: str = "R82.20", interfaces: Optional[Iterable[Any]] = None,
                 blades: Optional[Dict[str, bool]] = None, access_policy: Optional[str] = "Standard",
                 threat_policy: Optional[str] = "Standard", threat_prevention_mode: Optional[str] = "custom",
                 https_inspection: Optional[bool] = True, workforce_ai: Optional[bool] = True,
                 sic_state: str = "communicating", **extra: Any) -> Dict[str, Any]:
    """Describe a simple gateway for ``FakeMgmtServer(gateways=[...])``.

    ``blades`` uses show-simple-gateway key names (firewall, application-control, ips, ...).
    ``None`` for ``threat_prevention_mode`` / ``https_inspection`` / ``workforce_ai`` leaves that
    field out of show-simple-gateway. ``extra`` keys are merged into the show-simple-gateway reply."""
    b = dict(_DEFAULT_BLADES)
    b.update(blades or {})
    return {"_fake_spec": "gateway", "name": name, "ipv4": ipv4, "version": version,
            "interfaces": _norm_ifaces(interfaces if interfaces is not None else [(ipv4, 24)]),
            "blades": b, "access_policy": access_policy, "threat_policy": threat_policy,
            "tp_mode": threat_prevention_mode, "https": https_inspection, "workforce_ai": workforce_ai,
            "sic_state": sic_state, "members": [], "extra": dict(extra)}


def make_cluster(name: str, ipv4: str, members: Iterable[Tuple[str, str]], **kwargs: Any) -> Dict[str, Any]:
    """Describe a simple cluster (listed as CpmiGatewayCluster, members as CpmiClusterMember)."""
    spec = make_gateway(name, ipv4, **kwargs)
    spec["_fake_spec"] = "cluster"
    spec["members"] = [(str(m[0]), str(m[1])) for m in members]
    return spec


def _default_gateways() -> List[Dict[str, Any]]:
    return [make_gateway("HQ-GW", "10.1.1.111",
                         interfaces=[("eth0", "10.1.1.111", 24), ("eth1", "198.51.100.111", 24)])]


def _default_cluster() -> Dict[str, Any]:
    return make_cluster("LAB-CL", "10.2.2.100", [("LAB-CL-m1", "10.2.2.101"), ("LAB-CL-m2", "10.2.2.102")],
                        interfaces=[("eth0", "10.2.2.100", 24), ("eth1", "203.0.113.100", 24)])


def make_log(*, src: str = "10.1.1.50", host: str = "api.openai.com", action: str = "Prevent",
             product: str = "AI Agent Security", protection_name: str = "Prompt Injection",
             time_: Optional[Union[str, datetime.datetime]] = None, rule_name: str = "AI Guard Demo",
             profile: str = "AIGuard-Demo", gateway: str = "HQ-GW", **fields: Any) -> Dict[str, Any]:
    """A show-logs entry shaped like the official examples (for FakeMgmtServer.add_log).
    The AI Agent Security ``product`` string is not confirmed by Check Point docs."""
    if isinstance(time_, datetime.datetime):
        t = _iso_z(time_.astimezone(datetime.timezone.utc))
    else:
        t = time_ or _iso_z()
    log = {
        "id": _uid(), "log_uid": _uid().upper(), "time": t, "type": "Log", "action": action,
        "product": product, "product_family": "Threat", "src": src, "dst": host, "service": "443",
        "proto": "6", "orig": gateway, "resource": "https://%s/v1/chat/completions" % host,
        "dst_attr": [{"isCHKPObject": "false", "resolved": host}],
        "protection_name": protection_name, "protection_type": "AI Agent Security",
        "severity": "High", "confidence_level": "High", "policy_name": "Standard", "rule_name": rule_name,
        "smartdefense_profile": profile,
        "TP_match_table": [{"layer_name": "Standard Threat Prevention", "smartdefense_profile": profile,
                            "malware_rule_id": _uid().upper()}],
        "description": "%s blocked a request from %s to %s" % (product, src, host),
    }
    log.update(fields)
    return log


class FakeMgmtServer(_FakeServerBase):
    """Fake Check Point Management API over verified HTTPS.

    ``calls``: list of ``(command, payload, headers)`` in arrival order, payload exactly as
    sent (secrets intact) and headers as a case-insensitive dict.
    ``state`` (AttrDict, attribute or key access): ``objects`` {type: {name: obj}} for
    host / network / group / threat-profile / threat-rule / https-rule, ``rulebases``
    {layer: [rule names in order]}, ``gateways`` {name: show-simple-* reply (mutable)},
    ``outbound_cert``, ``published``, ``publish_count``, ``dirty``, ``changes``, ``discards``,
    ``installed``, ``install_count``, ``installs``, ``scripts``, ``moderation`` {gw: bool},
    ``gateway_changes``, ``logins``, ``sessions``, ``tasks``, ``logs``, ``log_queries``.
    Changes are stored immediately; ``publish`` snapshots them and ``discard`` reverts to
    the last snapshot.

    Scenario names (string, comma/space separated string, or iterable): see ``SCENARIOS``.
    Extra (not in the build spec) scenarios: ``cluster`` (adds LAB-CL), ``ai_guard_names``
    (server uses ai-guard* / test-ai-guard-api-key), ``ai_key_param_rejected`` (the AI test
    command refuses the ``api-key`` parameter), ``script_tasks_only`` (run-script replies with
    ``tasks`` only, like the real schema), ``publish_fails``, ``read_only`` (every session is
    read-only), ``ai_unsupported`` (API 2.2 without the test-ai-* commands),
    ``outbound_needs_name`` (show-outbound-inspection-certificate refuses an empty request, so
    the client must look the name up with show-outbound-inspection-certificates),
    ``partial_install_failed`` (the 2026-09-30 lab: the last install on the first gateway failed
    on the Access Control part with the sk116272 data-type error while Threat Prevention installed;
    the history is in ``task_history``, and a new install with access=true fails the same way,
    status ``partial_install_status``), ``https_learning`` (HTTPS Inspection in Learning mode).

    ``task_history``: finished tasks show-tasks returns besides the tasks of this run (see
    ``make_install_task``). ``state.policies`` {gateway: {"access"|"threat": {"name", "installed",
    "posix", "revision"}}}: what show-gateways-and-servers reports as installed; a successful
    install part updates it. ``outbound_certs``: the outbound certificates (name, uid, is-default).
    """

    server_header = "Apache"
    SCENARIOS = frozenset({
        "forbidden_ip", "bad_login", "install_fails", "https_off", "script_denied", "locked", "autonomous",
        "rate_limited", "old_version", "bad_ai_key",
        "cluster", "ai_guard_names", "ai_key_param_rejected", "script_tasks_only", "publish_fails", "read_only",
        "ai_unsupported", "outbound_needs_name", "partial_install_failed", "https_learning",
    })

    def __init__(self, pki: FakePKI, *, api_version: str = "2.2", scenario: Union[None, str, Iterable[str]] = None,
                 server_type: str = "SMS", domains: Sequence[str] = ("Corp-EMEA", "Lab"),
                 gateways: Optional[Iterable[Dict[str, Any]]] = None, with_cluster: bool = False,
                 packages: Sequence[str] = ("Standard",), task_polls: int = 3, host: str = "127.0.0.1"):
        super().__init__(pki, host=host)
        self.scenarios: Set[str] = _norm_scenarios(scenario)
        unknown = self.scenarios - self.SCENARIOS
        if unknown:
            raise ValueError("unknown FakeMgmtServer scenario(s): %s" % ", ".join(sorted(unknown)))
        if "old_version" in self.scenarios:
            api_version = OLD_API_VERSION
        self.api_version = str(api_version)
        st = str(server_type).upper()
        if st not in ("SMS", "MDS"):
            raise ValueError("server_type must be 'SMS' or 'MDS'")
        self.server_type = st
        self.domains: List[str] = list(domains)
        self.task_polls = max(1, int(task_polls))
        self.valid_api_key: Optional[str] = None
        self.valid_user: Optional[str] = None
        self.valid_password: Optional[str] = None
        self.admin_name = "aiguard-admin"
        self.strict_ai_key_format = False       # also reject non-hex keys on add/set-threat-profile
        self.ai_projects: Optional[Set[str]] = None  # None: the AI test command accepts any project-id
        self.mgmt_ipv4 = "10.1.1.101"
        self.task_history: List[Dict[str, Any]] = []
        self.partial_install_status = "failed"
        self.calls: List[Tuple[str, Any, Headers]] = []
        self.requests: List[Dict[str, Any]] = []
        self.commands: Set[str] = self._default_commands()
        self._ids = {k: _uid() for k in _BUILTIN_REFS}
        self._domain_uids = {d: _uid() for d in list(self.domains) + ["SMC User", "System Data"]}
        self._outbound_uid = _uid()
        self.outbound_certs: List[Dict[str, Any]] = [
            {"name": "Outbound Certificate", "uid": self._outbound_uid, "is-default": True}]

        specs = list(gateways) if gateways is not None else _default_gateways()
        if (with_cluster or "cluster" in self.scenarios) and not any(
                s.get("name") == "LAB-CL" for s in specs):
            specs.append(_default_cluster())
        self._gw_specs: Dict[str, Dict[str, Any]] = {}
        self._members: Dict[str, Dict[str, Any]] = {}
        for raw in specs:
            spec = raw if raw.get("_fake_spec") else make_gateway(**raw)
            self._gw_specs[spec["name"]] = spec
        self.packages: Dict[str, Dict[str, Any]] = {}
        rulebases: Dict[str, List[str]] = {}
        for pkg in packages:
            self.packages[pkg] = self._make_package(pkg)
            rulebases[self.packages[pkg]["_threat_layer"]] = []
            rulebases[self.packages[pkg]["_https_out"]] = []
            rulebases[self.packages[pkg]["_https_in"]] = []
        rulebases.setdefault("Default Layer", [])  # R81.20 single HTTPS layer name

        self.state = AttrDict(
            objects=AttrDict({"host": {}, "network": {}, "group": {}, "threat-profile": {}, "threat-rule": {},
                              "https-rule": {}}),
            rulebases=rulebases,
            gateways={},
            outbound_cert="https_off" not in self.scenarios,
            published=False, publish_count=0, dirty=False, changes=0, discards=0,
            installed=False, install_count=0, installs=[], install_failures=0,
            scripts=[], moderation={}, gateway_changes=[],
            logins=0, sessions={}, tasks={}, logs=[], log_queries=[], policies={},
        )
        for name in _PREDEFINED_PROFILES:
            self.state.objects["threat-profile"][name] = self._profile_obj(
                name, {"comments": "Predefined profile", "ips": True, "anti-bot": True, "anti-virus": True,
                       "threat-emulation": name != "Basic", "threat-extraction": False,
                       "confidence-level-high": "Prevent", "confidence-level-medium": "Prevent",
                       "confidence-level-low": "Detect"}, None)
            self.state.objects["threat-profile"][name]["_predefined"] = True
        installed_at = _now() - datetime.timedelta(days=1)
        for spec in self._gw_specs.values():
            self.state.gateways[spec["name"]] = self._build_detail(spec)
            self.state.policies[spec["name"]] = {
                kind: {"name": spec["%s_policy" % kind], "installed": True, "at": installed_at,
                       "revision": _uid()}
                for kind in ("access", "threat") if spec["%s_policy" % kind]}
            if spec["access_policy"] or spec["threat_policy"]:
                # the lab installed the policy a day ago and it succeeded
                self.task_history.append(make_install_task(
                    spec["name"], package=spec["threat_policy"] or spec["access_policy"],
                    status="succeeded", start=installed_at - datetime.timedelta(seconds=40),
                    access=bool(spec["access_policy"]), threat_prevention=bool(spec["threat_policy"]),
                    gateway_uid=self.state.gateways[spec["name"]]["uid"]))
        if "partial_install_failed" in self.scenarios and self._gw_specs:
            gw0 = next(iter(self._gw_specs))
            started = _now() - datetime.timedelta(hours=2)
            pol = self.state.policies[gw0]
            if "access" in pol:
                pol["access"]["at"] = _now() - datetime.timedelta(days=2)
            if "threat" in pol:
                pol["threat"]["at"] = started + datetime.timedelta(seconds=35)
            self.task_history.append(make_install_task(
                gw0, package=self._gw_specs[gw0]["threat_policy"] or "Standard",
                status=self.partial_install_status, start=started, access_ok=False, threat_ok=True,
                gateway_uid=self.state.gateways[gw0]["uid"]))
        self._snapshot = self._take_snapshot()

    # ------------------------------------------------------------------ public helpers

    def add_log(self, log: Optional[Dict[str, Any]] = None, **fields: Any) -> Dict[str, Any]:
        """Append a log entry returned by show-logs (newest first). Missing id/time/type are filled."""
        entry = dict(log or {})
        entry.update(fields)
        entry.setdefault("id", _uid())
        entry.setdefault("log_uid", _uid().upper())
        entry.setdefault("time", _iso_z())
        entry.setdefault("type", "Log")
        with self.lock:
            self.state.logs.append(entry)
        return entry

    def gateway(self, name: str) -> Dict[str, Any]:
        """Mutable show-simple-gateway/cluster reply for ``name`` (edit it to shape a test)."""
        return self.state.gateways[name]

    def find(self, obj_type: str, name: str) -> Optional[Dict[str, Any]]:
        return self.state.objects.get(obj_type, {}).get(name)

    def seed_object(self, obj_type: str, name: str, **fields: Any) -> Dict[str, Any]:
        """Pre-create an object as if it already existed (published). Keyword names may use
        underscores for hyphens (``ipv4_address="10.1.1.50"``, ``ai_agent_security=True``).
        obj_type: host | network | group | threat-profile (``api_key=`` sets the stored key) |
        threat-rule (``layer=``, ``position=``, ``action=``, ``protected_scope=`` ...)."""
        fields = {k.replace("_", "-"): v for k, v in fields.items()}
        with self.lock:
            if obj_type == "threat-profile":
                if "api-key" in fields:
                    fields[self._ai_prefix() + "-api-key"] = fields.pop("api-key")
                obj = self._profile_obj(name, fields, None)
            elif obj_type == "threat-rule":
                layer = self._layer_name(fields.pop("layer", self._first_threat_layer()), self._threat_layers())
                position = fields.pop("position", "bottom")
                payload = dict(fields, name=name, layer=layer, position=position)
                obj = self._make_threat_rule(payload, layer)
                self._insert_rule(layer, name, position)
            elif obj_type in ("host", "network", "group"):
                obj = {"uid": _uid(), "name": name, "type": obj_type, "comments": fields.pop("comments", ""),
                       "color": "black", "tags": [], "domain": self._domain_obj(None), "meta-info": self._meta()}
                obj.update(fields)
            else:
                raise ValueError("cannot seed %r" % obj_type)
            self.state.objects.setdefault(obj_type, {})[name] = obj
            self._snapshot = self._take_snapshot()
            return obj

    def calls_for(self, command: str) -> List[Any]:
        return [p for (c, p, _h) in self.calls if c == command]

    def last_call(self, command: str) -> Optional[Any]:
        found = self.calls_for(command)
        return found[-1] if found else None

    def call_names(self) -> List[str]:
        return [c for (c, _p, _h) in self.calls]

    def reset_calls(self) -> None:
        with self.lock:
            del self.calls[:]
            del self.requests[:]

    @property
    def outbound_ca_pem(self) -> str:
        """``base64-public-certificate`` as the v2+ API returns it (PEM text with CRLF body lines)."""
        body = "".join(self.pki.ca_pem.strip().splitlines()[1:-1])
        lines = [body[i:i + 64] for i in range(0, len(body), 64)]
        return "-----BEGIN CERTIFICATE-----\n" + "\r\n".join(lines) + "\r\n-----END CERTIFICATE-----\n"

    # ------------------------------------------------------------------ setup helpers

    def _default_commands(self) -> Set[str]:
        names = set(_V22_COMMANDS)
        v = _vt(self.api_version)
        if v < (2, 2, 0):
            names -= _AI_COMMANDS
            names -= set(_NOT_IN_V2)
        if v < (2, 0, 0):
            names -= set(_NOT_IN_V1_9_1)
        if self.server_type != "MDS":
            names -= _MDS_ONLY
        if "ai_guard_names" in self.scenarios and v >= (2, 2, 0):
            names.discard("test-ai-agent-security-api-key")
            names.add("test-ai-guard-api-key")
        if "ai_unsupported" in self.scenarios:
            names -= _AI_COMMANDS
            names.discard("test-ai-guard-api-key")
        return names

    def _ai_prefix(self) -> str:
        return "ai-guard" if "ai_guard_names" in self.scenarios else "ai-agent-security"

    def _make_package(self, name: str) -> Dict[str, Any]:
        std = name == "Standard"
        return {
            "uid": _uid(), "name": name, "type": "package", "comments": "", "color": "black",
            "access": True, "threat-prevention": True, "desktop-security": False, "qos": False,
            "nat-policy": True, "https-inspection-policy": True, "installation-targets": "all",
            "_access_layer": "Network" if std else "%s Network" % name, "_access_uid": _uid(),
            "_threat_layer": "%s Threat Prevention" % name, "_threat_uid": _uid(),
            "_https_out": "Default Outbound Layer" if std else "%s Outbound Layer" % name, "_https_out_uid": _uid(),
            "_https_in": "Default Inbound Layer" if std else "%s Inbound Layer" % name, "_https_in_uid": _uid(),
        }

    def _threat_layers(self) -> Dict[str, str]:
        return {p["_threat_layer"]: p["_threat_uid"] for p in self.packages.values()}

    def _https_layers(self) -> Dict[str, str]:
        out = {"Default Layer": self._ids.setdefault("https-default-layer", _uid())}
        for p in self.packages.values():
            out[p["_https_out"]] = p["_https_out_uid"]
            out[p["_https_in"]] = p["_https_in_uid"]
        return out

    def _first_threat_layer(self) -> str:
        return next(iter(self._threat_layers()))

    def _meta(self) -> Dict[str, Any]:
        d = _api_date()
        return {"lock": "unlocked", "validation-state": "ok", "last-modify-time": d, "last-modifier": self.admin_name,
                "creation-time": d, "creator": self.admin_name}

    def _domain_name(self, session: Optional[Dict[str, Any]]) -> str:
        if session is not None:
            return session["domain"]
        return "SMC User" if self.server_type == "SMS" else (self.domains[0] if self.domains else "System Data")

    def _domain_obj(self, session: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        name = self._domain_name(session)
        dtype = "mds" if name == "System Data" else "domain"
        return {"uid": self._domain_uids.setdefault(name, _uid()), "name": name, "domain-type": dtype}

    def _iface_detail(self, name: str, ip: str, mask: int, topo: str) -> Dict[str, Any]:
        return {"uid": _uid(), "name": name, "ipv4-address": ip, "ipv4-network-mask": _mask_str(mask),
                "ipv4-mask-length": mask, "ipv6-address": "", "topology": topo, "anti-spoofing": False,
                "security-zone": False, "network-interface-type": "ethernet", "comments": "", "color": "black",
                "icon": "NetworkObjects/network"}

    def _build_detail(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        cluster = spec["_fake_spec"] == "cluster"
        d: Dict[str, Any] = {
            "uid": _uid(), "name": spec["name"], "type": "simple-cluster" if cluster else "simple-gateway",
            "domain": self._domain_obj(None), "meta-info": self._meta(), "read-only": False, "comments": "",
            "color": "black", "icon": "NetworkObjects/cluster" if cluster else "NetworkObjects/gateway",
            "tags": [], "groups": [], "ipv4-address": spec["ipv4"], "ipv6-address": "", "dynamic-ip": False,
            "version": spec["version"], "os-name": "Gaia", "hardware": "Open server",
            "sic-state": spec["sic_state"], "sic-name": "CN=%s,O=mgmt.aiguard.test" % spec["name"],
            "ips-update-policy": "via management", "network-policy-management": False, "log-server": False,
            "save-logs-locally": False, "send-logs-to-server": ["SMS"],
        }
        for blade, on in spec["blades"].items():
            d[blade] = bool(on)
        mode = spec["tp_mode"]
        if mode is not None:
            d["threat-prevention-mode"] = "autonomous" if "autonomous" in self.scenarios else mode
        https = spec["https"]
        if https is not None:
            d["enable-https-inspection"] = False if "https_off" in self.scenarios else bool(https)
            d["https-inspection"] = {
                "bypass-on-failure": {"override-profile": False, "value": False},
                "bypass-on-client-failure": {"override-profile": False, "value": False},
                "site-categorization-allow-mode": {"override-profile": False, "value": "background"},
                "deny-untrusted-server-cert": {"override-profile": False, "value": False},
                "deny-revoked-server-cert": {"override-profile": False, "value": True},
                "deny-expired-server-cert": {"override-profile": False, "value": False},
                "deployment-mode": "learning" if "https_learning" in self.scenarios else "full",
            }
        if spec["workforce_ai"] is not None:
            d["workforce-ai"] = bool(spec["workforce_ai"])
        ifaces = [self._iface_detail(*i) for i in spec["interfaces"]]
        if cluster:
            for i in ifaces:
                i["interface-type"] = "cluster"
            d["interfaces"] = {"total": len(ifaces), "from": 1 if ifaces else 0, "to": len(ifaces), "objects": ifaces}
            d["cluster-mode"] = "cluster-xl-ha"
            members = []
            for mname, mip in spec["members"]:
                muid = _uid()
                self._members[mname] = {"uid": muid, "name": mname, "ip": mip, "cluster": spec["name"]}
                members.append({"uid": muid, "name": mname, "ip-address": mip, "ipv6-address": "",
                                "sic-state": spec["sic_state"], "sic-message": "Trust established",
                                "interfaces": [{"uid": _uid(), "name": "eth0", "ipv4-address": mip,
                                                "ipv4-network-mask": _mask_str(24), "ipv4-mask-length": 24,
                                                "ipv6-address": ""}]})
            d["cluster-members"] = members
        else:
            d["interfaces"] = ifaces
        d.update(copy.deepcopy(spec["extra"]))
        return d

    def _policy_obj(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        pol: Dict[str, Any] = {}
        state = self.state.policies.get(spec["name"], {})
        for kind in ("access", "threat"):
            st = state.get(kind)
            if not st:
                continue
            pol.update({"%s-policy-name" % kind: st["name"], "%s-policy-installed" % kind: bool(st["installed"]),
                        "%s-policy-installation-date" % kind: _api_date(st["at"]),
                        "%s-policy-revision" % kind: {"uid": st["revision"], "name": "Revision %s" % st["revision"][:8],
                                                      "type": "session"}})
        return pol

    def _listing_ifaces(self, spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [{"interface-name": n, "ipv4-address": ip, "ipv4-network-mask": _mask_str(m), "ipv4-mask-length": m,
                 "dynamic-ip": False, "topology": {"leads-to-internet": topo == "external"}}
                for (n, ip, m, topo) in spec["interfaces"]]

    def _listing(self, ctx: "_Ctx") -> List[Dict[str, Any]]:
        dom = self._domain_obj(ctx.session)
        base = {"domain": dom, "meta-info": self._meta(), "tags": [], "read-only": True, "comments": "",
                "color": "black", "groups": [], "operating-system": "Gaia", "hardware": "Open server"}
        if self.server_type == "MDS" and dom["name"] == "System Data":
            mds = dict(base, uid=self._ids.setdefault("mds", _uid()), name="MDS", type="CpmiHostCkp",
                       icon="NetworkObjects/CheckPoint/Hosts/xHost_CP", version="R82.20")
            mds.update({"ipv4-address": self.mgmt_ipv4, "sic-status": "communicating", "policy": {},
                        "network-security-blades": {},
                        "management-blades": {"network-policy-management": True, "logging-and-status": True}})
            return [mds]
        out: List[Dict[str, Any]] = []
        mgmt_name = "SMS" if self.server_type == "SMS" else "%s_Server" % dom["name"]
        mgmt = dict(base, uid=self._ids.setdefault("mgmt:" + mgmt_name, _uid()), name=mgmt_name, type="CpmiHostCkp",
                    icon="NetworkObjects/CheckPoint/Hosts/xHost_CP", version="R82.20")
        mgmt.update({"ipv4-address": self.mgmt_ipv4, "sic-status": "communicating", "policy": {},
                     "interfaces": [{"interface-name": "eth0", "ipv4-address": self.mgmt_ipv4,
                                     "ipv4-network-mask": "255.255.255.0", "ipv4-mask-length": 24,
                                     "dynamic-ip": False, "topology": {"leads-to-internet": False}}],
                     "network-security-blades": {},
                     "management-blades": {"network-policy-management": True, "logging-and-status": True}})
        out.append(mgmt)
        for name, spec in self._gw_specs.items():
            detail = self.state.gateways[name]
            cluster = spec["_fake_spec"] == "cluster"
            blades = {_LISTING_BLADE[b]: True for b in _API_BLADES if b in _LISTING_BLADE and detail.get(b)}
            obj = dict(base, uid=detail["uid"], name=name, type="CpmiGatewayCluster" if cluster else "simple-gateway",
                       icon=detail["icon"], version=detail.get("version"))
            obj.update({"ipv4-address": detail.get("ipv4-address"), "ipv6-address": "",
                        "sic-status": detail.get("sic-state"), "interfaces": self._listing_ifaces(spec),
                        "policy": self._policy_obj(spec), "network-security-blades": blades,
                        "management-blades": {}, "vpn-encryption-domain": "addresses_behind_gw"})
            if cluster:
                obj["cluster-member-names"] = [m for m, _ip in spec["members"]]
            out.append(obj)
            for mname, mip in spec["members"]:
                m = self._members[mname]
                mo = dict(base, uid=m["uid"], name=mname, type="CpmiClusterMember",
                          icon="NetworkObjects/CheckPoint/Gateways/xClusterMember", version=detail.get("version"))
                mo.update({"ipv4-address": mip, "sic-status": detail.get("sic-state"),
                           "interfaces": [{"interface-name": "eth0", "ipv4-address": mip,
                                           "ipv4-network-mask": "255.255.255.0", "ipv4-mask-length": 24,
                                           "dynamic-ip": False, "topology": {"leads-to-internet": False}}],
                           "policy": self._policy_obj(spec), "network-security-blades": blades,
                           "management-blades": {}})
                out.append(mo)
        out.sort(key=lambda o: o["name"].lower())
        return out

    # ------------------------------------------------------------------ snapshots / tasks

    def _take_snapshot(self) -> Dict[str, Any]:
        return {"objects": copy.deepcopy(dict(self.state.objects)), "rulebases": copy.deepcopy(self.state.rulebases),
                "gateways": copy.deepcopy(self.state.gateways), "outbound_cert": self.state.outbound_cert}

    def _changed(self) -> None:
        self.state.dirty = True
        self.state.changes += 1

    def _new_task(self, name: str, *, kind: str = "generic", fail: bool = False,
                  details_ok: Optional[List[Dict[str, Any]]] = None, details_fail: Optional[List[Dict[str, Any]]] = None,
                  comments_fail: str = "", polls: Optional[int] = None, description: str = "") -> str:
        tid = _uid()
        self.state.tasks[tid] = {
            "task-id": tid, "task-name": name, "kind": kind, "fail": fail, "polls": 0,
            "polls_needed": self.task_polls if polls is None else max(1, polls),
            "details_ok": details_ok or [], "details_fail": details_fail or [], "comments_fail": comments_fail,
            "description": description or name, "start": _now(),
        }
        return tid

    def _task_view(self, t: Dict[str, Any], full: bool) -> Dict[str, Any]:
        t["polls"] += 1
        n = t["polls"]
        need = t["polls_needed"]
        if n < need:
            pct = 30 if n == 1 else min(95, 70 + 10 * (n - 2))
            status, comments, details = "in progress", "", []
        elif t["fail"]:
            pct, status, comments, details = (100, t.get("fail_status") or "failed", t["comments_fail"],
                                              t["details_fail"])
        else:
            pct, status, comments, details = 100, "succeeded", "", t["details_ok"]
        view = {"uid": t["task-id"], "type": "task", "task-id": t["task-id"], "task-name": t["task-name"],
                "status": status, "progress-percentage": pct, "progress-description": t["description"],
                "suppressed": False, "start-time": _api_date(t["start"]), "last-update-time": _api_date(),
                "comments": comments, "color": "black", "domain": self._domain_obj(None)}
        if full:
            view["task-details"] = copy.deepcopy(details)
        return view

    def _async_reply(self, ctx: "_Ctx", name: str, obj: Dict[str, Any]) -> Dict[str, Any]:
        if ctx.ver >= (2, 2, 0):
            return {"task-id": self._new_task(name, details_ok=[{"statusCode": "succeeded",
                                                                 "statusDescription": name + " succeeded"}])}
        return self._public(obj)

    # ------------------------------------------------------------------ dispatch

    def _dispatch(self, req: _Request) -> _Reply:
        path = urlsplit(req.path).path
        m = _MGMT_PATH.match(path)
        with self.lock:
            if "forbidden_ip" in self.scenarios and path.startswith("/web_api"):
                self.requests.append({"path": path, "method": req.method, "command": m.group(2) if m else None,
                                      "version": m.group(1) if m else None, "headers": req.headers})
                if m:
                    self.calls.append((m.group(2), self._parse_or_text(req.body), req.headers))
                return _apache_403(path)
            if not m:
                return _html_reply(404, "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1>"
                                        "<p>The requested URL was not found on this server.</p></body></html>")
            pinned, command = m.group(1), m.group(2)
            payload = self._parse_or_text(req.body)
            self.calls.append((command, payload, req.headers))
            self.requests.append({"path": path, "method": req.method, "command": command, "version": pinned,
                                  "headers": req.headers, "payload": payload})
            try:
                return self._handle(req, pinned, command, payload)
            except _ApiError as e:
                return e.reply()

    @staticmethod
    def _parse_or_text(body: bytes) -> Any:
        try:
            return json.loads(body.decode("utf-8")) if body.strip() else {}
        except (ValueError, UnicodeDecodeError):
            return body.decode("utf-8", "replace")

    def _handle(self, req: _Request, pinned: Optional[str], command: str, payload: Any) -> _Reply:
        if req.method != "POST":
            raise _ApiError(400, "generic_error", "Only POST requests are supported")
        if not isinstance(payload, dict):
            raise _ApiError(400, "generic_err_invalid_syntax", "Request body is not a valid JSON object")
        version = self.api_version
        if pinned:
            if pinned not in _SUPPORTED_VERSIONS or _vt(pinned) > _vt(self.api_version):
                raise _ApiError(400, "generic_err_invalid_api_version", "API version [%s] is not supported" % pinned)
            version = pinned
        if command not in self.commands:
            return _json_reply(404, {"code": "generic_err_command_not_found",
                                     "message": "Unknown command \"%s\"" % command,
                                     "errors": [], "warnings": [], "blocking-errors": []})
        session = None
        if command != "login":
            sid = req.headers.get("X-chkp-sid")
            if not sid:
                raise _ApiError(401, "generic_err_wrong_session_id", "Missing header: [X-chkp-sid]")
            session = self.state.sessions.get(sid)
            if session is None:
                raise _ApiError(401, "generic_err_wrong_session_id",
                                "Wrong session id [%s]. Session may be expired. Please check session id and resend "
                                "the request" % sid)
            session["last-seen"] = _now()
        ctx = _Ctx(session, _vt(version), version, req.headers, req.client_ip, command)
        fn = getattr(self, "_c_" + command.replace("-", "_"), None)
        if fn is None:
            raise _ApiError(501, "generic_err_not_implemented",
                            "FakeMgmtServer does not implement \"%s\"" % command)
        self._check_params(ctx, command, payload)
        if session is not None and session["read-only"] and command not in _READONLY_ALLOWED and not (
                command.startswith("show-") or command.startswith("test-")):
            raise _ApiError(403, "generic_err_permission_denied",
                            "Permission denied: the session is read-only (log in without read-only to make changes)")
        result = fn(ctx, payload)
        if isinstance(result, _Reply):
            return result
        return _json_reply(200, result)

    def _check_params(self, ctx: "_Ctx", command: str, payload: Dict[str, Any]) -> None:
        if command in _AI_COMMANDS:
            allowed = {"project-id", "profile-name", "api-key"}
            if "ai_key_param_rejected" in self.scenarios:
                allowed.discard("api-key")
        else:
            raw = _PARAMS.get(command)
            if ctx.ver < (2, 0, 0) and command in _PARAMS_V1_9_1:
                raw = _PARAMS_V1_9_1[command]
            if raw is None:
                return
            allowed = set(raw.split())
            if command in ("add-threat-profile", "set-threat-profile"):
                ai = {a for a in allowed if a.startswith("ai-agent-security")}
                allowed -= ai
                if ctx.ver >= (2, 2, 0):
                    prefix = self._ai_prefix()
                    allowed |= {prefix + a[len("ai-agent-security"):] for a in ai}
        for key in payload:
            if key not in allowed:
                raise _ApiError(400, "generic_err_invalid_parameter_name", "Unrecognized parameter [%s]" % key)

    # ------------------------------------------------------------------ generic helpers

    @staticmethod
    def _public(obj: Dict[str, Any]) -> Dict[str, Any]:
        return {k: copy.deepcopy(v) for k, v in obj.items() if not k.startswith("_")}

    @staticmethod
    def _page(items: List[Any], p: Dict[str, Any], default_limit: int = 50) -> Tuple[List[Any], Dict[str, int]]:
        limit = p.get("limit", default_limit)
        offset = p.get("offset", 0)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise _invalid("Invalid parameter for [limit]. The value must be an integer between 1 and 500")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise _invalid("Invalid parameter for [offset]. The value must be a non-negative integer")
        chunk = items[offset:offset + limit]
        return chunk, {"from": offset + 1 if chunk else 0, "to": offset + len(chunk), "total": len(items)}

    @staticmethod
    def _details_level(p: Dict[str, Any]) -> str:
        level = p.get("details-level", "standard")
        if level not in _DETAILS_LEVELS:
            raise _invalid("Invalid value [%s] for parameter [details-level]. Valid values: uid, standard, full" % level)
        return level

    @staticmethod
    def _enum(p: Dict[str, Any], key: str, allowed: Sequence[str]) -> Optional[str]:
        if key not in p:
            return None
        value = p[key]
        for a in allowed:
            if isinstance(value, str) and value.lower() == a.lower():
                return a
        raise _invalid("Invalid value [%s] for parameter [%s]. Valid values: %s" % (value, key, ", ".join(allowed)))

    @staticmethod
    def _bool(p: Dict[str, Any], key: str) -> Optional[bool]:
        if key not in p:
            return None
        if not isinstance(p[key], bool):
            raise _invalid("Invalid value [%s] for parameter [%s]. The value must be true or false" % (p[key], key))
        return p[key]

    def _find_by(self, obj_type: str, p: Dict[str, Any], what: str = "name") -> Dict[str, Any]:
        objs = self.state.objects[obj_type]
        if "uid" in p:
            for o in objs.values():
                if o["uid"] == p["uid"]:
                    return o
            raise _not_found(p["uid"])
        if "name" not in p:
            raise _missing(what)
        o = objs.get(p["name"])
        if o is None:
            for k, v in objs.items():
                if k.lower() == str(p["name"]).lower():
                    return v
            raise _not_found(p["name"])
        return o

    def _ref_index(self) -> Dict[str, Dict[str, Any]]:
        idx: Dict[str, Dict[str, Any]] = {}
        for low, typ in _BUILTIN_REFS.items():
            idx[low] = {"uid": self._ids[low], "name": _BUILTIN_CANON[low], "type": typ}
        for t in ("host", "network", "group"):
            for n, o in self.state.objects[t].items():
                idx[n.lower()] = {"uid": o["uid"], "name": n, "type": t}
        for n, d in self.state.gateways.items():
            idx[n.lower()] = {"uid": d["uid"], "name": n, "type": d["type"]}
        for n, m in self._members.items():
            idx[n.lower()] = {"uid": m["uid"], "name": n, "type": "CpmiClusterMember"}
        return idx

    def _refs(self, field: str, value: Any, *, validate: bool = True) -> List[Dict[str, Any]]:
        idx = self._ref_index()
        out = []
        for item in _as_list(value):
            if not isinstance(item, str):
                raise _invalid("Invalid parameter for [%s]. Expected an object name or UID" % field)
            ref = idx.get(item.lower())
            if ref is None:
                for r in idx.values():
                    if r["uid"] == item:
                        ref = r
                        break
            if ref is None:
                if validate:
                    raise _not_found(item)
                ref = {"uid": _uid(), "name": item, "type": "service-tcp"}
            out.append(dict(ref))
        return out or [{"uid": self._ids["any"], "name": "Any", "type": "CpmiAnyObject"}]

    def _apply_ref_update(self, current: List[Dict[str, Any]], field: str, value: Any,
                          validate: bool = True) -> List[Dict[str, Any]]:
        if isinstance(value, dict):
            names = [r["name"] for r in current if r["name"] != "Any"]
            for n in _as_list(value.get("add")):
                if n not in names:
                    names.append(n)
            for n in _as_list(value.get("remove")):
                names = [x for x in names if x.lower() != str(n).lower()]
            return self._refs(field, names, validate=validate)
        return self._refs(field, value, validate=validate)

    def _gateway_names(self) -> Dict[str, str]:
        return {n.lower(): n for n in self.state.gateways}

    # ------------------------------------------------------------------ session commands

    def _c_login(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        self.state.logins += 1
        if "rate_limited" in self.scenarios and self.state.logins >= 2:
            raise _ApiError(429, "err_too_many_requests", "Too many requests in a given amount of time")
        if "bad_login" in self.scenarios:
            raise _ApiError(400, "err_login_failed", "Authentication to server failed.")
        if p.get("api-key") is not None:  # a JSON null counts as absent
            key = p.get("api-key")
            ok = isinstance(key, str) and bool(key) and (self.valid_api_key is None
                                                          or _same(key, self.valid_api_key))
            user = self.admin_name
            auth = "api-key"
        elif p.get("user") is not None or p.get("password") is not None:
            if not p.get("user"):
                raise _missing("user")
            if not p.get("password"):
                raise _missing("password")
            user = str(p["user"])
            ok = (self.valid_user is None or _same(user, self.valid_user)) and (
                self.valid_password is None or _same(p["password"], self.valid_password))
            auth = "password"
        else:
            raise _missing("user, password")
        if not ok:
            raise _ApiError(400, "err_login_failed", "Authentication to server failed.")
        domain = self._resolve_login_domain(p.get("domain"))
        read_only = bool(p.get("read-only", False)) or "read_only" in self.scenarios
        return self._new_session(ctx, domain, read_only, user, auth, p)

    def _resolve_login_domain(self, domain: Any) -> str:
        if self.server_type == "SMS":
            if domain in (None, "", "SMC User"):
                return "SMC User"
            if domain == "System Data":
                return "System Data"
            raise _ApiError(400, "err_login_failed", "Authentication to server failed.")
        if domain in (None, "", "System Data", "MDS"):
            return "System Data"
        for d in self.domains:
            if str(domain).lower() == d.lower() or domain == self._domain_uids.get(d):
                return d
        raise _ApiError(400, "err_login_failed", "Authentication to server failed.")

    def _new_session(self, ctx: "_Ctx", domain: str, read_only: bool, user: str, auth: str,
                     p: Dict[str, Any]) -> Dict[str, Any]:
        sid = secrets.token_urlsafe(32)
        uid = _uid()
        timeout = p.get("session-timeout", 600)
        self.state.sessions[sid] = {
            "sid": sid, "uid": uid, "domain": domain, "read-only": read_only, "user": user, "auth": auth,
            "name": p.get("session-name", ""), "description": p.get("session-description", ""),
            "timeout": timeout, "created": _now(), "last-seen": _now(), "client-ip": ctx.client_ip,
        }
        reply = {"sid": sid, "url": "https://%s:%s/web_api" % (self.host, self.port), "uid": uid,
                 "session-timeout": timeout, "last-login-was-at": _api_date(), "api-server-version": self.api_version,
                 "read-only": read_only, "standby": False}
        return reply

    def _c_logout(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        self.state.sessions.pop(ctx.session["sid"], None)
        return {"message": "OK"}

    def _c_keepalive(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        return {"message": "OK"}

    def _c_show_api_versions(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        return {"current-version": self.api_version,
                "supported-versions": [v for v in _SUPPORTED_VERSIONS if _vt(v) <= _vt(self.api_version)]}

    def _c_show_commands(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        prefix = p.get("prefix", "")
        names = sorted(n for n in self.commands if n.startswith(prefix))
        return {"commands": [{"name": n, "description": _command_description(n)} for n in names]}

    def _c_show_session(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        s = ctx.session
        if "uid" in p and p["uid"] != s["uid"]:
            raise _not_found(p["uid"])
        return {"uid": s["uid"], "name": s["name"], "type": "session", "domain": self._domain_obj(s),
                "user-name": s["user"], "description": s["description"], "state": "open",
                "connection-mode": "read only" if s["read-only"] else "read write",
                "changes": self.state.changes, "locks": self.state.changes, "session-timeout": s["timeout"],
                "expired-session": False, "in-work": True, "ip-address": s["client-ip"], "application": "WEB_API",
                "last-login-time": _api_date(s["created"]),
                "connected-server": {"uid": self._ids.setdefault("mgmt:self", _uid()),
                                     "name": "SMS" if self.server_type == "SMS" else "MDS",
                                     "type": "CpmiHostCkp"}}

    def _c_show_domains(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        level = self._details_level(p)
        flt = str(p.get("filter", "")).lower()
        doms = [d for d in self.domains if flt in d.lower()]
        items = []
        for d in doms:
            if level == "uid":
                items.append(self._domain_uids[d])
                continue
            o = {"uid": self._domain_uids[d], "name": d, "type": "domain", "domain": self._domain_obj(
                {"domain": "System Data"})}
            if level == "full":
                o.update({"domain-type": "domain", "comments": "", "color": "black",
                          "servers": [{"name": "%s_Server" % d, "ipv4-address": self.mgmt_ipv4,
                                       "multi-domain-server": "MDS", "active": True, "type": "management server"}]})
            items.append(o)
        chunk, meta = self._page(items, p)
        return dict(meta, objects=chunk)

    def _c_show_mdss(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        o = {"uid": self._ids.setdefault("mds", _uid()), "name": "MDS", "type": "mds",
             "ipv4-address": self.mgmt_ipv4, "server-type": "multi-domain server"}
        return {"objects": [o], "from": 1, "to": 1, "total": 1}

    def _c_login_to_domain(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        if "domain" not in p:
            raise _missing("domain")
        if ctx.session["domain"] != "System Data":
            raise _ApiError(400, "generic_err_command_not_allowed",
                            "login-to-domain is only allowed from a Multi-Domain Server (System Data) session")
        target = None
        for d in self.domains:
            if str(p["domain"]).lower() == d.lower() or p["domain"] == self._domain_uids.get(d):
                target = d
        if target is None:
            raise _not_found(p["domain"])
        s = ctx.session
        return self._new_session(ctx, target, bool(p.get("read-only", False)) or "read_only" in self.scenarios,
                                 s["user"], s["auth"], {"session-name": s["name"],
                                                        "session-description": s["description"]})

    # ------------------------------------------------------------------ gateways

    def _c_show_gateways_and_servers(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        level = self._details_level(p)
        objs = self._listing(ctx)
        if level == "uid":
            items: List[Any] = [o["uid"] for o in objs]
        elif level == "standard":
            items = [{k: o[k] for k in ("uid", "name", "type", "domain")} for o in objs]
        else:
            items = objs
        chunk, meta = self._page(items, p)
        return dict(meta, objects=chunk)

    def _visible_gateways(self, ctx: "_Ctx") -> bool:
        return not (self.server_type == "MDS" and ctx.session["domain"] == "System Data")

    def _find_gateway(self, ctx: "_Ctx", p: Dict[str, Any], gtype: str) -> Dict[str, Any]:
        if "uid" not in p and "name" not in p:
            raise _missing("name")
        key = p.get("uid") or p.get("name")
        if self._visible_gateways(ctx):
            for n, d in self.state.gateways.items():
                if d["type"] == gtype and (p.get("uid") == d["uid"] or str(p.get("name", "")).lower() == n.lower()):
                    return d
        raise _not_found(key)

    def _gateway_reply(self, ctx: "_Ctx", d: Dict[str, Any]) -> Dict[str, Any]:
        out = self._public(d)
        if ctx.ver < (2, 2, 0):
            out.pop("workforce-ai", None)
        return out

    def _c_show_simple_gateway(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        self._details_level(p)
        return self._gateway_reply(ctx, self._find_gateway(ctx, p, "simple-gateway"))

    def _c_show_simple_cluster(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        self._details_level(p)
        out = self._gateway_reply(ctx, self._find_gateway(ctx, p, "simple-cluster"))
        limit = p.get("limit-interfaces", 50)   # the real default is 50
        ifaces = out.get("interfaces")
        if isinstance(ifaces, dict) and isinstance(limit, int) and not isinstance(limit, bool):
            objs = list(ifaces.get("objects") or [])
            chunk = objs[:max(0, limit)]
            out["interfaces"] = {"total": len(objs), "from": 1 if chunk else 0, "to": len(chunk),
                                 "objects": chunk}
        return out

    def _set_gateway(self, ctx: "_Ctx", p: Dict[str, Any], gtype: str) -> Dict[str, Any]:
        hi = p.get("https-inspection")
        if isinstance(hi, dict) and "deployment-mode" in hi:
            if ctx.ver < (2, 0, 0):
                raise _ApiError(400, "generic_err_invalid_parameter_name",
                                "Unrecognized parameter [https-inspection.deployment-mode]")
            if hi["deployment-mode"] not in ("full", "learning"):
                raise _invalid("Invalid value [%s] for parameter [deployment-mode]. Valid values: full, "
                               "learning" % hi["deployment-mode"])
        d = self._find_gateway(ctx, p, gtype)
        if p.get("enable-https-inspection") is True and not self.state.outbound_cert:
            raise _validation("HTTPS Inspection cannot be enabled on %s: there is no outbound inspection "
                              "certificate. Create or import one (HTTPS Inspection > Step 1) first." % d["name"])
        changes = {}
        for k, v in p.items():
            if k in ("uid", "name", "details-level", "ignore-warnings", "ignore-errors"):
                continue
            if k == "new-name":
                continue
            if k == "https-inspection" and isinstance(v, dict):
                d.setdefault("https-inspection", {}).update(copy.deepcopy(v))
            else:
                d[k] = copy.deepcopy(v)
            changes[k] = copy.deepcopy(v)
        self.state.gateway_changes.append({"gateway": d["name"], "command": ctx.command, "changes": changes})
        self._changed()
        return self._gateway_reply(ctx, d)

    def _c_set_simple_gateway(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        return self._set_gateway(ctx, p, "simple-gateway")

    def _c_set_simple_cluster(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        d = self._set_gateway(ctx, p, "simple-cluster")
        return {"task-id": self._new_task("Update cluster %s" % d["name"],
                                          details_ok=[{"statusCode": "succeeded",
                                                       "statusDescription": "Cluster %s updated" % d["name"]}])}

    # ------------------------------------------------------------------ packages & layers

    def _find_package(self, p: Dict[str, Any]) -> Dict[str, Any]:
        if "uid" in p:
            for pkg in self.packages.values():
                if pkg["uid"] == p["uid"]:
                    return pkg
            raise _not_found(p["uid"])
        if "name" not in p:
            raise _missing("name")
        for n, pkg in self.packages.items():
            if n.lower() == str(p["name"]).lower():
                return pkg
        raise _not_found(p["name"])

    def _package_reply(self, ctx: "_Ctx", pkg: Dict[str, Any]) -> Dict[str, Any]:
        out = self._public(pkg)
        out["domain"] = self._domain_obj(ctx.session)
        out["access-layers"] = [{"uid": pkg["_access_uid"], "name": pkg["_access_layer"], "type": "access-layer"}]
        out["threat-layers"] = [{"uid": pkg["_threat_uid"], "name": pkg["_threat_layer"], "type": "threat-layer"}]
        if ctx.ver >= (2, 0, 0):
            out["https-inspection-layers"] = {
                "inbound-https-layer": {"uid": pkg["_https_in_uid"], "name": pkg["_https_in"], "type": "https-layer"},
                "outbound-https-layer": {"uid": pkg["_https_out_uid"], "name": pkg["_https_out"],
                                         "type": "https-layer"}}
        else:
            out["https-inspection-layer"] = {"uid": self._https_layers()["Default Layer"], "name": "Default Layer",
                                             "type": "https-layer"}
        return out

    def _c_show_package(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        self._details_level(p)
        return self._package_reply(ctx, self._find_package(p))

    def _c_show_packages(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        level = self._details_level(p)
        items = []
        for pkg in self.packages.values():
            if level == "full":
                items.append(self._package_reply(ctx, pkg))
            else:
                items.append({"uid": pkg["uid"], "name": pkg["name"], "type": "package",
                              "domain": self._domain_obj(ctx.session)})
        chunk, meta = self._page(items, p)
        return dict(meta, packages=chunk)

    def _c_show_threat_layers(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        self._details_level(p)
        items = [{"uid": uid, "name": n, "type": "threat-layer", "domain": self._domain_obj(ctx.session)}
                 for n, uid in self._threat_layers().items()]
        chunk, meta = self._page(items, p)
        return dict(meta, **{"threat-layers": chunk})

    def _layer_name(self, value: Any, layers: Dict[str, str]) -> str:
        if value is None:
            raise _missing("layer")
        for n, uid in layers.items():
            if str(value).lower() == n.lower() or value == uid:
                return n
        raise _not_found(value)

    def _c_show_threat_rulebase(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        layer = self._layer_name(p.get("name", p.get("uid")), self._threat_layers())
        rules = [self._rule_reply(self.state.objects["threat-rule"][n], i + 1)
                 for i, n in enumerate(self.state.rulebases[layer])]
        chunk, meta = self._page(rules, p)
        return dict(meta, uid=self._threat_layers()[layer], name=layer, rulebase=chunk, **{"objects-dictionary": []})

    # ------------------------------------------------------------------ threat profiles

    def _profile_fields(self, ctx: Optional["_Ctx"], p: Dict[str, Any]) -> Dict[str, Any]:
        fields: Dict[str, Any] = {}
        for key in ("confidence-level-high", "confidence-level-medium", "confidence-level-low"):
            v = self._enum(p, key, _CONFIDENCE)
            if v is not None:
                fields[key] = v
        v = self._enum(p, "active-protections-performance-impact", _PERF_IMPACT)
        if v is not None:
            fields["active-protections-performance-impact"] = v
        v = self._enum(p, "active-protections-severity", _SEVERITY)
        if v is not None:
            fields["active-protections-severity"] = v
        for key in ("ips", "anti-bot", "anti-virus", "threat-emulation", "threat-extraction", "zero-phishing",
                    "use-indicators", "use-extended-attributes"):
            b = self._bool(p, key)
            if b is not None:
                fields[key] = b
        for key in ("comments", "color", "tags", "ips-settings", "overrides", "indicator-overrides"):
            if key in p:
                fields[key] = copy.deepcopy(p[key])
        prefix = self._ai_prefix()
        b = self._bool(p, prefix)
        if b is not None:
            fields[prefix] = b
        if prefix + "-settings" in p:
            s = p[prefix + "-settings"]
            if not isinstance(s, dict) or set(s) - {"project-id"}:
                raise _invalid("Invalid parameter for [%s-settings]. Expected {\"project-id\": \"...\"}" % prefix)
            fields[prefix + "-settings"] = dict(s)
        if prefix + "-api-key" in p:
            key = p[prefix + "-api-key"]
            if not isinstance(key, str) or not key:
                raise _invalid("Invalid parameter for [%s-api-key]" % prefix)
            if self.strict_ai_key_format and not re.fullmatch(r"[0-9a-fA-F]{64}", key):
                raise _invalid("%s-api-key must be a 64-character hex string" % prefix)
            fields["_secret"] = key
        return fields

    def _profile_obj(self, name: str, p: Dict[str, Any], ctx: Optional["_Ctx"]) -> Dict[str, Any]:
        obj: Dict[str, Any] = {
            "uid": _uid(), "name": name, "type": "threat-profile", "comments": "", "color": "black", "tags": [],
            "domain": self._domain_obj(ctx.session if ctx else None), "meta-info": self._meta(), "read-only": False,
            "ips": True, "anti-bot": True, "anti-virus": True, "threat-emulation": True, "threat-extraction": True,
            "zero-phishing": False, "use-indicators": True, "use-extended-attributes": False,
            "confidence-level-high": "Prevent", "confidence-level-medium": "Prevent", "confidence-level-low": "Detect",
            "active-protections-performance-impact": "medium", "active-protections-severity": "Medium or above",
            "overrides": [], "indicator-overrides": [],
        }
        if _vt(self.api_version) >= (2, 2, 0):
            prefix = self._ai_prefix()
            obj[prefix] = False
            obj[prefix + "-settings"] = {"project-id": ""}
        fields = self._profile_fields(ctx, p)
        obj.update(fields)
        return obj

    def _check_ai(self, obj: Dict[str, Any]) -> None:
        prefix = self._ai_prefix()
        if obj.get(prefix) and not obj.get("_secret"):
            raise _validation("%s-api-key is required when %s is enabled" % (prefix, prefix))

    def _profile_reply(self, ctx: "_Ctx", obj: Dict[str, Any]) -> Dict[str, Any]:
        out = self._public(obj)
        if ctx.ver < (2, 2, 0):
            for k in list(out):
                if k.startswith("ai-"):
                    out.pop(k)
        return out

    def _c_show_threat_profile(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        self._details_level(p)
        return self._profile_reply(ctx, self._find_by("threat-profile", p))

    def _c_add_threat_profile(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        name = p.get("name")
        if not name:
            raise _missing("name")
        if any(n.lower() == str(name).lower() for n in self.state.objects["threat-profile"]):
            raise _validation("More than one object named '%s' exists." % name)
        obj = self._profile_obj(str(name), p, ctx)
        obj["_request"] = copy.deepcopy(p)
        self._check_ai(obj)
        self.state.objects["threat-profile"][obj["name"]] = obj
        self._changed()
        return self._async_reply(ctx, "Add threat profile %s" % name, obj)

    def _c_set_threat_profile(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        obj = self._find_by("threat-profile", p)
        if obj.get("_predefined"):
            raise _ApiError(400, "generic_err_object_read_only", "Profile '%s' is predefined and cannot be changed"
                            % obj["name"])
        updated = dict(obj)
        updated.update(self._profile_fields(ctx, p))
        self._check_ai(updated)
        if p.get("new-name"):
            self.state.objects["threat-profile"].pop(obj["name"], None)
            updated["name"] = p["new-name"]
        updated["_request"] = copy.deepcopy(p)
        self.state.objects["threat-profile"][updated["name"]] = updated
        self._changed()
        return self._async_reply(ctx, "Set threat profile %s" % updated["name"], updated)

    def _c_delete_threat_profile(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        obj = self._find_by("threat-profile", p)
        if obj.get("_predefined"):
            raise _ApiError(400, "generic_err_object_read_only", "Profile '%s' is predefined and cannot be deleted"
                            % obj["name"])
        for rname, rule in self.state.objects["threat-rule"].items():
            if rule["action"]["name"] == obj["name"]:
                raise _validation("Object '%s' is in use by rule '%s' in layer '%s'"
                                  % (obj["name"], rname, rule["_layer"]))
        self.state.objects["threat-profile"].pop(obj["name"], None)
        self._changed()
        if ctx.ver >= (2, 2, 0):
            return {"task-id": self._new_task("Delete threat profile %s" % obj["name"])}
        return {"message": "OK"}

    # ------------------------------------------------------------------ threat rules

    def _position_index(self, rules: List[str], position: Any, field: str = "position") -> int:
        if position is None:
            raise _missing(field)
        if isinstance(position, bool):
            raise _invalid("Invalid parameter for [%s]" % field)
        if isinstance(position, int):
            if position < 1:
                raise _invalid("Invalid parameter for [%s]. Rule numbers start at 1" % field)
            return min(position - 1, len(rules))
        if isinstance(position, str):
            if position.lower() == "top":
                return 0
            if position.lower() == "bottom":
                return len(rules)
            if position.isdigit():
                return self._position_index(rules, int(position), field)
        if isinstance(position, dict) and len(position) == 1:
            (where, ref), = position.items()
            if where in ("top", "bottom"):
                return 0 if where == "top" else len(rules)
            if where in ("above", "below"):
                if ref in rules:
                    i = rules.index(ref)
                    return i if where == "above" else i + 1
                raise _not_found(ref)
        raise _invalid("Invalid parameter for [%s]. Use an integer, \"top\", \"bottom\" or "
                       "{\"above\"|\"below\"|\"top\"|\"bottom\": <rule or section>}" % field)

    def _insert_rule(self, layer: str, name: str, position: Any) -> None:
        rules = self.state.rulebases.setdefault(layer, [])
        idx = self._position_index(rules, position if position is not None else "bottom")
        rules.insert(idx, name)

    @staticmethod
    def _track(value: Any, allowed: Sequence[str]) -> str:
        if not isinstance(value, str):
            raise _invalid("Invalid parameter for [track]. The value must be a string, one of: %s"
                           % ", ".join(allowed))
        for a in allowed:
            if value.lower() == a.lower():
                return a
        raise _invalid("Invalid value [%s] for parameter [track]. Valid values: %s" % (value, ", ".join(allowed)))

    def _profile_ref(self, name: Any) -> Dict[str, Any]:
        for n, o in self.state.objects["threat-profile"].items():
            if str(name).lower() == n.lower() or name == o["uid"]:
                return {"uid": o["uid"], "name": n, "type": "threat-profile"}
        raise _not_found(name)

    def _make_threat_rule(self, p: Dict[str, Any], layer: str) -> Dict[str, Any]:
        rule = {
            "uid": _uid(), "name": p.get("name", ""), "type": "threat-rule", "layer": self._threat_layers().get(layer),
            "_layer": layer, "enabled": p.get("enabled", True), "comments": p.get("comments", ""),
            "action": self._profile_ref(p.get("action", "Optimized")),
            "protected-scope": self._refs("protected-scope", p.get("protected-scope", "Any")),
            "protected-scope-negate": bool(p.get("protected-scope-negate", False)),
            "source": self._refs("source", p.get("source", "Any")),
            "source-negate": bool(p.get("source-negate", False)),
            "destination": self._refs("destination", p.get("destination", "Any")),
            "destination-negate": bool(p.get("destination-negate", False)),
            "service": self._refs("service", p.get("service", "Any"), validate=False),
            "service-negate": bool(p.get("service-negate", False)),
            "track": {"uid": _uid(), "name": self._track(p.get("track", "None"), _THREAT_TRACKS), "type": "Track"},
            "track-settings": {"packet-capture": False},
            "install-on": self._refs("install-on", p.get("install-on", "Policy Targets")),
            "domain": self._domain_obj(None), "meta-info": self._meta(), "_request": copy.deepcopy(p),
        }
        return rule

    def _rule_reply(self, rule: Dict[str, Any], number: Optional[int] = None) -> Dict[str, Any]:
        out = self._public(rule)
        if number is not None:
            out["rule-number"] = number
        return out

    def _find_rule(self, p: Dict[str, Any], obj_type: str, layers: Dict[str, str]) -> Tuple[str, Dict[str, Any]]:
        layer = self._layer_name(p.get("layer"), layers)
        names = self.state.rulebases.get(layer, [])
        objs = self.state.objects[obj_type]
        if "uid" in p:
            for n in names:
                if objs[n]["uid"] == p["uid"]:
                    return layer, objs[n]
            raise _not_found(p["uid"])
        if "rule-number" in p:
            num = p["rule-number"]
            if isinstance(num, int) and not isinstance(num, bool) and 1 <= num <= len(names):
                return layer, objs[names[num - 1]]
            raise _not_found("rule number %s" % num)
        if "name" not in p:
            raise _missing("name")
        for n in names:
            if n.lower() == str(p["name"]).lower():
                return layer, objs[n]
        raise _not_found(p["name"])

    def _c_show_threat_rule(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        layer, rule = self._find_rule(p, "threat-rule", self._threat_layers())
        return self._rule_reply(rule, self.state.rulebases[layer].index(rule["name"]) + 1)

    def _c_add_threat_rule(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        layer = self._layer_name(p.get("layer"), self._threat_layers())
        if "position" not in p:
            raise _missing("position")
        if "locked" in self.scenarios:
            msg = "Object '%s' is locked by another session (admin@SmartConsole)" % layer
            raise _ApiError(409, "generic_err_object_locked", msg, errors=[
                {"message": msg, "current-session": False}])
        name = str(p.get("name", ""))
        if name and any(n.lower() == name.lower() for n in self.state.objects["threat-rule"]):
            raise _validation("More than one rule named '%s' exists in layer '%s'." % (name, layer))
        if not name:
            name = "Rule-%s" % secrets.token_hex(3)
        rule = self._make_threat_rule(dict(p, name=name), layer)
        self._position_index(self.state.rulebases.setdefault(layer, []), p["position"])
        self.state.objects["threat-rule"][name] = rule
        self._insert_rule(layer, name, p["position"])
        self._changed()
        return self._rule_reply(rule)

    def _c_set_threat_rule(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        layer, rule = self._find_rule(p, "threat-rule", self._threat_layers())
        new = dict(rule)
        if "action" in p:
            new["action"] = self._profile_ref(p["action"])
        for field in ("protected-scope", "source", "destination", "install-on", "service"):
            if field in p:
                new[field] = self._apply_ref_update(rule[field], field, p[field], validate=field != "service")
        for field in ("protected-scope-negate", "source-negate", "destination-negate", "service-negate", "enabled"):
            b = self._bool(p, field)
            if b is not None:
                new[field] = b
        if "track" in p:
            new["track"] = {"uid": _uid(), "name": self._track(p["track"], _THREAT_TRACKS), "type": "Track"}
        if "comments" in p:
            new["comments"] = p["comments"]
        new["_request"] = copy.deepcopy(p)
        rules = self.state.rulebases[layer]
        old_name = rule["name"]
        if p.get("new-name"):
            new["name"] = str(p["new-name"])
            rules[rules.index(old_name)] = new["name"]
            self.state.objects["threat-rule"].pop(old_name, None)
        self.state.objects["threat-rule"][new["name"]] = new
        if "new-position" in p:
            rules.remove(new["name"])
            rules.insert(self._position_index(rules, p["new-position"], "new-position"), new["name"])
        self._changed()
        return self._rule_reply(new)

    def _c_delete_threat_rule(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        layer, rule = self._find_rule(p, "threat-rule", self._threat_layers())
        self.state.rulebases[layer].remove(rule["name"])
        self.state.objects["threat-rule"].pop(rule["name"], None)
        self._changed()
        return {"message": "OK"}

    # ------------------------------------------------------------------ hosts

    def _c_show_host(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        self._details_level(p)
        return self._public(self._find_by("host", p))

    def _c_show_objects(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        level = self._details_level(p)
        otype = str(p.get("type", "object"))
        flt = str(p.get("filter", "") or "")
        ip_only = bool(p.get("ip-only", False))
        types = ("host", "network", "group") if otype == "object" else (otype,)
        items: List[Dict[str, Any]] = []
        for t in types:
            for name, obj in sorted(self.state.objects.get(t, {}).items()):
                if flt:
                    if ip_only:
                        if flt not in (obj.get("ipv4-address"), obj.get("ipv6-address")):
                            continue
                    elif flt.lower() not in name.lower() and flt not in json.dumps(self._public(obj)):
                        continue
                pub = self._public(obj)
                if level == "uid":
                    items.append(pub["uid"])
                elif level == "standard":
                    items.append({k: pub[k] for k in ("uid", "name", "type", "domain", "ipv4-address",
                                                      "ipv6-address", "comments") if k in pub})
                else:
                    items.append(pub)
        chunk, meta = self._page(items, p)
        return dict(meta, objects=chunk)

    def _c_add_host(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        name = p.get("name")
        if not name:
            raise _missing("name")
        ip = p.get("ip-address", p.get("ipv4-address", p.get("ipv6-address")))
        if ip is None:
            raise _missing("ip-address")
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            raise _invalid("Invalid parameter for [ip-address]. Invalid IP address [%s]" % ip) from None
        existing = self.state.objects["host"].get(name)
        if existing is not None and not p.get("set-if-exists"):
            raise _validation("More than one object named '%s' exists." % name)
        same_ip = [n for n, o in self.state.objects["host"].items()
                   if n != name and str(addr) in (o.get("ipv4-address"), o.get("ipv6-address"))]
        if same_ip and not p.get("ignore-warnings"):
            raise _validation_warning("More than one object have the same IP address %s" % addr)
        obj = {"uid": existing["uid"] if existing else _uid(), "name": name, "type": "host",
               "comments": p.get("comments", ""), "color": p.get("color", "black"), "tags": [], "groups": [],
               "interfaces": [], "nat-settings": {"auto-rule": False}, "domain": self._domain_obj(ctx.session),
               "meta-info": self._meta(), "read-only": False, "icon": "Objects/host", "_request": copy.deepcopy(p)}
        obj["ipv4-address" if addr.version == 4 else "ipv6-address"] = str(addr)
        self.state.objects["host"][name] = obj
        self._changed()
        return self._public(obj)

    def _c_set_host(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        obj = self._find_by("host", p)
        new = dict(obj)
        ip = p.get("ip-address", p.get("ipv4-address", p.get("ipv6-address")))
        if ip is not None:
            try:
                addr = ipaddress.ip_address(str(ip))
            except ValueError:
                raise _invalid("Invalid parameter for [ip-address]. Invalid IP address [%s]" % ip) from None
            new.pop("ipv4-address", None)
            new.pop("ipv6-address", None)
            new["ipv4-address" if addr.version == 4 else "ipv6-address"] = str(addr)
        for key in ("comments", "color"):
            if key in p:
                new[key] = p[key]
        new["_request"] = copy.deepcopy(p)
        if p.get("new-name"):
            self.state.objects["host"].pop(obj["name"], None)
            new["name"] = str(p["new-name"])
        self.state.objects["host"][new["name"]] = new
        self._changed()
        return self._public(new)

    def _c_delete_host(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        obj = self._find_by("host", p)
        for rtype in ("threat-rule", "https-rule"):
            for rname, rule in self.state.objects[rtype].items():
                for field in ("protected-scope", "source", "destination"):
                    if any(r.get("uid") == obj["uid"] for r in rule.get(field, [])):
                        raise _validation("Object '%s' is in use by rule '%s' (%s)" % (obj["name"], rname, field))
        self.state.objects["host"].pop(obj["name"], None)
        self._changed()
        return {"message": "OK"}

    # ------------------------------------------------------------------ publish / discard / install / tasks

    def _c_publish(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        fail = "publish_fails" in self.scenarios
        n = self.state.changes
        tid = self._new_task(
            "Publish operation", kind="publish", fail=fail,
            details_ok=[{"statusCode": "succeeded", "statusDescription": "Published %d changes" % n}],
            details_fail=[{"statusCode": "failed", "statusDescription": "Publish failed",
                           "stagesInfo": [{"stage": "Validation", "messages": [
                               {"type": "err", "message": "Validation failed: the session has invalid objects"}]}]}],
            comments_fail="Publish failed")
        if not fail:
            self._snapshot = self._take_snapshot()
            self.state.published = True
            self.state.publish_count += 1
            self.state.dirty = False
            self.state.changes = 0
        return {"task-id": tid}

    def _c_discard(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        n = self.state.changes
        snap = copy.deepcopy(self._snapshot)
        self.state.objects = AttrDict(snap["objects"])
        self.state.rulebases = snap["rulebases"]
        self.state.gateways = snap["gateways"]
        self.state.outbound_cert = snap["outbound_cert"]
        self.state.dirty = False
        self.state.changes = 0
        self.state.discards += 1
        return {"message": "OK", "number-of-discarded-changes": n}

    def _install_error_text(self, gw: str) -> Tuple[int, str]:
        prefix = self._ai_prefix()
        for layer_rules in self.state.rulebases.values():
            for i, rname in enumerate(layer_rules):
                rule = self.state.objects["threat-rule"].get(rname)
                if rule is None:
                    continue
                prof = self.state.objects["threat-profile"].get(rule["action"]["name"], {})
                if prof.get(prefix):
                    return i + 1, prof["name"]
        return 1, "AIGuard-Demo"

    def _c_install_policy(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        if not p.get("policy-package"):
            raise _missing("policy-package")
        pkg = self._find_package({"name": p["policy-package"]})
        names = self._gateway_names()
        targets = []
        for t in _as_list(p.get("targets")) or list(self.state.gateways):
            real = names.get(str(t).lower())
            if real is None:
                for n, d in self.state.gateways.items():
                    if d["uid"] == t:
                        real = n
            if real is None:
                raise _not_found(t)
            targets.append(real)
        access = p.get("access", True)
        tp = p.get("threat-prevention", True)
        for key in ("access", "threat-prevention"):
            self._bool(p, key)
        record = {"policy-package": pkg["name"], "targets": targets, "access": access, "threat-prevention": tp}
        self.state.installs.append(record)
        if "partial_install_failed" in self.scenarios and access:
            return self._partial_install(pkg, targets, tp)
        fail = "install_fails" in self.scenarios
        rule_no, profile = self._install_error_text(targets[0] if targets else "HQ-GW")
        gw0 = targets[0] if targets else "HQ-GW"
        msg = ("Rule %d uses profile %s. AI Agent Security is not supported by the software on %s."
               % (rule_no, profile, gw0))
        ok_details = [{"gatewayName": t, "gatewayId": self.state.gateways[t]["uid"], "statusCode": "succeeded",
                       "statusDescription": "Policy installation succeeded on %s" % t,
                       "stagesInfo": [{"stage": "Installation", "messages": []}]} for t in targets]
        fail_details = [{"gatewayName": gw0, "gatewayId": self.state.gateways[gw0]["uid"] if gw0 in
                         self.state.gateways else "", "statusCode": "failed",
                         "statusDescription": "Policy installation failed on %s" % gw0,
                         "stagesInfo": [{"stage": "Verification", "messages": [{"type": "err", "message": msg}]}]}]
        tid = self._new_task("Policy installation - %s" % pkg["name"], kind="install", fail=fail,
                             details_ok=ok_details, details_fail=fail_details,
                             comments_fail="Policy installation failed on %s" % gw0,
                             description="Installing policy %s on %s" % (pkg["name"], ", ".join(targets)))
        if fail:
            self.state.install_failures += 1
        else:
            self.state.installed = True
            self.state.install_count += 1
            self._mark_installed(targets, pkg["name"], access=bool(access), threat=bool(tp),
                                 at=self.state.tasks[tid]["start"])
        return {"task-id": tid}

    def _mark_installed(self, targets: List[str], package: str, *, access: bool, threat: bool,
                        at: datetime.datetime) -> None:
        when = at + datetime.timedelta(seconds=1)
        for t in targets:
            pol = self.state.policies.setdefault(t, {})
            for kind, on in (("access", access), ("threat", threat)):
                if on:
                    pol[kind] = {"name": package, "installed": True, "at": when, "revision": _uid()}

    def _partial_install(self, pkg: Dict[str, Any], targets: List[str], tp: bool) -> Dict[str, Any]:
        gw0 = targets[0] if targets else "HQ-GW"
        stages = [{"stage": "Access Control", "messages": [{"type": "err", "message": LAB_DATA_TYPES_ERROR}]}]
        if tp:
            stages.append({"stage": "Threat Prevention", "messages": [
                {"type": "info", "message": "Threat Prevention policy installed successfully"}]})
        details = [{"gatewayName": gw0, "gatewayId": self.state.gateways.get(gw0, {}).get("uid", ""),
                    "statusCode": "failed", "statusDescription": "Policy installation failed on %s" % gw0,
                    "stagesInfo": stages}]
        tid = self._new_task("Policy installation - %s" % pkg["name"], kind="install", fail=True,
                             details_fail=details, comments_fail="Policy installation failed on %s" % gw0,
                             description="Installing policy %s on %s" % (pkg["name"], ", ".join(targets)))
        self.state.tasks[tid]["fail_status"] = self.partial_install_status
        self.state.install_failures += 1
        if tp:
            self._mark_installed(targets, pkg["name"], access=False, threat=True,
                                 at=self.state.tasks[tid]["start"])
        return {"task-id": tid}

    def _c_show_task(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        if "task-id" not in p:
            raise _missing("task-id")
        level = self._details_level(p)
        views = []
        for tid in _as_list(p["task-id"]):
            t = self.state.tasks.get(tid)
            if t is None:
                raise _not_found(tid)
            views.append(self._task_view(t, level == "full"))
        return {"tasks": views}

    def _c_show_tasks(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        level = self._details_level(p)
        status = p.get("status", "all")
        if status not in ("successful", "failed", "in-progress", "all"):
            raise _invalid("Invalid value [%s] for parameter [status]. Valid values: successful, failed, "
                           "in-progress, all" % status)
        since = None
        if p.get("from-date"):
            try:
                since = datetime.datetime.fromisoformat(str(p["from-date"]).replace("Z", "+00:00"))
            except ValueError:
                raise _invalid("Invalid value [%s] for parameter [from-date]" % p["from-date"]) from None
            if since.tzinfo is None:
                since = since.replace(tzinfo=datetime.timezone.utc)
        views: List[Dict[str, Any]] = []
        for t in self.state.tasks.values():   # this run's tasks, without counting as a poll
            done = t["polls"] >= t["polls_needed"]
            st = ("in progress" if not done else (t.get("fail_status") or "failed") if t["fail"]
                  else "succeeded")
            v = {"uid": t["task-id"], "type": "task", "task-id": t["task-id"], "task-name": t["task-name"],
                 "status": st, "progress-percentage": 100 if done else 30,
                 "progress-description": t["description"], "suppressed": False,
                 "start-time": _api_date(t["start"]), "last-update-time": _api_date(t["start"]),
                 "comments": t["comments_fail"] if done and t["fail"] else "", "color": "black",
                 "task-details": copy.deepcopy((t["details_fail"] if t["fail"] else t["details_ok"]) if done
                                               else [])}
            views.append(v)
        views.extend(copy.deepcopy(self.task_history))
        out = []
        for v in views:
            st = v.get("status")
            if status == "successful" and st not in ("succeeded", "succeeded with warnings"):
                continue
            if status == "failed" and st not in ("failed", "partially succeeded"):
                continue
            if status == "in-progress" and st != "in progress":
                continue
            upd = (v.get("last-update-time") or {}).get("posix") or (v.get("start-time") or {}).get("posix") or 0
            if since is not None and upd < since.timestamp() * 1000:
                continue
            if level != "full":
                v.pop("task-details", None)
            out.append(v)
        out.sort(key=lambda v: ((v.get("last-update-time") or {}).get("posix") or 0), reverse=True)
        chunk, meta = self._page(out, p)
        return dict(meta, tasks=chunk)

    def _c_run_script(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        if "script_denied" in self.scenarios:
            raise _ApiError(403, "generic_err_permission_denied", "Run one time script permission is required")
        name = p.get("script-name") or p.get("uid")
        if not name:
            raise _missing("script-name")
        targets_in = _as_list(p.get("targets"))
        if not targets_in:
            raise _missing("targets")
        stype = p.get("script-type", "one time")
        if stype not in ("one time", "repository"):
            raise _invalid("Invalid value [%s] for parameter [script-type]. Valid values: repository, one time" % stype)
        script = p.get("script")
        if script is None and "script-base64" in p:
            try:
                script = base64.b64decode(str(p["script-base64"]), validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                raise _invalid("Invalid parameter for [script-base64]") from None
        if stype == "one time" and script is None:
            raise _missing("script")
        names = self._gateway_names()
        targets = []
        for t in targets_in:
            real = names.get(str(t).lower())
            if real is None:
                real = next((m for m in self._members if m.lower() == str(t).lower()), None)
            if real is None:
                raise _not_found(t)
            targets.append(real)
        self.state.scripts.append({"script-name": name, "script-type": stype, "script": script, "targets": targets,
                                   "timeout": p.get("timeout")})
        if script and "prompt_injection_moderated_content_enable" in script:
            m = re.search(r"prompt_injection_moderated_content_enable\s+-v\s+(true|false)", script)
            if m:
                for t in targets:
                    self.state.moderation[t] = m.group(1) == "true"
        ok = base64.b64encode(b"ok").decode("ascii")
        details = [{"target": t, "gatewayName": t, "statusCode": "succeeded",
                    "statusDescription": "Script finished running successfully on %s" % t,
                    "responseMessage": ok, "responseError": ""} for t in targets]
        tid = self._new_task(name, kind="script", details_ok=details)
        reply: Dict[str, Any] = {"tasks": [{"target": t, "task-id": tid} for t in targets]}
        if "script_tasks_only" not in self.scenarios:
            reply["task-id"] = tid
        return reply

    # ------------------------------------------------------------------ logs

    def _c_show_logs(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        if "query-id" in p:
            return {"logs": [], "logs-count": 0, "query-id": p["query-id"]}
        nq = p.get("new-query")
        if nq is None:
            raise _missing("new-query")
        if not isinstance(nq, dict):
            raise _invalid("Invalid parameter for [new-query]")
        tf = nq.get("time-frame", "last-24-hours")
        if tf not in _TIME_FRAMES:
            raise _invalid("Invalid value [%s] for parameter [time-frame]" % tf)
        try:
            limit = int(nq.get("max-logs-per-request", 100))
        except (TypeError, ValueError):
            raise _invalid("Invalid parameter for [max-logs-per-request]") from None
        if not 1 <= limit <= 100:
            raise _invalid("Invalid parameter for [max-logs-per-request]. The value must be between 1 and 100")
        self.state.log_queries.append(copy.deepcopy(nq))
        if nq.get("type", "logs") == "audit":
            logs: List[Dict[str, Any]] = []
        else:
            flt = str(nq.get("filter", "") or "")
            logs = [copy.deepcopy(entry) for entry in reversed(self.state.logs) if _log_matches(entry, flt)]
        page = logs[:limit]
        return {"logs": page, "logs-count": len(page), "query-id": "q_" + _uid()}

    # ------------------------------------------------------------------ AI Agent Security

    def _c_test_ai_agent_security_api_key(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        key = p.get("api-key")
        profile = p.get("profile-name")
        if key is None and profile is None:
            raise _missing("api-key")
        if key is not None and not (isinstance(key, str) and re.fullmatch(r"[0-9a-fA-F]{64}", key)):
            raise _invalid("api-key must be a 64-character hex string")
        if profile is not None:
            prof = self._find_by("threat-profile", {"name": profile})
            if not prof.get("_secret"):
                return {"success": False, "message": "Profile '%s' has no AI Agent Security API key." % profile}
        if "bad_ai_key" in self.scenarios:
            return {"success": False, "message": "Invalid API key"}
        project = p.get("project-id")
        if project and self.ai_projects is not None and project not in self.ai_projects:
            return {"success": False, "message": "Project [%s] does not belong to this API key." % project}
        return {"success": True, "message": "API key is valid."}

    _c_test_ai_guard_api_key = _c_test_ai_agent_security_api_key

    # ------------------------------------------------------------------ HTTPS inspection

    def _c_show_outbound_inspection_certificate(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        self._details_level(p)
        if "outbound_needs_name" in self.scenarios and "name" not in p and "uid" not in p:
            raise _ApiError(400, "generic_err_missing_required_parameters",
                            "Missing parameter: [uid] or [name]")
        default = next((c for c in self.outbound_certs if c.get("is-default")), None)
        if not self.state.outbound_cert or not self.outbound_certs:
            raise _not_found(p.get("name") or p.get("uid") or "Outbound Certificate")
        if "name" in p or "uid" in p:
            entry = next((c for c in self.outbound_certs if ("name" in p and str(p["name"]).lower() ==
                                                             c["name"].lower()) or p.get("uid") == c["uid"]), None)
        else:
            entry = default
        if entry is None:
            raise _not_found(p.get("name") or p.get("uid") or "default outbound certificate")
        name = entry["name"]
        cert = self.pki.ca_cert
        try:
            from cryptography.hazmat.primitives.serialization import pkcs12
            p12 = pkcs12.serialize_key_and_certificates(b"outbound", None, cert, None,
                                                        serialization.NoEncryption())
        except Exception:  # pragma: no cover - older cryptography
            p12 = self.pki.ca_der
        out = {"uid": entry["uid"], "name": name, "type": "outbound-inspection-certificate",
               "domain": self._domain_obj(ctx.session), "meta-info": self._meta(), "read-only": False,
               "comments": "", "tags": [], "icon": "subject_user_certificate",
               "issued-by": self.pki.ca_issuer_dn, "subject": self.pki.ca_issuer_dn,
               "valid-from": cert.not_valid_before_utc.strftime("%d-%b-%y"),
               "valid-to": cert.not_valid_after_utc.strftime("%d-%b-%y"),
               "base64-certificate": base64.b64encode(p12).decode("ascii")}
        if ctx.ver >= (2, 0, 0):
            out.update({"base64-public-certificate": entry.get("pem") or self.outbound_ca_pem,
                        "is-default": bool(entry.get("is-default")),
                        "public-key-algorithm": "ecdsa-p-256"})
        return out

    def _c_show_outbound_inspection_certificates(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        level = self._details_level(p)
        items = []
        if self.state.outbound_cert:
            for c in sorted(self.outbound_certs, key=lambda c: c["name"].lower()):   # sorted by name
                o = {"uid": c["uid"], "name": c["name"], "type": "outbound-inspection-certificate",
                     "domain": self._domain_obj(ctx.session)}
                if level == "full":
                    o["is-default"] = bool(c.get("is-default"))
                items.append(o)
        chunk, meta = self._page(items, p)
        return dict(meta, objects=chunk)

    def _make_https_rule(self, p: Dict[str, Any], layer: str) -> Dict[str, Any]:
        action = self._enum(p, "action", _HTTPS_ACTIONS) or "Inspect"
        blades = []
        for b in _as_list(p.get("blade")):
            match = next((a for a in _HTTPS_BLADES if isinstance(b, str) and a.lower() == b.lower()), None)
            if match is None:
                raise _invalid("Invalid value [%s] for parameter [blade]. Valid values: %s"
                               % (b, ", ".join(_HTTPS_BLADES)))
            blades.append({"uid": _uid(), "name": match, "type": "Internal"})
        track = self._track(p.get("track", "None"), ("None", "Log", "Alert", "Mail", "SNMP trap", "User Alert 1",
                                                      "User Alert 2", "User Alert 3"))
        return {
            "uid": _uid(), "name": p.get("name", ""), "type": "https-rule", "layer": self._https_layers().get(layer),
            "_layer": layer, "enabled": p.get("enabled", True), "comments": p.get("comments", ""),
            "action": {"uid": _uid(), "name": action, "type": "RulebaseAction"},
            "source": self._refs("source", p.get("source", "Any")), "source-negate": bool(p.get("source-negate")),
            "destination": self._refs("destination", p.get("destination", "Any")),
            "destination-negate": bool(p.get("destination-negate")),
            "service": self._refs("service", p.get("service", "Any"), validate=False),
            "site-category": self._refs("site-category", p.get("site-category", "Any"), validate=False),
            "blade": blades or [{"uid": _uid(), "name": "Any", "type": "Internal"}],
            "certificate": {"uid": self._outbound_uid, "name": p.get("certificate", "Outbound Certificate"),
                            "type": "outbound-inspection-certificate"},
            "track": {"uid": _uid(), "name": track, "type": "Track"},
            "install-on": self._refs("install-on", p.get("install-on", "Policy Targets")),
            "domain": self._domain_obj(None), "meta-info": self._meta(), "_request": copy.deepcopy(p),
        }

    def _c_show_https_rulebase(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        layer = self._layer_name(p.get("name", p.get("uid")), self._https_layers())
        rules = [self._rule_reply(self.state.objects["https-rule"][n], i + 1)
                 for i, n in enumerate(self.state.rulebases.get(layer, []))]
        chunk, meta = self._page(rules, p)
        return dict(meta, uid=self._https_layers()[layer], name=layer, rulebase=chunk, **{"objects-dictionary": []})

    def _c_show_https_rule(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        layer, rule = self._find_rule(p, "https-rule", self._https_layers())
        return self._rule_reply(rule, self.state.rulebases[layer].index(rule["name"]) + 1)

    def _c_add_https_rule(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        layer = self._layer_name(p.get("layer"), self._https_layers())
        if "position" not in p:
            raise _missing("position")
        name = str(p.get("name", "")) or "HTTPS-Rule-%s" % secrets.token_hex(3)
        if any(n.lower() == name.lower() for n in self.state.objects["https-rule"]):
            raise _validation("More than one rule named '%s' exists in layer '%s'." % (name, layer))
        rule = self._make_https_rule(dict(p, name=name), layer)
        self._position_index(self.state.rulebases.setdefault(layer, []), p["position"])
        self.state.objects["https-rule"][name] = rule
        self._insert_rule(layer, name, p["position"])
        self._changed()
        return self._rule_reply(rule)

    def _c_set_https_rule(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        if ctx.ver < (2, 0, 0) and "uid" not in p and "rule-number" not in p:
            # v1.9.1: TLSRuleIdentifierRequest is uid or rule-number; "name" renames the rule
            raise _missing("uid")
        layer, rule = self._find_rule(p, "https-rule", self._https_layers())
        merged = dict(rule["_request"])
        merged.update({k: v for k, v in p.items() if k not in ("uid", "rule-number", "new-name", "new-position")})
        merged["name"] = rule["name"]
        new = self._make_https_rule(merged, layer)
        new["uid"] = rule["uid"]
        rules = self.state.rulebases[layer]
        if p.get("new-name"):
            new["name"] = str(p["new-name"])
            rules[rules.index(rule["name"])] = new["name"]
            self.state.objects["https-rule"].pop(rule["name"], None)
        self.state.objects["https-rule"][new["name"]] = new
        if "new-position" in p:
            rules.remove(new["name"])
            rules.insert(self._position_index(rules, p["new-position"], "new-position"), new["name"])
        self._changed()
        return self._rule_reply(new)

    def _c_delete_https_rule(self, ctx: "_Ctx", p: Dict[str, Any]) -> Dict[str, Any]:
        layer, rule = self._find_rule(p, "https-rule", self._https_layers())
        self.state.rulebases[layer].remove(rule["name"])
        self.state.objects["https-rule"].pop(rule["name"], None)
        self._changed()
        return {"message": "OK"}


class _Ctx(object):
    __slots__ = ("session", "ver", "ver_str", "headers", "client_ip", "command")

    def __init__(self, session: Optional[Dict[str, Any]], ver: Tuple[int, int, int], ver_str: str,
                 headers: Headers, client_ip: str, command: str):
        self.session = session
        self.ver = ver
        self.ver_str = ver_str
        self.headers = headers
        self.client_ip = client_ip
        self.command = command


def _command_description(name: str) -> str:
    if name in _AI_COMMANDS:
        return ("Test the validity of an AI Agent Security API key. Optionally validates that a project ID "
                "belongs to the key.")
    verb = name.split("-", 1)[0]
    return {"show": "Retrieve existing object(s).", "add": "Create new object.",
            "set": "Edit existing object using object name or uid.",
            "delete": "Delete existing object using object name or uid."}.get(verb, "Run %s." % name)


def _log_matches(log: Dict[str, Any], flt: str) -> bool:
    """Tiny SmartLog-style filter: ``field:value`` terms joined by AND / OR, optional NOT,
    free text matches anywhere. Unknown syntax degrades to a substring match."""
    flt = flt.strip()
    if not flt:
        return True
    for term in re.split(r"\s+AND\s+", flt, flags=re.IGNORECASE):
        term = term.strip()
        neg = False
        if term.upper().startswith("NOT "):
            neg, term = True, term[4:].strip()
        alts = re.split(r"\s+OR\s+", term.strip("()"), flags=re.IGNORECASE)
        ok = any(_term_matches(log, a) for a in alts)
        if ok == neg:
            return False
    return True


def _term_matches(log: Dict[str, Any], term: str) -> bool:
    term = term.strip().strip("()")
    m = re.match(r"^([A-Za-z_][\w\-]*)\s*:\s*(.+)$", term)
    if not m:
        return term.strip('"').lower() in json.dumps(log).lower()
    field, value = m.group(1).lower(), m.group(2).strip().strip('"').lower()
    for key in _LOG_FILTER_FIELDS.get(field, (field,)):
        v = log.get(key)
        if v is None:
            continue
        text = str(v).lower()
        if field in ("src", "source", "dst", "destination"):
            if text == value:
                return True
            if key == "dst" and any(str(a.get("resolved", "")).lower() == value for a in log.get("dst_attr", [])):
                return True
        elif value in text:
            return True
    return False


# ===========================================================================
# Fake LLM provider (and gateway block behaviours)
# ===========================================================================

PROVIDER_BEHAVIORS = ("allow", "provider401", "usercheck", "redirect", "reset", "timeout", "html_other")
USERCHECK_REDIRECT = "https://10.1.1.111/UserCheck/PortalMain?IID=abc"

# Optional keyword rules that make FakeProviderServer act like a gateway enforcing AI Agent Security
# (assign to ``server.rules``). Matching is case-insensitive on the prompt text.
GATEWAY_LIKE_RULES: List[Tuple[str, str]] = [
    ("ignore all previous instructions", "usercheck"),
    ("ignore previous instructions", "usercheck"),
    ("do anything now", "usercheck"),
    ("4111 1111 1111 1111", "usercheck"),
    ("078-05-1120", "usercheck"),
    ("threatening message", "reset"),
    ("profanity", "reset"),
    ("inferior", "reset"),
]

_USERCHECK_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Check Point UserCheck</title></head>
<body class="usercheck">
<div id="usercheck-portal">
<h1>Check Point</h1>
<h2>UserCheck - Access blocked</h2>
<p>This request was blocked by your organization's security policy (AI Agent Security).</p>
<p>Reference: {ref}</p>
</div>
</body></html>
"""


class FakeProviderServer(_FakeServerBase):
    """HTTPS server posing as an LLM API on any path.

    Behaviour per request: header ``X-Fake-Behavior`` if present, else ``default_behavior``,
    else the first ``rules`` entry ``(substring, behavior)`` found (case-insensitive) in the
    JSON body's string values (the prompt), else "allow". Behaviours: see PROVIDER_BEHAVIORS.
    ``requests``: dicts with method, path, headers, body (bytes), json, prompt, behavior.
    ``timeout`` stalls until the client hangs up (or ``timeout_cap`` seconds, default 5)."""

    server_header = "FakeProvider/1.0"

    def __init__(self, pki: FakePKI, *, default_behavior: Optional[str] = None,
                 rules: Optional[Iterable[Tuple[str, str]]] = None, timeout_cap: float = 5.0,
                 host: str = "127.0.0.1"):
        super().__init__(pki, host=host)
        self.default_behavior = default_behavior
        self.rules: List[Tuple[str, str]] = list(rules or [])
        self.timeout_cap = float(timeout_cap)
        self.redirect_location = USERCHECK_REDIRECT
        self.requests: List[Dict[str, Any]] = []

    def choose(self, headers: Headers, prompt: str) -> str:
        forced = headers.get("X-Fake-Behavior")
        if forced:
            return str(forced).strip()
        if self.default_behavior:
            return self.default_behavior
        low = prompt.lower()
        for needle, behavior in self.rules:
            if needle.lower() in low:
                return behavior
        return "allow"

    def _dispatch(self, req: _Request) -> _Reply:
        try:
            parsed = req.json()
        except (ValueError, UnicodeDecodeError):
            parsed = None
        prompt = "\n".join(_collect_strings(parsed)) if parsed is not None else req.body.decode("utf-8", "replace")
        behavior = self.choose(req.headers, prompt)
        with self.lock:
            self.requests.append({"method": req.method, "path": req.path, "headers": req.headers, "body": req.body,
                                  "json": parsed, "prompt": prompt, "behavior": behavior, "time": _now()})
        if behavior == "allow":
            return _json_reply(200, {"id": "chatcmpl-x", "choices": [{"message": {"content": "ok"}}]})
        if behavior == "provider401":
            return _json_reply(401, {"error": {"message": "Incorrect API key"}})
        if behavior == "usercheck":
            return _html_reply(403, _USERCHECK_HTML.format(ref=secrets.token_hex(4)))
        if behavior == "redirect":
            return _html_reply(302, "<html><body>Redirecting to <a href=\"%s\">UserCheck</a></body></html>"
                               % self.redirect_location, headers=[("Location", self.redirect_location)])
        if behavior == "reset":
            return _Reply(action="reset")
        if behavior == "timeout":
            return _Reply(action="timeout", wait=min(self.timeout_cap, 5.0))
        if behavior == "html_other":
            return _html_reply(200, "<html>hello</html>")
        return _Reply(500, ("unknown fake behavior %r; use one of %s" % (behavior, ", ".join(PROVIDER_BEHAVIORS)))
                      .encode("utf-8"), "text/plain")


# ===========================================================================
# Fake Lakera Guard
# ===========================================================================

DEFAULT_LAKERA_DETECTORS: List[str] = [
    "prompt_attack", "moderated_content/crime", "moderated_content/hate", "moderated_content/profanity",
    "moderated_content/sexual", "moderated_content/violence", "moderated_content/weapons",
    "pii/credit_card", "pii/us_social_security_number", "pii/email", "unknown_links",
]

DEFAULT_LAKERA_RULES: List[Tuple[str, List[str]]] = [
    ("ignore all previous instructions", ["prompt_attack"]),
    ("ignore previous instructions", ["prompt_attack"]),
    ("do anything now", ["prompt_attack"]),
    ("4111 1111 1111 1111", ["pii/credit_card"]),
    ("078-05-1120", ["pii/us_social_security_number"]),
    ("threatening message", ["moderated_content/violence"]),
    ("profanity", ["moderated_content/profanity"]),
    ("inferior", ["moderated_content/hate"]),
]


def _detector_id(detector_type: str) -> str:
    slug = "pinj" if detector_type == "prompt_attack" else re.sub(r"[/_]+", "-", detector_type)
    return "detector-lakera-%s-user-content" % slug


class FakeLakeraServer(_FakeServerBase):
    """Lakera Guard API: ``POST /v2/guard`` and ``POST /v2/policies/health``.

    ``valid_key`` (Bearer token; generated: 64 hex chars), ``projects`` (valid project ids;
    ``project_id`` is the first), ``rules`` [(substring, [detector_type, ...])],
    ``action`` "enforce" | "detect", ``detectors`` (types always present in the breakdown),
    ``health_mode`` "http" (unknown project -> HTTP 400) or "status" (HTTP 200, status "error"),
    ``force_error`` (status, message) to make every request fail (e.g. (429, "Too Many Requests")).
    ``requests``: dicts with method, path, headers, body, json."""

    server_header = "uvicorn"

    def __init__(self, pki: FakePKI, *, valid_key: Optional[str] = None,
                 project_ids: Optional[Iterable[str]] = None,
                 rules: Optional[Iterable[Tuple[str, Sequence[str]]]] = None, action: str = "enforce",
                 detectors: Optional[Iterable[str]] = None, host: str = "127.0.0.1"):
        super().__init__(pki, host=host)
        self.valid_key = valid_key or secrets.token_hex(32)
        ids = list(project_ids) if project_ids is not None else ["project-%010d" % secrets.randbelow(10 ** 10)]
        self.projects: Set[str] = set(ids)
        self.project_id = ids[0] if ids else None
        self.rules: List[Tuple[str, List[str]]] = [(s, list(d)) for s, d in (
            rules if rules is not None else DEFAULT_LAKERA_RULES)]
        self.action = action
        self.detectors: List[str] = list(detectors if detectors is not None else DEFAULT_LAKERA_DETECTORS)
        self.health_mode = "http"
        self.force_error: Optional[Tuple[int, str]] = None
        self.requests: List[Dict[str, Any]] = []

    def _err(self, status: int, message: str, request_id: Optional[str] = None) -> _Reply:
        return _json_reply(status, {"error": message, "code": status, "request_id": request_id or "req_" + _uid()})

    def _dispatch(self, req: _Request) -> _Reply:
        path = urlsplit(req.path).path.rstrip("/")
        try:
            parsed = req.json()
        except (ValueError, UnicodeDecodeError):
            parsed = None
        with self.lock:
            self.requests.append({"method": req.method, "path": path, "headers": req.headers, "body": req.body,
                                  "json": parsed, "time": _now()})
        if path not in ("/v2/guard", "/v2/policies/health"):
            return self._err(404, "Not Found")
        if req.method != "POST":
            return self._err(405, "Method Not Allowed")
        auth = req.headers.get("Authorization") or ""
        token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        if not token or not _same(token, self.valid_key):
            return _json_reply(401, {"error": "Unauthorized", "code": 401, "request_id": "r1"})
        if self.force_error is not None:
            return self._err(self.force_error[0], self.force_error[1])
        if not isinstance(parsed, dict):
            return self._err(400, "Request body must be a JSON object")
        if path == "/v2/policies/health":
            return self._health(parsed)
        return self._guard(parsed)

    def _health(self, body: Dict[str, Any]) -> _Reply:
        pid = body.get("project_id")
        if not pid:
            return self._err(400, "project_id is required")
        if pid not in self.projects:
            if self.health_mode == "status":
                return _json_reply(200, {"status": "error", "is_default": False,
                                         "message": "project with policy not found", "lint": []})
            return self._err(400, "project with policy not found")
        return _json_reply(200, {"status": "ok", "is_default": False, "message": "", "lint": []})

    def _guard(self, body: Dict[str, Any]) -> _Reply:
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            return self._err(400, "messages must be a non-empty list")
        pid = body.get("project_id")
        if pid is not None and pid not in self.projects:
            return self._err(400, "project with policy not found")
        screened = []
        last_index = 0
        for i, msg in enumerate(messages):
            if not isinstance(msg, dict) or msg.get("role") in ("system", "developer"):
                continue
            screened.extend(_collect_strings(msg.get("content")))
            last_index = i
        text = "\n".join(screened).lower()
        hits: List[str] = []
        for needle, types in self.rules:
            if needle.lower() in text:
                for t in types:
                    if t not in hits:
                        hits.append(t)
        policy_id = "policy-%s" % (pid or "default")
        breakdown = []
        for t in list(self.detectors) + [h for h in hits if h not in self.detectors]:
            detected = t in hits
            breakdown.append({"project_id": pid or "", "policy_id": policy_id, "detector_id": _detector_id(t),
                              "detector_type": t, "detected": detected,
                              "result": "l1_confident" if detected else "l5_unlikely", "message_id": last_index})
        action = self.action if pid else "enforce"
        reply: Dict[str, Any] = {"flagged": bool(hits) and action == "enforce", "action": action,
                                 "metadata": {"request_uuid": _uid()}}
        if body.get("breakdown"):
            reply["breakdown"] = breakdown
        if body.get("payload"):
            reply["payload"] = []
        return _json_reply(200, reply)


# ===========================================================================
# Embedded API data (generated from the official v2.2 / v2 / v1.9.1 schema)
# ===========================================================================
# _V22_COMMANDS: the v2.2 commands relevant to the kit (session, gateways, packages, threat
# prevention, hosts/networks/groups, HTTPS inspection, logs, scripts, tasks, domains).
# _NOT_IN_V2 / _NOT_IN_V1_9_1: which of those are missing from older API versions.
# _PARAMS: accepted request parameter names for the commands this fake implements
# (unknown names -> generic_err_invalid_parameter_name, like the real server).

_V22_COMMANDS = (
    "add-access-layer add-access-rule add-access-section add-api-key add-application-site-group "
    "add-auto-updater-package add-client-login-option add-data-type-compound-group "
    "add-data-type-group add-data-type-traditional-group add-domain add-dynamic-global-network-object "
    "add-group add-group-with-exclusion add-host add-https-layer add-https-rule add-https-section "
    "add-ldap-group add-mds add-multiple-key-exchanges add-network add-network-feed add-network-probe "
    "add-objects-batch add-outbound-inspection-certificate add-package add-simple-cluster "
    "add-simple-gateway add-threat-indicator add-threat-ioc-feed add-threat-layer add-threat-profile "
    "add-threat-protections add-threat-rule add-user-group approve-session assign-session "
    "change-password-on-next-login check-network-feed check-threat-ioc-feed "
    "clear-objects-subscriptions clone-access-layer clone-application-site-group "
    "clone-client-login-option clone-domain clone-group clone-group-with-exclusion clone-host "
    "clone-https-layer clone-ldap-group clone-network clone-network-probe clone-package "
    "clone-user-group connect-session continue-session-in-smartconsole delete-access-layer "
    "delete-access-rule delete-access-section delete-api-key delete-application-site-group "
    "delete-client-login-option delete-data-type-compound-group delete-data-type-group "
    "delete-data-type-traditional-group delete-domain delete-dynamic-global-network-object "
    "delete-group delete-group-with-exclusion delete-host delete-https-layer delete-https-rule "
    "delete-https-section delete-ldap-group delete-mds delete-multiple-key-exchanges delete-network "
    "delete-network-feed delete-network-probe delete-objects-batch "
    "delete-outbound-inspection-certificate delete-package delete-simple-cluster "
    "delete-simple-gateway delete-threat-indicator delete-threat-ioc-feed delete-threat-layer "
    "delete-threat-profile delete-threat-protections delete-threat-rule delete-user-group discard "
    "export-access-rulebase get-cloud-api-key get-login-token import-outbound-inspection-certificate "
    "install-policy install-software-package keepalive login login-to-domain login-to-system-domain "
    "logout prepare-software-package publish purge-published-sessions reject-session "
    "replace-where-used revert-to-revision revoke-cloud-api-key run-internal-script run-script "
    "run-threat-emulation-file-types-offline-update set-access-layer set-access-rule "
    "set-access-section set-api-settings set-application-site-group set-client-login-option "
    "set-data-type-compound-group set-data-type-group set-data-type-traditional-group set-domain "
    "set-dynamic-global-network-object set-global-domain set-group set-group-with-exclusion set-host "
    "set-https-advanced-settings set-https-layer set-https-rule set-https-section set-ldap-group "
    "set-login-message set-login-restrictions set-mds set-multiple-key-exchanges set-network "
    "set-network-feed set-network-probe set-objects-batch set-outbound-inspection-certificate "
    "set-package set-session set-simple-cluster set-simple-gateway set-task "
    "set-threat-advanced-settings set-threat-emulation-file-type set-threat-emulation-file-types "
    "set-threat-extraction-file-type set-threat-extraction-file-types set-threat-indicator "
    "set-threat-ioc-feed set-threat-layer set-threat-profile set-threat-protection "
    "set-threat-protection-category set-threat-protection-sub-category set-threat-rule set-user-group "
    "show-access-layer show-access-layers show-access-rule show-access-rule-track-settings "
    "show-access-rulebase show-access-section show-any-objects show-api-settings show-api-status "
    "show-api-versions show-application-site-group show-application-site-groups show-changes "
    "show-client-login-option show-client-login-options show-commands show-data-type-compound-group "
    "show-data-type-compound-groups show-data-type-file-group show-data-type-file-groups "
    "show-data-type-group show-data-type-groups show-data-type-traditional-group "
    "show-data-type-traditional-groups show-domain show-domains show-dynamic-global-network-object "
    "show-dynamic-global-network-objects show-external-group show-external-groups "
    "show-gateways-and-servers show-generic-objects show-global-domain show-group "
    "show-group-with-exclusion show-groups show-groups-with-exclusion show-host show-hosts "
    "show-https-advanced-settings show-https-layer show-https-layers show-https-rule "
    "show-https-rulebase show-https-section show-last-published-session show-ldap-group "
    "show-ldap-groups show-login-message show-login-restrictions show-logs show-mds show-mdss "
    "show-multiple-key-exchanges show-multiple-key-exchanges-objects show-network show-network-feed "
    "show-network-feeds show-network-probe show-network-probes show-networks show-object show-objects "
    "show-objects-subscriptions show-outbound-inspection-certificate "
    "show-outbound-inspection-certificates show-package show-packages show-publish-information "
    "show-sdwan-nat-gateway-settings-objects show-sdwan-nat-objects show-sdwan-qos-objects "
    "show-security-group-members show-session show-sessions show-simple-cluster show-simple-clusters "
    "show-simple-gateway show-simple-gateways show-software-package-details "
    "show-software-packages-per-targets show-steering-internet-objects show-steering-overlay-objects "
    "show-subscriptions-notification show-task show-tasks show-threat-advanced-settings "
    "show-threat-emulation-file-type show-threat-emulation-file-types show-threat-emulation-image "
    "show-threat-emulation-images show-threat-extraction-file-type show-threat-extraction-file-types "
    "show-threat-indicator show-threat-indicators show-threat-ioc-feed show-threat-ioc-feeds "
    "show-threat-layer show-threat-layers show-threat-profile show-threat-profiles "
    "show-threat-protection show-threat-protection-categories show-threat-protection-category "
    "show-threat-protection-sub-categories show-threat-protection-sub-category "
    "show-threat-protections show-threat-rule show-threat-rulebase show-unused-objects "
    "show-user-group show-user-groups submit-session subscribe-cell-override-guideline-objects "
    "subscribe-cells-guideline-objects subscribe-objects subscribe-segments-guideline-objects "
    "suppress-task switch-session take-over-session test-ai-agent-security-api-key "
    "uninstall-software-package unsubscribe-objects verify-policy verify-revert "
    "verify-software-package where-used "
).split()
_NOT_IN_V2 = (
    "add-auto-updater-package add-client-login-option add-ldap-group change-password-on-next-login "
    "clone-client-login-option clone-ldap-group delete-client-login-option delete-ldap-group "
    "export-access-rulebase login-to-system-domain prepare-software-package replace-where-used "
    "run-internal-script set-client-login-option set-ldap-group set-login-restrictions set-task "
    "set-threat-emulation-file-type set-threat-emulation-file-types set-threat-extraction-file-type "
    "set-threat-extraction-file-types set-threat-protection-category "
    "set-threat-protection-sub-category show-access-rule-track-settings show-client-login-option "
    "show-client-login-options show-ldap-group show-ldap-groups show-login-restrictions "
    "show-sdwan-nat-gateway-settings-objects show-sdwan-nat-objects show-sdwan-qos-objects "
    "show-steering-internet-objects show-steering-overlay-objects show-threat-emulation-file-type "
    "show-threat-emulation-file-types show-threat-emulation-image show-threat-emulation-images "
    "show-threat-extraction-file-type show-threat-extraction-file-types "
    "show-threat-protection-categories show-threat-protection-category "
    "show-threat-protection-sub-categories show-threat-protection-sub-category "
    "subscribe-cell-override-guideline-objects subscribe-cells-guideline-objects "
    "subscribe-segments-guideline-objects test-ai-agent-security-api-key "
).split()
_NOT_IN_V1_9_1 = (
    "add-auto-updater-package add-client-login-option add-data-type-compound-group "
    "add-data-type-group add-data-type-traditional-group add-ldap-group add-multiple-key-exchanges "
    "add-network-probe change-password-on-next-login clone-client-login-option clone-domain "
    "clone-ldap-group clone-network-probe clone-package connect-session delete-client-login-option "
    "delete-data-type-compound-group delete-data-type-group delete-data-type-traditional-group "
    "delete-ldap-group delete-multiple-key-exchanges delete-network-probe "
    "delete-outbound-inspection-certificate export-access-rulebase login-to-system-domain "
    "prepare-software-package replace-where-used run-internal-script set-client-login-option "
    "set-data-type-compound-group set-data-type-group set-data-type-traditional-group "
    "set-https-advanced-settings set-ldap-group set-login-restrictions set-multiple-key-exchanges "
    "set-network-probe set-task set-threat-emulation-file-type set-threat-emulation-file-types "
    "set-threat-extraction-file-type set-threat-extraction-file-types set-threat-protection-category "
    "set-threat-protection-sub-category show-access-rule-track-settings show-client-login-option "
    "show-client-login-options show-data-type-compound-group show-data-type-compound-groups "
    "show-data-type-file-group show-data-type-file-groups show-data-type-group show-data-type-groups "
    "show-data-type-traditional-group show-data-type-traditional-groups show-external-group "
    "show-external-groups show-https-advanced-settings show-ldap-group show-ldap-groups "
    "show-login-restrictions show-multiple-key-exchanges show-multiple-key-exchanges-objects "
    "show-network-probe show-network-probes show-outbound-inspection-certificates "
    "show-sdwan-nat-gateway-settings-objects show-sdwan-nat-objects show-sdwan-qos-objects "
    "show-security-group-members show-steering-internet-objects show-steering-overlay-objects "
    "show-threat-emulation-file-type show-threat-emulation-file-types show-threat-emulation-image "
    "show-threat-emulation-images show-threat-extraction-file-type show-threat-extraction-file-types "
    "show-threat-protection-categories show-threat-protection-category "
    "show-threat-protection-sub-categories show-threat-protection-sub-category "
    "subscribe-cell-override-guideline-objects subscribe-cells-guideline-objects "
    "subscribe-segments-guideline-objects test-ai-agent-security-api-key "
).split()
_PARAMS = {
    "add-host": (
        "color comments details-level groups host-servers ignore-errors ignore-warnings "
        "interfaces ip-address ipv4-address ipv6-address name nat-settings set-if-exists tags "
    ),
    "add-https-rule": (
        "action blade certificate comments destination destination-negate details-level enabled "
        "ignore-errors ignore-warnings install-on layer name position service service-negate "
        "site-category site-category-negate source source-negate tags track "
    ),
    "add-threat-profile": (
        "activate-protections-by-extended-attributes active-protections-performance-impact "
        "active-protections-severity advanced-dns-settings ai-agent-security "
        "ai-agent-security-api-key ai-agent-security-settings anti-bot anti-bot-settings "
        "anti-virus anti-virus-settings color comments confidence-level-high confidence-level-low "
        "confidence-level-medium deactivate-protections-by-extended-attributes details-level "
        "ignore-errors ignore-warnings indicator-overrides ips ips-settings mail-exceptions "
        "mail-general mail-mime-nesting malicious-mail-policy-settings name overrides "
        "scan-malicious-links tags threat-emulation threat-emulation-settings threat-extraction "
        "threat-extraction-settings use-extended-attributes use-indicators zero-phishing "
        "zero-phishing-settings "
    ),
    "add-threat-rule": (
        "action comments destination destination-negate details-level enabled ignore-errors "
        "ignore-warnings install-on layer name position protected-scope protected-scope-negate "
        "service service-negate source source-negate tags track track-settings "
    ),
    "delete-host": "details-level ignore-errors ignore-warnings name uid",
    "delete-https-rule": "details-level layer name rule-number uid",
    "delete-threat-profile": "details-level ignore-errors ignore-warnings name uid",
    "delete-threat-rule": "details-level layer name rule-number uid",
    "discard": "uid",
    "install-policy": (
        "access desktop-security ignore-warnings install-on-all-cluster-members-or-fail "
        "policy-package prepare-only qos revision targets threat-prevention "
    ),
    "keepalive": "",
    "login": (
        "api-key continue-last-session domain enter-last-published-session new-password password "
        "read-only session-comments session-description session-name session-timeout user "
    ),
    "login-to-domain": "continue-last-session domain read-only",
    "logout": "",
    "publish": "uid",
    "run-script": "args comments script script-base64 script-name script-type targets timeout uid",
    "set-https-rule": (
        "action blade certificate comments destination destination-negate details-level enabled "
        "ignore-errors ignore-warnings install-on layer name new-name new-position rule-number "
        "service service-negate site-category site-category-negate source source-negate tags "
        "track uid "
    ),
    "set-host": (
        "color comments details-level groups host-servers ignore-errors ignore-warnings interfaces "
        "ip-address ipv4-address ipv6-address name nat-settings new-name tags uid "
    ),
    "set-simple-cluster": (
        "advanced-settings anti-bot anti-malware-settings anti-spam-and-email-security anti-virus "
        "application-control application-control-and-url-filtering-settings "
        "auto-topology-custom-recalculation-time auto-topology-use-custom-recalculation-time "
        "cluster-mode cluster-settings color comments communication-with-servers-behind-nat "
        "content-awareness data-loss-prevention details-level dns-server enable-https-inspection "
        "fetch-policy firewall firewall-settings geo-mode groups hardware hit-count "
        "https-inspection identity-awareness identity-awareness-settings ignore-errors "
        "ignore-warnings interfaces ip-address ips ips-settings ips-update-policy ipv4-address "
        "ipv6-address logs-settings members mobile-access monitoring name "
        "nat-hide-internal-interfaces nat-settings new-name os-name platform-portal-settings "
        "policy-server proxy-settings qos rtm-counters-report rtm-traffic-report "
        "rtm-traffic-report-per-connection send-alerts-to-server send-logs-to-backup-server "
        "send-logs-to-server show-portals-certificate tags threat-emulation threat-extraction "
        "threat-extraction-settings threat-prevention-mode uid url-filtering "
        "usercheck-portal-settings version vpn vpn-settings workforce-ai zero-phishing "
        "zero-phishing-settings "
    ),
    "set-simple-gateway": (
        "accept-syslog-messages advanced-settings anti-bot anti-malware-settings "
        "anti-spam-and-email-security anti-virus application-control "
        "application-control-and-url-filtering-settings auto-generate-ip "
        "auto-topology-custom-recalculation-time auto-topology-use-custom-recalculation-time "
        "autonomous-system-number color comments communication-with-servers-behind-nat "
        "content-awareness data-loss-prevention details-level dns-server dynamic-address "
        "enable-https-inspection enable-log-indexing export-logs-to-servers fetch-policy "
        "fetch-policy-scheduler firewall firewall-settings groups hardware hardware-subtype "
        "hit-count https-inspection icap-server identity-awareness identity-awareness-settings "
        "ignore-errors ignore-warnings install-policy-without-push interfaces "
        "interfaces-topology-settings ip-address ips ips-settings ips-update-policy ipv4-address "
        "ipv6-address logs-settings mobile-access monitoring name nat-hide-internal-interfaces "
        "nat-settings new-name one-time-password os-name platform-portal-settings policy-server "
        "proxy-settings qos rtm-counters-report rtm-traffic-report "
        "rtm-traffic-report-per-connection save-logs-locally send-alerts-to-server "
        "send-logs-to-backup-server send-logs-to-server show-portals-certificate sic-name "
        "smart-event-intro-correlation-unit tags threat-emulation threat-extraction "
        "threat-extraction-settings threat-prevention-mode trust-method trust-settings uid "
        "url-filtering usercheck-portal-settings version vpn vpn-settings workforce-ai "
        "zero-phishing zero-phishing-settings "
    ),
    "set-threat-profile": (
        "activate-protections-by-extended-attributes active-protections-performance-impact "
        "active-protections-severity advanced-dns-settings ai-agent-security "
        "ai-agent-security-api-key ai-agent-security-settings anti-bot anti-bot-settings "
        "anti-virus anti-virus-settings color comments confidence-level-high confidence-level-low "
        "confidence-level-medium deactivate-protections-by-extended-attributes details-level "
        "ignore-errors ignore-warnings indicator-overrides ips ips-settings mail-exceptions "
        "mail-general mail-mime-nesting malicious-mail-policy-settings name new-name overrides "
        "scan-malicious-links tags threat-emulation threat-emulation-settings threat-extraction "
        "threat-extraction-settings uid use-extended-attributes use-indicators zero-phishing "
        "zero-phishing-settings "
    ),
    "set-threat-rule": (
        "action comments destination destination-negate details-level enabled ignore-errors "
        "ignore-warnings install-on layer name new-name new-position protected-scope "
        "protected-scope-negate rule-number service service-negate source source-negate tags "
        "track track-settings uid "
    ),
    "show-api-versions": "",
    "show-commands": "prefix",
    "show-domains": "details-level domains-to-process filter limit offset order",
    "show-gateways-and-servers": "details-level domains-to-process limit offset order show-only-local-domain",
    "show-host": "details-level name uid",
    "show-objects": (
        "dereference-group-members details-level domains-to-process filter ip-only limit offset order "
        "show-membership show-only-local-domain type uids "
    ),
    "show-tasks": "details-level from-date initiator limit offset order status to-date",
    "show-outbound-inspection-certificates": (
        "details-level domains-to-process filter limit offset order show-only-local-domain "
    ),
    "show-https-rule": "details-level hits-settings layer name rule-number show-hits uid",
    "show-https-rulebase": (
        "dereference-group-members details-level filter filter-settings hits-settings limit name "
        "offset order package show-hits show-membership uid use-object-dictionary "
    ),
    "show-logs": "ignore-warnings new-query query-id",
    "show-mdss": "details-level filter limit offset order show-domains",
    "show-outbound-inspection-certificate": "details-level name uid",
    "show-package": "details-level name show-installation-targets uid",
    "show-packages": (
        "async-response details-level domains-to-process filter limit offset order "
        "show-installation-targets show-only-local-domain "
    ),
    "show-session": "detailed-admin-info uid",
    "show-simple-cluster": "details-level limit-interfaces name show-advanced-settings show-portals-certificate uid",
    "show-simple-gateway": "details-level name show-advanced-settings show-portals-certificate uid",
    "show-task": "details-level task-id",
    "show-threat-layers": "details-level domains-to-process filter limit offset order show-only-local-domain",
    "show-threat-profile": "details-level limit-overrides name offset-overrides uid",
    "show-threat-rule": "details-level layer name rule-number uid",
    "show-threat-rulebase": (
        "dereference-group-members details-level filter filter-settings limit name offset order "
        "package show-membership uid use-object-dictionary "
    ),
    "test-ai-agent-security-api-key": "project-id",
}

# v1.9.1 differs for the HTTPS rule identifiers (TLSRuleIdentifierRequest: uid or rule-number).
_PARAMS_V1_9_1 = {
    "show-https-rule": "details-level layer rule-number uid",
    "delete-https-rule": "details-level layer rule-number uid",
}
