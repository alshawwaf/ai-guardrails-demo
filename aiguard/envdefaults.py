"""Management connection defaults from the environment (spec 9.1 / 9.2 addition).

A lab installer writes these optional variables into ``.env``; the web console's
container gets them with ``docker run --env-file .env`` and the CLI runs in the same
container (``docker exec``). They pre-fill the Connect page and are the CLI's defaults
when a flag is not given, so the presenter only types secrets. Flags (and what is typed
on the page) always win. Empty means unset.

==============================  =========================================================
``AIGUARD_MGMT_SERVER``          management address (IP or name)
``AIGUARD_MGMT_PORT``            Management API port (default 443)
``AIGUARD_MGMT_SERVER_NAME``     name to verify the certificate against (``--server-name``)
``AIGUARD_MGMT_TYPE``            ``SMS`` or ``MDS``
``AIGUARD_MGMT_DOMAIN``          MDS domain
``AIGUARD_MGMT_CA_FILE``         PEM file with the management CA (``--ca-file`` for the
                                 management connection)
``AIGUARD_GATEWAY``              gateway or cluster to pre-select after discovery
``AIGUARD_MGMT_FINGERPRINT_SHA1`` informational: the SHA-1 the installer saw, to compare
                                 with ``api fingerprint`` on the server
==============================  =========================================================

None of them is a secret (keys and passwords are never read from here). A value that is
not valid is ignored and described in :attr:`Defaults.problems` (user-facing text that
names the variable, never its value).

:func:`inspect_ca_file` reads the CA file with the standard library only: the SHA-1 of
the first certificate (DER via :func:`ssl.PEM_cert_to_DER_cert`) and its subject common
name (a small DER walk; ``None`` when it cannot be read). The file is never copied,
changed or deleted here.
"""

from __future__ import annotations

import hashlib
import os
import re
import ssl
import threading
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

__all__ = [
    "ENV_SERVER",
    "ENV_PORT",
    "ENV_SERVER_NAME",
    "ENV_TYPE",
    "ENV_DOMAIN",
    "ENV_CA_FILE",
    "ENV_GATEWAY",
    "ENV_FINGERPRINT_SHA1",
    "VARIABLES",
    "CA_FILE_MAX_BYTES",
    "Defaults",
    "CaFileError",
    "from_env",
    "inspect_ca_file",
    "normalize_sha1",
    "subject_cn",
]

ENV_SERVER = "AIGUARD_MGMT_SERVER"
ENV_PORT = "AIGUARD_MGMT_PORT"
ENV_SERVER_NAME = "AIGUARD_MGMT_SERVER_NAME"
ENV_TYPE = "AIGUARD_MGMT_TYPE"
ENV_DOMAIN = "AIGUARD_MGMT_DOMAIN"
ENV_CA_FILE = "AIGUARD_MGMT_CA_FILE"
ENV_GATEWAY = "AIGUARD_GATEWAY"
ENV_FINGERPRINT_SHA1 = "AIGUARD_MGMT_FINGERPRINT_SHA1"
VARIABLES = (ENV_SERVER, ENV_PORT, ENV_SERVER_NAME, ENV_TYPE, ENV_DOMAIN, ENV_CA_FILE,
             ENV_GATEWAY, ENV_FINGERPRINT_SHA1)

CA_FILE_MAX_BYTES = 64 * 1024

# Same address pattern as the web console's connect form (gateway_mode.routes._HOST_RE).
_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]%]+$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_HEX40_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
_CERT_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----")


class CaFileError(ValueError):
    """The CA file cannot be used. The message is user-facing: it names the file (not
    its directory) and never quotes its content."""


class Defaults(object):
    """The parsed variables (``None`` when unset or not valid)."""

    __slots__ = ("server", "port", "server_name", "server_type", "domain", "ca_file",
                 "gateway", "fingerprint_sha1", "problems")

    def __init__(self, *, server: Optional[str] = None, port: Optional[int] = None,
                 server_name: Optional[str] = None, server_type: Optional[str] = None,
                 domain: Optional[str] = None, ca_file: Optional[str] = None,
                 gateway: Optional[str] = None, fingerprint_sha1: Optional[str] = None,
                 problems: Optional[List[str]] = None) -> None:
        self.server = server
        self.port = port
        self.server_name = server_name
        self.server_type = server_type
        self.domain = domain
        self.ca_file = ca_file
        self.gateway = gateway
        self.fingerprint_sha1 = fingerprint_sha1
        self.problems: List[str] = list(problems or [])

    def any(self) -> bool:
        return any(getattr(self, k) is not None for k in self.__slots__ if k != "problems")

    def applies_to(self, server: Optional[str]) -> bool:
        """Do the per-server values (port, type, domain, server name, fingerprint) belong
        to ``server``? True when no address is configured or it is the same address
        (case-insensitive)."""
        if not self.server:
            return True
        return str(server or "").strip().lower() == self.server.lower()

    def to_dict(self) -> Dict[str, Any]:
        return {k: (list(getattr(self, k)) if k == "problems" else getattr(self, k))
                for k in self.__slots__}

    def __repr__(self) -> str:
        return "Defaults(%s)" % ", ".join("%s=%r" % (k, getattr(self, k)) for k in self.__slots__
                                          if getattr(self, k))


def _get(environ: Mapping[str, str], name: str) -> Optional[str]:
    value = environ.get(name)
    if value is None:
        return None
    value = str(value).strip()
    # .env files are often written with quotes; docker --env-file keeps them.
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1].strip()
    return value or None


def _text(environ: Mapping[str, str], name: str, problems: List[str], *, max_len: int,
          pattern: Optional["re.Pattern[str]"] = None, what: str = "value") -> Optional[str]:
    value = _get(environ, name)
    if value is None:
        return None
    if len(value) > max_len or _CTRL_RE.search(value) or (pattern is not None
                                                          and not pattern.match(value)):
        problems.append("%s is not a valid %s: ignored" % (name, what))
        return None
    return value


def normalize_sha1(value: Optional[str]) -> Optional[str]:
    """``AB:CD:...`` (upper case, colon separated) for 40 hex digits written with or
    without ``:``/spaces; None when it is not a SHA-1 fingerprint."""
    if not value:
        return None
    raw = re.sub(r"[\s:]", "", str(value))
    if not _HEX40_RE.match(raw):
        return None
    raw = raw.upper()
    return ":".join(raw[i:i + 2] for i in range(0, 40, 2))


def from_env(environ: Optional[Mapping[str, str]] = None) -> Defaults:
    """Parse the variables from ``environ`` (default ``os.environ``), read at call time."""
    env = os.environ if environ is None else environ
    problems: List[str] = []
    server = _text(env, ENV_SERVER, problems, max_len=253, pattern=_HOST_RE,
                   what="management address")
    port: Optional[int] = None
    raw_port = _get(env, ENV_PORT)
    if raw_port is not None:
        if raw_port.isdigit() and 0 < int(raw_port) < 65536:
            port = int(raw_port)
        else:
            problems.append("%s is not a port number from 1 to 65535: ignored" % ENV_PORT)
    server_name = _text(env, ENV_SERVER_NAME, problems, max_len=253, pattern=_HOST_RE,
                        what="certificate name")
    server_type: Optional[str] = None
    raw_type = _get(env, ENV_TYPE)
    if raw_type is not None:
        if raw_type.upper() in ("SMS", "MDS"):
            server_type = raw_type.upper()
        else:
            problems.append("%s must be SMS or MDS: ignored" % ENV_TYPE)
    domain = _text(env, ENV_DOMAIN, problems, max_len=128, what="domain name")
    if domain is not None and domain.lower() == "system data":
        domain = None       # where an MDS login without a domain lands, not a domain
    ca_file = _text(env, ENV_CA_FILE, problems, max_len=4096, what="file path")
    gateway = _text(env, ENV_GATEWAY, problems, max_len=128, what="gateway name")
    fingerprint: Optional[str] = None
    raw_fp = _get(env, ENV_FINGERPRINT_SHA1)
    if raw_fp is not None:
        fingerprint = normalize_sha1(raw_fp)
        if fingerprint is None:
            problems.append("%s is not a SHA-1 fingerprint (40 hex digits): ignored"
                            % ENV_FINGERPRINT_SHA1)
    return Defaults(server=server, port=port, server_name=server_name, server_type=server_type,
                    domain=domain, ca_file=ca_file, gateway=gateway, fingerprint_sha1=fingerprint,
                    problems=problems)


# --------------------------------------------------------------------------- CA file

_ca_lock = threading.Lock()
_ca_cache: Dict[Tuple[str, int, int], Dict[str, Any]] = {}


def _sha1(der: bytes) -> str:
    try:
        digest = hashlib.sha1(der, usedforsecurity=False).hexdigest()  # type: ignore[call-arg]
    except TypeError:  # Python < 3.9
        digest = hashlib.sha1(der).hexdigest()  # nosec - display only, compared by a person
    return normalize_sha1(digest) or ""


def _tlv(buf: bytes, pos: int) -> Tuple[int, int, int]:
    """(tag, start, end) of the DER element at ``pos`` (content is ``buf[start:end]``)."""
    tag = buf[pos]
    length = buf[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(buf):
        raise ValueError("truncated DER")
    return tag, pos, end


_OID_CN = b"\x55\x04\x03"   # 2.5.4.3 commonName


def subject_cn(der: bytes) -> Optional[str]:
    """The subject common name of a DER certificate, or None (no CN, or not parsable)."""
    try:
        tag, start, end = _tlv(der, 0)               # Certificate
        if tag != 0x30:
            return None
        tag, start, end = _tlv(der, start)           # TBSCertificate
        if tag != 0x30:
            return None
        fields = []
        pos = start
        while pos < end and len(fields) < 7:
            f = _tlv(der, pos)
            fields.append(f)
            pos = f[2]
        if fields and fields[0][0] == 0xA0:          # [0] version
            fields = fields[1:]
        # serialNumber, signature, issuer, validity, subject
        if len(fields) < 5 or fields[4][0] != 0x30:
            return None
        _, start, end = fields[4]
        cn: Optional[str] = None
        pos = start
        while pos < end:
            rtag, rstart, rend = _tlv(der, pos)      # RelativeDistinguishedName (SET)
            pos = rend
            if rtag != 0x31:
                return None
            apos = rstart
            while apos < rend:
                atag, astart, aend = _tlv(der, apos)  # AttributeTypeAndValue
                apos = aend
                if atag != 0x30:
                    continue
                otag, ostart, oend = _tlv(der, astart)
                if otag != 0x06 or der[ostart:oend] != _OID_CN:
                    continue
                vtag, vstart, vend = _tlv(der, oend)
                raw = der[vstart:vend]
                if vtag == 0x1E:                      # BMPString
                    cn = raw.decode("utf-16-be", "replace")
                elif vtag == 0x0C:                    # UTF8String
                    cn = raw.decode("utf-8", "replace")
                else:                                 # Printable/IA5/Teletex...
                    cn = raw.decode("latin-1", "replace")
        if cn is None:
            return None
        cn = _CTRL_RE.sub("", cn).strip()
        return cn[:128] or None
    except (IndexError, ValueError):
        return None


def inspect_ca_file(path: Any) -> Dict[str, Any]:
    """Check that ``path`` is a readable PEM file of CA certificates without a private
    key. Returns ``{"path", "name", "sha1", "subject_cn", "count"}`` (the first
    certificate's facts). Raises :class:`CaFileError`."""
    p = Path(str(path)).expanduser()
    name = p.name or str(p)
    try:
        st = p.stat()
    except FileNotFoundError:
        raise CaFileError("The CA file %s does not exist" % name) from None
    except OSError:
        raise CaFileError("The CA file %s cannot be read" % name) from None
    if not p.is_file():
        raise CaFileError("%s is not a file" % name)
    key = (str(p), int(getattr(st, "st_mtime_ns", 0)), int(st.st_size))
    with _ca_lock:
        hit = _ca_cache.get(key)
    if hit is not None:
        return dict(hit)
    if st.st_size > CA_FILE_MAX_BYTES:
        raise CaFileError("The CA file %s is larger than 64 KB" % name)
    try:
        with open(str(p), "rb") as fh:
            data = fh.read(CA_FILE_MAX_BYTES + 1)
    except OSError:
        raise CaFileError("The CA file %s cannot be read (permissions?)" % name) from None
    if len(data) > CA_FILE_MAX_BYTES:
        raise CaFileError("The CA file %s is larger than 64 KB" % name)
    text = data.decode("utf-8", "replace")
    if "PRIVATE KEY" in text:
        raise CaFileError("The CA file %s contains a private key: it must hold only the CA "
                          "certificate" % name)
    blocks = []
    for match in _CERT_BLOCK_RE.finditer(text):
        body = re.sub(r"\s+", "", match.group(1))
        if body:
            lines = [body[i:i + 64] for i in range(0, len(body), 64)]
            blocks.append("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n"
                          % "\n".join(lines))
    if not blocks:
        raise CaFileError("The CA file %s has no certificate (-----BEGIN CERTIFICATE-----)"
                          % name)
    try:
        # Parsed by the TLS stack that will use it (verification stays on).
        ssl.create_default_context().load_verify_locations(cadata="".join(blocks))
        der = ssl.PEM_cert_to_DER_cert(blocks[0])
    except (ssl.SSLError, ValueError):
        raise CaFileError("The CA file %s is not a readable PEM certificate" % name) from None
    info = {"path": str(p), "name": name, "sha1": _sha1(der), "subject_cn": subject_cn(der),
            "count": len(blocks)}
    with _ca_lock:
        if len(_ca_cache) > 16:
            _ca_cache.clear()
        _ca_cache[key] = dict(info)
    return info
