"""TLS helpers (spec 2.5). Verification is always on.

* :func:`make_context` -- default trust store (+ optional ``--ca-file``), TLS 1.2+.
* :class:`VerifiedHTTPSConnection` -- ``http.client.HTTPSConnection`` that can
  connect to one address (e.g. the management IP) while verifying the
  certificate against another name (``--server-name``).
* :func:`peer_summary` -- issuer / subject / SAN / fingerprints of the peer.
* :func:`is_public_issuer` -- was the certificate issued by a public CA (i.e.
  *not* re-signed by HTTPS Inspection)?
* :func:`trust_error` -- turn a verification failure into a
  :class:`~aiguard.errors.TlsTrustError` with concrete fix steps.

Trust is only ever extended by loading a CA file or by checking against an
expected name. Nothing in here turns certificate or hostname checks off.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .errors import TlsTrustError

__all__ = [
    "make_context",
    "VerifiedHTTPSConnection",
    "peer_summary",
    "fingerprint",
    "PUBLIC_CA_ORGS",
    "is_public_issuer",
    "trust_error",
    "classify_verify_error",
]

# --------------------------------------------------------------------------- context


def make_context(ca_file: Optional[str] = None) -> ssl.SSLContext:
    """Client context: system trust store, TLS 1.2 minimum, hostname checks on.

    ``ca_file`` (PEM, one or more certificates) is added to the trust store.
    Raises :class:`TlsTrustError` if it is missing, unreadable or not PEM.
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_file:
        path = Path(str(ca_file)).expanduser()
        if not path.exists():
            raise TlsTrustError(
                "CA file not found: %s" % path,
                code="tls.ca_file_missing",
                why="--ca-file must point to a PEM file with the certificate(s) to trust.",
                fix=[
                    "Check the path and the file name: %s" % path,
                    "Export the certificate again (management: the Gaia portal / ICA "
                    "certificate; gateway: SmartConsole > Gateway > HTTPS Inspection > "
                    "Step 2 export) and pass --ca-file <file.pem>",
                ],
                state="No connection was made.",
                details={"ca_file": str(path)},
            )
        if not path.is_file():
            raise TlsTrustError(
                "CA file is not a file: %s" % path,
                code="tls.ca_file_invalid",
                why="--ca-file takes one PEM file, not a directory.",
                fix=["Pass the PEM file itself: --ca-file %s" % (path / "<file.pem>")],
                state="No connection was made.",
                details={"ca_file": str(path)},
            )
        try:
            ctx.load_verify_locations(cafile=str(path))
        except (ssl.SSLError, OSError, ValueError) as exc:
            unreadable = isinstance(exc, OSError) and not isinstance(exc, ssl.SSLError)
            raise TlsTrustError(
                ("Cannot read CA file %s" if unreadable else "CA file %s is not a PEM certificate") % path,
                code="tls.ca_file_invalid",
                server_said=str(exc),
                why=("The file exists but could not be opened (permissions?)." if unreadable else
                     "Python needs PEM text: blocks that start with "
                     "-----BEGIN CERTIFICATE-----. A .cer/.der file is binary (DER)."),
                fix=[
                    "Make sure the file is readable by this user" if unreadable else
                    "Convert DER to PEM: openssl x509 -inform der -in <file.cer> -out <file.pem>",
                    "Then pass --ca-file <file.pem>",
                ],
                state="No connection was made.",
                details={"ca_file": str(path)},
            ) from exc
    return ctx


# --------------------------------------------------------------------------- connection


class VerifiedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that verifies against ``server_hostname`` when given.

    TCP goes to ``host``; SNI and certificate name checks use
    ``server_hostname or host``. The context must verify certificates and
    hostnames (use :func:`make_context`). After :meth:`connect`, :attr:`peer`
    holds :func:`peer_summary` of the server.
    """

    def __init__(self, host: str, port: int = 443, *, context: ssl.SSLContext,
                 server_hostname: Optional[str] = None, timeout: float = 30) -> None:
        if not isinstance(context, ssl.SSLContext):
            raise TypeError("context must be an ssl.SSLContext (use tlsutil.make_context())")
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise ValueError("VerifiedHTTPSConnection needs a context that verifies "
                             "certificates and hostnames (use tlsutil.make_context())")
        super().__init__(host, port, timeout=timeout, context=context)
        self._verified_context = context
        self.server_hostname: Optional[str] = (server_hostname or "").strip() or None
        self.peer: Optional[Dict[str, Any]] = None

    def connect(self) -> None:
        # Plain TCP (and proxy CONNECT tunnel, if set) from HTTPConnection.
        http.client.HTTPConnection.connect(self)
        name = self.server_hostname or getattr(self, "_tunnel_host", None) or self.host
        raw = self.sock
        try:
            self.sock = self._verified_context.wrap_socket(raw, server_hostname=name)
        except BaseException:
            try:
                raw.close()
            finally:
                self.sock = None
            raise
        try:
            self.peer = peer_summary(self.sock)
        except Exception:  # noqa: BLE001 - summary is informational only
            self.peer = None


# --------------------------------------------------------------------------- certificate info


def fingerprint(der: bytes, algorithm: str = "sha256") -> str:
    """Colon-separated upper-case hex digest (``AB:CD:...``) of a DER certificate."""
    if not der:
        return ""
    algo = algorithm.lower().replace("-", "")
    if algo == "sha1":
        # SHA1 only to compare with `api fingerprint` on the management server.
        try:
            digest = hashlib.sha1(der, usedforsecurity=False).digest()  # type: ignore[call-arg]
        except TypeError:  # Python < 3.9
            digest = hashlib.sha1(der).digest()  # nosec - display only
    else:
        digest = hashlib.new(algo, der).digest()
    return ":".join("%02X" % b for b in digest)


def _name_fields(rdns: Any) -> Dict[str, str]:
    fields: Dict[str, List[str]] = {}
    for rdn in rdns or ():
        for pair in rdn:
            if len(pair) == 2:
                fields.setdefault(pair[0], []).append(str(pair[1]))
    return {k: ", ".join(v) for k, v in fields.items()}


def _cert_time(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        ts = ssl.cert_time_to_seconds(value)
    except (ValueError, TypeError):
        return value
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def peer_summary(sock: Any) -> Dict[str, Any]:
    """Summary of the verified peer certificate and the TLS session.

    Keys: issuer_org, issuer_cn, subject_cn, subject_org, san (``"DNS:x"`` /
    ``"IP:x"`` strings), san_dns, san_ip, not_before, not_after (ISO UTC),
    serial, sha256 and sha1 (colon hex, upper), tls_version, cipher, peer_ip,
    local_ip. Accepts an ``ssl.SSLSocket`` or an object with ``.sock``.
    """
    if not isinstance(sock, ssl.SSLSocket) and getattr(sock, "sock", None) is not None:
        sock = sock.sock
    try:
        cert = sock.getpeercert() or {}
    except (ValueError, OSError):
        cert = {}
    try:
        der = sock.getpeercert(binary_form=True) or b""
    except (ValueError, OSError):
        der = b""
    issuer = _name_fields(cert.get("issuer"))
    subject = _name_fields(cert.get("subject"))
    san: List[str] = []
    san_dns: List[str] = []
    san_ip: List[str] = []
    for entry in cert.get("subjectAltName", ()) or ():
        if len(entry) != 2:
            continue
        kind, value = entry[0], str(entry[1]).strip()
        if kind == "DNS":
            san_dns.append(value)
            san.append("DNS:" + value)
        elif kind == "IP Address":
            san_ip.append(value)
            san.append("IP:" + value)
        else:
            san.append("%s:%s" % (kind, value))
    try:
        version = sock.version()
    except (ValueError, OSError, AttributeError):
        version = None
    try:
        cipher_info = sock.cipher()
        cipher = cipher_info[0] if cipher_info else None
    except (ValueError, OSError, AttributeError):
        cipher = None
    try:
        peer_ip = sock.getpeername()[0]
    except (OSError, IndexError, AttributeError):
        peer_ip = None
    try:
        local_ip = sock.getsockname()[0]
    except (OSError, IndexError, AttributeError):
        local_ip = None
    return {
        "issuer_org": issuer.get("organizationName", ""),
        "issuer_cn": issuer.get("commonName", ""),
        "subject_cn": subject.get("commonName", ""),
        "subject_org": subject.get("organizationName", ""),
        "san": san,
        "san_dns": san_dns,
        "san_ip": san_ip,
        "not_before": _cert_time(cert.get("notBefore")),
        "not_after": _cert_time(cert.get("notAfter")),
        "serial": cert.get("serialNumber"),
        "sha256": fingerprint(der, "sha256"),
        "sha1": fingerprint(der, "sha1"),
        "tls_version": version,
        "cipher": cipher,
        "peer_ip": peer_ip,
        "local_ip": local_ip,
    }


# --------------------------------------------------------------------------- public CAs

PUBLIC_CA_ORGS: Tuple[str, ...] = (
    # from ai_guard_test.py
    "google trust services", "digicert", "let's encrypt", "sectigo", "cloudflare",
    "globalsign", "amazon", "microsoft", "entrust", "godaddy", "baltimore",
    "identrust", "comodo", "usertrust", "isrg", "starfield", "certainly",
    # extended
    "buypass", "actalis", "ssl.com", "harica", "e-tugra", "certum", "quovadis",
    "swisssign", "telia", "wisekey", "trustwave", "secom", "t-systems", "d-trust",
    "internet security research group", "letsencrypt", "go daddy", "zerossl",
    "thawte", "geotrust", "rapidssl", "verisign", "symantec", "gts ca", "gts root",
)

_PUBLIC_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    + "|".join(re.escape(n) for n in sorted(set(PUBLIC_CA_ORGS), key=len, reverse=True))
    + r")(?![a-z0-9])"
)


def is_public_issuer(org: Optional[str], cn: Optional[str] = "") -> bool:
    """True when issuer organisation/CN names a public web CA.

    A public issuer on a provider connection means HTTPS Inspection did *not*
    re-sign it (the prompt would pass the gateway unseen).
    """
    text = ("%s %s" % (org or "", cn or "")).lower()
    text = text.replace("’", "'").replace("‘", "'")
    return bool(_PUBLIC_RE.search(text))


# --------------------------------------------------------------------------- errors

_UNTRUSTED_CODES = {2, 18, 19, 20, 21}
_UNTRUSTED_TEXT = ("self signed", "self-signed", "unable to get local issuer",
                   "unable to get issuer", "unable to verify the first certificate",
                   "certificate chain")
_STRICT_TEXT = ("not marked critical", "key usage", "authority key identifier",
                "subject key identifier", "basic constraints")


def classify_verify_error(message: Optional[str], code: Optional[int] = None) -> str:
    """One of: hostname_mismatch, ip_mismatch, expired, not_yet_valid, strict,
    untrusted, revoked, not_tls, old_tls, handshake, other."""
    m = (message or "").lower()
    if code == 64 or "ip address mismatch" in m:
        return "ip_mismatch"
    if code == 62 or "hostname mismatch" in m:
        return "hostname_mismatch"
    if code == 10 or "has expired" in m or "certificate expired" in m:
        return "expired"
    if code == 9 or "not yet valid" in m:
        return "not_yet_valid"
    if code == 23 or "revoked" in m:
        return "revoked"
    if any(t in m for t in _STRICT_TEXT):
        return "strict"
    if code in _UNTRUSTED_CODES or any(t in m for t in _UNTRUSTED_TEXT):
        return "untrusted"
    if ("wrong version number" in m or "http request" in m
            or "record layer failure" in m or "packet length too long" in m):
        return "not_tls"
    if ("unsupported protocol" in m or "protocol version" in m
            or "no protocols available" in m):
        return "old_tls"
    if "handshake failure" in m:
        return "handshake"
    return "other"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _fp_command(host: str, port: int, name: Optional[str]) -> str:
    sni = name or host
    sni_opt = "" if _is_ip(sni) else " -servername %s" % sni
    addr = "[%s]" % host if ":" in host and not host.startswith("[") else host
    return ("openssl s_client -connect %s:%d%s </dev/null | "
            "openssl x509 -noout -fingerprint -sha1 -subject -ext subjectAltName"
            % (addr, port, sni_opt))


def trust_error(e: BaseException, host: str, purpose: str, *, port: Optional[int] = None,
                ca_file: Optional[str] = None,
                server_name: Optional[str] = None) -> TlsTrustError:
    """Build a :class:`TlsTrustError` for a failed TLS handshake.

    ``purpose`` is ``"management"`` (Check Point management server) or
    ``"provider"`` (an AI provider reached through the gateway; any other value
    is treated like ``"provider"``). ``port``/``ca_file``/``server_name`` are
    optional context that make the fix text exact.
    """
    verify_message = getattr(e, "verify_message", None) or ""
    verify_code = getattr(e, "verify_code", None)
    raw = str(e)
    said = verify_message or raw or type(e).__name__
    category = classify_verify_error(verify_message or raw, verify_code)
    port = int(port or 443)
    target = server_name or host
    details = {
        "host": host, "port": port, "purpose": purpose, "server_name": server_name,
        "ca_file": str(ca_file) if ca_file else None, "category": category,
        "verify_code": verify_code, "verify_message": verify_message or None,
        "error": raw,
    }
    code = {
        "ip_mismatch": "tls.hostname_mismatch", "hostname_mismatch": "tls.hostname_mismatch",
        "expired": "tls.expired", "not_yet_valid": "tls.expired", "untrusted": "tls.untrusted",
        "strict": "tls.strict", "revoked": "tls.revoked", "not_tls": "tls.not_tls",
        "old_tls": "tls.protocol", "handshake": "tls.handshake",
    }.get(category, "tls.error")
    if purpose == "management":
        what, why, fix, state = _management_text(category, host, port, target, ca_file,
                                                 server_name)
    else:
        what, why, fix, state = _provider_text(category, host, port, target, ca_file)
        if category == "untrusted":
            # A UI can offer this as a button (the fix text keeps the CLI command).
            details["action"] = {"id": "outbound-ca",
                                 "label": "Trust the outbound CA for the demo traffic",
                                 "cli": "aiguard trust-ca"}
    return TlsTrustError(what, code=code, server_said=said, why=why, fix=fix, state=state,
                         details=details)


def _management_text(category: str, host: str, port: int, target: str,
                     ca_file: Optional[str], server_name: Optional[str]
                     ) -> Tuple[str, str, List[str], str]:
    state = "No connection was made. Nothing was changed."
    fp_step = ("Before trusting a certificate, compare its SHA1 fingerprint with the one "
               "`api fingerprint` prints on the management server (Expert mode). On this "
               "computer: " + _fp_command(host, port, server_name))
    sk_step = ("Replace the Gaia portal certificate with one signed by the Check Point ICA "
               "that lists this address (%s) and the server's hostname as Subject "
               "Alternative Names (sk164382). Then export the ICA or portal certificate to "
               "a PEM file and pass --ca-file <file.pem>" % host)
    name_step = ("Or, if the certificate's Common Name / SAN is a DNS name, keep the address "
                 "and add --server-name <name in the certificate> --ca-file <file.pem>: "
                 "aiguard connects to %s and checks the certificate against that name"
                 % host)
    if category in ("ip_mismatch", "hostname_mismatch"):
        what = "The management server's certificate is not valid for %s" % target
        if category == "ip_mismatch" or _is_ip(target):
            why = ("The Management API is served by the Gaia portal web server. Its default "
                   "certificate is self-signed and carries the management IP only as the "
                   "Common Name, with no Subject Alternative Name (SAN). Python checks the "
                   "address you connect to against the SAN list, so connecting by IP to the "
                   "default certificate fails even with --ca-file. aiguard does not turn "
                   "certificate checks off.")
        else:
            why = ("The certificate does not list the name '%s'. The Management API uses "
                   "the Gaia portal certificate: by default it is self-signed, with the "
                   "management IP as its Common Name and no Subject Alternative Name. "
                   "aiguard does not turn certificate checks off." % target)
        return what, why, [sk_step, name_step, fp_step], state
    if category == "untrusted":
        what = "This computer does not trust the management server's certificate (%s)" % host
        if ca_file:
            why = ("The CA file %s does not contain the certificate that issued the "
                   "management server's certificate. The Management API uses the Gaia "
                   "portal certificate: self-signed by default, or signed by the Check "
                   "Point ICA." % ca_file)
        else:
            why = ("The Management API uses the Gaia portal certificate. It is self-signed "
                   "by default, or signed by the Check Point ICA. Neither is in this "
                   "computer's trust store, and aiguard does not turn certificate checks "
                   "off.")
        fix = [
            "Export the management server's web certificate to a PEM file (Expert mode on "
            "the server: /web/conf/server.crt), or the Check Point ICA certificate if the "
            "portal certificate is ICA-signed",
            "Compare its SHA1 fingerprint with `api fingerprint` on the server: "
            "openssl x509 -in <file.pem> -noout -fingerprint -sha1",
            "Pass it with --ca-file <file.pem> (web console: paste the PEM text)",
        ]
        if _is_ip(host) and not server_name:
            fix.append("Connecting by IP address: the default certificate has no IP in its "
                       "Subject Alternative Name, so the name check fails next. Use "
                       "--server-name <name in the certificate>, or replace the certificate "
                       "with an ICA-signed one that lists the IP (sk164382)")
        return what, why, fix, state
    if category in ("expired", "not_yet_valid"):
        what = ("The management server's certificate has expired" if category == "expired"
                else "The management server's certificate is not valid yet")
        why = "Certificates are only accepted inside their validity dates."
        fix = ["Check the date, time and time zone on this computer and on the management "
               "server", "Renew the Gaia portal certificate (sk164382), export it and pass "
               "--ca-file <file.pem>"]
        return what, why, fix, state
    if category == "strict":
        what = "Python rejected the management server's certificate chain"
        why = ("Python 3.13 and later check certificates strictly (RFC 5280). The "
               "certificate or its CA is missing an extension Python requires (see the "
               "server message).")
        fix = ["Re-issue the Gaia portal certificate signed by the Check Point ICA "
               "(sk164382) and export the ICA certificate for --ca-file",
               "Or run aiguard with Python 3.8-3.12, which do not apply the strict checks",
               fp_step]
        return what, why, fix, state
    if category == "not_tls":
        what = "%s:%d did not answer with TLS" % (host, port)
        why = "Something that is not the Management API HTTPS server answered on this port."
        fix = ["Check the port: the Management API listens on the Gaia portal port (443 by "
               "default; 4434 on some servers: see the url in `api status`)",
               "On the management server run: api status"]
        return what, why, fix, state
    if category == "old_tls":
        what = "%s:%d does not offer TLS 1.2 or newer" % (host, port)
        why = "aiguard requires TLS 1.2 or newer."
        fix = ["Update the management server (Gaia) or enable TLS 1.2 on the Gaia portal"]
        return what, why, fix, state
    what = "TLS connection to the management server %s:%d failed" % (host, port)
    why = "The TLS handshake failed (see the server message)."
    fix = ["Check the address and port", "On the management server run: api status", fp_step]
    return what, why, fix, state


def _provider_text(category: str, host: str, port: int, target: str,
                   ca_file: Optional[str]) -> Tuple[str, str, List[str], str]:
    state = "The request was not sent."
    deploy = ("Deploy the gateway's outbound CA to this computer: SmartConsole > Gateway > "
              "HTTPS Inspection > Step 2 (export the certificate, then deploy it with GPO or "
              "import it into this computer's trust store; `aiguard trust-ca` shows the "
              "commands)")
    pass_ca = "Or pass --outbound-ca <outbound-ca.pem>"
    if category == "untrusted":
        what = "This computer does not trust the certificate presented for %s" % host
        why = ("A gateway (HTTPS Inspection) or a proxy re-signed the certificate for %s "
               "with a CA this computer does not trust. Inspection is happening; this "
               "computer just does not trust the gateway's outbound CA yet." % host)
        if ca_file:
            why += (" The CA file %s does not contain the CA that signed it: export the "
                    "outbound CA from the gateway again." % ca_file)
        return what, why, [deploy, pass_ca], state
    if category in ("ip_mismatch", "hostname_mismatch"):
        what = "The certificate presented for %s is for a different name" % host
        why = ("HTTPS Inspection re-signs certificates with the original name, so a name "
               "mismatch usually means a proxy, captive portal or DNS entry is redirecting "
               "%s." % host)
        fix = ["Check DNS for %s on this computer (nslookup %s)" % (host, host),
               "Check proxy settings (HTTPS_PROXY) and any captive portal",
               "See who issued it: openssl s_client -connect %s:%d -servername %s </dev/null"
               " | openssl x509 -noout -subject -issuer" % (host, port, host)]
        return what, why, fix, state
    if category in ("expired", "not_yet_valid"):
        what = "The certificate presented for %s is outside its validity dates" % host
        why = ("Either this computer's clock is wrong or the certificate (or the gateway's "
               "outbound CA) has expired.")
        fix = ["Check the date, time and time zone on this computer",
               "Check the outbound CA validity: SmartConsole > Gateway > HTTPS Inspection > "
               "Step 1", pass_ca]
        return what, why, fix, state
    if category == "strict":
        what = "Python rejected the certificate chain presented for %s" % host
        why = ("Python 3.13 and later check certificates strictly (RFC 5280). The "
               "certificate or the CA that re-signed it is missing an extension Python "
               "requires (see the server message).")
        fix = ["Re-create the gateway's outbound CA with standard CA extensions "
               "(SmartConsole > Gateway > HTTPS Inspection > Step 1), then deploy it again",
               "Or run aiguard with Python 3.8-3.12, which do not apply the strict checks"]
        return what, why, fix, state
    what = "TLS connection to %s:%d failed" % (host, port)
    why = "The TLS handshake failed (see the server message)."
    fix = ["Check that this computer can reach %s:%d (proxy, DNS, firewall)" % (host, port),
           deploy, pass_ca]
    return what, why, fix, state
