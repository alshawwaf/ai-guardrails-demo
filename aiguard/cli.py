"""``aiguard`` command line (spec 9.1): ``python -m aiguard`` or the ``aiguard`` script.

Every command works through :class:`aiguard.engine.Session` (the same orchestration
the web console uses). The CLI adds prompts, approval, rendering and exit codes:

==========  =====================================================================
exit code   meaning
==========  =====================================================================
0           ok (also: the user cancelled before anything was written)
1           expectation mismatch (a demo prompt did not do what we expected, or the
            enforcement check after setup did not block the test prompt)
2           blocking preflight result / not supported (also: usage errors)
3           an :class:`~aiguard.errors.AiguardError` (rendered as the five-field
            block: What failed / Server said / Why / Fix / State + Details)
130         Ctrl-C (the open management session is discarded first)
==========  =====================================================================

Secrets are never taken from the command line: only from a hidden prompt
(:mod:`getpass`) or from an environment variable *named* on the command line
(``--api-key-env``, ``--password-env``, ``--lakera-key-env``, ``--provider-key-env``).
Flags such as ``--api-key`` / ``--password`` are refused before parsing, without
echoing their value.

Defaults from the environment (:mod:`aiguard.envdefaults`, written to ``.env`` by the lab
installer): when ``--server``, ``--port``, ``--server-type``, ``--domain``,
``--server-name``, ``--ca-file`` or ``--gateway`` is not given, ``AIGUARD_MGMT_SERVER``,
``AIGUARD_MGMT_PORT``, ``AIGUARD_MGMT_TYPE``, ``AIGUARD_MGMT_DOMAIN``,
``AIGUARD_MGMT_SERVER_NAME``, ``AIGUARD_MGMT_CA_FILE`` and ``AIGUARD_GATEWAY`` are used
before the remembered state and before asking; ``setup`` shows them as the default
answers. Flags always win. Port, type, domain and server name apply only to the
configured server; ``AIGUARD_MGMT_CA_FILE`` is checked like ``--ca-file`` and is for the
management connection only (the provider connections use ``--outbound-ca``).

Testing: :func:`main` takes ``console`` (a :class:`Console` whose ``input`` /
``secret`` / ``print`` can be scripted) and ``session_factory`` (called with the
``Session`` keyword arguments; tests use it to point the session at fake servers).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import getpass
import hashlib
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import ssl
import sys
import textwrap
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from . import __version__
from . import envdefaults as _envdefaults
from . import paths as _paths
from . import probe as _probe
from . import redact as _redact
from . import runlog as _runlog
from . import scenes as _scenes
from . import tlsutil as _tlsutil
from .engine import Session
from .errors import AiguardError, ApprovalError, LakeraError, PlanError, TlsTrustError
from .plan import PlanOptions
from .runlog import RunLog
from .state import State

__all__ = [
    "main",
    "Console",
    "build_parser",
    "EXIT_OK",
    "EXIT_MISMATCH",
    "EXIT_BLOCKED",
    "EXIT_ERROR",
    "EXIT_INTERRUPTED",
]

EXIT_OK = 0
EXIT_MISMATCH = 1
EXIT_BLOCKED = 2
EXIT_ERROR = 3
EXIT_INTERRUPTED = 130
EXIT_USAGE = 2

LABEL_W = 30          # width of the "? Label" / "OK Label" column
FIELD_W = 14          # width of the "What failed" column of an error block
RESULT_INDENT = " " * 15

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PLAN_ID_RE = re.compile(r"^[0-9a-f]{12}$")

# Flags that would carry a secret. Refused before argparse sees them (argparse would
# echo the value in "unrecognized arguments: ...").
_SECRET_FLAG_RE = re.compile(
    r"^--?(?:api[-_]?key|apikey|key|password|passwd|pass|pw|secret|token|sid|"
    r"lakera[-_]?(?:api[-_]?)?key|guard[-_]?(?:api[-_]?)?key|provider[-_]?key|"
    r"(?:openai|anthropic|gemini|llm|ai)[-_]?(?:api[-_]?)?key)(?:=.*)?$",
    re.IGNORECASE)

_GLYPHS_UTF8 = {
    "ok": "✓", "fail": "✗", "warn": "!", "arrow": "▸", "full": "█",
    "empty": "░", "bar": "▌", "pick": "›", "pipe": "│", "dash": "–",
    "rule": "─", "dot": "·", "to": "→", "dots": "•" * 8, "ell": "…",
}
_GLYPHS_ASCII = {
    "ok": "OK", "fail": "X", "warn": "!", "arrow": ">", "full": "#", "empty": ".",
    "bar": "|", "pick": ">", "pipe": "|", "dash": "-", "rule": "-", "dot": "-", "to": "->",
    "dots": "*" * 8, "ell": "...",
}

_STYLES = {
    "bold": "1", "dim": "90", "white": "1;97", "magenta": "95", "blue": "94",
    "amber": "33", "green": "32", "red": "91",
    "blocked": "1;30;105", "allowed": "1;30;42", "unknown": "1;30;43", "error": "1;97;41",
    "failed": "1;97;41", "stopped": "1;30;43",
}

_BADGE = {"BLOCKED": "blocked", "ALLOWED": "allowed", "UNKNOWN": "unknown", "ERROR": "error"}

_SERVER_KIND = {"SMS": "Security Management Server", "MDS": "Multi-Domain Server"}


# =========================================================================== console


def _isatty(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _utf8_capable(stream: Any) -> bool:
    enc = getattr(stream, "encoding", None)
    if not enc:
        return False
    try:
        return codecs.lookup(enc).name in ("utf-8", "utf-8-sig", "utf-16", "utf-32")
    except LookupError:
        return False


def _enable_windows_vt(stream: Any) -> bool:
    """Turn on ANSI escape handling in a Windows console (best effort, via ctypes)."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-12 if stream is sys.stderr else -11)
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        enable_vt = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if mode.value & enable_vt:
            return True
        return bool(kernel32.SetConsoleMode(handle, mode.value | enable_vt))
    except Exception:  # noqa: BLE001 - no colour is fine
        return False


def _color_capable(stream: Any) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if not _isatty(stream):
        return False
    return _enable_windows_vt(stream)


def _reconfigure_stdio() -> None:
    """``errors="replace"`` so a cp1252 console never crashes on a glyph (spec 2.4)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (ValueError, OSError, TypeError):
            pass


class Console(object):
    """Terminal I/O for every command. Tests subclass it and script ``input`` /
    ``secret`` (and capture ``print`` / ``write``).

    ``unicode``: use the ✓ ✗ ▸ █ glyphs (only when stdout can encode them);
    otherwise ASCII ``OK X > #``. ``color``: ANSI colours (only on a terminal,
    never with ``NO_COLOR`` / ``--no-color``).
    """

    def __init__(self, stdout: Any = None, stdin: Any = None, *, color: Optional[bool] = None,
                 unicode: Optional[bool] = None, width: Optional[int] = None) -> None:
        self.stdout = stdout if stdout is not None else sys.stdout
        self.stdin = stdin if stdin is not None else sys.stdin
        self.unicode = _utf8_capable(self.stdout) if unicode is None else bool(unicode)
        self.color = _color_capable(self.stdout) if color is None else bool(color)
        if width is None:
            try:
                width = shutil.get_terminal_size((100, 24)).columns
            except (OSError, ValueError):
                width = 100
        self.width = max(60, min(int(width), 160))

    # ------------------------------------------------------------------ properties

    @property
    def interactive(self) -> bool:
        """A person can answer prompts (stdin is a terminal)."""
        return _isatty(self.stdin)

    @property
    def live(self) -> bool:
        """stdout is a terminal (transient progress lines are allowed)."""
        return _isatty(self.stdout)

    # ------------------------------------------------------------------ output

    def write(self, text: str) -> None:
        try:
            self.stdout.write(text)
        except UnicodeEncodeError:
            enc = getattr(self.stdout, "encoding", None) or "ascii"
            self.stdout.write(text.encode(enc, "replace").decode(enc, "replace"))
        try:
            self.stdout.flush()
        except (OSError, ValueError, AttributeError):
            pass

    def print(self, text: str = "") -> None:
        self.write(text + "\n")

    # ------------------------------------------------------------------ input

    def input(self, prompt: str = "") -> str:
        """One line from the user (raises EOFError when input ended)."""
        if self.stdin is sys.stdin and self.stdout is sys.stdout:
            return input(prompt)
        self.write(prompt)
        line = self.stdin.readline()
        if not line:
            raise EOFError
        return line.rstrip("\r\n")

    def secret(self, prompt: str = "") -> str:
        """A hidden answer (never echoed, never logged)."""
        return getpass.getpass(prompt)

    # ------------------------------------------------------------------ styling

    def style(self, text: str, *names: str) -> str:
        if not self.color or not names:
            return text
        codes = ";".join(_STYLES[n] for n in names if n in _STYLES)
        return "\x1b[%sm%s\x1b[0m" % (codes, text) if codes else text

    def g(self, name: str) -> str:
        return (_GLYPHS_UTF8 if self.unicode else _GLYPHS_ASCII).get(name, "")


# =========================================================================== arguments


class _UsageError(Exception):
    def __init__(self, message: str, usage: str = "") -> None:
        super().__init__(message)
        self.usage = usage


class _Parser(argparse.ArgumentParser):
    """No abbreviations (``--api-key`` must never match ``--api-key-env``) and errors
    raised instead of printed (the message is sanitised before display)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> None:  # type: ignore[override]
        raise _UsageError(message, self.format_usage())


def _port_type(value: str) -> int:
    try:
        port = int(str(value).strip())
    except ValueError:
        raise argparse.ArgumentTypeError("not a port number") from None
    if not 0 < port < 65536:
        raise argparse.ArgumentTypeError("a port is 1-65535")
    return port


def _ip_type(value: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise argparse.ArgumentTypeError("not an IP address") from None


def build_parser() -> argparse.ArgumentParser:
    """The ``aiguard`` argument parser (no flag takes a secret value)."""
    glob = _Parser(add_help=False, argument_default=argparse.SUPPRESS)
    glob.add_argument("--home", metavar="DIR",
                      help="where logs, reports and state live (default: $AIGUARD_HOME or "
                           "~/.aiguard)")
    glob.add_argument("--no-color", action="store_true", help="no colours")
    glob.add_argument("-v", "--verbose", action="store_true", help="show more detail")

    conn = _Parser(add_help=False)
    g = conn.add_argument_group("management server")
    g.add_argument("--server", metavar="ADDRESS",
                   help="management server (SMS/MDS) address (default: $AIGUARD_MGMT_SERVER, "
                        "else the last one)")
    g.add_argument("--port", type=_port_type, metavar="N",
                   help="web API port (default: $AIGUARD_MGMT_PORT, else 443)")
    g.add_argument("--server-type", choices=["sms", "mds"], type=str.lower,
                   help="SMS or MDS (asked by setup when not given; default $AIGUARD_MGMT_TYPE)")
    g.add_argument("--domain", metavar="NAME", help="MDS domain (default: $AIGUARD_MGMT_DOMAIN)")
    g.add_argument("--api-key-env", metavar="VAR",
                   help="read the Management API key from environment variable VAR")
    g.add_argument("--user", metavar="NAME", help="administrator name (password is asked, "
                                                  "hidden)")
    g.add_argument("--password-env", metavar="VAR",
                   help="read the password for --user from environment variable VAR")
    g.add_argument("--ca-file", metavar="PEM",
                   help="extra CA certificate(s) to trust: the management certificate / ICA, "
                        "and (unless --outbound-ca is given) the gateway's outbound CA "
                        "(default for the management connection: $AIGUARD_MGMT_CA_FILE)")
    g.add_argument("--server-name", metavar="NAME",
                   help="name in the management certificate when it differs from --server "
                        "(default: $AIGUARD_MGMT_SERVER_NAME)")
    g.add_argument("--gateway", metavar="NAME",
                   help="target gateway or cluster (default: $AIGUARD_GATEWAY)")

    planp = _Parser(add_help=False)
    p = planp.add_argument_group("demo policy")
    p.add_argument("--profile-name", metavar="NAME", help="threat profile (default AIGuard-Demo)")
    p.add_argument("--rule-name", metavar="NAME", help="threat rule (default \"AI Guard Demo\")")
    p.add_argument("--track", metavar="TRACK", help="rule track (default Log)")
    p.add_argument("--scope", metavar="SCOPE",
                   help="protected scope: client (this computer only, default), any, or an "
                        "existing object name")
    p.add_argument("--package", metavar="NAME", help="policy package (default: the gateway's)")
    p.add_argument("--moderation", dest="moderation", action="store_const", const=True,
                   default=None, help="also turn on content moderation on the gateway")
    p.add_argument("--no-moderation", dest="moderation", action="store_const", const=False,
                   help="no content moderation")
    p.add_argument("--project-id", metavar="ID", help="AI Guardrails project ID")
    p.add_argument("--lakera-key-env", metavar="VAR",
                   help="read the AI Agent Security (Guard) API key from environment variable "
                        "VAR")
    p.add_argument("--no-install", action="store_true",
                   help="publish only, do not install the policy")

    provp = _Parser(add_help=False)
    v = provp.add_argument_group("AI provider")
    v.add_argument("--provider", choices=sorted(_probe.PROVIDERS), type=str.lower,
                   default="openai", help="AI developer API to send prompts to (default openai)")
    v.add_argument("--provider-key-env", metavar="VAR",
                   help="read the provider API key from environment variable VAR (default: "
                        "the provider's usual variable, e.g. OPENAI_API_KEY; else a dummy key)")
    v.add_argument("--model", metavar="MODEL", help="model (default: the provider's small model)")
    v.add_argument("--outbound-ca", metavar="PEM",
                   help="the gateway's outbound CA, for the provider connections")
    v.add_argument("--local-ip", type=_ip_type, metavar="IP",
                   help="this computer's IP address as the gateway sees it (behind NAT or in "
                        "Docker); default: $AIGUARD_LOCAL_IP, else detected")

    parser = _Parser(
        prog="aiguard", parents=[glob],
        description="AI Guard Demo Kit: set up and show Check Point AI Agent Security on a "
                    "gateway.",
        epilog="Secrets are never taken from the command line: use the hidden prompts or the "
               "*-env VAR options.")
    parser.add_argument("--version", action="version",
                        version="aiguard %s (AI Guard Demo Kit)" % __version__)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    def add(name: str, text: str, parents: Sequence[argparse.ArgumentParser],
            func: Callable[["_Run"], int]) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=text, description=text, parents=[glob] + list(parents))
        sp.set_defaults(func=func)
        return sp

    sp = add("setup", "guided setup: connect, preflight, build and install the demo policy",
             [conn, planp, provp], cmd_setup)
    sp.add_argument("--approve", metavar="PLAN_ID",
                    help="approve this plan id without the typed APPROVE prompt")
    sp.add_argument("--continue-anyway", action="store_true",
                    help="go on after a blocking preflight result")
    sp.add_argument("--skip-enforcement", action="store_true",
                    help="do not send the test prompt after install")

    add("preflight", "check the management server, gateway and traffic path (read-only)",
        [conn, provp], cmd_preflight)

    add("plan", "show the change the demo needs (read-only)", [conn, planp, provp], cmd_plan)

    sp = add("apply", "apply a reviewed plan (asks for typed APPROVE)", [conn, planp, provp],
             cmd_apply)
    sp.add_argument("--plan-id", metavar="PLAN_ID", help="the plan id you reviewed")
    sp.add_argument("--approve", metavar="PLAN_ID",
                    help="approve this plan id without the typed APPROVE prompt")
    sp.add_argument("--skip-enforcement", action="store_true",
                    help="do not send the test prompt after install")

    sp = add("demo", "send demo prompts through the gateway and show what it does",
             [conn, provp], cmd_demo)
    sp.add_argument("--guided", action="store_true", help="presenter mode: scenes with say: lines")
    sp.add_argument("--scene", metavar="SCENE",
                    help="one scene: %s (or its number)" % ", ".join(_scenes.scene_ids()))
    sp.add_argument("--prompt", metavar="TEXT", help="send your own prompt")
    sp.add_argument("--expect", choices=["block", "allow"], type=str.lower,
                    help="what --prompt should do (default block)")
    sp.add_argument("--json", metavar="FILE", help="also write the results as JSON")
    sp.add_argument("--no-pause", action="store_true", help="do not wait for Enter between scenes")
    sp.add_argument("--no-logs", action="store_true",
                    help="do not match the results to gateway logs")
    sp.add_argument("--skip-tls-check", action="store_true",
                    help="run even when the provider traffic is not inspected")

    sp = add("rollback", "undo what setup/apply/fix changed", [conn], cmd_rollback)
    sp.add_argument("rollback_id", nargs="?", metavar="ID", help="rollback id (default: latest)")
    sp.add_argument("--no-install", action="store_true", help="publish only, do not install")
    sp.add_argument("--yes", action="store_true", help="do not ask for confirmation")

    sp = add("logs", "show the latest run log (secrets are never in it)", [], cmd_logs)
    sp.add_argument("--last", action="store_true", help="the latest log (default)")
    sp.add_argument("--path", action="store_true", help="print only the log path")
    sp.add_argument("--errors", action="store_true", help="only warnings, errors and hints")
    sp.add_argument("--json", action="store_true", help="structured records (JSON lines)")
    sp.add_argument("-n", "--lines", type=int, metavar="N", help="how many lines")

    sp = add("fix", "fix a preflight problem (asks for typed APPROVE)", [conn, provp], cmd_fix)
    sp.add_argument("target", choices=["https-inspection"], help="what to fix")
    sp.add_argument("--add-rule", action="store_true",
                    help="also add an Inspect rule for this computer at the top of the HTTPS "
                         "Inspection policy")
    sp.add_argument("--approve", metavar="PLAN_ID",
                    help="approve this plan id without the typed APPROVE prompt")

    sp = add("trust-ca", "export the gateway's outbound CA and show how to trust it",
             [conn], cmd_trust_ca)
    sp.add_argument("--export", metavar="FILE",
                    help="where to write the PEM (default <home>/outbound-ca.pem)")
    sp.add_argument("--from-file", metavar="FILE",
                    help="use this certificate file instead of asking the management server")
    sp.add_argument("--os", dest="target_os", choices=["auto", "windows", "macos", "linux", "all"],
                    default="auto", help="which commands to show (default: this computer)")
    sp.add_argument("--force", action="store_true", help="overwrite --export FILE")

    sp = add("status", "what the kit knows: last server, rollback points, logs", [conn],
             cmd_status)
    sp.add_argument("--connect", action="store_true",
                    help="also connect and read the gateway state")

    add("version", "print the version", [], cmd_version)
    return parser


def _secret_flag(argv: Sequence[str]) -> Optional[str]:
    """The first flag that would carry a secret (its value is registered for redaction)."""
    for i, token in enumerate(argv):
        if token == "--":
            break
        if _SECRET_FLAG_RE.match(token):
            if "=" in token:
                _redact.register_secret(token.split("=", 1)[1])
            elif i + 1 < len(argv):
                _redact.register_secret(argv[i + 1])
            return token.split("=", 1)[0]
    return None


def _safe_usage_message(message: str) -> str:
    """argparse errors echo values ("unrecognized arguments: --x VALUE"); keep only the
    option names so a mistyped secret is never printed."""
    m = re.match(r"^(unrecognized arguments:)\s*(.*)$", message, re.S)
    if m:
        kept = [t if t.startswith("-") and len(t) <= 40 else "…" for t in m.group(2).split()]
        return "%s %s" % (m.group(1), " ".join(kept))
    return _redact.redact(message)[:300]


# =========================================================================== helpers


class _Stop(Exception):
    """End the command with this exit code (the reason was already printed)."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


def _unique(items: Iterable[str]) -> List[str]:
    out: List[str] = []
    for item in items:
        if item and item not in out:
            out.append(item)
    return out


def _preview(text: str, limit: int = 58) -> str:
    one = " ".join(str(text or "").split())
    return one if len(one) <= limit else one[: limit - 3].rstrip() + "..."


def _match_choice(answer: str, options: Sequence[str]) -> Optional[str]:
    a = answer.strip()
    if a.isdigit() and 1 <= int(a) <= len(options):
        return options[int(a) - 1]
    low = a.lower()
    for o in options:
        if o.lower() == low:
            return o
    hits = [o for o in options if o.lower().startswith(low)]
    return hits[0] if len(hits) == 1 else None


def _os_name() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _provider_target(session: Any, provider: str) -> Tuple[Optional[str], Optional[str], int]:
    """``(provider host, address actually connected to, port)`` for the TLS check."""
    info = _probe.PROVIDERS.get(provider) or {}
    host = info.get("host")
    target, port = host, 443
    base = (getattr(session, "provider_base_urls", None) or {}).get(provider)
    if base:
        try:
            parts = urlsplit(base)
            if parts.hostname:
                target, port = parts.hostname, int(parts.port or 443)
                host = host or parts.hostname
        except ValueError:
            pass
    endpoint = (getattr(session, "probe_endpoints", None) or {}).get(host) if host else None
    if isinstance(endpoint, (tuple, list)) and len(endpoint) == 2:
        target, port = str(endpoint[0]), int(endpoint[1])
    elif isinstance(endpoint, str) and endpoint:
        try:
            parts = urlsplit(endpoint if "://" in endpoint else "https://" + endpoint)
            if parts.hostname:
                target, port = parts.hostname, int(parts.port or 443)
        except ValueError:
            pass
    return host, target, port


def _normalize_pem(data: Any, *, what: str = "certificate") -> str:
    """PEM text (one or more certificates, LF line ends) from PEM text, base64 DER or
    DER bytes. Refuses files with private keys."""
    if isinstance(data, bytes):
        raw = data
        if b"-----BEGIN" not in raw:
            try:
                return ssl.DER_cert_to_PEM_cert(raw)
            except (ValueError, TypeError):
                raw = raw.strip()
        text = raw.decode("ascii", "replace")
    else:
        text = str(data or "")
    if "PRIVATE KEY" in text:
        raise AiguardError(
            "This file contains a private key", code="cli.private_key",
            why="Only the CA certificate is needed to trust the gateway; a private key must "
                "never be copied to the demo computers.",
            fix=["SmartConsole > Gateway > HTTPS Inspection > Step 2: Export certificate "
                 "(certificate only, no private key)",
                 "Or let aiguard read it from the management server: aiguard trust-ca"],
            state="Nothing was written.")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S)
    if not blocks and "-----BEGIN" not in text and text.strip():
        blocks = [text]
    pems: List[str] = []
    for body in blocks:
        try:
            der = base64.b64decode("".join(body.split()), validate=True)
            pems.append(ssl.DER_cert_to_PEM_cert(der))
        except (binascii.Error, ValueError, TypeError):
            continue
    if not pems:
        raise AiguardError(
            "No certificate found in the %s" % what, code="cli.no_certificate",
            why="Expected a PEM (-----BEGIN CERTIFICATE-----) or DER certificate.",
            fix=["Export the outbound CA again: SmartConsole > Gateway > HTTPS Inspection > "
                 "Step 2: Export certificate",
                 "Or let aiguard read it from the management server: aiguard trust-ca"],
            state="Nothing was written.")
    return "".join(pems)


def _pem_sha256(pem: str) -> str:
    der = ssl.PEM_cert_to_DER_cert(pem.split("-----END CERTIFICATE-----")[0]
                                   + "-----END CERTIFICATE-----\n")
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(".%s.%d.tmp" % (path.name, os.getpid()))
    try:
        with open(str(tmp), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(str(tmp), str(path))
    except BaseException:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise


def _read_jsonl(path: Path) -> List[dict]:
    out: List[dict] = []
    try:
        with open(str(path), "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    out.append(rec)
    except OSError:
        return []
    return out


def _latest_report(home: Path) -> Optional[Path]:
    d = _paths.reports_dir(home, create=False)
    try:
        files = [p for p in d.glob("*.html") if p.is_file()]
    except OSError:
        return None
    if not files:
        return None
    return max(files, key=lambda p: (p.stat().st_mtime, p.name))


# =========================================================================== one run


class _Run(object):
    """State of one command: arguments, console, log, engine session."""

    def __init__(self, args: argparse.Namespace, console: Console,
                 factory: Optional[Callable[..., Any]]) -> None:
        self.args = args
        self.c = console
        self.factory = factory
        self.home = _paths.aiguard_home(getattr(args, "home", None))
        self.state = State(_paths.state_path(self.home))
        self.log: Optional[RunLog] = None
        self.session: Any = None
        self.verbose = bool(getattr(args, "verbose", False))
        self.stage = ""
        self.connected = False
        self.conn_info: Optional[dict] = None
        self.approved_id: Optional[str] = None
        self.provider_key_set = False
        self.correlate_s = 0.0
        self._live_open = False
        self._env: Optional[_envdefaults.Defaults] = None
        self._env_warned = False

    # ------------------------------------------------------------------ plumbing

    def arg(self, name: str, default: Any = None) -> Any:
        value = getattr(self.args, name, None)
        return default if value is None else value

    @property
    def env(self) -> "_envdefaults.Defaults":
        """Connection defaults from the environment (read once per run)."""
        if self._env is None:
            self._env = _envdefaults.from_env()
        return self._env

    def env_problems(self) -> None:
        """Say once which environment defaults were ignored (and why)."""
        if self._env_warned:
            return
        self._env_warned = True
        for problem in self.env.problems:
            self.line("warn", "Environment", problem)
            if self.log is not None:
                self.log.warn("cli", "environment default ignored", problem=problem)

    def env_ca_file(self) -> str:
        """``AIGUARD_MGMT_CA_FILE``, checked the way ``--ca-file`` is (missing, not a
        file, not PEM): an :class:`AiguardError` naming the variable otherwise."""
        name = _envdefaults.ENV_CA_FILE
        path = Path(str(self.env.ca_file)).expanduser()
        try:
            _tlsutil.make_context(str(path))
        except TlsTrustError as exc:
            raise TlsTrustError(
                "The CA file in %s cannot be used: %s" % (name, exc.what), code=exc.code,
                server_said=exc.server_said,
                why="%s (set in .env by the lab installer) names the CA certificate for the "
                    "management connection. %s" % (name, exc.why or ""),
                fix=["Check the file and the path in .env (%s=%s); run the installer again "
                     "to save the certificate" % (name, path),
                     "Or pass --ca-file <file.pem> to use another file (a flag wins over "
                     "the environment)",
                     "Or empty %s in .env to connect without it" % name],
                state="No connection was made.",
                details={"variable": name, "ca_file": str(path)}) from None
        return str(path)

    def open(self) -> Any:
        """The engine session (created on first use, with its run log)."""
        if self.session is not None:
            return self.session
        self.log = RunLog(home=self.home)
        kwargs: Dict[str, Any] = {"log": self.log, "home": self.home}
        ca = self.arg("outbound_ca") or self.arg("ca_file")
        if ca:
            kwargs["provider_ca_file"] = str(Path(str(ca)).expanduser())
        if self.arg("local_ip"):
            kwargs["local_ip"] = self.arg("local_ip")
        factory = self.factory or Session
        self.session = factory(**kwargs)
        given = sorted(k for k, v in vars(self.args).items()
                       if k != "func" and v not in (None, False, ""))
        self.log.info("cli", "aiguard %s" % self.args.command, options=given, version=__version__,
                      python=platform.python_version())
        return self.session

    def close(self) -> None:
        if self.session is not None:
            try:
                self.session.close()
            except Exception:  # noqa: BLE001 - close never fails the command
                pass
        if self.log is not None:
            try:
                self.log.close()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------ output

    def p(self, text: str = "") -> None:
        self._clear_live()
        self.c.print(text)

    def st(self, text: str, *names: str) -> str:
        return self.c.style(text, *names)

    def dim(self, text: str) -> str:
        return self.c.style(text, "dim")

    def bold(self, text: str) -> str:
        return self.c.style(text, "white")

    def live(self, text: str) -> None:
        """A transient progress line (terminals only)."""
        if not self.c.live:
            return
        self.c.write("\r" + text[: self.c.width - 1].ljust(self.c.width - 1))
        self._live_open = True

    def _clear_live(self) -> None:
        if self._live_open:
            self.c.write("\r" + " " * (self.c.width - 1) + "\r")
            self._live_open = False

    def wrap(self, text: str, indent: int = 18) -> List[str]:
        width = max(40, self.c.width - indent)
        out: List[str] = []
        for para in str(text or "").splitlines() or [""]:
            out.extend(textwrap.wrap(para, width=width) or [""])
        return out

    def bar(self, pct: Optional[float], cells: int = 20) -> str:
        pct = max(0.0, min(100.0, float(pct or 0)))
        full = int(round(cells * pct / 100.0))
        return self.st(self.c.g("full") * full, "green") + self.dim(self.c.g("empty") * (cells - full))

    def banner(self) -> None:
        bar = self.st(self.c.g("bar"), "magenta")
        dot = self.c.g("dot")
        self.p()
        self.p("  %s%s %s" % (bar, self.bold("AI Guard Demo Kit"),
                              self.dim("v%s  %s  Check Point AI Agent Security" % (__version__, dot))))
        if self.log is not None:
            self.p("  %s%s" % (bar, self.dim("log  %s %s" % (self.c.g("to"), self.log.path))))

    def section(self, n: Optional[int], total: int, title: str, extra: str = "") -> None:
        self.p()
        head = ("%s " % self.st("[%d/%d]" % (n, total), "blue")) if n else ""
        self.p("  %s%s%s" % (head, self.bold(title), ("  " + self.dim(extra)) if extra else ""))

    def line(self, kind: str, label: str, value: str = "", note: str = "") -> None:
        sym = {"ok": (self.c.g("ok"), "green"), "fail": (self.c.g("fail"), "red"),
               "warn": (self.c.g("warn"), "amber"), "skip": (self.c.g("dash"), "dim"),
               "q": ("?", "blue"), "info": (" ", None)}.get(kind, (" ", None))
        mark = self.st(sym[0], sym[1]) if sym[1] else sym[0]
        text = "  %s %s" % (mark, label.ljust(LABEL_W) + value if (value or note) else label)
        if note:
            text += "  " + self.dim(note)
        self.p(text.rstrip())

    def note(self, text: str, indent: int = 4) -> None:
        for ln in self.wrap(text, indent + 2):
            self.p(" " * indent + self.dim(ln))

    # ------------------------------------------------------------------ prompts

    def _prompt(self, label: str, hint: str = "") -> str:
        return "  %s %s%s" % (self.st("?", "blue"), label.ljust(LABEL_W),
                              (hint + " ") if hint else "")

    def _given(self, label: str, value: Any) -> None:
        self.p("  %s %s%s" % (self.st("?", "blue"), label.ljust(LABEL_W), self.bold(str(value))))

    def ask_text(self, label: str, *, default: Optional[str] = None, given: Any = None,
                 validate: Optional[Callable[[str], Optional[str]]] = None,
                 hint: str = "") -> str:
        if given is not None and str(given) != "":
            self._given(label, given)
            return str(given)
        shown = (hint + "  " if hint else "") + ("[%s]" % default if default else "")
        prompt = self._prompt(label, shown.strip())
        for _ in range(5):
            try:
                answer = self.c.input(prompt).strip()
            except EOFError:
                if default is not None:
                    self.p()
                    return default
                raise
            if not answer and default is not None:
                answer = default
            if not answer:
                self.p("    %s An answer is needed." % self.st(self.c.g("warn"), "amber"))
                continue
            problem = validate(answer) if validate else None
            if problem:
                self.p("    %s %s" % (self.st(self.c.g("warn"), "amber"), problem))
                continue
            return answer
        raise AiguardError("No valid answer for '%s'" % label, code="cli.no_answer",
                           fix=["Run the command again and answer the question, or pass the "
                                "matching option"], state="Nothing was changed.")

    def ask_choice(self, label: str, options: Sequence[str], *, default: str,
                   given: Any = None) -> str:
        if given is not None and str(given) != "":
            self._given(label, given)
            return _match_choice(str(given), options) or str(given)
        pick = self.c.g("pick")
        hint = "   ".join(("%s %s" % (pick, o)) if o == default else o for o in options)
        prompt = self._prompt(label, hint)
        for _ in range(5):
            try:
                answer = self.c.input(prompt).strip()
            except EOFError:
                self.p()
                return default
            if not answer:
                return default
            hit = _match_choice(answer, options)
            if hit:
                return hit
            self.p("    %s Answer one of: %s (or its number)"
                   % (self.st(self.c.g("warn"), "amber"), ", ".join(options)))
        raise AiguardError("No valid answer for '%s'" % label, code="cli.no_answer",
                           fix=["Answer one of: %s" % ", ".join(options)],
                           state="Nothing was changed.")

    def ask_yes_no(self, label: str, *, default: bool = False, given: Optional[bool] = None) -> bool:
        if given is not None:
            self._given(label, "yes" if given else "no")
            return bool(given)
        text = label.ljust(LABEL_W) if len(label) < LABEL_W else label + " "
        prompt = "  %s %s%s " % (self.st("?", "blue"), text, self.dim("(Y/n)" if default else "(y/N)"))
        for _ in range(5):
            try:
                answer = self.c.input(prompt).strip().lower()
            except EOFError:
                self.p()
                return default
            if not answer:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            self.p("    %s Answer y or n." % self.st(self.c.g("warn"), "amber"))
        return default

    def ask_secret(self, label: str, *, allow_empty: bool = False, note: str = "",
                   keep_tail: bool = True) -> str:
        """A hidden answer; registered for redaction at once. Shown only masked
        (``keep_tail=False`` for passwords: ``****`` without the last characters)."""
        hint = self.dim(note or "input hidden, kept in memory, never written")
        prompt = "  %s %s%s " % (self.st("?", "blue"), label.ljust(LABEL_W), hint)
        for _ in range(3):
            value = (self.c.secret(prompt) or "").strip()
            if value:
                _redact.register_secret(value, keep_tail=keep_tail)
                self.p("    %s  %s" % (self.dim(self.c.g("dots")), self.dim(
                    "the log shows it as %s" % _redact.mask_secret(value, keep_tail=keep_tail))))
                return value
            if allow_empty:
                return ""
            self.p("    %s Nothing was entered." % self.st(self.c.g("warn"), "amber"))
        raise AiguardError("No %s was entered" % label, code="cli.no_secret",
                           fix=["Run the command again and paste it when asked (input is hidden)",
                                "Or put it in an environment variable and pass its name with the "
                                "matching *-env option"],
                           state="Nothing was changed.")

    def env_secret(self, flag: str, name: str, what: str, *, keep_tail: bool = True) -> str:
        """The secret in environment variable ``name`` (named by ``flag``)."""
        if not _ENV_NAME_RE.match(str(name or "")):
            _redact.register_secret(str(name or ""))
            raise AiguardError(
                "%s needs the name of an environment variable" % flag, code="cli.bad_env_name",
                why="It takes a variable name such as AIGUARD_KEY, not the secret itself: secrets "
                    "are never taken from the command line.",
                fix=["Put the value in an environment variable (macOS/Linux: export AIGUARD_KEY=...; "
                     "PowerShell: $env:AIGUARD_KEY = \"...\"), then pass %s AIGUARD_KEY" % flag,
                     "Or leave %s out and type the value when asked (input hidden)" % flag],
                state="Nothing was changed.")
        value = os.environ.get(name, "").strip()
        if not value:
            raise AiguardError(
                "Environment variable %s is not set" % name, code="cli.env_missing",
                why="%s %s reads %s from that variable, and it is empty." % (flag, name, what),
                fix=["Set %s first (macOS/Linux: export %s=...; PowerShell: $env:%s = \"...\")"
                     % (name, name, name),
                     "Or leave %s out and type the value when asked (input hidden)" % flag],
                state="Nothing was changed.")
        _redact.register_secret(value, keep_tail=keep_tail)
        return value

    def pause(self, text: str) -> None:
        if not self.arg("guided") or self.arg("no_pause"):
            return
        try:
            self.c.input("    %s " % self.dim("%s %s" % (self.c.g("arrow"), text)))
        except EOFError:
            self.p()
            self.args.no_pause = True

    # ------------------------------------------------------------------ errors

    def render_error(self, err: AiguardError, *, header: Optional[str] = None,
                     badge: str = "FAILED") -> None:
        """The five-field block (What failed / Server said / Why / Fix / State) + Details."""
        if getattr(err, "log_line", None) is None and self.log is not None:
            try:
                self.log.exception(err, "cli")
            except Exception:  # noqa: BLE001 - rendering must not fail
                pass
        d = err.to_dict() if hasattr(err, "to_dict") else {"what": str(err)}
        dot = self.c.g("dot")
        rows: List[Tuple[str, List[str]]] = [("What failed", self.wrap(d.get("what") or "", 18))]
        said = d.get("server_said")
        if said:
            text = str(said).strip()
            if len(text) > 600:
                text = text[:597] + "..."
            lines: List[str] = []
            for raw in [ln.strip() for ln in text.splitlines() if ln.strip()]:
                lines.extend(self.wrap(raw, 20))
            lines = lines or [""]
            lines[0] = '"' + lines[0]
            lines[-1] = lines[-1] + '"'
            rows.append(("Server said", [lines[0]] + [" " + ln for ln in lines[1:]]))
        if d.get("why"):
            rows.append(("Why", self.wrap(d["why"], 18)))
        fixes = [str(f) for f in (d.get("fix") or []) if str(f).strip()]
        if fixes:
            rows.append(("Fix", ["%d. %s" % (i, f) for i, f in enumerate(fixes, 1)]
                         if len(fixes) > 1 else fixes))
        else:
            rows.append(("Fix", ["See the log line below for the details"]))
        if d.get("state"):
            rows.append(("State", self.wrap(d["state"], 18)))
        line_no = getattr(err, "log_line", None)
        if self.log is not None:
            rows.append(("Details", ["log line %s %s %s" % (line_no, dot, self.log.path)
                                     if line_no else str(self.log.path)]))
        self.p()
        self.p("   %s  %s" % (self.st(" %s " % badge, "failed" if badge == "FAILED" else "stopped"),
                              self.bold(_redact.redact(header or d.get("what") or ""))))
        for label, lines in rows:
            for i, ln in enumerate(lines):
                self.p("  %s%s" % ((label if i == 0 else "").ljust(FIELD_W), ln))

    def stopped(self, title: str, rows: Sequence[Tuple[str, Sequence[str]]]) -> None:
        self.p()
        self.p("   %s  %s" % (self.st(" STOPPED ", "stopped"), self.bold(title)))
        for label, lines in rows:
            for i, ln in enumerate(lines):
                self.p("  %s%s" % ((label if i == 0 else "").ljust(FIELD_W), ln))

    def discard_open_session(self) -> str:
        s = self.session
        client = getattr(s, "client", None) if s is not None else None
        if client is None or not getattr(client, "logged_in", False):
            return ""
        try:
            fn = getattr(s, "discard", None)
            if callable(fn):
                done = fn()          # Session.discard: best effort, never raises
            else:
                client.discard()     # MgmtClient.discard is best effort and never raises
                done = True
            return ("The unpublished changes of this management session were discarded."
                    if done is not False else "")
        except Exception:  # noqa: BLE001 - best effort
            return ""

    def interrupted(self) -> int:
        self._clear_live()
        self.c.print()
        note = self.discard_open_session()
        self.c.print("  %s Interrupted (Ctrl-C).%s" % (self.st(self.c.g("warn"), "amber"),
                                                      (" " + note) if note else ""))
        if self.session is not None:
            self.c.print("    If changes were already published, undo them with: aiguard rollback")
        if self.log is not None:
            try:
                self.log.warn("cli", "interrupted by the user", stage=self.stage or None,
                              discarded=bool(note))
            except Exception:  # noqa: BLE001
                pass
        return EXIT_INTERRUPTED

    def input_ended(self) -> int:
        self._clear_live()
        self.c.print()
        note = self.discard_open_session()
        self.c.print("  %s Input ended before the command finished. Nothing more was done.%s"
                     % (self.st(self.c.g("warn"), "amber"), (" " + note) if note else ""))
        if self.log is not None:
            self.log.warn("cli", "input ended (EOF)", stage=self.stage or None)
        return EXIT_INTERRUPTED

    def internal_error(self, exc: BaseException) -> int:
        if self.log is not None:
            try:
                self.log.debug("cli", "unexpected error", traceback=_redact.redact(
                    "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))))
            except Exception:  # noqa: BLE001
                pass
        self.discard_open_session()
        err = AiguardError(
            "Unexpected error in aiguard %s" % getattr(self.args, "command", ""),
            code="aiguard.internal",
            why="%s: %s" % (type(exc).__name__, _redact.redact(str(exc))[:300]),
            fix=["Send the log file %s to the demo owner" % (self.log.path if self.log else
                                                             "(no log was started)")],
            state="The command stopped. Unpublished changes were discarded; see the log for what "
                  "was done before the error.")
        self.render_error(err, header=self.stage or None)
        return EXIT_ERROR

    def cancelled(self) -> int:
        self.p()
        self.p("  Cancelled. Nothing was changed.")
        if self.log is not None:
            self.log.info("cli", "cancelled by the user", stage=self.stage or None)
        return EXIT_OK

    # ------------------------------------------------------------------ connect

    def connect(self, *, wizard: bool = False, quiet: bool = False,
                optional: bool = False) -> Optional[dict]:
        """Log in (``optional``: an empty hidden answer skips and returns None)."""
        s = self.open()
        last = self.state.last()
        env = self.env
        self.env_problems()
        used_env: List[str] = []
        server = self.arg("server")
        stype = (self.arg("server_type") or "").upper() or None
        if wizard:
            last_type = str(last.get("server_type") or "").upper()
            type_default = (env.server_type if env.server_type and env.applies_to(server or
                                                                                  env.server)
                            else last_type if last_type in ("SMS", "MDS") else "SMS")
            stype = self.ask_choice("Server type", ["SMS", "MDS"], default=type_default,
                                    given=stype)
            server = self.ask_text("Management address", default=env.server or last.get("server"),
                                   given=server)
        if not server and env.server:
            server = env.server
            used_env.append(_envdefaults.ENV_SERVER)
        if not server:
            server = last.get("server")
        if not server:
            raise AiguardError(
                "No management server was given", code="cli.no_server",
                fix=["Pass --server <address> (and --port if the API is not on 443)",
                     "Or run aiguard setup once: it remembers the server (never the key)"],
                state="Nothing was changed.")
        server = str(server).strip()
        same = server == str(last.get("server") or "")
        # port, domain and certificate name from the environment describe its server only
        env_on = env.applies_to(server)

        def pick(name: str, value: Any, var: str, remembered: Any) -> Any:
            """The flag (given empty: none), else the environment's value (for its server),
            else the value remembered for this server."""
            given = getattr(self.args, name, None)
            if given is not None:
                return given if str(given).strip() else None
            if env_on and value:
                used_env.append(var)
                return value
            return remembered

        port = pick("port", env.port, _envdefaults.ENV_PORT,
                    last.get("port") if same else None) or 443
        if wizard:
            port = int(self.ask_text("Port", default=str(port), given=self.arg("port"),
                                     validate=lambda v: None if v.isdigit() and 0 < int(v) < 65536
                                     else "A port is a number from 1 to 65535."))
        domain = pick("domain", env.domain, _envdefaults.ENV_DOMAIN,
                      last.get("domain") if same else None)
        if str(domain or "").strip().lower() == "system data":
            domain = None
        server_name = pick("server_name", env.server_name, _envdefaults.ENV_SERVER_NAME,
                           last.get("server_name") if same else None)
        ca_from_env = False
        given_ca = getattr(self.args, "ca_file", None)
        if given_ca is not None:
            ca_file = given_ca if str(given_ca).strip() else None
        elif env.ca_file:
            # for the management connection only; any server (it only adds trust)
            ca_file = self.env_ca_file()       # checked like --ca-file; stops when unusable
            ca_from_env = True
            used_env.append(_envdefaults.ENV_CA_FILE)
            if not quiet:
                self.line("info", "CA file", ca_file, "from %s" % _envdefaults.ENV_CA_FILE)
        else:
            ca_file = last.get("ca_file") if same else None
        if used_env and self.log is not None:
            self.log.info("cli", "defaults from the environment", variables=sorted(set(used_env)))
        if ca_file and not self.arg("ca_file") and not ca_from_env and \
                not Path(str(ca_file)).expanduser().is_file():
            # Remembered from an earlier run (or a web console upload) and gone since:
            # connect without it rather than stop; a CA that is really needed is asked
            # for by the certificate error.
            self.line("warn", "CA file", "%s no longer exists" % ca_file,
                      "ignored; pass --ca-file to use another")
            if self.log is not None:
                self.log.warn("cli", "the remembered CA file no longer exists; ignored",
                              ca_file=str(ca_file))
            ca_file = None
        if ca_file and not self.arg("ca_file") and not ca_from_env and not quiet:
            self.line("info", "CA file", str(ca_file), "from the last run")

        api_key: Optional[str] = None
        user: Optional[str] = None
        password: Optional[str] = None
        if self.arg("api_key_env"):
            api_key = self.env_secret("--api-key-env", self.args.api_key_env,
                                      "the Management API key")
            if not quiet:
                self.line("ok", "API key", "from $%s" % self.args.api_key_env,
                          "kept in memory, never written")
        elif self.arg("user"):
            user = self.args.user
            if self.arg("password_env"):
                password = self.env_secret("--password-env", self.args.password_env,
                                           "the password", keep_tail=False)
            else:
                password = self.ask_secret("Password for %s" % user, allow_empty=optional,
                                           note="Enter to skip" if optional else "",
                                           keep_tail=False)
        else:
            by_password = bool(same and last.get("auth") == "password" and last.get("user"))
            if wizard:
                how = self.ask_choice("Authenticate with", ["API key", "username + password"],
                                      default="username + password" if by_password else "API key")
            else:
                how = "username + password" if by_password else "API key"
            if how == "API key":
                api_key = self.ask_secret("API key" if not optional else "API key for log matching",
                                          allow_empty=optional,
                                          note="Enter to skip" if optional else "")
            else:
                user = (self.ask_text("Username", default=last.get("user") if same else None)
                        if wizard or not last.get("user") else str(last.get("user")))
                password = self.ask_secret("Password", allow_empty=optional,
                                           note="Enter to skip" if optional else "",
                                           keep_tail=False)
        if optional and not (api_key or password):
            return None

        self.stage = "connect to %s:%s" % (server, port)
        info = s.connect(server, port=int(port), api_key=api_key, user=user, password=password,
                         domain=domain, ca_file=ca_file, server_name=server_name)
        api_key = password = None   # noqa: F841 - drop the references early
        self.connected = True
        self.conn_info = info
        try:
            self.state.set_last(server_type=info.get("server_type"))
        except (ValueError, TypeError, OSError):
            pass
        self._show_connection(info, quiet=quiet)
        seen = str(info.get("fingerprint_sha1") or "").upper()
        if env_on and env.fingerprint_sha1 and seen and seen != env.fingerprint_sha1:
            self.line("warn", "Certificate", "differs from what the installer saw",
                      "%s %s; compare with: api fingerprint" % (
                          _envdefaults.ENV_FINGERPRINT_SHA1, env.fingerprint_sha1))
            if self.log is not None:
                self.log.warn("cli", "the certificate differs from the one the installer saw",
                              fingerprint_sha1=seen, installer=env.fingerprint_sha1)
        if info.get("server_type") == "MDS" and not domain:
            info = self._pick_domain(info, wizard=wizard, quiet=quiet)
        if wizard and stype and info.get("server_type") in ("SMS", "MDS") and \
                stype != info.get("server_type"):
            self.line("warn", "Server type", "the server reports %s" % info.get("server_type"))
        return info

    def _show_connection(self, info: dict, *, quiet: bool) -> None:
        kind = _SERVER_KIND.get(str(info.get("server_type")), "Management server")
        dot = self.c.g("dot")
        release = info.get("release") or "unknown release"
        api = info.get("api_version")
        ms = info.get("ms") or 0
        if quiet:
            self.line("ok", "Connected", "%s %s %s %s %s %s %d ms" % (
                info.get("server") or "", dot, kind, dot, release, dot, ms))
            return
        self.line("ok", "Connected", "%s %s %s%s %s %d ms" % (
            kind, dot, release, (" (API %s)" % api) if api else "", dot, ms))
        fp = info.get("fingerprint_sha1") or info.get("fingerprint_sha256")
        if fp:
            self.line("ok", "Certificate", "verified %s SHA-1 %s" % (dot, fp),
                      "compare with: api fingerprint")
        if info.get("read_only"):
            self.line("warn", "Session", "read-only", "this login cannot change the policy")
        else:
            self.line("ok", "Session", "aiguard-demo", "changes are made only after you type APPROVE")
        if info.get("domain") and str(info.get("domain")).lower() != "system data":
            self.line("ok", "Domain", str(info["domain"]))

    def _pick_domain(self, info: dict, *, wizard: bool, quiet: bool) -> dict:
        domains = [str(d) for d in info.get("domains") or [] if d]
        if not domains:
            try:
                domains = self.open().list_domains()
            except AiguardError as exc:
                self.line("warn", "Domains", "could not be listed: %s" % exc.what)
                domains = []
        if not domains:
            self.line("warn", "Domain", "System Data", "pass --domain NAME to work in a domain")
            return info
        if not (wizard or self.c.interactive):
            self.line("warn", "Domain", "System Data",
                      "pass --domain NAME (%s)" % ", ".join(domains[:6]))
            return info
        if not quiet:
            self.p("    %s" % self.dim("Domains: %s" % ", ".join(
                "%d %s" % (i, d) for i, d in enumerate(domains, 1))))
        choice = self.ask_choice("Domain", domains, default=domains[0])
        switch = getattr(self.open(), "select_domain", None)
        if not callable(switch):
            self.line("warn", "Domain", "System Data", "pass --domain %s to work in it" % choice)
            return info
        self.stage = "switch to domain %s" % choice
        new = switch(choice)
        self.conn_info = new
        self.line("ok", "Domain", choice)
        return new

    # ------------------------------------------------------------------ gateways

    def _ai_cell(self, gw: Any) -> Tuple[str, Optional[str]]:
        on = gw.blade("ai_security")
        if on is True:
            return "%s on" % self.c.g("ok"), "green"
        if on is False:
            return "%s needs R82.20" % self.c.g("fail"), "red"
        vt = gw.version_tuple() if hasattr(gw, "version_tuple") else None
        if vt is not None and vt >= (82, 20):
            return "%s supported" % self.c.g("ok"), "green"
        return "unknown", "dim"

    def _https_cell(self, gw: Any) -> Tuple[str, Optional[str]]:
        on = gw.blade("https_inspection")
        if on is True:
            return "%s enabled" % self.c.g("ok"), "green"
        if on is False:
            return "%s disabled" % self.c.g("fail"), "red"
        return "not read yet", "dim"

    def show_gateways(self, gws: Sequence[Any], selected: Optional[str] = None) -> None:
        headers = ["NAME", "ADDRESS", "VERSION", "PACKAGE", "AI SECURITY", "HTTPS INSPECTION"]
        rows = []
        for g in gws:
            ai, ai_style = self._ai_cell(g)
            https, https_style = self._https_cell(g)
            name = g.name + (" (cluster)" if getattr(g, "is_cluster", False) else "")
            rows.append(([name, g.ipv4 or "-", g.release or g.version or "?",
                          g.policy_package or "-", ai, https],
                         [None, None, None, None, ai_style, https_style], g.name))
        widths = [max([len(h)] + [len(r[0][i]) for r in rows]) for i, h in enumerate(headers)]
        self.p("    " + self.dim("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()))
        for cells, styles, name in rows:
            parts = []
            for i, cell in enumerate(cells):
                text = cell.ljust(widths[i]) if i < len(cells) - 1 else cell
                if i == 0 and name == selected:
                    text = self.bold(text)
                elif styles[i]:
                    text = self.st(text, styles[i])
                parts.append(text)
            mark = self.st(self.c.g("pick"), "magenta") if name == selected else " "
            self.p("  %s %s" % (mark, "  ".join(parts)))

    def _gateway_summary(self, gw: Any) -> str:
        dot = " %s " % self.c.g("dot")
        bits = [gw.release or gw.version or "version unknown"]
        if gw.ipv4:
            bits.append(gw.ipv4)
        https = gw.blade("https_inspection")
        bits.append("HTTPS Inspection %s" % ({True: "on", False: "off"}.get(https, "unknown")))
        mode = getattr(gw, "threat_prevention_mode", None)
        if mode:
            bits.append("Threat Prevention %s" % mode)
        if gw.policy_package:
            bits.append("package %s" % gw.policy_package)
        return dot.join(bits)

    def pick_gateway(self, *, wizard: bool = False, quiet: bool = False) -> Any:
        s = self.open()
        self.stage = "discover gateways"
        gws = list(s.discover())
        if not gws:
            raise AiguardError(
                "No gateways were found", code="cli.no_gateways",
                why="The management server (this domain) lists no security gateways or clusters.",
                fix=["On a Multi-Domain Server, connect to the domain that manages the gateway "
                     "(--domain NAME)",
                     "Check that this administrator may read gateways and servers"],
                state="Nothing was changed.")
        names = [g.name for g in gws]
        last_gw = self.state.last().get("gateway")
        wanted = self.arg("gateway")
        env_gw = self.env.gateway if not wanted else None
        if env_gw and env_gw not in names:
            self.line("warn", "Gateway", "%s is not on this server" % env_gw,
                      "%s ignored" % _envdefaults.ENV_GATEWAY)
            env_gw = None
        if wizard:
            default = wanted or env_gw or (last_gw if last_gw in names else names[0])
            self.show_gateways(gws, selected=default)
            name = self.ask_choice("Target gateway", names, default=default, given=wanted)
        elif wanted:
            name = wanted
        elif env_gw:
            name = env_gw
        elif last_gw in names:
            name = last_gw
        elif len(names) == 1:
            name = names[0]
        elif self.c.interactive:
            self.show_gateways(gws)
            name = self.ask_choice("Target gateway", names, default=names[0])
        else:
            raise AiguardError(
                "More than one gateway: say which one", code="cli.gateway_needed",
                why="This management server has %d gateways: %s." % (len(names), ", ".join(names)),
                fix=["Pass --gateway <name>"], state="Nothing was changed.")
        self.stage = "read gateway %s" % name
        gw = s.select_gateway(name)
        if not quiet:
            self.line("ok", "Gateway", gw.name, self._gateway_summary(gw))
        return gw

    # ------------------------------------------------------------------ preflight

    def _check_line(self, c: Any) -> None:
        pipe = self.dim(self.c.g("pipe"))
        if c.status == "pass":
            self.p("  %s %s" % (self.st(self.c.g("ok"), "green"), c.title))
            if self.verbose and c.detail:
                for ln in self.wrap(c.detail, 6):
                    self.p("  %s %s" % (pipe, self.dim(ln)))
            return
        if c.status == "skip":
            self.p("  %s %s  %s" % (self.dim(self.c.g("dash")), self.dim(c.title), self.dim("skipped")))
            if self.verbose and c.detail:
                for ln in self.wrap(c.detail, 6):
                    self.p("  %s %s" % (pipe, self.dim(ln)))
            return
        blocking = c.status == "fail" and c.blocking
        sym, color, tag = ((self.c.g("fail"), "red", "blocking") if blocking
                           else (self.c.g("warn"), "amber", "warning"))
        head = "%s %s" % (sym, c.title)
        pad = max(2, self.c.width - 14 - len(head))
        self.p("  %s%s%s" % (self.st(head, color), " " * pad, self.st(tag, color)))
        for ln in self.wrap(c.detail, 6):
            self.p("  %s %s" % (pipe, ln))
        said = getattr(c, "server_said", None)
        if said:
            lines = [ln.strip() for ln in str(said).splitlines() if ln.strip()]
            for i, raw in enumerate(lines[:6]):
                for j, ln in enumerate(self.wrap(raw, 11)):
                    label = "Said" if i == 0 and j == 0 else ""
                    self.p("  %s %s %s" % (pipe, self.dim(label.ljust(4)), ln))
        evidence = list((c.evidence or {}).items())
        if c.id == "last_install" and not self.verbose:
            keep = ("not-installed", "failed-task-start", "access-policy-installation-date",
                    "threat-policy-installation-date")
            evidence = [(k, v) for k, v in evidence if k in keep]
        if evidence and (self.verbose or c.id in ("tls_path", "outbound_ca", "gw_version",
                                                  "api_version", "last_install")):
            for k, v in evidence[: (None if self.verbose else 4 if c.id == "last_install" else 3)]:
                self.p("  %s %s %s" % (pipe, self.dim("Seen".ljust(4)), "%s: %s" % (k, v)))
        for i, fix in enumerate(c.fix or []):
            label = "Fix" if i == 0 else ""
            text = str(fix)
            if text[:3].lower() == "or ":
                label, text = "Or", text[3:]
            self.p("  %s %s %s" % (pipe, self.bold(label.ljust(4)), text))

    def preflight(self) -> Any:
        s = self.open()
        self.stage = "preflight"
        report = s.run_preflight()
        for c in report.checks:
            self._check_line(c)
        lines = [c.log_line for c in report.checks if c.log_line]
        parts = [self.st("%d passed" % report.passed, "green")]
        if report.failed_blocking:
            parts.append(self.st("%d blocking" % report.failed_blocking, "red"))
        if report.warnings:
            parts.append(self.st("%d warning%s" % (report.warnings, "" if report.warnings == 1 else "s"),
                                 "amber"))
        if report.skipped:
            parts.append(self.dim("%d skipped" % report.skipped))
        where = ("details in the log, lines %d%s%d" % (min(lines), self.c.g("dash"), max(lines))
                 if lines else "")
        self.p()
        self.p("  %s  %s   %s" % (self.bold("Preflight"), (" %s " % self.c.g("dot")).join(parts),
                                  self.dim(where)))
        return report

    def offer_https_fix(self, gw: Any, report: Any) -> Any:
        fixable = report.fixable()
        add_rule = "https-rule" in fixable and "https-inspection" not in fixable
        if "https-inspection" not in fixable and not add_rule:
            return report
        self.p()
        question = ("Add an Inspect rule for this computer on %s now?" % gw.name if add_rule
                    else "Fix HTTPS Inspection on %s now?" % gw.name)
        if not self.ask_yes_no(question, default=False):
            return report
        if self.https_fix(gw, add_rule=add_rule, use_flag=False) != "applied":
            return report
        self.section(None, 0, "Preflight again")
        return self.preflight()

    def https_fix(self, gw: Any, *, add_rule: bool = False, use_flag: bool = True) -> str:
        """Turn HTTPS Inspection on through the engine. Returns applied | cancelled |
        unsupported (the reason was printed)."""
        s = self.open()
        self.stage = "plan HTTPS Inspection for %s" % gw.name
        try:
            plan = s.build_https_plan(add_rule=add_rule)
        except PlanError as err:
            if err.code == "plan.no_outbound_ca":
                self.render_error(err, header="HTTPS Inspection cannot be turned on yet")
                return "unsupported"
            raise
        gw_step = plan.step("https_gateway") or next(
            (st for st in plan.steps if st.kind == "set"), None)
        if gw_step is not None and gw_step.action == "manual":
            from .preflight import HTTPS_FIX
            self.p()
            self.p("  %s This management server cannot turn HTTPS Inspection on through the "
                   "Management API. Do it in SmartConsole:" % self.st(self.c.g("warn"), "amber"))
            for i, text in enumerate(list(gw_step.manual_steps) + HTTPS_FIX(gw.name)[1:], 1):
                self.p("      %d. %s" % (i, text[3:] if text[:3].lower() == "or " else text))
            return "unsupported"
        self.p()
        self.show_plan(plan, title="Planned change")
        if not self.approve(plan, use_flag=use_flag):
            self.cancelled()
            return "cancelled"
        self.p()
        self.apply(plan)
        self.line("ok", "HTTPS Inspection", "on for %s" % gw.name,
                  "next: the demo computers must trust the outbound CA (aiguard trust-ca)")
        return "applied"

    # ------------------------------------------------------------------ plans

    def setup_provider(self) -> str:
        s = self.open()
        prov = str(self.arg("provider") or "openai").lower()
        env = self.arg("provider_key_env")
        if env:
            key = self.env_secret("--provider-key-env", env, "the %s API key" % prov)
            s.set_provider_key(prov, key)
            self.provider_key_set = True
        if self.arg("model"):
            models = getattr(s, "models", None)
            if isinstance(models, dict):
                models[prov] = str(self.args.model)
        return prov

    def plan_options(self, gw: Any, *, wizard: bool) -> PlanOptions:
        s = self.open()
        last = self.state.last()
        dot = self.c.g("dot")
        profile_default = str(last.get("profile_name") or "AIGuard-Demo")
        if wizard:
            profile = self.ask_text("Threat profile name", default=profile_default,
                                    given=self.arg("profile_name"))
            self.line("info", "Prompt injection, jailbreaks", "Prevent",
                      "detectors of the AI Guardrails project policy")
            self.line("info", "Sensitive data in prompts", "Prevent",
                      "PII detectors of the project policy (if the policy has them)")
            given_mod = self.arg("moderation")
            moderation = self.ask_yes_no("Add content moderation", default=False, given=given_mod)
            self.p()
            self.note("AI Agent Security needs the Guard API key and the project ID. Check Point "
                      "Portal %s AI Security %s AI Guardrails %s Settings %s API Access (key) "
                      "and %s Projects (project ID)." % ((self.c.g("pick"),) * 5))
        else:
            profile = str(self.arg("profile_name") or profile_default)
            moderation = self.arg("moderation")
            if moderation is None:
                moderation = bool(last.get("moderation", False))
        rule = str(self.arg("rule_name") or last.get("rule_name") or "AI Guard Demo")
        track = str(self.arg("track") or "Log")
        scope = str(self.arg("scope") or "client")

        project = self.arg("project_id")
        attempts = 0
        while True:
            attempts += 1
            from_env = bool(self.arg("lakera_key_env"))
            if from_env:
                key = self.env_secret("--lakera-key-env", self.args.lakera_key_env,
                                      "the AI Agent Security (Guard) API key")
                self.line("ok", "Guard API key", "from $%s" % self.args.lakera_key_env,
                          "kept in memory, never written")
            else:
                key = self.ask_secret("Guard API key")
            if wizard:
                project = self.ask_text("Project ID", default=last.get("project_id"), given=project)
            elif not project:
                project = last.get("project_id")
                if project:
                    self.line("info", "Project ID", str(project), "from the last run")
                elif self.c.interactive:
                    project = self.ask_text("Project ID")
                else:
                    raise AiguardError(
                        "No AI Guardrails project ID", code="cli.no_project",
                        fix=["Pass --project-id <id> (Check Point Portal > AI Security > AI "
                             "Guardrails > Projects)"], state="Nothing was changed.")
            self.stage = "check the AI Agent Security key"
            try:
                info = s.set_lakera(key, project)
                break
            except LakeraError as err:
                if from_env or attempts >= 3 or not (wizard or self.c.interactive):
                    raise
                self.render_error(err)
                if not self.ask_yes_no("Try another key / project ID?", default=True):
                    raise _Stop(EXIT_ERROR)
                project = None
        key = ""  # noqa: F841 - the engine keeps it in memory; drop our reference
        if info.get("validated"):
            by = "the management server" if info.get("validated_by") == "management" else "Lakera"
            self.line("ok", "Key validated", "by %s" % by, info.get("message") or "")
        else:
            self.line("warn", "Key not validated yet", "", info.get("message") or "")
        for w in _unique(info.get("warnings") or []):
            self.p("    %s %s" % (self.st(self.c.g("warn"), "amber"), w))
        self.note("The key stays in memory for this run. The log shows it as %s."
                  % (info.get("masked_key") or _redact.MASK))
        try:
            self.state.set_last(profile_name=profile, rule_name=rule, moderation=bool(moderation),
                                project_id=project)
        except (ValueError, TypeError, OSError) as exc:
            self.log.warn("cli", "could not remember the plan options", error=str(exc))
        if not wizard:
            self.line("info", "Options", "%s %s rule \"%s\" %s scope %s %s moderation %s" % (
                profile, dot, rule, dot, scope, dot, "on" if moderation else "off"))
        return PlanOptions(gateway=gw.name, package=self.arg("package"), profile_name=profile,
                           rule_name=rule, track=track, scope=scope, moderation=bool(moderation),
                           lakera_project_id=project, install=not self.arg("no_install", False))

    def build_plan(self, options: PlanOptions) -> Any:
        self.stage = "build the plan"
        plan = self.open().build_plan(options)
        self.p()
        self.show_plan(plan)
        return plan

    def show_plan(self, plan: Any, title: str = "Planned changes") -> None:
        dot = self.c.g("dot")
        to = self.c.g("to")
        where = "server %s%s %s package %s %s target %s" % (
            plan.server, (" %s domain %s" % (dot, plan.domain)) if plan.domain else "", dot,
            plan.package, dot, plan.gateway)
        self.p("  %s  %s" % (self.bold(title), where))
        rule = self.dim(self.c.g("rule") * min(75, self.c.width - 4))
        self.p("  " + rule)
        changes = sum(1 for st in plan.steps if st.action in ("add", "update"))
        sym = {"add": ("+", "green"), "update": ("~", "amber"), "delete": ("-", "red"),
               "publish": (to, "blue"), "install": (to, "blue"), "script": (to, "blue"),
               "manual": ("!", "amber"), "none": ("=", "dim")}
        for stp in plan.steps:
            mark, color = sym.get(stp.action, (dot, "dim"))
            command = stp.command or "you do this"
            desc = stp.describe or stp.id
            if stp.action == "none":
                desc = "%s  (%s)" % (desc, stp.message or "already in place")
            elif stp.action == "manual":
                desc = "You do this: %s" % desc
            elif stp.kind == "publish":
                desc = "%s (%d change%s)" % (desc, changes, "" if changes == 1 else "s")
            elif stp.kind == "install":
                parts = [n for n, on in (("Access Control", (stp.display_payload or {}).get("access")),
                                         ("Threat Prevention",
                                          (stp.display_payload or {}).get("threat-prevention")))
                         if on]
                desc = "%s %s %s   %s" % (plan.package, to, ", ".join(
                    (stp.display_payload or {}).get("targets") or [plan.gateway]),
                    " + ".join(parts) + (" only" if len(parts) == 1 else ""))
            self.p("  %s %s %s" % (self.st(mark, color), command.ljust(21), desc))
            if stp.action == "manual":
                for i, m in enumerate(stp.manual_steps or [], 1):
                    self.p("  %s%d. %s" % (" " * 24, i, m))
            if self.verbose and stp.display_payload:
                for ln in json.dumps(stp.display_payload, indent=2, ensure_ascii=False).splitlines():
                    self.p("  %s%s" % (" " * 24, self.dim(ln)))
        self.p("  " + rule)
        for w in _unique(plan.warnings):
            self.p("  %s %s" % (self.st(self.c.g("warn"), "amber"), w))
        self.p("  Nothing has been written yet.   Plan id %s" % self.bold(plan.plan_id))

    def show_api_calls(self, plan: Any) -> None:
        calls = plan.api_calls()
        self.p()
        self.p("  %s  %s" % (self.bold("API calls"), self.dim("in order, secrets masked; "
                                                           "POST /web_api/<command>")))
        for i, call in enumerate(calls, 1):
            self.p("  %d. %s" % (i, self.bold(str(call.get("command")))))
            for ln in json.dumps(call.get("payload") or {}, indent=2, ensure_ascii=False).splitlines():
                self.p("     " + ln)
        self.p()

    def approve(self, plan: Any, *, use_flag: bool = True) -> bool:
        """Typed ``APPROVE`` (case-sensitive), ``D`` shows the API calls, ``N`` cancels;
        ``--approve <plan id>`` approves without a prompt when it equals the plan id."""
        verb = "publish and install" if any(st.kind == "install" for st in plan.steps) else "publish"
        given = self.arg("approve") if use_flag else None
        if given:
            value = str(given).strip().lower()
            if value != plan.plan_id:
                raise ApprovalError(
                    "--approve does not match this plan",
                    why="The plan shown above is %s; --approve was %s." % (
                        plan.plan_id, _redact.redact(str(given))[:24]),
                    fix=["Review the plan, then pass --approve %s" % plan.plan_id,
                         "Or leave --approve out and type APPROVE when asked"],
                    state="Nothing was changed.")
            self._given("Approved with --approve", plan.plan_id)
            self.approved_id = value
            self.log.info("cli", "plan approved with --approve", plan_id=plan.plan_id)
            return True
        prompt = "  %s Type %s to %s, D to see the API calls, N to cancel: " % (
            self.st("?", "blue"), self.bold("APPROVE"), verb)
        for _ in range(6):
            try:
                answer = self.c.input(prompt).strip()
            except EOFError:
                self.p()
                return False
            if answer == "APPROVE":
                self.approved_id = plan.plan_id
                self.log.info("cli", "plan approved (typed APPROVE)", plan_id=plan.plan_id)
                return True
            if answer in ("D", "d"):
                self.show_api_calls(plan)
                continue
            if answer.lower() in ("n", "no", "q", "quit", "cancel"):
                return False
            if answer.upper() == "APPROVE":
                msg = "Type APPROVE in capital letters to go ahead."
            else:
                msg = "Type APPROVE to go ahead, D for the API calls or N to cancel."
            self.p("    %s %s" % (self.st(self.c.g("warn"), "amber"), msg))
        return False

    def apply(self, plan: Any) -> Any:
        s = self.open()
        self.stage = "apply plan %s" % plan.plan_id
        progress = _Progress(self, plan)
        res = s.apply(self.approved_id or plan.plan_id, progress_cb=progress)
        self._clear_live()
        notices = list(getattr(res, "notices", None) or [])
        whats = [str(n.get("what") or "").rstrip(".") for n in notices]
        for w in _unique(res.warnings):
            if w in (plan.warnings or []) or any(x and w.startswith(x) for x in whats):
                continue
            self.p("  %s %s" % (self.st(self.c.g("warn"), "amber"), w))
        for n in notices:
            self.render_error(_NoticeError(n), header=n.get("what"), badge="YOU DO THIS")
        if not res.ok:
            failed = next((st for st in res.steps if st.status == "failed"), None)
            header = ("%s on %s" % (failed.command or failed.id, plan.gateway) if failed
                      else "apply plan %s" % plan.plan_id)
            err = res.error or AiguardError(res.message or "The plan was not applied",
                                            state=res.message or None)
            self.render_error(err, header=header)
            raise _Stop(EXIT_ERROR)
        return res

    def enforcement(self, provider: str) -> bool:
        s = self.open()
        self.stage = "enforcement check"
        r = s.confirm_enforcement(provider=provider)
        gw = s.gateway.name if s.gateway is not None else "the gateway"
        if r.verdict == "BLOCKED":
            self.line("ok", "Enforcement check", "%s blocked the test prompt (inj-override)" % gw,
                      r.evidence or "")
            return True
        self.line("fail", "Enforcement check", "inj-override was %s, expected BLOCKED" % r.verdict,
                  r.evidence or "")
        for reason in s.diagnose(r):
            self.p("    %s %s" % (self.dim(self.c.g("pipe")), reason))
        return False

    def apply_command(self, plan_id: str) -> str:
        parts = ["aiguard"]
        home = getattr(self.args, "home", None)   # a global option (SUPPRESS default)
        if home:
            parts += ["--home", str(home)]
        parts += ["apply", "--plan-id", plan_id]
        for flag in ("server", "port", "domain", "gateway", "ca_file", "server_name", "api_key_env",
                     "user", "password_env", "profile_name", "rule_name", "track", "scope",
                     "package", "project_id", "lakera_key_env", "provider", "provider_key_env",
                     "outbound_ca", "local_ip"):
            value = getattr(self.args, flag, None)
            if value is None or (flag == "provider" and value == "openai"):
                continue
            parts += ["--" + flag.replace("_", "-"), str(value)]
        if self.arg("moderation") is True:
            parts.append("--moderation")
        elif self.arg("moderation") is False:
            parts.append("--no-moderation")
        if self.arg("no_install"):
            parts.append("--no-install")
        return " ".join(shlex.quote(p) for p in parts)

    # ------------------------------------------------------------------ demo

    def moderation_on(self) -> bool:
        s = self.session
        if s is not None and getattr(s, "moderation_enabled", None) is not None:
            return bool(s.moderation_enabled)
        client = getattr(s, "client", None) if s is not None else None
        if client is not None and getattr(client, "logged_in", False) and callable(
                getattr(s, "moderation_on", None)):
            return bool(s.moderation_on())
        last = self.state.last()
        server = self.arg("server") or last.get("server")
        gateway = self.arg("gateway") or last.get("gateway")
        try:
            points = self.state.list_rollbacks()
        except Exception:  # noqa: BLE001 - informational
            return False
        for point in reversed(points):
            if server and point.get("server") not in (None, server):
                continue
            if gateway and point.get("gateway") not in (None, gateway):
                continue
            if point.get("status") in ("rolled-back", "discarded"):
                continue
            if any((o or {}).get("step") == "moderation" for o in point.get("objects") or []):
                return True
        return False

    def last_profile(self) -> Optional[str]:
        last = self.state.last()
        try:
            points = self.state.list_rollbacks()
        except Exception:  # noqa: BLE001
            points = []
        for point in reversed(points):
            if point.get("status") in ("rolled-back", "discarded"):
                continue
            for obj in point.get("objects") or []:
                if (obj or {}).get("step") == "profile" and obj.get("name"):
                    return str(obj["name"])
        return last.get("profile_name")

    def tls_check(self, provider: str) -> None:
        s = self.open()
        host, target, port = _provider_target(s, provider)
        if not target:
            return
        self.stage = "TLS check to %s" % host
        if callable(getattr(s, "tls_check", None)):
            res = s.tls_check(provider)
            host = res.get("host") or host
            port = int(res.get("port") or port)
        else:
            res = _probe.tls_probe(target, port, ca_file=getattr(s, "provider_ca_file", None),
                                   timeout=float(getattr(s, "tls_timeout", 10) or 10))
        status = res.get("status")
        issuer = res.get("issuer") or res.get("issuer_org") or "unknown issuer"
        self.log.info("cli", "TLS check before the demo", host=host, status=status, issuer=issuer)
        if status == "inspected":
            self.line("ok", "TLS to %s is inspected" % host, "", "issuer: %s" % issuer)
            return
        if self.arg("skip_tls_check"):
            self.line("warn", "TLS to %s" % host, str(status), "--skip-tls-check: running anyway")
            return
        gw = (self.arg("gateway") or self.env.gateway or self.state.last().get("gateway")
              or "The gateway")
        if status == "not_inspected":
            title = "Traffic to %s is not being inspected" % host
            rows = [("Seen", ["certificate issuer %s (public CA)" % issuer]),
                    ("Means", ["%s cannot read the prompts, so it cannot block them." % gw,
                               "Running the demo now would show ALLOWED for every attack."]),
                    ("Fix", ["aiguard fix https-inspection   turns HTTPS Inspection on (Full mode)",
                             "aiguard fix https-inspection --add-rule   if it is already on: adds "
                             "an Inspect rule for this computer",
                             "If HTTPS Inspection is on: check for a Bypass rule or category that "
                             "matches %s, and that the last Access Control install succeeded "
                             "(aiguard preflight)" % host])]
        elif status == "untrusted":
            title = "This computer does not trust the certificate for %s" % host
            rows = [("Seen", self.wrap(res.get("verify_error") or "certificate verify failed", 18)),
                    ("Means", ["The gateway re-signs the traffic, but this computer does not trust "
                               "its outbound CA:", "every prompt would fail with a certificate error."]),
                    ("Fix", ["aiguard trust-ca   shows how to trust the outbound CA",
                             "or pass --outbound-ca <outbound-ca.pem>  (--ca-file is for the "
                             "management server's certificate)"])]
        else:
            err = res.get("error") or {}
            title = err.get("what") or "Cannot reach %s:%d" % (host, port)
            rows = [("Seen", self.wrap(err.get("server_said") or res.get("connect_error")
                                       or str(status), 18)),
                    ("Means", self.wrap(err.get("why") or "No prompt can be sent from this "
                                        "computer.", 18)),
                    ("Fix", list(err.get("fix") or ["Check the proxy, DNS and route to %s" % host]))]
        rows.append(("Run anyway", ["aiguard demo --skip-tls-check"]))
        self.log.warn("cli", "demo stopped by the TLS check", host=host, status=status)
        self.stopped(title, rows)
        raise _Stop(EXIT_BLOCKED)

    def connect_for_logs(self) -> bool:
        if self.arg("no_logs"):
            return False
        last = self.state.last()
        if not (self.arg("server") or self.env.server or last.get("server")):
            self.line("skip", "Gateway logs", "not matched", "no management server known (aiguard "
                                                              "setup or --server)")
            return False
        has_env = bool(self.arg("api_key_env") or (self.arg("user") and self.arg("password_env")))
        if not has_env and not self.c.interactive:
            self.line("skip", "Gateway logs", "not matched",
                      "pass --api-key-env VAR to match results to SmartConsole logs")
            return False
        try:
            info = self.connect(quiet=True, optional=not has_env)
        except AiguardError as err:
            self.line("warn", "Gateway logs", "not matched: %s" % err.what,
                      ("log line %s" % err.log_line) if err.log_line else "")
            return False
        if info is None:
            self.line("skip", "Gateway logs", "not matched", "skipped")
            return False
        return True

    def last_install(self) -> None:
        """Before the demo runs: did the last policy installation on the gateway succeed
        for both Access Control and Threat Prevention? (A partial install leaves the
        gateway on an older policy, and every result after that is misleading.)"""
        s = self.open()
        check = getattr(s, "check_last_install", None)
        if not callable(check):
            return
        self.stage = "check the last policy install"
        try:
            if getattr(s, "gateway", None) is None:
                name = (self.arg("gateway") or self.env.gateway
                        or self.state.last().get("gateway"))
                if not name:
                    self.line("skip", "Last policy install", "not checked",
                              "no gateway known (pass --gateway NAME)")
                    return
                s.select_gateway(str(name))
            res = check()
        except AiguardError as err:
            self.line("warn", "Last policy install", "not checked: %s" % err.what,
                      ("log line %s" % err.log_line) if err.log_line else "")
            return
        if res.status == "pass":
            self.line("ok", "Last policy install", res.detail)
        elif res.status == "skip":
            self.line("skip", "Last policy install", "not checked", res.detail)
        else:
            self.p()
            self._check_line(res)
            self.note("The demo runs anyway: results may reflect the older policy until the "
                      "install succeeds for both policy types.", indent=4)

    def correlate(self) -> None:
        t0 = time.monotonic()
        self.stage = "match the results to gateway logs"
        self.open().correlate()
        self.correlate_s += time.monotonic() - t0

    def _scene_progress(self, step: str, status: str, pct: Optional[int], message: str) -> None:
        if status == "warning":
            self.p("    %s %s" % (self.st(self.c.g("warn"), "amber"), message))
        elif status == "running":
            self.live("    %s sending %s %s" % (self.c.g("arrow"), step, self.c.g("ell")))

    def _verdict_text(self, r: Any) -> str:
        dot = " %s " % self.c.g("dot")
        parts: List[str] = []
        if r.verdict == "BLOCKED":
            parts.append("by the gateway")
            if r.category:
                conf = r.confidence_label or (("%.2f" % r.confidence) if r.confidence else "")
                parts.append(("%s %s" % (r.category, conf)).strip())
        elif r.verdict == "ALLOWED":
            parts.append("%s from %s" % (r.http_status if r.http_status is not None else "reply",
                                         r.host))
            if r.inspected is True:
                parts.append("inspected by %s" % (r.issuer or "the gateway"))
            elif r.inspected is False:
                parts.append("NOT inspected (issuer %s)" % (r.issuer or "public CA"))
            if r.dummy_key:
                parts.append("dummy key")
        elif r.verdict == "ERROR":
            parts.append(r.reason or (r.error or {}).get("what") or "not sent")
        else:
            parts.append(r.reason or "no conclusive reply")
        parts.append("%d ms" % (r.ms or 0))
        return dot.join(p for p in parts if p)

    def _log_text(self, lm: dict) -> str:
        dot = " %s " % self.c.g("dot")
        bits = [str(lm.get("action") or "logged")]
        for key, fmt in (("blade", "%s"), ("protection", "%s"), ("rule", "rule %s"),
                         ("log_id", "log %s")):
            if lm.get(key):
                bits.append(fmt % lm[key])
        return "SmartConsole: " + dot.join(bits)

    def show_result(self, r: Any) -> None:
        self.p("    %s %s" % (str(r.prompt_id).ljust(17), self.dim('"%s"' % _preview(r.prompt))))
        badge = self.st(" %s " % r.verdict, _BADGE.get(r.verdict, "unknown"))
        if not self.c.color:
            badge = " %s " % r.verdict
        self.p("     %s  %s" % (badge.ljust(9) if not self.c.color else badge, self._verdict_text(r)))
        if r.evidence:
            self.p("%s%s %s" % (RESULT_INDENT, self.dim("evidence".ljust(9)), r.evidence))
        if r.log_match:
            self.p("%s%s %s" % (RESULT_INDENT, self.dim("log".ljust(9)), self._log_text(r.log_match)))
        if not r.matched:
            want = "BLOCKED" if r.expect == "block" else "ALLOWED"
            self.p("%s%s" % (RESULT_INDENT, self.st("%s unexpected: we expected %s"
                                                     % (self.c.g("fail"), want), "red")))
            for reason in self.open().diagnose(r):
                self.p("%s%s %s" % (RESULT_INDENT, self.dim(self.c.g("pipe")), reason))

    def play_scene(self, scene: Any, *, explicit: bool, provider: str, connected: bool) -> None:
        s = self.open()
        guided = bool(self.arg("guided"))
        extra = "  needs content moderation" if scene.requires == "moderation" else ""
        self.p()
        self.p("  %s %s%s" % (self.st(self.c.g("arrow"), "magenta"),
                              self.bold("Scene %d  %s" % (scene.number, scene.title)), self.dim(extra)))
        if scene.requires == "moderation" and not explicit and not self.moderation_on():
            self.note("skipped: content moderation is not turned on (aiguard setup --moderation). "
                      "Run it anyway: aiguard demo --scene %s" % scene.id)
            self.log.info("cli", "scene skipped", scene=scene.id, reason="moderation is not on")
            return
        if guided:
            self.p('    %s "%s"' % (self.st("say:", "blue"), scene.say))
        if scene.note and (guided or self.verbose):
            self.note(scene.note)
        if not scene.prompts:
            if not (guided or explicit):
                self.note("skipped: type your own prompt with --guided or --prompt TEXT")
                return
            self.custom_prompts(provider, connected)
            return
        n = len(scene.prompts)
        self.pause("Enter sends %d prompt%s" % (n, "" if n == 1 else "s"))
        self.stage = "scene %s" % scene.id
        results = s.run_scene(scene.id, provider=provider, progress_cb=self._scene_progress)
        self._clear_live()
        if connected:
            self.correlate()
        for r in results:
            self.show_result(r)
        if guided and scene.after:
            self.p('    %s "%s"' % (self.st("say:", "blue"), scene.after))
        self.pause("Enter for the next scene")

    def custom_prompts(self, provider: str, connected: bool) -> None:
        s = self.open()
        while True:
            try:
                text = self.c.input("  %s %s" % (self.st("?", "blue"),
                                                 "Your prompt (Enter to finish): ")).strip()
            except EOFError:
                self.p()
                return
            if not text:
                return
            expect = self.ask_choice("Expect", ["block", "allow"], default="block")
            self.stage = "send your prompt"
            r = s.run_prompt(text, provider=provider, expect=expect, prompt_id="custom")
            if connected:
                self.correlate()
            self.show_result(r)

    def smartconsole_filter(self) -> str:
        s = self.open()
        ip = getattr(s, "local_ip", None) or next(
            (r.local_ip for r in s.results if getattr(r, "local_ip", None)), None) or "<this computer>"
        blades = _unique(str((r.log_match or {}).get("blade") or "") for r in s.results)
        if blades:
            return 'blade:"%s" AND src:%s' % (blades[0], ip)
        return "src:%s AND action:Prevent" % ip

    def finish_demo(self, connected: bool) -> int:
        s = self.open()
        dot = " %s " % self.c.g("dot")
        if connected and s.results:
            self.correlate()
        summary = s.summary()
        total = int(summary.get("total") or 0)
        if total == 0:
            self.p()
            self.p("  No prompts were sent.")
            return EXIT_OK
        report = None
        try:
            self.stage = "write the report"
            report = s.write_report()
        except AiguardError as err:
            self.line("warn", "Report", "not written: %s" % err.what)
        json_path = None
        if self.arg("json"):
            json_path = Path(str(self.args.json)).expanduser()
            payload = {"version": __version__, "summary": summary,
                       "results": [r.to_dict() for r in s.results]}
            _write_atomic(json_path, json.dumps(_redact.redact_obj(payload), indent=2,
                                                ensure_ascii=False) + "\n")
        unexpected = len(summary.get("unexpected") or [])
        counts = ["%d prompt%s" % (total, "" if total == 1 else "s"),
                  "%d blocked" % summary.get("blocked", 0), "%d allowed" % summary.get("allowed", 0)]
        if summary.get("unknown"):
            counts.append("%d unknown" % summary["unknown"])
        if summary.get("error"):
            counts.append("%d error%s" % (summary["error"], "" if summary["error"] == 1 else "s"))
        counts.append(self.st("%d unexpected" % unexpected, "red" if unexpected else "green"))
        matched = int(summary.get("matched") or 0)
        self.p()
        self.p("  %s%s" % ("Result".ljust(11), dot.join(counts)))
        self.p("  %s%s %d/%d matched what we expected" % ("".ljust(11), self.bar(matched * 100.0 / total),
                                                          matched, total))
        blocked = [r for r in s.results if r.verdict == "BLOCKED"]
        found = [r for r in blocked if r.log_match]
        cerr = getattr(s, "correlate_error", None)
        if connected and cerr:
            proof = self.st("not matched: %s" % (cerr.get("what") or "show-logs failed"), "amber")
            fixes = [str(f) for f in (cerr.get("fix") or []) if str(f).strip()]
            if fixes:
                proof += self.dim("  (fix: %s)" % fixes[0])
        elif connected:
            proof = "%d of %d block%s found in SmartConsole logs (matched by show-logs, %.0f s)" % (
                len(found), len(blocked), "" if len(blocked) == 1 else "s", self.correlate_s)
        else:
            proof = self.dim("not checked: no management connection (pass --server and "
                             "--api-key-env VAR to match SmartConsole logs)")
        self.p("  %s%s" % ("Proof".ljust(11), proof))
        if report:
            self.p("  %s%s" % ("Report".ljust(11), report))
        if json_path:
            self.p("  %s%s" % ("JSON".ljust(11), json_path))
        self.p("  %s%s" % ("Log".ljust(11), s.log.path))
        self.p("  In SmartConsole   Logs & Events %s %s" % (self.c.g("pick"), self.smartconsole_filter()))
        if unexpected:
            self.note("Unexpected results are explained under each prompt (lines with %s)."
                      % self.c.g("pipe"), indent=2)
        return EXIT_MISMATCH if unexpected else EXIT_OK


class _NoticeError(AiguardError):
    """A five-field notice dict (``ApplyResult.notices``) for :meth:`_Run.render_error`."""

    def __init__(self, data: dict) -> None:
        super().__init__(str(data.get("what") or ""), code=data.get("code"),
                         server_said=data.get("server_said"), why=data.get("why"),
                         fix=list(data.get("fix") or []), state=data.get("state"))
        self.log_line = data.get("log_line")


class _Progress(object):
    """``progress_cb`` for apply / rollback: one line per finished step, a live bar on a
    terminal while a step runs."""

    def __init__(self, run: _Run, plan: Any = None) -> None:
        self.run = run
        self.plan = plan
        self.t0: Dict[str, float] = {}

    def __call__(self, step_id: str, status: str, pct: Optional[int], message: str) -> None:
        try:
            self._handle(step_id, status, pct, message)
        except Exception:  # noqa: BLE001 - progress output must never break an apply
            pass

    def _step(self, step_id: str) -> Any:
        if self.plan is None:
            return None
        try:
            return self.plan.step(step_id)
        except Exception:  # noqa: BLE001
            return None

    def _handle(self, step_id: str, status: str, pct: Optional[int], message: str) -> None:
        run = self.run
        c = run.c
        step = self._step(step_id)
        name = step.command if step is not None and step.command else step_id
        now = time.monotonic()
        if status == "running":
            self.t0.setdefault(step_id, now)
            if pct is not None:
                run.live("  %s %s %s %3d%%" % (c.g("arrow"), name.ljust(21), run.bar(pct), int(pct)))
            else:
                run.live("  %s %s %s" % (c.g("arrow"), name.ljust(21), _preview(message, 50)))
            return
        sym = {"done": (c.g("ok"), "green"), "failed": (c.g("fail"), "red"),
               "skipped": (c.g("dash"), "dim"), "manual": (c.g("warn"), "amber"),
               "warning": (c.g("warn"), "amber")}.get(status, (c.g("dot"), "dim"))
        detail = self._detail(step, status, message)
        plain = "%s %s" % (name.ljust(21), detail)
        timing = ""
        if status in ("done", "failed") and step_id in self.t0:
            timing = "%6.1f s" % (now - self.t0[step_id])
        if timing:
            plain = plain.ljust(max(len(plain), 66)) + timing
        run.p("  %s %s" % (run.st(sym[0], sym[1]), plain))
        if status == "manual" and step is not None:
            for i, m in enumerate(step.manual_steps or [], 1):
                run.p("  %s%d. %s" % (" " * 24, i, m))

    def _detail(self, step: Any, status: str, message: str) -> str:
        if step is None:
            return message or ""
        to = self.run.c.g("to")
        if status == "done" and step.kind in ("add", "set") and step.display_payload:
            name = (step.display_payload or {}).get("name")
            if name:
                name = '"%s"' % name if "rule" in str(step.command or "") else str(name)
                return "%s  %s" % (name, (message or "").lower())
        if status == "done" and step.kind == "install":
            targets = ", ".join((step.display_payload or {}).get("targets") or [])
            return "%s %s %s  %s 100%%" % ((step.display_payload or {}).get("policy-package") or "",
                                            to, targets, self.run.bar(100))
        return message or step.describe or ""


# =========================================================================== commands


def cmd_setup(run: _Run) -> int:
    run.open()
    run.banner()
    total = 6
    run.section(1, total, "Connect to management")
    run.connect(wizard=True)
    run.section(2, total, "Discover gateways")
    gw = run.pick_gateway(wizard=True)
    run.section(3, total, "Preflight")
    report = run.preflight()
    report = run.offer_https_fix(gw, report)
    if not report.ok:
        run.p()
        given = True if run.arg("continue_anyway") else (None if run.c.interactive else False)
        if not run.ask_yes_no("Continue anyway? The demo will probably not block anything",
                              default=False, given=given):
            run.p()
            run.p("  Stopped before any change. Fix the blocking checks above, then run "
                  "aiguard setup again.")
            run.log.info("cli", "setup stopped at preflight", blocking=[c.id for c in report.blocking()])
            return EXIT_BLOCKED
    prov = run.setup_provider()
    run.section(4, total, "Build the demo policy")
    options = run.plan_options(gw, wizard=True)
    plan = run.build_plan(options)
    run.p()
    if not run.approve(plan):
        return run.cancelled()
    run.section(5, total, "Publish and install")
    res = run.apply(plan)
    ok = True
    if res.installed and not run.arg("skip_enforcement"):
        ok = run.enforcement(prov)
    run.p()
    if res.rollback_id:
        run.p("  Undo everything later with  %s" % run.bold("aiguard rollback %s" % res.rollback_id))
    if ok:
        run.p("  Ready. Start the demo with  %s" % run.bold("aiguard demo --guided"))
    else:
        run.p("  Setup finished, but the gateway did not block the test prompt yet. Check the "
              "reasons above, then try: aiguard demo --scene injection")
    run.p("  Everything above is in %s" % run.log.path)
    return EXIT_OK if ok else EXIT_MISMATCH


def cmd_preflight(run: _Run) -> int:
    run.open()
    run.banner()
    run.connect()
    run.pick_gateway()
    run.p()
    report = run.preflight()
    if not report.ok:
        if "https-inspection" in report.fixable():
            run.p("  Next: %s   (asks for approval)" % run.bold("aiguard fix https-inspection"))
        elif "https-rule" in report.fixable():
            run.p("  Next: %s   (asks for approval)"
                  % run.bold("aiguard fix https-inspection --add-rule"))
        return EXIT_BLOCKED
    run.p("  Next: %s to review the change, or %s" % (run.bold("aiguard plan"),
                                                     run.bold("aiguard setup")))
    return EXIT_OK


def cmd_plan(run: _Run) -> int:
    run.open()
    run.banner()
    run.connect()
    gw = run.pick_gateway()
    run.p()
    options = run.plan_options(gw, wizard=False)
    plan = run.build_plan(options)
    if run.verbose:
        run.show_api_calls(plan)
    run.p()
    run.p("  Read-only: nothing was written. To apply exactly this plan:")
    run.p("    %s" % run.bold(run.apply_command(plan.plan_id)))
    return EXIT_OK


def cmd_apply(run: _Run) -> int:
    run.open()
    run.banner()
    run.connect()
    gw = run.pick_gateway()
    prov = run.setup_provider()
    run.p()
    options = run.plan_options(gw, wizard=False)
    plan = run.build_plan(options)
    wanted = run.arg("plan_id")
    if wanted and str(wanted).strip().lower() != plan.plan_id:
        raise ApprovalError(
            "The plan changed since it was reviewed",
            why="You reviewed plan %s; with the current objects and options the plan is %s."
                % (_redact.redact(str(wanted))[:24], plan.plan_id),
            fix=["Check the plan above. If it is what you want: %s" % run.apply_command(plan.plan_id),
                 "Use the same options as for aiguard plan, so the same plan is rebuilt"],
            state="Nothing was changed.")
    run.p()
    if not run.approve(plan):
        return run.cancelled()
    run.section(None, 0, "Publish and install")
    res = run.apply(plan)
    ok = True
    if res.installed and not run.arg("skip_enforcement"):
        ok = run.enforcement(prov)
    run.p()
    if res.rollback_id:
        run.p("  Undo later with  %s" % run.bold("aiguard rollback %s" % res.rollback_id))
    run.p("  %s" % (res.message or "Done."))
    return EXIT_OK if ok else EXIT_MISMATCH


def cmd_demo(run: _Run) -> int:
    s = run.open()
    prov = run.setup_provider()
    guided = bool(run.arg("guided"))
    run.banner()
    dot = " %s " % run.c.g("dot")
    last = run.state.last()
    info = _probe.provider_info(prov)
    model = run.arg("model") or info.get("model")
    if run.provider_key_set or info.get("key_configured"):
        key_kind = "real key"
    else:
        key_kind = "dummy key"
    gw_name = run.arg("gateway") or last.get("gateway")
    bits = [str(gw_name)] if gw_name else []
    profile = run.last_profile()
    if profile:
        bits.append("profile %s" % profile)
    bits += ["provider %s (%s)" % (prov, model), key_kind]
    run.section(6 if guided else None, 6, "Live demo", dot.join(bits))
    if key_kind == "dummy key":
        run.note("No %s key: the provider answers 401 to what gets through; blocks show the same. "
                 "Pass --provider-key-env VAR or set %s for real answers." % (prov, info.get("env")))
    run.tls_check(prov)
    connected = run.connect_for_logs()
    if connected:
        run.last_install()
    prompt = run.arg("prompt")
    if prompt is not None:
        if not str(prompt).strip():
            raise AiguardError("--prompt is empty", code="cli.empty_prompt",
                               fix=["Pass the text to send: --prompt \"...\""],
                               state="Nothing was sent.")
        run.p()
        run.p("  %s %s" % (run.st(run.c.g("arrow"), "magenta"), run.bold("Your prompt")))
        run.stage = "send your prompt"
        r = s.run_prompt(str(prompt), provider=prov, expect=run.arg("expect") or "block",
                         prompt_id="custom")
        if connected:
            run.correlate()
        run.show_result(r)
    else:
        if run.arg("scene"):
            scenes = [_scenes.get_scene(run.args.scene)]
        else:
            scenes = list(_scenes.SCENES)
        for scene in scenes:
            run.play_scene(scene, explicit=bool(run.arg("scene")), provider=prov,
                           connected=connected)
    return run.finish_demo(connected)


def cmd_rollback(run: _Run) -> int:
    s = run.open()
    run.banner()
    info = run.connect() or {}
    rid = run.arg("rollback_id")
    server = info.get("server") or run.arg("server") or run.state.last().get("server")
    point = run.state.get_rollback(rid) if rid else run.state.latest_rollback(server=server)
    if point is None:
        raise PlanError(
            ("Rollback point %s was not found" % rid) if rid else
            "There is nothing to roll back on %s" % server,
            code="plan.rollback_not_found",
            why="Rollback points are kept in %s." % run.state.path,
            fix=["List them: aiguard status",
                 "Or remove the objects in SmartConsole (their comments say \"Created by AI Guard "
                 "Demo Kit\")"],
            state="Nothing was changed.")
    dot = " %s " % run.c.g("dot")
    run.p()
    run.p("  %s %s  %s" % (run.bold("Rollback"), run.bold(str(point.get("id"))), dot.join(
        str(x) for x in (point.get("summary"), point.get("created_at"), point.get("status")) if x)))
    for obj in reversed(point.get("objects") or []):
        rb = (obj or {}).get("rollback") or {}
        target = obj.get("name") or obj.get("describe") or obj.get("step") or ""
        run.p("    %s %s %s" % (run.st("-", "red"), str(rb.get("command") or "undo").ljust(22), target))
    install = not run.arg("no_install")
    run.p("    %s %s" % (run.st(run.c.g("to"), "blue"),
                         "publish" + (" and install-policy" if install else "")))
    if not run.arg("yes"):
        if not run.ask_yes_no("Undo these changes now?", default=False):
            return run.cancelled()
    run.stage = "rollback %s" % point.get("id")
    progress = _Progress(run)
    res = s.rollback(str(point.get("id")), progress_cb=progress, install=install)
    run._clear_live()
    for w in _unique(res.warnings):
        run.p("  %s %s" % (run.st(run.c.g("warn"), "amber"), w))
    if not res.ok:
        run.render_error(res.error or AiguardError(res.message or "Rollback failed"),
                         header="rollback %s" % point.get("id"))
        return EXIT_ERROR
    run.p()
    run.line("ok", "Rolled back", str(point.get("id")), res.message or "")
    return EXIT_OK


def cmd_logs(run: _Run) -> int:
    path = _runlog.latest_log(run.home)
    if path is None:
        run.p("  No logs yet in %s" % _paths.logs_dir(run.home, create=False))
        return EXIT_OK
    if run.arg("path"):
        run.c.print(str(path))
        return EXIT_OK
    errors_only = bool(run.arg("errors"))
    n = run.arg("lines") or (200 if errors_only or run.arg("json") else 80)
    n = max(1, int(n))
    if errors_only or run.arg("json"):
        records = _read_jsonl(path.with_suffix(".jsonl"))
        if errors_only:
            records = [r for r in records if str(r.get("level")) in ("WARN", "ERROR", "HINT")]
        records = records[-n:]
        if run.arg("json"):
            for rec in records:
                run.c.print(json.dumps(rec, ensure_ascii=False))
            return EXIT_OK
        run.p("  %s %s" % (run.dim(run.c.g("rule") * 2), path))
        if not records:
            run.p("  No warnings or errors in this log.")
        for rec in records:
            level = str(rec.get("level") or "")
            color = {"ERROR": "red", "WARN": "amber", "HINT": "blue"}.get(level)
            run.p("  %s %s %s %s" % (run.dim(("line %s" % rec.get("line")).ljust(10)),
                                     run.st(level.ljust(5), color) if color else level.ljust(5),
                                     str(rec.get("component") or "").ljust(9), rec.get("msg") or ""))
            fields = rec.get("fields") or {}
            for key in ("server_said", "why", "fix", "state"):
                if fields.get(key):
                    value = fields[key]
                    text = "; ".join(str(x) for x in value) if isinstance(value, list) else str(value)
                    run.p("  %s%s %s" % (" " * 27, run.dim(key.ljust(11)), _preview(text, 160)))
        return EXIT_OK
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise AiguardError("Could not read %s" % path, code="cli.read_failed", server_said=str(exc),
                           fix=["Check the file permissions"], state="Nothing was changed.")
    run.p("  %s %s %s" % (run.dim(run.c.g("rule") * 2), path, run.dim(run.c.g("rule") * 8)))
    for ln in lines[-n:]:
        run.c.print("  " + ln)
    run.p("  %s" % run.dim("Never written to the log: API keys, passwords, session IDs, secrets "
                           "found in prompts."))
    return EXIT_OK


def cmd_fix(run: _Run) -> int:
    run.open()
    run.banner()
    run.connect()
    gw = run.pick_gateway()
    add_rule = bool(run.arg("add_rule"))
    learning = str(getattr(gw, "https_deployment_mode", "") or "").lower() == "learning"
    if gw.blade("https_inspection") is True and not add_rule and not learning:
        run.p()
        run.line("ok", "HTTPS Inspection", "already on for %s" % gw.name,
                 "if the provider traffic is still not inspected: aiguard fix https-inspection "
                 "--add-rule (adds an Inspect rule for this computer); aiguard preflight checks it")
        return EXIT_OK
    if learning:
        run.line("warn", "HTTPS Inspection", "Learning mode on %s" % gw.name,
                 "the plan sets Full mode")
    if gw.blade("https_inspection") is None:
        run.line("warn", "HTTPS Inspection", "state unknown", "the plan turns it on")
    status = run.https_fix(gw, add_rule=add_rule)
    if status == "unsupported":
        return EXIT_BLOCKED
    if status == "applied":
        run.p("  Next: %s, then %s" % (run.bold("aiguard trust-ca"), run.bold("aiguard preflight")))
    return EXIT_OK


def _trust_sections(path: Path, target: str) -> List[Tuple[str, List[str]]]:
    win = '"%s"' % path
    posix = shlex.quote(str(path))
    out: List[Tuple[str, List[str]]] = []
    if target in ("windows", "all"):
        out.append(("Windows  (PowerShell or Command Prompt, run as Administrator)", [
            "certutil -addstore -f Root %s" % win,
            "or in PowerShell: Import-Certificate -FilePath %s -CertStoreLocation "
            "Cert:\\LocalMachine\\Root" % win,
            "many computers: deploy it by GPO (Computer Configuration > Policies > Windows "
            "Settings > Security Settings > Public Key Policies > Trusted Root Certification "
            "Authorities)",
        ]))
    if target in ("macos", "all"):
        out.append(("macOS", [
            "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "
            "%s" % posix,
        ]))
    if target in ("linux", "all"):
        out.append(("Linux  (Debian / Ubuntu)", [
            "sudo cp %s /usr/local/share/ca-certificates/aiguard-outbound-ca.crt" % posix,
            "sudo update-ca-certificates",
        ]))
        out.append(("Linux  (RHEL / Fedora)", [
            "sudo cp %s /etc/pki/ca-trust/source/anchors/aiguard-outbound-ca.pem" % posix,
            "sudo update-ca-trust",
        ]))
    return out


def _env_command(target: str, var: str, value: str) -> str:
    if target == "windows":
        return '$env:%s = "%s"' % (var, value)
    return "export %s=%s" % (var, shlex.quote(value))


def cmd_trust_ca(run: _Run) -> int:
    meta: Dict[str, Any] = {}
    source = run.arg("from_file")
    if source:
        src = Path(str(source)).expanduser()
        try:
            raw = src.read_bytes()
        except OSError as exc:
            raise AiguardError("Could not read %s" % src, code="cli.read_failed",
                               server_said=str(exc), fix=["Check the path and the permissions"],
                               state="Nothing was written.")
        pem = _normalize_pem(raw, what=str(src))
        dest = Path(str(run.arg("export"))).expanduser() if run.arg("export") else src
        run.banner()
    else:
        s = run.open()
        run.banner()
        run.connect()
        run.stage = "read the outbound inspection certificate"
        meta = _outbound_ca(run, s)
        value = (meta.get("pem") or meta.get("base64-public-certificate")
                 or meta.get("public_certificate"))
        if not value:
            if meta.get("pkcs12_only"):
                raise AiguardError(
                    "The management server returned the outbound CA only as PKCS#12",
                    code="cli.no_pem",
                    why="Management API 1.9.x replies with base64-certificate only; the PEM field "
                        "(base64-public-certificate) needs Management API 2 or later.",
                    fix=["SmartConsole > Gateway > HTTPS Inspection > Step 2: Export certificate",
                         "Then: aiguard trust-ca --from-file <exported file>"],
                    state="Nothing was written.")
            raise AiguardError("The management server returned no outbound CA certificate",
                               code="cli.no_pem",
                               fix=["SmartConsole > Gateway > HTTPS Inspection > Step 1: create or "
                                    "import the outbound CA, publish, then run aiguard trust-ca"],
                               state="Nothing was written.")
        pem = _normalize_pem(value, what="management server reply")
        dest = Path(str(run.arg("export") or (run.home / "outbound-ca.pem"))).expanduser()
    if source is None or run.arg("export"):
        if dest.exists() and not run.arg("force"):
            try:
                same = _normalize_pem(dest.read_bytes()) == pem
            except AiguardError:
                same = False
            if not same:
                raise AiguardError(
                    "%s already exists" % dest, code="cli.file_exists",
                    fix=["Pass --force to overwrite it", "Or choose another file: --export FILE"],
                    state="Nothing was written.")
        _write_atomic(dest, pem)
        if run.log is not None:
            run.log.info("cli", "outbound CA written", path=str(dest), sha256=_pem_sha256(pem))
    dest = dest.resolve()
    target = run.arg("target_os") or "auto"
    if target == "auto":
        target = _os_name()
    dot = " %s " % run.c.g("dot")
    run.p()
    run.p("  %s" % run.bold("Trust the gateway's outbound CA on the demo computers"))
    facts = [x for x in (meta.get("name"), ("issued by %s" % meta["issued-by"]) if meta.get("issued-by")
                         else None, ("valid to %s" % meta["valid-to"]) if meta.get("valid-to") else None)
             if x]
    if facts:
        run.line("info", "Certificate", dot.join(str(f) for f in facts))
    run.line("info", "SHA-256", _pem_sha256(pem))
    run.line("ok", "Saved" if (source is None or run.arg("export")) else "File", str(dest))
    run.p()
    run.p("  aiguard never changes the trust store. Run these yourself:")
    for title, cmds in _trust_sections(dest, target):
        run.p()
        run.p("  %s" % run.bold(title))
        for cmd in cmds:
            run.p("    %s" % cmd)
    env_os = "windows" if target == "windows" else "posix"
    run.p()
    run.p("  %s" % run.bold("Apps with their own CA list"))
    rows = [("Python requests", _env_command(env_os, "REQUESTS_CA_BUNDLE", "<bundle.pem>")),
            ("httpx, OpenAI and Anthropic SDKs", _env_command(env_os, "SSL_CERT_FILE", "<bundle.pem>")),
            ("Node.js", _env_command(env_os, "NODE_EXTRA_CA_CERTS", str(dest)))]
    for label, cmd in rows:
        run.p("    %s %s" % (label.ljust(34), cmd))
    run.note("REQUESTS_CA_BUNDLE and SSL_CERT_FILE replace the default CA list: point them at a "
             "file with the public CAs plus this one (for example the OS bundle after the step "
             "above: /etc/ssl/certs/ca-certificates.crt on Debian/Ubuntu). NODE_EXTRA_CA_CERTS adds "
             "to Node's built-in list.")
    if target != "all":
        run.note("Commands for the other systems: aiguard trust-ca --os all", indent=4)
    run.p()
    run.p("  This kit only:  aiguard demo --outbound-ca %s" % (
        '"%s"' % dest if target == "windows" else shlex.quote(str(dest))))
    return EXIT_OK


def _outbound_ca(run: _Run, session: Any) -> dict:
    """The outbound inspection certificate through the engine (``Session.outbound_ca()``
    when the engine has it; else the preflight helper, read-only)."""
    for name in ("outbound_ca", "outbound_certificate", "get_outbound_ca"):
        fn = getattr(session, name, None)
        if callable(fn):
            data = fn()
            break
    else:
        from . import mgmt as _mgmt
        client = getattr(session, "client", None)
        if client is None or not getattr(client, "logged_in", False):
            raise AiguardError("Not connected to a management server", code="engine.not_connected",
                               fix=["Connect first: pass --server and --api-key-env VAR"],
                               state="Nothing was changed.")
        raw = _mgmt.show_outbound_certificate(client)  # read-only show-* calls
        data = _mgmt.outbound_certificate_info(raw) if raw is not None else None
    if not data:
        gw = run.arg("gateway") or run.state.last().get("gateway") or "Gateway"
        raise PlanError(
            "No outbound inspection certificate", code="plan.no_outbound_ca",
            why="HTTPS Inspection re-signs the traffic with the gateway's outbound CA, and none "
                "exists yet.",
            fix=["SmartConsole > %s > HTTPS Inspection > Step 1: create or import the outbound CA"
                 % gw, "Publish, then run aiguard trust-ca again"],
            state="Nothing was changed.")
    return dict(data) if isinstance(data, dict) else {"pem": str(data)}


def _status_env(run: _Run, dot: str) -> None:
    """The connection defaults from the environment (lab installer's .env), if any."""
    env = run.env
    bits: List[str] = []
    if env.server:
        bits.append("%s:%s" % (env.server, env.port or 443))
    elif env.port:
        bits.append("port %s" % env.port)
    if env.server_type:
        bits.append(env.server_type)
    if env.domain:
        bits.append("domain %s" % env.domain)
    if env.server_name:
        bits.append("certificate name %s" % env.server_name)
    if env.gateway:
        bits.append("gateway %s" % env.gateway)
    if bits:
        run.line("info", "Defaults from the environment", dot.join(bits), "flags win")
    if env.ca_file:
        path = Path(env.ca_file).expanduser()
        if path.is_file():
            run.line("info", "CA file (environment)", str(path))
        else:
            run.line("warn", "CA file (environment)", "%s (missing)" % path,
                     "connecting stops until %s names a PEM file" % _envdefaults.ENV_CA_FILE)
    if env.fingerprint_sha1:
        run.line("info", "Installer saw SHA-1", env.fingerprint_sha1,
                 "compare with: api fingerprint")
    run.env_problems()


def cmd_status(run: _Run) -> int:
    run.banner()
    last = run.state.last()
    dot = " %s " % run.c.g("dot")
    run.section(None, 0, "Status")
    run.line("info", "Version", __version__)
    run.line("info", "Home", str(run.home))
    _status_env(run, dot)
    if last.get("server"):
        conn = ["%s:%s" % (last.get("server"), last.get("port") or 443)]
        if last.get("server_type"):
            conn.append(str(last["server_type"]))
        if last.get("domain"):
            conn.append("domain %s" % last["domain"])
        conn.append("API key" if last.get("auth") != "password" else "user %s" % last.get("user"))
        run.line("info", "Last management server", dot.join(conn))
        if last.get("gateway"):
            run.line("info", "Last gateway", str(last["gateway"]))
        if last.get("ca_file"):
            if Path(str(last["ca_file"])).expanduser().is_file():
                run.line("info", "CA file", str(last["ca_file"]))
            else:
                run.line("warn", "CA file", "%s (missing)" % last["ca_file"],
                         "no longer exists; the next run ignores it")
        if last.get("project_id") or last.get("profile_name"):
            run.line("info", "Demo policy", dot.join(str(x) for x in (
                last.get("profile_name"), ("project %s" % last["project_id"])
                if last.get("project_id") else None,
                "moderation on" if last.get("moderation") else "moderation off") if x))
    else:
        run.line("info", "Last management server", "none yet", "run aiguard setup")
    try:
        points = run.state.list_rollbacks()
    except Exception:  # noqa: BLE001 - informational
        points = []
    if points:
        run.p()
        run.p("  %s  %s" % (run.bold("Rollback points"), run.dim("newest last; undo: aiguard "
                                                                 "rollback ID")))
        for point in points[-8:]:
            run.p("    %s  %s  %s  %s" % (run.bold(str(point.get("id"))),
                                          str(point.get("created_at") or "")[:19],
                                          str(point.get("status") or "").ljust(12),
                                          point.get("summary") or ""))
    log = _runlog.latest_log(run.home)
    report = _latest_report(run.home)
    run.p()
    run.line("info", "Latest log", str(log) if log else "none")
    run.line("info", "Latest report", str(report) if report else "none")
    if run.arg("connect") or run.arg("api_key_env") or (run.arg("user") and run.arg("password_env")):
        s = run.open()
        run.p()
        run.connect(quiet=True)
        gw = run.pick_gateway()
        st = s.status()
        # moderation_on also counts a rollback point that still has the moderation step
        on = True if st.get("moderation_on") else st.get("moderation_enabled")
        run.line("info", "Moderation", {True: "on", False: "off"}.get(on, "unknown"))
        run.line("info", "AI Security", run._ai_cell(gw)[0])
    return EXIT_OK


def cmd_version(run: _Run) -> int:
    run.c.print("aiguard %s  (AI Guard Demo Kit)" % __version__)
    run.c.print(run.dim("Python %s %s %s" % (platform.python_version(), run.c.g("dot"),
                                             platform.platform())))
    return EXIT_OK


# =========================================================================== main


def _refuse_secret_flag(console: Console, flag: str) -> None:
    warn = console.style(console.g("fail"), "red")
    console.print()
    console.print("  %s %s is not accepted." % (warn, flag))
    console.print("    Secrets are never taken from the command line (they end up in shell "
                  "history and process lists).")
    console.print("    Use instead:")
    for opt, text in (("--api-key-env VAR", "the Management API key, from environment variable VAR"),
                      ("--user NAME", "then the password is asked (hidden), or --password-env VAR"),
                      ("--lakera-key-env VAR", "the AI Agent Security (Guard) API key"),
                      ("--provider-key-env VAR", "the AI provider key (e.g. OpenAI)")):
        console.print("      %s %s" % (opt.ljust(24), text))
    console.print("    or leave it out and type the value when asked (input hidden).")


def main(argv: Optional[Sequence[str]] = None, *, console: Optional[Console] = None,
         session_factory: Optional[Callable[..., Any]] = None) -> int:
    """Run the ``aiguard`` command line; returns the exit code (see the module docstring)."""
    args_list = [str(a) for a in (sys.argv[1:] if argv is None else argv)]
    if console is None:
        _reconfigure_stdio()
        console = Console()
    bad = _secret_flag(args_list)
    if bad:
        _refuse_secret_flag(console, bad)
        return EXIT_USAGE
    parser = build_parser()
    try:
        args = parser.parse_args(args_list)
    except _UsageError as exc:
        console.print(exc.usage.rstrip())
        console.print("aiguard: error: %s" % _safe_usage_message(str(exc)))
        return EXIT_USAGE
    except SystemExit as exc:   # --help / --version
        code = exc.code
        if code is None:
            return EXIT_OK
        return code if isinstance(code, int) else EXIT_USAGE
    if getattr(args, "no_color", False):
        console.color = False
    func = getattr(args, "func", None)
    if func is None:
        console.print(parser.format_help().rstrip())
        return EXIT_USAGE
    run = _Run(args, console, session_factory)
    try:
        return int(func(run))
    except _Stop as stop:
        return stop.code
    except KeyboardInterrupt:
        return run.interrupted()
    except EOFError:
        return run.input_ended()
    except AiguardError as err:
        run.render_error(err, header=run.stage or None)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - every failure gets the five-field block
        return run.internal_error(exc)
    finally:
        run.close()


if __name__ == "__main__":  # pragma: no cover - ``python -m aiguard`` uses __main__.py
    raise SystemExit(main())
