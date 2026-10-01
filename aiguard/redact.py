"""Masking and redaction of secrets (spec 2.2).

Everything that leaves the core (log lines, state, reports, JSON for the web
console, error text) goes through :func:`redact` or :func:`redact_obj`.

* :func:`register_secret` adds a value (API key, password, sid ...) to a
  process-wide, thread-safe registry. Every later :func:`redact` call replaces
  it (and its JSON-escaped / URL-encoded forms) with :func:`mask_secret`.
  An ``owner`` (any hashable token, e.g. one per engine session) holds the value:
  :func:`forget_secret` drops it only when no owner holds it any more, so two web
  sessions that share a key never unmask it for each other.
* :func:`redact` then applies a fixed set of regular expressions for secrets
  that were never registered (Bearer tokens, ``X-chkp-sid``, ``"password": ...``,
  provider key formats, private key blocks ...).
* :func:`redact_obj` deep-copies a structure, masks values stored under
  sensitive keys and runs :func:`redact` on every other string.

Passwords are masked without their last characters (``****``): a human-chosen password
is short, so four characters are a large share of it. Values under password keys
(``password``, ``passwd``, ``pwd``, ``passphrase`` ...) and secrets registered with
``keep_tail=False`` are shown as ``****`` everywhere; API keys and tokens keep the
``prefix****last4`` form so a presenter can tell two keys apart.

Masked output is a fixed point: ``redact(redact(x)) == redact(x)``. The state
store relies on that to refuse anything that still looks like a secret.
"""

from __future__ import annotations

import copy
import json
import re
import threading
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, quote_plus

__all__ = [
    "MASK",
    "KNOWN_PREFIXES",
    "register_secret",
    "forget_secret",
    "clear_secrets",
    "mask_secret",
    "redact",
    "redact_obj",
    "is_sensitive_key",
    "is_password_key",
]

MASK = "****"

# Longest first: "sk-ant-" must win over "sk-".
KNOWN_PREFIXES = ("sk-ant-", "sk-", "lk_", "AKIA", "ghp_", "xoxb-")

# --------------------------------------------------------------------------- registry

_lock = threading.Lock()
_registry: Dict[str, Tuple[str, ...]] = {}
_holders: Dict[str, set] = {}  # value -> owners that still use it (see forget_secret)
_no_tail: set = set()          # values registered with keep_tail=False (passwords)
# (variant, replacement) pairs, longest variant first; replaced atomically
_active: Tuple[Tuple[str, str], ...] = ()


def _to_text(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return value if isinstance(value, str) else str(value)


def _variants(value: str) -> Tuple[str, ...]:
    """The forms a secret can take inside text we redact."""
    candidates = [value, value.strip()]
    try:
        candidates.append(json.dumps(value)[1:-1])
        candidates.append(json.dumps(value, ensure_ascii=False)[1:-1])
    except (TypeError, ValueError):  # pragma: no cover - str always serialises
        pass
    candidates.append(quote(value, safe=""))
    candidates.append(quote_plus(value, safe=""))
    out: List[str] = []
    for c in candidates:
        if len(c) >= 4 and c not in out:
            out.append(c)
    return tuple(out)


def _rebuild() -> None:
    global _active
    pairs: Dict[str, str] = {}
    for value, vs in _registry.items():
        tail = value not in _no_tail
        for v in vs:
            masked = mask_secret(v, keep_tail=tail)
            # A variant shared by a password and a key: the stricter mask wins.
            if v not in pairs or masked == MASK:
                pairs[v] = masked
    _active = tuple(sorted(pairs.items(), key=lambda kv: (-len(kv[0]), kv[0])))


def register_secret(value: Optional[str], *, owner: Any = None, keep_tail: bool = True) -> None:
    """Remember ``value`` so every later :func:`redact` masks it.

    ``None`` and values shorter than 4 characters are ignored. Thread-safe.
    ``owner`` (optional, hashable) records who holds the value; see
    :func:`forget_secret`. ``keep_tail=False`` (passwords) masks it as ``****`` without
    its last characters; once a value was registered that way it stays so.
    """
    if value is None:
        return
    text = _to_text(value)
    if len(text) < 4:
        return
    with _lock:
        changed = False
        if text not in _registry:
            _registry[text] = _variants(text)
            changed = True
        if not keep_tail and text not in _no_tail:
            _no_tail.add(text)
            changed = True
        if changed:
            _rebuild()
        if owner is not None:
            _holders.setdefault(text, set()).add(owner)


def forget_secret(value: Any, *, owner: Any = None) -> None:
    """Stop masking ``value`` (e.g. when a session ends). Never raises.

    With ``owner``: that owner lets go; the value is forgotten once no owner holds it.
    Without ``owner``: the value is forgotten only when no owner holds it (a value an
    engine session still uses stays masked).
    """
    if value is None:
        return
    text = _to_text(value)
    with _lock:
        holders = _holders.get(text)
        if owner is not None and holders is not None:
            holders.discard(owner)
        if holders:
            return
        _holders.pop(text, None)
        _no_tail.discard(text)
        if _registry.pop(text, None) is not None:
            _rebuild()


def clear_secrets() -> None:
    """Forget every registered secret (tests, full shutdown)."""
    with _lock:
        _registry.clear()
        _holders.clear()
        _no_tail.clear()
        _rebuild()


def _registry_snapshot() -> Dict[str, Tuple[str, ...]]:
    """Private: used by the test suite to isolate tests from each other."""
    with _lock:
        return dict(_registry)


def _registry_restore(snapshot: Dict[str, Tuple[str, ...]]) -> None:
    """Private: used by the test suite to isolate tests from each other."""
    with _lock:
        _registry.clear()
        _registry.update(snapshot)
        for text in list(_holders):
            if text not in _registry:
                _holders.pop(text, None)
        for text in list(_no_tail):
            if text not in _registry:
                _no_tail.discard(text)
        _rebuild()


# --------------------------------------------------------------------------- masking

def mask_secret(value: Optional[str], *, keep_tail: bool = True) -> str:
    """``prefix****last4``.

    ``None``/``""`` -> ``""``; fewer than 8 characters -> ``"****"``; otherwise a
    recognised provider prefix (``sk-ant-``, ``sk-``, ``lk_``, ``AKIA``, ``ghp_``,
    ``xoxb-``) is kept when at least 8 characters follow it, then ``****`` and
    the last 4 characters. A 64-hex Guard API key becomes ``****`` + last 4.
    ``keep_tail=False`` (passwords) always gives ``"****"`` for a non-empty value.
    """
    if value is None:
        return ""
    text = _to_text(value)
    if text == "":
        return ""
    if len(text) < 8 or not keep_tail:
        return MASK
    prefix = ""
    for p in KNOWN_PREFIXES:
        if text.startswith(p) and len(text) - len(p) >= 8:
            prefix = p
            break
    return prefix + MASK + text[-4:]


def _mask_quoted(value: str, keep_tail: bool = True) -> str:
    """Mask a value that sits inside quotes without breaking the quoting."""
    masked = mask_secret(value, keep_tail=keep_tail)
    tail = value[-5:]
    if any(ch in tail for ch in "\\\"'"):
        # The last 4 characters could split an escape sequence: drop them.
        prefix = masked[: masked.index(MASK)] if MASK in masked else ""
        return prefix + MASK
    return masked


# --------------------------------------------------------------------------- patterns

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY( BLOCK)?-----[\s\S]*?"
    r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)"
)

_URL_CREDS_RE = re.compile(
    r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@\"'<>]+:)([^\s@/\"'<>]+)(@)"
)

_COOKIE_HEADER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])((?:set-)?cookie[ \t]*:[ \t]*)([^\r\n\"']+)"
)

_AUTH_HEADER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])((?:proxy-)?authorization\\?[\"']?[ \t]*[:=][ \t]*\\?[\"']?)"
    r"(?:(bearer|basic|digest|token|negotiate|apikey)[ \t]+)?"
    r"([^\s\"',;\\]+)"
)

_BEARER_RE = re.compile(r"(?i)\b(bearer[ \t]+)([A-Za-z0-9\-._~+/]{8,}=*)")

_KV_KEYS = (
    r"x-chkp-sid|aws[-_]?secret[-_]?access[-_]?key|secret[-_]?access[-_]?key|"
    r"client[-_]?secret|secret[-_]?key|private[-_]?key|"
    r"(?:access|refresh|auth|id|session|bearer)[-_]?token|"
    r"api[-_]?key|apikey|passw(?:or)?d|passphrase|pwd|secret|token|sid|cookie"
)

_KV_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?P<key>" + _KV_KEYS + r")"
    r"(?P<sep>\\?[\"']?[ \t]*[:=][ \t]*)"
    r"(?:\\(?P<q1>[\"'])(?P<v1>.*?)\\(?P=q1)"
    r"|(?P<q2>[\"'])(?P<v2>(?:\\.|(?!(?P=q2))[^\\])*)(?P=q2)"
    r"|(?P<v3>(?!(?:null|true|false|none)\b)[^\s\"',;}\])&<>]+))"
)

_GENERIC_RE = re.compile(
    r"(?i)(key|token|secret|password|passwd)(\\?[\"']?[ \t]*[:=][ \t]*\\?[\"']?)"
    r"([A-Za-z0-9_\-]{32,})"
)

_TOKEN_RES = tuple(
    re.compile(p)
    for p in (
        r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_\-]{16,}",
        r"(?<![A-Za-z0-9])lk_[A-Za-z0-9_\-]{12,}",
        r"(?<![A-Za-z0-9])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}",
        r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}",
        r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9\-]{10,}",
        r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])",
        r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}",
    )
)


def _sub_private_key(m: re.Match[str]) -> str:
    kind = m.group(1) or ""
    block = m.group(2) or ""
    return "-----BEGIN %sPRIVATE KEY%s-----%s-----END %sPRIVATE KEY%s-----" % (
        kind, block, MASK, kind, block)


def _sub_url_creds(m: re.Match[str]) -> str:
    return m.group(1) + mask_secret(m.group(2)) + m.group(3)


def _sub_cookie(m: re.Match[str]) -> str:
    value = m.group(2).rstrip()
    trailing = m.group(2)[len(value):]
    return m.group(1) + mask_secret(value) + trailing


def _sub_auth(m: re.Match[str]) -> str:
    scheme = m.group(2)
    return m.group(1) + ((scheme + " ") if scheme else "") + mask_secret(m.group(3))


def _sub_bearer(m: re.Match[str]) -> str:
    token = m.group(2)
    # Plain words ("Bearer authentication") are left alone; real tokens have
    # digits or are long.
    if not (any(ch.isdigit() for ch in token) or len(token) >= 24):
        return m.group(0)
    return m.group(1) + mask_secret(token)


_PASSWORD_KEY_RE = re.compile(r"(?i)^(?:passw(?:or)?d|passphrase|pwd)$")


def _sub_kv(m: re.Match[str]) -> str:
    key, sep = m.group("key"), m.group("sep")
    tail = not _PASSWORD_KEY_RE.match(key)
    if m.group("q1") is not None:
        q = m.group("q1")
        return "%s%s\\%s%s\\%s" % (key, sep, q, _mask_quoted(m.group("v1"), tail), q)
    if m.group("q2") is not None:
        q = m.group("q2")
        return "%s%s%s%s%s" % (key, sep, q, _mask_quoted(m.group("v2"), tail), q)
    return key + sep + mask_secret(m.group("v3"), keep_tail=tail)


def _sub_generic(m: re.Match[str]) -> str:
    tail = not _PASSWORD_KEY_RE.match(m.group(1))
    return m.group(1) + m.group(2) + mask_secret(m.group(3), keep_tail=tail)


def _sub_token(m: re.Match[str]) -> str:
    return mask_secret(m.group(0))


_PATTERNS = (
    (_PRIVATE_KEY_RE, _sub_private_key),
    (_URL_CREDS_RE, _sub_url_creds),
    (_COOKIE_HEADER_RE, _sub_cookie),
    (_AUTH_HEADER_RE, _sub_auth),
    (_BEARER_RE, _sub_bearer),
    (_KV_RE, _sub_kv),
    (_GENERIC_RE, _sub_generic),
) + tuple((r, _sub_token) for r in _TOKEN_RES)


def redact(text: Any) -> str:
    """Return ``text`` with registered secrets and secret-looking values masked.

    ``None`` -> ``""``; bytes are decoded as UTF-8; other objects are ``str()``-ed.
    """
    if text is None:
        return ""
    text = _to_text(text)
    if not text:
        return text
    for secret, masked in _active:
        if secret in text:
            text = text.replace(secret, masked)
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


# --------------------------------------------------------------------------- objects

_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_WORD_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")

_SENSITIVE_WORDS = frozenset((
    "pass", "password", "passwd", "pwd", "passphrase", "secret", "secrets",
    "token", "sid", "authorization", "cookie", "cookies", "apikey",
    "credential", "credentials", "privatekey",
))
_SENSITIVE_PAIRS = frozenset((("api", "key"), ("private", "key")))
# Values under these words are human-chosen passwords: masked without a tail.
_PASSWORD_WORDS = frozenset(("pass", "password", "passwd", "pwd", "passphrase"))
# A key whose LAST word is one of these describes a secret without holding it
# ("api_key_env", "lakera_api_key_configured", "token_count", "password_file").
_DESCRIPTIVE_SUFFIXES = frozenset((
    "env", "var", "name", "configured", "present", "set", "len", "length",
    "source", "type", "masked", "format", "ok", "valid", "validated",
    "required", "count", "hint", "file", "path", "id", "expires", "expiry",
    "timeout", "status",
))


def _key_words(key: str) -> List[str]:
    parts = _WORD_SPLIT_RE.split(_CAMEL_RE.sub("_", key))
    return [p.lower() for p in parts if p]


def is_sensitive_key(key: Any) -> bool:
    """True for dict keys whose values are secrets.

    Matches whole words (split on ``-``, ``_``, ``.``, spaces and camelCase) for
    pass/password/api-key/secret/token/sid/authorization/x-chkp-sid/cookie, so
    ``ai-agent-security-api-key``, ``lakera_api_key``, ``X-Chkp-Sid`` and
    ``apiKey`` match while ``bypass``, ``passed``, ``inside``, ``masked_key``
    and descriptive keys such as ``api_key_env`` or ``token_count`` do not.
    """
    if not isinstance(key, str) or not key:
        return False
    words = _key_words(key)
    if len(words) > 1 and words[-1] in _DESCRIPTIVE_SUFFIXES:
        return False
    if any(w in _SENSITIVE_WORDS for w in words):
        return True
    return any((a, b) in _SENSITIVE_PAIRS for a, b in zip(words, words[1:]))


def is_password_key(key: Any) -> bool:
    """True for sensitive keys that hold a password (``password``, ``passwd``,
    ``mgmt_password``, ``passphrase`` ...): their values are masked without a tail."""
    if not is_sensitive_key(key):
        return False
    return any(w in _PASSWORD_WORDS for w in _key_words(key))


_FORCE_SECRET = 1
_FORCE_PASSWORD = 2


def _redact_value(obj: Any, force: int, seen: Tuple[int, ...]) -> Any:
    if isinstance(obj, dict):
        if id(obj) in seen:
            return MASK
        seen = seen + (id(obj),)
        out = {}
        for k, v in obj.items():
            new_key = redact(k) if isinstance(k, str) else k
            sub = force
            if is_password_key(k):
                sub = _FORCE_PASSWORD
            elif not force and is_sensitive_key(k):
                sub = _FORCE_SECRET
            out[new_key] = _redact_value(v, sub, seen)
        return out
    if isinstance(obj, (list, tuple, set, frozenset)):
        if id(obj) in seen:
            return MASK
        seen = seen + (id(obj),)
        items = [_redact_value(v, force, seen) for v in obj]
        if isinstance(obj, tuple):
            if hasattr(obj, "_fields"):  # namedtuple
                try:
                    return type(obj)(*items)
                except TypeError:
                    return tuple(items)
            return tuple(items)
        if isinstance(obj, (set, frozenset)):
            try:
                return type(obj)(items)
            except TypeError:
                return items
        return items
    if obj is None or isinstance(obj, bool):
        return obj
    if force:
        return mask_secret(_to_text(obj), keep_tail=force != _FORCE_PASSWORD)
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, (bytes, bytearray)):
        return redact(obj).encode("utf-8")
    if isinstance(obj, (int, float, complex)):
        return obj
    try:
        return copy.deepcopy(obj)
    except Exception:  # noqa: BLE001 - uncopyable objects are returned as-is
        return obj


def redact_obj(obj: Any) -> Any:
    """Deep copy of ``obj`` that is safe to log, store or display.

    * values under sensitive keys (see :func:`is_sensitive_key`) become
      ``mask_secret(str(value))`` (``"****"`` under password keys, see
      :func:`is_password_key`); containers under such keys have every leaf
      masked; ``None`` and booleans are kept (they cannot hold a secret);
    * every other string goes through :func:`redact` (dict keys too).
    """
    return _redact_value(obj, 0, ())
