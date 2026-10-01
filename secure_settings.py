"""Encryption at rest for secret Settings values (AES-256-GCM).

Stored formats:

* ``enc:v2:<base64 nonce>:<base64 ciphertext+tag>``: current. The Settings key
  name is the AES-GCM associated data, so a ciphertext copied into another
  row (DEMO_API_KEY -> AZURE_OPENAI_API_KEY, say) fails to decrypt.
* ``enc:v1:...``: older, not bound to a name. Still decrypted so the startup
  migration can re-encrypt it as v2.
* ``mac:v1:<base64 tag>:<value>``: a readable value (an endpoint URL) with an
  HMAC-SHA256 tag over the key name and value, so a database write cannot
  silently point a saved API key at another host. The HMAC key is derived
  from the encryption key with HKDF.

Key source, in order:
  1. env ``SETTINGS_ENCRYPTION_KEY``: base64 of exactly 32 random bytes.
  2. ``<instance dir>/.settings_key``: generated on first use (32 random bytes,
     base64), file mode 0o600, created atomically so several gunicorn workers
     starting together agree on one key.

Values without an ``enc:`` prefix are returned unchanged by ``decrypt`` so
plaintext rows written by older versions keep working until the startup
migration re-encrypts them (app.py then stops accepting them).

Nothing in this module logs or prints key material or setting values.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import secrets as _secrets
import tempfile
import threading
from pathlib import Path
from typing import Callable, Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ENC_PREFIX_V1 = "enc:v1:"
ENC_PREFIX_V2 = "enc:v2:"
ENC_PREFIX = ENC_PREFIX_V2  # what encrypt(value, name) writes
MAC_PREFIX = "mac:v1:"
_AAD_PREFIX = b"aiguard-settings:v2:"
_MAC_INFO = b"aiguard-settings-mac:v1"
KEY_ENV = "SETTINGS_ENCRYPTION_KEY"
KEY_FILENAME = ".settings_key"
KEY_BYTES = 32
NONCE_BYTES = 12
MASK = "****"

# Settings keys that always hold secrets. Any other key that ends in _KEY or
# _API_KEY, or contains SECRET / PASSWORD / TOKEN, is treated as secret too.
KNOWN_SECRET_KEYS = frozenset(
    {
        "DEMO_API_KEY",
        "LAKERA_API_KEY",
        "OPENAI_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AZURE_CONTENT_SAFETY_KEY",
    }
)
_SECRET_WORDS = ("SECRET", "PASSWORD", "TOKEN")

KEY_HELP = (
    "SETTINGS_ENCRYPTION_KEY must be the base64 encoding of exactly 32 random bytes. "
    "Generate one with: python -c \"import base64,os; print(base64.b64encode(os.urandom(32)).decode())\""
)

PathLike = Union[str, "os.PathLike[str]"]

_lock = threading.Lock()
_instance_dir: Optional[Path] = None
_cipher: Optional[AESGCM] = None
_mac_key: Optional[bytes] = None
_key_source: Optional[str] = None


class SettingsCryptoError(Exception):
    """Base error for settings encryption problems (messages never contain secrets)."""


class SettingsKeyError(SettingsCryptoError):
    """The configured encryption key is unusable."""


class SettingsDecryptError(SettingsCryptoError):
    """A stored value could not be decrypted (wrong key or tampered data)."""


class SettingsIntegrityError(SettingsCryptoError):
    """A stored value is unauthenticated or its integrity tag does not match."""


# ---------------------------------------------------------------------------
# Classification and masking
# ---------------------------------------------------------------------------


def is_secret_key(key: Optional[str]) -> bool:
    """True when a Settings key holds a secret that must be encrypted at rest."""
    k = (key or "").strip().upper()
    if not k:
        return False
    if k in KNOWN_SECRET_KEYS:
        return True
    if k.endswith("_KEY") or k.endswith("_API_KEY"):
        return True
    return any(word in k for word in _SECRET_WORDS)


def is_encrypted(value: object) -> bool:
    """True for any encrypted format (enc:v1 or enc:v2)."""
    return isinstance(value, str) and value.startswith((ENC_PREFIX_V1, ENC_PREFIX_V2))


def is_bound(value: object) -> bool:
    """True for the current format, encrypted with the setting name as associated data."""
    return isinstance(value, str) and value.startswith(ENC_PREFIX_V2)


def is_signed(value: object) -> bool:
    """True for a readable value carrying an integrity tag (mac:v1)."""
    return isinstance(value, str) and value.startswith(MAC_PREFIX)


def mask(value: Optional[str]) -> str:
    """Display-safe hint: '' when empty, '****' when short, else '****' + last 4."""
    if not value:
        return ""
    value = str(value)
    if len(value) < 8:
        return MASK
    return MASK + value[-4:]


# ---------------------------------------------------------------------------
# Secret files (shared with app.py for instance/.flask_secret)
# ---------------------------------------------------------------------------


def _tighten_permissions(path: Path) -> None:
    """Best effort: make an existing secret file owner-only (POSIX)."""
    if os.name != "posix":
        return
    try:
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            os.chmod(path, 0o600)
    except OSError:
        pass


def read_or_create_secret_file(path: PathLike, factory: Callable[[], str]) -> "tuple[str, bool]":
    """Return (value, created) for a small secret file, creating it atomically.

    The value is written to a 0o600 temp file in the same directory and then
    hard-linked into place, which fails if another process got there first; in
    that case the winner's value is used. File systems without hard links fall
    back to os.replace when the target is still missing.
    """
    path = Path(path)
    try:
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            _tighten_permissions(path)
            return existing, False
    except FileNotFoundError:
        pass

    path.parent.mkdir(parents=True, exist_ok=True)
    value = factory().strip()
    if not value:
        raise SettingsCryptoError("secret factory returned an empty value")
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    created = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(value + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp_name, 0o600)
        except OSError:
            pass
        try:
            os.link(tmp_name, str(path))
            created = True
        except FileExistsError:
            created = False
        except (AttributeError, NotImplementedError, OSError):
            if not path.exists():
                os.replace(tmp_name, str(path))
                created = True
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass

    final = path.read_text(encoding="utf-8").strip()
    if not final:
        raise SettingsCryptoError("secret file %s is empty" % path.name)
    _tighten_permissions(path)
    return final, created and final == value


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


def configure(instance_dir: Optional[PathLike] = None) -> None:
    """Set the directory holding .settings_key and drop any cached key."""
    global _instance_dir, _cipher, _mac_key, _key_source
    with _lock:
        _instance_dir = Path(instance_dir).resolve() if instance_dir else None
        _cipher = None
        _mac_key = None
        _key_source = None


def instance_dir() -> Path:
    if _instance_dir is not None:
        return _instance_dir
    env_dir = os.getenv("INSTANCE_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    return Path(__file__).resolve().parent / "instance"


def decode_key(text: str) -> bytes:
    """Decode a base64 (standard or URL-safe) 32-byte key or raise SettingsKeyError."""
    cleaned = (text or "").strip()
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        try:
            raw = base64.b64decode(cleaned, altchars=b"-_", validate=True)
        except (binascii.Error, ValueError):
            raw = b""
    if len(raw) != KEY_BYTES:
        raise SettingsKeyError(KEY_HELP)
    return raw


def generate_key_text() -> str:
    return base64.b64encode(_secrets.token_bytes(KEY_BYTES)).decode("ascii")


def _derive_mac_key(key: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_MAC_INFO).derive(key)


def _load_cipher() -> AESGCM:
    global _cipher, _mac_key, _key_source
    if _cipher is not None:
        return _cipher
    with _lock:
        if _cipher is not None:
            return _cipher
        env_value = os.getenv(KEY_ENV, "").strip()
        if env_value:
            key = decode_key(env_value)
            source = "env"
        else:
            key_path = instance_dir() / KEY_FILENAME
            text, created = read_or_create_secret_file(key_path, generate_key_text)
            key = decode_key(text)
            # The caller (app.py) reports a generated key once at startup.
            source = "generated" if created else "file"
        _mac_key = _derive_mac_key(key)
        _cipher = AESGCM(key)
        _key_source = source
        return _cipher


def _load_mac_key() -> bytes:
    _load_cipher()
    assert _mac_key is not None
    return _mac_key


def key_source() -> Optional[str]:
    """'env', 'file' or 'generated' once the key has been loaded, else None."""
    return _key_source


def ensure_key() -> str:
    """Load (or create) the key now so configuration errors surface at startup."""
    _load_cipher()
    return _key_source or "unknown"


# ---------------------------------------------------------------------------
# Encrypt / decrypt
# ---------------------------------------------------------------------------

_ENC_RE = re.compile(r"^enc:(v1|v2):([A-Za-z0-9+/=_-]+):([A-Za-z0-9+/=_-]+)$")
_MAC_RE = re.compile(r"^mac:v1:([A-Za-z0-9+/=]+):(.*)$", re.S)


def _aad(name: str) -> bytes:
    name = (name or "").strip()
    if not name:
        raise SettingsCryptoError("a setting name is required")
    return _AAD_PREFIX + name.encode("utf-8")


def encrypt(plaintext: str, name: Optional[str] = None) -> str:
    """Encrypt a string for the Settings row ``name``: 'enc:v2:<b64 nonce>:<b64 ciphertext>'.

    The name is the associated data, so the value only decrypts under that name.
    The given text is always encrypted as-is (a key that happens to start with
    'enc:' is still a key).

    Without ``name`` this writes the older unbound 'enc:v1:' format and returns
    already encrypted values unchanged; app.py always passes the name.
    """
    if plaintext is None:
        raise TypeError("encrypt() needs a string")
    plaintext = str(plaintext)
    if name is None:
        if is_encrypted(plaintext):
            return plaintext
        prefix, aad = ENC_PREFIX_V1, None
    else:
        prefix, aad = ENC_PREFIX_V2, _aad(name)
    cipher = _load_cipher()
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = cipher.encrypt(nonce, plaintext.encode("utf-8"), aad)
    return "%s%s:%s" % (
        prefix,
        base64.b64encode(nonce).decode("ascii"),
        base64.b64encode(ciphertext).decode("ascii"),
    )


def decrypt(value: str, name: Optional[str] = None, *, allow_v1: bool = True) -> str:
    """Decrypt an 'enc:v2:' (needs ``name``) or 'enc:v1:' value.

    Anything without an 'enc:' prefix is returned unchanged. ``allow_v1=False``
    refuses the unbound v1 format.
    """
    if not is_encrypted(value):
        return value
    match = _ENC_RE.match(value.strip())
    if not match:
        raise SettingsDecryptError("Stored value is not in the enc:v1/enc:v2 format")
    version = match.group(1)
    if version == "v1" and not allow_v1:
        raise SettingsDecryptError("Stored value uses the old enc:v1 format")
    if version == "v2" and not name:
        raise SettingsDecryptError("Stored value is bound to a setting name; pass it")
    try:
        nonce = base64.b64decode(match.group(2), validate=True)
        ciphertext = base64.b64decode(match.group(3), validate=True)
    except (binascii.Error, ValueError):
        raise SettingsDecryptError("Stored value is not valid base64") from None
    if len(nonce) != NONCE_BYTES:
        raise SettingsDecryptError("Stored value has an invalid nonce")
    cipher = _load_cipher()
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, _aad(name) if version == "v2" else None)
    except InvalidTag:
        raise SettingsDecryptError(
            "Stored value could not be decrypted with the current settings key for this "
            "setting (was SETTINGS_ENCRYPTION_KEY or instance/.settings_key changed, or "
            "was the value copied from another setting?)"
        ) from None
    return plaintext.decode("utf-8")


def _tag(name: str, value: str) -> bytes:
    message = _MAC_INFO + b"\x00" + _aad(name) + b"\x00" + value.encode("utf-8")
    return hmac.new(_load_mac_key(), message, hashlib.sha256).digest()


def sign(name: str, value: str) -> str:
    """'mac:v1:<b64 tag>:<value>': the value stays readable, its integrity is bound to ``name``."""
    if value is None:
        raise TypeError("sign() needs a string")
    value = str(value)
    return "%s%s:%s" % (MAC_PREFIX, base64.b64encode(_tag(name, value)).decode("ascii"), value)


def verify(name: str, stored: str) -> str:
    """The value of a 'mac:v1:' string when its tag matches ``name``, else SettingsIntegrityError."""
    match = _MAC_RE.match(stored or "")
    if not match:
        raise SettingsIntegrityError("Stored value carries no integrity tag")
    try:
        tag = base64.b64decode(match.group(1), validate=True)
    except (binascii.Error, ValueError):
        raise SettingsIntegrityError("Stored value has an invalid integrity tag") from None
    value = match.group(2)
    if not hmac.compare_digest(tag, _tag(name, value)):
        raise SettingsIntegrityError(
            "Stored value does not match its integrity tag (changed outside the app, "
            "copied from another setting, or the settings key changed)"
        )
    return value
