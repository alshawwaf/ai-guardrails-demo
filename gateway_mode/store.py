"""In-memory, per-user store of aiguard engine Sessions for the web console (spec 9.2).

* One :class:`aiguard.engine.Session` per (signed-in user id, random browser id kept in
  the Flask session as ``session["gw_sid"]``). Nothing is persisted: secrets live only in
  the engine Session's memory.
* Idle entries expire after ``idle_seconds`` (60 minutes): the engine Session is closed
  (Management API logout, secrets forgotten) and uploaded CA files are deleted. An entry
  with a running job is never expired.
* CA certificates uploaded as PEM text are written to ``<instance>/aiguard/ca/<random>.pem``
  with mode 0600. A replaced CA file is kept until the session closes (a running check or
  the management client may still read it) and every file is deleted on disconnect /
  expiry. :meth:`SessionStore.purge_ca_dir` removes what a killed process left behind.
* At most ``max_per_user`` entries per signed-in user (the least recently used idle one is
  closed first), and the per-key history is bounded.
* An engine Session that is in the middle of a synchronous operation (``Session.busy``)
  is never expired; when one is closed anyway (disconnect race, shutdown) a watcher closes
  it again once the operation ends, so a login that completes late is logged out.
* ``session_factory`` is a module attribute so tests can replace it (monkeypatch) with a
  factory returning a pre-configured or fake Session.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import ssl
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

__all__ = [
    "IDLE_SECONDS",
    "CA_PEM_MAX_BYTES",
    "MAX_ENTRIES_PER_USER",
    "CaPemError",
    "SessionClosed",
    "session_busy",
    "Entry",
    "SessionStore",
    "default_session_factory",
    "session_factory",
    "normalize_ca_pem",
    "read_jsonl_tail",
]

IDLE_SECONDS = 60 * 60
CA_PEM_MAX_BYTES = 64 * 1024
MAX_ENTRIES_PER_USER = 5
MAX_HISTORY = 500
LATE_CLOSE_SECONDS = 15 * 60
_CA_NAME_RE = re.compile(r"^[0-9a-f]{32}\.pem$")

Key = Tuple[str, str]

_CERT_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----")


def default_session_factory(*, home: Path) -> Any:
    """A real engine Session whose RunLog / state live under ``home``."""
    from aiguard.engine import Session

    return Session(home=home)


# Replaced by tests (monkeypatch gateway_mode.store.session_factory).
session_factory: Callable[..., Any] = default_session_factory


class CaPemError(ValueError):
    """The uploaded CA text is not acceptable (message is user-facing, no secrets)."""


class SessionClosed(RuntimeError):
    """The entry was closed (disconnect, expiry) while a request was still using it."""


def session_busy(sess: Any) -> Optional[str]:
    """Name of the engine operation running in ``sess`` right now, or None (the engine's
    public ``Session.busy``; ``_busy`` for an engine without it)."""
    try:
        value = getattr(sess, "busy", None)
        if value is None or callable(value):
            value = getattr(sess, "_busy", None)
        return str(value) if value else None
    except Exception:  # noqa: BLE001 - a broken probe counts as busy
        return "unknown"


def normalize_ca_pem(text: Any) -> str:
    """Validate PEM text holding one or more CA certificates; return only the
    certificate blocks. Raises :class:`CaPemError` with a user-facing message."""
    if not isinstance(text, str) or not text.strip():
        raise CaPemError("The CA certificate is empty")
    raw = text.encode("utf-8", "replace")
    if len(raw) > CA_PEM_MAX_BYTES:
        raise CaPemError("The CA certificate is larger than 64 KB")
    if "PRIVATE KEY" in text:
        raise CaPemError("This file contains a private key. Upload only the CA certificate "
                         "(-----BEGIN CERTIFICATE-----), never a key")
    if "-----BEGIN CERTIFICATE-----" not in text:
        raise CaPemError("Not a PEM certificate: the text must contain "
                         "-----BEGIN CERTIFICATE-----")
    blocks = []
    for match in _CERT_BLOCK_RE.finditer(text):
        body = re.sub(r"\s+", "", match.group(1))
        if not body:
            continue
        lines = [body[i:i + 64] for i in range(0, len(body), 64)]
        blocks.append("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n"
                      % "\n".join(lines))
    if not blocks:
        raise CaPemError("No complete certificate found (missing -----END CERTIFICATE-----)")
    if len(blocks) > 20:
        raise CaPemError("Too many certificates in one file (at most 20)")
    pem = "".join(blocks)
    # Parse with the same TLS stack that will use it (verification stays on).
    try:
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cadata=pem)
    except (ssl.SSLError, ValueError) as exc:
        raise CaPemError("The certificate could not be read (%s)" % type(exc).__name__) from None
    return pem


def _write_private(directory: Path, data: str) -> Path:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / ("%s.pem" % secrets.token_hex(16))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "w", encoding="ascii", newline="\n") as fh:
        fh.write(data)
    return path


def _remove(path: Optional[Path]) -> None:
    if path is None:
        return
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _norm_filter(value: Optional[str], upper: bool) -> Optional[set]:
    if not value:
        return None
    items = [v.strip() for v in str(value).split(",") if v.strip()]
    if not items:
        return None
    return {v.upper() if upper else v.lower() for v in items}


def read_jsonl_tail(path: Optional[Path], n: int = 200, level: Optional[str] = None,
                    component: Optional[str] = None) -> List[dict]:
    """Last ``n`` records of a RunLog ``.jsonl`` file (for a session that was closed)."""
    if not path or n <= 0:
        return []
    try:
        with open(str(path), "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    levels = _norm_filter(level, True)
    comps = _norm_filter(component, False)
    out: List[dict] = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        lvl = str(rec.get("level", "")).upper()
        if lvl == "WARNING":
            lvl = "WARN"
        if levels and lvl not in levels:
            continue
        if comps and str(rec.get("component", "")).lower() not in comps:
            continue
        out.append(rec)
    return out[-n:]


class Entry(object):
    """One user's engine Session plus the files uploaded for it."""

    def __init__(self, key: Key, session: Any, now: float) -> None:
        self.key = key
        self.session = session
        self.created = now
        self.last_used = now
        self.mgmt_ca: Optional[Path] = None       # CA for the management server
        self.outbound_ca: Optional[Path] = None   # gateway outbound (HTTPS Inspection) CA
        self.retired: List[Path] = []             # replaced CA files, deleted on close
        self.last_error: Optional[dict] = None
        self.closed = False

    def log_paths(self) -> Dict[str, Optional[str]]:
        log = getattr(self.session, "log", None)
        path = getattr(log, "path", None)
        jsonl = getattr(log, "jsonl_path", None)
        return {"log_path": str(path) if path else None,
                "jsonl_path": str(jsonl) if jsonl else None}


class SessionStore(object):
    """Thread-safe map of :data:`Key` -> :class:`Entry` with idle expiry."""

    def __init__(self, *, home: Path, ca_dir: Path, idle_seconds: float = IDLE_SECONDS,
                 clock: Callable[[], float] = time.monotonic,
                 is_busy: Optional[Callable[[Key], bool]] = None,
                 on_create: Optional[Callable[[Any], None]] = None,
                 max_per_user: int = MAX_ENTRIES_PER_USER, max_history: int = MAX_HISTORY,
                 late_close_seconds: float = LATE_CLOSE_SECONDS,
                 late_close_poll: float = 0.2) -> None:
        self.home = Path(home)
        self.ca_dir = Path(ca_dir)
        self.idle_seconds = float(idle_seconds)
        self.clock = clock
        self.is_busy = is_busy
        self.on_create = on_create
        self.max_per_user = max(1, int(max_per_user))
        self.max_history = max(1, int(max_history))
        self.late_close_seconds = float(late_close_seconds)
        self.late_close_poll = float(late_close_poll)
        self._lock = threading.RLock()
        self._entries: Dict[Key, Entry] = {}
        # What survives a closed session (per key, bounded): log location and last error.
        self._history: "OrderedDict[Key, Dict[str, Any]]" = OrderedDict()

    # ------------------------------------------------------------------ lookup

    def _busy(self, key: Key) -> bool:
        try:
            return bool(self.is_busy and self.is_busy(key))
        except Exception:  # noqa: BLE001 - a broken probe must not expire a session
            return True

    def _in_use(self, entry: Entry) -> bool:
        """A running job, or an engine operation in progress (e.g. a slow login)."""
        return self._busy(entry.key) or session_busy(entry.session) is not None

    def _expired(self, entry: Entry, now: float) -> bool:
        return (now - entry.last_used) > self.idle_seconds and not self._in_use(entry)

    def _hist(self, key: Key) -> Dict[str, Any]:
        """The history record of ``key`` (created, moved to the end; caller holds the lock)."""
        rec = self._history.pop(key, None)
        if rec is None:
            rec = {}
        self._history[key] = rec
        while len(self._history) > self.max_history:
            self._history.popitem(last=False)
        return rec

    def get(self, key: Optional[Key], *, touch: bool = True) -> Optional[Entry]:
        if key is None:
            return None
        expired = None
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            now = self.clock()
            if self._expired(entry, now):
                expired = self._entries.pop(key)
            elif touch:
                entry.last_used = now
        if expired is not None:
            self._close(expired, reason="idle")
            return None
        return entry

    def _evict_for(self, user: str) -> List[Entry]:
        """Entries of ``user`` to close so a new one fits (least recently used idle ones;
        caller holds the lock)."""
        mine = sorted((e for k, e in self._entries.items() if k[0] == user),
                      key=lambda e: e.last_used)
        out: List[Entry] = []
        excess = len(mine) - self.max_per_user + 1
        for e in mine:
            if excess <= 0:
                break
            if self._in_use(e):
                continue
            self._entries.pop(e.key, None)
            out.append(e)
            excess -= 1
        return out

    def create(self, key: Key) -> Entry:
        """The existing entry for ``key``, or a new one with a fresh engine Session.
        Keeps at most ``max_per_user`` entries per user (closes the least recently used
        idle one)."""
        existing = self.get(key)
        if existing is not None:
            return existing
        self.home.mkdir(parents=True, exist_ok=True)
        sess = session_factory(home=self.home)
        entry = Entry(key, sess, self.clock())
        evicted: List[Entry] = []
        with self._lock:
            race = self._entries.get(key)
            if race is not None:
                new_entry = None
            else:
                evicted = self._evict_for(key[0])
                self._entries[key] = entry
                new_entry = entry
                self._hist(key).update(entry.log_paths())
        for old in evicted:
            self._close(old, reason="too many sessions for this user")
        if new_entry is None:
            # another request created it first; discard ours
            try:
                sess.close()
            except Exception:  # noqa: BLE001
                pass
            return race  # type: ignore[return-value]
        if self.on_create is not None:
            try:
                self.on_create(sess)
            except Exception as exc:  # noqa: BLE001 - settings are a convenience
                try:
                    sess.log.warn("web", "could not load saved keys from Settings",
                                  error=type(exc).__name__)
                except Exception:  # noqa: BLE001
                    pass
        return entry

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    # ------------------------------------------------------------------ errors / history

    def remember_error(self, key: Optional[Key], error: Optional[dict]) -> None:
        if key is None or not isinstance(error, dict):
            return
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None:
                entry.last_error = error
            self._hist(key)["last_error"] = error

    def history(self, key: Optional[Key]) -> Dict[str, Any]:
        if key is None:
            return {}
        with self._lock:
            return dict(self._history.get(key) or {})

    def history_count(self) -> int:
        with self._lock:
            return len(self._history)

    # ------------------------------------------------------------------ CA files

    def save_ca(self, entry: Entry, pem_text: str, kind: str = "mgmt") -> Path:
        """Validate and store a CA PEM for this entry (replacing the previous one, which is
        kept until the session closes). Raises :class:`SessionClosed` when the entry was
        closed meanwhile (the new file is removed again)."""
        pem = normalize_ca_pem(pem_text)
        path = _write_private(self.ca_dir, pem)
        with self._lock:
            if entry.closed:
                closed = True
            else:
                closed = False
                if kind == "outbound":
                    old, entry.outbound_ca = entry.outbound_ca, path
                else:
                    old, entry.mgmt_ca = entry.mgmt_ca, path
                if old is not None:
                    entry.retired.append(old)
        if closed:
            _remove(path)
            raise SessionClosed("The web session was closed")
        return path

    def restore_ca(self, entry: Entry, kind: str, previous: Optional[Path],
                   rejected: Optional[Path]) -> None:
        """Undo :meth:`save_ca` when the engine could not take the new file: ``previous``
        is the entry's CA again and ``rejected`` is retired (deleted when it closes)."""
        with self._lock:
            if entry.closed:
                _remove(rejected)
                return
            current = entry.outbound_ca if kind == "outbound" else entry.mgmt_ca
            if current != rejected:
                return          # replaced again meanwhile: leave it
            if previous is not None and previous in entry.retired:
                entry.retired.remove(previous)
            if kind == "outbound":
                entry.outbound_ca = previous
            else:
                entry.mgmt_ca = previous
            if rejected is not None:
                entry.retired.append(rejected)

    def clear_ca(self, entry: Entry, kind: str = "mgmt") -> None:
        """Stop using the CA of ``kind`` (the file is deleted when the session closes)."""
        with self._lock:
            if kind == "outbound":
                old, entry.outbound_ca = entry.outbound_ca, None
            else:
                old, entry.mgmt_ca = entry.mgmt_ca, None
            if old is not None:
                if entry.closed:
                    _remove(old)
                else:
                    entry.retired.append(old)

    def purge_ca_dir(self) -> int:
        """Delete CA files this console wrote that no open entry uses (left behind by a
        process that was killed). Returns how many were deleted."""
        try:
            names = [p for p in self.ca_dir.iterdir() if _CA_NAME_RE.match(p.name)]
        except OSError:
            return 0
        with self._lock:
            used = set()
            for e in self._entries.values():
                used.update(str(p) for p in [e.mgmt_ca, e.outbound_ca] + list(e.retired) if p)
        count = 0
        for path in names:
            if str(path) in used or not path.is_file():
                continue
            _remove(path)
            count += 1
        return count

    # ------------------------------------------------------------------ closing

    def _close(self, entry: Entry, reason: str, *, discard: bool = False) -> None:
        with self._lock:
            if entry.closed:
                return
            entry.closed = True
            files = [p for p in [entry.mgmt_ca, entry.outbound_ca] + list(entry.retired) if p]
            entry.mgmt_ca = None
            entry.outbound_ca = None
            entry.retired = []
            self._hist(entry.key).update(entry.log_paths())
        sess = entry.session
        busy = session_busy(sess)
        try:
            sess.log.info("web", "web session closed", reason=reason, busy=busy)
        except Exception:  # noqa: BLE001
            pass
        if busy and discard:
            # shutdown during an operation: drop what it has not published yet
            try:
                getattr(sess, "discard", lambda: False)()
            except Exception:  # noqa: BLE001 - best effort
                pass
        try:
            sess.close()
        except Exception:  # noqa: BLE001 - close never raises by contract
            pass
        if busy and not discard:
            # The operation still running may finish its login after close() gave up
            # waiting for it: close again (log out) once it ends, then delete the files.
            # (At shutdown there is no "later": the files go now.)
            watcher = threading.Thread(target=self._late_close, args=(sess, files),
                                       name="aiguard-web-late-close", daemon=True)
            watcher.start()
            return
        for path in files:
            _remove(path)

    def _late_close(self, sess: Any, files: List[Path]) -> None:
        deadline = time.monotonic() + self.late_close_seconds
        while session_busy(sess) is not None and time.monotonic() < deadline:
            time.sleep(self.late_close_poll)
        try:
            sess.close()
        except Exception:  # noqa: BLE001 - close never raises by contract
            pass
        for path in files:
            _remove(path)

    def drop(self, key: Optional[Key], reason: str = "disconnect") -> bool:
        if key is None:
            return False
        with self._lock:
            entry = self._entries.pop(key, None)
        if entry is None:
            return False
        self._close(entry, reason)
        return True

    def sweep(self) -> int:
        """Close idle entries; returns how many were closed."""
        now = self.clock()
        with self._lock:
            stale = [k for k, e in self._entries.items() if self._expired(e, now)]
            entries = [self._entries.pop(k) for k in stale]
        for entry in entries:
            self._close(entry, reason="idle")
        return len(entries)

    def keepalive_all(self) -> int:
        """Ask every idle engine Session to keep its Management API session alive
        (``Session.keepalive``: never blocks on a running operation). Returns how many
        sessions are alive."""
        with self._lock:
            sessions = [e.session for e in self._entries.values() if not e.closed]
        alive = 0
        for sess in sessions:
            keepalive = getattr(sess, "keepalive", None)
            if not callable(keepalive) or getattr(sess, "client", None) is None:
                continue
            try:
                alive += 1 if keepalive() else 0
            except Exception:  # noqa: BLE001 - a timer helper never raises
                pass
        return alive

    def busy_keys(self) -> List[Key]:
        """Keys whose engine Session is in the middle of an operation."""
        with self._lock:
            return [k for k, e in self._entries.items() if session_busy(e.session) is not None]

    def close_all(self, *, discard_busy: bool = False) -> None:
        """Close every entry (``discard_busy``: first discard the unpublished changes of a
        session that is still in the middle of an operation)."""
        with self._lock:
            entries = list(self._entries.values())
            self._entries.clear()
        for entry in entries:
            self._close(entry, reason="shutdown", discard=discard_busy)
