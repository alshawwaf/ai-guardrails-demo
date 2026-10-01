"""Persistent state (spec 4.5): rollback points + last-used connection.

``<home>/state.json``, written atomically (temp file + ``os.replace``), mode
0600. **No secrets, ever**: before anything is written, every key and value is
checked with :func:`aiguard.redact.redact` / :func:`aiguard.redact.redact_obj`;
if redaction would change anything the write is refused with ``ValueError``
and the file (and the in-memory view) is left as it was.

File shape::

    {"version": 1,
     "last": {"server": ..., "port": ..., "domain": ..., "gateway": ...,
              "ca_file": ..., "server_name": ..., "auth": "api-key"|"password",
              "user": ..., "updated_at": ...},
     "rollbacks": [{"id": "3fa9c1", "created_at": ..., "status": "recorded", ...}, ...]}

``list_rollbacks()`` returns points oldest first (append order);
``latest_rollback()`` picks the newest one that still has something to undo, optionally
for one server.

Writers serialise on the file: every ``State`` for the same path shares one in-process
lock, and each read-modify-write also holds an exclusive lock on ``<state.json>.lock``
(``fcntl.flock`` on POSIX, ``msvcrt.locking`` on Windows), so several web sessions and a
CLI sharing one home never lose each other's rollback points.
"""

from __future__ import annotations

import contextlib
import copy
import datetime as _dt
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

try:  # POSIX
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows
    _fcntl = None  # type: ignore[assignment]
try:  # Windows
    import msvcrt as _msvcrt
except ImportError:
    _msvcrt = None  # type: ignore[assignment]

from . import paths as _paths
from . import redact as _redact

__all__ = ["State", "check_secret_free", "STATE_VERSION", "DONE_STATUSES"]

STATE_VERSION = 1

#: Rollback points with these statuses have nothing left to undo.
DONE_STATUSES = ("rolled-back", "discarded")

_FILE_LOCK_TIMEOUT = 30.0


class _PathLock(object):
    """One per state file path in this process: a re-entrant thread lock plus, while a
    write is in progress, an exclusive OS lock on ``<path>.lock`` (other processes)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.rlock = threading.RLock()
        self._depth = 0
        self._fd: Optional[int] = None

    def _acquire_file(self) -> None:
        lock_path = self.path.with_name(self.path.name + ".lock")
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            return   # cannot lock (read-only folder ...): the write itself will report it
        deadline = time.monotonic() + _FILE_LOCK_TIMEOUT
        try:
            if _fcntl is not None:
                _fcntl.flock(fd, _fcntl.LOCK_EX)
            elif _msvcrt is not None:  # pragma: no cover - Windows
                while True:
                    try:
                        _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.05)
        except OSError:
            os.close(fd)
            return
        self._fd = fd

    def _release_file(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if _fcntl is not None:
                _fcntl.flock(fd, _fcntl.LOCK_UN)
            elif _msvcrt is not None:  # pragma: no cover - Windows
                try:
                    os.lseek(fd, 0, 0)
                    _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def write(self) -> Iterator[None]:
        with self.rlock:
            if self._depth == 0:
                self._acquire_file()
            self._depth += 1
            try:
                yield
            finally:
                self._depth -= 1
                if self._depth == 0:
                    self._release_file()


_PATH_LOCKS: Dict[str, _PathLock] = {}
_PATH_LOCKS_GUARD = threading.Lock()


def _lock_for(path: Path) -> _PathLock:
    key = os.path.normcase(os.path.abspath(str(path)))
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = _PATH_LOCKS[key] = _PathLock(path)
        return lock


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (_dt.datetime, _dt.date)):
        return value.isoformat()
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    raise TypeError("State cannot store %s values" % type(value).__name__)


def _normalize(value: Any) -> Any:
    """Plain JSON types only (Path -> str, tuple -> list ...)."""
    try:
        return json.loads(json.dumps(value, default=_default))
    except (TypeError, ValueError) as exc:
        raise ValueError("State only stores JSON data: %s" % exc) from None


def _where(path: List[str]) -> str:
    return "".join(path) or "<root>"


def check_secret_free(obj: Any, _path: Optional[List[str]] = None) -> None:
    """Raise ``ValueError`` if ``obj`` holds anything redaction would mask.

    The message names the location, never the value.
    """
    path = _path or []
    if isinstance(obj, dict):
        for key, value in obj.items():
            loc = path + ["[%s]" % json.dumps(_redact.redact(str(key)))]
            if isinstance(key, str) and _redact.redact(key) != key:
                raise ValueError("refusing to store a secret-looking key at %s"
                                 % _where(path))
            if _redact.is_sensitive_key(key) and _redact.redact_obj({key: value}) != {key: value}:
                raise ValueError(
                    "refusing to store a secret at %s: secrets are never written to disk"
                    % _where(loc))
            check_secret_free(value, loc)
        return
    if isinstance(obj, (list, tuple)):
        for i, value in enumerate(obj):
            check_secret_free(value, path + ["[%d]" % i])
        return
    if isinstance(obj, str) and _redact.redact(obj) != obj:
        raise ValueError("refusing to store a secret-looking value at %s: secrets are "
                         "never written to disk" % _where(path))


class State:
    """Read/modify/write access to ``state.json``.

    Each call re-reads the file, so a CLI and the web console sharing one home see each
    other's rollback points. Writes are serialised per file across ``State`` objects and
    processes (see the module docstring), so no update is lost.
    """

    def __init__(self, path: Optional[Union[str, Path]] = None) -> None:
        self.path: Path = Path(path).expanduser() if path is not None else _paths.state_path()
        self._path_lock = _lock_for(self.path)
        self._lock = self._path_lock.rlock   # shared by every State for this path

    # ------------------------------------------------------------------ file I/O

    @staticmethod
    def _empty() -> Dict[str, Any]:
        return {"version": STATE_VERSION, "last": {}, "rollbacks": []}

    def _load(self) -> Dict[str, Any]:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return self._empty()
        except (ValueError, UnicodeDecodeError):
            # Keep the unreadable file for inspection and start clean.
            aside = self.path.with_name(self.path.name + ".corrupt-" +
                                        _dt.datetime.now().strftime("%Y%m%d%H%M%S"))
            try:
                os.replace(str(self.path), str(aside))
            except OSError:
                pass
            return self._empty()
        if not isinstance(data, dict):
            return self._empty()
        data.setdefault("version", STATE_VERSION)
        if not isinstance(data.get("last"), dict):
            data["last"] = {}
        if not isinstance(data.get("rollbacks"), list):
            data["rollbacks"] = []
        data["rollbacks"] = [r for r in data["rollbacks"] if isinstance(r, dict)]
        return data

    def _save(self, data: Dict[str, Any]) -> None:
        data = _normalize(data)
        check_secret_free(data)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.path.with_name(".%s.%d.%s.tmp" % (self.path.name, os.getpid(),
                                                     secrets.token_hex(4)))
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(str(tmp), str(self.path))
        except BaseException:
            try:
                os.unlink(str(tmp))
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------ last used

    def last(self) -> dict:
        """Last-used connection settings (a copy; ``{}`` if none)."""
        with self._lock:
            return copy.deepcopy(self._load().get("last", {}))

    def set_last(self, **kwargs: Any) -> None:
        """Merge settings (server, port, domain, gateway, ca_file, server_name,
        auth, user, ...). ``None`` removes a key. Secret-looking keys or values
        raise ``ValueError`` and nothing is written."""
        with self._path_lock.write():
            data = self._load()
            last = dict(data.get("last") or {})
            for key, value in kwargs.items():
                if _redact.is_sensitive_key(key):
                    raise ValueError("refusing to store '%s' in state: secrets are never "
                                     "written to disk" % key)
                if value is None:
                    last.pop(key, None)
                else:
                    last[key] = _normalize(value)
            last["updated_at"] = _now()
            data["last"] = last
            self._save(data)

    # ------------------------------------------------------------------ rollbacks

    def add_rollback(self, point: dict) -> str:
        """Store a rollback point; returns its short id (6 hex characters).

        ``id`` is assigned here; ``created_at`` (UTC ISO) and ``status``
        (``"recorded"``) are added when missing.
        """
        if not isinstance(point, dict):
            raise TypeError("rollback point must be a dict")
        record = _normalize(point)
        with self._path_lock.write():
            data = self._load()
            used = {str(r.get("id")) for r in data["rollbacks"]}
            rid = secrets.token_hex(3)
            while rid in used:
                rid = secrets.token_hex(3)
            record["id"] = rid
            record.setdefault("created_at", _now())
            record.setdefault("status", "recorded")
            data["rollbacks"].append(record)
            self._save(data)
            return rid

    def get_rollback(self, rid: Any) -> Optional[dict]:
        """The rollback point with this id (a copy) or ``None``."""
        key = str(rid or "").strip().lower()
        if not key:
            return None
        with self._lock:
            for rec in self._load()["rollbacks"]:
                if str(rec.get("id", "")).lower() == key:
                    return copy.deepcopy(rec)
        return None

    def list_rollbacks(self) -> List[dict]:
        """All rollback points, oldest first (copies)."""
        with self._lock:
            return copy.deepcopy(self._load()["rollbacks"])

    def latest_rollback(self, server: Optional[str] = None, *,
                        include_done: bool = False,
                        domain: Optional[str] = None) -> Optional[dict]:
        """Newest rollback point (for ``server`` and, when given, ``domain``). Points with
        nothing left to undo (status ``"rolled-back"`` or ``"discarded"``) are skipped
        unless ``include_done``."""
        for rec in reversed(self.list_rollbacks()):
            if server is not None and rec.get("server") != server:
                continue
            if domain is not None and (rec.get("domain") or "").lower() not in (
                    "", str(domain).lower()):
                continue
            if not include_done and rec.get("status") in DONE_STATUSES:
                continue
            return rec
        return None

    def mark_rollback(self, rid: Any, **kw: Any) -> Optional[dict]:
        """Update fields of a rollback point (``id`` cannot change); adds
        ``updated_at``. Returns the updated copy, or ``None`` if there is no such
        point. Secret-looking values raise ``ValueError`` and nothing is written."""
        key = str(rid or "").strip().lower()
        with self._path_lock.write():
            data = self._load()
            for rec in data["rollbacks"]:
                if str(rec.get("id", "")).lower() == key and key:
                    for k, v in kw.items():
                        if k == "id":
                            continue
                        rec[k] = _normalize(v)
                    rec["updated_at"] = _now()
                    self._save(data)
                    return copy.deepcopy(rec)
        return None

    def mark_rollback_if(self, rid: Any, current_status: str, **kw: Any) -> Optional[dict]:
        """:meth:`mark_rollback`, but only while the point's status is still
        ``current_status`` (checked and written under one lock, so a status another thread
        or process just recorded is never overwritten). Returns the updated copy, or
        ``None`` when nothing was written."""
        key = str(rid or "").strip().lower()
        if not key:
            return None
        with self._path_lock.write():
            data = self._load()
            for rec in data["rollbacks"]:
                if str(rec.get("id", "")).lower() != key:
                    continue
                if rec.get("status") != current_status:
                    return None
                for k, v in kw.items():
                    if k != "id":
                        rec[k] = _normalize(v)
                rec["updated_at"] = _now()
                self._save(data)
                return copy.deepcopy(rec)
        return None

    # ------------------------------------------------------------------ misc

    def to_dict(self) -> dict:
        """The whole state (a copy)."""
        with self._lock:
            return copy.deepcopy(self._load())

    def __repr__(self) -> str:
        return "State(%s)" % self.path
