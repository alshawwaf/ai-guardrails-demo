"""Run log (spec 2.3): one human-readable ``.log`` and one ``.jsonl`` per run.

Human line format::

    HH:MM:SS.mmm LEVEL  component msg k=v k=v
    <30 spaces>continuation of a multi-line value

The first line of every log is::

    <ISO datetime> INFO   session   start host=<hostname> user=<login> ver=<version> os=<platform>

Each :meth:`RunLog.event` returns the 1-based line number of its first human
line, so errors can say "Details: log line N". Everything written passes
:func:`aiguard.redact.redact` / :func:`aiguard.redact.redact_obj`.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import getpass
import json
import os
import platform
import socket
import threading
import traceback
from pathlib import Path
from typing import IO, Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from . import __version__
from . import paths as _paths
from . import redact as _redact

__all__ = ["RunLog", "latest_log", "LEVELS"]

LEVELS = ("DEBUG", "INFO", "WARN", "ERROR", "HINT")
_LEVEL_ALIASES = {"WARNING": "WARN", "ERR": "ERROR", "CRITICAL": "ERROR", "FATAL": "ERROR"}

_INDENT = " " * 30  # = len("HH:MM:SS.mmm ") + 5 + 2 + 9 + 1

# Every line break becomes a continuation line (so text from a server can never
# forge a log line); other control characters (ANSI escapes ...) are replaced.
_LINE_SAFE = {c: "\ufffd" for c in list(range(0x00, 0x20)) + [0x7F] if c not in (0x09, 0x0A)}
_LINE_SAFE.update({0x0D: "\n", 0x0B: "\n", 0x0C: "\n", 0x85: "\n", 0x2028: "\n",
                   0x2029: "\n", 0x1C: "\n", 0x1D: "\n", 0x1E: "\n"})


def _norm_level(level: Any) -> str:
    text = str(level or "INFO").strip().upper()
    return _LEVEL_ALIASES.get(text, text)


def _jsonable(value: Any, _depth: int = 0) -> Any:
    """Convert arbitrary field values into JSON types (before redaction)."""
    if _depth > 50:
        return "..."
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _jsonable(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, _depth + 1) for v in value]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        try:
            return _jsonable(dataclasses.asdict(value), _depth + 1)
        except Exception:  # noqa: BLE001
            pass
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            return _jsonable(to_dict(), _depth + 1)
        except Exception:  # noqa: BLE001
            pass
    if isinstance(value, BaseException):
        return "%s: %s" % (type(value).__name__, value)
    return str(value)


def _format_value(key: str, value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if key == "fix" and isinstance(value, list) and value:
        return "\n".join("%d. %s" % (i, item) for i, item in enumerate(value, 1))
    if isinstance(value, str):
        text = value.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
        if "\n" in text:
            return text
        if text == "" or any(ch.isspace() for ch in text) or '"' in text or "=" in text:
            return json.dumps(text, ensure_ascii=False)
        return text
    return json.dumps(value, ensure_ascii=False, sort_keys=False, default=str)


def _login_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no USER/LOGNAME/pwd entry
        return "unknown"


def _hostname() -> str:
    try:
        return socket.gethostname() or "unknown"
    except OSError:
        return "unknown"


def _create_exclusive(path: Path) -> IO[str]:
    """Create a new file (fails if it exists), owner read/write only."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8", newline="\n")


class RunLog:
    """Thread-safe run log writing ``<home>/logs/<YYYY-MM-DD_HHMMSS>[_n].log``
    plus a ``.jsonl`` twin with the same stem.

    ``prefix`` is only added to the file name when it is not the default
    (``"aiguard"``), e.g. ``prefix="web"`` -> ``web_2026-09-30_101500.log``.
    ``echo(level, text)`` is called after each event (never inside the lock;
    exceptions from it are swallowed).
    """

    def __init__(
        self,
        home: Optional[Union[str, Path]] = None,
        prefix: str = "aiguard",
        echo: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.home: Path = _paths.aiguard_home(home)
        self.prefix = prefix or "aiguard"
        self.echo = echo
        self._lock = threading.Lock()
        self._line = 0
        self._closed = False
        logs = _paths.logs_dir(self.home)
        self.path, self.jsonl_path, self._fh, self._jh = self._open_new(logs)
        self._write_event(
            "INFO", "session", "start",
            {"host": _hostname(), "user": _login_user(), "ver": __version__,
             "os": platform.platform()},
            first=True,
        )

    # ------------------------------------------------------------------ files

    def _open_new(self, logs: Path) -> Tuple[Path, Path, IO[str], IO[str]]:
        stamp = _dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        base = stamp if self.prefix == "aiguard" else "%s_%s" % (self.prefix, stamp)
        n = 1
        while True:
            stem = base if n == 1 else "%s_%d" % (base, n)
            log_path = logs / (stem + ".log")
            jsonl_path = logs / (stem + ".jsonl")
            n += 1
            if log_path.exists() or jsonl_path.exists():
                continue
            try:
                fh = _create_exclusive(log_path)
            except FileExistsError:
                continue
            try:
                jh = _create_exclusive(jsonl_path)
            except FileExistsError:
                fh.close()
                try:
                    log_path.unlink()
                except OSError:
                    pass
                continue
            return log_path, jsonl_path, fh, jh

    def _ensure_open(self) -> None:
        # Events after close() are still recorded (append mode) rather than lost;
        # a later close() closes the reopened files again.
        if self._fh is None or self._fh.closed:
            self._fh = open(self.path, "a", encoding="utf-8", newline="\n")
            self._closed = False
        if self._jh is None or self._jh.closed:
            self._jh = open(self.jsonl_path, "a", encoding="utf-8", newline="\n")
            self._closed = False

    # ------------------------------------------------------------------ writing

    def _write_event(self, level: str, component: str, msg: Any,
                     fields: Dict[str, Any], first: bool = False) -> int:
        level = _norm_level(level)
        component = str(component or "-")
        now = _dt.datetime.now().astimezone()
        safe_msg = _redact.redact(msg)
        safe_fields = _redact.redact_obj(_jsonable(fields or {}))
        if not isinstance(safe_fields, dict):  # pragma: no cover - defensive
            safe_fields = {"fields": safe_fields}

        # Single-line fields first, multi-line ones after them (each starting
        # on its own continuation line after the first), so continuation lines
        # never mix a multi-line value with the next k=v.
        single: List[str] = [safe_msg] if safe_msg else []
        multi: List[str] = []
        for key, value in safe_fields.items():
            if not first and (value is None or value == {} or value == []):
                continue  # still in the .jsonl record
            part = "%s=%s" % (key, _format_value(key, value))
            (multi if "\n" in part else single).append(part)
        body = " ".join(single)
        for part in multi:
            body = (body + ("\n" if "\n" in body else " ") + part) if body else part
        body = _redact.redact(body).replace("\r\n", "\n").translate(_LINE_SAFE)
        body_lines = body.split("\n")

        if first:
            stamp = now.isoformat(timespec="seconds")
        else:
            stamp = now.strftime("%H:%M:%S.") + "%03d" % (now.microsecond // 1000)
        header = "%s %-5s  %-9s " % (stamp, level, component)
        lines = [(header + body_lines[0]).rstrip()]
        lines.extend((_INDENT + extra).rstrip() for extra in body_lines[1:])
        text = "\n".join(lines)

        with self._lock:
            self._ensure_open()
            line_no = self._line + 1
            record = {
                "ts": now.isoformat(timespec="milliseconds"),
                "level": level,
                "component": component,
                "msg": safe_msg,
                "fields": safe_fields,
                "line": line_no,
            }
            self._fh.write(text + "\n")
            self._fh.flush()
            self._jh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            self._jh.flush()
            self._line += len(lines)

        echo = self.echo
        if echo is not None:
            try:
                echo(level, text)
            except Exception:  # noqa: BLE001 - a broken UI callback must not break logging
                pass
        return line_no

    def event(self, level: str, component: str, msg: str, **fields: Any) -> int:
        """Write one event; returns the 1-based line number in :attr:`path`."""
        return self._write_event(level, component, msg, fields)

    def debug(self, component: str, msg: str, **fields: Any) -> int:
        return self._write_event("DEBUG", component, msg, fields)

    def info(self, component: str, msg: str, **fields: Any) -> int:
        return self._write_event("INFO", component, msg, fields)

    def warn(self, component: str, msg: str, **fields: Any) -> int:
        return self._write_event("WARN", component, msg, fields)

    warning = warn

    def error(self, component: str, msg: str, **fields: Any) -> int:
        return self._write_event("ERROR", component, msg, fields)

    def hint(self, component: str, msg: str, **fields: Any) -> int:
        return self._write_event("HINT", component, msg, fields)

    def exception(self, err: BaseException, component: str) -> int:
        """Log an error with all its fields at ERROR; sets ``err.log_line``.

        Accepts any exception: non-Aiguard exceptions are logged with their
        type and traceback.
        """
        to_dict = getattr(err, "to_dict", None)
        if callable(to_dict):
            data = dict(to_dict())
            what = data.pop("what", str(err))
            data.pop("log_line", None)
            cause = err.__cause__ or err.__context__
            if cause is not None and "cause" not in data:
                data["cause"] = "%s: %s" % (type(cause).__name__, cause)
            order = ("code", "command", "http_status", "api_code", "task_id", "server_said",
                     "why", "state", "fix")
            ordered = {k: data.pop(k) for k in order if k in data}
            ordered.update(data)
            data = ordered
        else:
            what = "%s: %s" % (type(err).__name__, err)
            data = {"type": type(err).__name__}
            if err.__traceback__ is not None:
                data["traceback"] = "".join(
                    traceback.format_exception(type(err), err, err.__traceback__)).rstrip()
        line = self._write_event("ERROR", component, what, data)
        try:
            setattr(err, "log_line", line)
        except Exception:  # noqa: BLE001 - exceptions with __slots__
            pass
        return line

    # ------------------------------------------------------------------ reading

    @property
    def lines(self) -> int:
        """Number of human lines written so far."""
        return self._line

    @property
    def closed(self) -> bool:
        return self._closed

    def tail(self, n: int = 200, level: Optional[Union[str, Sequence[str]]] = None,
             component: Optional[Union[str, Sequence[str]]] = None) -> List[dict]:
        """Last ``n`` structured records, optionally filtered.

        ``level`` / ``component`` match exactly (case-insensitive); each may be
        a list or a comma-separated string (``"WARN,ERROR"``).
        """
        if n is None or n <= 0:
            return []
        levels = _filter_set(level, upper=True)
        comps = _filter_set(component, upper=False)
        with self._lock:
            if self._jh is not None and not self._jh.closed:
                self._jh.flush()
            try:
                with open(self.jsonl_path, "r", encoding="utf-8") as f:
                    raw_lines = f.readlines()
            except OSError:
                return []
        out: List[dict] = []
        for raw in raw_lines:
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            if levels and _norm_level(rec.get("level")) not in levels:
                continue
            if comps and str(rec.get("component", "")).lower() not in comps:
                continue
            out.append(rec)
        return out[-n:]

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        """Write ``session end`` and close the files. Idempotent."""
        if self._closed:
            return
        try:
            self._write_event("INFO", "session", "end", {"lines": self._line + 1})
        finally:
            with self._lock:
                self._closed = True
                for fh in (self._fh, self._jh):
                    try:
                        if fh is not None:
                            fh.close()
                    except OSError:
                        pass

    def __enter__(self) -> "RunLog":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return "RunLog(%s)" % self.path


def _filter_set(value: Optional[Union[str, Sequence[str]]], *, upper: bool) -> set:
    if value is None:
        return set()
    items = value.split(",") if isinstance(value, str) else list(value)
    out = set()
    for item in items:
        text = str(item).strip()
        if not text:
            continue
        out.add(_norm_level(text) if upper else text.lower())
    return out


def latest_log(home: Optional[Union[str, Path]] = None) -> Optional[Path]:
    """Most recent human log in ``<home>/logs`` (``None`` if there is none)."""
    logs = _paths.logs_dir(home, create=False)
    try:
        candidates = [p for p in logs.glob("*.log") if p.is_file()]
    except OSError:
        return None
    if not candidates:
        return None

    def key(p: Path) -> Tuple[float, str]:
        try:
            return (p.stat().st_mtime, p.name)
        except OSError:
            return (0.0, p.name)

    return max(candidates, key=key)
