"""AiguardError hierarchy (spec 2.1).

Every failure shown to a user is an :class:`AiguardError` carrying five
user-facing fields, rendered the same way by the CLI and the web console:

* ``what``        one line: what failed
* ``server_said`` verbatim server text (redacted) when there is one
* ``why``         plain explanation
* ``fix``         ordered, concrete steps (SmartConsole paths, commands)
* ``state``       what changed / what is left

plus ``code`` (stable machine id), ``details`` (dict for the log) and
``log_line`` (set by :meth:`aiguard.runlog.RunLog.exception`).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import redact as _redact

__all__ = [
    "AiguardError",
    "MgmtApiError",
    "TlsTrustError",
    "ConnectError",
    "LakeraError",
    "PlanError",
    "ApprovalError",
]


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, dict)):
        return [value]
    try:
        return list(value)
    except TypeError:
        return [value]


def _opt_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    return value if isinstance(value, str) else str(value)


class AiguardError(Exception):
    """Base class. ``str(err)`` is ``err.what``."""

    default_code = "aiguard.error"

    def __init__(
        self,
        what: str,
        *,
        code: Optional[str] = None,
        server_said: Optional[str] = None,
        why: Optional[str] = None,
        fix: Optional[List[str]] = None,
        state: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> None:
        what = "" if what is None else str(what)
        super().__init__(what)
        self.what: str = what
        self.code: str = code or self.default_code
        self.server_said: Optional[str] = _opt_str(server_said)
        self.why: Optional[str] = _opt_str(why)
        self.fix: List[str] = [str(x) for x in _as_list(fix)]
        self.state: Optional[str] = _opt_str(state)
        self.details: Dict[str, Any] = dict(details) if details else {}
        self.log_line: Optional[int] = None

    def __str__(self) -> str:
        return self.what

    def __repr__(self) -> str:
        return "%s(code=%r, what=%r)" % (
            type(self).__name__, self.code, _redact.redact(self.what))

    def _extra(self) -> Dict[str, Any]:
        """Subclass-specific fields for :meth:`to_dict`."""
        return {}

    def to_dict(self) -> dict:
        """All fields, redacted, JSON-serialisable (for logs, web, reports)."""
        data: Dict[str, Any] = {
            "type": type(self).__name__,
            "code": self.code,
            "what": _redact.redact(self.what),
            "server_said": (_redact.redact(self.server_said)
                            if self.server_said is not None else None),
            "why": _redact.redact(self.why) if self.why is not None else None,
            "fix": [_redact.redact(x) for x in self.fix],
            "state": _redact.redact(self.state) if self.state is not None else None,
            "details": _redact.redact_obj(self.details),
            "log_line": self.log_line,
        }
        for key, value in self._extra().items():
            data[key] = _redact.redact_obj(value)
        return data


class MgmtApiError(AiguardError):
    """A Check Point Management API call failed."""

    default_code = "mgmt.error"

    def __init__(
        self,
        what: str,
        *,
        command: Optional[str] = None,
        http_status: Optional[int] = None,
        api_code: Optional[str] = None,
        errors: Optional[List[Any]] = None,
        warnings: Optional[List[Any]] = None,
        blocking_errors: Optional[List[Any]] = None,
        task_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(what, **kwargs)
        self.command: Optional[str] = command
        self.http_status: Optional[int] = http_status
        self.api_code: Optional[str] = api_code
        self.errors: List[Any] = _as_list(errors)
        self.warnings: List[Any] = _as_list(warnings)
        self.blocking_errors: List[Any] = _as_list(blocking_errors)
        self.task_id: Optional[str] = task_id

    def _extra(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "http_status": self.http_status,
            "api_code": self.api_code,
            "errors": self.errors,
            "warnings": self.warnings,
            "blocking_errors": self.blocking_errors,
            "task_id": self.task_id,
        }


class TlsTrustError(AiguardError):
    """Certificate verification failed or a CA file could not be used."""

    default_code = "tls.error"


class ConnectError(AiguardError):
    """TCP/DNS/timeout problems reaching a server."""

    default_code = "connect.error"


class LakeraError(AiguardError):
    """AI Agent Security / Lakera key or project problems."""

    default_code = "lakera.error"


class PlanError(AiguardError):
    """A change plan cannot be built or applied."""

    default_code = "plan.error"


class ApprovalError(AiguardError):
    """The approved plan id does not match the plan being applied."""

    default_code = "plan.approval"
