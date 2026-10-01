"""Background jobs for the Gateway Mode web console (spec 9.2).

Long operations (preflight, apply, rollback, guided scenes, the HTTPS Inspection fix)
run in one daemon thread per job. The browser polls ``GET /gateway/api/jobs/<id>``
every second and gets :meth:`Job.to_dict`::

    {"id", "kind", "status": "running"|"done"|"failed", "progress": 0..100, "message",
     "steps": [{"id", "title", "status", "pct", "message", "at"}], "result",
     "error": {what, server_said, why, fix[], state, code, log_line, log_path} | None,
     "log_line", "started_at", "finished_at", "elapsed_ms"}

A job function receives the :class:`Job`; ``job.progress_cb`` matches the engine's
``progress_cb(step_id, status, pct, message)``. It returns the (display-safe) result
dict, or raises :class:`JobFailure` (operation finished but did not succeed, e.g. an
ApplyResult with ``ok=False``) or an exception (converted to the five-field error).
Only one job per owner runs at a time.
"""

from __future__ import annotations

import datetime as _dt
import secrets
import threading
import time
from typing import Any, Callable, Dict, Hashable, List, Optional

from aiguard import redact as _redact
from aiguard.errors import AiguardError

__all__ = ["Job", "JobFailure", "JobBusyError", "JobRegistry", "error_dict"]

FINAL_STEP_STATES = frozenset({"done", "failed", "skipped", "manual", "pass", "fail", "warn",
                               "skip", "warning", "ok", "error"})


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def error_dict(exc: BaseException, *, log_path: Optional[str] = None) -> Dict[str, Any]:
    """Five-field error for the UI (what, server_said, why, fix, state + code, log line).

    Non-aiguard exceptions never expose their text (it could carry anything); the
    type name is enough to find the traceback in the log.
    """
    if isinstance(exc, AiguardError):
        data = exc.to_dict()
    else:
        data = AiguardError(
            "Unexpected error in the web console", code="web.internal",
            why="%s (details are in the log)" % type(exc).__name__,
            fix=["Open Logs and report, then send the log file to the demo owner"],
            state="The operation stopped. See the log for what was done before the error.",
        ).to_dict()
    if log_path and not data.get("log_path"):
        data["log_path"] = str(log_path)
    return data


class JobFailure(Exception):
    """The job ran to the end but failed (carries the five-field error and a result)."""

    def __init__(self, error: Dict[str, Any], result: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(str((error or {}).get("what") or "failed"))
        self.error = dict(error or {})
        self.result = result


class JobBusyError(AiguardError):
    default_code = "web.job_running"


class Job(object):
    def __init__(self, kind: str, owner: Hashable, *, steps: Optional[List[dict]] = None,
                 log_path: Optional[str] = None, label: str = "") -> None:
        self.id = secrets.token_hex(8)
        self.kind = kind
        self.owner = owner
        self.label = label or kind
        self.status = "running"
        self.progress = 0
        self.message = ""
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[Dict[str, Any]] = None
        self.log_line: Optional[int] = None
        self.log_path = log_path
        self.started_at = _now_iso()
        self.finished_at: Optional[str] = None
        self._t0 = time.monotonic()
        self._t1: Optional[float] = None
        self._lock = threading.Lock()
        self._steps: List[Dict[str, Any]] = []
        self._index: Dict[str, int] = {}
        for s in steps or []:
            sid = str(s.get("id"))
            self._index[sid] = len(self._steps)
            self._steps.append({"id": sid, "title": str(s.get("title") or sid),
                                "status": str(s.get("status") or "pending"),
                                "pct": None, "message": str(s.get("message") or ""),
                                "at": None})
        self.thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ progress

    def progress_cb(self, step_id: Any, status: Any, pct: Any = None, message: Any = "") -> None:
        """Engine-style callback: ``(step_id, status, pct, message)``."""
        self.update(step_id, status, pct, message)

    def preflight_cb(self, check_id: Any, status: Any, detail: Any = "") -> None:
        """Preflight-style callback: ``(check_id, status, detail)``."""
        self.update(check_id, status, None, detail)

    def update(self, step_id: Any, status: Any, pct: Any = None, message: Any = "") -> None:
        sid = str(step_id or "step")
        st = str(status or "running")
        msg = _redact.redact(str(message or ""))[:500]
        try:
            pct_v: Optional[int] = None if pct is None else max(0, min(100, int(pct)))
        except (TypeError, ValueError):
            pct_v = None
        with self._lock:
            idx = self._index.get(sid)
            if idx is None:
                self._index[sid] = len(self._steps)
                self._steps.append({"id": sid, "title": sid, "status": st, "pct": pct_v,
                                    "message": msg, "at": _now_iso()})
            else:
                step = self._steps[idx]
                step["status"] = st
                if pct_v is not None:
                    step["pct"] = pct_v
                if msg:
                    step["message"] = msg
                step["at"] = _now_iso()
            if msg:
                self.message = msg
            self._recompute()

    def _recompute(self) -> None:
        total = len(self._steps)
        if not total:
            return
        score = 0.0
        for s in self._steps:
            if s["status"] in FINAL_STEP_STATES:
                score += 1.0
            elif s["status"] == "running" and s.get("pct") is not None:
                score += s["pct"] / 100.0
        self.progress = max(self.progress, min(99, int(score * 100 / total)))

    def set_message(self, message: str) -> None:
        with self._lock:
            self.message = _redact.redact(str(message or ""))[:500]

    # ------------------------------------------------------------------ outcome

    def _finish(self, status: str, result: Optional[dict], error: Optional[dict]) -> None:
        with self._lock:
            self.status = status
            self.result = result
            self.error = error
            if error and error.get("log_line") is not None:
                self.log_line = error.get("log_line")
            if status == "done":
                self.progress = 100
            self._t1 = time.monotonic()
            self.finished_at = _now_iso()

    @property
    def running(self) -> bool:
        return self.status == "running"

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            end = self._t1 if self._t1 is not None else time.monotonic()
            data = {
                "id": self.id, "kind": self.kind, "label": self.label, "status": self.status,
                "progress": self.progress, "message": self.message,
                "steps": [dict(s) for s in self._steps],
                "result": self.result, "error": self.error, "log_line": self.log_line,
                "log_path": self.log_path, "started_at": self.started_at,
                "finished_at": self.finished_at, "elapsed_ms": int((end - self._t0) * 1000),
            }
        return _redact.redact_obj(data)


class JobRegistry(object):
    """All jobs of this process (bounded), at most one running job per owner."""

    def __init__(self, *, max_jobs: int = 200) -> None:
        self.max_jobs = int(max_jobs)
        self._lock = threading.Lock()
        self._jobs: Dict[str, Job] = {}
        self._order: List[str] = []

    def _prune(self) -> None:
        while len(self._order) > self.max_jobs:
            for jid in list(self._order):
                job = self._jobs.get(jid)
                if job is None or not job.running:
                    self._order.remove(jid)
                    self._jobs.pop(jid, None)
                    break
            else:
                return

    def running(self, owner: Hashable) -> Optional[Job]:
        with self._lock:
            for jid in reversed(self._order):
                job = self._jobs[jid]
                if job.owner == owner and job.running:
                    return job
        return None

    def is_busy(self, owner: Hashable) -> bool:
        return self.running(owner) is not None

    def any_running(self) -> bool:
        with self._lock:
            return any(j.running for j in self._jobs.values())

    def wait_all(self, timeout: float) -> bool:
        """Wait at most ``timeout`` seconds in total for every running job to finish
        (shutdown). True when none is left running."""
        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            with self._lock:
                threads = [j.thread for j in self._jobs.values()
                           if j.running and j.thread is not None]
            threads = [t for t in threads if t.is_alive()]
            if not threads:
                return True
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            threads[0].join(min(left, 0.5))

    def latest(self, owner: Hashable) -> Optional[Job]:
        with self._lock:
            for jid in reversed(self._order):
                job = self._jobs[jid]
                if job.owner == owner:
                    return job
        return None

    def get(self, job_id: str, owner: Hashable) -> Optional[Job]:
        with self._lock:
            job = self._jobs.get(str(job_id or ""))
        if job is None or job.owner != owner:
            return None
        return job

    def start(self, kind: str, owner: Hashable, fn: Callable[[Job], Optional[dict]], *,
              steps: Optional[List[dict]] = None, log_path: Optional[str] = None,
              label: str = "", on_error: Optional[Callable[[dict], None]] = None,
              on_done: Optional[Callable[[Job], None]] = None) -> Job:
        """Start ``fn(job)`` in a daemon thread. Raises :class:`JobBusyError` when this
        owner already has a running job."""
        with self._lock:
            for jid in self._order:
                other = self._jobs[jid]
                if other.owner == owner and other.running:
                    raise JobBusyError(
                        "Another operation is still running (%s)" % other.label,
                        why="The demo session runs one operation at a time.",
                        fix=["Wait for it to finish (its progress is shown on the page), "
                             "then try again"],
                        state="Nothing was started.", details={"job": other.id})
            job = Job(kind, owner, steps=steps, log_path=log_path, label=label)
            self._jobs[job.id] = job
            self._order.append(job.id)
            self._prune()

        def run() -> None:
            try:
                result = fn(job)
                job._finish("done", _redact.redact_obj(result) if result is not None else None,
                            None)
            except JobFailure as fail:
                err = dict(fail.error)
                if log_path and not err.get("log_path"):
                    err["log_path"] = log_path
                job._finish("failed", _redact.redact_obj(fail.result) if fail.result else None,
                            _redact.redact_obj(err))
            except Exception as exc:  # noqa: BLE001 - every failure becomes a five-field error
                job._finish("failed", None, error_dict(exc, log_path=log_path))
            if job.status == "failed" and on_error is not None and job.error:
                try:
                    on_error(job.error)
                except Exception:  # noqa: BLE001
                    pass
            if on_done is not None:
                try:
                    on_done(job)
                except Exception:  # noqa: BLE001
                    pass

        thread = threading.Thread(target=run, name="aiguard-job-%s-%s" % (kind, job.id),
                                  daemon=True)
        job.thread = thread
        thread.start()
        return job
