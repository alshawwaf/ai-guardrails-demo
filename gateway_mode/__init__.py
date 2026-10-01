"""Gateway Mode: the AI Guard Demo Kit web console (spec 9.2).

``init_gateway_mode(app, get_setting=..., record_log=...)`` registers the ``gateway``
blueprint at ``/gateway``. ``get_setting(key)`` returns a (decrypted) Settings value or
None; ``record_log(entry)`` adds a prompt result to the app's Logs / Dashboard.

Engine sessions are kept in memory per signed-in user and browser (see store.py), so
run the app with a single worker process when Gateway Mode is used. Run logs and the
rollback state go to ``AIGUARD_HOME`` when set, else ``<app root>/logs/aiguard``.

Sign-out (app.py ``end_gateway_session``) relies on this stable contract: the context is
``app.extensions["gateway_mode"]``; an engine session is keyed by ``owner = (str(user id),
session["gw_sid"])``; ``ctx.jobs.is_busy(owner)`` says whether a job of that owner runs and
``ctx.store.drop(owner, reason=...)`` closes its session (idempotent: False when there is
none). tests/test_gateway_web.py checks these names and signatures.

Shutdown: the sessions are logged out (and a running change gets a few seconds to finish,
then its unpublished part is discarded) by an ``atexit`` hook. ``docker stop`` sends
SIGTERM, which Python does not turn into an exit on its own (and PID 1 ignores by
default), so a SIGTERM handler that raises ``SystemExit`` is installed when nothing else
handles SIGTERM. CA files left behind by a process that was killed are deleted at start.
"""

from __future__ import annotations

import atexit
import os
import threading
from pathlib import Path
from typing import Any, Callable, Optional

__all__ = ["init_gateway_mode", "gateway_home", "install_sigterm_exit"]


def gateway_home(app: Any) -> Path:
    env = (os.environ.get("AIGUARD_HOME") or "").strip()
    if env:
        return Path(env).expanduser()
    return Path(app.root_path) / "logs" / "aiguard"


def install_sigterm_exit(signal_module: Any = None) -> bool:
    """Make SIGTERM raise ``SystemExit(143)`` so ``atexit`` hooks run. Only from the main
    thread and only when SIGTERM still has its default handler (a server such as gunicorn
    that handles it itself is left alone). Returns True when the handler was installed."""
    import signal as _signal

    sig = signal_module if signal_module is not None else _signal
    if threading.current_thread() is not threading.main_thread():
        return False
    term = getattr(sig, "SIGTERM", None)
    if term is None:
        return False
    try:
        current = sig.getsignal(term)
    except (ValueError, OSError):
        return False
    if current not in (sig.SIG_DFL, None):
        return False

    def _exit_on_sigterm(signum: int, frame: Any) -> None:
        raise SystemExit(128 + int(signum))

    try:
        sig.signal(term, _exit_on_sigterm)
    except (ValueError, OSError):
        return False
    return True


def init_gateway_mode(app: Any, get_setting: Optional[Callable[..., Any]] = None,
                      record_log: Optional[Callable[[dict], Any]] = None) -> Any:
    """Register the Gateway Mode blueprint on ``app`` (idempotent). Returns the context."""
    from .routes import EXT_KEY, GatewayContext, bp

    existing = app.extensions.get(EXT_KEY)
    if existing is not None:
        return existing
    ctx = GatewayContext(home=gateway_home(app),
                         ca_dir=Path(app.instance_path) / "aiguard" / "ca",
                         get_setting=get_setting, record_log=record_log)
    ctx.store.purge_ca_dir()          # left behind by a process that was killed
    app.extensions[EXT_KEY] = ctx
    app.register_blueprint(bp)
    ctx.start_reaper()
    atexit.register(ctx.shutdown)
    install_sigterm_exit()
    return ctx
