"""Data-driven policy templates (spec 4.1).

Built-in templates are JSON files next to this module (package data):

* ``ai-agent-security`` -- host object (optional), threat profile with AI Agent Security,
  threat rule, publish, install, optional content-moderation script;
* ``https-inspection`` -- turn on HTTPS Inspection on the gateway, optional inspect rule,
  publish, install (Access Control + Threat Prevention).

Optional per-step keys: ``min_api_version`` (the step becomes a "You do this" manual step
on an older Management API) and ``api_payload`` (``{"2": {...}}``: fields merged into the
payload when the server's API is at least that version).

The lab can adjust a template without code changes: a file
``<aiguard home>/templates/<id>.json`` (same format) overrides the built-in one with
that id. Template ids are restricted to ``[a-z0-9][a-z0-9_-]*`` so a name can never
point outside those two directories.

Files are read with :mod:`importlib.resources` (works from a source checkout, a wheel
or a zip) and fall back to the directory of this file. Every loaded template is
checked by :func:`validate_template`; problems raise
:class:`~aiguard.errors.PlanError` (code ``plan.template``).
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, List, Optional, Union

from .. import paths as _paths
from ..errors import PlanError

__all__ = [
    "load_template",
    "list_templates",
    "template_names",
    "validate_template",
    "STEP_KINDS",
    "WHEN_OPTIONS",
    "MARKER",
]

#: Text put in the ``comments`` of every object the kit creates; it is how the kit
#: recognises its own objects (update instead of conflict, safe rollback).
MARKER = "AI Guard Demo Kit"

STEP_KINDS = ("add", "set", "publish", "install", "script", "manual")
#: Boolean plan options a step's ``when`` may name (prefix ``!`` negates).
WHEN_OPTIONS = ("moderation", "install", "scope_is_client", "add_https_rule")

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SUFFIX = ".json"


def _err(what: str, *, why: Optional[str] = None, fix: Optional[List[str]] = None,
         details: Optional[dict] = None) -> PlanError:
    return PlanError(what, code="plan.template", why=why,
                     fix=fix or ["Check the template file (it is JSON; see the built-in templates "
                                 "in aiguard/templates for the format)"],
                     state="Nothing was changed.", details=details)


def _norm_name(name: Any) -> str:
    text = str(name or "").strip()
    if text.lower().endswith(_SUFFIX):
        text = text[: -len(_SUFFIX)]
    text = text.lower()
    if not _NAME_RE.match(text):
        raise _err("Unknown template name %r" % (str(name)[:80],),
                   why="Template names use lowercase letters, digits, '-' and '_' only.",
                   fix=["Use one of: %s" % ", ".join(template_names() or ["ai-agent-security"])])
    return text


# --------------------------------------------------------------------------- reading


def _builtin_names() -> List[str]:
    names: List[str] = []
    try:
        from importlib import resources
        files = getattr(resources, "files", None)
        if files is not None:
            for entry in files(__name__).iterdir():
                if entry.name.endswith(_SUFFIX):
                    names.append(entry.name[: -len(_SUFFIX)])
        else:  # Python 3.8
            for fname in resources.contents(__name__):
                if fname.endswith(_SUFFIX):
                    names.append(fname[: -len(_SUFFIX)])
    except (ImportError, OSError, TypeError, AttributeError, ValueError):
        names = []
    if not names:
        here = Path(__file__).resolve().parent
        names = [p.stem for p in here.glob("*" + _SUFFIX)]
    return sorted(n for n in set(names) if _NAME_RE.match(n))


def _read_builtin(name: str) -> Optional[str]:
    fname = name + _SUFFIX
    try:
        from importlib import resources
        files = getattr(resources, "files", None)
        if files is not None:
            return files(__name__).joinpath(fname).read_text(encoding="utf-8")
        return resources.read_text(__name__, fname, encoding="utf-8")  # Python 3.8
    except FileNotFoundError:
        pass
    except (ImportError, OSError, TypeError, AttributeError, ValueError):
        pass
    path = Path(__file__).resolve().parent / fname
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def _override_dir(home: Optional[Union[str, Path]]) -> Path:
    return _paths.aiguard_home(home) / "templates"


def _read_override(name: str, home: Optional[Union[str, Path]]) -> Optional[str]:
    path = _override_dir(home) / (name + _SUFFIX)
    try:
        if path.is_file():
            return path.read_text(encoding="utf-8")
    except OSError:
        return None
    return None


def template_names(home: Optional[Union[str, Path]] = None) -> List[str]:
    """Ids of the built-in templates plus any lab overrides in ``<home>/templates``."""
    names = set(_builtin_names())
    try:
        d = _override_dir(home)
        if d.is_dir():
            names.update(p.stem for p in d.glob("*" + _SUFFIX) if _NAME_RE.match(p.stem))
    except OSError:
        pass
    return sorted(names)


def load_template(name: str, *, home: Optional[Union[str, Path]] = None) -> dict:
    """The template with id ``name`` (a fresh copy, validated).

    ``<home>/templates/<name>.json`` wins over the built-in file. The returned dict has
    an extra ``"_source"`` key: ``"builtin"`` or the override path.
    """
    key = _norm_name(name)
    source = "builtin"
    text = _read_override(key, home)
    if text is not None:
        source = str(_override_dir(home) / (key + _SUFFIX))
    else:
        text = _read_builtin(key)
    if text is None:
        raise _err("Unknown template '%s'" % key,
                   why="There is no built-in template with that name.",
                   fix=["Use one of: %s" % ", ".join(template_names(home) or ["ai-agent-security"])])
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise _err("Template '%s' is not valid JSON" % key, why=str(exc),
                   details={"source": source}) from None
    validate_template(data, expected_id=key)
    data = copy.deepcopy(data)
    data["_source"] = source
    return data


def list_templates(home: Optional[Union[str, Path]] = None) -> List[dict]:
    """``[{"id", "title", "min_api_version", "min_gateway_version", "steps": [ids], "source"}]``.

    Templates that fail to load are listed with an ``"error"`` instead of being hidden.
    """
    out: List[dict] = []
    for name in template_names(home):
        try:
            t = load_template(name, home=home)
        except PlanError as exc:
            out.append({"id": name, "title": None, "error": exc.what})
            continue
        out.append({
            "id": t["id"], "title": t.get("title") or t["id"],
            "min_api_version": t.get("min_api_version"),
            "min_gateway_version": t.get("min_gateway_version"),
            "steps": [s["id"] for s in t["steps"]],
            "source": t["_source"],
        })
    return out


# --------------------------------------------------------------------------- validation


def _check_call(where: str, value: Any, *, need_payload: bool = True) -> None:
    if not isinstance(value, dict):
        raise _err("Template %s must be an object" % where)
    if not isinstance(value.get("command"), str) or not value["command"].strip():
        raise _err("Template %s needs a 'command'" % where)
    if need_payload and not isinstance(value.get("payload", {}), dict):
        raise _err("Template %s 'payload' must be an object" % where)


def _check_strings(where: str, value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise _err("Template %s must be a list of strings" % where)


def validate_template(tpl: Any, *, expected_id: Optional[str] = None) -> None:
    """Raise :class:`PlanError` when ``tpl`` does not follow the template format.

    Checks: ids, step kinds, required fields per kind, ``when`` option names, and the
    apply order the rollback logic relies on (changes -> publish -> install -> scripts).
    """
    if not isinstance(tpl, dict):
        raise _err("A template must be a JSON object")
    tid = tpl.get("id")
    if not isinstance(tid, str) or not _NAME_RE.match(tid):
        raise _err("Template 'id' must be a lowercase name")
    if expected_id is not None and tid != expected_id:
        raise _err("Template file %s.json has id '%s'" % (expected_id, tid),
                   why="The file name and the 'id' inside must match.")
    if not isinstance(tpl.get("variables", {}), dict):
        raise _err("Template 'variables' must be an object")
    fv = tpl.get("field_variants")
    if fv is not None:
        if not isinstance(fv, dict) or not fv:
            raise _err("Template 'field_variants' must be a non-empty object")
        for vname, variant in fv.items():
            if not isinstance(variant, dict) or not isinstance(variant.get("detect_command"), str):
                raise _err("Field variant '%s' needs a 'detect_command'" % vname)
    _check_strings("'checks'", tpl.get("checks"))
    steps = tpl.get("steps")
    if not isinstance(steps, list) or not steps:
        raise _err("Template 'steps' must be a non-empty list")
    seen = set()
    phase = 0  # 0 changes, 1 published, 2 installed
    publishes = 0
    for i, step in enumerate(steps):
        where = "step %d" % (i + 1)
        if not isinstance(step, dict):
            raise _err("Template %s must be an object" % where)
        sid = step.get("id")
        if not isinstance(sid, str) or not sid.strip():
            raise _err("Template %s needs an 'id'" % where)
        if sid in seen:
            raise _err("Template step id '%s' is used twice" % sid)
        seen.add(sid)
        where = "step '%s'" % sid
        kind = step.get("kind")
        if kind not in STEP_KINDS:
            raise _err("Template %s has an unknown kind %r" % (where, kind),
                       why="Valid kinds: %s" % ", ".join(STEP_KINDS))
        when = step.get("when")
        if when is not None:
            items = when if isinstance(when, list) else [when]
            for w in items:
                if not isinstance(w, str) or w.lstrip("!") not in WHEN_OPTIONS:
                    raise _err("Template %s has an unknown 'when' %r" % (where, w),
                               why="Valid options: %s" % ", ".join(WHEN_OPTIONS))
        for key in ("manual_steps", "conflict_fix"):
            _check_strings("%s '%s'" % (where, key), step.get(key))
        mav = step.get("min_api_version")
        if mav is not None and (not isinstance(mav, str) or not re.match(r"^\d+(\.\d+)*$", mav)):
            raise _err("Template %s 'min_api_version' must be a version text like \"2\"" % where)
        ap = step.get("api_payload")
        if ap is not None:
            if not isinstance(ap, dict) or not all(
                    isinstance(k, str) and re.match(r"^\d+(\.\d+)*$", k) and isinstance(v, dict)
                    for k, v in ap.items()):
                raise _err("Template %s 'api_payload' must map API versions to objects" % where,
                           why="Fields in api_payload are added to the payload when the server's "
                               "Management API is at least that version.")
        if kind in ("add", "set", "script"):
            _check_call(where, step)
        if step.get("exists") is not None:
            _check_call("%s 'exists'" % where, step["exists"])
        if step.get("rollback") is not None:
            _check_call("%s 'rollback'" % where, step["rollback"])
            _check_strings("%s rollback 'manual_steps'" % where, step["rollback"].get("manual_steps"))
        if kind == "add" and step.get("exists") is None:
            raise _err("Template %s (kind add) needs an 'exists' probe" % where,
                       why="The kit checks for an object with the same name before creating one.")
        if kind in ("add", "set", "manual"):
            if phase != 0:
                raise _err("Template %s must come before the publish step" % where)
        elif kind == "publish":
            publishes += 1
            if phase != 0:
                raise _err("Template has more than one publish step")
            phase = 1
        elif kind == "install":
            if phase != 1:
                raise _err("Template %s must come right after publish" % where)
            phase = 2
        elif kind == "script":
            if phase == 0:
                raise _err("Template %s (script) must come after publish" % where,
                           why="Scripts change the gateway immediately; they cannot be discarded "
                               "with the session, so they run only after the changes are published.")
    if publishes != 1:
        raise _err("Template needs exactly one publish step")
