"""Web console wording for engine text (spec 9.2).

The shared engine words its fix steps for the CLI ("aiguard rollback 1a2b3c",
"--ca-file <file.pem>", "aiguard setup --moderation"). The web console has buttons and
fields for the same things, so every JSON response of the console passes through
:func:`webify`:

* user-facing text fields (``fix``, ``why``, ``state``, ``message``, ``detail``,
  ``diagnosis``, ``reasons``, ``warnings``, ``note``, ...) are rewritten to name the
  console's own fields and buttons (:func:`web_text`, one ordered rule list, unanchored);
* every five-field error dict gets ``actions``: machine-readable buttons the page renders
  (:func:`web_actions`), taken from the engine's ``details.action`` when it gives one and
  otherwise recognised from the CLI wording (rollback, HTTPS Inspection fix, outbound CA).

``server_said``, prompts, payloads and log records are never rewritten.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Pattern, Sequence, Tuple, Union

__all__ = ["web_text", "web_fix", "web_actions", "webify", "action_id", "check_action",
           "TEXT_KEYS"]

# Keys whose string (or list of strings) values are rewritten wherever they appear.
TEXT_KEYS = frozenset({
    "why", "fix", "state", "message", "detail", "diagnosis", "reasons", "warnings", "note",
    "after", "manual_steps",
})
_ROLLBACK_ID = r"[0-9a-fA-F]{4,32}"   # state.add_rollback ids: 6 hex characters
_MGMT_CA = '"Management CA certificate (PEM)" on Connect'
_OUTBOUND = '"Export outbound CA" on Preflight (or paste the outbound CA there)'

Replacement = Union[str, Callable[["re.Match[str]"], str]]

_RULE_SOURCE: Sequence[Tuple[str, Replacement]] = (
    # ---- "CLI: ...; web console: ..." -> the web half only
    (r"^CLI:[^;]*;\s*[Ww]eb\s+console:\s*", ""),
    (r"^Web console:\s*", ""),
    # inside a sentence: "(web console: X; CLI: Y)" / "(CLI: Y; web console: X)" -> "(X)"
    (r"\([Ww]eb console:\s*([^;()]*?);\s*CLI:[^()]*\)", r"(\1)"),
    (r"\(CLI:[^;()]*;\s*[Ww]eb console:\s*([^()]*)\)", r"(\1)"),
    (r"Connect again: aiguard setup \(web console: Connect\)", "Connect again (Connect page)"),
    # ---- rollback
    (r"Pass the id shown after apply: aiguard rollback <id>",
     'Pick the rollback point under "Rollback points on this server" (Approve and install)'),
    (r"aiguard rollback without an id undoes the latest change on this server",
     "Approve and install lists the rollback points of this server"),
    (r"\b[Rr]un aiguard rollback (%s)\b again" % _ROLLBACK_ID,
     lambda m: '%sress "Roll back %s" on Approve and install again'
     % ("P" if m.group(0)[0] == "R" else "p", m.group(1))),
    (r"aiguard rollback (%s)\b" % _ROLLBACK_ID, r'the "Roll back \1" button on Approve and install'),
    (r"aiguard rollback <id>", "the Roll back button on Approve and install"),
    # ---- HTTPS Inspection fix (the --add-rule forms first: the generic rule below would
    # leave '"Turn on for me" on Preflight --add-rule ...')
    (r"aiguard fix https-inspection --add-rule\s*\(asks for approval([^)]*)\)",
     lambda m: 'Press "Add the Inspect rule for me" on Preflight (asks for approval%s)'
     % m.group(1).replace("this computer", "this server")),
    (r"aiguard fix https-inspection --add-rule",
     '"Add the Inspect rule for me" on Preflight'),
    (r"aiguard fix https-inspection\s*\(asks for approval([^)]*)\)",
     r'Press "Turn on for me" on Preflight (asks for approval\1)'),
    (r"\(aiguard fix https-inspection\)", '(press "Turn on for me" on Preflight)'),
    (r"\brun aiguard fix https-inspection again", 'press "Turn on for me" on Preflight again'),
    (r"aiguard fix https-inspection", '"Turn on for me" on Preflight'),
    # ---- outbound CA (trust-ca)
    (r"aiguard trust-ca\s*\(shows how to trust it\)",
     'Press "Export outbound CA" on Preflight so the demo traffic trusts it (or paste the PEM '
     'there)'),
    (r"\(aiguard trust-ca shows how\)", "(the outbound CA panel on Preflight shows how)"),
    (r"\brun aiguard trust-ca again", 'press "Export outbound CA" on Preflight again'),
    (r"`?aiguard trust-ca`? shows the commands", "the outbound CA panel on Preflight shows how"),
    (r"`?aiguard trust-ca`?", "the outbound CA panel on Preflight"),
    (r"\bOr pass --(?:ca-file|outbound-ca) <outbound-ca\.pem>", "Or press " + _OUTBOUND),
    (r"\bor pass --(?:ca-file|outbound-ca) <outbound-ca\.pem>", "or press " + _OUTBOUND),
    (r"--(?:ca-file|outbound-ca) <outbound-ca\.pem>", _OUTBOUND),
    (r"--outbound-ca <[^<>]*>", _OUTBOUND),
    (r"--outbound-ca\b", "the outbound CA panel on Preflight"),
    # ---- management CA / certificate name (Connect > Certificate trust)
    (r"Pass it with --ca-file <file\.pem> \(web console: paste the PEM text\)",
     "Paste it in %s (Certificate trust)" % _MGMT_CA),
    (r"and add --server-name <name in the certificate> --ca-file <file\.pem>",
     'and enter that name in "Name in the certificate" on Connect, with the CA in '
     '"Management CA certificate (PEM)"'),
    (r"\bUse\s+--server-name <name in the certificate>",
     'Enter the name from the certificate in "Name in the certificate" on Connect'),
    (r"\badd --server-name <name in the certificate>",
     'enter the name from the certificate in "Name in the certificate" on Connect'),
    (r"--server-name <name in the certificate>", '"Name in the certificate" on Connect'),
    (r"Step 2 export\) and pass --ca-file <file\.pem>",
     "Step 2 export) and give it to the console again (management CA: Connect; outbound CA: "
     "Preflight)"),
    (r"export the ICA certificate for --ca-file",
     "export the ICA certificate and paste it in " + _MGMT_CA),
    (r"[Pp]ass the PEM file itself: --ca-file \S+", "Upload the PEM file itself"),
    (r"--ca-file must point to a PEM file with the certificate\(s\) to trust\.",
     "The CA must be a PEM file with the certificate(s) to trust."),
    (r"--ca-file takes one PEM file, not a directory\.", "The CA must be one PEM file."),
    (r"\bpass --ca-file <file\.pem>", "paste it in " + _MGMT_CA),
    (r"\bPass --ca-file <file\.pem>", "Paste it in " + _MGMT_CA),
    (r"--ca-file <file\.pem>", _MGMT_CA),
    (r"even with --ca-file", "even with the right CA"),
    (r"--ca-file", "the CA certificate field"),
    # ---- content moderation
    (r"\(aiguard setup --moderation\)",
     "(Configure > Content moderation, then approve and install the plan)"),
    (r"aiguard setup --moderation", "Configure > Content moderation"),
    # ---- versions
    (r"Check the management version with `aiguard status`",
     "Check the management version shown on Connect after you connect"),
    (r"Check the version with: aiguard status \(or api status on the management server\)",
     "Check the version shown on Connect (or run api status on the management server)"),
    (r"\(or aiguard status\)", "(or see the version on Connect)"),
    (r"`aiguard status`|\baiguard status\b", "the Connect page"),
    # ---- protected scope (Configure)
    (r"Or choose another scope: --scope any, or --scope <existing object name>",
     'Or pick another "Protected scope" on Configure: Any, or an existing network object'),
    (r"Or use --scope client \(only this computer\) or --scope any",
     'Or pick another "Protected scope" on Configure: This server only, or Any'),
    (r"\bor use --scope any", 'or pick "Protected scope" Any on Configure'),
    (r"--scope <(?:existing )?object name>\s*\(or --scope any\)",
     '"Protected scope" on Configure: an existing network object (or Any)'),
    (r"--scope <(?:existing )?object name>",
     '"Protected scope" on Configure: an existing network object'),
    (r"--scope any", '"Protected scope" Any on Configure'),
    (r"--scope client", '"Protected scope" This server only on Configure'),
    # ---- policy package
    (r"Choose the package: --package <name>",
     'Choose the package: type its name in "Policy package" (Preflight or Configure)'),
    (r"Then pass --package <name>", 'Then type it in "Policy package" (Preflight or Configure)'),
    (r"--package <name>", '"Policy package" (Preflight or Configure)'),
    # ---- names
    (r"Pick another name with --profile-name / --rule-name",
     'Pick another "Threat profile name" / "Threat rule name" on Configure'),
    (r"--profile-name", '"Threat profile name" on Configure'),
    (r"--rule-name", '"Threat rule name" on Configure'),
    # ---- connect / gateway / plan / demo
    (r"Pick a gateway: --gateway <name> \(aiguard setup lists them\)", "Pick a gateway on Connect"),
    (r"Pick a gateway: aiguard setup or --gateway <name> \(web console: Connect > Gateway\)",
     "Pick a gateway on Connect"),
    (r"--gateway <name>", "the gateway list on Connect"),
    (r"Connect first: aiguard setup \(web console: Connect\)", "Connect first (Connect page)"),
    (r"Connect first \(aiguard setup, or Connect in the web console\)",
     "Connect first (Connect page)"),
    (r"Pass --server <address> \(web console: the Server field\)",
     "Enter the management server address on Connect"),
    (r"Build the plan first \(aiguard plan, or Configure in the web console\), review it, then "
     r"approve its id",
     "Build the plan on Configure, review it, then approve it on Approve and install"),
    (r"Send your own prompt \(aiguard demo --prompt TEXT, or the prompt box in the web "
     r"console\)", "Type your own prompt in the box on Run the demo"),
    (r"\(aiguard setup lists them\)", "(Connect lists them)"),
    # ---- this computer's address as the gateway sees it (NAT, Docker)
    (r"--local-ip(?: IP)?(?: or AIGUARD_LOCAL_IP)?",
     '"Network address translation" on Connect'),
    # ---- what is left of the program name
    (r"(?<![\w./\\~-])aiguard(?![\w/\\-])(?!\.\w)", "AI Guard"),
)
_RULES: List[Tuple[Pattern[str], Replacement]] = [(re.compile(p), r) for p, r in _RULE_SOURCE]

# A fix step that only makes sense on the command line (and says nothing for the web).
_CLI_ONLY = re.compile(r"^CLI:")


def web_text(text: Any) -> Any:
    """``text`` with the CLI wording replaced by the web console's (non-strings unchanged)."""
    if not isinstance(text, str) or not text:
        return text
    out = text
    for pattern, repl in _RULES:
        out = pattern.sub(repl, out)
    return out


def web_fix(items: Any) -> Any:
    """A fix list for the web: CLI-only steps are dropped (when something else is left),
    the rest is reworded with :func:`web_text`."""
    if not isinstance(items, list):
        return web_text(items)
    keep = [x for x in items if not (isinstance(x, str) and _CLI_ONLY.match(x)
                                     and "web console" not in x.lower())]
    if not keep:
        keep = list(items)
    return [web_text(x) for x in keep]


# --------------------------------------------------------------------------- actions

_ACTION_ALIASES = {
    "rollback": "rollback", "roll-back": "rollback", "undo": "rollback",
    "https-inspection": "https_fix", "fix-https-inspection": "https_fix", "fix-https": "https_fix",
    "https-fix": "https_fix", "enable-https-inspection": "https_fix", "https-rule": "https_rule",
    "add-https-rule": "https_rule",
    "trust-ca": "outbound_ca", "outbound-ca": "outbound_ca", "export-outbound-ca": "outbound_ca",
    "fetch-outbound-ca": "outbound_ca", "outbound-ca-from-management": "outbound_ca",
    "discard": "discard", "discard-session": "discard",
    "moderation": "configure", "setup-moderation": "configure", "enable-moderation": "configure",
    "configure": "configure", "plan": "configure", "rebuild-plan": "configure",
    "connect": "connect", "reconnect": "connect",
}
_LABELS = {
    "https_fix": "Turn on for me",
    "https_rule": "Add the Inspect rule for me",
    "outbound_ca": "Export outbound CA",
    "discard": "Discard unpublished changes",
    "configure": "Open Configure",
    "connect": "Open Connect",
}
_RID_RE = re.compile(r"^%s$" % _ROLLBACK_ID)
_RID_IN_TEXT = re.compile(r"aiguard rollback (%s)\b" % _ROLLBACK_ID)


def action_id(name: Any) -> Optional[str]:
    """The console's id for an engine action name (``"fix-https-inspection"`` ->
    ``"https_fix"``), or None when the console has no button for it."""
    if not isinstance(name, str):
        return None
    key = name.strip().lower().replace("_", "-").replace(" ", "-")
    return _ACTION_ALIASES.get(key)


def check_action(check: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The button for a preflight check: from ``CheckResult.action`` (``{"id", "label",
    "cli", "options"}``) or ``fixable``; None when the console has none."""
    if not isinstance(check, dict) or check.get("status") not in ("fail", "warn"):
        return None
    raw = check.get("action")
    name = raw.get("id") if isinstance(raw, dict) else raw
    aid = action_id(name) or action_id(check.get("fixable"))
    if aid is None or aid == "rollback":
        return None
    return _action(aid)


def _action(aid: str, rollback_id: Optional[str] = None) -> Dict[str, Any]:
    if aid == "rollback":
        return {"id": "rollback", "label": "Roll back %s" % rollback_id,
                "rollback_id": rollback_id}
    return {"id": aid, "label": _LABELS.get(aid, aid)}


def _core_actions(raw: Any, details: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    items = raw if isinstance(raw, list) else [raw]
    for item in items:
        if isinstance(item, dict):
            name = (item.get("action") or item.get("type") or item.get("kind")
                    or item.get("name") or item.get("id"))
            rid = item.get("rollback_id") or item.get("rollback-id")
            if rid is None and action_id(name) == "rollback":
                rid = item.get("id") if item.get("id") != name else None
        else:
            name, rid = item, None
        aid = action_id(name)
        if aid is None:
            continue
        if aid == "rollback":
            rid = rid or details.get("rollback_id") or details.get("rollback-id")
            if not (isinstance(rid, str) and _RID_RE.match(rid)):
                continue
            out.append(_action(aid, rid))
        else:
            out.append(_action(aid))
    return out


def web_actions(err: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Buttons for a five-field error dict (before its text is reworded):
    ``[{"id": "rollback" | "https_fix" | "outbound_ca" | "discard" | "configure" |
    "connect", "label", "rollback_id"?}]``."""
    out: List[Dict[str, Any]] = []
    seen = set()

    def add(action: Dict[str, Any]) -> None:
        key = (action["id"], action.get("rollback_id"))
        if key not in seen:
            seen.add(key)
            out.append(action)

    details = err.get("details") if isinstance(err.get("details"), dict) else {}
    for action in _core_actions(details.get("action"), details):
        add(action)
    for action in _core_actions(details.get("actions"), details):
        add(action)
    fix = err.get("fix") if isinstance(err.get("fix"), list) else [err.get("fix")]
    text = " ".join(str(x) for x in [err.get("state")] + list(fix) if isinstance(x, str))
    for rid in _RID_IN_TEXT.findall(text):
        add(_action("rollback", rid))
    if "aiguard fix https-inspection --add-rule" in text:
        add(_action("https_rule"))
    if re.search(r"aiguard fix https-inspection(?! --add-rule)", text):
        add(_action("https_fix"))
    if ("aiguard trust-ca" in text or "--ca-file <outbound-ca.pem>" in text
            or "--outbound-ca" in text):
        add(_action("outbound_ca"))
    if "aiguard setup --moderation" in text:
        add(_action("configure"))
    return out


# --------------------------------------------------------------------------- payloads


def _is_error(d: Dict[str, Any]) -> bool:
    return "what" in d and "fix" in d and ("state" in d or "why" in d)


def _is_check(d: Dict[str, Any]) -> bool:
    return "blocking" in d and "detail" in d and "status" in d and "fix" in d


def webify(obj: Any, _depth: int = 0) -> Any:
    """A copy of ``obj`` (JSON-like) with the web wording applied (see the module doc)."""
    if _depth > 40:
        return obj
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for key, value in obj.items():
            if key == "server_said":
                out[key] = value
            elif key == "fix" and isinstance(value, list):
                out[key] = web_fix(value)
            elif key in TEXT_KEYS and isinstance(value, str):
                out[key] = web_text(value)
            elif key in TEXT_KEYS and isinstance(value, list):
                out[key] = [web_text(v) if isinstance(v, str) else webify(v, _depth + 1)
                            for v in value]
            else:
                out[key] = webify(value, _depth + 1)
        if _is_error(obj) and "actions" not in obj:
            out["actions"] = web_actions(obj)
        elif _is_check(obj) and "web_action" not in obj:
            out["web_action"] = check_action(obj)
        return out
    if isinstance(obj, list):
        return [webify(v, _depth + 1) for v in obj]
    return obj
