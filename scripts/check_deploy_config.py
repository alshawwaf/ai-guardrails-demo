#!/usr/bin/env python3
"""Check that the Docker and nginx files keep the client address trustworthy.

The app trusts X-Forwarded-* headers only when TRUSTED_PROXY_HOPS is above 0.
The sign-in limit (10 attempts per minute) and the sign-in log lines count
by client address, so:

* docker-compose.yml (users reach port 9000 directly) must trust no proxy and
  must not start nginx;
* docker-compose.prod.yml (nginx in front) must set TRUSTED_PROXY_HOPS=1 for
  the web service and publish the app port on loopback only; otherwise every
  user shares one count (hops 0), or a client that reaches port 9000 directly
  can choose its own address (hops 1 on a public port);
* every nginx location that proxies to the app must set X-Forwarded-For,
  X-Forwarded-Proto and X-Forwarded-Host itself and remove X-Forwarded-Port,
  so a value a client sent is never passed through to an app that trusts it.
  X-Forwarded-Host is $http_host (host and port as the browser sent them): the
  app's same-origin check compares scheme, host and port exactly.

Usage (standard library only, no Docker needed for the first two):

    python scripts/check_deploy_config.py               # checks the files in this repository
    python scripts/check_deploy_config.py --self-test   # proves the checks catch the known mistakes
    # what Docker Compose actually resolves (CI runs this):
    docker compose config --format json > base.json
    docker compose -f docker-compose.yml -f docker-compose.prod.yml config --format json > prod.json
    python scripts/check_deploy_config.py --base-json base.json --prod-json prod.json

Exit code 0 when every check holds; 1 with one line per problem otherwise.
"""

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOOPBACK = ("127.0.0.1", "::1")

# Header -> the only value nginx may send for it ('""' removes the header).
REQUIRED_PROXY_HEADERS = {
    "host": "$host",
    "x-forwarded-for": "$proxy_add_x_forwarded_for",
    "x-forwarded-proto": "$scheme",
    "x-forwarded-host": "$http_host",
    "x-forwarded-port": '""',
}


# ---------------------------------------------------------------------------
# nginx
# ---------------------------------------------------------------------------

def _strip_comments(text):
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _parse_blocks(text):
    """Parse nginx config text into a tree of {"name", "args", "directives", "children"}."""
    tokens = re.findall(r"[{};]|[^\s{};]+", _strip_comments(text))
    root = {"name": "main", "args": [], "directives": [], "children": []}
    stack = [root]
    words = []
    for tok in tokens:
        if tok == ";":
            if words:
                stack[-1]["directives"].append(words)
            words = []
        elif tok == "{":
            block = {"name": words[0] if words else "", "args": words[1:],
                     "directives": [], "children": []}
            stack[-1]["children"].append(block)
            stack.append(block)
            words = []
        elif tok == "}":
            if len(stack) == 1:
                raise ValueError("unbalanced '}' in nginx config")
            stack.pop()
            words = []
        else:
            words.append(tok)
    if len(stack) != 1:
        raise ValueError("unbalanced '{' in nginx config")
    return root


def _headers(block):
    return {d[1].lower(): " ".join(d[2:]) for d in block["directives"]
            if d[0] == "proxy_set_header" and len(d) >= 3}


def _walk_locations(block, inherited, label, problems):
    # nginx inherits proxy_set_header from the enclosing level only when the
    # level itself sets none.
    own = _headers(block)
    effective = own if own else inherited
    if block["name"] == "location":
        where = "%s location %s" % (label, " ".join(block["args"]))
        if any(d[0] == "proxy_pass" for d in block["directives"]):
            for header, value in REQUIRED_PROXY_HEADERS.items():
                got = effective.get(header)
                if got != value:
                    problems.append(
                        "nginx: %s must set 'proxy_set_header %s %s;' (found: %s)"
                        % (where, header_name(header), value, got or "nothing"))
    for child in block["children"]:
        _walk_locations(child, effective, label, problems)


def header_name(header):
    return "-".join(part.capitalize() for part in header.split("-"))


def _commented_server_blocks(text):
    """The commented-out server blocks (the ready-made TLS block), uncommented."""
    blocks = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if re.match(r"^\s*#\s*server\s*\{", lines[i]):
            depth, chunk = 0, []
            while i < len(lines) and lines[i].lstrip().startswith("#"):
                body = lines[i].lstrip()[1:]
                chunk.append(body)
                depth += body.count("{") - body.count("}")
                i += 1
                if depth == 0:
                    break
            blocks.append("\n".join(chunk))
        else:
            i += 1
    return blocks


def nginx_problems(text):
    """Problems in nginx.conf text: active server blocks and the commented TLS block."""
    problems = []
    try:
        _walk_locations(_parse_blocks(text), {}, "active", problems)
        for n, block in enumerate(_commented_server_blocks(text), 1):
            _walk_locations(_parse_blocks(block), {}, "commented server #%d" % n, problems)
    except ValueError as exc:
        problems.append("nginx: %s" % exc)
    if not re.search(r"(?:^|[\s;{}])proxy_pass\s", _strip_comments(text)):
        problems.append("nginx: no active proxy_pass found")
    return problems


# ---------------------------------------------------------------------------
# Compose files as text (no Docker needed)
# ---------------------------------------------------------------------------

def _service_block(text, name):
    """The lines of top-level service `name` in a compose file (2-space indent)."""
    lines = text.splitlines()
    try:
        services = next(i for i, l in enumerate(lines) if l.rstrip() == "services:")
    except StopIteration:
        return None
    out, inside, found = [], False, False
    for line in lines[services + 1:]:
        if re.match(r"^[^\s#]", line):      # next top-level key
            break
        m = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line)
        if m:
            inside = m.group(1) == name
            found = found or inside
            continue
        if inside:
            out.append(line)
    return out if found else None


def _list_after(block, key):
    """Items of the YAML list `key:` (list syntax) inside a service block."""
    items, collecting = [], False
    for line in block:
        if re.match(r"^    %s:" % re.escape(key), line):
            collecting = True
            continue
        if collecting:
            m = re.match(r"^      - (.*)$", line)
            if m:
                items.append(m.group(1).strip().strip("\"'"))
            elif line.strip() and not line.strip().startswith("#"):
                if not line.startswith("      "):
                    collecting = False
    return items


def _env_value(block, name):
    for item in _list_after(block, "environment"):
        if item.split("=", 1)[0] == name:
            return item.split("=", 1)[1] if "=" in item else None
    return None


def _host_ip(port_spec):
    """'127.0.0.1:9000:9000' -> '127.0.0.1'; '9000:9000' -> '' (all interfaces)."""
    spec = re.sub(r"\$\{[^}]*\}", "N", port_spec)
    if spec.startswith("["):
        return spec[1:spec.index("]")]
    parts = spec.split(":")
    return parts[0] if len(parts) == 3 else ""


def compose_text_problems(base_text, prod_text):
    problems = []
    web = _service_block(base_text, "web")
    if web is None:
        problems.append("docker-compose.yml: no web service")
    else:
        hops = _env_value(web, "TRUSTED_PROXY_HOPS")
        if hops not in ("${TRUSTED_PROXY_HOPS:-0}", "0"):
            problems.append("docker-compose.yml: web must default to TRUSTED_PROXY_HOPS 0 "
                            "(users reach the app port directly); found %r" % hops)
    if _service_block(base_text, "nginx") is not None:
        problems.append("docker-compose.yml: nginx belongs in docker-compose.prod.yml, which "
                        "also makes the app trust it; here the app would see one address "
                        "for every user")
    for name in ("redis", "redis-commander"):
        block = _service_block(base_text, name) or []
        for spec in _list_after(block, "ports"):
            if _host_ip(spec) not in LOOPBACK:
                problems.append("docker-compose.yml: %s has no sign-in; publish it on "
                                "127.0.0.1 only (found %r)" % (name, spec))

    pweb = _service_block(prod_text, "web")
    if pweb is None:
        problems.append("docker-compose.prod.yml: no web override")
    else:
        if _env_value(pweb, "TRUSTED_PROXY_HOPS") != "1":
            problems.append("docker-compose.prod.yml: web must set TRUSTED_PROXY_HOPS=1 behind "
                            "nginx, or every user shares one sign-in limit")
        if not any(re.match(r"^    ports:\s*!override\s*$", line) for line in pweb):
            problems.append("docker-compose.prod.yml: web ports must use '!override' so the "
                            "base file's public port is replaced, not added to")
        ports = _list_after(pweb, "ports")
        if not ports:
            problems.append("docker-compose.prod.yml: web publishes no port (expected one on "
                            "127.0.0.1)")
        for spec in ports:
            if _host_ip(spec) not in LOOPBACK:
                problems.append("docker-compose.prod.yml: web port %r must be on 127.0.0.1: "
                                "with TRUSTED_PROXY_HOPS=1 a direct client could set its own "
                                "X-Forwarded-For" % spec)
    if _service_block(prod_text, "nginx") is None:
        problems.append("docker-compose.prod.yml: no nginx service")
    return problems


# ---------------------------------------------------------------------------
# What Docker Compose resolved ("docker compose config --format json")
# ---------------------------------------------------------------------------

def _resolved_hops(service):
    env = service.get("environment") or {}
    if isinstance(env, list):
        env = dict(item.split("=", 1) if "=" in item else (item, None) for item in env)
    return env.get("TRUSTED_PROXY_HOPS")


def compose_json_problems(base_cfg, prod_cfg):
    problems = []
    base = base_cfg.get("services", {})
    prod = prod_cfg.get("services", {})
    if "nginx" in base:
        problems.append("compose (base): nginx must not start without docker-compose.prod.yml")
    if "web" not in base:
        problems.append("compose (base): no web service")
    elif str(_resolved_hops(base["web"])) != "0":
        problems.append("compose (base): web TRUSTED_PROXY_HOPS is %r, expected '0'"
                        % _resolved_hops(base["web"]))
    for name in ("redis", "redis-commander"):
        for port in (base.get(name) or {}).get("ports") or []:
            if port.get("host_ip") not in LOOPBACK:
                problems.append("compose (base): %s port %s is not on loopback"
                                % (name, port.get("published")))
    web = prod.get("web")
    if web is None:
        problems.append("compose (prod): no web service")
    else:
        if str(_resolved_hops(web)) != "1":
            problems.append("compose (prod): web TRUSTED_PROXY_HOPS is %r, expected '1'"
                            % _resolved_hops(web))
        ports = web.get("ports") or []
        if not ports:
            problems.append("compose (prod): web publishes no port")
        for port in ports:
            if port.get("host_ip") not in LOOPBACK:
                problems.append("compose (prod): web port %s is published on %s, not loopback "
                                "(Docker Compose older than 2.24.4 ignores !override)"
                                % (port.get("published"), port.get("host_ip") or "all interfaces"))
    if "nginx" not in prod:
        problems.append("compose (prod): no nginx service")
    return problems


# ---------------------------------------------------------------------------
# Self-test: the checks must catch the mistakes they exist for
# ---------------------------------------------------------------------------

def self_test():
    """Run the checks on the repository files and on broken copies of them."""
    failures = []
    nginx = (ROOT / "nginx" / "nginx.conf").read_text()
    base = (ROOT / "docker-compose.yml").read_text()
    prod = (ROOT / "docker-compose.prod.yml").read_text()

    def expect(label, problems, needle):
        if needle is None:
            if problems:
                failures.append("%s: expected no problems, got %s" % (label, problems))
        elif not any(needle in p for p in problems):
            failures.append("%s: expected a problem mentioning %r, got %s"
                            % (label, needle, problems))

    expect("repository nginx.conf", nginx_problems(nginx), None)
    expect("repository compose files", compose_text_problems(base, prod), None)

    # The original finding: production web left at TRUSTED_PROXY_HOPS 0.
    expect("prod hops 0",
           compose_text_problems(base, prod.replace("TRUSTED_PROXY_HOPS=1", "TRUSTED_PROXY_HOPS=0")),
           "TRUSTED_PROXY_HOPS=1")
    # Hops 1 with the app port public: X-Forwarded-For can be forged.
    expect("prod public port",
           compose_text_problems(base, prod.replace('"127.0.0.1:${APP_PORT', '"${APP_PORT')),
           "must be on 127.0.0.1")
    expect("prod without !override",
           compose_text_problems(base, prod.replace("ports: !override", "ports:")),
           "!override")
    # nginx back in the base file, in front of an app that trusts no proxy.
    expect("nginx in base",
           compose_text_problems(base.replace("services:\n", "services:\n  nginx:\n"
                                              "    image: nginx:alpine\n", 1), prod),
           "nginx belongs in docker-compose.prod.yml")
    # A client-supplied X-Forwarded-Host / -Port passed through to an app that trusts it.
    expect("nginx without X-Forwarded-Host",
           nginx_problems(nginx.replace("proxy_set_header X-Forwarded-Host $http_host;", "", 1)),
           "X-Forwarded-Host")
    expect("nginx not removing X-Forwarded-Port",
           nginx_problems(nginx.replace('proxy_set_header X-Forwarded-Port "";', "", 1)),
           "X-Forwarded-Port")
    # $host drops the port: a browser on a non-default port would fail the origin check.
    expect("nginx X-Forwarded-Host without the port",
           nginx_problems(nginx.replace("X-Forwarded-Host $http_host;", "X-Forwarded-Host $host;", 1)),
           "X-Forwarded-Host $http_host")
    expect("nginx overwriting X-Forwarded-For with a client value",
           nginx_problems(nginx.replace("X-Forwarded-For $proxy_add_x_forwarded_for",
                                        "X-Forwarded-For $http_x_forwarded_for", 1)),
           "X-Forwarded-For")
    # The commented TLS block is checked too (what HTTPS users switch on).
    tls_start = nginx.index("# server {")
    broken_tls = nginx[:tls_start] + nginx[tls_start:].replace(
        "#         proxy_set_header X-Forwarded-Host $http_host;", "#", 1)
    expect("commented TLS block without X-Forwarded-Host", nginx_problems(broken_tls),
           "commented server")

    resolved_ok_base = {"services": {"web": {"environment": {"TRUSTED_PROXY_HOPS": "0"},
                                             "ports": [{"published": "9000"}]},
                                     "redis": {"ports": [{"host_ip": "127.0.0.1"}]}}}
    resolved_ok_prod = {"services": {"web": {"environment": {"TRUSTED_PROXY_HOPS": "1"},
                                             "ports": [{"host_ip": "127.0.0.1",
                                                        "published": "9000"}]},
                                     "nginx": {}}}
    expect("resolved ok", compose_json_problems(resolved_ok_base, resolved_ok_prod), None)
    merged = json.loads(json.dumps(resolved_ok_prod))
    merged["services"]["web"]["ports"].append({"published": "9000"})   # !override ignored
    expect("resolved: old Compose merged the public port",
           compose_json_problems(resolved_ok_base, merged), "not loopback")
    unset = json.loads(json.dumps(resolved_ok_prod))
    unset["services"]["web"]["environment"] = {"TRUSTED_PROXY_HOPS": "0"}
    expect("resolved: prod hops 0", compose_json_problems(resolved_ok_base, unset), "expected '1'")
    return failures


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base-json", help="output of: docker compose config --format json")
    ap.add_argument("--prod-json", help="output of: docker compose -f docker-compose.yml "
                                        "-f docker-compose.prod.yml config --format json")
    ap.add_argument("--self-test", action="store_true",
                    help="also check that the checks catch the known mistakes")
    args = ap.parse_args(argv)

    problems = nginx_problems((ROOT / "nginx" / "nginx.conf").read_text())
    problems += compose_text_problems((ROOT / "docker-compose.yml").read_text(),
                                      (ROOT / "docker-compose.prod.yml").read_text())
    if bool(args.base_json) != bool(args.prod_json):
        ap.error("give both --base-json and --prod-json")
    if args.base_json:
        with open(args.base_json, encoding="utf-8") as fh:
            base_cfg = json.load(fh)
        with open(args.prod_json, encoding="utf-8") as fh:
            prod_cfg = json.load(fh)
        problems += compose_json_problems(base_cfg, prod_cfg)
    if args.self_test:
        problems += ["self-test: %s" % f for f in self_test()]

    for problem in problems:
        print("FAIL  %s" % problem)
    if not problems:
        print("OK    reverse proxy, client address and port settings"
              + (" (resolved by Docker Compose)" if args.base_json else "")
              + (" + self-test" if args.self_test else ""))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
