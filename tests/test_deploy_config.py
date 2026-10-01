"""The Docker and nginx files keep the client address trustworthy (scripts/check_deploy_config.py).

CI also runs the script on what Docker Compose resolves; this keeps the text checks and
their self-test in the normal pytest run, without Docker.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_deploy_config.py"


@pytest.fixture(scope="module")
def checker():
    spec = importlib.util.spec_from_file_location("check_deploy_config", str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_nginx_sets_every_forwarded_header_itself(checker):
    text = (ROOT / "nginx" / "nginx.conf").read_text(encoding="utf-8")
    assert checker.nginx_problems(text) == []


def test_compose_files_trust_exactly_the_bundled_proxy(checker):
    base = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    prod = (ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
    assert checker.compose_text_problems(base, prod) == []


def test_checks_catch_the_known_mistakes(checker):
    assert checker.self_test() == []


def test_gateway_api_is_rate_limited_in_both_server_blocks(checker):
    """Defense in depth for /gateway/api/ (the app limits connect / domain / key check /
    apply itself): the active server and the commented TLS twin both limit it, loosely
    enough for the console's job polling (1 request per second)."""
    text = (ROOT / "nginx" / "nginx.conf").read_text(encoding="utf-8")
    assert "zone=gateway_api" in checker._strip_comments(text)
    blocks = [checker._parse_blocks(text)] + [
        checker._parse_blocks(b) for b in checker._commented_server_blocks(text)]
    assert len(blocks) == 2

    def locations(block):
        for child in block["children"]:
            if child["name"] == "location":
                yield child
            yield from locations(child)

    for block in blocks:
        api = [loc for loc in locations(block) if loc["args"] == ["/gateway/api/"]]
        assert len(api) == 1
        limits = [d for d in api[0]["directives"] if d[0] == "limit_req"]
        assert limits and "zone=gateway_api" in limits[0]


def test_web_service_has_a_stop_grace_period_for_the_shutdown(checker):
    base = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    web = checker._service_block(base, "web") or []
    grace = [line.split(":", 1)[1].strip() for line in web
             if line.startswith("    stop_grace_period:")]
    assert grace and grace[0].endswith("s") and int(grace[0][:-1]) >= 15
    assert any(line.strip() == "init: true" for line in web)
