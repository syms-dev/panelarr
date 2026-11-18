"""Regression tests for the verified security sweep of 2026-11-17 (docs/audits/2026-11-17-*.md).

Each finding has an attack test, which reproduced the defect before its fix (it was marked
``xfail(strict=True)`` until then), and a guard test for the legitimate path. Both must pass.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import shlex
import subprocess
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from backend.services import arr
from backend.tests.test_security import PASSWORD, SETUP_BASE, _basic_config, _client, _write


@pytest.fixture()
def config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Same isolation as test_security.config_path: a temp panelarr.json, no env overrides."""
    import backend.config as cfg_module
    import backend.services.config as svc_cfg

    cfg = tmp_path / "panelarr.json"
    new_settings = dataclasses.replace(cfg_module.settings, config_path=str(cfg))
    monkeypatch.setattr(cfg_module, "settings", new_settings)
    monkeypatch.setattr(svc_cfg, "settings", new_settings)
    monkeypatch.setattr(svc_cfg, "_resolved_config_path", None)
    monkeypatch.delenv("PANELARR_TRUSTED_PROXIES", raising=False)
    monkeypatch.delenv("PANELARR_ALLOWED_ORIGINS", raising=False)
    return cfg


REAL_CLIENT = httpx.AsyncClient
FAKE_SAB_KEY = "sabkey" + "0123456789abcdef0123456789"  # test fixture, not a real key


def _patch_client(
    monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]
) -> None:
    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs.pop("limits", None)
        return REAL_CLIENT(transport=httpx.MockTransport(handler), **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def _patch_sab(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(arr, "load_config", lambda: object())
    monkeypatch.setattr(
        arr,
        "get_service_config",
        lambda _c, _n: {"url": "http://sab:8080", "api_key": FAKE_SAB_KEY},
    )
    monkeypatch.setattr(arr, "_http_client", None)


# ---------------------------------------------------------------------------
# 2026-11-17-media-integrations/F1: SABnzbd API key written to the log on a non-2xx answer
# ---------------------------------------------------------------------------


async def test_sab_stats_error_does_not_log_api_key(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _patch_sab(monkeypatch)
    _patch_client(monkeypatch, lambda req: httpx.Response(403, text="Hostname verification failed"))
    with caplog.at_level(logging.WARNING, logger="backend.services.arr"):
        result = await arr.get_sabnzbd_stats()
    assert result == {"configured": True, "error": "HTTP 403"}
    assert FAKE_SAB_KEY not in caplog.text


async def test_sab_stats_success_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_sab(monkeypatch)

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.params["apikey"] == FAKE_SAB_KEY
        return httpx.Response(200, json={"queue": {"noofslots_total": 2, "status": "Downloading"}})

    _patch_client(monkeypatch, handler)
    result = await arr.get_sabnzbd_stats()
    assert result["configured"] is True
    assert result["queue"] == 2
    assert "error" not in result


# ---------------------------------------------------------------------------
# 2026-11-17-docker-control/F1: registry token realm fetched without the outbound guard
# ---------------------------------------------------------------------------


async def _realm_requests(realm: str) -> tuple[str, list[str]]:
    from backend.services import docker

    docker._registry_token_cache.clear()
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url.host)
        return httpx.Response(200, json={"token": "anon-token", "expires_in": 300})

    async with REAL_CLIENT(transport=httpx.MockTransport(handler)) as client:
        token = await docker._get_registry_token(
            client, {"realm": realm, "service": "registry", "scope": "repository:x:pull"}
        )
    return token, seen


async def test_registry_realm_to_metadata_is_refused() -> None:
    token, seen = await _realm_requests("http://169.254.169.254/latest/meta-data/")
    assert seen == []
    assert token == ""


async def test_registry_realm_public_guard() -> None:
    token, seen = await _realm_requests("https://203.0.113.10/token")
    assert seen == ["203.0.113.10"]
    assert token == "anon-token"


# ---------------------------------------------------------------------------
# 2026-11-17-docker-control/F2: _guard_critical matches strings, not the resolved container
# ---------------------------------------------------------------------------

PROXY_ID = "a1" * 32
PANELARR_ID = "3f" * 32


def _inspect(cid: str, name: str, aliases: list[str]) -> dict:
    return {
        "Id": cid,
        "Name": f"/{name}",
        "State": {"Running": False},
        "Config": {"Image": "img:1", "Labels": {}},
        "NetworkSettings": {"Networks": {"stack_default": {"Aliases": aliases}}},
    }


@pytest.fixture()
def docker_env(tmp_path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Panelarr in mode none, DOCKER_SOCKET=tcp://dockerproxy:2375, HOSTNAME=panelarr."""
    import backend.config as cfg_module
    import backend.services.config as svc_cfg
    from backend.services import docker

    cfg = tmp_path / "panelarr.json"
    cfg.write_text(json.dumps({"auth": {"mode": "none"}, "setup": {"completed_at": "t"}}))
    new = dataclasses.replace(
        cfg_module.settings, config_path=str(cfg), docker_socket="tcp://dockerproxy:2375"
    )
    for mod in (cfg_module, svc_cfg, docker):
        monkeypatch.setattr(mod, "settings", new)
    monkeypatch.setattr(svc_cfg, "_resolved_config_path", None)
    monkeypatch.setenv("HOSTNAME", "panelarr")

    containers = {
        "stack-dockerproxy-1": _inspect(PROXY_ID, "stack-dockerproxy-1", ["dockerproxy"]),
        PANELARR_ID[:12]: _inspect(PANELARR_ID, "panelarr", ["panelarr"]),
        "sonarr": _inspect("b2" * 32, "sonarr", ["sonarr"]),
    }
    actions: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        parts = req.url.path.strip("/").split("/")  # [version, "containers", name, op]
        target = containers.get(parts[2]) if len(parts) > 3 else None
        if req.method == "GET" and parts[-1] == "json":
            return httpx.Response(200, json=target) if target else httpx.Response(404)
        actions.append(f"{req.method} {parts[2]}/{parts[-1]}")
        return httpx.Response(204)

    monkeypatch.setattr(docker, "_docker_transport", lambda: httpx.MockTransport(handler))
    return actions


def _app_client():
    from backend.main import app

    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("203.0.113.7", 40000)),
        base_url="http://panel.test",
    )


@pytest.mark.parametrize("target", ["stack-dockerproxy-1", PANELARR_ID[:12]])
async def test_guard_refuses_proxy_and_self_by_resolved_identity(
    docker_env: list[str], target: str
) -> None:
    async with _app_client() as c:
        resp = await c.post(f"/api/containers/{target}/stop")
    assert resp.status_code == 409
    assert docker_env == []


async def test_guard_allows_ordinary_container(docker_env: list[str]) -> None:
    async with _app_client() as c:
        resp = await c.post("/api/containers/sonarr/stop")
    assert resp.status_code == 200
    assert docker_env == ["POST sonarr/stop"]


# ---------------------------------------------------------------------------
# Zone auth-sessions (2026-11-17-auth-sessions/F1..F6)
# ---------------------------------------------------------------------------

REPO = Path(__file__).resolve().parents[2]


def _trusted() -> list[str]:
    from backend.services.security import get_trusted_proxies

    return get_trusted_proxies()


# F1: a stranger before setup plants trusted_proxies through a request that fails validation


async def test_failed_setup_request_does_not_persist_trusted_proxies(config_path: Path) -> None:
    async with _client(base_url=SETUP_BASE) as c:
        resp = await c.post(
            "/api/setup/auth", json={"mode": "basic", "trusted_proxies": ["0.0.0.0/0", "::/0"]}
        )
    assert resp.status_code == 422
    assert "0.0.0.0/0" not in _trusted()


async def test_setup_proxy_mode_with_explicit_list_guard(config_path: Path) -> None:
    async with _client(("203.0.113.7", 40000), base_url=SETUP_BASE) as c:
        resp = await c.post(
            "/api/setup/auth",
            json={"mode": "proxy", "trusted_proxies": ["203.0.113.7/32"]},
            headers={"Remote-User": "admin"},
        )
    assert resp.status_code == 200, resp.text
    assert _trusted() == ["203.0.113.7/32"]


# F2: uvicorn's proxy-header middleware (on by default in entrypoint.sh) rewrites the client
# address before Panelarr's trusted-proxy logic sees it.


def _app_as_entrypoint_runs_it(monkeypatch: pytest.MonkeyPatch):
    import uvicorn

    from backend.main import app

    monkeypatch.delenv("FORWARDED_ALLOW_IPS", raising=False)
    script = (REPO / "entrypoint.sh").read_text().replace("\\\n", " ")
    line = next(
        ln for ln in script.splitlines() if ln.lstrip().startswith("exec ") and "uvicorn " in ln
    )
    args = shlex.split(line)
    fwd = args[args.index("--forwarded-allow-ips") + 1] if "--forwarded-allow-ips" in args else None
    config = uvicorn.Config(
        app, proxy_headers="--no-proxy-headers" not in args, forwarded_allow_ips=fwd
    )
    config.load()
    return config.loaded_app


def _loopback_client(asgi_app) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=asgi_app, client=("127.0.0.1", 40000)),
        base_url="http://panel.test",
    )


async def test_enabling_proxy_mode_through_loopback_proxy_trusts_the_proxy_not_the_client(
    config_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(config_path, {"auth": {"mode": "none"}, "setup": {"completed_at": "t"}})
    async with _loopback_client(_app_as_entrypoint_runs_it(monkeypatch)) as c:
        resp = await c.put(
            "/api/auth/config",
            json={"mode": "proxy"},
            headers={"Remote-User": "admin", "X-Forwarded-For": "198.51.100.20"},
        )
    assert resp.status_code == 200, resp.text
    assert "198.51.100.20/32" not in _trusted()


async def test_loopback_proxy_header_without_xff_guard(
    config_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(
        config_path,
        {
            "auth": {"mode": "proxy", "proxy_header": "Remote-User", "proxy_hosts": ["panel.test"]},
            "setup": {"completed_at": "t"},
        },
    )
    async with _loopback_client(_app_as_entrypoint_runs_it(monkeypatch)) as c:
        assert (await c.get("/api/config", headers={"Remote-User": "admin"})).status_code == 200


# F3: PANELARR_HOST is documented but entrypoint.sh always binds 0.0.0.0


def _entrypoint_argv(tmp_path: Path, **env: str) -> list[str]:
    stub = tmp_path / "bin"
    stub.mkdir()
    for name, body in (("gosu", 'printf "%s\\n" "$@"'), ("chown", "exit 0")):
        path = stub / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
    full_env = {
        "PATH": f"{stub}:{os.environ['PATH']}",
        "DOCKER_SOCKET": str(tmp_path / "no-socket"),
        **env,
    }
    out = subprocess.run(
        ["sh", str(REPO / "entrypoint.sh")],
        env=full_env,
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.splitlines()


def test_entrypoint_honours_panelarr_host(tmp_path: Path) -> None:
    argv = _entrypoint_argv(tmp_path, PANELARR_HOST="127.0.0.1")
    assert argv[argv.index("--host") + 1] == "127.0.0.1"


def test_entrypoint_default_host_guard(tmp_path: Path) -> None:
    argv = _entrypoint_argv(tmp_path)
    assert argv[argv.index("--host") + 1] == "0.0.0.0"
    assert argv[argv.index("--port") + 1] == "8000"


# F4: enabling proxy mode auto-trusts the Docker bridge gateway address


async def test_enabling_proxy_mode_from_bridge_gateway_does_not_trust_it(config_path: Path) -> None:
    _write(config_path, {"auth": {"mode": "none"}, "setup": {"completed_at": "t"}})
    async with _client(("172.18.0.1", 40000)) as c:
        await c.put("/api/auth/config", json={"mode": "proxy"}, headers={"Remote-User": "admin"})
    assert "172.18.0.1/32" not in _trusted()


async def test_enabling_proxy_mode_from_proxy_container_guard(config_path: Path) -> None:
    _write(config_path, {"auth": {"mode": "none"}, "setup": {"completed_at": "t"}})
    async with _client(("172.18.0.9", 40000)) as c:
        resp = await c.put(
            "/api/auth/config", json={"mode": "proxy"}, headers={"Remote-User": "admin"}
        )
    assert resp.status_code == 200, resp.text
    assert "172.18.0.9/32" in _trusted()


# F5: session cookie lacks Secure behind an HTTPS proxy that is not in the trusted list


async def _login_cookie(peer: tuple[str, int], headers: dict[str, str]) -> str:
    async with _client(peer) as c:
        resp = await c.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}, headers=headers
        )
    assert resp.status_code == 200, resp.text
    return resp.headers["set-cookie"].lower()


async def test_cookie_secure_behind_untrusted_https_proxy(config_path: Path) -> None:
    _basic_config(config_path)
    cookie = await _login_cookie(("172.18.0.9", 40000), {"X-Forwarded-Proto": "https"})
    assert "; secure" in cookie


async def test_cookie_plain_http_guard(config_path: Path) -> None:
    _basic_config(config_path)
    cookie = await _login_cookie(("203.0.113.7", 40000), {})
    assert "; secure" not in cookie
    assert "samesite=strict" in cookie


# F6: README says Docker networks are trusted by default; the code trusts loopback only


def test_readme_trusted_proxy_default_matches_code() -> None:
    from backend.services.security import DEFAULT_TRUSTED_PROXIES

    readme = (REPO / "README.md").read_text()
    if not any(c.startswith("172.") for c in DEFAULT_TRUSTED_PROXIES):
        assert "Docker networks by default" not in readme


def test_configuration_doc_trusted_proxy_default_guard() -> None:
    from backend.services.security import DEFAULT_TRUSTED_PROXIES

    assert DEFAULT_TRUSTED_PROXIES == ("127.0.0.1/32", "::1/128")
    assert "By default only localhost is trusted" in (REPO / "docs/configuration.md").read_text()


# ---------------------------------------------------------------------------
# Zone config-secrets-outbound (2026-11-17-config-secrets-outbound/F1, F2)
# ---------------------------------------------------------------------------

# F1: an unwritable /config makes Panelarr ignore panelarr.json and reopen the wizard


@pytest.fixture()
def unwritable_config_dir(config_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    _basic_config(config_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    config_path.parent.chmod(0o500)
    yield config_path
    config_path.parent.chmod(0o700)


async def test_unwritable_config_dir_does_not_reopen_setup(unwritable_config_dir: Path) -> None:
    async with _client() as c:
        assert (await c.get("/api/config")).status_code in (401, 503)
        resp = await c.post("/api/setup/auth", json={"mode": "none"})
    assert resp.status_code in (401, 403, 503)


async def test_writable_config_dir_guard(config_path: Path) -> None:
    _basic_config(config_path)
    async with _client() as c:
        assert (await c.get("/api/config")).status_code == 401
        assert (await c.post("/api/setup/auth", json={"mode": "none"})).status_code == 401


# F2: the unauthenticated 503 echoes pydantic input values from panelarr.json

TAIL_MARKER = "ENDMARK" + "q" * 20


def _wrong_shape_config(path: Path) -> None:
    import backend.services.config as svc_cfg

    # A hand-edited service written as a list instead of an object; the second item stands in
    # for the service's API key.
    key = "k" * 40 + TAIL_MARKER
    path.write_text(
        json.dumps(
            {
                "auth": {"mode": "none"},
                "setup": {"completed_at": "t"},
                "services": {"sonarr": ["http://sonarr:8989", key]},
            }
        )
    )
    svc_cfg._config_cache = None


async def test_config_invalid_response_does_not_echo_values(config_path: Path) -> None:
    _wrong_shape_config(config_path)
    async with _client() as c:
        resp = await c.get("/api/containers")
    assert resp.status_code == 503
    assert TAIL_MARKER[-12:] not in resp.text


async def test_config_invalid_still_fails_closed_guard(config_path: Path) -> None:
    _wrong_shape_config(config_path)
    async with _client() as c:
        resp = await c.get("/api/containers")
    assert resp.status_code == 503
    assert resp.json()["code"] == "config_invalid"


# auth-sessions F7: an unknown auth mode in panelarr.json falls back to "none" (fails open)


async def test_unknown_auth_mode_fails_closed(config_path: Path) -> None:
    from backend.services.auth import hash_password

    auth = {"mode": "Basic", "username": "admin", "password_hash": hash_password(PASSWORD)}
    _write(config_path, {"auth": auth, "setup": {"completed_at": "t"}})
    async with _client() as c:
        assert (await c.get("/api/config")).status_code in (401, 503)


async def test_known_auth_mode_guard(config_path: Path) -> None:
    _basic_config(config_path)
    async with _client() as c:
        assert (await c.get("/api/config")).status_code == 401


# Follow-ups to the fixes: the Settings path saves trusted proxies with the mode, and gateway
# detection reads the container's routing table.


async def test_refused_proxy_mode_change_does_not_persist_trusted_proxies(
    config_path: Path,
) -> None:
    _write(config_path, {"auth": {"mode": "none"}, "setup": {"completed_at": "t"}})
    async with _client(("203.0.113.7", 40000)) as c:
        resp = await c.put(
            "/api/auth/config",
            json={"mode": "proxy", "trusted_proxies": ["10.0.0.0/8"]},
            headers={"Remote-User": "admin"},
        )
    assert resp.status_code == 422
    assert "10.0.0.0/8" not in _trusted()


def test_route_table_gateways(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    from backend.services import security

    def hexaddr(ip: str) -> str:
        import ipaddress

        return int.from_bytes(ipaddress.IPv4Address(ip).packed, sys.byteorder).to_bytes(4).hex()

    route = tmp_path / "route"
    header = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
    rows = [
        ("eth0", "0.0.0.0", "10.20.0.1", "0.0.0.0"),
        ("eth0", "10.20.0.0", "0.0.0.0", "255.255.0.0"),
    ]
    route.write_text(
        header
        + "".join(
            f"{i}\t{hexaddr(d)}\t{hexaddr(g)}\t0003\t0\t0\t0\t{hexaddr(m)}\n" for i, d, g, m in rows
        )
    )
    monkeypatch.setattr(security, "Path", lambda _p: route)
    assert security._route_gateways() == {security._ip("10.20.0.1")}
    assert security.looks_like_docker_gateway("10.20.0.1")
    assert not security.looks_like_docker_gateway("10.20.0.9")
    assert not security.looks_like_docker_gateway("127.0.0.1")


# ---------------------------------------------------------------------------
# Claude-BugHunter run of 2026-11-17 (findings verified and fixed the same day)
# ---------------------------------------------------------------------------

REBIND = "http://rebind.attacker.test:8000"


# DNS rebinding before setup: a web page reaches the open wizard under its own hostname.


async def test_setup_refuses_rebound_hostname(config_path: Path) -> None:
    async with _client(base_url=REBIND) as c:
        resp = await c.post(
            "/api/setup/auth",
            json={"mode": "basic", "username": "pwned", "password": "AttackerPass9"},
            headers={"Origin": REBIND},
        )
    assert resp.status_code == 421
    assert resp.json()["code"] == "setup_host"
    assert not config_path.exists()


@pytest.mark.parametrize("base", ["http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]"])
async def test_setup_by_ip_or_localhost_guard(config_path: Path, base: str) -> None:
    async with _client(base_url=base) as c:
        resp = await c.post("/api/setup/auth", json={"mode": "none"})
    assert resp.status_code == 200, resp.text


async def test_setup_on_listed_hostname_guard(
    config_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PANELARR_ALLOWED_HOSTS", "panelarr.home.test")
    async with _client(base_url="http://panelarr.home.test") as c:
        assert (await c.post("/api/setup/auth", json={"mode": "none"})).status_code == 200


# DNS rebinding in proxy mode: a page in a browser on the Panelarr host reaches it from
# loopback (a trusted proxy) and sets the auth header itself.


def _loopback_proxy_mode(path: Path, **extra) -> None:
    auth = {"mode": "proxy", "proxy_header": "Remote-User", **extra}
    _write(path, {"auth": auth, "setup": {"completed_at": "t"}})


async def test_proxy_header_on_rebound_hostname_is_ignored(config_path: Path) -> None:
    _loopback_proxy_mode(config_path, proxy_hosts=["panelarr.example.com"])
    async with _client(("127.0.0.1", 40000), base_url=REBIND) as c:
        assert (await c.get("/api/config", headers={"Remote-User": "x"})).status_code == 401
        resp = await c.put(
            "/api/auth/config",
            json={"mode": "none"},
            headers={"Remote-User": "x", "Origin": REBIND},
        )
    assert resp.status_code == 401
    assert json.loads(config_path.read_text())["auth"]["mode"] == "proxy"


async def test_proxy_mode_without_pinned_host_ignores_header(config_path: Path) -> None:
    _loopback_proxy_mode(config_path)
    async with _client(("127.0.0.1", 40000)) as c:
        assert (await c.get("/api/config", headers={"Remote-User": "x"})).status_code == 401


async def test_enabling_proxy_mode_pins_the_hostname_guard(config_path: Path) -> None:
    _write(config_path, {"auth": {"mode": "none"}, "setup": {"completed_at": "t"}})
    async with _client(("127.0.0.1", 40000), base_url="https://panelarr.example.com") as c:
        resp = await c.put(
            "/api/auth/config", json={"mode": "proxy"}, headers={"Remote-User": "admin"}
        )
        assert resp.status_code == 200, resp.text
        assert (await c.get("/api/config", headers={"Remote-User": "admin"})).status_code == 200
    assert json.loads(config_path.read_text())["auth"]["proxy_hosts"] == ["panelarr.example.com"]


# The F7 fix skipped falsy modes: "mode": null (or "") with stored credentials meant no auth.


@pytest.mark.parametrize("mode", [None, "", False, 0])
async def test_empty_auth_mode_fails_closed(config_path: Path, mode: object) -> None:
    from backend.services.auth import hash_password

    auth = {"mode": mode, "username": "admin", "password_hash": hash_password(PASSWORD)}
    _write(config_path, {"auth": auth, "setup": {"completed_at": "t"}})
    async with _client() as c:
        assert (await c.get("/api/config")).status_code == 503


async def test_missing_auth_mode_is_still_unset_guard(config_path: Path) -> None:
    async with _client(base_url=SETUP_BASE) as c:
        assert (await c.get("/api/setup/status")).status_code == 200
        assert (await c.get("/api/config")).json()["code"] == "setup_required"


# The notification guard checked webhook_url but the generic webhook sends to url: a decoy
# webhook_url let url point at the Docker API, before setup and without claiming the instance.


@pytest.fixture()
def docker_over_tcp(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    import backend.config as cfg_module

    new = dataclasses.replace(cfg_module.settings, docker_socket="tcp://127.0.0.1:23750")
    monkeypatch.setattr(cfg_module, "settings", new)
    sent: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        sent.append(str(req.url))
        return httpx.Response(204)

    _patch_client(monkeypatch, handler)
    return sent


async def test_webhook_guard_checks_the_field_it_sends_to(docker_over_tcp: list[str]) -> None:
    from backend.services.notifications import send_to_channel

    cfg = {
        "webhook_url": "http://127.0.0.1:29999/decoy",
        "url": "http://127.0.0.1:23750/v1.44/containers/sonarr/stop",
    }
    assert await send_to_channel({"type": "webhook", "config": cfg}, "t", "b") is False
    assert docker_over_tcp == []


async def test_webhook_to_ordinary_lan_target_guard(docker_over_tcp: list[str]) -> None:
    from backend.services.notifications import send_to_channel

    cfg = {"url": "http://127.0.0.1:29999/hook"}
    assert await send_to_channel({"type": "webhook", "config": cfg}, "t", "b") is True
    assert docker_over_tcp == ["http://127.0.0.1:29999/hook"]


# The Docker API check compared hostnames: localhost or 127.1 reached a Docker API configured
# as 127.0.0.1 (registry realms and manifests chosen by an image's registry).


@pytest.mark.parametrize("host", ["localhost", "127.1", "127.0.0.1"])
async def test_docker_api_refused_under_other_names(docker_over_tcp: list[str], host: str) -> None:
    from backend.services.security import check_outbound_url

    assert await check_outbound_url(f"http://{host}:23750/v1.44/info") is not None


async def test_other_port_on_loopback_guard(docker_over_tcp: list[str]) -> None:
    from backend.services.security import check_outbound_url

    assert await check_outbound_url("http://localhost:8989/api") is None


# An existing panelarr.json in a directory Panelarr cannot search: from Python 3.14,
# Path.is_file() answers False instead of raising, which reopened the setup wizard.


@pytest.fixture()
def unsearchable_config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import backend.config as cfg_module
    import backend.services.config as svc_cfg

    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    locked = tmp_path / "locked"
    locked.mkdir()
    cfg = locked / "panelarr.json"
    _basic_config(cfg)
    new = dataclasses.replace(cfg_module.settings, config_path=str(cfg))
    monkeypatch.setattr(cfg_module, "settings", new)
    monkeypatch.setattr(svc_cfg, "settings", new)
    monkeypatch.setattr(svc_cfg, "_resolved_config_path", None)
    monkeypatch.setattr(svc_cfg, "_config_cache", None)
    monkeypatch.setattr(svc_cfg, "_last_good_config", None)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    locked.chmod(0o000)
    yield cfg
    locked.chmod(0o700)


async def test_unsearchable_config_dir_fails_closed(unsearchable_config_dir: Path) -> None:
    async with _client(base_url=SETUP_BASE) as c:
        assert (await c.get("/api/config")).status_code == 503
        assert (await c.post("/api/setup/auth", json={"mode": "none"})).status_code == 503
    assert not (unsearchable_config_dir.parent.parent / "home").exists()


# Hardening from the Claude-BugHunter record (docs/audits/bughunter-2026-11-17.md).


async def test_http_origin_refused_when_served_over_https(config_path: Path) -> None:
    _basic_config(config_path, trusted_proxies=["172.18.0.9/32"])
    headers = {"X-Forwarded-Proto": "https", "Host": "panel.test"}
    async with _client(("172.18.0.9", 40000)) as c:
        plain = await c.post("/api/auth/logout", headers={**headers, "Origin": "http://panel.test"})
        tls = await c.post("/api/auth/logout", headers={**headers, "Origin": "https://panel.test"})
    assert plain.status_code == 403
    assert tls.status_code == 200


async def test_api_answers_are_not_cached(config_path: Path) -> None:
    _basic_config(config_path)
    async with _client() as c:
        assert (await c.get("/api/auth/status")).headers["cache-control"] == "no-store"
        assert "cache-control" not in (await c.get("/")).headers


async def test_swagger_oauth2_redirect_route_is_gone(config_path: Path) -> None:
    _basic_config(config_path)
    async with _client() as c:
        resp = await c.get("/docs/oauth2-redirect")
    assert "oauth2" not in resp.text.lower()


@pytest.mark.parametrize(
    ("addr", "gateway"),
    [
        ("2001:db8:1::1", True),
        ("fd00:1:2:3:4::1", True),
        ("fd00:1:2:3::9", False),
        ("fe80::1", False),
        ("::1", False),
    ],
)
def test_ipv6_docker_gateways(addr: str, gateway: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.services import security

    monkeypatch.setattr(security, "_route_gateways", lambda: set())
    assert security.looks_like_docker_gateway(addr) is gateway


def test_loggable_error_drops_urls() -> None:
    from backend.services.security import loggable_error

    req = httpx.Request("GET", f"http://sab:8080/api?apikey={FAKE_SAB_KEY}")
    status = httpx.HTTPStatusError("x", request=req, response=httpx.Response(403, request=req))
    assert loggable_error(status) == "HTTP 403"
    other = httpx.ConnectError(f"failed for http://sab:8080/api?apikey={FAKE_SAB_KEY}")
    assert FAKE_SAB_KEY not in loggable_error(other)
    assert loggable_error(ValueError("bad")) == "ValueError: bad"


async def test_calendar_overflowing_date_is_a_400(config_path: Path) -> None:
    _write(config_path, {"auth": {"mode": "none"}, "setup": {"completed_at": "t"}})
    async with _client() as c:
        resp = await c.get("/api/calendar", params={"start": "9999-12-31T23:59:59-23:59"})
    assert resp.status_code == 400


@pytest.mark.parametrize(
    "image", ["evil.test/a?x=1", "evil.test/../v1.44/info", "a b", "evil.test/x#frag"]
)
async def test_malformed_image_reference_is_not_checked(image: str) -> None:
    from backend.services import docker

    async with REAL_CLIENT(transport=httpx.MockTransport(lambda r: httpx.Response(500))) as c:
        result = await docker._check_single_container_update({"name": "x", "image": image}, c, c)
    assert result is None


async def test_registry_token_answer_is_size_capped() -> None:
    from backend.services import docker

    docker._registry_token_cache.clear()
    big = b'{"token": "' + b"a" * (docker._REGISTRY_TOKEN_MAX_BYTES + 10) + b'"}'
    async with REAL_CLIENT(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=big))
    ) as c:
        token = await docker._get_registry_token(
            c, {"realm": "https://203.0.113.10/token", "service": "s", "scope": "x"}
        )
    assert token == ""
