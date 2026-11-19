"""Security regression tests.

Each test pins a finding from the November 2026 audit so it cannot quietly
come back. They drive the real ASGI app; the client address matters because
loopback is a trusted proxy by default, so most tests connect from a public
TEST-NET address that is not.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

UNTRUSTED = ("203.0.113.7", 40000)
TRUSTED_PROXY = ("172.18.0.5", 40000)
PASSWORD = "correct horse battery"


@pytest.fixture()
def config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
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


def _write(path: Path, data: dict) -> None:
    import backend.services.config as svc_cfg

    path.write_text(json.dumps(data))
    svc_cfg._config_cache = None


# Setup only answers to an IP literal or localhost (DNS-rebinding guard), so tests that run
# the wizard address Panelarr by IP, as an owner on a fresh install does.
SETUP_BASE = "http://192.0.2.10:8000"


def _client(peer: tuple[str, int] = UNTRUSTED, base_url: str = "http://panel.test") -> AsyncClient:
    from backend.main import app

    return AsyncClient(transport=ASGITransport(app=app, client=peer), base_url=base_url)


def _basic_config(path: Path, **extra) -> None:
    from backend.services.auth import hash_password

    auth = {"mode": "basic", "username": "admin", "password_hash": hash_password(PASSWORD)}
    auth.update(extra)
    _write(path, {"auth": auth, "setup": {"completed_at": "test"}})


async def _login(client: AsyncClient) -> None:
    resp = await client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert resp.status_code == 200, resp.text


# --- Fail closed on a broken config ------------------------------------------


async def test_corrupt_config_does_not_disable_auth(config_path: Path) -> None:
    config_path.write_text('{"auth": {"mode": "basic",}')  # trailing comma
    async with _client() as c:
        assert (await c.get("/api/config")).status_code == 503
        resp = await c.post("/api/setup/auth", json={"mode": "none"})
        assert resp.status_code == 503
    # The broken file was not replaced with defaults.
    assert config_path.read_text() == '{"auth": {"mode": "basic",}'


async def test_runtime_corruption_keeps_last_good_config(config_path: Path) -> None:
    _basic_config(config_path)
    async with _client() as c:
        assert (await c.get("/api/config")).status_code == 401
        config_path.write_text("{not json")
        import backend.services.config as svc_cfg

        svc_cfg._config_cache = None
        # Still basic auth, not silently "none".
        assert (await c.get("/api/config")).status_code == 401


def test_save_backs_up_corrupt_file(config_path: Path) -> None:
    from backend.services.config import PanelarrConfig, save_config

    config_path.write_text("{broken")
    save_config(PanelarrConfig())
    backups = list(config_path.parent.glob("panelarr.json.corrupt-*"))
    assert len(backups) == 1 and backups[0].read_text() == "{broken"


# --- Setup wizard gating ---------------------------------------------------------


async def test_fresh_install_exposes_only_the_wizard(config_path: Path) -> None:
    async with _client() as c:
        resp = await c.get("/api/config")
        assert resp.status_code == 403 and resp.json()["code"] == "setup_required"
        assert (await c.post("/api/containers/sonarr/stop")).status_code == 403
        assert (await c.get("/api/setup/status")).status_code == 200


async def test_setup_auth_signs_user_in_and_locks_setup(config_path: Path) -> None:
    async with _client(base_url=SETUP_BASE) as c:
        resp = await c.post(
            "/api/setup/auth",
            json={"mode": "basic", "username": "admin", "password": PASSWORD},
        )
        assert resp.status_code == 200
        assert "sp_session" in resp.cookies
        # The wizard continues with the new session...
        assert (await c.get("/api/config/registry")).status_code == 200
    # ...while anyone else is now locked out of the wizard.
    async with _client(base_url=SETUP_BASE) as other:
        assert (await other.post("/api/setup/auth", json={"mode": "none"})).status_code == 401
        assert (await other.get("/api/config/registry")).status_code == 401


async def test_reset_does_not_reopen_setup_to_strangers(config_path: Path) -> None:
    _basic_config(config_path)
    async with _client() as admin:
        await _login(admin)
        resp = await admin.post("/api/setup/reset", headers={"X-Confirm-Reset": "true"})
        assert resp.status_code == 200
    async with _client() as attacker:
        assert (await attacker.post("/api/setup/auth", json={"mode": "none"})).status_code == 401
    from backend.services.auth_config import get_effective_auth_mode

    assert get_effective_auth_mode() == "basic"


async def test_thresholds_step_keeps_disk_selection(config_path: Path) -> None:
    _write(config_path, {"auth": {"mode": "none"}})
    async with _client() as c:
        assert (
            await c.post("/api/setup/disks", json={"mounts": ["/mnt/media"]})
        ).status_code == 200
        assert (
            await c.post("/api/setup/thresholds", json={"disk_warn_pct": 80})
        ).status_code == 200
    from backend.services.config import load_config

    thresholds = load_config().thresholds
    assert thresholds["disks"] == ["/mnt/media"] and thresholds["disk_warn_pct"] == 80


# --- Proxy auth mode ----------------------------------------------------------------


def _proxy_config(path: Path) -> None:
    _write(
        path,
        {
            "auth": {
                "mode": "proxy",
                "proxy_header": "Remote-User",
                "trusted_proxies": ["172.18.0.5/32"],
                "proxy_hosts": ["panel.test"],
            },
            "setup": {"completed_at": "t"},
        },
    )


async def test_proxy_mode_requires_the_header(config_path: Path) -> None:
    _proxy_config(config_path)
    async with _client(TRUSTED_PROXY) as c:
        assert (await c.get("/api/config")).status_code == 401
        status = (await c.get("/api/auth/status")).json()
        assert status["authenticated"] is False


async def test_proxy_header_from_untrusted_peer_is_ignored(config_path: Path) -> None:
    _proxy_config(config_path)
    async with _client(UNTRUSTED) as c:
        resp = await c.get("/api/config", headers={"Remote-User": "admin"})
        assert resp.status_code == 401


async def test_proxy_header_from_trusted_proxy_is_accepted(config_path: Path) -> None:
    _proxy_config(config_path)
    async with _client(TRUSTED_PROXY) as c:
        assert (await c.get("/api/config", headers={"Remote-User": "admin"})).status_code == 200
        status = (await c.get("/api/auth/status", headers={"Remote-User": "admin"})).json()
        assert status["authenticated"] is True and status["user"] == "admin"


async def test_cannot_switch_to_proxy_mode_without_a_proxy(config_path: Path) -> None:
    _basic_config(config_path)
    async with _client() as c:
        await _login(c)
        resp = await c.put("/api/auth/config", json={"mode": "proxy"})
        assert resp.status_code == 422
        resp = await c.put(
            "/api/auth/config",
            json={"mode": "basic", "username": "admin", "trusted_proxies": ["not-a-cidr"]},
        )
        assert resp.status_code == 422


# --- Cross-origin protections ---------------------------------------------------------


async def test_no_wildcard_cors(config_path: Path) -> None:
    _write(config_path, {"auth": {"mode": "none"}, "setup": {"completed_at": "t"}})
    async with _client() as c:
        resp = await c.get("/api/config", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in resp.headers


async def test_cross_origin_writes_are_refused(config_path: Path) -> None:
    _write(config_path, {"auth": {"mode": "none"}, "setup": {"completed_at": "t"}})
    async with _client() as c:
        evil = {"Origin": "https://evil.example"}
        assert (await c.post("/api/containers/sonarr/stop", headers=evil)).status_code == 403
        sibling = {"Origin": "https://sonarr.panel.test"}
        assert (await c.put("/api/config", json={}, headers=sibling)).status_code == 403
        same = {"Origin": "http://panel.test"}
        assert (await c.put("/api/config", json={}, headers=same)).status_code == 200


def test_websocket_rejects_foreign_origin_and_missing_auth(config_path: Path) -> None:
    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    from backend.main import app

    _basic_config(config_path)
    client = TestClient(app, base_url="http://panel.test")
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/logs/sonarr") as ws:
            ws.receive_text()
    assert exc.value.code == 4401

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(
            "/ws/logs/sonarr", headers={"Origin": "https://evil.example"}
        ) as ws:
            ws.receive_text()
    assert exc.value.code == 4403


# --- Sessions ---------------------------------------------------------------------------


async def test_logout_revokes_the_token(config_path: Path) -> None:
    _basic_config(config_path)
    async with _client() as c:
        await _login(c)
        token = c.cookies["sp_session"]
        await c.post("/api/auth/logout")
    async with _client() as replay:
        replay.cookies.set("sp_session", token)
        assert (await replay.get("/api/config")).status_code == 401


async def test_password_change_logs_out_other_sessions(config_path: Path) -> None:
    _basic_config(config_path)
    async with _client() as other:
        await _login(other)
        async with _client() as me:
            await _login(me)
            resp = await me.put(
                "/api/auth/config",
                json={"mode": "basic", "username": "admin", "password": "a brand new password"},
            )
            assert resp.status_code == 200
            assert (await me.get("/api/config")).status_code == 200
        assert (await other.get("/api/config")).status_code == 401


async def test_session_cookie_flags(config_path: Path) -> None:
    _basic_config(config_path)
    async with _client() as c:
        resp = await c.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
        cookie = resp.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie


def test_wrong_username_still_runs_bcrypt(config_path: Path, monkeypatch) -> None:
    _basic_config(config_path)
    import backend.services.auth as auth_svc

    calls = []
    real = auth_svc.verify_password
    monkeypatch.setattr(auth_svc, "verify_password", lambda p, h: calls.append(h) or real(p, h))
    assert auth_svc.check_credentials("nobody", PASSWORD) is False
    assert calls == [auth_svc._DUMMY_HASH]


async def test_apikey_mode_browser_login(config_path: Path) -> None:
    _write(
        config_path,
        {"auth": {"mode": "apikey", "api_key": "k" * 40}, "setup": {"completed_at": "t"}},
    )
    async with _client() as c:
        assert (await c.post("/api/auth/login", json={"api_key": "wrong"})).status_code == 401
        assert (await c.post("/api/auth/login", json={"api_key": "k" * 40})).status_code == 200
        assert (await c.get("/api/config")).status_code == 200


async def test_rate_limit_ignores_spoofed_forwarded_for(config_path: Path) -> None:
    _basic_config(config_path)
    async with _client(UNTRUSTED) as c:
        codes = []
        for i in range(12):
            resp = await c.post(
                "/api/auth/login",
                json={"username": "admin", "password": "wrong"},
                headers={"X-Forwarded-For": f"198.51.100.{i}"},
            )
            codes.append(resp.status_code)
        assert codes[-1] == 429


# --- Secrets -----------------------------------------------------------------------------


def _with_sonarr(path: Path) -> None:
    _write(
        path,
        {
            "auth": {"mode": "none"},
            "setup": {"completed_at": "t"},
            "services": {"sonarr": {"url": "http://sonarr:8989", "api_key": "REALKEY1234567"}},
            "notifications": {
                "channels": [
                    {
                        "id": "c1",
                        "type": "telegram",
                        "name": "tg",
                        "enabled": True,
                        "config": {"bot_token": "123:SECRETTOKEN", "chat_id": "1"},
                    },
                    {
                        "id": "c2",
                        "type": "email",
                        "name": "mail",
                        "enabled": True,
                        "config": {"smtp_host": "smtp.example.com", "password": "mailpassword"},
                    },
                ],
                "rules": [],
            },
        },
    )


def test_test_endpoint_does_not_send_stored_key_to_new_url(config_path: Path) -> None:
    from backend.services.config import _build_config_for_test

    _with_sonarr(config_path)
    moved = _build_config_for_test(
        "sonarr", {"url": "http://attacker.example", "api_key": "****4567"}
    )
    assert moved.services["sonarr"]["api_key"] == ""
    same = _build_config_for_test("sonarr", {"url": "http://sonarr:8989", "api_key": "****4567"})
    assert same.services["sonarr"]["api_key"] == "REALKEY1234567"


async def test_changing_url_with_masked_key_is_rejected(config_path: Path) -> None:
    _with_sonarr(config_path)
    async with _client() as c:
        resp = await c.put(
            "/api/config",
            json={"services": {"sonarr": {"url": "http://evil:8989", "api_key": "****4567"}}},
        )
        assert resp.status_code == 422
        resp = await c.put(
            "/api/config",
            json={"services": {"sonarr": {"url": "http://sonarr:8989", "api_key": "****4567"}}},
        )
        assert resp.status_code == 200
    from backend.services.config import load_config

    assert load_config().services["sonarr"]["api_key"] == "REALKEY1234567"


async def test_channel_secrets_are_masked_everywhere(config_path: Path) -> None:
    _with_sonarr(config_path)
    async with _client() as c:
        channels = json.dumps((await c.get("/api/notifications/channels")).json())
        config = json.dumps((await c.get("/api/config")).json())
    for blob in (channels, config):
        assert "SECRETTOKEN" not in blob
        assert "mailpassword" not in blob
        assert "REALKEY1234567" not in blob


async def test_thresholds_are_validated(config_path: Path) -> None:
    _write(config_path, {"auth": {"mode": "none"}, "setup": {"completed_at": "t"}})
    async with _client() as c:
        resp = await c.put("/api/config", json={"thresholds": {"disk_warn_pct": "lots"}})
        assert resp.status_code == 422


# --- SSRF ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/",
        "http://[64:ff9b::a9fe:a9fe]/",
        "http://100.100.100.200/",
        "http://metadata.google.internal/",
        "http://[fe80::1]/",
        "file:///etc/passwd",
    ],
)
async def test_outbound_guard_blocks_metadata_and_link_local(url: str) -> None:
    from backend.services.security import check_outbound_url

    assert await check_outbound_url(url) is not None


async def test_outbound_guard_resolves_hostnames(monkeypatch) -> None:
    import asyncio

    from backend.services.security import check_outbound_url

    loop = asyncio.get_running_loop()

    async def fake_getaddrinfo(host, port, **kwargs):
        return [(2, 1, 6, "", ("169.254.169.254", port))]

    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    assert await check_outbound_url("http://rebind.attacker.example/") is not None


@pytest.mark.parametrize("url", ["http://192.168.1.10:8080/ntfy", "http://10.0.0.2/hook"])
async def test_outbound_guard_allows_lan_targets(url: str) -> None:
    from backend.services.security import check_outbound_url

    assert await check_outbound_url(url) is None


async def test_outbound_guard_blocks_docker_tcp_endpoint(monkeypatch) -> None:
    import backend.config as cfg_module
    from backend.services.security import check_outbound_url

    monkeypatch.setattr(
        cfg_module,
        "settings",
        dataclasses.replace(cfg_module.settings, docker_socket="tcp://10.9.9.9:2375"),
    )
    assert await check_outbound_url("http://10.9.9.9:2375/v1.44/containers/json") is not None


# --- Misc surface -----------------------------------------------------------------------------


async def test_docs_require_auth_and_healthz_is_public(config_path: Path) -> None:
    _basic_config(config_path)
    async with _client() as c:
        assert (await c.get("/api/openapi.json")).status_code == 401
        assert (await c.get("/api/docs")).status_code == 401
        assert (await c.get("/api/healthz")).status_code == 200


async def test_calendar_feed_token(config_path: Path) -> None:
    _basic_config(config_path, calendar_token="feedtoken123")
    async with _client() as c:
        assert (await c.get("/api/calendar/feed.ics")).status_code == 401
        assert (await c.get("/api/calendar/feed.ics?token=nope")).status_code == 401
        resp = await c.get("/api/calendar/feed.ics?token=feedtoken123")
        assert resp.status_code == 200
        assert resp.text.startswith("BEGIN:VCALENDAR")
        # The token only opens the feed, nothing else.
        assert (await c.get("/api/config?token=feedtoken123")).status_code == 401


async def test_cannot_stop_or_update_panelarr_itself(config_path: Path) -> None:
    _write(config_path, {"auth": {"mode": "none"}, "setup": {"completed_at": "t"}})
    async with _client() as c:
        assert (await c.post("/api/containers/panelarr/stop")).status_code == 409
        assert (await c.post("/api/containers/panelarr/update")).status_code == 409


# --- Follow-up review findings -----------------------------------------------------------------


async def test_docker_bridge_is_not_trusted_by_default(config_path: Path) -> None:
    """Docker's userland proxy makes every client look like a bridge gateway."""
    _write(
        config_path,
        {"auth": {"mode": "proxy", "proxy_header": "Remote-User"}, "setup": {"completed_at": "t"}},
    )
    async with _client(("172.17.0.1", 40000)) as c:
        assert (await c.get("/api/config", headers={"Remote-User": "admin"})).status_code == 401


async def test_enabling_proxy_mode_trusts_exactly_the_proxy(config_path: Path) -> None:
    _write(config_path, {"auth": {"mode": "none"}, "setup": {"completed_at": "t"}})
    async with _client(("172.19.0.9", 40000)) as c:
        resp = await c.put(
            "/api/auth/config", json={"mode": "proxy"}, headers={"Remote-User": "admin"}
        )
        assert resp.status_code == 200, resp.text
    from backend.services.security import get_trusted_proxies

    assert "172.19.0.9/32" in get_trusted_proxies()
    async with _client(("172.19.0.1", 40000)) as gateway:
        assert (await gateway.get("/api/config", headers={"Remote-User": "x"})).status_code == 401


async def test_invalid_trusted_proxy_env_fails_closed(config_path: Path, monkeypatch) -> None:
    _proxy_config(config_path)
    monkeypatch.setenv("PANELARR_TRUSTED_PROXIES", "garbage")
    async with _client(("127.0.0.1", 40000)) as c:
        assert (await c.get("/api/config", headers={"Remote-User": "admin"})).status_code == 401


def test_test_endpoint_does_not_send_omitted_key_to_new_url(config_path: Path) -> None:
    from backend.services.config import _build_config_for_test

    _with_sonarr(config_path)
    moved = _build_config_for_test("sonarr", {"url": "http://attacker.example:9"})
    assert moved.services["sonarr"]["api_key"] == ""
    explicit = _build_config_for_test(
        "sonarr", {"url": "http://new-host:8989", "api_key": "typed-in-key"}
    )
    assert explicit.services["sonarr"]["api_key"] == "typed-in-key"


async def test_fresh_install_cannot_be_backfilled_open(config_path: Path) -> None:
    async with _client(base_url=SETUP_BASE) as c:
        resp = await c.post(
            "/api/setup/services", json={"services": {"sonarr": {"url": "http://a:1"}}}
        )
        assert resp.status_code in (200, 422)
        # Still a fresh install: everything outside the wizard stays closed.
        resp = await c.get("/api/config")
        assert resp.status_code == 403 and resp.json()["code"] == "setup_required"


async def test_logout_revocation_survives_restart(config_path: Path) -> None:
    import backend.services.auth as auth_svc

    _basic_config(config_path)
    async with _client() as c:
        await _login(c)
        token = c.cookies["sp_session"]
        await c.post("/api/auth/logout")
    auth_svc.reset_secret_cache()  # simulate a restart (in-memory list gone)
    async with _client() as replay:
        replay.cookies.set("sp_session", token)
        assert (await replay.get("/api/config")).status_code == 401


async def test_calendar_token_is_never_created_by_a_request(config_path: Path) -> None:
    _basic_config(config_path)
    async with _client() as c:
        assert (await c.get("/api/calendar/feed.ics?token=guess")).status_code == 401
    assert "calendar_token" not in json.loads(config_path.read_text())["auth"]


async def test_allowed_hosts_blocks_dns_rebinding(config_path: Path, monkeypatch) -> None:
    _write(config_path, {"auth": {"mode": "none"}, "setup": {"completed_at": "t"}})
    monkeypatch.setenv("PANELARR_ALLOWED_HOSTS", "panel.test,192.168.1.5")
    async with _client() as c:
        assert (await c.get("/api/config")).status_code == 200
        assert (await c.get("/api/config", headers={"Host": "rebind.evil"})).status_code == 421


async def test_allowed_hosts_keep_container_healthcheck_working(
    config_path: Path, monkeypatch
) -> None:
    """The image's HEALTHCHECK calls localhost:8000; an allowlist must not make it fail."""
    _write(config_path, {"auth": {"mode": "basic"}, "setup": {"completed_at": "t"}})
    monkeypatch.setenv("PANELARR_ALLOWED_HOSTS", "panelarr.example.com")
    async with _client() as c:
        resp = await c.get("/api/healthz", headers={"Host": "localhost:8000"})
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
        # Only the probe is exempt: every other route still checks the Host.
        assert (await c.get("/api/config", headers={"Host": "localhost:8000"})).status_code == 421
        assert (await c.post("/api/healthz", headers={"Host": "localhost:8000"})).status_code == 421


async def test_self_update_refuses_downgrade(config_path: Path) -> None:
    _write(config_path, {"auth": {"mode": "none"}, "setup": {"completed_at": "t"}})
    async with _client() as c:
        resp = await c.post("/api/system/self-update", json={"version": "0.0.1"})
        assert resp.status_code == 422
