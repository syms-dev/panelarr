"""Regression tests for qBittorrent 5.x compatibility and non-JSON handling in services/arr.py."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from backend.services import arr

REAL_CLIENT = httpx.AsyncClient


def _patch_client(
    monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]
):
    """Route every httpx.AsyncClient created by the code under test to a MockTransport."""

    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs.pop("limits", None)
        return REAL_CLIENT(transport=httpx.MockTransport(handler), **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def _patch_config(monkeypatch: pytest.MonkeyPatch, **svc: str) -> None:
    monkeypatch.setattr(arr, "load_config", lambda: object())
    monkeypatch.setattr(arr, "get_service_config", lambda _cfg, _name: svc)
    monkeypatch.setattr(arr, "_http_client", None)
    arr._qbit_uses_stop_start.clear()


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (200, "Ok.", True),
        (204, "", True),
        (200, "", True),
        (200, "Fails.", False),
        (401, "", False),
        (403, "Forbidden", False),
        (200, "<html>", False),
    ],
)
def test_qbit_login_ok(status: int, body: str, expected: bool) -> None:
    assert arr._qbit_login_ok(httpx.Response(status, text=body)) is expected


@pytest.mark.asyncio
async def test_qbit_stats_with_204_login(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == "/api/v2/auth/login":
            return httpx.Response(204)
        if path == "/api/v2/transfer/info":
            return httpx.Response(200, json={"dl_info_speed": 5, "up_info_speed": 7})
        if path == "/api/v2/torrents/info":
            return httpx.Response(200, json=[{"hash": "a"}])
        return httpx.Response(200, json={})

    _patch_client(monkeypatch, handler)
    _patch_config(monkeypatch, url="http://qb:8080", username="u", password="p")
    out = await arr.get_qbittorrent_stats()
    assert out["downloading"] == 1
    assert out["speed_down"] == 5
    assert "error" not in out


@pytest.mark.asyncio
async def test_qbit_relogin_on_403(monkeypatch: pytest.MonkeyPatch) -> None:
    logins = 0
    calls = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal logins, calls
        if req.url.path == "/api/v2/auth/login":
            logins += 1
            return httpx.Response(200, text="Ok.")
        calls += 1
        if calls == 1:
            return httpx.Response(403)
        return httpx.Response(200, json=[])

    _patch_client(monkeypatch, handler)
    _patch_config(monkeypatch, url="http://qb:8080")
    out = await arr.get_qbittorrent_torrents("seeding")
    assert out == {"configured": True, "torrents": []}
    assert logins == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("action", "new_path", "old_path"),
    [
        ("pause", "/torrents/stop", "/torrents/pause"),
        ("resume", "/torrents/start", "/torrents/resume"),
    ],
)
async def test_qbit_action_prefers_new_and_falls_back(
    monkeypatch: pytest.MonkeyPatch, action: str, new_path: str, old_path: str
) -> None:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v2/auth/login":
            return httpx.Response(200, text="Ok.")
        seen.append(req.url.path)
        if req.url.path.endswith(new_path):
            return httpx.Response(404)
        return httpx.Response(200)

    _patch_client(monkeypatch, handler)
    _patch_config(monkeypatch, url="http://qb:8080")
    assert (await arr.qbittorrent_torrent_action(action, ["a" * 40]))["ok"] is True
    assert seen == [f"/api/v2{new_path}", f"/api/v2{old_path}"]
    # Second call goes straight to the legacy endpoint (cached)
    seen.clear()
    assert (await arr.qbittorrent_torrent_action(action, ["a" * 40]))["ok"] is True
    assert seen == [f"/api/v2{old_path}"]


@pytest.mark.asyncio
async def test_qbit_paused_filter_covers_stopped_and_paused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = [
        {"hash": "1", "state": "pausedUP"},
        {"hash": "2", "state": "stoppedUP"},
        {"hash": "3", "state": "stoppedDL"},
        {"hash": "4", "state": "uploading"},
    ]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v2/auth/login":
            return httpx.Response(204)
        return httpx.Response(200, json=rows)

    _patch_client(monkeypatch, handler)
    _patch_config(monkeypatch, url="http://qb:8080")
    out = await arr.get_qbittorrent_torrents("paused")
    assert [t["hash"] for t in out["torrents"]] == ["1", "2", "3"]


@pytest.mark.asyncio
async def test_arr_html_200_is_graceful(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>login</html>")

    _patch_client(monkeypatch, handler)
    _patch_config(monkeypatch, url="http://sonarr:8989", api_key="k")
    status = await arr.get_arr_status("sonarr")
    assert status["configured"] is True
    assert "error" in status
    queue = await arr.get_arr_queue("sonarr")
    assert queue["records"] == []
    assert await arr.get_radarr_movies() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [httpx.ReadError("boom"), httpx.RemoteProtocolError("bad")])
async def test_arr_transport_errors_are_graceful(
    monkeypatch: pytest.MonkeyPatch, exc: Exception
) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        raise exc

    _patch_client(monkeypatch, handler)
    _patch_config(monkeypatch, url="http://sonarr:8989", api_key="k")
    status = await arr.get_arr_status("sonarr")
    assert status == {"configured": True, "error": "Connection error"}
    assert (await arr.trigger_import_scan("sonarr"))["ok"] is False
