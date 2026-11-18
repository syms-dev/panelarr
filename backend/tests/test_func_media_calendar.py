"""Tests for calendar window parsing, poster URL encoding and the poster proxy."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException

from backend.routers import calendar as cal_router
from backend.routers import media
from backend.services import arr
from backend.services import calendar as cal_service

FALLBACK = datetime(2000, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-03-01", datetime(2026, 3, 1, tzinfo=UTC)),
        ("2026-03-01T00:00:00Z", datetime(2026, 3, 1, tzinfo=UTC)),
        ("2026-02-28T23:00:00.000Z", datetime(2026, 2, 28, 23, tzinfo=UTC)),
        ("2026-03-01T00:00:00+05:30", datetime(2026, 2, 28, 18, 30, tzinfo=UTC)),
        # '+' unescaped in a query string arrives as a space
        ("2026-03-01T00:00:00 05:30", datetime(2026, 2, 28, 18, 30, tzinfo=UTC)),
        ("2026-03-01T00:00:00-08:00", datetime(2026, 3, 1, 8, tzinfo=UTC)),
        ("2026-03-01T10:00:00", datetime(2026, 3, 1, 10, tzinfo=UTC)),
        (None, FALLBACK),
        ("", FALLBACK),
    ],
)
def test_parse_date(value: str | None, expected: datetime) -> None:
    assert cal_router._parse_date(value, fallback=FALLBACK) == expected


@pytest.mark.parametrize("bad", ["tomorrow", "2026-13-45", "2026/03/01", "x" * 100])
def test_parse_date_rejects_garbage(bad: str) -> None:
    with pytest.raises(HTTPException) as exc:
        cal_router._parse_date(bad, fallback=FALLBACK)
    assert exc.value.status_code == 400


def test_soonest_release_end_is_exclusive() -> None:
    start = datetime(2026, 3, 1, tzinfo=UTC)
    end = datetime(2026, 4, 1, tzinfo=UTC)
    on_end = {"digitalRelease": "2026-04-01T00:00:00Z"}
    last_instant = {"digitalRelease": "2026-03-31T23:59:59Z"}
    at_start = {"digitalRelease": "2026-03-01T00:00:00Z"}
    assert cal_service._soonest_release(on_end, start, end) is None
    assert cal_service._soonest_release(last_instant, start, end) is not None
    assert cal_service._soonest_release(at_start, start, end) is not None


def test_poster_url_is_encoded() -> None:
    url = arr.poster_proxy_url("https://image.tmdb.org/p/x.jpg?a=1&b=2#frag")
    assert url == "/api/media/poster?url=https://image.tmdb.org/p/x.jpg%3Fa%3D1%26b%3D2%23frag"
    local = arr.poster_proxy_url("/MediaCover/5/poster.jpg?lastWrite=1", "sonarr")
    assert local.endswith("&source=sonarr")
    assert "%3FlastWrite%3D1" in local
    # remote URLs never get a source param
    assert "source=" not in arr.poster_proxy_url("https://a/b.jpg", "sonarr")


def _patch_arr_config(monkeypatch: pytest.MonkeyPatch, url: str = "http://sonarr:8989") -> None:
    monkeypatch.setattr(media, "load_config", lambda: object())
    monkeypatch.setattr(
        media, "get_service_config", lambda _c, _n: {"url": url, "api_key": "KEY"} if url else {}
    )


@pytest.mark.parametrize(
    "path",
    [
        "/MediaCover/../../etc/passwd",
        "/MediaCover/%2e%2e/x",
        "/MediaCover/1/..%2f..%2fapi",
        "/api/v3/system",
        "//evil.com/MediaCover/x",
        "/MediaCover/http://evil",
        "/mediacover/1/p.jpg",
    ],
)
def test_arr_cover_target_rejects_bad_paths(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    _patch_arr_config(monkeypatch)
    assert media._arr_cover_target(path, "sonarr") is None


def test_arr_cover_target_ok_and_source_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_arr_config(monkeypatch)
    target = media._arr_cover_target("/MediaCover/5/poster.jpg?lastWrite=1", "sonarr")
    assert target == (
        "http://sonarr:8989/MediaCover/5/poster.jpg?lastWrite=1",
        {"X-Api-Key": "KEY"},
    )
    assert media._arr_cover_target("/MediaCover/5/poster.jpg", "plex") is None
    assert media._arr_cover_target("/MediaCover/5/poster.jpg", None) is None


@pytest.mark.asyncio
async def test_poster_proxy_serves_arr_cover_with_api_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_arr_config(monkeypatch)
    monkeypatch.setattr(media, "resolve_config_path", lambda: tmp_path / "panelarr.json")
    seen: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["url"] = str(req.url)
        seen["key"] = req.headers.get("x-api-key", "")
        return httpx.Response(200, content=b"\xff\xd8img", headers={"content-type": "image/jpeg"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def fake_client() -> httpx.AsyncClient:
        return client

    monkeypatch.setattr(media, "_get_poster_client", fake_client)
    resp = await media.poster_proxy("/MediaCover/5/poster.jpg", "sonarr")
    assert resp.status_code == 200
    assert seen == {"url": "http://sonarr:8989/MediaCover/5/poster.jpg", "key": "KEY"}
    assert list((tmp_path / "poster_cache").iterdir())  # cached under the config dir

    forbidden = await media.poster_proxy("/MediaCover/5/poster.jpg", None)
    assert forbidden.status_code == 403
    await client.aclose()


def test_cache_dir_follows_config_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(media, "resolve_config_path", lambda: tmp_path / "cfg" / "panelarr.json")
    assert media.poster_cache_dir() == tmp_path / "cfg" / "poster_cache"


def test_eviction_removes_oldest_first_and_is_throttled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(media, "resolve_config_path", lambda: tmp_path / "panelarr.json")
    cache = tmp_path / "poster_cache"
    cache.mkdir()
    import os

    for i, name in enumerate(("old", "mid", "new")):
        p = cache / f"{name}.jpg"
        p.write_bytes(b"x" * 100)
        os.utime(p, (1000 + i, 1000 + i))
    media._evict_poster_cache(max_bytes=150)
    assert [p.name for p in cache.iterdir()] == ["new.jpg"]

    media._last_evict_at = None
    assert media._should_evict() is True
    assert media._should_evict() is False


def test_first_eviction_runs_right_after_boot(monkeypatch: pytest.MonkeyPatch) -> None:
    """monotonic() starts near 0 on a freshly booted host; the first sweep must still run."""
    monkeypatch.setattr(media, "_last_evict_at", None)
    monkeypatch.setattr(media.time, "monotonic", lambda: 5.0)
    assert media._should_evict() is True
    assert media._should_evict() is False
