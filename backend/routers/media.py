from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from pathlib import Path
from urllib.parse import unquote, urlparse

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, Response

from backend.services.arr import (
    add_movie,
    add_show,
    get_quality_profiles,
    get_radarr_movie_detail,
    get_radarr_movies,
    get_sonarr_series,
    get_sonarr_series_detail,
    poster_proxy_url,
    search_movies,
    search_shows,
    trigger_episode_search,
    trigger_movie_search,
    trigger_search_missing,
    trigger_season_search,
)
from backend.services.config import get_service_config, load_config, resolve_config_path
from backend.services.security import RASTER_IMAGE_TYPES

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/media", tags=["media"])

POSTER_TIMEOUT = 10
POSTER_CACHE_MAX_BYTES = 500 * 1024 * 1024
POSTER_EVICT_INTERVAL = 60.0  # seconds between eviction sweeps

_last_evict_at: float = 0.0


def poster_cache_dir() -> Path:
    """Directory for cached posters, next to the (writable) resolved config file."""
    return resolve_config_path().parent / "poster_cache"


def _evict_poster_cache(max_bytes: int = POSTER_CACHE_MAX_BYTES) -> None:
    """Evict oldest cached posters when total size exceeds max_bytes (blocking)."""
    cache_dir = poster_cache_dir()
    if not cache_dir.is_dir():
        return
    entries: list[tuple[float, int, Path]] = []
    for p in cache_dir.iterdir():
        try:
            st = p.stat()
        except OSError:
            continue  # vanished between listdir and stat
        entries.append((st.st_mtime, st.st_size, p))
    entries.sort(key=lambda e: e[0])
    total = sum(e[1] for e in entries)
    for _mtime, size, path in entries:
        if total <= max_bytes:
            break
        path.unlink(missing_ok=True)
        total -= size


def _store_poster(cache_path: Path, content: bytes, *, evict: bool) -> None:
    """Write a poster to the cache and optionally sweep old entries (blocking)."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if evict:
        _evict_poster_cache()
    cache_path.write_bytes(content)


def _should_evict() -> bool:
    """Throttle eviction sweeps to once per POSTER_EVICT_INTERVAL."""
    global _last_evict_at
    now = time.monotonic()
    if now - _last_evict_at >= POSTER_EVICT_INTERVAL:
        _last_evict_at = now
        return True
    return False


_poster_client: httpx.AsyncClient | None = None
_poster_client_lock = asyncio.Lock()


async def _get_poster_client() -> httpx.AsyncClient:
    global _poster_client
    if _poster_client is None or _poster_client.is_closed:
        async with _poster_client_lock:
            if _poster_client is None or _poster_client.is_closed:
                _poster_client = httpx.AsyncClient(
                    timeout=POSTER_TIMEOUT,
                    limits=httpx.Limits(max_connections=20),
                )
    return _poster_client


def _proxy_images(item: dict, source: str | None = None) -> dict:
    """Replace poster and fanart URLs with (URL-encoded) proxy URLs."""
    for key in ("poster", "fanart", "banner"):
        if item.get(key):
            item[key] = poster_proxy_url(item[key], source)
    return item


@router.get("/movies")
async def list_movies() -> list[dict]:
    movies = await get_radarr_movies()
    for m in movies:
        if m.get("poster"):
            m["poster"] = poster_proxy_url(m["poster"], "radarr")
    return movies


@router.get("/shows")
async def list_shows() -> list[dict]:
    shows = await get_sonarr_series()
    for s in shows:
        if s.get("poster"):
            s["poster"] = poster_proxy_url(s["poster"], "sonarr")
    return shows


@router.get("/movies/quality-profiles")
async def movie_quality_profiles() -> list[dict]:
    return await get_quality_profiles("radarr")


@router.get("/shows/quality-profiles")
async def show_quality_profiles() -> list[dict]:
    return await get_quality_profiles("sonarr")


@router.get("/movies/search")
async def movie_search(q: str) -> list[dict]:
    if len(q) < 2 or len(q) > 200:
        return []
    results = await search_movies(q)
    for m in results:
        if m.get("poster"):
            m["poster"] = poster_proxy_url(m["poster"], "radarr")
    return results


@router.post("/movies/add")
async def movie_add(body: dict) -> dict:
    tmdb_id = body.get("tmdbId")
    if not tmdb_id:
        return {"ok": False, "message": "tmdbId required"}
    quality = body.get("qualityProfileId", 0)
    return await add_movie(int(tmdb_id), int(quality))


@router.get("/shows/search")
async def show_search(q: str) -> list[dict]:
    if len(q) < 2 or len(q) > 200:
        return []
    results = await search_shows(q)
    for s in results:
        if s.get("poster"):
            s["poster"] = poster_proxy_url(s["poster"], "sonarr")
    return results


@router.post("/shows/add")
async def show_add(body: dict) -> dict:
    tvdb_id = body.get("tvdbId")
    if not tvdb_id:
        return {"ok": False, "message": "tvdbId required"}
    quality = body.get("qualityProfileId", 0)
    return await add_show(int(tvdb_id), int(quality))


@router.get("/shows/{show_id}")
async def show_detail(show_id: int) -> dict:
    detail = await get_sonarr_series_detail(show_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Not found")
    return _proxy_images(detail, "sonarr")


@router.get("/movies/{movie_id}")
async def movie_detail(movie_id: int) -> dict:
    detail = await get_radarr_movie_detail(movie_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Not found")
    return _proxy_images(detail, "radarr")


@router.post("/movies/{movie_id}/search")
async def search_movie(movie_id: int) -> dict:
    """Trigger a Radarr search for a specific movie."""
    return await trigger_movie_search(movie_id)


@router.post("/shows/{show_id}/search-missing")
async def search_missing_episodes(show_id: int) -> dict:
    """Search for all missing episodes of a show."""
    return await trigger_search_missing("sonarr", show_id)


@router.post("/shows/{show_id}/search-season/{season_number}")
async def search_season(show_id: int, season_number: int) -> dict:
    """Search for all episodes in a specific season."""
    return await trigger_season_search(show_id, season_number)


@router.post("/shows/search-episodes")
async def search_episodes(body: dict) -> dict:
    """Search for specific episodes by ID."""
    episode_ids = body.get("episodeIds", [])
    if not episode_ids or not isinstance(episode_ids, list):
        return {"ok": False, "message": "episodeIds required"}
    return await trigger_episode_search(episode_ids)


ALLOWED_POSTER_HOSTS = {
    "image.tmdb.org",
    "artworks.thetvdb.com",
    "assets.fanart.tv",
    "www.thetvdb.com",
    "thetvdb.com",
}


_ARR_COVER_SOURCES = frozenset({"sonarr", "radarr"})


def _arr_cover_target(path: str, source: str | None) -> tuple[str, dict[str, str]] | None:
    """Resolve an Arr-local ``/MediaCover/...`` path to (absolute URL, auth headers).

    Returns None unless ``source`` is a configured Arr service and the path is a
    plain ``/MediaCover/`` path (no scheme, no traversal, no backslashes).
    """
    if source not in _ARR_COVER_SOURCES:
        return None
    route = path.split("?", 1)[0]
    decoded = unquote(route)
    if (
        not route.startswith("/MediaCover/")
        or "://" in path
        or "\\" in decoded
        or any(seg == ".." for seg in decoded.split("/"))
        or not decoded.startswith("/MediaCover/")
    ):
        return None
    svc = get_service_config(load_config(), source)
    base, api_key = (svc.get("url") or "").rstrip("/"), svc.get("api_key", "")
    if not base or not api_key:
        return None
    return f"{base}{path}", {"X-Api-Key": api_key}


@router.get("/poster")
async def poster_proxy(url: str, source: str | None = None) -> Response:
    """Proxy and cache poster images.

    Absolute URLs must be HTTPS on a known image CDN. Arr-local ``/MediaCover/``
    paths are fetched from the configured Arr service (``source``) with its API key.
    """
    if not url:
        return Response(status_code=404)

    headers: dict[str, str] = {}
    if url.startswith("/"):
        target = _arr_cover_target(url, source)
        if target is None:
            return Response(status_code=403)
        fetch_url, headers = target
        cache_input = f"{source}:{url}"
    else:
        # Must be HTTPS from an allowed host
        if not url.startswith("https://"):
            return Response(status_code=403)
        parsed = urlparse(url)
        if parsed.hostname not in ALLOWED_POSTER_HOSTS:
            return Response(status_code=403)
        fetch_url, cache_input = url, url

    # Generate cache key from URL
    url_hash = hashlib.md5(cache_input.encode()).hexdigest()
    cache_path = poster_cache_dir() / f"{url_hash}.jpg"

    # Serve from cache if exists
    if cache_path.is_file():
        return FileResponse(
            cache_path,
            media_type="image/jpeg",
            headers={"Cache-Control": "private, max-age=604800"},  # 7 days
        )

    # Fetch from remote
    try:
        client = await _get_poster_client()
        resp = await client.get(fetch_url, headers=headers)
        if resp.status_code != 200:
            return Response(status_code=404)

        # Raster images only (no SVG, which can carry script)
        content_type = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type not in RASTER_IMAGE_TYPES:
            return Response(status_code=415)

        # Reject oversized responses (max 10 MB)
        if len(resp.content) > 10 * 1024 * 1024:
            return Response(status_code=413)

        # Cache write + (throttled) eviction run off the event loop
        await asyncio.to_thread(_store_poster, cache_path, resp.content, evict=_should_evict())

        return Response(
            content=resp.content,
            media_type=content_type,
            headers={"Cache-Control": "private, max-age=604800"},
        )
    except Exception:
        return Response(status_code=404)
