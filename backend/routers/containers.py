from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException

from backend.services.docker import (
    check_container_updates,
    container_action,
    get_container,
    list_containers,
    pull_and_recreate,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/containers", tags=["containers"])

CONTAINER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$")


def _validate_name(name: str) -> None:
    if not CONTAINER_NAME_RE.match(name):
        raise HTTPException(status_code=422, detail="Invalid container name")


def _socket_proxy_host() -> str | None:
    from backend.config import settings

    sock = settings.docker_socket
    if sock.startswith(("tcp://", "http://", "https://")):
        return (urlparse(sock.replace("tcp://", "http://", 1)).hostname or "").lower() or None
    return None


async def _guard_critical(name: str, action: str) -> None:
    """Refuse stop/update on Panelarr itself and on its Docker socket proxy.

    Stopping or recreating either cuts Panelarr off mid-request and leaves it
    down. Panelarr updates itself through Settings → Update instead.
    """
    lowered = name.lower()
    if lowered == "panelarr":
        raise HTTPException(
            status_code=409,
            detail=f"Panelarr can't {action} its own container; use Settings → Update",
        )
    proxy = _socket_proxy_host()
    if proxy and lowered == proxy:
        raise HTTPException(
            status_code=409,
            detail=f"Refusing to {action} the Docker socket proxy Panelarr depends on",
        )
    own_id = os.getenv("HOSTNAME", "")
    if len(own_id) >= 12:
        try:
            container = await get_container(name)
        except Exception:  # noqa: BLE001, Docker unavailable is reported by the action
            return
        cid = str((container or {}).get("id", ""))
        if cid and (cid.startswith(own_id) or own_id.startswith(cid[:12])):
            raise HTTPException(
                status_code=409,
                detail=f"Panelarr can't {action} its own container; use Settings → Update",
            )


@router.get("")
async def get_containers(show_all: bool = True) -> list[dict]:
    try:
        return await list_containers(show_all=show_all)
    except Exception as exc:
        logger.error("Docker error listing containers: %s", exc)
        raise HTTPException(status_code=503, detail="Docker unavailable") from exc


_last_update_check: float = 0.0
_last_update_result: dict | None = None
_update_lock = asyncio.Lock()
_UPDATE_CHECK_COOLDOWN = 60  # seconds between full registry scans


def invalidate_update_cache() -> None:
    global _last_update_check
    _last_update_check = 0.0


@router.get("/check-updates")
async def check_updates() -> dict:
    """Check all containers for available image updates.

    Registry scans are slow and rate-limited upstream, so results are cached
    for a minute; callers inside that window get the cached result.
    """
    global _last_update_check, _last_update_result
    async with _update_lock:
        now = time.monotonic()
        if _last_update_result is not None and now - _last_update_check < _UPDATE_CHECK_COOLDOWN:
            return _last_update_result
        try:
            containers = await list_containers(show_all=True)
        except Exception as exc:
            logger.error("Docker error checking updates: %s", exc)
            raise HTTPException(status_code=503, detail="Docker unavailable") from exc
        results = await check_container_updates(containers)
        updates_available = sum(1 for r in results.values() if r.get("has_update"))
        _last_update_result = {"updates": results, "updates_available": updates_available}
        _last_update_check = now
        return _last_update_result


@router.get("/{name}")
async def get_container_detail(name: str) -> dict:
    _validate_name(name)
    try:
        container = await get_container(name)
    except Exception as exc:
        logger.error("Docker error getting container %s: %s", name, exc)
        raise HTTPException(status_code=503, detail="Docker unavailable") from exc
    if not container:
        raise HTTPException(status_code=404, detail="Container not found")
    return container


@router.post("/{name}/restart")
async def restart_container(name: str) -> dict:
    _validate_name(name)
    return await container_action(name, "restart")


@router.post("/{name}/start")
async def start_container(name: str) -> dict:
    _validate_name(name)
    return await container_action(name, "start")


@router.post("/{name}/stop")
async def stop_container(name: str) -> dict:
    _validate_name(name)
    await _guard_critical(name, "stop")
    return await container_action(name, "stop")


@router.post("/{name}/update")
async def update_container(name: str) -> dict:
    _validate_name(name)
    await _guard_critical(name, "update")
    result = await pull_and_recreate(name)
    invalidate_update_cache()
    return result
