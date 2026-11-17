from __future__ import annotations

import asyncio
import logging
import re

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from backend.services.auth import authenticate
from backend.services.config import ConfigError
from backend.services.docker import get_container_logs, stream_container_logs
from backend.services.security import origin_allowed

logger = logging.getLogger(__name__)

router = APIRouter(tags=["logs"])

CONTAINER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$")

MAX_LOG_STREAMS = 50
_active_log_streams = 0

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _check_ws_auth(websocket: WebSocket) -> bool:
    """Same rules as the HTTP middleware (see ``services.auth.authenticate``)."""
    from backend.services.auth_config import is_auth_configured

    try:
        if not is_auth_configured():
            return False
        return authenticate(websocket) is not None
    except ConfigError:
        return False


@router.get("/api/logs/{container_name}")
async def get_logs(
    container_name: str,
    lines: int = Query(default=200, ge=1, le=5000),
) -> dict:
    if not CONTAINER_NAME_RE.match(container_name):
        return {"container": container_name, "lines": [], "error": "Invalid container name"}
    log_lines = await get_container_logs(container_name, lines)
    return {"container": container_name, "lines": [_strip_ansi(line) for line in log_lines]}


async def _reject(websocket: WebSocket, code: int, reason: str) -> None:
    # Closing before accept() turns into a bare HTTP 403 and the browser only
    # sees code 1006, so accept first to deliver a meaningful close code.
    await websocket.accept()
    await websocket.close(code=code, reason=reason)


async def _pump_logs(websocket: WebSocket, container_name: str) -> None:
    async for line in stream_container_logs(container_name):
        await websocket.send_text(_strip_ansi(line))
        await asyncio.sleep(0)
    await websocket.send_text("[Stream ended, container stopped]")
    await websocket.close(code=4000, reason="Container stopped")


async def _wait_for_disconnect(websocket: WebSocket) -> None:
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return


@router.websocket("/ws/logs/{container_name}")
async def ws_stream_logs(websocket: WebSocket, container_name: str) -> None:
    global _active_log_streams
    if not origin_allowed(websocket):
        await _reject(websocket, 4403, "Cross-origin connection refused")
        return
    if not _check_ws_auth(websocket):
        await _reject(websocket, 4401, "Authentication required")
        return
    if not CONTAINER_NAME_RE.match(container_name):
        await _reject(websocket, 4400, "Invalid container name")
        return
    if _active_log_streams >= MAX_LOG_STREAMS:
        await _reject(websocket, 4429, "Too many log streams")
        return
    _active_log_streams += 1
    await websocket.accept()
    # Watch for the client going away so a quiet container doesn't keep the
    # Docker stream (and a stream slot) open forever.
    pump = asyncio.create_task(_pump_logs(websocket, container_name))
    watcher = asyncio.create_task(_wait_for_disconnect(websocket))
    try:
        done, _ = await asyncio.wait({pump, watcher}, return_when=asyncio.FIRST_COMPLETED)
        if pump in done and pump.exception() is not None:
            exc = pump.exception()
            if not isinstance(exc, (WebSocketDisconnect, RuntimeError)):
                logger.error("Log streaming error for %s: %r", container_name, exc)
                try:
                    await websocket.close(code=1011)
                except RuntimeError:
                    pass
    finally:
        for task in (pump, watcher):
            task.cancel()
        await asyncio.gather(pump, watcher, return_exceptions=True)
        _active_log_streams -= 1
