from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.routers import (
    arr,
    auth,
    calendar,
    config,
    containers,
    downloads,
    logs,
    media,
    notifications,
    setup,
    system,
)
from backend.services.arr import close_http_client
from backend.services.auth import authenticate
from backend.services.auth_config import (
    backfill_legacy_setup,
    get_effective_auth_mode,
    is_auth_configured,
)
from backend.services.config import ConfigError, load_config
from backend.services.security import (
    host_allowed,
    is_state_changing,
    origin_allowed,
    setup_host_allowed,
)

_log = logging.getLogger("panelarr.startup")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: report config/auth problems on startup, close
    shared HTTP clients on shutdown."""
    try:
        try:
            load_config()
            backfill_legacy_setup()
            if is_auth_configured() and get_effective_auth_mode() == "none":
                _log.warning(
                    "Panelarr is running without authentication. "
                    "Set an auth mode under Settings → Authentication for security."
                )
            elif not is_auth_configured():
                _log.warning(
                    "Setup has not been completed. Open Panelarr and finish the setup "
                    "wizard before exposing it to other machines."
                )
        except ConfigError as exc:
            _log.error(
                "panelarr.json is invalid, so the API is disabled until it is fixed or removed: %s",
                exc,
            )
        yield
    finally:
        await close_http_client()


def _get_version() -> str:
    """Read version from package metadata (set by pyproject.toml)."""
    from importlib.metadata import version

    try:
        return version("panelarr")
    except Exception:
        return "0.0.0-dev"


app = FastAPI(
    title="Panelarr",
    version=_get_version(),
    description="Self-hosted control center for Docker-based media server stacks",
    lifespan=lifespan,
    # Docs live under /api so the auth middleware covers them.
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
    # FastAPI otherwise serves /docs/oauth2-redirect outside /api, unauthenticated.
    swagger_ui_oauth2_redirect_url=None,
)

# No CORS middleware: the SPA is served from the same origin, and allowing
# other origins would let any website drive the API from a user's browser.

# Reachable without authentication in every mode.
_PUBLIC_PATHS = {
    "/api/healthz",
    "/api/setup/status",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/status",
}
_CALENDAR_FEED = "/api/calendar/feed.ics"


def _calendar_token_ok(request: Request) -> bool:
    import secrets

    provided = request.query_params.get("token", "")
    if not provided:
        return False
    # Read only: an unauthenticated request must never create the token.
    expected = (load_config().auth or {}).get("calendar_token", "")
    if not expected:
        return False
    return secrets.compare_digest(provided.encode(), expected.encode())


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Authenticate every /api request.

    WebSockets do not pass through HTTP middleware; ``routers/logs.py``
    applies the same ``authenticate`` and ``origin_allowed`` checks itself.
    """
    path = request.url.path
    if not path.startswith("/api/"):
        # SPA shell and static assets; the frontend handles redirects.
        return await call_next(request)

    # Before the Host check: the image's HEALTHCHECK calls localhost:8000, and
    # with PANELARR_ALLOWED_HOSTS set the container would never turn healthy
    # (Traefik then won't route to it). The answer is a constant.
    if path == "/api/healthz" and request.method in ("GET", "HEAD"):
        return await call_next(request)

    if not host_allowed(request):
        return JSONResponse(status_code=421, content={"detail": "Unknown host"})

    if is_state_changing(request.method) and not origin_allowed(request):
        return JSONResponse(status_code=403, content={"detail": "Cross-origin request refused"})

    if path == "/api/healthz":
        return await call_next(request)

    try:
        if path in _PUBLIC_PATHS:
            return await call_next(request)

        if path == _CALENDAR_FEED and request.method == "GET" and _calendar_token_ok(request):
            return await call_next(request)

        if not is_auth_configured():
            # Fresh install: only the wizard is reachable until its auth step
            # has been saved. /setup/reset is never public.
            if path.startswith("/api/setup/") and path != "/api/setup/reset":
                if not setup_host_allowed(request):
                    return JSONResponse(
                        status_code=421,
                        content={
                            "detail": (
                                "Run setup through Panelarr's IP address or localhost, or add "
                                "this hostname to PANELARR_ALLOWED_HOSTS."
                            ),
                            "code": "setup_host",
                        },
                    )
                return await call_next(request)
            return JSONResponse(
                status_code=403,
                content={"detail": "Setup required", "code": "setup_required"},
            )

        if authenticate(request) is not None:
            return await call_next(request)
    except ConfigError as exc:
        return JSONResponse(
            status_code=503,
            content={
                "detail": f"panelarr.json is invalid, fix or remove it: {exc}",
                "code": "config_invalid",
            },
        )

    apikey_mode = get_effective_auth_mode() == "apikey"
    detail = "Valid API key required" if apikey_mode else "Authentication required"
    return JSONResponse(status_code=401, content={"detail": detail})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add security response headers."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if request.url.path == "/api/docs":
        # Swagger UI loads its bundle from a CDN.
        csp = (
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'"
        )
    else:
        csp = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; connect-src 'self' ws: wss:; font-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
    response.headers["Content-Security-Policy"] = csp
    if request.url.path.startswith("/api/") and "cache-control" not in response.headers:
        # API answers carry configuration and service data: keep them out of
        # browser and proxy caches. Image proxies set their own (private) policy.
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/healthz", include_in_schema=False)
async def healthz() -> dict:
    """Unauthenticated liveness probe for the container HEALTHCHECK."""
    return {"status": "ok"}


app.include_router(setup.router)
app.include_router(auth.router)
app.include_router(containers.router)
app.include_router(arr.router)
app.include_router(system.router)
app.include_router(logs.router)
app.include_router(config.router)
app.include_router(downloads.router)
app.include_router(media.router)
app.include_router(notifications.router)
app.include_router(calendar.router)

# Serve built frontend assets in production
static_dir = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if static_dir.is_dir():
    from fastapi.responses import FileResponse

    # Mount static assets (JS, CSS, fonts, images)
    app.mount("/assets", StaticFiles(directory=str(static_dir / "assets")), name="assets")

    # Serve static files that exist (favicon, logos, etc.)
    @app.get("/{path:path}")
    async def spa_fallback(path: str) -> FileResponse:
        """Serve static files or fall back to index.html for SPA routing."""
        if path == "api" or path.startswith("api/"):
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="Not found")
        file_path = (static_dir / path).resolve()
        # Prevent path traversal, file must be within static_dir
        if not file_path.is_relative_to(static_dir.resolve()):
            return FileResponse(static_dir / "index.html")
        if file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(static_dir / "index.html")
