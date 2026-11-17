from __future__ import annotations

import asyncio
import ipaddress
import os
import secrets
import time
from collections import OrderedDict

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from backend.services.auth import (
    APIKEY_SESSION_SUB,
    COOKIE_NAME,
    TOKEN_EXPIRY_HOURS,
    authenticate,
    check_credentials,
    create_token,
    get_credentials,
    revoke_token,
    validate_api_key,
)
from backend.services.auth_config import (
    get_effective_auth_mode,
    get_effective_proxy_header,
    get_or_create_calendar_token,
    is_auth_writable,
    set_auth_in_config,
)
from backend.services.config import AUTH_MODES
from backend.services.security import (
    client_ip,
    effective_trusted_proxies,
    get_trusted_proxies,
    is_trusted_proxy,
    looks_like_docker_gateway,
    parse_cidrs,
    peer_host,
    request_host_name,
    request_is_https,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

# In-memory rate limiter: max 10 attempts per client per 60 seconds, capped at
# 10k tracked clients to bound memory. IPv6 clients are bucketed by /64 so an
# attacker cannot get a fresh budget per address.
_login_attempts: OrderedDict[str, list[float]] = OrderedDict()
RATE_LIMIT_MAX = 10
_RATE_LIMIT_MAX_IPS = 10_000
RATE_LIMIT_WINDOW = 60


def _rate_key(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip or "unknown"
    if isinstance(addr, ipaddress.IPv6Address) and not addr.ipv4_mapped:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr.ipv4_mapped or addr) if isinstance(addr, ipaddress.IPv6Address) else str(addr)


def _check_rate_limit(ip: str) -> bool:
    """Return True if the request is within rate limits."""
    key = _rate_key(ip)
    now = time.monotonic()
    attempts = [t for t in _login_attempts.get(key, []) if now - t < RATE_LIMIT_WINDOW]
    if len(attempts) >= RATE_LIMIT_MAX:
        _login_attempts[key] = attempts
        return False
    attempts.append(now)
    _login_attempts[key] = attempts
    _login_attempts.move_to_end(key)
    while len(_login_attempts) > _RATE_LIMIT_MAX_IPS:
        _login_attempts.popitem(last=False)
    return True


def issue_session(response: Response, request: Request, subject: str) -> None:
    """Set a fresh session cookie for ``subject`` on ``response``."""
    response.set_cookie(
        key=COOKIE_NAME,
        value=create_token(subject),
        httponly=True,
        # Strict costs nothing here: the SPA shell needs no cookie, and every
        # API call is made from Panelarr's own pages.
        samesite="strict",
        path="/",
        max_age=TOKEN_EXPIRY_HOURS * 3600,
        secure=request_is_https(request) or _forwarded_https(request),
    )


def _forwarded_https(request: Request) -> bool:
    """True if any peer says the browser is on HTTPS.

    Unlike ``request_is_https`` this needs no trusted proxy: the answer only
    makes the cookie stricter (``Secure``), so a forged header harms nobody,
    while ignoring it would send the session over plain HTTP behind a proxy
    that terminates TLS but is not in the trusted list.
    """
    proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return proto == "https"


def require_proxy_auth_on(
    request: Request, header: str, requested: list[str] | None = None
) -> list[str] | None:
    """Refuse to enable proxy mode unless this request proves it works.

    Saves nothing: returns the trusted-proxy list to write together with the
    mode, or None to keep the current one. ``requested`` is a list sent in the
    same request; the header must then come from an address in it.

    Otherwise, if the header arrives from an address that is not yet trusted
    and the owner has not configured the list explicitly, exactly that address
    is trusted (/32 or /128): the owner is, right now, talking to Panelarr
    through it. A Docker network gateway is never trusted this way, because
    every client of a published port can appear from it.
    """
    peer = peer_host(request)
    if not request.headers.get(header, "").strip():
        raise HTTPException(
            status_code=422,
            detail=(
                f"This request has no {header} header. Open Panelarr through your "
                "authenticating reverse proxy before switching to proxy mode."
            ),
        )
    if requested is not None:
        if is_trusted_proxy(peer, effective_trusted_proxies(requested)):
            return requested
        raise HTTPException(
            status_code=422,
            detail=(
                f"The {header} header came from {peer or 'an unknown address'}, which is "
                "not in the trusted proxies list you entered."
            ),
        )
    if is_trusted_proxy(peer):
        return None
    from backend.services.config import load_config

    explicit = (load_config().auth or {}).get("trusted_proxies")
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        addr = None
    if explicit or os.getenv("PANELARR_TRUSTED_PROXIES") or addr is None:
        raise HTTPException(
            status_code=422,
            detail=(
                f"The {header} header came from {peer or 'an unknown address'}, which is "
                "not a trusted proxy. Add it to the trusted proxies list first."
            ),
        )
    if looks_like_docker_gateway(peer):
        raise HTTPException(
            status_code=422,
            detail=(
                f"The {header} header came from {peer}, which looks like a Docker network "
                "gateway: every client of a published port can appear from that address, so "
                "it is not trusted automatically. Put your proxy on Panelarr's Docker network "
                "and open Panelarr through it, or add the address to the trusted proxies list "
                "only if nothing else can reach Panelarr from it."
            ),
        )
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return [*get_trusted_proxies(), f"{addr}/{addr.max_prefixlen}"]


def proxy_hosts_with(request: Request) -> list[str]:
    """The pinned proxy hostnames plus the one this request came through."""
    from backend.services.config import load_config

    current = (load_config().auth or {}).get("proxy_hosts")
    hosts = [str(h).lower() for h in current] if isinstance(current, list) else []
    name = request_host_name(request)
    if name and name not in hosts:
        hosts.append(name)
    return hosts


def _validated_cidrs(values: list[str] | None) -> list[str] | None:
    if values is None:
        return None
    cleaned = [v.strip() for v in values if v and v.strip()]
    try:
        parse_cidrs(cleaned)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return cleaned


class LoginRequest(BaseModel):
    username: str | None = None
    password: str | None = None
    api_key: str | None = None


@router.post("/login")
async def login(body: LoginRequest, request: Request) -> JSONResponse:
    mode = get_effective_auth_mode()
    if mode not in ("basic", "apikey"):
        return JSONResponse(
            status_code=400,
            content={"detail": "Login not available in this auth mode"},
        )

    if not _check_rate_limit(client_ip(request)):
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many login attempts. Try again in a minute."},
        )

    if mode == "apikey":
        if not body.api_key or not validate_api_key(body.api_key):
            return JSONResponse(status_code=401, content={"detail": "Invalid API key"})
        response = JSONResponse(content={"ok": True, "user": None})
        issue_session(response, request, APIKEY_SESSION_SUB)
        return response

    username, _ = get_credentials()
    if not username:
        return JSONResponse(
            status_code=500,
            content={
                "detail": "No credentials configured, run setup or configure auth in Settings"
            },
        )

    ok = await asyncio.to_thread(check_credentials, body.username or "", body.password or "")
    if not ok:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid username or password"},
        )

    response = JSONResponse(content={"ok": True, "user": username})
    issue_session(response, request, username)
    return response


@router.post("/logout")
async def logout(request: Request) -> JSONResponse:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        revoke_token(token)
    response = JSONResponse(content={"ok": True})
    response.delete_cookie(key=COOKIE_NAME, path="/")
    return response


@router.get("/status")
async def auth_status(request: Request) -> dict:
    mode = get_effective_auth_mode()
    principal = authenticate(request)
    authenticated = principal is not None
    user = None
    if mode == "basic" and authenticated and principal != APIKEY_SESSION_SUB:
        user = principal
    elif mode == "proxy" and authenticated:
        user = principal

    response: dict = {
        "mode": mode,
        "authenticated": authenticated,
        "user": user,
        "writable": is_auth_writable(),
    }
    # Only expose admin metadata to authenticated callers
    if authenticated:
        stored_username, stored_hash = get_credentials()
        response["username"] = stored_username
        response["has_password"] = bool(stored_hash)
        response["proxy_header"] = get_effective_proxy_header()
        response["trusted_proxies"] = get_trusted_proxies()
    return response


class AuthConfigBody(BaseModel):
    mode: str
    username: str | None = None
    password: str | None = None
    proxy_header: str | None = None
    trusted_proxies: list[str] | None = None


@router.put("/config")
async def update_auth_config(body: AuthConfigBody, request: Request) -> JSONResponse:
    """Update the persistent auth configuration after the initial setup.

    Mirrors the wizard's `POST /api/setup/auth` shape but is callable any
    time. Changing the password or username logs out every other session;
    the caller gets a fresh cookie so they stay signed in.
    """
    if body.mode not in AUTH_MODES:
        raise HTTPException(status_code=422, detail=f"Invalid mode: {body.mode!r}")
    # Validated first and written in the same save as the mode, so a request
    # that is refused below leaves no trusted proxies behind.
    trusted = _validated_cidrs(body.trusted_proxies)

    reissue: str | None = None

    if body.mode == "basic":
        username, current_hash = get_credentials()
        if not body.username:
            raise HTTPException(status_code=422, detail="username is required for basic auth mode")
        # Allow updating username without rotating the password by leaving
        # it blank, preserves the existing hash.
        if body.password:
            try:
                set_auth_in_config(
                    mode="basic",
                    username=body.username,
                    password=body.password,
                    trusted_proxies=trusted,
                )
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        elif current_hash and body.username == username:
            # Mode-only refresh, keep existing creds.
            set_auth_in_config(mode="basic", trusted_proxies=trusted)
        elif current_hash:
            set_auth_in_config(mode="basic", username=body.username, trusted_proxies=trusted)
        else:
            raise HTTPException(
                status_code=422,
                detail="password is required when no credentials exist yet",
            )
        reissue = body.username

    elif body.mode == "proxy":
        header = (body.proxy_header or get_effective_proxy_header() or "Remote-User").strip()
        to_trust = require_proxy_auth_on(request, header, trusted)
        set_auth_in_config(
            mode="proxy",
            proxy_header=header,
            trusted_proxies=to_trust,
            proxy_hosts=proxy_hosts_with(request),
        )

    elif body.mode == "apikey":
        # Mode switch only, does not regenerate the key. Use
        # POST /api/auth/apikey/regenerate to mint a fresh one.
        from backend.services.auth_config import get_effective_api_key

        new_key = None if get_effective_api_key() else secrets.token_urlsafe(32)
        set_auth_in_config(mode="apikey", api_key=new_key, trusted_proxies=trusted)
        reissue = APIKEY_SESSION_SUB

    else:
        set_auth_in_config(mode="none", trusted_proxies=trusted)

    response = JSONResponse(content={"ok": True})
    if reissue:
        issue_session(response, request, reissue)
    return response


@router.post("/apikey/regenerate")
async def regenerate_apikey(request: Request) -> JSONResponse:
    """Generate a fresh API key and persist it. Returned only once."""
    new_key = secrets.token_urlsafe(32)
    set_auth_in_config(api_key=new_key)
    response = JSONResponse(content={"ok": True, "api_key": new_key})
    # The key change rotated the session secret; keep the caller signed in.
    mode = get_effective_auth_mode()
    if mode == "basic":
        username, _ = get_credentials()
        issue_session(response, request, username)
    elif mode == "apikey":
        issue_session(response, request, APIKEY_SESSION_SUB)
    return response


@router.get("/calendar-token")
async def calendar_token() -> dict:
    """Token that authorises the read-only ICS feed URL."""
    return {"token": get_or_create_calendar_token()}


@router.post("/calendar-token/regenerate")
async def regenerate_calendar_token() -> dict:
    token = secrets.token_urlsafe(24)
    set_auth_in_config(calendar_token=token)
    return {"token": token}
