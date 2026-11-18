from __future__ import annotations

import logging
import secrets
import threading
import time
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from starlette.requests import HTTPConnection

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 24
COOKIE_NAME = "sp_session"
APIKEY_SESSION_SUB = "apikey"

_cached_secret: str | None = None
_secret_lock = threading.Lock()

# jti -> exp (epoch seconds). Logged-out tokens are refused until they expire.
# In-memory only: a restart forgets the list, which is acceptable because
# tokens are short-lived and a password change rotates the signing secret.
_revoked: dict[str, float] = {}


def get_or_create_secret() -> str:
    """Return the JWT signing secret, generating and persisting it on first use.

    Persisted through ``save_config`` so the write is atomic and goes through
    the same cache as every other config change.
    """
    global _cached_secret
    if _cached_secret:
        return _cached_secret
    with _secret_lock:
        if _cached_secret:
            return _cached_secret
        from backend.services.config import PanelarrConfig, load_config, save_config

        config = load_config()
        stored = (config.auth or {}).get("secret", "")
        if stored:
            _cached_secret = stored
            return stored
        new_secret = secrets.token_hex(32)
        data = config.model_dump()
        data.setdefault("auth", {})["secret"] = new_secret
        try:
            save_config(PanelarrConfig(**data))
        except OSError:
            logger.warning("Could not persist auth secret; sessions will not survive a restart")
        _cached_secret = new_secret
        return new_secret


def rotate_secret(auth_block: dict) -> None:
    """Put a fresh signing secret into ``auth_block`` (caller saves it).

    Invalidates every outstanding session token.
    """
    global _cached_secret
    auth_block["secret"] = secrets.token_hex(32)
    _cached_secret = None


def reset_secret_cache() -> None:
    global _cached_secret
    _cached_secret = None
    _revoked.clear()


MAX_PASSWORD_BYTES = 72

# Hash of a random password, verified against when the username is wrong so a
# failed login costs the same either way (no username enumeration by timing).
_DUMMY_HASH = bcrypt.hashpw(secrets.token_bytes(16), bcrypt.gensalt()).decode()


def hash_password(plaintext: str) -> str:
    """Hash a password with bcrypt.

    Raises ValueError if the encoded password exceeds bcrypt's 72-byte limit.
    """
    encoded = plaintext.encode()
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be {MAX_PASSWORD_BYTES} bytes or fewer when encoded")
    return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode()


def verify_password(plaintext: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plaintext.encode(), hashed.encode())
    except (ValueError, TypeError):
        return False


def check_credentials(username: str, password: str) -> bool:
    """Constant-effort username + password check (always runs bcrypt)."""
    stored_user, stored_hash = get_credentials()
    user_ok = bool(stored_user) and secrets.compare_digest(username.encode(), stored_user.encode())
    pw_ok = verify_password(password, stored_hash if user_ok and stored_hash else _DUMMY_HASH)
    return user_ok and pw_ok


def get_credentials() -> tuple[str, str]:
    """Return (username, password_hash) for basic auth."""
    from backend.services.auth_config import get_effective_credentials

    return get_effective_credentials()


def create_token(username: str) -> str:
    """Create a session JWT."""
    secret = get_or_create_secret()
    now = datetime.now(UTC)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(hours=TOKEN_EXPIRY_HOURS),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def _prune_revoked() -> None:
    now = time.time()
    for jti in [j for j, exp in _revoked.items() if exp < now]:
        _revoked.pop(jti, None)


def verify_token(token: str) -> dict | None:
    """Verify a session JWT: signature, expiry, revocation and subject.

    The subject must still be valid for the current auth mode: the configured
    username in basic mode, or the API-key session marker in apikey mode.
    """
    try:
        payload = jwt.decode(
            token,
            get_or_create_secret(),
            algorithms=[ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
    except jwt.InvalidTokenError:
        return None
    jti = payload.get("jti")
    if jti and (jti in _revoked or jti in _persisted_revoked()):
        return None

    from backend.services.auth_config import get_effective_auth_mode

    mode = get_effective_auth_mode()
    sub = payload.get("sub", "")
    if mode == "basic":
        username, _ = get_credentials()
        if not username or not secrets.compare_digest(sub.encode(), username.encode()):
            return None
    elif mode == "apikey":
        if sub != APIKEY_SESSION_SUB:
            return None
    else:
        return None
    return payload


def revoke_token(token: str) -> None:
    """Refuse this token from now until it would have expired anyway."""
    try:
        payload = jwt.decode(
            token,
            get_or_create_secret(),
            algorithms=[ALGORITHM],
            options={"verify_exp": False},
        )
    except jwt.InvalidTokenError:
        return
    jti = payload.get("jti")
    if jti:
        _prune_revoked()
        exp = float(payload.get("exp", time.time() + TOKEN_EXPIRY_HOURS * 3600))
        _revoked[jti] = exp
        _persist_revocation(jti, exp)


def _persisted_revoked() -> dict:
    from backend.services.config import load_config

    revoked = (load_config().auth or {}).get("revoked", {})
    return revoked if isinstance(revoked, dict) else {}


def _persist_revocation(jti: str, exp: float) -> None:
    """Store revoked token ids in panelarr.json so a restart doesn't revive them."""
    from backend.services.config import PanelarrConfig, load_config, save_config

    config = load_config()
    data = config.model_dump()
    auth = data.setdefault("auth", {})
    now = time.time()
    revoked = {k: v for k, v in (auth.get("revoked") or {}).items() if float(v) > now}
    revoked[jti] = exp
    auth["revoked"] = revoked
    try:
        save_config(PanelarrConfig(**data))
    except OSError:
        logger.warning("Could not persist session revocation; it lasts until restart")


def validate_api_key(provided: str) -> bool:
    """Validate an API key using a timing-safe comparison."""
    from backend.services.auth_config import get_effective_api_key

    expected = get_effective_api_key()
    if not expected or not provided:
        return False
    return secrets.compare_digest(provided.encode(), expected.encode())


def authenticate(conn: HTTPConnection) -> str | None:
    """Return a principal name if ``conn`` is authenticated, else None.

    Shared by the HTTP middleware, the WebSocket handler and /api/auth/status
    so every entry point applies identical rules:

    * a valid ``X-Api-Key`` header works in every mode;
    * mode ``none`` lets everyone in;
    * modes ``basic`` and ``apikey`` accept a valid session cookie;
    * mode ``proxy`` requires the configured header from a trusted proxy.
    """
    from backend.services.auth_config import (
        get_effective_auth_mode,
        get_effective_proxy_header,
    )
    from backend.services.security import proxy_user

    api_key = conn.headers.get("x-api-key", "")
    if api_key and validate_api_key(api_key):
        return APIKEY_SESSION_SUB

    mode = get_effective_auth_mode()
    if mode == "none":
        return "anonymous"
    if mode in ("basic", "apikey"):
        token = conn.cookies.get(COOKIE_NAME)
        if token:
            payload = verify_token(token)
            if payload:
                return str(payload.get("sub"))
        return None
    if mode == "proxy":
        return proxy_user(conn, get_effective_proxy_header())
    return None
