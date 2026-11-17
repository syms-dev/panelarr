from __future__ import annotations

import logging
from datetime import UTC, datetime
from importlib.metadata import version as _pkg_version

logger = logging.getLogger(__name__)

VERSION = _pkg_version("panelarr")

#
# All auth values live in panelarr.json. There is no env-var override:
# the setup wizard writes them, the Settings page updates them, and the
# backend reads them back. Keeping a single source of truth makes the
# code easier to reason about and the UX easier to explain.


def get_effective_auth_mode() -> str:
    """Return the configured auth mode, 'none' when no mode has been chosen.

    ``load_config`` already rejects an unknown mode with ``ConfigError``; the
    check is repeated here so no code path can turn an unknown mode into
    "no auth".
    """
    from backend.services.config import AUTH_MODES, ConfigError, load_config

    config = load_config()
    mode = (config.auth or {}).get("mode", "none")
    if mode not in AUTH_MODES:
        raise ConfigError("auth.mode is not a known authentication mode")
    return mode


def get_effective_credentials() -> tuple[str, str]:
    """Return ``(username, password_hash)`` for basic auth.

    Reads from ``panelarr.json``. Returns ``("", "")`` when credentials
    are not yet configured.
    """
    from backend.services.config import load_config

    config = load_config()
    if not config.auth:
        return ("", "")
    username = config.auth.get("username", "")  # type: ignore[union-attr]
    password_hash = config.auth.get("password_hash", "")  # type: ignore[union-attr]
    if username and password_hash:
        return (username, password_hash)
    return ("", "")


def get_effective_proxy_header() -> str:
    """Return the configured proxy header name, defaulting to 'Remote-User'."""
    from backend.services.config import load_config

    config = load_config()
    if not config.auth:
        return "Remote-User"
    return config.auth.get("proxy_header", "Remote-User")  # type: ignore[union-attr]


def get_effective_api_key() -> str:
    """Return the configured API key, or an empty string if unset."""
    from backend.services.config import load_config

    config = load_config()
    if not config.auth:
        return ""
    return config.auth.get("api_key", "")  # type: ignore[union-attr]


def is_auth_writable() -> bool:
    """Auth settings are always writable through the UI.

    This function used to return ``False`` when ``AUTH_USERNAME`` /
    ``AUTH_PASSWORD`` were pinned via the environment. Env-based auth
    has been removed, so it now always returns ``True``. Kept as a
    function so existing callers and API responses do not change shape.
    """
    return True


def set_auth_in_config(
    *,
    mode: str | None = None,
    username: str | None = None,
    password: str | None = None,
    proxy_header: str | None = None,
    api_key: str | None = None,
    trusted_proxies: list[str] | None = None,
    proxy_hosts: list[str] | None = None,
    calendar_token: str | None = None,
) -> None:
    """Write auth fields to panelarr.json, preserving existing auth.secret.

    Only non-None arguments are written. Password is bcrypt-hashed before
    storage. Changing the password, the username or the API key rotates the
    session signing secret, which logs out every other session.
    """
    from backend.services.auth import hash_password, rotate_secret
    from backend.services.config import load_config, save_config

    config = load_config()
    # config.auth is a plain dict, preserve existing fields (e.g. secret)
    auth: dict = dict(config.auth) if config.auth else {}  # type: ignore[arg-type]

    rotate = False
    if mode is not None:
        auth["mode"] = mode
    if username is not None:
        rotate = rotate or auth.get("username") != username
        auth["username"] = username
    if password is not None:
        auth["password_hash"] = hash_password(password)
        rotate = True
    if proxy_header is not None:
        auth["proxy_header"] = proxy_header
    if api_key is not None:
        auth["api_key"] = api_key
        rotate = True
    if trusted_proxies is not None:
        auth["trusted_proxies"] = trusted_proxies
    if proxy_hosts is not None:
        auth["proxy_hosts"] = proxy_hosts
    if calendar_token is not None:
        auth["calendar_token"] = calendar_token
    if rotate and auth.get("secret"):
        rotate_secret(auth)

    # Rebuild config with updated auth block
    data = config.model_dump()
    data["auth"] = auth
    from backend.services.config import PanelarrConfig

    save_config(PanelarrConfig(**data))


def get_trusted_proxies() -> list[str]:
    from backend.services.security import get_trusted_proxies as _get

    return _get()


def get_or_create_calendar_token() -> str:
    """Return the read-only token that authorises the ICS feed URL."""
    from backend.services.config import load_config

    config = load_config()
    token = (config.auth or {}).get("calendar_token", "")
    if token:
        return token
    import secrets

    token = secrets.token_urlsafe(24)
    set_auth_in_config(calendar_token=token)
    return token


def is_auth_configured() -> bool:
    """True once the wizard's auth step has been saved (or setup is done).

    Until then only the setup endpoints are reachable, so a freshly started
    instance exposes nothing but the wizard. Legacy installs that predate the
    wizard count as configured once ``is_setup_complete`` backfills them.
    """
    from backend.services.config import load_config

    config = load_config()
    if (config.auth or {}).get("mode"):
        return True
    return is_setup_complete()


def is_setup_complete() -> bool:
    """True iff config['setup']['completed_at'] is set. Never writes."""
    from backend.services.config import load_config

    config = load_config()
    setup: dict = config.setup if config.setup else {}  # type: ignore[assignment]
    return bool(setup.get("completed_at"))


def backfill_legacy_setup() -> bool:
    """Mark a pre-wizard install as set up. Call once at startup only.

    A legacy install (services configured, no ``setup`` block, no auth mode)
    predates the wizard and must not be sent back through it. This runs from
    the app lifespan, before any request is served, so it only ever looks at
    the config file as it existed when the process started. Running it from a
    request path would let an unauthenticated client on a fresh install save
    a service and have the instance "auto-migrated" into auth mode none.
    After a reset, ``setup`` holds a 'reset_at' sentinel, which also prevents
    backfilling.
    """
    from backend.services.config import PanelarrConfig, load_config, save_config

    config = load_config()
    setup: dict = config.setup if config.setup else {}  # type: ignore[assignment]
    auth_block: dict = config.auth if config.auth else {}  # type: ignore[assignment]
    if setup or not config.services or auth_block.get("mode"):
        return False
    logger.info(
        "Backfilling setup.completed_at for existing installation (%d service(s) configured)",
        len(config.services),
    )
    data = config.model_dump()
    data["setup"] = {"completed_at": "auto-migrated", "version": VERSION}
    save_config(PanelarrConfig(**data))
    return True


def mark_setup_complete() -> None:
    """Write config['setup'] = {completed_at, version}."""
    from backend.services.config import PanelarrConfig, load_config, save_config

    config = load_config()
    data = config.model_dump()
    data["setup"] = {
        "completed_at": datetime.now(UTC).isoformat(),
        "version": VERSION,
    }
    save_config(PanelarrConfig(**data))


def reset_setup() -> None:
    """Wipe wizard-managed config so the user can re-run the wizard cleanly.

    This is a *destructive* operation: it clears services, notifications,
    thresholds, and the setup flag, but preserves the `auth` block (and its
    `secret`) so the current user is not unexpectedly logged out.

    Writes a 'reset_at' sentinel into `setup` so `is_setup_complete()` does
    not re-backfill on the next call from the legacy migration heuristic.
    """
    from backend.services.config import PanelarrConfig, load_config, save_config

    config = load_config()
    data = config.model_dump()

    # Preserve auth (mode + credentials + secret) so login still works.
    preserved_auth = dict(data.get("auth", {}))

    # Wipe everything else managed by the wizard.
    data["services"] = {}
    data["notifications"] = {"channels": [], "rules": []}
    data["thresholds"] = {
        "disk_warn_pct": 85,
        "disk_crit_pct": 90,
        "watchdog_threshold_hours": 2,
        "disks": [],
    }
    data["auth"] = preserved_auth
    data["setup"] = {"reset_at": datetime.now(UTC).isoformat()}

    save_config(PanelarrConfig(**data))
