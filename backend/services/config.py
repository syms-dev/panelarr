from __future__ import annotations

import json
import logging
import os
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ValidationError

from backend.config import settings
from backend.services.registry import KNOWN_SERVICES, get_secret_fields

logger = logging.getLogger(__name__)

API_TIMEOUT = 10
MASKED_PREFIX = "****"
SENSITIVE_KEYS = {"api_key", "password", "token"}

# Secret fields per notification channel type. The URL of a webhook-style
# channel *is* the credential, so it is masked like a password.
CHANNEL_SECRET_FIELDS: dict[str, tuple[str, ...]] = {
    "discord": ("webhook_url",),
    "slack": ("webhook_url",),
    "telegram": ("bot_token",),
    "webhook": ("url",),
    "email": ("password",),
}
# A stored secret is only reused while these fields are unchanged; pointing a
# channel at a new host with the old secret masked would hand it to that host.
CHANNEL_DESTINATION_FIELDS: dict[str, tuple[str, ...]] = {
    "email": ("smtp_host", "smtp_port", "username"),
}


AUTH_MODES = frozenset({"none", "basic", "proxy", "apikey"})


class ConfigError(RuntimeError):
    """panelarr.json exists but cannot be parsed or validated."""


def _describe_config_error(exc: Exception) -> str:
    """Describe why panelarr.json was rejected without quoting its values.

    The message reaches unauthenticated clients (the 503 ``config_invalid``
    body) and the log, so it must never echo what the file contains: pydantic's
    default text includes ``input_value=`` with parts of API keys.
    """
    if isinstance(exc, ValidationError):
        parts = [
            f"{'.'.join(str(p) for p in err['loc']) or 'config'}: {err['msg']}"
            for err in exc.errors(include_input=False, include_url=False, include_context=False)
        ]
        return "; ".join(parts) or "validation failed"
    if isinstance(exc, json.JSONDecodeError):
        return f"not valid JSON (line {exc.lineno}, column {exc.colno})"
    if isinstance(exc, OSError):
        return f"cannot be read ({exc.strerror or type(exc).__name__})"
    return str(exc)


class SecretReuseError(ValueError):
    """A masked secret would be sent to a different destination."""


def channel_secret_fields(channel_type: str) -> tuple[str, ...]:
    return CHANNEL_SECRET_FIELDS.get(channel_type, ("webhook_url", "bot_token", "url", "password"))


def url_origin(url: str) -> tuple[str, str, int | None]:
    """(scheme, host, port) used to decide whether a URL changed destination."""
    try:
        parsed = urlparse(url or "")
        port = parsed.port
    except ValueError:
        return ("", url or "", None)
    scheme = parsed.scheme.lower()
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    return (scheme, (parsed.hostname or "").lower(), port)


class PanelarrConfig(BaseModel):
    services: dict[str, dict] = {}
    notifications: dict = {"channels": [], "rules": []}
    thresholds: dict = {
        "disk_warn_pct": 85,
        "disk_crit_pct": 90,
        "watchdog_threshold_hours": 2,
        "disks": [],
    }
    auth: dict = {}
    setup: dict = {}


_resolved_config_path: Path | None = None


def _may_exist(path: Path) -> bool:
    """False only when ``path`` is known not to exist.

    ``Path.is_file()`` is not enough: from Python 3.14 it returns False when
    the directory cannot be searched (EACCES), which would make an existing,
    unreadable panelarr.json look like a fresh install; before 3.14 it raises
    PermissionError instead. Use this, never ``is_file()``, on the config path.
    """
    try:
        path.stat()
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True
    return True


def resolve_config_path() -> Path:
    """Return a writable config file path.

    Tries `settings.config_path` first; if that location is not writable
    (common in dev where /config doesn't exist on the host), falls back to
    `~/.config/panelarr/panelarr.json`. Result is cached for the lifetime
    of the process.
    """
    global _resolved_config_path
    if _resolved_config_path is not None:
        return _resolved_config_path

    primary = Path(settings.config_path)
    if _may_exist(primary) or os.getenv("CONFIG_PATH"):
        # An existing config is always the one in force, even when its
        # directory is not writable (disk full, read-only remount, wrong
        # owner). Falling back would load defaults and reopen the setup
        # wizard to anyone on the network; saves fail loudly instead.
        _resolved_config_path = primary
        return primary
    fallback = Path.home() / ".config" / "panelarr" / "panelarr.json"
    candidates = [primary, fallback]

    for candidate in candidates:
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            test = candidate.parent / ".panelarr_write_test"
            test.write_text("ok")
            test.unlink()
        except OSError:
            continue
        if candidate != primary:
            logger.warning("Config path %s not writable; falling back to %s", primary, candidate)
        _resolved_config_path = candidate
        return candidate

    # Last resort, use the fallback path even if untested; subsequent
    # writes will surface the underlying error.
    _resolved_config_path = fallback
    return fallback


def is_masked(value: str) -> bool:
    """Check if a value is a masked secret (starts with ****)."""
    return isinstance(value, str) and value.startswith(MASKED_PREFIX)


def get_service_config(config: PanelarrConfig, name: str) -> dict:
    """Get config dict for a service by name."""
    return config.services.get(name, {})


def _migrate_v1_to_v2(raw: dict) -> dict:
    """Migrate old config format (typed top-level fields) to v2 (all in services dict)."""
    if "services" in raw and isinstance(raw["services"], dict):
        # Check if it's already v2 (services contains actual service configs)
        # v1 had services as overflow for dynamic services alongside typed fields
        # v2 has ALL services in services dict
        typed_keys = ("sonarr", "radarr", "sabnzbd", "qbittorrent", "plex", "jellyfin")
        has_typed = any(k in raw for k in typed_keys)
        if not has_typed:
            return raw  # Already v2

    # Migrate typed service fields into services dict
    services = raw.get("services", {}) if isinstance(raw.get("services"), dict) else {}
    for name in ("sonarr", "radarr", "sabnzbd", "qbittorrent", "plex", "jellyfin"):
        if name in raw and isinstance(raw[name], dict):
            svc = raw.pop(name)
            # Only migrate if it has data
            if any(v for v in svc.values() if v):
                services[name] = svc

    # Migrate discord_webhook into notifications
    notifications = raw.get("notifications", {"channels": [], "rules": []})
    if not isinstance(notifications, dict):
        notifications = {"channels": [], "rules": []}

    # Move old notification_channels/rules into notifications
    if "notification_channels" in raw:
        notifications["channels"] = raw.pop("notification_channels", [])
    if "notification_rules" in raw:
        notifications["rules"] = raw.pop("notification_rules", [])

    # Move discord_webhook, create a legacy channel if webhook exists
    discord_webhook = raw.pop("discord_webhook", "")

    # Migrate thresholds
    thresholds = raw.get("thresholds", {})
    if not isinstance(thresholds, dict):
        thresholds = {}
    for key in ("disk_warn_pct", "disk_crit_pct", "watchdog_threshold_hours"):
        if key in raw:
            thresholds[key] = raw.pop(key)
    thresholds.setdefault("disk_warn_pct", 85)
    thresholds.setdefault("disk_crit_pct", 90)
    thresholds.setdefault("watchdog_threshold_hours", 2)

    # Clean result, preserve auth and setup blocks untouched, since they
    # are not part of the v1 → v2 migration and stripping them would wipe
    # credentials and wizard state on first load.
    result = {
        "services": services,
        "notifications": notifications,
        "thresholds": thresholds,
    }
    if "auth" in raw and isinstance(raw["auth"], dict):
        result["auth"] = raw["auth"]
    if "setup" in raw and isinstance(raw["setup"], dict):
        result["setup"] = raw["setup"]

    # If there was a legacy discord webhook and no channels exist, preserve it
    # by creating a channel automatically
    if discord_webhook and not discord_webhook.startswith("****"):
        channels = notifications.get("channels", [])
        if not any(ch.get("type") == "discord" for ch in channels):
            channels.append(
                {
                    "id": uuid.uuid4().hex[:12],
                    "type": "discord",
                    "name": "Discord (migrated)",
                    "config": {"webhook_url": discord_webhook},
                    "enabled": True,
                }
            )
            notifications["channels"] = channels

    return result


def _preserve_secrets(merged: dict, original: dict, *, strict: bool = True) -> dict:
    """Replace masked values in ``merged`` with the real values from ``original``.

    A masked secret is only restored when it is going back to the same
    destination it was saved for. If a service URL (scheme, host, port) or an
    email channel's server changed while the secret was left masked, the
    stored secret is not carried over: with ``strict`` a ``SecretReuseError``
    is raised so the caller can ask for the secret again, otherwise the field
    is blanked.
    """
    merged_svcs = merged.get("services", {})
    orig_svcs = original.get("services", {})
    for svc_name, svc_config in merged_svcs.items():
        if not isinstance(svc_config, dict):
            continue
        orig_svc = orig_svcs.get(svc_name, {}) or {}
        same_dest = url_origin(svc_config.get("url", "")) == url_origin(orig_svc.get("url", ""))
        for sf in get_secret_fields(svc_name):
            if sf in svc_config and is_masked(svc_config[sf]):
                if same_dest:
                    svc_config[sf] = orig_svc.get(sf, "")
                elif strict and orig_svc.get(sf):
                    raise SecretReuseError(
                        f"Service '{svc_name}': re-enter the {sf.replace('_', ' ')} "
                        "when changing the URL"
                    )
                else:
                    svc_config[sf] = ""

    merged_channels = merged.get("notifications", {}).get("channels", [])
    orig_channels = original.get("notifications", {}).get("channels", [])
    orig_ch_map = {ch["id"]: ch for ch in orig_channels if "id" in ch}
    for ch in merged_channels:
        orig_ch = orig_ch_map.get(ch.get("id", ""), {})
        ch_config = ch.get("config", {}) or {}
        orig_config = orig_ch.get("config", {}) or {}
        ch_type = ch.get("type") or orig_ch.get("type", "")
        dest_fields = CHANNEL_DESTINATION_FIELDS.get(ch_type, ())
        same_dest = orig_ch.get("type") == ch_type and all(
            str(ch_config.get(f, "")) == str(orig_config.get(f, "")) for f in dest_fields
        )
        for key in channel_secret_fields(ch_type):
            if key in ch_config and is_masked(ch_config[key]):
                if same_dest:
                    ch_config[key] = orig_config.get(key, "")
                elif strict and orig_config.get(key):
                    raise SecretReuseError(
                        f"Channel '{ch.get('name', '')}': re-enter the "
                        f"{key.replace('_', ' ')} when changing where it is sent"
                    )
                else:
                    ch_config[key] = ""

    return merged


def _migrate_config_file(config_path: Path) -> None:
    """Migrate old config file names to current name."""
    if _may_exist(config_path):
        return
    old_names = ["stackpanel.json"]
    for old_name in old_names:
        old_path = config_path.parent / old_name
        try:
            if old_path.is_file():
                logger.info("Migrating config file: %s → %s", old_path, config_path)
                old_path.rename(config_path)
                return
        except OSError as exc:
            logger.warning("Could not migrate %s: %s", old_path, exc.strerror or exc)


_config_cache: PanelarrConfig | None = None
_config_cache_at: float = 0.0
_CONFIG_TTL = 5.0
# Last config that parsed successfully. If the file is later broken by hand,
# Panelarr keeps running on this instead of silently falling back to defaults
# (which would disable authentication and reopen the setup wizard).
_last_good_config: PanelarrConfig | None = None
_config_error: str | None = None


def get_config_error() -> str | None:
    """Return the current parse error for panelarr.json, if any."""
    return _config_error


def load_config() -> PanelarrConfig:
    """Load config from JSON file, migrate if needed, overlay env vars.

    Results are cached for up to _CONFIG_TTL seconds to avoid repeated disk reads.
    """
    global _config_cache, _config_cache_at
    now = time.monotonic()
    if _config_cache is not None and (now - _config_cache_at) < _CONFIG_TTL:
        return _config_cache

    global _last_good_config, _config_error
    config_path = resolve_config_path()
    _migrate_config_file(config_path)
    config = PanelarrConfig()
    if _may_exist(config_path):
        try:
            raw = json.loads(config_path.read_text())
            if not isinstance(raw, dict):
                raise ValueError("top level must be a JSON object")
            # Migrate v1 format to v2 if needed
            raw = _migrate_v1_to_v2(raw)
            config = PanelarrConfig(**raw)
            auth_block = config.auth or {}
            if "mode" in auth_block and auth_block["mode"] not in AUTH_MODES:
                # An unknown mode must not mean "no auth" (a hand-edited
                # "Basic", or a downgrade from a version with a new mode).
                raise ValueError(f"auth.mode must be one of {', '.join(sorted(AUTH_MODES))}")
            logger.debug("Config loaded from %s", config_path)
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            # Fail closed: never fall back to defaults, which would mean
            # auth mode "none" and an open setup wizard.
            detail = _describe_config_error(exc)
            _config_error = f"{config_path}: {detail}"
            if _last_good_config is not None:
                logger.error(
                    "Config file %s is invalid (%s); keeping the last valid config",
                    config_path,
                    detail,
                )
                _config_cache = _last_good_config
                _config_cache_at = now
                return _last_good_config
            logger.error("Config file %s is invalid: %s", config_path, detail)
            raise ConfigError(_config_error) from None
    else:
        logger.debug("No config file at %s, using defaults", config_path)

    _config_error = None
    _last_good_config = config
    _config_cache = config
    _config_cache_at = now
    return config


def _backup_if_corrupt(config_path: Path) -> None:
    """Keep a copy of an unparseable config file before overwriting it."""
    if not _may_exist(config_path):
        return
    try:
        json.loads(config_path.read_text())
        return
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    backup = config_path.with_name(f"{config_path.name}.corrupt-{int(time.time())}")
    try:
        os.replace(config_path, backup)
        logger.error("Moved invalid config file to %s before saving", backup)
    except OSError:
        logger.exception("Could not back up invalid config file %s", config_path)


def save_config(config: PanelarrConfig) -> None:
    """Write config to JSON file atomically and invalidate the in-process cache.

    Writes go through a sibling temp file + ``os.replace`` so the on-disk file
    is never observed half-written. If the process is killed between the
    ``write`` and the ``replace``, the original file is left untouched and
    the temp file is cleaned up on the next save attempt.
    """
    global _config_cache, _config_error
    config_path = resolve_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    _backup_if_corrupt(config_path)
    data = config.model_dump()
    payload = json.dumps(data, indent=2)

    # Write to a sibling temp file in the same directory so os.replace is
    # guaranteed to be atomic (same filesystem). NamedTemporaryFile is used
    # with delete=False because we hand the path to os.replace ourselves.
    tmp_dir = config_path.parent
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=tmp_dir,
        prefix=".panelarr.",
        suffix=".tmp",
        delete=False,
    )
    try:
        try:
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
        finally:
            tmp.close()
        # Lock down permissions BEFORE the rename so the file is never
        # world-readable, even for the brief window between create and replace.
        try:
            os.chmod(tmp.name, 0o600)
        except OSError:
            pass
        os.replace(tmp.name, config_path)
    except Exception:
        # Best-effort cleanup of the temp file if anything went wrong
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise

    _config_cache = None
    _config_error = None
    # Log which services have data
    saved_svcs = [name for name, cfg in data.get("services", {}).items() if cfg.get("url")]
    logger.info("Config saved to %s, services: %s", config_path, ", ".join(saved_svcs) or "none")


def mask_secret(value: str) -> str:
    """Show only last 4 chars of a secret. Hide fully if 8 chars or fewer."""
    if not value:
        return ""
    if len(value) <= 8:
        return MASKED_PREFIX
    return MASKED_PREFIX + value[-4:]


def mask_channel(channel: dict) -> dict:
    """Mask a channel's secret fields in place and return it."""
    ch_config = channel.get("config", {}) or {}
    for key in channel_secret_fields(channel.get("type", "")):
        if key in ch_config and isinstance(ch_config[key], str):
            ch_config[key] = mask_secret(ch_config[key])
    return channel


def get_masked_config() -> dict:
    """Return config with sensitive fields masked."""
    config = load_config()
    data = config.model_dump()

    # Mask service secrets
    for svc_name, svc_config in data.get("services", {}).items():
        if isinstance(svc_config, dict):
            secret_fields = get_secret_fields(svc_name)
            for sf in secret_fields:
                if sf in svc_config and isinstance(svc_config[sf], str):
                    svc_config[sf] = mask_secret(svc_config[sf])

    # Mask notification channel secrets
    for ch in data.get("notifications", {}).get("channels", []):
        mask_channel(ch)

    # Never expose auth secrets
    data.pop("auth", None)
    return data


def _validate_url(url: str) -> str | None:
    """Validate a service URL. Returns error message or None if valid."""
    if not url:
        return "No URL configured"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return f"URL scheme '{parsed.scheme}' not allowed, use http or https"
    if not parsed.hostname:
        return "URL has no hostname"
    return None


def _build_config_for_test(service: str, override: dict | None = None) -> PanelarrConfig:
    """Build a config for testing, merging form overrides onto real config."""
    config = load_config()
    if not override:
        return config

    data = config.model_dump()
    original = json.loads(json.dumps(data))  # Deep copy

    # Merge service-specific overrides into services dict
    if service == "discord":
        # Discord override goes into notification channel config
        pass  # Handled separately in test function
    elif service in data.get("services", {}):
        for key, value in override.items():
            data["services"][service][key] = value
    else:
        data.setdefault("services", {})[service] = override

    # Lenient: a masked secret is dropped (not reused) when the URL changed.
    data = _preserve_secrets(data, original, strict=False)

    # A secret the caller did not type in explicitly (omitted or masked) must
    # never travel to a different destination than the one it was saved for.
    if service != "discord":
        tested = data.get("services", {}).get(service, {})
        stored = original.get("services", {}).get(service, {}) or {}
        if url_origin(tested.get("url", "")) != url_origin(stored.get("url", "")):
            for sf in get_secret_fields(service):
                supplied = override.get(sf)
                if not isinstance(supplied, str) or not supplied or is_masked(supplied):
                    tested[sf] = ""
    return PanelarrConfig(**data)


async def _test_arr_service(url: str, api_key: str, client: httpx.AsyncClient) -> dict:
    """Test an ARR service."""
    err = _validate_url(url)
    if err:
        return {"ok": False, "message": err}
    resp = await client.get(
        f"{url}/api/v3/system/status",
        headers={"X-Api-Key": api_key},
    )
    resp.raise_for_status()
    return {"ok": True, "message": f"Connected, v{resp.json().get('version', '?')}"}


async def _test_sabnzbd(url: str, api_key: str, client: httpx.AsyncClient) -> dict:
    if not url:
        return {"ok": False, "message": "No URL configured"}
    resp = await client.get(
        f"{url}/api",
        params={"mode": "version", "apikey": api_key, "output": "json"},
    )
    resp.raise_for_status()
    return {"ok": True, "message": f"Connected, {resp.json().get('version', '?')}"}


async def _test_qbittorrent(
    url: str, username: str, password: str, client: httpx.AsyncClient
) -> dict:
    if not url:
        return {"ok": False, "message": "No URL configured"}
    resp = await client.post(
        f"{url}/api/v2/auth/login",
        data={"username": username, "password": password},
    )
    # qBittorrent < 5.1 answers "Ok."; 5.1+ answers 204 with an empty body.
    body = resp.text.strip()
    if resp.is_success and (body == "Ok." or (body == "" and resp.status_code == 204)):
        return {"ok": True, "message": "Connected"}
    return {"ok": False, "message": "Authentication failed"}


async def _test_transmission(
    url: str, username: str, password: str, client: httpx.AsyncClient
) -> dict:
    if not url:
        return {"ok": False, "message": "No URL configured"}
    resp = await client.get(
        f"{url}/transmission/rpc",
        auth=(username, password) if username else None,
    )
    if resp.status_code in (200, 409):
        return {"ok": True, "message": "Connected"}
    resp.raise_for_status()
    return {"ok": False, "message": f"HTTP {resp.status_code}"}


async def _test_plex(url: str, token: str, client: httpx.AsyncClient) -> dict:
    if not url:
        return {"ok": False, "message": "No URL configured"}
    resp = await client.get(
        f"{url}/identity",
        headers={"X-Plex-Token": token},
    )
    resp.raise_for_status()
    return {"ok": True, "message": "Connected"}


async def _test_jellyfin_emby(url: str, client: httpx.AsyncClient) -> dict:
    if not url:
        return {"ok": False, "message": "No URL configured"}
    resp = await client.get(f"{url}/System/Info/Public")
    resp.raise_for_status()
    info = resp.json()
    return {"ok": True, "message": f"Connected, v{info.get('Version', '?')}"}


async def _test_api_key_service(
    url: str, api_key: str, test_path: str, client: httpx.AsyncClient
) -> dict:
    if not url:
        return {"ok": False, "message": "No URL configured"}
    resp = await client.get(
        f"{url}{test_path}",
        params={"apikey": api_key},
    )
    resp.raise_for_status()
    return {"ok": True, "message": "Connected"}


async def test_service_connection(service: str, override: dict | None = None) -> dict[str, object]:
    """Test connectivity to a configured service."""
    config = _build_config_for_test(service, override)
    svc_config = get_service_config(config, service)

    # For discord, use the override directly
    if service == "discord" and override and "webhook_url" in override.get("config", override):
        cfg = override.get("config", override)
        webhook = cfg.get("webhook_url", override.get("discord_webhook", ""))
        if not webhook or is_masked(webhook):
            return {"ok": False, "message": "No webhook URL configured"}
        from backend.services.security import check_outbound_url

        blocked = await check_outbound_url(webhook)
        if blocked:
            return {"ok": False, "message": blocked}
        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                resp = await client.post(webhook, json={"content": "Panelarr test notification"})
                resp.raise_for_status()
                return {"ok": True, "message": "Webhook sent"}
        except Exception as exc:
            return {"ok": False, "message": type(exc).__name__}

    from backend.services.security import check_outbound_url

    url = svc_config.get("url", "")
    if url:
        blocked = await check_outbound_url(url)
        if blocked:
            return {"ok": False, "message": blocked}

    try:
        async with httpx.AsyncClient(timeout=API_TIMEOUT, follow_redirects=False) as client:
            svc_info = KNOWN_SERVICES.get(service)
            svc_type = svc_info["type"] if svc_info else None

            if svc_type == "arr":
                return await _test_arr_service(
                    svc_config.get("url", ""), svc_config.get("api_key", ""), client
                )
            elif svc_type == "sabnzbd":
                return await _test_sabnzbd(
                    svc_config.get("url", ""), svc_config.get("api_key", ""), client
                )
            elif svc_type == "qbittorrent":
                return await _test_qbittorrent(
                    svc_config.get("url", ""),
                    svc_config.get("username", ""),
                    svc_config.get("password", ""),
                    client,
                )
            elif svc_type == "transmission":
                return await _test_transmission(
                    svc_config.get("url", ""),
                    svc_config.get("username", ""),
                    svc_config.get("password", ""),
                    client,
                )
            elif svc_type == "plex":
                return await _test_plex(
                    svc_config.get("url", ""), svc_config.get("token", ""), client
                )
            elif svc_type in ("jellyfin", "emby"):
                return await _test_jellyfin_emby(svc_config.get("url", ""), client)
            else:
                return {"ok": False, "message": f"Unknown service: {service}"}
    except httpx.ConnectError:
        return {"ok": False, "message": "Connection refused, is the service running?"}
    except httpx.TimeoutException:
        return {"ok": False, "message": "Connection timed out"}
    except httpx.HTTPStatusError as exc:
        return {"ok": False, "message": f"HTTP {exc.response.status_code}"}
    except ValueError:
        return {"ok": False, "message": "Unexpected response, is this the right URL?"}
    except Exception as exc:
        return {"ok": False, "message": type(exc).__name__}
