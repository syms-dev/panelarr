from __future__ import annotations

import json
from urllib.parse import urlparse

from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, Field, ValidationError

from backend.services.config import (
    PanelarrConfig,
    SecretReuseError,
    _preserve_secrets,
    get_masked_config,
    load_config,
    save_config,
    test_service_connection,
)
from backend.services.registry import KNOWN_SERVICES, SERVICE_CATEGORIES, SERVICE_TYPES

router = APIRouter(prefix="/api/config", tags=["config"])

PROTECTED_KEYS = {"auth", "setup"}


class ThresholdsUpdate(BaseModel):
    disk_warn_pct: int | None = Field(default=None, ge=1, le=100)
    disk_crit_pct: int | None = Field(default=None, ge=1, le=100)
    watchdog_threshold_hours: int | None = Field(default=None, ge=1, le=720)
    disks: list[str] | None = None


@router.get("")
async def get_config() -> dict:
    return get_masked_config()


@router.put("")
async def update_config(updates: dict) -> dict:
    for key in PROTECTED_KEYS:
        updates.pop(key, None)

    current = load_config()
    original = json.loads(json.dumps(current.model_dump()))  # Deep copy
    merged = json.loads(json.dumps(original))

    # Validate service URLs before saving
    if "services" in updates:
        if not isinstance(updates["services"], dict):
            raise HTTPException(status_code=422, detail="services must be an object")
        for svc_name, svc_cfg in updates["services"].items():
            if not isinstance(svc_cfg, dict):
                raise HTTPException(
                    status_code=422, detail=f"Service '{svc_name}' must be an object"
                )
            url = svc_cfg.get("url", "")
            if url:
                parsed = urlparse(url)
                if parsed.scheme not in ("http", "https"):
                    raise HTTPException(
                        status_code=422,
                        detail=f"Service '{svc_name}': URL scheme must be http or https",
                    )
                if not parsed.hostname:
                    raise HTTPException(
                        status_code=422,
                        detail=f"Service '{svc_name}': URL has no hostname",
                    )
        merged["services"] = updates["services"]

    # Merge notifications
    if "notifications" in updates:
        merged["notifications"] = updates["notifications"]

    # Merge thresholds
    if "thresholds" in updates:
        try:
            thresholds = ThresholdsUpdate.model_validate(updates["thresholds"])
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=f"Invalid thresholds: {exc}") from exc
        merged.setdefault("thresholds", {}).update(thresholds.model_dump(exclude_none=True))

    # Preserve secrets (masked values → keep originals, same destination only)
    try:
        merged = _preserve_secrets(merged, original)
    except SecretReuseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        new_config = PanelarrConfig(**merged)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid config: {exc}") from exc
    save_config(new_config)
    return {"status": "ok"}


@router.post("/test/{service}")
async def test_connection(
    service: str,
    override: dict | None = Body(default=None),
) -> dict:
    return await test_service_connection(service, override)


@router.get("/registry")
async def get_service_registry() -> dict:
    """Return the service registry for UI rendering."""
    return {
        "services": KNOWN_SERVICES,
        "types": SERVICE_TYPES,
        "categories": SERVICE_CATEGORIES,
    }

    # Debug endpoint removed for security, use `docker exec` for troubleshooting
