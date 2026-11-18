from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_module_state():
    """Reset process-wide caches so tests cannot leak auth/config state."""
    import backend.routers.auth as auth_router
    import backend.routers.containers as containers_router
    import backend.services.auth as auth_svc
    import backend.services.config as svc_cfg
    import backend.services.security as security

    def reset() -> None:
        svc_cfg._config_cache = None
        svc_cfg._config_cache_at = 0.0
        svc_cfg._last_good_config = None
        svc_cfg._config_error = None
        auth_svc.reset_secret_cache()
        auth_router._login_attempts.clear()
        containers_router._last_update_result = None
        containers_router._last_update_check = 0.0
        security._cached_networks.cache_clear()

    reset()
    yield
    reset()
