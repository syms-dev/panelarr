from __future__ import annotations

from backend.services.registry import KNOWN_SERVICES, get_service_fields

# Known image repositories per service, as "<org>/<name>" (or a bare "<name>" for
# official/library images). Matching is exact on the image's final two path
# components, ignoring registry host, tag and digest, so variants such as
# "linuxserver/plex-meta-manager" or "jellyfin/jellyfin-vue" never match.
IMAGE_PATTERNS: dict[str, frozenset[str]] = {
    "sonarr": frozenset({"linuxserver/sonarr", "hotio/sonarr", "sonarr"}),
    "radarr": frozenset({"linuxserver/radarr", "hotio/radarr", "radarr"}),
    "sabnzbd": frozenset(
        {
            "linuxserver/sabnzbd",
            "hotio/sabnzbd",
            "binhex/arch-sabnzbd",
            "sabnzbd/sabnzbd",
            "sabnzbd",
        }
    ),
    "nzbget": frozenset(
        {"linuxserver/nzbget", "hotio/nzbget", "binhex/arch-nzbget", "nzbget/nzbget", "nzbget"}
    ),
    "qbittorrent": frozenset(
        {
            "linuxserver/qbittorrent",
            "hotio/qbittorrent",
            "qbittorrentofficial/qbittorrent-nox",
            "binhex/arch-qbittorrent",
            "binhex/arch-qbittorrentvpn",
            "binhex/qbittorrentvpn",
            "qbittorrent",
        }
    ),
    "transmission": frozenset(
        {
            "linuxserver/transmission",
            "haugene/transmission-openvpn",
            "binhex/arch-transmissionvpn",
            "transmission",
        }
    ),
    "deluge": frozenset(
        {"linuxserver/deluge", "binhex/arch-delugevpn", "binhex/arch-deluge", "deluge"}
    ),
    "plex": frozenset(
        {"plexinc/pms-docker", "linuxserver/plex", "hotio/plex", "binhex/arch-plex", "plex"}
    ),
    "jellyfin": frozenset(
        {"jellyfin/jellyfin", "linuxserver/jellyfin", "hotio/jellyfin", "jellyfin"}
    ),
    "emby": frozenset({"emby/embyserver", "linuxserver/emby", "emby"}),
}

# Default ports, supplement what KNOWN_SERVICES provides
DEFAULT_PORTS: dict[str, int] = {
    "sonarr": 8989,
    "radarr": 7878,
    "sabnzbd": 8080,
    "nzbget": 6789,
    "qbittorrent": 8080,
    "transmission": 9091,
    "deluge": 8112,
    "plex": 32400,
    "jellyfin": 8096,
    "emby": 8096,
}

_CONFIDENCE_RANK = {"high": 2, "medium": 1}


def _service_default_port(service: str) -> int | None:
    """Return the default port for a service, preferring the registry value."""
    info = KNOWN_SERVICES.get(service, {})
    return info.get("default_port") or DEFAULT_PORTS.get(service)


def _image_repo_key(image: str) -> str:
    """Return the lowercased ``org/name`` (or bare ``name``) of an image reference.

    The registry host, tag and digest are stripped, so ``lscr.io/linuxserver/sonarr:4``
    and ``linuxserver/sonarr`` both yield ``linuxserver/sonarr``.
    """
    ref = image.strip().lower().split("@", 1)[0]
    if ":" in ref.rsplit("/", 1)[-1]:
        ref = ref.rsplit(":", 1)[0]
    parts = [p for p in ref.split("/") if p]
    return "/".join(parts[-2:])


def _image_matches(image: str, service: str) -> bool:
    """Return True if the container image is exactly a known image of the service."""
    return _image_repo_key(image) in IMAGE_PATTERNS.get(service, frozenset())


def match_container(container: dict) -> tuple[str, str] | None:
    """Match a container dict to a known service.

    Returns (service_name, confidence) where confidence is "high" or "medium",
    or None if no service can be confidently matched.

    The container dict is expected to have the shape returned by list_containers():
      name, image, ports ({"8989/tcp": 8989}), state, etc.

    Confidence heuristics, image_match is required so a name/port collision
    on its own (like authelia listening on transmission's port 9091) cannot
    cause a false positive:
    - high   = image_match AND name_match AND port_match (all three agree)
    - medium = image_match alone, or image_match plus exactly one of name/port
    - None   = no image match (single-signal name/port matches are dropped)
    """
    name: str = container.get("name", "").lower()
    image: str = container.get("image", "")
    ports: dict = container.get("ports", {})
    port_values: set[int] = {v for v in ports.values() if isinstance(v, int)}

    best_service: str | None = None
    best_confidence: str | None = None

    for service in IMAGE_PATTERNS:
        default_port = _service_default_port(service)

        image_match = _image_matches(image, service)
        if not image_match:
            continue

        name_match = service in name
        port_match = default_port is not None and default_port in port_values

        if name_match and port_match:
            confidence = "high"
        else:
            confidence = "medium"

        current_rank = _CONFIDENCE_RANK.get(best_confidence or "", -1)
        if _CONFIDENCE_RANK[confidence] > current_rank:
            best_service = service
            best_confidence = confidence

    if best_service is None or best_confidence is None:
        return None
    return (best_service, best_confidence)


def suggested_url(container: dict, service: str) -> str:
    """Build the suggested URL for a service.

    The URL is meant for Panelarr reaching the container over the Docker network,
    so it uses the container name as DNS hostname and the container's INTERNAL
    port. A host-published port (``18989:8989``) is irrelevant on that network.
    """
    name: str = container.get("name", "").lstrip("/")
    default_port = _service_default_port(service) or 80
    return f"http://{name}:{default_port}"


def match_containers_to_services(
    containers: list[dict],
    configured_services: set[str] | None = None,
) -> list[dict]:
    """Match a list of containers to known services.

    Returns one match dict per service slug (best confidence wins for duplicates).

    Each match dict:
    {
        "service": "sonarr",
        "label": "Sonarr",
        "category": "arr",
        "confidence": "high",
        "container_name": "sonarr",
        "image": "linuxserver/sonarr:latest",
        "suggested_url": "http://sonarr:8989",
        "port": 8989,
        "fields": ["url", "api_key"],
        "already_configured": False,
    }
    """
    if configured_services is None:
        configured_services = set()

    # service -> best match so far
    best: dict[str, dict] = {}

    for container in containers:
        result = match_container(container)
        if result is None:
            continue
        service, confidence = result

        existing = best.get(service)
        existing_rank = _CONFIDENCE_RANK.get(existing["confidence"], -1) if existing else -1
        if _CONFIDENCE_RANK[confidence] > existing_rank:
            info = KNOWN_SERVICES.get(service, {})
            best[service] = {
                "service": service,
                "label": info.get("label", service.title()),
                "category": info.get("category", ""),
                "confidence": confidence,
                "container_name": container.get("name", "").lstrip("/"),
                "image": container.get("image", ""),
                "suggested_url": suggested_url(container, service),
                "port": _service_default_port(service),
                "fields": get_service_fields(service),
                "already_configured": service in configured_services,
            }

    return list(best.values())
