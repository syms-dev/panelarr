"""Regression tests for anchored image matching in services/discover.py."""

from __future__ import annotations

import pytest

from backend.services.discover import match_container


@pytest.mark.parametrize(
    ("image", "service"),
    [
        ("linuxserver/sonarr:latest", "sonarr"),
        ("lscr.io/linuxserver/radarr:5.0", "radarr"),
        ("ghcr.io/hotio/sonarr:release-4", "sonarr"),
        ("ghcr.io/hotio/qbittorrent:latest", "qbittorrent"),
        ("hotio/qbittorrent", "qbittorrent"),
        ("binhex/arch-qbittorrentvpn:latest", "qbittorrent"),
        ("binhex/arch-sabnzbd", "sabnzbd"),
        ("ghcr.io/hotio/plex", "plex"),
        ("binhex/arch-delugevpn", "deluge"),
        ("haugene/transmission-openvpn:latest", "transmission"),
        ("jellyfin/jellyfin:10.9.0", "jellyfin"),
        ("registry.local:5000/linuxserver/plex:latest", "plex"),
        ("sonarr", "sonarr"),
        ("sonarr:latest", "sonarr"),
        ("LinuxServer/Sonarr:Latest", "sonarr"),
        ("lscr.io/linuxserver/sonarr@sha256:abcd", "sonarr"),
    ],
)
def test_known_images_match(image: str, service: str) -> None:
    result = match_container({"name": "x", "image": image, "ports": {}})
    assert result is not None
    assert result[0] == service


@pytest.mark.parametrize(
    "image",
    [
        "linuxserver/plex-meta-manager",
        "jellyfin/jellyfin-vue",
        "linuxserver/sonarr-extras",
        "someorg/sonarr",
        "linuxserver/plexdrive",
        "hotio/radarr-sync",
        "myregistry/emby-exporter:latest",
        "qbittorrent-exporter",
        "sonarr-importer:latest",
    ],
)
def test_lookalike_images_do_not_match(image: str) -> None:
    assert match_container({"name": "plex", "image": image, "ports": {"32400/tcp": 32400}}) is None
