from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from backend.routers import system as system_mod


def test_collect_disks_skips_file_bind_mounts(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    file_mount = tmp_path / "entrypoint.sh"
    file_mount.write_text("#!/bin/sh\n")

    fake_parts = [
        SimpleNamespace(mountpoint=str(root)),
        SimpleNamespace(mountpoint=str(file_mount)),
    ]

    def fake_usage(path: str) -> dict | None:
        # Distinct st_dev so both would otherwise be kept
        return {
            "mount": path,
            "total": 100,
            "used": 50,
            "free": 50,
            "pct": 50.0,
            "_dev": hash(path) & 0xFFFFFFFF,
        }

    with (
        patch.object(system_mod.psutil, "disk_partitions", return_value=fake_parts),
        patch.object(system_mod, "_disk_usage_for_path", side_effect=fake_usage),
        patch.object(system_mod, "load_config", side_effect=Exception("no config")),
    ):
        disks = system_mod._collect_disks(filter_by_config=False)

    mounts = [d["mount"] for d in disks]
    assert str(file_mount) not in mounts
    assert str(root) in mounts


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_collect_disks_skips_unreachable_mountpoint(tmp_path) -> None:
    """A mountpoint under a directory this user can't search is skipped, not a 500."""
    locked = tmp_path / "locked"
    hidden = locked / "mnt"
    hidden.mkdir(parents=True)
    locked.chmod(0)
    try:
        fake_parts = [SimpleNamespace(mountpoint=str(hidden))]
        with patch.object(system_mod.psutil, "disk_partitions", return_value=fake_parts):
            disks = system_mod._collect_disks(filter_by_config=False)
    finally:
        locked.chmod(0o755)
    assert str(hidden) not in [d["mount"] for d in disks]
