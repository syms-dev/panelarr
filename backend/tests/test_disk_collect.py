from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

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
