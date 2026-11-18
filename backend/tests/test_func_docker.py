"""Tests for docker service helpers: image refs, registry auth, pulls, labels and self-update."""

from __future__ import annotations

import base64
import dataclasses
import json
from collections.abc import Callable

import httpx
import pytest

from backend.services import docker

DOCKER_HUB = "registry-1.docker.io"


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        ("nginx", (DOCKER_HUB, "library/nginx", "latest")),
        ("nginx:1.25", (DOCKER_HUB, "library/nginx", "1.25")),
        ("linuxserver/sonarr:develop", (DOCKER_HUB, "linuxserver/sonarr", "develop")),
        ("lscr.io/linuxserver/sonarr:latest", ("lscr.io", "linuxserver/sonarr", "latest")),
        ("ghcr.io/org/app:v1", ("ghcr.io", "org/app", "v1")),
        ("localhost:5000/img:tag", ("localhost:5000", "img", "tag")),
        ("localhost:5000/img", ("localhost:5000", "img", "latest")),
        ("registry.local:5000/a/b/c:2", ("registry.local:5000", "a/b/c", "2")),
        ("docker.io/library/redis:7", (DOCKER_HUB, "library/redis", "7")),
        ("nginx@sha256:abcd", (DOCKER_HUB, "library/nginx", "")),
        ("ghcr.io/org/app:1.0@sha256:abcd", ("ghcr.io", "org/app", "1.0")),
    ],
)
def test_parse_image_ref(image: str, expected: tuple[str, str, str]) -> None:
    assert docker._parse_image_ref(image) == expected


@pytest.mark.parametrize(
    ("image", "pinned"),
    [("nginx@sha256:abcd", True), ("ghcr.io/o/a:1@sha256:ff", True), ("nginx:latest", False)],
)
def test_digest_pinned_detection(image: str, pinned: bool) -> None:
    assert docker._split_image_ref(image).pinned is pinned


def test_parse_www_authenticate() -> None:
    hdr = 'Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:o/a:pull"'
    assert docker._parse_www_authenticate(hdr) == {
        "realm": "https://ghcr.io/token",
        "service": "ghcr.io",
        "scope": "repository:o/a:pull",
    }
    assert docker._parse_www_authenticate('Basic realm="x"') is None
    assert docker._parse_www_authenticate("") is None


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_manifest_head_performs_bearer_flow_and_caches_token() -> None:
    docker._registry_token_cache.clear()
    token_calls = 0
    seen_auth: list[str | None] = []

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal token_calls
        if req.url.host == "auth.example":
            token_calls += 1
            assert req.url.params["service"] == "reg.example"
            assert req.url.params["scope"] == "repository:o/a:pull"
            return httpx.Response(200, json={"token": "tok", "expires_in": 300})
        seen_auth.append(req.headers.get("authorization"))
        if req.headers.get("authorization") != "Bearer tok":
            return httpx.Response(
                401,
                headers={
                    "www-authenticate": 'Bearer realm="https://auth.example/token",'
                    'service="reg.example",scope="repository:o/a:pull"'
                },
            )
        return httpx.Response(200, headers={"docker-content-digest": "sha256:new"})

    async with _client(handler) as c:
        url = "https://reg.example/v2/o/a/manifests/latest"
        r1 = await docker._registry_manifest_head(c, url)
        r2 = await docker._registry_manifest_head(c, url)
    assert r1.headers["docker-content-digest"] == "sha256:new"
    assert r2.status_code == 200
    assert token_calls == 1  # second call reused the cached token
    assert seen_auth[0] is None and seen_auth[1] == "Bearer tok"


@pytest.mark.asyncio
async def test_check_update_detects_remote_change_and_pinned() -> None:
    docker._registry_token_cache.clear()

    def registry(req: httpx.Request) -> httpx.Response:
        if req.url.host == "ghcr.io" and req.url.path == "/token":
            return httpx.Response(200, json={"token": "t"})
        if req.headers.get("authorization") != "Bearer t":
            return httpx.Response(
                401,
                headers={
                    "www-authenticate": 'Bearer realm="https://ghcr.io/token",service="ghcr.io"'
                },
            )
        return httpx.Response(200, headers={"docker-content-digest": "sha256:" + "b" * 64})

    def local(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"RepoDigests": ["ghcr.io/o/a@sha256:" + "a" * 64]})

    async with _client(local) as dk, _client(registry) as rc:
        out = await docker._check_single_container_update(
            {"name": "a", "image": "ghcr.io/o/a:latest"}, dk, rc
        )
        pinned = await docker._check_single_container_update(
            {"name": "n", "image": "nginx@sha256:abcd"}, dk, rc
        )
    assert out is not None and out[1]["has_update"] is True
    assert pinned is not None
    assert pinned[1]["has_update"] is False and pinned[1]["pinned"] is True


@pytest.mark.parametrize(
    ("body", "has_error"),
    [
        ('{"status":"Pulling"}\n{"status":"Downloaded"}\n', False),
        ('{"status":"Pulling"}\n{"errorDetail":{"message":"denied"},"error":"denied"}\n', True),
        ('{"error":"manifest unknown"}', True),
        ("not json\n\n", False),
    ],
)
def test_pull_stream_error(body: str, has_error: bool) -> None:
    assert (docker._pull_stream_error(body) is not None) is has_error


def _patch_docker(
    monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]
):
    monkeypatch.setattr(docker, "_docker_transport", lambda: httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_pull_and_recreate_reports_stream_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(f"{req.method} {req.url.path}")
        if req.url.path.endswith("/json"):
            return httpx.Response(
                200, json={"Id": "abc" * 20, "Name": "/x", "Config": {"Image": "foo/bar:1"}}
            )
        if req.url.path.endswith("/images/create"):
            return httpx.Response(200, text='{"error":"pull access denied","errorDetail":{}}\n')
        return httpx.Response(204)

    _patch_docker(monkeypatch, handler)
    out = await docker.pull_and_recreate("x")
    assert out["status"] == "error"
    assert "pull access denied" in out["message"]
    assert not any("/stop" in c or c.startswith("DELETE") for c in calls)


@pytest.mark.asyncio
async def test_self_update_aborts_on_pull_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/containers/panelarr/json"):
            return httpx.Response(
                200, json={"Id": "a" * 64, "Name": "/panelarr", "Config": {"Image": "x/y:latest"}}
            )
        if req.url.path.endswith("/images/create"):
            return httpx.Response(200, text='{"error":"nope"}\n')
        raise AssertionError(f"unexpected call {req.url.path}")

    _patch_docker(monkeypatch, handler)
    out = await docker.self_update()
    assert out["status"] == "error"


def test_inspect_labels_and_url_filtering() -> None:
    inspect = {
        "Id": "a" * 64,
        "Name": "/svc",
        "State": {"Status": "running"},
        "Config": {
            "Image": "x/y",
            "Labels": {
                "panelarr.url": "https://svc.example.com",
                "caddy_0": "javascript:alert(1)",
            },
        },
    }
    urls = docker._parse_container(inspect)["urls"]
    assert urls == [{"url": "https://svc.example.com", "source": "custom"}]


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "data:text/html,x", "ftp://x", "//x.y", ""])
def test_custom_label_non_http_dropped(bad: str) -> None:
    assert docker._extract_public_urls({"panelarr.url": bad}) == []


@pytest.mark.asyncio
async def test_get_docker_version_swallows_http_status_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_docker(monkeypatch, lambda _r: httpx.Response(403))
    assert await docker.get_docker_version() is None
    _patch_docker(monkeypatch, lambda _r: httpx.Response(200, text="<html>"))
    assert await docker.get_docker_version() is None


# ── self-update builders ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("image", "target", "expected"),
    [
        ("ghcr.io/thug-drama/panelarr:0.3.0", "0.3.1", "ghcr.io/thug-drama/panelarr:0.3.1"),
        ("ghcr.io/thug-drama/panelarr:v0.3.0", "0.3.1", "ghcr.io/thug-drama/panelarr:v0.3.1"),
        (
            "ghcr.io/thug-drama/panelarr:0.3.0-alpha",
            "0.3.1-alpha",
            "ghcr.io/thug-drama/panelarr:0.3.1-alpha",
        ),
        ("ghcr.io/thug-drama/panelarr:latest", "0.3.1", "ghcr.io/thug-drama/panelarr:latest"),
        ("ghcr.io/thug-drama/panelarr:dev", "0.3.1", "ghcr.io/thug-drama/panelarr:dev"),
        ("ghcr.io/thug-drama/panelarr:0.3.0", None, "ghcr.io/thug-drama/panelarr:0.3.0"),
        ("ghcr.io/thug-drama/panelarr:0.3.0", "latest", "ghcr.io/thug-drama/panelarr:0.3.0"),
        ("localhost:5000/panelarr:1.0.0", "1.1.0", "localhost:5000/panelarr:1.1.0"),
        ("panelarr@sha256:ab", "1.1.0", "panelarr@sha256:ab"),
    ],
)
def test_resolve_update_image(image: str, target: str | None, expected: str) -> None:
    assert docker.resolve_update_image(image, target) == expected


@pytest.mark.parametrize(
    ("sock", "expected"),
    [
        ("http://socket-proxy:2375", "tcp://socket-proxy:2375"),
        ("tcp://socket-proxy:2375/", "tcp://socket-proxy:2375"),
        ("/var/run/docker.sock", "unix:///var/run/docker.sock"),
    ],
)
def test_docker_cli_host(sock: str, expected: str) -> None:
    assert docker._docker_cli_host(sock) == expected


def test_sidecar_spec_tcp_joins_self_networks_and_keeps_secrets_out_of_cmd() -> None:
    spec = docker.build_sidecar_spec(
        "echo hi",
        "SECRET=hunter2",
        "http://socket-proxy:2375",
        ["media_net", "bridge"],
        "media_net",
    )
    assert spec["Image"] == "docker:27-cli"
    assert spec["HostConfig"]["NetworkMode"] == "media_net"
    assert set(spec["NetworkingConfig"]["EndpointsConfig"]) == {"media_net", "bridge"}
    assert "DOCKER_HOST=tcp://socket-proxy:2375" in spec["Env"]
    assert "hunter2" not in json.dumps(spec["Cmd"])
    b64 = next(e for e in spec["Env"] if e.startswith("PANELARR_ENV_B64="))
    assert base64.b64decode(b64.split("=", 1)[1]).decode() == "SECRET=hunter2"


def test_sidecar_spec_tcp_host_mode_and_unix() -> None:
    host = docker.build_sidecar_spec("x", "", "tcp://h:1", [], "host")
    assert host["HostConfig"]["NetworkMode"] == "host"
    unix = docker.build_sidecar_spec("x", "", "/var/run/docker.sock", ["n"], "n")
    assert unix["HostConfig"]["NetworkMode"] == "none"
    assert unix["HostConfig"]["Binds"] == ["/var/run/docker.sock:/var/run/docker.sock"]
    assert not any(e.startswith("DOCKER_HOST") for e in unix["Env"])


def _old_container() -> dict:
    return {
        "Id": "f" * 64,
        "Name": "/panelarr",
        "Config": {
            "Image": "ghcr.io/thug-drama/panelarr:0.3.0",
            "Hostname": "f" * 12,
            "Env": ["PATH=/usr/bin", "PYTHON_VERSION=3.12", "API_TOKEN=s3cret", "TZ=UTC"],
            "Labels": {
                "org.opencontainers.image.version": "0.3.0",
                "panelarr.url": "https://p.example",
            },
            "Cmd": ["uvicorn"],
            "Entrypoint": ["/entrypoint.sh"],
            "Healthcheck": {
                "Test": ["CMD", "curl", "-f", "http://localhost:8000/x y"],
                "Interval": 30_000_000_000,
                "Retries": 3,
            },
        },
        "HostConfig": {
            "NetworkMode": "media_net",
            "RestartPolicy": {"Name": "unless-stopped"},
            "Binds": ["/srv/config:/config:rw"],
            "Mounts": [
                {"Type": "bind", "Source": "/mnt/a,b", "Target": "/data", "ReadOnly": True},
                {"Type": "volume", "Source": "vol1", "Target": "/v"},
                {"Type": "tmpfs", "Target": "/t", "TmpfsOptions": {"SizeBytes": 1000}},
            ],
            "PortBindings": {"8000/tcp": [{"HostIp": "", "HostPort": "18000"}]},
            "SecurityOpt": ["no-new-privileges:true"],
            "Devices": [
                {
                    "PathOnHost": "/dev/dri",
                    "PathInContainer": "/dev/dri",
                    "CgroupPermissions": "rwm",
                }
            ],
            "ExtraHosts": ["db:10.0.0.5"],
            "Dns": ["1.1.1.1"],
            "Tmpfs": {"/run": "rw,size=64m"},
            "CapAdd": ["NET_ADMIN"],
            "CapDrop": ["ALL"],
        },
        "NetworkSettings": {
            "Networks": {
                "other": {"Aliases": ["svc"]},
                "media_net": {
                    "Aliases": ["panelarr", "ffffffffffff", "panel"],
                    "IPAMConfig": {"IPv4Address": "10.1.0.9"},
                },
            }
        },
    }


def test_build_recreate_plan_fidelity() -> None:
    image_cfg = {
        "Env": ["PATH=/usr/bin", "PYTHON_VERSION=3.12"],
        "Labels": {"org.opencontainers.image.version": "0.3.0"},
        "Cmd": ["uvicorn"],
        "Entrypoint": ["/entrypoint.sh"],
    }
    plan = docker.build_recreate_plan(
        _old_container(), "ghcr.io/thug-drama/panelarr:0.3.1", image_cfg, env_file_path="/tmp/e"
    )
    argv = plan.argv
    joined = " ".join(argv)

    # secrets and env never appear in argv; image defaults are not pinned
    assert "s3cret" not in joined
    assert plan.env_file.splitlines() == ["API_TOKEN=s3cret", "TZ=UTC"]
    assert "--env-file" in argv and "/tmp/e" in argv

    # image labels dropped, container-specific labels kept
    assert "panelarr.url=https://p.example" in argv
    assert "org.opencontainers.image.version=0.3.0" not in joined

    pairs = list(zip(argv, argv[1:]))
    for pair in [
        ("--security-opt", "no-new-privileges:true"),
        ("--add-host", "db:10.0.0.5"),
        ("--dns", "1.1.1.1"),
        ("--cap-add", "NET_ADMIN"),
        ("--cap-drop", "ALL"),
        ("--device", "/dev/dri:/dev/dri:rwm"),
        ("--tmpfs", "/run:rw,size=64m"),
        ("--volume", "/srv/config:/config:rw"),
        ("--publish", "18000:8000/tcp"),
        ("--restart", "unless-stopped"),
        ("--mount", 'type=bind,"source=/mnt/a,b",target=/data,readonly'),
        ("--mount", "type=volume,source=vol1,target=/v"),
        ("--mount", "type=tmpfs,target=/t,tmpfs-size=1000"),
        ("--health-cmd", "curl -f 'http://localhost:8000/x y'"),
        ("--health-interval", "30000ms"),
        ("--network", "media_net"),
        ("--network-alias", "panel"),
        ("--ip", "10.1.0.9"),
    ]:
        assert pair in pairs, pair
    assert "--hostname" not in argv  # default hostname == container id prefix
    assert argv[-1] == "ghcr.io/thug-drama/panelarr:0.3.1"
    assert plan.network_connects == [
        ["docker", "network", "connect", "--alias", "svc", "other", "panelarr"]
    ]


def test_build_recreate_plan_host_network_has_no_publish() -> None:
    old = {
        "Id": "a" * 64,
        "Name": "/x",
        "Config": {},
        "HostConfig": {"NetworkMode": "host", "PortBindings": {"80/tcp": [{"HostPort": "80"}]}},
    }
    argv = docker.build_recreate_plan(old, "img").argv
    assert ("--network", "host") in list(zip(argv, argv[1:]))
    assert "--publish" not in argv


def test_update_script_is_rollback_safe_and_secret_free() -> None:
    plan = docker.build_recreate_plan(
        _old_container(), "img:1", {}, env_file_path="/tmp/panelarr.env"
    )
    script = docker.build_update_script("panelarr", plan)
    assert "set -e" not in script.splitlines()
    assert script.index("docker rename 'panelarr' 'panelarr-old'") < script.index(
        "'docker' 'create'"
    )
    assert "rollback" in script
    assert script.index("|| rollback") < script.rindex("docker rm -f 'panelarr-old'")
    assert "docker rename 'panelarr-old' 'panelarr'" in script
    assert "s3cret" not in script
    # old container is not removed before the new one is created and started
    assert script.index("'docker' 'create'") < script.rindex("docker rm -f 'panelarr-old'")
    assert not script.startswith("docker rm 'panelarr'")


def test_sidecar_image_is_pinned() -> None:
    assert ":" in docker.SIDECAR_IMAGE and not docker.SIDECAR_IMAGE.endswith(":cli")


def test_dataclass_plan_default() -> None:
    assert dataclasses.is_dataclass(docker.RecreatePlan)
