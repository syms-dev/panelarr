from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import shlex
import struct
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)

DOCKER_API_VERSION = "v1.44"
DOCKER_TIMEOUT = 30
STATS_TIMEOUT = 5
_MANIFEST_ACCEPT = (
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.docker.distribution.manifest.v2+json, "
    "application/vnd.oci.image.index.v1+json"
)


def _docker_transport() -> httpx.AsyncHTTPTransport:
    sock = settings.docker_socket
    if sock.startswith("tcp://") or sock.startswith("http://"):
        return httpx.AsyncHTTPTransport()
    return httpx.AsyncHTTPTransport(uds=sock)


def _docker_base_url() -> str:
    sock = settings.docker_socket
    if sock.startswith("tcp://"):
        return sock.replace("tcp://", "http://")
    if sock.startswith("http://"):
        return sock
    return "http://localhost"


def _docker_url(path: str) -> str:
    return f"{_docker_base_url()}/{DOCKER_API_VERSION}{path}"


def _is_tcp_socket(sock: str) -> bool:
    """Return True when the configured Docker endpoint is TCP rather than a unix socket."""
    return sock.startswith("tcp://") or sock.startswith("http://")


def _docker_cli_host(sock: str) -> str:
    """Return a DOCKER_HOST value (tcp://host:port) the docker CLI understands.

    The CLI rejects ``http://`` endpoints, so TCP endpoints are normalised to
    ``tcp://``. Unix socket paths are not usable as DOCKER_HOST inside a sidecar
    (they are bind-mounted instead) and are returned as ``unix:///var/run/docker.sock``.
    """
    if sock.startswith("http://"):
        return "tcp://" + sock[len("http://") :].rstrip("/")
    if sock.startswith("tcp://"):
        return sock.rstrip("/")
    return "unix:///var/run/docker.sock"


def _safe_http_url(url: str) -> str:
    """Return ``url`` only if it is an absolute http(s) URL, else an empty string."""
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme in ("http", "https") and parsed.hostname:
            parsed.port  # noqa: B018 - raises ValueError on a malformed port
            return url.strip()
    except ValueError:
        pass
    return ""


async def get_docker_info() -> dict | None:
    """Return the Docker daemon ``/info`` payload, or None if unreachable."""
    try:
        async with httpx.AsyncClient(transport=_docker_transport(), timeout=5) as client:
            resp = await client.get(_docker_url("/info"))
            if resp.status_code == 200:
                data = resp.json()
                return data if isinstance(data, dict) else None
    except (httpx.HTTPError, ValueError):
        pass
    return None


def _human_uptime(started_at: str) -> str:
    """Convert ISO timestamp to human-readable uptime."""
    try:
        start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        delta = datetime.now(UTC) - start
        days = delta.days
        hours, remainder = divmod(delta.seconds, 3600)
        minutes = remainder // 60
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"
    except (ValueError, TypeError):
        return ""


def _compute_uptime(started_at: str, raw_status: str, state: str) -> str:
    """Compute uptime from StartedAt or fall back to Docker Status field."""
    if state != "running":
        return ""
    if started_at:
        result = _human_uptime(started_at)
        if result:
            return result
    # List API returns "Up 3 days" or "Up 2 hours" in Status field
    if raw_status.lower().startswith("up "):
        return raw_status[3:].strip()
    return ""


def _format_bytes(num_bytes: int | float) -> str:
    """Format bytes to human-readable string."""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num_bytes) < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PiB"


def _calc_cpu_pct(stats: dict) -> float:
    """Calculate CPU % from Docker stats response."""
    try:
        cpu_delta = (
            stats["cpu_stats"]["cpu_usage"]["total_usage"]
            - stats["precpu_stats"]["cpu_usage"]["total_usage"]
        )
        system_delta = (
            stats["cpu_stats"]["system_cpu_usage"] - stats["precpu_stats"]["system_cpu_usage"]
        )
        num_cpus = stats["cpu_stats"].get("online_cpus", 1)
        if system_delta > 0 and cpu_delta >= 0:
            return round((cpu_delta / system_delta) * num_cpus * 100, 2)
    except (KeyError, TypeError, ZeroDivisionError):
        pass
    return 0.0


def _extract_public_urls(labels: dict) -> list[dict]:
    """Extract public URLs from reverse proxy labels (Traefik, Caddy, nginx-proxy, custom)."""
    urls: list[dict] = []
    seen: set[str] = set()

    # Traefik: traefik.http.routers.{name}.rule = Host(`domain`)
    entrypoints: dict[str, str] = {}
    rules: dict[str, str] = {}
    tls_routers: set[str] = set()
    for key, value in labels.items():
        if not key.startswith("traefik.http.routers."):
            continue
        parts = key.split(".")
        if len(parts) < 5:
            continue
        router_name = parts[3]
        suffix = ".".join(parts[4:])
        if suffix == "rule":
            rules[router_name] = value
        elif suffix == "entrypoints":
            entrypoints[router_name] = value
        elif suffix.startswith("tls"):
            tls_routers.add(router_name)

    for router_name, rule in rules.items():
        hosts = re.findall(r"Host\(`([^`]+)`\)", rule)
        ep = entrypoints.get(router_name, "")
        has_tls = router_name in tls_routers
        is_https = has_tls or "websecure" in ep or "https" in ep
        protocol = "https" if is_https else "http"
        for host in hosts:
            url = f"{protocol}://{host}"
            if url not in seen:
                urls.append({"url": url, "source": "traefik"})
                seen.add(url)

    # Caddy: caddy=domain or caddy_0=domain
    for key, value in labels.items():
        if key == "caddy" or key.startswith("caddy_"):
            domain = value.strip()
            if domain and not domain.startswith("http"):
                url = f"https://{domain}"
            else:
                url = domain
            if url and url not in seen:
                urls.append({"url": url, "source": "caddy"})
                seen.add(url)

    # nginx-proxy: VIRTUAL_HOST=domain
    vhost = labels.get("VIRTUAL_HOST", "")
    if vhost:
        for host in vhost.split(","):
            host = host.strip()
            if host:
                url = f"http://{host}"
                if url not in seen:
                    urls.append({"url": url, "source": "nginx-proxy"})
                    seen.add(url)

    # Custom: panelarr.url=https://...
    custom_url = labels.get("panelarr.url", "")
    if custom_url and custom_url not in seen:
        urls.append({"url": custom_url, "source": "custom"})
        seen.add(custom_url)

    # Only http(s) URLs may reach the UI (drops javascript:, data:, etc.)
    return [u for u in urls if _safe_http_url(u["url"])]


def _parse_container(container: dict, stats: dict | None = None) -> dict:
    """Parse Docker API container + optional stats into our response shape."""
    state = container.get("State", "unknown")
    if isinstance(state, dict):
        status_text = state.get("Status", "unknown")
        started_at = state.get("StartedAt", "")
    else:
        status_text = state
        started_at = ""

    name = container.get("Name", "").lstrip("/")
    if not name:
        names = container.get("Names", [])
        name = names[0].lstrip("/") if names else container.get("Id", "")[:12]

    ports = {}
    for p in container.get("Ports", []):
        private = p.get("PrivatePort")
        public = p.get("PublicPort")
        if private:
            ports[f"{private}/tcp"] = public or private

    cpu_pct = 0.0
    mem_usage = "0 MiB"
    mem_limit = "0 MiB"
    if stats:
        cpu_pct = _calc_cpu_pct(stats)
        mem_stats = stats.get("memory_stats", {})
        mem_usage = _format_bytes(mem_stats.get("usage", 0))
        mem_limit = _format_bytes(mem_stats.get("limit", 0))

    restart_count = 0
    host_config = container.get("HostConfig", {})
    if isinstance(host_config, dict):
        restart_policy = host_config.get("RestartPolicy", {})
        if isinstance(restart_policy, dict):
            restart_count = restart_policy.get("MaximumRetryCount", 0)
    state_obj = container.get("State", {})
    if isinstance(state_obj, dict):
        restart_count = state_obj.get("RestartCount", restart_count)

    # Resolve human-readable image name, multiple fallback sources
    image = container.get("Image", "")
    config_obj = container.get("Config", {}) if isinstance(container.get("Config"), dict) else {}
    # The list endpoint exposes top-level "Labels"; inspect nests them in Config.Labels.
    labels = container.get("Labels") or config_obj.get("Labels") or {}

    # Priority: Compose label > Config.Image > OCI label > top-level Image
    compose_image = labels.get("com.docker.compose.image", "")
    config_image = config_obj.get("Image", "")

    if compose_image and not compose_image.startswith("sha256:"):
        image = compose_image
    elif config_image and not config_image.startswith("sha256:"):
        image = config_image
    elif image.startswith("sha256:"):
        oci_title = labels.get("org.opencontainers.image.title", "")
        if oci_title:
            image = oci_title
        else:
            image = image[:19] + "..."

    return {
        "id": container.get("Id", "")[:12],
        "name": name,
        "image": image,
        "status": container.get("Status", status_text),
        "state": status_text if isinstance(status_text, str) else "unknown",
        "ports": ports,
        "created": container.get("Created", ""),
        "uptime": _compute_uptime(started_at, container.get("Status", ""), status_text),
        "cpu_percent": cpu_pct,
        "memory_usage": mem_usage,
        "memory_limit": mem_limit,
        "restart_count": restart_count,
        "urls": _extract_public_urls(labels),
    }


async def _fetch_stats(client: httpx.AsyncClient, container_id: str) -> dict | None:
    """Fetch stats for a single container. Returns None on error."""
    try:
        resp = await client.get(
            _docker_url(f"/containers/{container_id}/stats"),
            params={"stream": "false"},
            timeout=STATS_TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json()
    except (httpx.HTTPError, ValueError):
        pass
    return None


async def list_containers(show_all: bool = True) -> list[dict]:
    """List all Docker containers with stats."""
    async with httpx.AsyncClient(transport=_docker_transport(), timeout=DOCKER_TIMEOUT) as client:
        resp = await client.get(
            _docker_url("/containers/json"),
            params={"all": str(show_all).lower()},
        )
        resp.raise_for_status()
        containers = resp.json()

        running_ids = [c["Id"] for c in containers if c.get("State") == "running"]

        stats_map: dict[str, dict | None] = {}
        if running_ids:
            results = await asyncio.gather(
                *[_fetch_stats(client, cid) for cid in running_ids],
                return_exceptions=True,
            )
            for cid, result in zip(running_ids, results):
                stats_map[cid] = result if isinstance(result, dict) else None

        return [_parse_container(c, stats_map.get(c["Id"])) for c in containers]


async def get_container(name_or_id: str) -> dict | None:
    """Get a single container by name or ID."""
    async with httpx.AsyncClient(transport=_docker_transport(), timeout=DOCKER_TIMEOUT) as client:
        resp = await client.get(_docker_url(f"/containers/{name_or_id}/json"))
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        container = resp.json()

        stats = None
        state = container.get("State", {})
        if isinstance(state, dict) and state.get("Running"):
            stats = await _fetch_stats(client, container["Id"])

        return _parse_container(container, stats)


async def container_identity(name_or_id: str) -> dict | None:
    """Resolve a name, id or id prefix to the container Docker would act on.

    Returns ``{"id": <full id>, "names": {name, hostname, network aliases}}``
    (lower-cased), or None when no such container exists.
    """
    async with httpx.AsyncClient(transport=_docker_transport(), timeout=DOCKER_TIMEOUT) as client:
        resp = await client.get(_docker_url(f"/containers/{name_or_id}/json"))
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
    names = {str(data.get("Name", "")).lstrip("/")}
    names.add(str((data.get("Config") or {}).get("Hostname", "")))
    networks = (data.get("NetworkSettings") or {}).get("Networks") or {}
    for net in networks.values():
        names.update(str(a) for a in (net or {}).get("Aliases") or [])
    return {
        "id": str(data.get("Id", "")).lower(),
        "names": {n.lower() for n in names if n},
    }


ALLOWED_ACTIONS = frozenset({"start", "stop", "restart"})
PULL_TIMEOUT = 300  # 5 minutes for image pulls


def _pull_stream_error(body: str) -> str | None:
    """Return the first error found in an ``/images/create`` JSON-lines stream.

    The Engine answers ``200`` even when a pull fails midway; the failure is only
    reported as ``{"error": ..., "errorDetail": {...}}`` in the streamed body.
    """
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue
        detail = obj.get("errorDetail")
        msg = obj.get("error") or (detail.get("message") if isinstance(detail, dict) else None)
        if msg or detail:
            return str(msg or "pull failed")[:200]
    return None


async def _pull_image(
    client: httpx.AsyncClient, image: str, *, timeout: float = PULL_TIMEOUT
) -> str | None:
    """Pull ``image`` via the Engine API. Returns None on success, else an error string."""
    resp = await client.post(
        _docker_url("/images/create"), params={"fromImage": image}, timeout=timeout
    )
    if resp.status_code not in (200, 204):
        return f"HTTP {resp.status_code}"
    return _pull_stream_error(resp.text)


async def _image_config(client: httpx.AsyncClient, image_ref: str) -> dict:
    """Return the ``Config`` section of a local image, or {} if it cannot be inspected."""
    try:
        resp = await client.get(_docker_url(f"/images/{image_ref}/json"))
        if resp.status_code == 200:
            cfg = resp.json().get("Config")
            if isinstance(cfg, dict):
                return cfg
    except (httpx.HTTPError, ValueError):
        pass
    return {}


def _user_env(env: list[str] | None, image_env: list[str] | None) -> list[str]:
    """Return container env entries that are not just the old image's defaults."""
    defaults = set(image_env or [])
    return [e for e in env or [] if e not in defaults]


def _user_labels(labels: dict | None, image_labels: dict | None) -> dict[str, str]:
    """Return container labels that are not just inherited from the old image."""
    inherited = image_labels or {}
    return {k: v for k, v in (labels or {}).items() if k not in inherited or inherited[k] != v}


def _strip_image_defaults(config: dict, image_config: dict, container_id: str) -> dict:
    """Copy a container ``Config`` without values merely inherited from its old image.

    Pinning the old image's ENV/labels/CMD onto the recreated container would
    override the new image's updated defaults (e.g. PYTHON_VERSION, PATH).
    """
    out = dict(config)
    out["Env"] = _user_env(config.get("Env"), image_config.get("Env"))
    out["Labels"] = _user_labels(config.get("Labels"), image_config.get("Labels"))
    for key in (
        "Cmd",
        "Entrypoint",
        "Healthcheck",
        "User",
        "WorkingDir",
        "ExposedPorts",
        "Volumes",
    ):
        if key in out and out[key] == image_config.get(key):
            del out[key]
    if out.get("Hostname") == container_id[:12]:
        del out["Hostname"]
    return out


def _endpoint_config(net_config: dict, short_id: str) -> dict:
    """Build an EndpointConfig for create/connect from an inspected network entry."""
    aliases = [a for a in net_config.get("Aliases") or [] if a != short_id]
    return {"IPAMConfig": net_config.get("IPAMConfig"), "Aliases": aliases or None}


async def pull_and_recreate(name_or_id: str) -> dict:
    """Pull the latest image and fully recreate the container.

    Watchtower-style update: inspect → pull → stop → remove → create → start → reconnect networks.
    Preserves container-specific config (env vars, volumes, ports, labels, restart policy,
    networks) but not values merely inherited from the old image.

    NOTE: Do NOT call this from within the container being updated. The stop step
    will kill the running process before the new container can be started, leaving
    the service down. Use self_update() instead, which delegates the destructive
    steps to an ephemeral Docker CLI sidecar container so the swap happens after
    the HTTP response has been sent.
    """
    try:
        async with httpx.AsyncClient(transport=_docker_transport(), timeout=PULL_TIMEOUT) as client:
            # 1. Inspect the running container to capture full config
            inspect_resp = await client.get(_docker_url(f"/containers/{name_or_id}/json"))
            if inspect_resp.status_code == 404:
                return {"status": "error", "message": "Container not found"}
            inspect_resp.raise_for_status()
            old = inspect_resp.json()

            config = old.get("Config", {})
            host_config = old.get("HostConfig", {})
            network_settings = old.get("NetworkSettings", {})
            container_name = old.get("Name", "").lstrip("/")
            image = config.get("Image", "")

            if not image:
                return {"status": "error", "message": "Cannot determine container image"}

            # 2. Pull the latest image (a failed pull still answers HTTP 200)
            logger.info("Pulling image %s for container %s", image, container_name)
            pull_error = await _pull_image(client, image)
            if pull_error:
                logger.warning("Pull failed for %s: %s", image, pull_error)
                return {"status": "error", "message": f"Pull failed: {pull_error}"}

            old_image_config = await _image_config(client, old.get("Image", ""))

            # 3. Stop the old container
            await client.post(
                _docker_url(f"/containers/{old['Id']}/stop"),
                params={"t": "10"},
            )

            # 4. Remove the old container
            rm_resp = await client.delete(
                _docker_url(f"/containers/{old['Id']}"),
                params={"force": "true"},
            )
            if rm_resp.status_code not in (200, 204):
                return {
                    "status": "error",
                    "message": "Failed to remove old container, it may need manual cleanup",
                }

            # 5. Build the create payload from the old container's config
            if host_config.get("Privileged"):
                logger.warning(
                    "Container %s has Privileged=true, recreating with same privileges",
                    container_name,
                )
            create_body: dict = {
                **_strip_image_defaults(config, old_image_config, old.get("Id", "")),
                "HostConfig": host_config,
            }

            # Attach to the same networks
            networks = network_settings.get("Networks", {})
            short_id = old.get("Id", "")[:12]
            if networks:
                networking_config: dict = {"EndpointsConfig": {}}
                for net_name, net_config in networks.items():
                    networking_config["EndpointsConfig"][net_name] = _endpoint_config(
                        net_config, short_id
                    )
                create_body["NetworkingConfig"] = networking_config

            # 6. Create the new container with the same name
            create_resp = await client.post(
                _docker_url("/containers/create"),
                params={"name": container_name},
                json=create_body,
            )
            if create_resp.status_code not in (200, 201):
                error_body = create_resp.text
                logger.warning("Container create failed: %s", error_body[:200])
                return {
                    "status": "error",
                    "message": "Failed to create container, check server logs",
                }
            new_id = create_resp.json().get("Id", "")

            # 7. Connect to additional networks (create only connects to the first)
            for net_name in list(networks.keys())[1:]:
                await client.post(
                    _docker_url(f"/networks/{net_name}/connect"),
                    json={
                        "Container": new_id,
                        "EndpointConfig": _endpoint_config(networks[net_name], short_id),
                    },
                )

            # 8. Start the new container
            start_resp = await client.post(_docker_url(f"/containers/{new_id}/start"))
            if start_resp.status_code not in (200, 204):
                return {
                    "status": "partial",
                    "message": "Container recreated but failed to start",
                }

            logger.info("Container %s updated successfully", container_name)
            return {
                "status": "ok",
                "message": f"Updated {container_name}, pulled, recreated, and started",
                "image": image,
            }
    except httpx.TimeoutException:
        return {"status": "error", "message": "Pull timed out, image may be very large"}
    except Exception:
        logger.exception("Container update failed for %s", name_or_id)
        return {"status": "error", "message": "Container update failed, check server logs"}


# ── Self-update helpers (pure, unit-tested) ──────────────────────────────────

SELF_CONTAINER_NAME = "panelarr"
SIDECAR_IMAGE = "docker:27-cli"
_VERSION_TAG_RE = re.compile(r"^v?\d+(\.\d+){1,3}([.-][0-9A-Za-z.-]+)?$")
_DEFAULT_SHM_SIZE = 64 * 1024 * 1024


def _shell_quote(s: str) -> str:
    """Minimal shell single-quote escaping for embedding in a sh -c script."""
    return "'" + s.replace("'", "'\\''") + "'"


def is_version_tag(tag: str) -> bool:
    """Return True if ``tag`` looks like a release version (``0.3.0``, ``v1.2.3-alpha``)."""
    return bool(_VERSION_TAG_RE.match(tag or ""))


def resolve_update_image(image: str, target_version: str | None) -> str:
    """Return the image reference self-update should pull.

    A version-pinned tag can never update by re-pulling itself, so when the
    current tag looks like a version and ``target_version`` is a valid version,
    the tag is swapped for the target. ``latest``/``dev``/digest-pinned
    references are returned unchanged (re-pull the same tag).
    """
    registry, repo, tag = _parse_image_ref(image)
    if (
        not target_version
        or not tag
        or not is_version_tag(tag)
        or not is_version_tag(target_version)
    ):
        return image
    base = image.split("@", 1)[0]
    last = base.rsplit("/", 1)[-1]
    if ":" in last:
        base = base.rsplit(":", 1)[0]
    new_tag = target_version
    if tag.startswith("v") and not new_tag.startswith("v"):
        new_tag = f"v{new_tag}"
    elif not tag.startswith("v") and new_tag.startswith("v"):
        new_tag = new_tag[1:]
    return f"{base}:{new_tag}"


def _mount_csv(fields: list[tuple[str, str | None]]) -> str:
    """Build a ``--mount`` CSV value, quoting fields that contain commas or quotes."""
    out: list[str] = []
    for key, value in fields:
        item = key if value is None else f"{key}={value}"
        if "," in item or '"' in item:
            item = '"' + item.replace('"', '""') + '"'
        out.append(item)
    return ",".join(out)


def _mount_args(host_config: dict) -> list[str]:
    """Translate HostConfig.Binds and HostConfig.Mounts into docker CLI flags."""
    argv: list[str] = []
    for bind in host_config.get("Binds") or []:
        argv += ["--volume", bind]
    for mount in host_config.get("Mounts") or []:
        mtype = mount.get("Type", "")
        target = mount.get("Target") or mount.get("Destination") or ""
        source = mount.get("Source") or mount.get("Name") or ""
        if not target or mtype not in ("bind", "volume", "tmpfs"):
            continue
        fields: list[tuple[str, str | None]] = [("type", mtype)]
        if mtype != "tmpfs":
            if not source:
                continue
            fields.append(("source", source))
        fields.append(("target", target))
        if mount.get("ReadOnly"):
            fields.append(("readonly", None))
        bind_opts = mount.get("BindOptions") or {}
        if mtype == "bind" and bind_opts.get("Propagation"):
            fields.append(("bind-propagation", bind_opts["Propagation"]))
        tmpfs_opts = mount.get("TmpfsOptions") or {}
        if mtype == "tmpfs":
            if tmpfs_opts.get("SizeBytes"):
                fields.append(("tmpfs-size", str(tmpfs_opts["SizeBytes"])))
            if tmpfs_opts.get("Mode"):
                fields.append(("tmpfs-mode", str(tmpfs_opts["Mode"])))
        argv += ["--mount", _mount_csv(fields)]
    for path, opts in (host_config.get("Tmpfs") or {}).items():
        argv += ["--tmpfs", f"{path}:{opts}" if opts else path]
    return argv


def _network_args(old: dict, container_name: str) -> tuple[list[str], list[list[str]]]:
    """Build ``--network`` flags plus ``docker network connect`` commands for extras."""
    host_config = old.get("HostConfig") or {}
    mode = host_config.get("NetworkMode") or ""
    nets = (old.get("NetworkSettings") or {}).get("Networks") or {}
    short_id = (old.get("Id") or "")[:12]
    if mode in ("host", "none") or mode.startswith("container:"):
        return ["--network", mode], []
    names = list(nets.keys())
    if mode in names:
        names.remove(mode)
        names.insert(0, mode)

    args: list[str] = []
    connects: list[list[str]] = []
    for idx, net in enumerate(names):
        ep = nets[net] or {}
        flags: list[str] = []
        if net != "bridge":  # aliases / static IPs need a user-defined network
            alias_flag = "--network-alias" if idx == 0 else "--alias"
            for alias in ep.get("Aliases") or []:
                if alias not in (short_id, container_name):
                    flags += [alias_flag, alias]
            ipam = ep.get("IPAMConfig") or {}
            if ipam.get("IPv4Address"):
                flags += ["--ip", ipam["IPv4Address"]]
            if ipam.get("IPv6Address"):
                flags += ["--ip6", ipam["IPv6Address"]]
        if idx == 0:
            args += ["--network", net, *flags]
        else:
            connects.append(["docker", "network", "connect", *flags, net, container_name])
    return args, connects


def _healthcheck_args(healthcheck: dict, image_healthcheck: dict | None) -> list[str]:
    """Translate Config.Healthcheck into ``--health-*`` flags (CMD and CMD-SHELL forms)."""
    if not healthcheck or healthcheck == (image_healthcheck or {}):
        return []
    test = healthcheck.get("Test") or []
    if test and test[0] == "NONE":
        return ["--no-healthcheck"]
    argv: list[str] = []
    if len(test) > 1:
        if test[0] == "CMD-SHELL":
            cmd = test[1]
        elif test[0] == "CMD":
            cmd = shlex.join(test[1:])
        else:
            cmd = ""
        if cmd:
            argv += ["--health-cmd", cmd]
    for key, flag in (
        ("Interval", "--health-interval"),
        ("Timeout", "--health-timeout"),
        ("StartPeriod", "--health-start-period"),
    ):
        if healthcheck.get(key):
            argv += [flag, f"{healthcheck[key] // 1_000_000}ms"]
    if healthcheck.get("Retries"):
        argv += ["--health-retries", str(healthcheck["Retries"])]
    return argv


@dataclass
class RecreatePlan:
    """Everything the sidecar needs to recreate a container with the docker CLI."""

    argv: list[str]
    env_file: str
    network_connects: list[list[str]] = field(default_factory=list)


def build_recreate_plan(
    old: dict, image: str, image_config: dict | None = None, *, env_file_path: str = ""
) -> RecreatePlan:
    """Build the ``docker create`` argv for recreating ``old`` (an inspect payload).

    ``image_config`` is the OLD image's Config; env/labels/cmd that equal its
    defaults are not pinned onto the new container. Container env vars are never
    placed in argv, they are returned as ``env_file`` content (one ``KEY=VALUE``
    per line) and referenced via ``--env-file env_file_path``.
    """
    image_config = image_config or {}
    config = old.get("Config") or {}
    host_config = old.get("HostConfig") or {}
    container_name = (old.get("Name") or "").lstrip("/")
    container_id = old.get("Id") or ""
    argv: list[str] = ["docker", "create", "--name", container_name]

    restart = host_config.get("RestartPolicy") or {}
    rp_name = restart.get("Name", "")
    if rp_name and rp_name != "no":
        retries = restart.get("MaximumRetryCount", 0)
        argv += [
            "--restart",
            f"on-failure:{retries}" if rp_name == "on-failure" and retries else rp_name,
        ]

    env_lines: list[str] = []
    for entry in _user_env(config.get("Env"), image_config.get("Env")):
        if "\n" in entry:
            logger.warning("self_update: dropping multi-line env var that --env-file cannot carry")
            continue
        env_lines.append(entry)
    if env_lines and env_file_path:
        argv += ["--env-file", env_file_path]

    for k, v in _user_labels(config.get("Labels"), image_config.get("Labels")).items():
        argv += ["--label", f"{k}={v}"]

    argv += _mount_args(host_config)

    net_args, connects = _network_args(old, container_name)
    argv += net_args
    net_mode = host_config.get("NetworkMode") or ""
    if net_mode != "host" and not net_mode.startswith("container:"):
        for container_port, bindings in (host_config.get("PortBindings") or {}).items():
            for hb in bindings or []:
                host_ip, host_port = hb.get("HostIp", ""), hb.get("HostPort", "")
                if host_ip:
                    argv += ["--publish", f"{host_ip}:{host_port}:{container_port}"]
                elif host_port:
                    argv += ["--publish", f"{host_port}:{container_port}"]
                else:
                    argv += ["--publish", container_port]

    hostname = config.get("Hostname", "")
    if hostname and hostname != container_id[:12] and net_mode != "host":
        argv += ["--hostname", hostname]
    if config.get("Domainname"):
        argv += ["--domainname", config["Domainname"]]
    if config.get("User") and config.get("User") != image_config.get("User"):
        argv += ["--user", config["User"]]
    if config.get("WorkingDir") and config.get("WorkingDir") != image_config.get("WorkingDir"):
        argv += ["--workdir", config["WorkingDir"]]
    if config.get("Tty"):
        argv.append("--tty")
    if config.get("OpenStdin"):
        argv.append("--interactive")

    for flag, key in (
        ("--dns", "Dns"),
        ("--dns-search", "DnsSearch"),
        ("--dns-option", "DnsOptions"),
        ("--add-host", "ExtraHosts"),
        ("--security-opt", "SecurityOpt"),
        ("--cap-add", "CapAdd"),
        ("--cap-drop", "CapDrop"),
        ("--group-add", "GroupAdd"),
    ):
        for value in host_config.get(key) or []:
            argv += [flag, value]
    for dev in host_config.get("Devices") or []:
        host_path = dev.get("PathOnHost", "")
        if host_path:
            spec = f"{host_path}:{dev.get('PathInContainer') or host_path}"
            perms = dev.get("CgroupPermissions")
            argv += ["--device", f"{spec}:{perms}" if perms else spec]
    for req in host_config.get("DeviceRequests") or []:
        caps = [c for cs in req.get("Capabilities") or [] for c in cs]
        if "gpu" in caps or req.get("Driver") == "nvidia":
            ids = req.get("DeviceIDs") or []
            if ids:
                argv += ["--gpus", f'"device={",".join(ids)}"']
            else:
                argv += ["--gpus", "all" if req.get("Count", -1) == -1 else str(req["Count"])]
    for key, value in (host_config.get("Sysctls") or {}).items():
        argv += ["--sysctl", f"{key}={value}"]
    for ul in host_config.get("Ulimits") or []:
        argv += ["--ulimit", f"{ul.get('Name')}={ul.get('Soft')}:{ul.get('Hard')}"]
    if host_config.get("Privileged"):
        argv.append("--privileged")
    if host_config.get("ReadonlyRootfs"):
        argv.append("--read-only")
    if host_config.get("Init"):
        argv.append("--init")
    for flag, key, skip in (
        ("--pid", "PidMode", ("", "private")),
        ("--ipc", "IpcMode", ("", "private", "shareable", "none")),
        ("--userns", "UsernsMode", ("",)),
    ):
        value = host_config.get(key) or ""
        if value not in skip:
            argv += [flag, value]
    shm = host_config.get("ShmSize") or 0
    if shm and shm != _DEFAULT_SHM_SIZE:
        argv += ["--shm-size", str(shm)]
    log_cfg = host_config.get("LogConfig") or {}
    if log_cfg.get("Type") and log_cfg["Type"] not in ("json-file", "json"):
        argv += ["--log-driver", log_cfg["Type"]]
    for k, v in (log_cfg.get("Config") or {}).items():
        argv += ["--log-opt", f"{k}={v}"]

    if host_config.get("Memory"):
        argv += ["--memory", str(host_config["Memory"])]
    if host_config.get("NanoCpus"):
        argv += ["--cpus", str(host_config["NanoCpus"] / 1_000_000_000)]

    argv += _healthcheck_args(config.get("Healthcheck") or {}, image_config.get("Healthcheck"))

    # Entrypoint / Cmd overrides (only if they differ from the old image's defaults)
    cmd_tail: list[str] = (
        list(config.get("Cmd") or []) if config.get("Cmd") != image_config.get("Cmd") else []
    )
    entrypoint = config.get("Entrypoint") or []
    if entrypoint != (image_config.get("Entrypoint") or []):
        if entrypoint:
            argv += ["--entrypoint", entrypoint[0]]
            cmd_tail = list(entrypoint[1:]) + (list(config.get("Cmd") or []))
        else:
            argv += ["--entrypoint", ""]
    argv.append(image)
    argv += cmd_tail

    return RecreatePlan(argv=argv, env_file="\n".join(env_lines), network_connects=connects)


def build_update_script(
    container_name: str, plan: RecreatePlan, env_file_path: str = "/tmp/panelarr.env"
) -> str:
    """Build the sidecar shell script performing a rollback-safe swap.

    Sequence: stop old → rename old to ``<name>-old`` → create + connect + start new →
    verify it is running → remove old. If create/start fails the new container is
    removed, the old one is renamed back and started again.
    """
    name = _shell_quote(container_name)
    old_name = _shell_quote(f"{container_name}-old")
    create_cmd = " ".join(_shell_quote(a) for a in plan.argv)
    connect_cmds = " && ".join(" ".join(_shell_quote(a) for a in c) for c in plan.network_connects)
    steps = [create_cmd]
    if connect_cmds:
        steps.append(connect_cmds)
    steps.append(f"docker start {name}")
    steps.append(f'sleep 5 && [ "$(docker inspect -f "{{{{.State.Running}}}}" {name})" = "true" ]')
    chain = " && ".join(steps)
    env_write = (
        f'printf %s "$PANELARR_ENV_B64" | base64 -d > {_shell_quote(env_file_path)}\n'
        if plan.env_file
        else ""
    )
    return (
        "set -u\n"
        "sleep 2\n"
        f"docker rm -f {old_name} >/dev/null 2>&1 || true\n"
        f"docker stop --time 10 {name} || exit 1\n"
        f"docker rename {name} {old_name} || {{ docker start {name}; exit 1; }}\n"
        f"{env_write}"
        "rollback() {\n"
        f"  docker rm -f {name} >/dev/null 2>&1\n"
        f"  docker rename {old_name} {name} && docker start {name}\n"
        f"  rm -f {_shell_quote(env_file_path)}\n"
        "  exit 1\n"
        "}\n"
        f"( {chain} ) || rollback\n"
        f"rm -f {_shell_quote(env_file_path)}\n"
        f"docker rm -f {old_name}\n"
    )


def build_sidecar_spec(
    script: str,
    env_file: str,
    docker_socket: str,
    self_networks: list[str],
    self_network_mode: str = "",
) -> dict:
    """Build the Engine API create body for the ephemeral ``docker:cli`` sidecar.

    TCP endpoints (socket proxies) usually resolve only on a compose network, so
    the sidecar joins the same network(s) as panelarr instead of host networking.
    The container env (which holds secrets) travels via the sidecar's Env as a
    base64 env-file, never in Cmd.
    """
    env = []
    if env_file:
        env.append("PANELARR_ENV_B64=" + base64.b64encode(env_file.encode()).decode())
    body: dict = {
        "Image": SIDECAR_IMAGE,
        "Cmd": ["/bin/sh", "-c", script],
        "Env": env,
    }
    if _is_tcp_socket(docker_socket):
        env.append(f"DOCKER_HOST={_docker_cli_host(docker_socket)}")
        nets = [n for n in self_networks if n not in ("host", "none")]
        if nets and self_network_mode != "host":
            body["HostConfig"] = {"AutoRemove": True, "NetworkMode": nets[0]}
            body["NetworkingConfig"] = {"EndpointsConfig": {n: {} for n in nets}}
        else:
            body["HostConfig"] = {"AutoRemove": True, "NetworkMode": "host"}
    else:
        body["HostConfig"] = {
            "AutoRemove": True,
            "Binds": [f"{docker_socket}:/var/run/docker.sock"],
            "NetworkMode": "none",
        }
    return body


async def self_update(target_version: str | None = None) -> dict:
    """Safely update the panelarr container from within itself.

    The process doing the update lives inside the container being replaced, so
    the destructive steps are delegated to an ephemeral ``docker:cli`` sidecar
    that outlives panelarr. Panelarr inspects itself, pulls the new image via
    the Engine API (aborting before touching anything if the pull fails) and
    starts the sidecar, which runs a rollback-safe swap script (see
    ``build_update_script``).

    ``target_version`` lets a version-pinned tag (``:0.3.0``) move to a newer
    release; it is ignored for ``latest``/``dev`` tags, which are simply re-pulled.

    After returning ``{"status": "updating"}`` the frontend should poll
    ``GET /api/system/health`` until it gets a 200 response with the new
    version, then reload.
    """
    try:
        async with httpx.AsyncClient(transport=_docker_transport(), timeout=PULL_TIMEOUT) as client:
            inspect_resp = await client.get(_docker_url(f"/containers/{SELF_CONTAINER_NAME}/json"))
            if inspect_resp.status_code == 404:
                return {
                    "status": "error",
                    "message": "Container 'panelarr' not found, is container_name set?",
                }
            inspect_resp.raise_for_status()
            old = inspect_resp.json()

            current_image = (old.get("Config") or {}).get("Image", "")
            if not current_image:
                return {"status": "error", "message": "Cannot determine container image"}
            image = resolve_update_image(current_image, target_version)

            logger.info("self_update: pulling %s", image)
            pull_error = await _pull_image(client, image)
            if pull_error:
                logger.warning("self_update: pull failed for %s: %s", image, pull_error)
                return {
                    "status": "error",
                    "message": f"Image pull failed: {pull_error}",
                }
            logger.info("self_update: pull complete for %s", image)

            old_image_config = await _image_config(client, old.get("Image", ""))
            env_path = "/tmp/panelarr.env"
            plan = build_recreate_plan(old, image, old_image_config, env_file_path=env_path)
            container_name = (old.get("Name") or "").lstrip("/") or SELF_CONTAINER_NAME
            script = build_update_script(container_name, plan, env_path)

            self_networks = list(((old.get("NetworkSettings") or {}).get("Networks") or {}).keys())
            sidecar_body = build_sidecar_spec(
                script,
                plan.env_file,
                settings.docker_socket,
                self_networks,
                (old.get("HostConfig") or {}).get("NetworkMode", ""),
            )

            logger.info("self_update: pulling %s sidecar image", SIDECAR_IMAGE)
            cli_error = await _pull_image(client, SIDECAR_IMAGE, timeout=60)
            if cli_error:
                logger.warning("self_update: sidecar image pull problem: %s", cli_error)

            sidecar_name = f"panelarr-updater-{int(time.time())}"
            logger.info("self_update: launching sidecar %s", sidecar_name)
            create_resp = await client.post(
                _docker_url("/containers/create"),
                params={"name": sidecar_name},
                json=sidecar_body,
                timeout=30,
            )
            if create_resp.status_code not in (200, 201):
                logger.error(
                    "self_update: sidecar create failed %s: %s",
                    create_resp.status_code,
                    create_resp.text[:200],
                )
                return {
                    "status": "error",
                    "message": "Failed to create updater sidecar, update aborted",
                }

            sidecar_id = create_resp.json().get("Id", "")
            start_resp = await client.post(
                _docker_url(f"/containers/{sidecar_id}/start"),
                timeout=10,
            )
            if start_resp.status_code not in (200, 204):
                await client.delete(
                    _docker_url(f"/containers/{sidecar_id}"),
                    params={"force": "true"},
                    timeout=10,
                )
                return {
                    "status": "error",
                    "message": "Failed to start updater sidecar, update aborted",
                }

            logger.info("self_update: sidecar %s started", sidecar_name)
            return {
                "status": "updating",
                "message": (
                    "Update in progress. Panelarr will restart in a few seconds. "
                    "The UI will reload automatically when the new version is ready."
                ),
                "image": image,
            }

    except httpx.TimeoutException:
        return {"status": "error", "message": "Image pull timed out, update aborted"}
    except Exception:
        logger.exception("self_update failed")
        return {"status": "error", "message": "Self-update failed, check server logs"}


async def container_action(name_or_id: str, action: str) -> dict:
    """Perform an action (start/stop/restart) on a container."""
    if action not in ALLOWED_ACTIONS:
        return {"status": "error", "message": f"Invalid action: {action}"}
    async with httpx.AsyncClient(transport=_docker_transport(), timeout=DOCKER_TIMEOUT) as client:
        resp = await client.post(_docker_url(f"/containers/{name_or_id}/{action}"))
        if resp.status_code == 404:
            return {"status": "error", "message": "Container not found"}
        if resp.status_code in (204, 304):
            return {"status": "ok", "container": name_or_id, "action": action}
        resp.raise_for_status()
        return {"status": "ok", "container": name_or_id, "action": action}


def _parse_docker_log_stream(data: bytes) -> list[str]:
    """Parse Docker multiplexed log stream into lines."""
    lines: list[str] = []
    offset = 0
    while offset < len(data):
        if offset + 8 > len(data):
            remaining = data[offset:].decode("utf-8", errors="replace").strip()
            if remaining:
                lines.extend(remaining.splitlines())
            break
        header = data[offset : offset + 8]
        _stream_type = header[0]
        frame_size = struct.unpack(">I", header[4:8])[0]
        offset += 8
        if frame_size == 0:
            continue
        if offset + frame_size > len(data):
            frame = data[offset:]
        else:
            frame = data[offset : offset + frame_size]
        text = frame.decode("utf-8", errors="replace").rstrip("\n")
        if text:
            lines.extend(text.splitlines())
        offset += frame_size
    return lines


async def get_container_logs(name_or_id: str, lines: int = 200) -> list[str]:
    """Get last N log lines from a container."""
    async with httpx.AsyncClient(transport=_docker_transport(), timeout=DOCKER_TIMEOUT) as client:
        tty = await _is_tty_container(client, name_or_id)
        resp = await client.get(
            _docker_url(f"/containers/{name_or_id}/logs"),
            params={
                "stdout": "true",
                "stderr": "true",
                "tail": str(lines),
                "timestamps": "true" if not tty else "false",
            },
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        if tty:
            # TTY: raw text, no multiplexing
            text = resp.content.decode("utf-8", errors="replace")
            return [line for line in text.splitlines() if line.strip()]
        return _parse_docker_log_stream(resp.content)


async def _is_tty_container(client: httpx.AsyncClient, name_or_id: str) -> bool:
    """Check if a container has TTY enabled (affects log format)."""
    try:
        resp = await client.get(_docker_url(f"/containers/{name_or_id}/json"))
        if resp.status_code == 200:
            config = resp.json().get("Config", {})
            return config.get("Tty", False)
    except Exception:
        pass
    return False


async def stream_container_logs(name_or_id: str):
    """Async generator yielding live log lines from a container."""
    async with httpx.AsyncClient(transport=_docker_transport(), timeout=None) as client:
        tty = await _is_tty_container(client, name_or_id)
        async with client.stream(
            "GET",
            _docker_url(f"/containers/{name_or_id}/logs"),
            params={
                "stdout": "true",
                "stderr": "true",
                "follow": "true",
                "tail": "50",
                "timestamps": "true" if not tty else "false",
            },
        ) as resp:
            if tty:
                # TTY containers send raw text, not multiplexed frames
                async for chunk in resp.aiter_bytes():
                    text = chunk.decode("utf-8", errors="replace")
                    for line in text.splitlines():
                        if line.strip():
                            yield line
            else:
                # Non-TTY: multiplexed Docker log format
                buffer = b""
                async for chunk in resp.aiter_bytes():
                    buffer += chunk
                    while len(buffer) >= 8:
                        frame_size = struct.unpack(">I", buffer[4:8])[0]
                        total = 8 + frame_size
                        if len(buffer) < total:
                            break
                        frame = buffer[8:total]
                        buffer = buffer[total:]
                        text = frame.decode("utf-8", errors="replace").rstrip("\n")
                        for line in text.splitlines():
                            if line:
                                yield line


async def get_docker_version() -> dict | None:
    """Get Docker engine version info."""
    try:
        async with httpx.AsyncClient(
            transport=_docker_transport(), timeout=DOCKER_TIMEOUT
        ) as client:
            resp = await client.get(_docker_url("/version"))
            resp.raise_for_status()
            data = resp.json()
            return data if isinstance(data, dict) else None
    except (httpx.HTTPError, ValueError):
        return None


DOCKER_HUB_REGISTRY = "registry-1.docker.io"
REGISTRY_TIMEOUT = 5

# (realm, service, scope) -> (token, monotonic expiry)
_registry_token_cache: dict[tuple[str, str, str], tuple[str, float]] = {}


@dataclass(frozen=True)
class ImageRef:
    """A parsed container image reference."""

    registry: str
    repo: str
    tag: str  # "" when the reference is digest-pinned without a tag
    digest: str = ""  # "sha256:..." when pinned by digest

    @property
    def pinned(self) -> bool:
        """True when the reference is pinned to an immutable digest."""
        return bool(self.digest)


# Registry host (with optional port), path, tag and digest characters; no
# query, fragment, userinfo, backslash or whitespace.
_IMAGE_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,511}")


def _split_image_ref(image: str) -> ImageRef:
    """Parse an image string into registry, repository, tag and digest.

    Handles registry hosts with ports (``localhost:5000/img:tag``), implicit
    Docker Hub library images and ``name@sha256:...`` / ``name:tag@sha256:...``.
    """
    ref, _, digest = image.partition("@")
    tag = ""
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    if not tag and not digest:
        tag = "latest"

    parts = ref.split("/")
    first = parts[0]
    if len(parts) > 1 and ("." in first or ":" in first or first == "localhost"):
        registry, repo = first, "/".join(parts[1:])
        if registry in ("docker.io", "index.docker.io"):
            registry = DOCKER_HUB_REGISTRY
            if "/" not in repo:
                repo = f"library/{repo}"
    elif len(parts) == 1:
        registry, repo = DOCKER_HUB_REGISTRY, f"library/{ref}"
    else:
        registry, repo = DOCKER_HUB_REGISTRY, ref
    return ImageRef(registry=registry, repo=repo, tag=tag, digest=digest)


def _parse_image_ref(image: str) -> tuple[str, str, str]:
    """Parse image string into (registry, repository, tag).

    The tag is ``""`` for digest-pinned references without a tag.

    Examples:
        lscr.io/linuxserver/sonarr:latest -> (lscr.io, linuxserver/sonarr, latest)
        ghcr.io/org/app:v1 -> (ghcr.io, org/app, v1)
        nginx:latest -> (registry-1.docker.io, library/nginx, latest)
        localhost:5000/img:tag -> (localhost:5000, img, tag)
        nginx@sha256:abcd -> (registry-1.docker.io, library/nginx, "")
    """
    ref = _split_image_ref(image)
    return (ref.registry, ref.repo, ref.tag)


def _parse_www_authenticate(header: str) -> dict[str, str] | None:
    """Parse a ``WWW-Authenticate: Bearer realm="...",service="...",scope="..."`` header."""
    if not header or not header.lower().startswith("bearer"):
        return None
    params = {k.lower(): v for k, v in re.findall(r'(\w+)="([^"]*)"', header)}
    return params if params.get("realm") else None


_REGISTRY_TOKEN_MAX_BYTES = 64 * 1024


async def _get_registry_token(client: httpx.AsyncClient, challenge: dict[str, str]) -> str:
    """Fetch (or reuse a cached) anonymous bearer token for a registry challenge."""
    realm = challenge.get("realm", "")
    if urlparse(realm).scheme not in ("http", "https"):
        return ""
    # The realm is chosen by whoever runs the registry, so it gets the same
    # outbound guard as every other server-side request (metadata, link-local,
    # the Docker API).
    from backend.services.security import check_outbound_url

    blocked = await check_outbound_url(realm)
    if blocked:
        logger.warning("Registry token realm refused: %s", blocked)
        return ""
    key = (realm, challenge.get("service", ""), challenge.get("scope", ""))
    cached = _registry_token_cache.get(key)
    if cached and cached[1] > time.monotonic():
        return cached[0]
    params = {k: v for k, v in (("service", key[1]), ("scope", key[2])) if v}
    # A token answer is a few KB; read at most 64 KiB so a hostile registry
    # can't make Panelarr buffer an arbitrarily large body.
    async with client.stream("GET", realm, params=params, timeout=REGISTRY_TIMEOUT) as resp:
        if resp.status_code != 200:
            return ""
        body = b""
        async for chunk in resp.aiter_bytes():
            body += chunk
            if len(body) > _REGISTRY_TOKEN_MAX_BYTES:
                logger.warning("Registry token answer too large; ignored")
                return ""
    try:
        data = json.loads(body)
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    token = data.get("token") or data.get("access_token") or ""
    if token:
        ttl = max(int(data.get("expires_in") or 60) - 10, 5)
        _registry_token_cache[key] = (token, time.monotonic() + ttl)
    return token


async def _registry_manifest_head(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """HEAD a manifest, performing the anonymous bearer-token flow on a 401."""
    from backend.services.security import check_outbound_url

    # The registry host comes from the image reference, which an image can set
    # through its Compose label; it gets the outbound guard like the realm.
    blocked = await check_outbound_url(url)
    if blocked:
        logger.warning("Registry manifest request refused: %s", blocked)
        return httpx.Response(204)  # no digest: reported as "no update"
    headers = {"Accept": _MANIFEST_ACCEPT}
    resp = await client.head(url, headers=headers, timeout=REGISTRY_TIMEOUT)
    if resp.status_code == 401:
        challenge = _parse_www_authenticate(resp.headers.get("www-authenticate", ""))
        if challenge:
            token = await _get_registry_token(client, challenge)
            if token:
                resp = await client.head(
                    url,
                    headers={**headers, "Authorization": f"Bearer {token}"},
                    timeout=REGISTRY_TIMEOUT,
                )
    return resp


def _registry_scheme(registry: str) -> str:
    """Local registries are conventionally plain http; everything else is https."""
    host = registry.split(":")[0]
    return "http" if host in ("localhost", "127.0.0.1") else "https"


async def _check_single_container_update(
    container: dict,
    docker: httpx.AsyncClient,
    registry_client: httpx.AsyncClient,
) -> tuple[str, dict] | None:
    """Check a single container for an available image update.

    Returns (name, result_dict) or None if the container should be skipped.
    Digest-pinned images are reported with ``pinned: True`` and never as updatable.
    """
    name = container.get("name", "")
    image = container.get("image", "")
    if not image:
        return None

    if not _IMAGE_REF_RE.fullmatch(image) or ".." in image:
        # Not a Docker image reference (the Compose label can hold anything):
        # never let it shape a registry URL.
        return None
    ref = _split_image_ref(image)
    if ref.pinned:
        return (
            name,
            {
                "has_update": False,
                "pinned": True,
                "local_digest": ref.digest[:19],
                "remote_digest": "",
                "image": image,
            },
        )
    try:
        # Get local image digest from Docker
        img_resp = await docker.get(_docker_url(f"/images/{image}/json"))
        if img_resp.status_code != 200:
            return None
        img_data = img_resp.json()
        local_digests = img_data.get("RepoDigests", [])
        local_digest = ""
        for d in local_digests:
            if "@sha256:" in d:
                local_digest = d.split("@")[1]
                break

        # Query the remote registry's manifest digest (HEAD, with anonymous bearer auth)
        manifest_resp = await _registry_manifest_head(
            registry_client,
            f"{_registry_scheme(ref.registry)}://{ref.registry}/v2/{ref.repo}/manifests/{ref.tag}",
        )

        remote_digest = manifest_resp.headers.get("docker-content-digest", "")
        has_update = bool(local_digest and remote_digest and local_digest != remote_digest)

        return (
            name,
            {
                "has_update": has_update,
                "pinned": False,
                "local_digest": local_digest[:19] if local_digest else "",
                "remote_digest": remote_digest[:19] if remote_digest else "",
                "image": image,
            },
        )
    except Exception:
        logger.debug("Update check failed for %s", name)
        return None


async def check_container_updates(containers: list[dict]) -> dict[str, dict]:
    """Check each container's image for available updates concurrently.

    Compares local image digest against remote registry using Docker v2 API.
    Returns {container_name: {"has_update": bool, "local_digest": str, "remote_digest": str}}.
    """
    results: dict[str, dict] = {}
    async with httpx.AsyncClient(transport=_docker_transport(), timeout=DOCKER_TIMEOUT) as docker:
        async with httpx.AsyncClient(timeout=REGISTRY_TIMEOUT) as registry_client:
            outcomes = await asyncio.gather(
                *[_check_single_container_update(c, docker, registry_client) for c in containers],
                return_exceptions=True,
            )
            for outcome in outcomes:
                if isinstance(outcome, tuple):
                    name, result = outcome
                    results[name] = result

    return results
