"""Request-trust and outbound-request helpers shared by HTTP and WebSocket paths.

Everything that decides "who is this request from" or "may the server call
that URL" lives here so the HTTP middleware, the WebSocket handler and the
routers apply exactly the same rules.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
from functools import lru_cache
from urllib.parse import urlparse

from starlette.requests import HTTPConnection

logger = logging.getLogger(__name__)

# Sources allowed to set the proxy auth header and X-Forwarded-* headers when
# the config does not say otherwise: loopback only. Trusting Docker's whole
# 172.16.0.0/12 pool is unsafe because Docker's userland proxy (published
# ports, Docker Desktop, rootless Docker) makes *every* client appear to come
# from a bridge gateway address in that range. Enabling proxy mode adds the
# proxy's own address (see routers/auth.require_proxy_auth_on).
DEFAULT_TRUSTED_PROXIES: tuple[str, ...] = ("127.0.0.1/32", "::1/128")

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


# ---------------------------------------------------------------------------
# Trusted proxies and client identity
# ---------------------------------------------------------------------------


def parse_cidrs(values: list[str] | tuple[str, ...]) -> list[ipaddress._BaseNetwork]:
    """Parse CIDR strings, raising ValueError with the offending entry."""
    nets = []
    for raw in values:
        value = str(raw).strip()
        if not value:
            continue
        try:
            nets.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR: {value!r}") from exc
    return nets


@lru_cache(maxsize=32)
def _cached_networks(values: tuple[str, ...]) -> tuple[ipaddress._BaseNetwork, ...]:
    try:
        return tuple(parse_cidrs(values))
    except ValueError:
        # Fail closed: an unparseable list trusts nobody rather than widening
        # to defaults.
        logger.error("Invalid trusted proxies %r; trusting no proxy until fixed", values)
        return ()


def get_trusted_proxies() -> list[str]:
    """Return the configured trusted-proxy CIDRs (env overrides config)."""
    env = os.getenv("PANELARR_TRUSTED_PROXIES", "").strip()
    if env:
        return [v.strip() for v in env.split(",") if v.strip()]
    from backend.services.config import load_config

    auth = load_config().auth or {}
    configured = auth.get("trusted_proxies")
    if isinstance(configured, list) and configured:
        return [str(v) for v in configured]
    return list(DEFAULT_TRUSTED_PROXIES)


def _ip(value: str | None) -> ipaddress._BaseAddress | None:
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def is_trusted_proxy(host: str | None) -> bool:
    addr = _ip(host)
    if addr is None:
        return False
    return any(addr in net for net in _cached_networks(tuple(get_trusted_proxies())))


def peer_host(conn: HTTPConnection) -> str:
    return conn.client.host if conn.client else ""


def client_ip(conn: HTTPConnection) -> str:
    """Best-effort real client IP.

    X-Forwarded-For is only honoured when the direct peer is a trusted proxy,
    and then we take the right-most address that is not itself a trusted
    proxy, so a client cannot spoof its address by prepending entries.
    """
    peer = peer_host(conn)
    if not is_trusted_proxy(peer):
        return peer
    xff = conn.headers.get("x-forwarded-for", "")
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    for hop in reversed(hops):
        if not is_trusted_proxy(hop):
            return hop
    return peer


def request_is_https(conn: HTTPConnection) -> bool:
    if conn.url.scheme in ("https", "wss"):
        return True
    if is_trusted_proxy(peer_host(conn)):
        return conn.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https"
    return False


_warned_untrusted: set[str] = set()


def proxy_user(conn: HTTPConnection, header_name: str) -> str | None:
    """Return the proxy-asserted user if the header came from a trusted proxy."""
    value = conn.headers.get(header_name, "").strip()
    if not value:
        return None
    peer = peer_host(conn)
    if not is_trusted_proxy(peer):
        if peer not in _warned_untrusted and len(_warned_untrusted) < 256:
            _warned_untrusted.add(peer)
            logger.warning(
                "Ignoring %s header from %s: not a trusted proxy. If this is your reverse "
                "proxy, add it under Settings → Authentication or PANELARR_TRUSTED_PROXIES.",
                header_name,
                peer or "unknown address",
            )
        return None
    return value


# ---------------------------------------------------------------------------
# Origin checks (CSRF / cross-site WebSocket hijacking)
# ---------------------------------------------------------------------------


def _extra_allowed_origins() -> set[str]:
    raw = os.getenv("PANELARR_ALLOWED_ORIGINS", "")
    return {o.strip().rstrip("/").lower() for o in raw.split(",") if o.strip()}


def origin_allowed(conn: HTTPConnection) -> bool:
    """True when the request has no Origin, or the Origin is this server.

    Browsers always send Origin on cross-origin requests, on every
    POST/PUT/DELETE and on WebSocket handshakes, so comparing it with the
    Host the browser addressed blocks cross-site and sibling-subdomain
    request forgery. Non-browser clients (curl, Homepage widgets) send no
    Origin and are unaffected.
    """
    origin = conn.headers.get("origin")
    if origin is None:
        return True
    origin = origin.strip().rstrip("/").lower()
    if origin == "null" or not origin:
        return False
    if origin in _extra_allowed_origins():
        return True
    parsed = urlparse(origin)
    if not parsed.netloc:
        return False
    hosts = {conn.headers.get("host", "").lower()}
    if is_trusted_proxy(peer_host(conn)):
        fwd = conn.headers.get("x-forwarded-host", "").split(",")[0].strip().lower()
        if fwd:
            hosts.add(fwd)
    default_port = {"http": "80", "https": "443"}.get(parsed.scheme, "")
    candidates = {parsed.netloc}
    if default_port and parsed.port is None:
        candidates.add(f"{parsed.hostname}:{default_port}")
    if parsed.port is not None and str(parsed.port) == default_port:
        candidates.add(parsed.hostname or "")
    return bool(candidates & hosts)


def host_allowed(conn: HTTPConnection) -> bool:
    """Optional Host allowlist (``PANELARR_ALLOWED_HOSTS``) against DNS rebinding.

    Unset by default so any hostname or IP works out of the box. When set,
    requests whose Host header isn't listed are refused, which stops a
    rebinding page from reaching an instance running in auth mode "none".
    """
    raw = os.getenv("PANELARR_ALLOWED_HOSTS", "")
    allowed = {h.strip().lower() for h in raw.split(",") if h.strip()}
    if not allowed:
        return True
    host = conn.headers.get("host", "").lower()
    name = host.rsplit(":", 1)[0] if not host.endswith("]") else host
    return host in allowed or name.strip("[]") in allowed or name in allowed


def is_state_changing(method: str) -> bool:
    return method.upper() not in _SAFE_METHODS


# ---------------------------------------------------------------------------
# Outbound URL guard (SSRF)
# ---------------------------------------------------------------------------

_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.google",
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
}
_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
    ipaddress.ip_address("fd00:ec2::254"),  # AWS IMDS IPv6
}


def _blocked_address(addr: ipaddress._BaseAddress) -> str | None:
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        elif addr in ipaddress.ip_network("64:ff9b::/96"):  # NAT64
            addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    if addr in _METADATA_IPS:
        return "cloud metadata address"
    if addr.is_link_local:
        return "link-local address"
    if addr.is_unspecified:
        return "unspecified address"
    if addr.is_multicast:
        return "multicast address"
    return None


def _docker_endpoint() -> tuple[str, int] | None:
    from backend.config import settings

    sock = settings.docker_socket
    if sock.startswith(("tcp://", "http://", "https://")):
        parsed = urlparse(sock.replace("tcp://", "http://", 1))
        if parsed.hostname:
            return parsed.hostname.lower(), parsed.port or 2375
    return None


async def check_outbound_url(url: str) -> str | None:
    """Return an error string if the server must not call ``url``, else None.

    Panelarr is a homelab tool: services and notification targets legitimately
    live on private and loopback addresses, so those are allowed and
    authentication is the trust boundary. What is always refused is the class
    of targets that only an attacker wants: cloud metadata, link-local,
    multicast/unspecified addresses, and the Docker API endpoint itself.
    Hostnames are resolved and every resolved address is checked.
    """
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https"):
        return "URL must use http or https"
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        return "URL has no hostname"
    if host in _METADATA_HOSTS:
        return "URL points at a cloud metadata service"
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return "URL has an invalid port"

    docker = _docker_endpoint()
    if docker and host == docker[0] and port == docker[1]:
        return "URL points at the Docker API"

    literal = _ip(host)
    if literal is not None:
        addrs = [literal]
    else:
        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=5
            )
        except (OSError, TimeoutError):
            return None  # Unresolvable: the request itself will fail cleanly.
        addrs = [a for a in (_ip(info[4][0]) for info in infos) if a is not None]

    for addr in addrs:
        reason = _blocked_address(addr)
        if reason:
            return f"URL resolves to a {reason}"
    return None
