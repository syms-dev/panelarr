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
import re
import socket
import sys
from functools import lru_cache
from pathlib import Path
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


# Image types the poster and thumbnail proxies pass through. No SVG: it can carry
# script, and a proxied image is served from Panelarr's own origin.
RASTER_IMAGE_TYPES = frozenset({"image/jpeg", "image/png", "image/webp", "image/gif", "image/avif"})

_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://\S+")


def loggable_error(exc: BaseException) -> str:
    """Describe an exception for a log line without any URL in it.

    httpx puts the full request URL, query string included, in its error text,
    and several services take their API key or token as a query parameter
    (SABnzbd ``apikey``, Plex ``X-Plex-Token``); webhook URLs are secrets
    themselves.
    """
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status is not None and type(exc).__name__ == "HTTPStatusError":
        return f"HTTP {status}"
    text = _URL_RE.sub("<url>", str(exc))
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


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


def effective_trusted_proxies(configured: object) -> list[str]:
    """Trusted-proxy CIDRs in force for a configured list (env overrides it)."""
    env = os.getenv("PANELARR_TRUSTED_PROXIES", "").strip()
    if env:
        return [v.strip() for v in env.split(",") if v.strip()]
    if isinstance(configured, list) and configured:
        return [str(v) for v in configured]
    return list(DEFAULT_TRUSTED_PROXIES)


def get_trusted_proxies() -> list[str]:
    """Return the configured trusted-proxy CIDRs (env overrides config)."""
    from backend.services.config import load_config

    return effective_trusted_proxies((load_config().auth or {}).get("trusted_proxies"))


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


def is_trusted_proxy(host: str | None, cidrs: list[str] | None = None) -> bool:
    """True if ``host`` is in ``cidrs``, or in the trusted proxies in force."""
    addr = _ip(host)
    if addr is None:
        return False
    values = tuple(cidrs if cidrs is not None else get_trusted_proxies())
    return any(addr in net for net in _cached_networks(values))


def _route_gateways() -> set[ipaddress._BaseAddress]:
    """Gateways of this container, from the kernel routing tables.

    Covers the IPv4 and IPv6 next hops and the first host of every directly
    connected IPv4 network, which is where Docker puts a bridge's gateway.
    Empty off Linux.
    """
    try:
        lines = Path("/proc/net/route").read_text().splitlines()[1:]
    except OSError:
        return set()

    def addr(field: str) -> ipaddress.IPv4Address:
        return ipaddress.IPv4Address(int(field, 16).to_bytes(4, sys.byteorder))

    found: set[ipaddress._BaseAddress] = set()
    for line in lines:
        fields = line.split()
        if len(fields) < 8:
            continue
        try:
            dest, gateway, mask = addr(fields[1]), addr(fields[2]), addr(fields[7])
        except ValueError:
            continue
        if int(gateway):
            found.add(gateway)
        elif int(mask) and int(mask) != 0xFFFFFFFF:
            found.add(ipaddress.IPv4Address(int(dest) + 1))
    try:
        # Columns: destination, prefix length, source, source length, next hop, ...
        for line in Path("/proc/net/ipv6_route").read_text().splitlines():
            fields = line.split()
            if len(fields) >= 5 and int(fields[4], 16):
                found.add(ipaddress.IPv6Address(int(fields[4], 16)))
    except (OSError, ValueError):
        pass
    return found


def looks_like_docker_gateway(host: str | None) -> bool:
    """True if ``host`` is, or looks like, a Docker network gateway.

    Docker's userland proxy (published ports, Docker Desktop, rootless Docker)
    makes every client of a published port appear from the bridge gateway, so
    that address must never be trusted automatically. Besides the gateways in
    the routing table, any private ``x.x.x.1`` (or ULA ``::1`` host) counts:
    Docker reserves it for the gateway, and refusing a real proxy there only
    means the owner adds it to the list by hand.
    """
    addr = _ip(host)
    if addr is None or addr.is_loopback:
        return False
    if addr in _route_gateways():
        return True
    if isinstance(addr, ipaddress.IPv4Address):
        return addr.is_private and addr.packed[-1] == 1
    if addr.is_link_local or addr.is_multicast:
        return False
    # Docker gives an IPv6 network's gateway the first host address, ``<prefix>::1``,
    # whatever the prefix length (/64, /80 and so on), global or ULA.
    return int(addr) & 0xFFFFFFFFFFFF == 1


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


def request_host_name(conn: HTTPConnection) -> str:
    """The hostname of the Host header, lower-cased, without port or brackets."""
    host = conn.headers.get("host", "").strip().lower()
    if host.startswith("["):
        return host[1 : host.find("]")] if "]" in host else host[1:]
    if host.count(":") == 1:
        return host.rsplit(":", 1)[0]
    return host


def _allowed_hosts() -> set[str]:
    raw = os.getenv("PANELARR_ALLOWED_HOSTS", "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def setup_host_allowed(conn: HTTPConnection) -> bool:
    """May this request reach the unauthenticated setup wizard?

    Before an auth mode is saved the wizard is open to whoever reaches it, and
    a web page can reach a loopback or LAN instance through DNS rebinding: its
    requests then carry the attacker's own hostname in Host and Origin. So the
    wizard only answers to an IP literal or ``localhost``, which rebinding
    cannot produce, or to a name the owner listed in ``PANELARR_ALLOWED_HOSTS``
    (``host_allowed`` has already refused every other name in that case).
    """
    if _allowed_hosts():
        return True
    name = request_host_name(conn)
    return name == "localhost" or _ip(name) is not None


def proxy_host_allowed(conn: HTTPConnection) -> bool:
    """Is the proxy auth header honoured on this request's Host?

    Loopback is a trusted proxy by default, so a DNS-rebinding page in a
    browser on the Panelarr host reaches it from a trusted address and can set
    the header itself. Its requests carry the attacker's hostname, though, so
    the header only counts on the hostname(s) proxy mode was enabled through
    (``auth.proxy_hosts``) or on ``PANELARR_ALLOWED_HOSTS``.
    """
    if _allowed_hosts():
        return True
    from backend.services.config import load_config

    pinned = (load_config().auth or {}).get("proxy_hosts")
    if not isinstance(pinned, list):
        return False
    return request_host_name(conn) in {str(h).lower() for h in pinned}


def proxy_user(conn: HTTPConnection, header_name: str) -> str | None:
    """Return the proxy-asserted user if the header came from a trusted proxy."""
    value = conn.headers.get(header_name, "").strip()
    if not value:
        return None
    if not proxy_host_allowed(conn):
        name = request_host_name(conn)
        if name not in _warned_untrusted and len(_warned_untrusted) < 256:
            _warned_untrusted.add(name)
            logger.warning(
                "Ignoring %s header for host %r: proxy mode was not enabled through that "
                "hostname. Re-save proxy mode while opening Panelarr through it, or list it "
                "in PANELARR_ALLOWED_HOSTS.",
                header_name,
                name,
            )
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
    if parsed.scheme == "http" and request_is_https(conn):
        # The page that sent this was loaded over plain HTTP while Panelarr is
        # known to be served over HTTPS: someone on the network path may have
        # injected it. (An https Origin on a request that looks like http is
        # fine: a TLS-terminating proxy that is not trusted hides the scheme.)
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
    allowed = _allowed_hosts()
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


async def _resolve(host: str, port: int) -> list[ipaddress._BaseAddress] | None:
    """Addresses ``host`` resolves to (itself if it is a literal), or None."""
    literal = _ip(host)
    if literal is not None:
        return [literal]
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=5
        )
    except (OSError, TimeoutError):
        return None
    return [a for a in (_ip(info[4][0]) for info in infos) if a is not None]


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

    addrs = await _resolve(host, port)
    if addrs is None:
        return None  # Unresolvable: the request itself will fail cleanly.

    if docker and port == docker[1]:
        # Compare addresses, not names: "localhost", "127.1", another alias
        # or the IP of the socket proxy all reach the same Docker API.
        docker_addrs = await _resolve(docker[0], docker[1]) or []
        for addr in addrs:
            if addr in docker_addrs or (
                addr.is_loopback and any(d.is_loopback for d in docker_addrs)
            ):
                return "URL points at the Docker API"

    for addr in addrs:
        reason = _blocked_address(addr)
        if reason:
            return f"URL resolves to a {reason}"
    return None
