# Configuration

Panelarr is configured through the web UI. On first start the setup wizard walks through authentication, service connections, notifications, and disk monitoring. Everything is saved to `/config/panelarr.json`.

There is no `.env` file. A fresh install is just `docker compose up -d` followed by finishing the wizard.

## Bootstrap Environment Variables

A handful of values need to be available before `panelarr.json` can be read, so they come from the environment. All four have defaults that match the official Docker image; you only need to set them to override those defaults.

| Variable | Default | When to set it |
|---|---|---|
| `PANELARR_HOST` | `0.0.0.0` | Pin the backend to a specific interface |
| `PANELARR_PORT` | `8000` | Run on a non-standard port |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Non-standard Docker socket path |
| `CONFIG_PATH` | `/config/panelarr.json` | Store the config file elsewhere |
| `PANELARR_TRUSTED_PROXIES` | (unset) | Comma-separated CIDRs that may set the proxy auth header and `X-Forwarded-*`. Overrides the list saved in Settings. See [proxy](#proxy) |
| `PANELARR_ALLOWED_ORIGINS` | (unset) | Extra browser origins allowed to make changes, e.g. when a proxy rewrites `Host`. See [Cross-origin requests](#cross-origin-requests) |
| `PANELARR_ALLOWED_HOSTS` | (unset) | Comma-separated hostnames/IPs Panelarr answers to; anything else gets `421`. Recommended in auth mode `none` to stop DNS-rebinding attacks from web pages |

Set them under `environment:` in `docker-compose.yml`:

```yaml
services:
  panelarr:
    image: panelarr:latest
    environment:
      - PANELARR_PORT=9000
      - DOCKER_SOCKET=/var/run/podman.sock
```

## What Lives in the UI

Everything below is configured through the setup wizard or the Settings page and persists across container rebuilds.

| Area | Where to set it |
|---|---|
| Authentication (none / basic / proxy / apikey) | Setup wizard, or Settings → Authentication |
| Sonarr / Radarr / SABnzbd / qBittorrent / Plex / Jellyfin | Settings → service cards |
| Notification channels (Discord, Telegram, Slack, Email/SMTP, webhook) | Settings → Notifications |
| Notification rules | Settings → Notifications |
| Disks to monitor | Settings → Disks to Monitor |
| Disk warning / critical thresholds | Settings → Alerts & Thresholds |
| Watchdog stall threshold | Settings → Alerts & Thresholds |

## JSON Config File

The wizard and Settings page save to `/config/panelarr.json`. The schema:

```json
{
  "services": {
    "sonarr":      { "url": "http://sonarr:8989",      "api_key": "..." },
    "radarr":      { "url": "http://radarr:7878",      "api_key": "..." },
    "sabnzbd":     { "url": "http://sabnzbd:8080",     "api_key": "..." },
    "qbittorrent": { "url": "http://qbittorrent:8080", "username": "...", "password": "..." },
    "plex":        { "url": "http://plex:32400",       "token": "..." },
    "jellyfin":    { "url": "http://jellyfin:8096",    "api_key": "..." }
  },
  "notifications": {
    "channels": [],
    "rules": []
  },
  "thresholds": {
    "disk_warn_pct": 85,
    "disk_crit_pct": 90,
    "watchdog_threshold_hours": 2,
    "disks": []
  },
  "auth": {
    "mode": "basic",
    "username": "admin",
    "password_hash": "...",
    "secret": "...",
    "proxy_header": "Remote-User",
    "api_key": "..."
  },
  "setup": {
    "completed_at": "2025-01-01T00:00:00Z",
    "version": "0.1.0-alpha"
  }
}
```

API keys and passwords are masked when returned by `GET /api/config` (last 4 characters only). The `auth` block is stripped entirely from that response; non-secret auth metadata is exposed via `GET /api/auth/status` instead.

Mount the config directory so it survives rebuilds:

```yaml
volumes:
  - /opt/panelarr/config:/config
```

## Traefik

By default Panelarr listens on port 8000. The shipped `docker-compose.yml` maps it to the host with `ports: ["8000:8000"]`.

When running behind Traefik:

1. Put Panelarr on the same Docker network as Traefik.
2. Remove the `ports` mapping (Traefik routes internally; keeping it open bypasses Traefik).

### Generic Traefik

```yaml
services:
  panelarr:
    build: .
    container_name: panelarr
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /opt/panelarr/config:/config
    restart: unless-stopped
    networks:
      - traefik
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.panelarr.rule=Host(`panelarr.your-domain.com`)"
      - "traefik.http.routers.panelarr.entrypoints=websecure"
      - "traefik.http.routers.panelarr.tls.certresolver=letsencrypt"
      - "traefik.http.services.panelarr.loadbalancer.server.port=8000"

networks:
  traefik:
    external: true
```

Replace `traefik` with your Traefik network name.

### Saltbox

Saltbox runs Traefik on a network called `saltbox`:

```yaml
services:
  panelarr:
    build: .
    container_name: panelarr
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /opt/panelarr/config:/config
    restart: unless-stopped
    networks:
      - saltbox
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.panelarr.rule=Host(`panelarr.your-domain.com`)"
      - "traefik.http.routers.panelarr.entrypoints=websecure"
      - "traefik.http.routers.panelarr.tls.certresolver=letsencrypt"
      - "traefik.http.services.panelarr.loadbalancer.server.port=8000"

networks:
  saltbox:
    external: true
```

## Authentication

Set the auth mode in the setup wizard or under Settings → Authentication. Panelarr controls Docker on its host, so anyone who gets past authentication effectively controls that machine. Pick a mode deliberately.

Until the wizard's authentication step has been saved, only the wizard itself is reachable: every other API route answers `403 Setup required`. Finish the wizard before exposing Panelarr to other machines. Once an auth mode is saved, the wizard (including a later "Re-run setup wizard") requires the same credentials as the rest of the app.

If `panelarr.json` cannot be parsed, Panelarr does **not** fall back to defaults. The API answers `503` with the parse error until you fix or remove the file, and a file that is still broken when Panelarr next saves is moved aside to `panelarr.json.corrupt-<timestamp>` first.

### none

No authentication. Every endpoint is open to anyone who can reach the port. Only use this when nothing but you can reach Panelarr.

### basic

Built-in username/password with JWT session cookies (`HttpOnly`, `SameSite=Strict`, `Secure` when served over HTTPS). Login page at `/login`. Sessions last 24 hours. Signing out revokes the session (recorded in `panelarr.json`, so it survives restarts), and changing the username, password or API key signs out every other session. The signing secret is generated on first start and saved to `auth.secret` in `panelarr.json`.

Login attempts are limited to 10 per minute per client address (per /64 for IPv6).

### proxy

Trusts a header set by an authenticating reverse proxy (Authelia, Authentik, oauth2-proxy and so on) and reads the username from it.

The header is only honoured when the request comes **directly from a trusted proxy address**. Anyone who can reach port 8000 directly could otherwise send the header themselves. By default only localhost is trusted. Whole Docker networks are deliberately *not* trusted by default: when a port is published, Docker's userland proxy makes every client appear to come from the network's gateway address.

To enable proxy mode, open Panelarr **through your proxy** and pick proxy mode in the wizard or Settings. Panelarr refuses unless that request carries the header, so you can't lock yourself out, and it adds the exact address the request came from (your proxy, e.g. `172.19.0.9/32`) to the trusted list. Edit the list under Settings → Authentication, or pin it with `PANELARR_TRUSTED_PROXIES` (which overrides the saved list and is the way back in if your proxy's address changes). An invalid list trusts nothing.

If your proxy's container address changes when it is recreated, give it a static IP on its Docker network, or trust its network CIDR and **don't publish port 8000**. Requests carrying the header from an untrusted address are logged with that address to make this easy to diagnose. The wizard auto-detects common providers and suggests the right header name.

Common headers:

| Proxy | Header |
|---|---|
| Authelia | `Remote-User` |
| Authentik | `X-authentik-username` |
| oauth2-proxy | `X-Auth-Request-User` |
| Cloudflare Access | `Cf-Access-Authenticated-User-Email` |
| Tailscale Serve | `Tailscale-User-Login` |

### apikey

Every API request needs an `X-Api-Key` header. The key is shown once when it is generated; rotate it under Settings → Authentication or with `POST /api/auth/apikey/regenerate`. In the browser, the login page asks for the key once and then uses a session cookie, because browsers can't add headers to page loads or WebSockets.

An `X-Api-Key` header is also accepted in every other mode, which is what dashboards like Homepage should use. The key stays valid when you switch modes, so regenerate it if it may have leaked.

### Cross-origin requests

Panelarr serves its own UI, so it sends no CORS headers: other websites cannot read its API from your browser. Requests that change something (POST, PUT, DELETE) and log WebSockets are refused with `403` when the browser's `Origin` doesn't match the host Panelarr was addressed by. That also covers other apps on sibling subdomains of the same domain. Clients that send no `Origin` (curl, Homepage, scripts) are unaffected. If your proxy rewrites the `Host` header, either have it pass `X-Forwarded-Host` (honoured from trusted proxies) or list the public origin in `PANELARR_ALLOWED_ORIGINS`.

### Calendar feed

`/api/calendar/feed.ics` takes a `token` query parameter so calendar apps can subscribe without signing in. Copy the full URL from the Calendar page. The token only opens the feed; regenerate it there if it leaks.

### Health check and API docs

`GET /api/healthz` is public and only reports that the process is up; the Docker `HEALTHCHECK` uses it. The interactive API docs are at `/api/docs` (OpenAPI JSON at `/api/openapi.json`) and require authentication.

### Outbound requests

Notification webhooks, SMTP servers and service connection tests may point at LAN and loopback addresses, which is normal in a homelab. Panelarr refuses cloud metadata endpoints, link-local and multicast addresses, and its own Docker API endpoint, after resolving hostnames. A stored API key or password is never sent to a new URL: if you change a service's URL, re-enter its key.

### Saltbox with Traefik + Authelia

```yaml
services:
  panelarr:
    build: .
    container_name: panelarr
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /opt/panelarr/config:/config
    restart: unless-stopped
    networks:
      - saltbox
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.panelarr.rule=Host(`panelarr.your-domain.com`)"
      - "traefik.http.routers.panelarr.entrypoints=websecure"
      - "traefik.http.routers.panelarr.tls.certresolver=letsencrypt"
      - "traefik.http.services.panelarr.loadbalancer.server.port=8000"
      - "traefik.http.routers.panelarr.middlewares=authelia@docker"

networks:
  saltbox:
    external: true
```

After the container starts, open the wizard and pick Reverse Proxy as the auth mode. Panelarr will detect Authelia's `Remote-User` header automatically.
