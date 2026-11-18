<div align="center">

<img src="frontend/public/logo-mark.svg" alt="Panelarr" height="80" />

**Homelab media control center**

<br />
<br />

[![CI](https://github.com/thug-drama/panelarr/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/thug-drama/panelarr/actions/workflows/ci.yml)
![Version](https://img.shields.io/github/v/release/thug-drama/panelarr?include_prereleases&style=flat-square&color=6366f1&label=version)
![License](https://img.shields.io/badge/license-MIT-6366f1?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-ready-2496ed?style=flat-square&logo=docker&logoColor=white)

</div>

<br />

<!-- screenshot here -->

A self-hosted control panel for Docker-based media stacks. Manage containers, monitor Sonarr/Radarr/qBittorrent/SABnzbd, browse your library, and stream live logs from one place.

## Is Panelarr for you?

Panelarr is a **day-to-day dashboard for a media stack you already run**. It ships as one container, talks to the Docker API and to your apps' own APIs, and works the same on any Docker host (a NAS, a Raspberry Pi, a VPS) however the stack was installed: docker-compose, Unraid, Portainer or Saltbox.

What it does **not** do is install or provision your server. It never runs Ansible, edits your apps' config files, or installs software on the host.

| You want to… | Use |
|---|---|
| Browse and add movies and shows, watch the download queue, see what's streaming, get alerts, and start/stop/update containers, on any Docker host | **Panelarr** |
| Install and maintain a [Saltbox](https://github.com/saltyorg/Saltbox) server end to end (installer, app catalog, `sb update`, Saltbox config files, rclone, Recyclarr, post-install wiring) | [saltbox-ui](https://github.com/syms-dev/saltbox-ui), Panelarr's sibling project, which runs on the Saltbox host itself |

The two can run side by side on a Saltbox server: saltbox-ui to run the server, Panelarr to use the media stack.

## Features

**Dashboard**: stat cards for containers, downloads, disk usage, and system health. Now Streaming card with Plex session details. Upcoming releases widget.

**Movies & Shows**: browse and search your Sonarr/Radarr libraries. Movie and show detail pages with per-episode download progress and search actions.

**Containers**: searchable container table with start/stop/restart, live stats, and WebSocket log streaming per container.

**Downloads**: unified queue from all configured ARR services. Warning detection with per-item and bulk blocklist. Tabs for All, Warnings, Torrents, NZBs, and per-service.

**Notifications**: Discord, Telegram, Slack, Email (SMTP), and generic webhook. Rules engine for routing events to channels.

**Settings**: configure all services from the UI. Secrets are masked on read and preserved on save.

**Authentication**: four modes: `none`, `basic` (JWT session cookies), `proxy` (header from Authelia/Authentik/etc., accepted only from trusted proxy addresses), `apikey`. See [Security](#security).

## Quick Start

### Option 1. Docker (recommended)

Pull the pre-built image from GitHub Container Registry. No build step, works on amd64 and arm64 (Raspberry Pi friendly).

Create a `docker-compose.yml`:

```yaml
services:
  panelarr:
    image: ghcr.io/thug-drama/panelarr:latest
    container_name: panelarr
    ports:
      - "8000:8000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - panelarr_config:/config
    restart: unless-stopped

volumes:
  panelarr_config:
```

Start it:

```bash
docker compose up -d
```

Open `http://localhost:8000` and finish the setup wizard.

Available tags:

| Tag | Source | Use when |
|---|---|---|
| `latest` | last `v*.*.*` release | production |
| `v0.1.0-alpha` | exact release tag | pinning to a specific version |
| `dev` | every push to `develop` | living on the edge |

Traefik users: see [docs/configuration.md](docs/configuration.md) for network and label setup, including Saltbox and Authelia.

### Option 2. Build from source

```bash
git clone https://github.com/thug-drama/panelarr.git
cd panelarr
docker compose up -d --build
```

Same endpoint (`http://localhost:8000`), same wizard. This builds the image locally instead of pulling from GHCR, useful when you want to test uncommitted changes.

### How it works

The setup wizard runs on first visit and asks for authentication preferences and service URLs (Sonarr, Radarr, qBittorrent, SABnzbd, Plex, Jellyfin, etc.). Everything is saved to `/config/panelarr.json` and editable later from Settings without a restart.

Panelarr needs the Docker socket (`/var/run/docker.sock`) to manage containers on the host. The `:ro` in the compose file only protects the socket file; it does **not** limit what can be done through the Docker API, so treat access to Panelarr like root access to the host (see [Security](#security)). If you're running behind a reverse proxy, remove the `ports` mapping and add Traefik labels instead. See [docs/configuration.md](docs/configuration.md) for details.

## Security

Whoever can use Panelarr can control Docker, and through it the host. Panelarr is built around that:

- **Nothing but the setup wizard is reachable until you choose an auth mode**, and after that the wizard needs the same credentials as everything else. Finish setup before exposing the port. Until then the wizard only answers when you open Panelarr by IP address or `localhost` (or a name in `PANELARR_ALLOWED_HOSTS`), so a web page can't use DNS rebinding to run it for you.
- **A broken `panelarr.json` fails closed**: the API returns 503 until it is fixed, instead of falling back to "no auth".
- **Proxy mode trusts the auth header only from trusted proxy addresses** (loopback only by default, configurable), and won't switch on unless your proxy is actually in front. Enabling proxy mode through your proxy trusts exactly that proxy's address, never a Docker network gateway, and the header only counts on the hostname you enabled it through.
- **No cross-site access**: no CORS, and changes and log WebSockets from other origins (including sibling subdomains) are refused. Sessions are `HttpOnly`/`SameSite=Strict`, revoked on sign-out, and invalidated by password changes.
- **Secrets stay put**: API keys, passwords and webhook URLs are masked in every response, and a stored secret is never sent to a changed URL.
- **Outbound requests** to cloud metadata, link-local addresses or the Docker API are refused.
- Panelarr won't stop or recreate its own container or its Docker socket proxy.

For the tightest setup, put Panelarr behind Traefik with Authelia or Authentik in `proxy` mode, don't publish port 8000, and point `DOCKER_SOCKET` at a [socket proxy](https://github.com/Tecnativa/docker-socket-proxy). Report vulnerabilities privately through GitHub's security advisories for this repository.

## Supported Services

| Category | Service |
|---|---|
| ARR | Sonarr, Radarr |
| Usenet | SABnzbd, NZBGet |
| Torrents | qBittorrent (4.x and 5.x), Transmission, Deluge |
| Media Servers | Plex, Jellyfin, Emby |
| Notifications | Discord, Telegram, Slack, Email (SMTP), Webhook |

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+ / FastAPI / uvicorn |
| Frontend | React 18 / Vite 6 / Tailwind CSS v4 |
| Components | Base UI React (coss/ui) |
| Data Fetching | React Query |
| Real-time | WebSockets |
| Deployment | Single Docker container, no nginx required |

The production image is a multi-stage build: Node 22 compiles the frontend to static assets, then `python:3.11-slim` serves everything from port 8000.

## Configuration

No `.env` file. All configuration lives in `panelarr.json` and is managed from the Settings page.

Four bootstrap values can be overridden via environment variables before the config file loads:

| Variable | Default | When to set it |
|---|---|---|
| `PANELARR_HOST` | `0.0.0.0` | Pin to a specific interface |
| `PANELARR_PORT` | `8000` | Non-standard port |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Podman or rootless socket |
| `CONFIG_PATH` | `/config/panelarr.json` | Custom config location |

Full reference in [docs/configuration.md](docs/configuration.md): JSON schema, Traefik setup, auth mode examples.

## Development

Active work lands on `develop`; `main` is cut from `develop` at release time by the maintainer and holds tagged stable releases only. Pull requests should target `develop`, never `main`. See [CONTRIBUTING.md](CONTRIBUTING.md) for full setup, code style, branch naming, and PR process.

```bash
git clone https://github.com/thug-drama/panelarr.git
cd panelarr
pip install -e ".[dev]"
npm -C frontend install

# Terminal 1
uvicorn backend.main:app --reload

# Terminal 2
npm -C frontend run dev
```

Backend at `http://localhost:8000` (OpenAPI docs at `/docs`). Frontend at `http://localhost:5173` (proxies `/api` and `/ws` to backend).

## Roadmap

- Watch history from Plex and Jellyfin

## License

[MIT](LICENSE)
