# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Versioning

Panelarr uses [Semantic Versioning](https://semver.org):

- **MAJOR** (`X.0.0`): breaking changes to the config schema, REST API, Docker image layout, or CLI
- **MINOR** (`0.X.0`): new features, backwards compatible
- **PATCH** (`0.0.X`): bug fixes, docs, small tweaks

## Roadmap

| Version | Status | Scope |
|---|---|---|
| `0.1.0-alpha` | current (unreleased) | dashboard, containers, downloads, calendar, shows, movies, settings, notifications, log streaming, setup wizard, ruff + pytest + vitest CI, GHCR publishing |
| `1.0.0-beta` | planned | feature complete, ready for community testing. Watch history from Plex and Jellyfin, polished onboarding, stable REST API surface |
| `1.0.0` | planned | stable release, API freeze |

Minor alpha bumps (`0.2.0-alpha`, `0.3.0-alpha`, etc.) happen on meaningful milestones between now and beta.

## [Unreleased]

Fixes from a full audit (unit, e2e and live penetration testing) of 0.3.1-alpha,
and from a verified security sweep of the fixed branch (`docs/audits/2026-11-17-*.md`).

### Security

- **An unknown auth mode fails closed.** A `panelarr.json` whose `auth.mode`
  is not `none`, `basic`, `proxy` or `apikey` (a hand-edited `"Basic"`, an
  empty value or `null`, or a downgrade from a newer version) used to mean
  "no auth"; the API now answers 503 `config_invalid` until it is fixed.
- **DNS rebinding can't run the setup wizard.** Before an auth mode is saved,
  the setup API only answers when Panelarr is opened by IP address or
  `localhost`, or through a hostname listed in `PANELARR_ALLOWED_HOSTS`;
  otherwise it returns `421`. A web page could previously take over a fresh
  instance, even one bound to loopback, from the owner's browser.
- **Proxy mode is pinned to its hostname.** Enabling proxy mode records the
  hostname it was enabled through, and the auth header only counts on that
  hostname (or on `PANELARR_ALLOWED_HOSTS`). A rebinding page in a browser on
  the Panelarr host reached it from loopback, a trusted proxy, and could set
  the header itself. **Existing proxy-mode users:** re-save proxy mode while
  opening Panelarr through your proxy.
- **Who becomes a trusted proxy is tighter.** The image starts uvicorn with
  `--no-proxy-headers`, so only Panelarr reads `X-Forwarded-*`, and only from
  trusted proxies. Enabling proxy mode never auto-trusts a Docker network
  gateway (every client of a published port can appear from it): put the
  proxy on Panelarr's network, or add the address by hand. A trusted-proxy
  list is saved together with the mode, so a refused request leaves nothing
  behind; the setup wizard accepts one only with proxy mode.
- **`PANELARR_HOST` works.** The image used to bind `0.0.0.0` whatever it
  said.
- **The session cookie is `Secure` behind any HTTPS proxy** that sends
  `X-Forwarded-Proto: https`, trusted or not.
- **An existing `panelarr.json` is always used**, even when `/config` is not
  writable or not readable (disk full, read-only remount, wrong owner);
  Panelarr no longer falls back to an empty config in the home directory and
  reopens the wizard. An unreadable file answers 503; saves fail instead.
- **No config values in errors or logs.** The 503 `config_invalid` message no
  longer quotes parts of the file (it could show the end of an API key), and
  a failing SABnzbd poll no longer logs the request URL with its API key.
- **Registry requests get the outbound guard** (token realms and manifest
  checks), so a registry or an image label can't point Panelarr's update check
  at cloud metadata or the Docker API. The Docker API is now recognised by
  address, not only by the name in `DOCKER_SOCKET` (`localhost`, `127.1` and
  other aliases are refused too).
- **Webhook notifications are checked against the URL they are sent to.** A
  generic webhook with a harmless `webhook_url` and a `url` pointing at the
  Docker API passed the check, even through the unauthenticated test button
  of a fresh install's wizard.
- **Panelarr won't stop its socket proxy or itself under another name**: the
  target is resolved first, so `stack-dockerproxy-1` or an id prefix of
  Panelarr's own container is refused too.
- **The wizard keeps no notification settings in sessionStorage**, including
  the generic webhook URL, which is the channel's credential.
- **Hardening:** an `http://` Origin is refused when Panelarr is known to be
  served over HTTPS; API answers are `Cache-Control: no-store` and image
  proxies `private`; the unauthenticated `/docs/oauth2-redirect` route is gone;
  IPv6 Docker gateways are recognised; registry token answers are size-capped
  and malformed image references are skipped by the update check; error log
  lines no longer include upstream URLs; poster and Plex thumbnail proxies pass
  raster images only; an out-of-range calendar date is a 400, not a 500.

- **Corrupt `panelarr.json` no longer disables authentication.** Previously
  a parse error fell back to defaults (auth `none`, wizard reopened) and the
  next save overwrote the real file. The API now answers 503 until the file
  is fixed, keeps the last valid config if it breaks at runtime, and moves a
  broken file to `panelarr.json.corrupt-<timestamp>` before saving over it.
- **Proxy auth mode actually authenticates.** The header is required and is
  only honoured from trusted proxy addresses (`auth.trusted_proxies`,
  `PANELARR_TRUSTED_PROXIES`; default localhost only). Switching to proxy
  mode is refused unless the request proves the proxy works, and then trusts
  exactly that proxy address. **Existing proxy-mode users:** open Panelarr
  through your proxy and re-save proxy mode, or set `PANELARR_TRUSTED_PROXIES`.
- **Setup wizard can't be hijacked.** Before the auth step only the wizard is
  reachable; after it, the wizard needs the new credentials (the auth step
  signs you in). Re-running the wizard no longer opens it to anyone.
- **No wildcard CORS**; writes and log WebSockets from other origins
  (including sibling subdomains) are refused.
- **Sessions**: logout revokes the token, credential or API-key changes sign
  out other sessions, cookies are `SameSite=Strict`, login is constant-time
  and rate-limited per real client IP.
- **Secrets**: a stored key or password is never sent to a changed URL or
  mail server; notification secrets (SMTP password, webhook URLs, bot
  tokens) are masked in every response.
- **Outbound requests** resolve hostnames and refuse cloud metadata,
  link-local addresses and the Docker API, while LAN webhooks (ntfy, Gotify)
  now work.
- Panelarr won't stop or recreate its own container or its socket proxy.
  Self-update pins its helper image and keeps env vars out of its command line.
- Optional `PANELARR_ALLOWED_HOSTS` host allowlist against DNS rebinding.
  Self-update refuses downgrades. The legacy-install migration only runs at
  startup, so a request can no longer mark a fresh install as set up.
- API docs moved behind auth to `/api/docs`; new public `/api/healthz` for the
  container healthcheck (previously "unhealthy" whenever auth was on).

### Fixed

- qBittorrent 5.x: login (204 response), stop/start actions, stopped states;
  paused torrents stay listed with Resume.
- API-key mode no longer locks the browser out (sign in once with the key);
  basic auth chosen in the wizard no longer bounces to `/login` mid-wizard;
  "Re-run setup wizard" works; the thresholds step keeps the disk selection.
- Image update checks work for ghcr.io/lscr.io/Docker Hub (registry token
  flow), digest-pinned images are reported as pinned, failed pulls are
  reported instead of "Updated", and update badges no longer vanish (cached
  results instead of 429).
- Self-update works through a TCP socket proxy, can move a pinned version
  tag forward, preserves mounts/devices/security options, and rolls back if
  the new container fails to start.
- Log streams: correct close codes, no reconnect storm, no leaked streams.
- Discovery suggests the container's internal port and no longer matches
  look-alike images; hotio/binhex variants added.
- Calendar: last day of the month and timezone edges no longer dropped; air
  dates no longer shown a day early in the Americas; the ICS feed has a
  subscribe URL with a token.
- Delete/blocklist/qBit actions report failures; the poster cache follows the
  config directory; container label links only allow http(s); keyboard
  activation of link buttons; logout leaves the dashboard immediately.

### Added

- Security regression suite (`backend/tests/test_security.py`) and a
  Playwright e2e suite (`frontend/e2e`, CI job `E2E`).

## [0.1.0-alpha] - Unreleased

### Fixed

- Disk Usage no longer lists Docker **file** bind-mounts (e.g. a mounted entrypoint script). Only directory mountpoints are treated as disks.

### Removed

- **`.env` file is gone.** Panelarr no longer ships `.env.example` and
  `docker-compose.yml` no longer loads one. All configuration (services,
  authentication, notifications, thresholds, monitored disks) lives in
  `panelarr.json` and is managed through the setup wizard or Settings
  page. Four bootstrap variables (`PANELARR_HOST`, `PANELARR_PORT`,
  `DOCKER_SOCKET`, `CONFIG_PATH`) are still read from the environment
  with sensible defaults, so a fresh install is just
  `docker compose up -d` followed by completing the wizard in a browser.
  Support for `AUTH_MODE`, `AUTH_USERNAME`, `AUTH_PASSWORD`,
  `AUTH_SECRET`, `AUTH_PROXY_HEADER`, and `AUTH_API_KEY` env vars has
  been dropped; those values are now read exclusively from the `auth`
  block of `panelarr.json`.

### Added

- Dashboard "Upcoming" widget now shows the release date alongside the
  time so users can see *when* a release is coming without having to
  open the calendar page.

#### Calendar
- Unified upcoming-releases view across Sonarr and Radarr (`/calendar`)
- Agenda layout grouped by day with sticky day headers and a "Today" highlight
- Filters for kind (all/episodes/movies), unmonitored, specials, and downloaded
- Subscribe-able iCalendar feed at `GET /api/calendar/feed.ics` that mirrors
  the same query params, with a "ICS" download button on the page
- Dashboard "Upcoming" widget showing the next five releases (matches the
  calendar's specials/downloaded/unmonitored defaults)

#### Shows
- Show detail page with seasons, episode tables, posters, and live download
  progress overlay per episode
- Specials (Sonarr season 0) are now included in the show detail view but
  excluded from the show-level totals; rendered as a collapsed "Specials"
  section with a "Not counted" badge
- Episode "missing" status uses a 24-hour grace period after air time so
  freshly-aired episodes aren't flagged before indexers have a release
- Action buttons: Search All Missing, per-season Search Season, per-episode
  Search

#### Movies
- Movie detail page with poster, metadata, releases, and search action

#### Other
- Poster proxy at `GET /api/media/poster?url=...` (CSP-friendly cached
  image fetcher with an allow-list of TVDB/TMDB/fanart hosts)

#### Backend
- Real Docker Engine API integration via unix socket (replaces all mock data)
- Container listing with live CPU, memory, uptime stats via concurrent stats fetching
- Docker multiplexed log stream parsing for both REST and WebSocket endpoints
- Config service with JSON file persistence at `/config/panelarr.json`
- Config API: GET (masked keys), PUT (partial update), POST test connection
- Downloads router: unified Sonarr + Radarr queue with warning detection
- Download actions: delete, blocklist, bulk blocklist all warnings
- Download stats: aggregated queue counts from Sonarr, Radarr, SABnzbd, qBittorrent
- Stalled download watchdog with configurable threshold
- System health endpoint: Docker connectivity, disk usage, memory, uptime
- Disk usage monitoring with configurable warning and critical thresholds
- Discord webhook integration for posting health check summaries
- Real Sonarr/Radarr API integration with graceful fallback when unconfigured
- SABnzbd queue and speed stats integration
- qBittorrent transfer info and active torrent count integration
- Plex and Jellyfin connection testing
- Service connection testing for all supported applications
- Added `pydantic>=2` and `psutil>=5` dependencies

#### Frontend
- Full sidebar navigation layout using coss/ui Sidebar with react-router
- Dashboard page: stat cards, container grid, download queue, disk meters
- Containers page: searchable table, start/stop/restart with confirmation, detail sheet with live logs
- Downloads page: tabbed queue (All/Sonarr/Radarr), progress bars, bulk blocklist
- Logs page: container selector, WebSocket live streaming, pause/resume, filter, line count
- Settings page: service configuration forms with test buttons, threshold sliders, Discord webhook
- React Query integration with 30-second auto-refresh on all data
- Toast notifications on all mutations (success/error)
- AlertDialog confirmations on all destructive actions
- WebSocket hook with automatic reconnection and exponential backoff
- Responsive design: sidebar collapses on mobile, tables adapt to screen size
- Added `react-router-dom` and `@tanstack/react-query` dependencies

#### Infrastructure
- Persistent config volume (`panelarr_config`) in docker-compose.yml
- Fixed Dockerfile README.md path for hatchling build
- Added `/config` directory creation in Dockerfile
- WebSocket proxy support in Vite dev server config
- Updated `.env.example` with all service environment variables
  *(removed in a later entry)*

### Changed

- Split vendor libraries (React, Base UI, lucide, React Query, React Router)
  into cacheable chunks and lazy-loaded the login page, so the initial
  entry bundle is ~80% smaller and vendor code stays cached across deploys
- New shows added through Panelarr now use Sonarr's `monitor: "future"`
  add-option (no auto-search) instead of `"all"` so the existing back
  catalogue isn't immediately queued
- Dashboard rebalanced: media (Library, Now Streaming, Upcoming) on the
  left, ops (Server, Disk Usage, Download Queue, Recent Activity) on the
  right
- Calendar dropped the confusing month-grid view; agenda is the only view
- Show detail no longer dims downloaded episodes that Sonarr has flipped
  to unmonitored (downloaded-then-unmonitored is intentional Sonarr
  behavior, not an error state)
- Replaced all mock backend data with real Docker/Sonarr/Radarr API calls
- Replaced tab-based frontend shell with full sidebar + router layout
- Updated container endpoints to use name-based routing
- WebSocket log endpoint moved from `/api/logs/ws/{name}` to `/ws/logs/{name}`
- Backend config expanded from 7 to 20+ environment variables
