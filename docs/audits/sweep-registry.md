# Sweep registry: what exists, what ran, what it is worth

Proposals for sweeps are written here, not in conversation. The `Last run` column is derived
from report filenames by `scripts/sweep_status.py` (verified-security-sweep); the other columns
are written by hand.

## Candidates

| Zone | Argument | Last run | Yield |
|---|---|---|---|
| `auth-sessions` | Auth modes, JWT, revocation, setup gating, trusted proxies, Origin and Host checks. Highest blast radius (auth bypass means Docker means host). Not covered: behaviour behind real Traefik/Caddy (simulated with uvicorn's middleware). | 2026-11-17 | 7/21 |
| `docker-control` | Container actions, self-update sidecar and rollback, registry checks, log WebSocket. Not covered: a real Docker daemon or registry (mocked transports only). | 2026-11-17 | 2/14 |
| `config-secrets-outbound` | Config load and save, secret masking and reuse, service tests, notification channels and the SSRF guard. Not covered: the SAB/Jellyfin connection-test log lines (proposed, see media-integrations F1). | 2026-11-17 | 2/19 |
| `media-integrations` | Arr, qBittorrent and SABnzbd, Plex, Jellyfin and Emby, discovery, calendar and the ICS feed token, poster cache. Not covered: real upstream services. | 2026-11-17 | 1/15 |
| `frontend` | SPA auth flow, redirects, URL rendering, WebSocket client, sessionStorage. Not covered: setup welcome, thresholds and system-check pages beyond grep. | 2026-11-17 | 1/14 |
| `supply-chain-deploy` | Dockerfile, entrypoint, compose, CI and release workflows, dependency audit. Not covered: gitleaks (CI only), an image build. Read by the sweep owner, not an independent reviewer. | 2026-11-17 | 0/11 |

## Proposed, not yet run

| Zone | Argument | Premise to re-verify before starting |
|---|---|---|
| `auth-sessions` | Re-run after the F1/F2/F4/F7 fixes land: who becomes a trusted proxy is the zone's recurring class. The fixes add an end-to-end test through uvicorn as the entrypoint starts it, and a heuristic gateway check (`looks_like_docker_gateway`) worth a fresh read. | the fixes are merged (xfail markers removed 2026-11-17; `findings.py recheck --run`: 13 fixed) |
| `config-secrets-outbound` | Outbound guard promises in the README vs R10 to R14 (rebinding, Docker endpoint by IP, IPv6 forms, SMTP port); decide pin-the-address or soften the README. | owner decision on the README wording |
| `fresh-code` | Whatever ships next on develop, read with transversal lenses. | run within 3 days of the next merge |

## Candidates verified and refused

Written here so they are not rediscovered. A refused candidate without a written reason comes back.

See the "Refused or unconfirmed candidates" section of each 2026-11-17 report (R1 onwards). Most
repeated reason: SSRF-guard gaps refused on exploitability because only an authenticated user, or
anyone before setup, can set an outbound URL, and both already control Docker by design.

## Owner decisions

| Date | Candidate | Question put to the owner | Decision | Result |
|---|---|---|---|---|
