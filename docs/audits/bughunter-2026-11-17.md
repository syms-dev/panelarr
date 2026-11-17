# Claude-BugHunter run, 2026-11-17

A second, independent pass after the [verified security sweep](sweep-registry.md) of the same day,
using the skills of [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) (commit
`5d91c81`, read from a clone, not installed). Mode: WAPT grey-box with `--source-code`, against
local instances of this branch (sweep fixes applied) on 127.0.0.1 with loopback-only mock Docker,
registry and upstream services. Three hunters (auth and sessions; browser trust boundary; server-side
requests, files and injection) plus a static pass by the owner's session. Every finding below was
reproduced by the session before it was fixed, and each has a regression test in
`backend/tests/test_audit_sweep_2026_11_17.py` (section "Claude-BugHunter run").

Scope note: one early scenario used real image names, so a single update check sent anonymous
manifest and token requests to public registries (lscr.io, ghcr.io, Docker Hub) before the mocks
were moved to loopback. Nothing else left the machine.

## Findings (all fixed)

| Id | Finding | Severity | Root cause | Fix |
|---|---|---|---|---|
| BH-1 | A web page takes over a fresh instance through DNS rebinding before setup, even when bound to loopback (reopens sweep R8: the port need not be exposed) | Medium | `backend/main.py` served `/api/setup/*` for any Host while unconfigured; `host_allowed` is opt-in | setup answers only an IP literal, `localhost` or `PANELARR_ALLOWED_HOSTS` (`setup_host_allowed`, 421 `setup_host`) |
| BH-2 | Proxy mode: a rebinding page in a browser on the Panelarr host reaches it from loopback (trusted by default) and sets the auth header itself | Medium | `proxy_user` checked only the TCP peer | enabling proxy mode pins the hostname (`auth.proxy_hosts`); the header counts only there or on `PANELARR_ALLOWED_HOSTS` |
| BH-3 | Webhook guard checked `webhook_url`, the webhook type sent to `url`: a decoy let `url` hit the Docker API (stop, kill, prune by query string), unauthenticated through the pre-setup test button | Medium | `backend/services/notifications.py` guarded one field, sent another | guard exactly the field each type sends to |
| BH-4 | Existing `panelarr.json` in an unsearchable directory looked absent on Python 3.14+ (`Path.is_file()` returns False on EACCES), so the wizard reopened | Medium | `resolve_config_path` and `load_config` used `is_file()` | `_may_exist` (stat; only ENOENT means absent); explicit `CONFIG_PATH` never falls back |
| BH-5 | Sweep F7 fix skipped falsy modes: `"mode": null` or `""` with stored credentials meant no auth | Low | truthiness check | a present `mode` key must be a known mode |
| BH-6 | Docker API check compared hostnames, so `localhost`, `127.1` or an alias reached it from a registry realm chosen by an image's registry | Low | `check_outbound_url` string compare | compare resolved addresses (any loopback on the Docker port when Docker is on loopback); manifest HEAD guarded too |

## Hardening notes (done the same day, with tests)

- `origin_allowed` refuses an `http://` Origin when the request is known to be HTTPS.
- Image proxies send `Cache-Control: private`; every other `/api/` answer gets `no-store`.
- FastAPI's `/docs/oauth2-redirect` route (outside `/api`) is disabled.
- `looks_like_docker_gateway` recognizes `<prefix>::1` IPv6 gateways (global or ULA, any prefix length) and reads IPv6 next hops from the routing table.
- Registry token answers are read up to 64 KiB; image references that are not valid Docker references (query, fragment, `..`, whitespace) are never turned into registry URLs.
- An overflowing ICS date answers 400 instead of 500.
- Upstream and notification error log lines go through `loggable_error`, which drops URLs (tokens and webhook URLs travel in them).
- The poster and Plex thumbnail proxies pass raster images only (no SVG).

## Killed candidates (7-Question Gate)

Sibling-subdomain CSRF and login/logout CSRF, cross-site WebSocket hijacking, CORS, method override,
clickjacking, Host-header poisoning, open redirect, XSS, web cache deception, request smuggling,
source maps and docs exposure, JWT `alg=none` and token placement, logout revocation, rate-limit
keying, apikey placement, calendar token scope, MediaCover and Plex thumb path tricks, masked-secret
reuse, middleware path tricks, pre-setup planting (reduces to R8). Reasons are in the session record;
none reached a trust boundary.
