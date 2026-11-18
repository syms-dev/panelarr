# Verified security sweep: auth-sessions, 2026-11-17

## Context

Scope: `backend/main.py` (HTTP middleware chain, public paths, setup gating, `spa_fallback`, CSP),
`backend/services/auth.py`, `backend/services/auth_config.py`, `backend/services/security.py`
(trusted proxies, `client_ip`, `request_is_https`, `proxy_user`, `origin_allowed`, `host_allowed`),
`backend/routers/auth.py`, `backend/routers/setup.py`, `entrypoint.sh` (how uvicorn is launched).

Trigger: the owner asked for a full security sweep with the verified-security-sweep method after the
2026-11-16 audit and its fixes. The whole zone is fresh code: it was rewritten on branch
`fix/audit-security-and-bugs` in the last day (`fresh_code.py` ranks every file of the zone in the
top 40). First run of this zone; `docs/audits/` was bootstrapped in this run.

Previous review: the 2026-11-16 audit (items 1 to 33 against develop @ 43c8e79, kept outside the
repository) and a follow-up review that closed M1, M2, M3, L1, L2, L4 and L5. None is re-reported
here; F2 and F4 are bypasses of the M3 fix (no Docker gateway trusted by default).

Commit: 2c08b9ca107c889e896874630396ea8bd91988cd

## Delegation

One read-only reviewer (OWASP reviewer, fresh context) for this zone, run in
parallel with four other zone reviewers. Brief: the skill's brief adapted to Panelarr (pre-read of
`CONTRIBUTING.md`, README "Security", `docs/configuration.md` "Authentication" to "Outbound
requests", `docs/audits/categories.md`, the 2026-11-16 audit with what it and the follow-up review
closed, and the test names in `backend/tests/test_security.py`), with zone-specific lenses: auth
across modes and mode transitions, setup reachability, JWT details, cookie flags, rate-limit keying,
X-Forwarded-* spoofing including uvicorn's own proxy-header middleware, Origin and Host checks, the
calendar feed token, timing, setup races. The reviewer returned 5 findings, 10 examined-and-refused
items and 7 hardening notes. Verification, reproduction and this report were done by the sweep
owner, not the reviewer. F6 came from the sweep owner's pre-flight; F7 was a reviewer hardening note
that verification promoted to a finding.

## Verification

| Finding | Zone | Verdict | Claimed | Verified | Reservations | Proof |
|---|---|---|---|---|---|---|
| F1 failed setup request persists `trusted_proxies` | auth-sessions | VERIFIED REAL | Medium | Medium | needs the pre-setup window; the planted list is visible in Settings once proxy mode is chosen | `backend/tests/test_audit_sweep_2026_11_17.py::test_failed_setup_request_does_not_persist_trusted_proxies`, ran, fails as expected (`'0.0.0.0/0' not in ['0.0.0.0/0', '::/0']`); guard `test_setup_proxy_mode_with_explicit_list_guard`, ran, passes |
| F2 uvicorn proxy headers rewrite the client before the trusted-proxy check | auth-sessions | VERIFIED REAL | Medium | Medium | needs a reverse proxy on loopback (host networking or a shared network namespace) that sets X-Forwarded-For; the attacker must share the trusted client address | `test_enabling_proxy_mode_through_loopback_proxy_trusts_the_proxy_not_the_client`, ran, fails as expected (`198.51.100.20/32` saved); guard `test_loopback_proxy_header_without_xff_guard`, ran, passes |
| F3 `PANELARR_HOST` ignored, always binds 0.0.0.0 | auth-sessions | VERIFIED REAL | Medium | Medium | consequence is full control only in mode `none` or before setup; needs host networking for the setting to matter | `test_entrypoint_honours_panelarr_host`, ran (entrypoint executed with a stub `gosu`), fails as expected (`'0.0.0.0' == '127.0.0.1'`); guard `test_entrypoint_default_host_guard`, ran, passes |
| F4 enabling proxy mode auto-trusts the Docker bridge gateway | auth-sessions | VERIFIED REAL | Medium | Medium | on standard Linux only host-local clients appear as the gateway; LAN-wide on Docker Desktop, rootless Docker or with the userland proxy | `test_enabling_proxy_mode_from_bridge_gateway_does_not_trust_it`, ran, fails as expected (`172.18.0.1/32` saved); guard `test_enabling_proxy_mode_from_proxy_container_guard`, ran, passes |
| F5 session cookie without `Secure` behind an untrusted HTTPS proxy | auth-sessions | VERIFIED REAL | Low | Low | needs a passive network position, no HSTS and a plain-http navigation | `test_cookie_secure_behind_untrusted_https_proxy`, ran, fails as expected (no `; secure`); guard `test_cookie_plain_http_guard`, ran, passes |
| F6 README states the old trusted-proxy default | auth-sessions | VERIFIED REAL | Low | Low | documentation drift; the code is right | `test_readme_trusted_proxy_default_matches_code`, ran, fails as expected; guard `test_configuration_doc_trusted_proxy_default_guard`, ran, passes |
| F7 unknown `auth.mode` falls back to `none` | auth-sessions | VERIFIED REAL | Low | High | needs an owner hand-edit (`"Basic"`) or a downgrade from a version with a new mode | `test_unknown_auth_mode_fails_closed`, ran, fails as expected (`assert 200 in (401, 503)`); guard `test_known_auth_mode_guard`, ran, passes |
| R1 Host header confuses `request.url.path` in the middleware | auth-sessions | FALSE POSITIVE | - | - | lens: existing mitigation; Starlette 1.10 `parse_host_header` rejects `Host: x/api/healthz?` | reviewer ran it in memory: path stays `/api/containers` |
| R2 path variants (`//api/x`, `/API/x`, `%2e%2e`) skip setup gating | auth-sessions | FALSE POSITIVE | - | - | lens: claim correctness; they match no protected route and fall to `spa_fallback` | `backend/main.py:226` |
| R3 calendar feed token unlocks more than the feed | auth-sessions | FALSE POSITIVE | - | - | lens: claim correctness; exact path and GET only, `compare_digest` | `backend/main.py:139`; `test_security.py::test_calendar_feed_token` |
| R4 JWT algorithm, subject or revocation weaknesses | auth-sessions | FALSE POSITIVE | - | - | lens: claim correctness; HS256 pinned, `exp`/`sub` required, subject bound to mode | `backend/services/auth.py:145` |
| R5 basic to apikey to basic revives old basic tokens | auth-sessions | FALSE POSITIVE | - | - | lens: exploitability; only the authenticated admin can switch modes | `backend/services/auth_config.py:103` |
| R6 login timing reveals usernames | auth-sessions | FALSE POSITIVE | - | - | lens: existing mitigation; dummy bcrypt hash and `compare_digest` | `backend/services/auth.py:105` |
| R7 Origin check bypass via ports, IPv6 or `null` | auth-sessions | FALSE POSITIVE | - | - | lens: claim correctness; normalisation correct both ways | `backend/services/security.py:183` |
| R8 setup `complete` before the auth step | auth-sessions | FALSE POSITIVE | - | - | lens: existing mitigation; documented first-comer risk ("Finish setup before exposing the port") | `README.md:116` |
| R9 concurrent `/api/setup/auth` race | auth-sessions | FALSE POSITIVE | - | - | lens: exploitability; microsecond window inside the documented pre-setup risk | `backend/routers/setup.py:196` |
| R10 duplicated proxy auth header, first value wins | auth-sessions | FALSE POSITIVE | - | - | lens: exploitability; gate not met, needs a proxy that appends instead of replacing | `backend/services/security.py:131` |
| R11 IPv6 /48 gives 65,536 login buckets | auth-sessions | FALSE POSITIVE | - | - | lens: exploitability; gate not met, bcrypt cost and per-/64 limit still bound guessing | `backend/routers/auth.py:52` |
| R12 CSP `connect-src ws: wss:` allows any host | auth-sessions | FALSE POSITIVE | - | - | lens: exploitability; gate not met, no script injection sink exists to use it | `backend/main.py:185` |
| R13 Swagger bundle loads without SRI | auth-sessions | FALSE POSITIVE | - | - | lens: exploitability; gate not met, authenticated page, pinned CDN version | `backend/main.py:178` |
| R14 calendar token in uvicorn access log | auth-sessions | FALSE POSITIVE | - | - | lens: exploitability; gate not met, the token only opens the read-only feed | `backend/main.py:104` |

## Confirmed defects

### F1. A stranger before setup can plant a trusted-proxy list that survives the owner's setup (Medium)

- Location: `backend/routers/setup.py:213`
- Class: setup and bootstrap; trusted proxies (CWE-284).
- Evidence chain:
  1. `backend/routers/setup.py:211` validates and `backend/routers/setup.py:213` saves
     `body.trusted_proxies` before the mode-specific checks; a `basic` body without a password then
     fails with 422, but the list is already on disk and no mode was saved, so the instance still
     looks fresh.
  2. The request is unauthenticated: `backend/main.py:145` lets `/api/setup/*` through while
     `is_auth_configured()` is false.
  3. Nothing clears it: the wizard's auth step never sends `trusted_proxies`, and
     `set_auth_in_config` (`backend/services/auth_config.py:103`) keeps existing keys.
- Scenario: an unauthenticated LAN client reaches a freshly started instance and sends one request
  with `trusted_proxies: ["0.0.0.0/0", "::/0"]` that fails with 422. The owner completes the wizard
  normally. Every address is now a trusted proxy: `client_ip` takes X-Forwarded-For from anyone,
  so the login rate limit is per forged value, and the moment the owner enables proxy mode,
  anyone can send the auth header directly.
- Fix approach: validate the whole body first, accept `trusted_proxies` only with `mode: "proxy"`,
  and write it in the same `set_auth_in_config(...)` call that saves the mode, as the basic branch
  does at `backend/routers/setup.py:222`. Apply the same order in `update_auth_config`.
- Reproduction: `test_failed_setup_request_does_not_persist_trusted_proxies` (attack, fails on the
  current code); `test_setup_proxy_mode_with_explicit_list_guard` (an explicit list for proxy
  mode is still saved, passes).

### F2. uvicorn's proxy-header middleware rewrites the client address before Panelarr's trusted-proxy logic (Medium)

- Location: `entrypoint.sh:23`
- Class: trusted proxies and client identity (CWE-348).
- Evidence chain:
  1. `entrypoint.sh:23` starts uvicorn without `--no-proxy-headers`; in uvicorn 0.54 proxy headers
     are on by default and `forwarded_allow_ips` defaults to `127.0.0.1,::1`.
  2. For a loopback peer, uvicorn replaces `scope["client"]` with the X-Forwarded-For address, so
     `peer_host` (`backend/services/security.py:97`) returns the end client, not the proxy.
  3. `require_proxy_auth_on` (`backend/routers/auth.py:131`) then auto-trusts that end-client
     address, and the default "loopback proxy is trusted" no longer works for other users. The
     existing tests use `ASGITransport` and never see uvicorn's wrapper.
- Scenario: Panelarr runs with host networking behind Caddy or nginx on loopback (both set
  X-Forwarded-For by default). The admin enables proxy mode from home; the admin's address is saved
  as a trusted proxy. Any device sharing that address (same NAT, same machine) can send
  `Remote-User: x` straight to port 8000 and control Docker; every other user behind the proxy gets
  401.
- Fix approach: start uvicorn with `--no-proxy-headers` so `backend/services/security.py` is the
  only code that reads X-Forwarded-*, and keep the test that builds the app the way the entrypoint
  runs it.
- Reproduction: `test_enabling_proxy_mode_through_loopback_proxy_trusts_the_proxy_not_the_client`
  wraps the app with `uvicorn.Config(...).load()` using the flags parsed from `entrypoint.sh`
  (attack, fails); `test_loopback_proxy_header_without_xff_guard` (passes).

### F3. `PANELARR_HOST` is documented but ignored (Medium)

- Location: `entrypoint.sh:23`
- Class: spec drift with security effect; network exposure (CWE-1188).
- Evidence chain:
  1. `entrypoint.sh:23` hard-codes `--host 0.0.0.0` while honouring `PANELARR_PORT` on the same line.
  2. `settings.host` (`backend/config.py:22`) is read and never used.
  3. `docs/configuration.md:13` and `README.md:157` document `PANELARR_HOST` as "Pin the backend to
     a specific interface".
- Scenario: an owner on host networking sets `PANELARR_HOST=127.0.0.1` and uses mode `none`,
  expecting local-only access. Any LAN client reaches port 8000 and controls Docker.
- Fix approach: `--host "${PANELARR_HOST:-0.0.0.0}"`, the pattern the same line uses for the port.
- Reproduction: `test_entrypoint_honours_panelarr_host` runs `entrypoint.sh` with a stub `gosu`
  that prints its arguments (attack, fails); `test_entrypoint_default_host_guard` (default stays
  `0.0.0.0:8000`, passes).

### F4. Enabling proxy mode auto-trusts the Docker bridge gateway (Medium)

- Location: `backend/routers/auth.py:131`
- Class: trusted proxies and client identity; bypass of the M3 fix (CWE-348).
- Evidence chain:
  1. `backend/routers/auth.py:131` adds `peer_host` as a /32 with no check of what that address is.
  2. When the admin's proxy reaches Panelarr through the published port (host nginx to
     `127.0.0.1:8000`, Docker Desktop, rootless Docker), the peer is the bridge gateway, the address
     M3 removed from the default list because every client of a published port can appear from it.
  3. The docstring above it claims a /32 avoids trusting the gateway; the only test covers a
     non-gateway peer.
- Scenario: on Docker Desktop or rootless Docker the owner fronts the published port with a host
  proxy and enables proxy mode through it. Every LAN client of port 8000 now appears as a trusted
  proxy and can send `Remote-User: x`.
- Fix approach: refuse to auto-trust an address that is the container's default gateway (or any
  `.1` of a Docker bridge), returning the existing 422 "add it to the trusted proxies list first"
  branch at `backend/routers/auth.py:120`.
- Reproduction: `test_enabling_proxy_mode_from_bridge_gateway_does_not_trust_it` (attack, fails);
  `test_enabling_proxy_mode_from_proxy_container_guard` (a proxy container address is still
  auto-trusted, passes).

### F5. Session cookie lacks `Secure` behind an HTTPS proxy that is not trusted (Low)

- Location: `backend/routers/auth.py:89`
- Class: authentication and sessions (CWE-614).
- Evidence chain:
  1. `backend/routers/auth.py:89` sets `secure=request_is_https(request)`.
  2. `request_is_https` reads X-Forwarded-Proto only from trusted proxies
     (`backend/services/security.py:122`), and by default only loopback is trusted.
  3. The documented Traefik plus basic-mode setup therefore issues the cookie without `Secure`
     although the browser is on HTTPS.
- Scenario: without HSTS, the admin types the bare hostname; the browser sends the session cookie
  over plain HTTP before Traefik redirects, and a passive observer captures it.
- Fix approach: set `Secure` when any peer sends `X-Forwarded-Proto: https`; the header can only make
  the cookie stricter, so it needs no trust.
- Reproduction: `test_cookie_secure_behind_untrusted_https_proxy` (attack, fails);
  `test_cookie_plain_http_guard` (plain LAN http still gets a working cookie, passes).

### F6. README states the old trusted-proxy default (Low)

- Location: `README.md:118`
- Class: spec drift.
- Evidence chain: `README.md:118` says "loopback and Docker networks by default";
  `backend/services/security.py:28` trusts loopback only; `docs/configuration.md` says "By default
  only localhost is trusted".
- Scenario: an owner reads the README, assumes the proxy container on the Docker network is
  trusted, and widens the list to `172.16.0.0/12` (the Settings placeholder suggests it) while
  port 8000 is published, which is the M3 exposure.
- Fix approach: change the README bullet to "loopback by default; enabling proxy mode through your
  proxy trusts exactly that address".
- Reproduction: `test_readme_trusted_proxy_default_matches_code` (attack, fails);
  `test_configuration_doc_trusted_proxy_default_guard` (passes).

### F7. Unknown `auth.mode` falls back to `none` (High)

- Location: `backend/services/auth_config.py:29`
- Class: configuration integrity; authentication (CWE-636, not failing securely).
- Evidence chain:
  1. `backend/services/auth_config.py:27` checks the mode against the four known values and
     `backend/services/auth_config.py:29` returns `none` for anything else.
  2. `authenticate` uses that effective mode, so every request passes; `is_auth_configured` is true
     (a mode is set), so nothing reopens or flags the instance.
  3. The fail-closed handling in `load_config` covers unparseable JSON only; a valid file with an
     unknown mode string is accepted.
- Scenario: the owner hand-edits `"mode": "Basic"`, or pins an older image after a newer version
  wrote a new mode. Panelarr logs one warning and serves the whole API, Docker included, to anyone
  who reaches the port; the README promises "A broken panelarr.json fails closed".
- Fix approach: treat an unknown mode as a `ConfigError` (503 `config_invalid`), the pattern
  `load_config` already uses at `backend/services/config.py:324`.
- Reproduction: `test_unknown_auth_mode_fails_closed` (attack, fails: unauthenticated
  `GET /api/config` returns 200); `test_known_auth_mode_guard` (passes).

## Refused or unconfirmed candidates

- R1, Host header path confusion: refused, lens existing mitigation. Starlette 1.10 rejects a Host
  with path characters and falls back to `scope["server"]`. Version-dependent: `pyproject.toml`
  allows older Starlette, see hand-off.
- R2, path variants: refused, lens claim correctness. None matches a protected route; they reach
  `spa_fallback` (`backend/main.py:226`), which returns 404 or `index.html`.
- R3, calendar token scope: refused, lens claim correctness (`backend/main.py:139`).
- R4, JWT: refused, lens claim correctness (`backend/services/auth.py:145`).
- R5, mode round-trip revives tokens: refused, lens exploitability; only the authenticated admin can
  do it (`backend/services/auth_config.py:103`).
- R6, login timing: refused, lens existing mitigation (`backend/services/auth.py:105`).
- R7, Origin normalisation: refused, lens claim correctness (`backend/services/security.py:183`).
- R8, setup complete before auth: refused, lens existing mitigation; documented first-comer risk
  (`README.md:116`).
- R9, setup race: refused, lens exploitability (`backend/routers/setup.py:196`).
- R10, duplicated proxy header: refused, lens exploitability, gate not met
  (`backend/services/security.py:131`); proposed as hardening.
- R11, IPv6 /48 login buckets: refused, lens exploitability, gate not met
  (`backend/routers/auth.py:52`); proposed as hardening.
- R12, CSP `connect-src`: refused, lens exploitability, gate not met (`backend/main.py:185`).
- R13, Swagger without SRI: refused, lens exploitability, gate not met (`backend/main.py:178`).
- R14, feed token in the access log: refused, lens exploitability, gate not met
  (`backend/main.py:104`).

## Coverage

Reviewer read fully: `backend/main.py`, `backend/services/auth.py`, `backend/services/auth_config.py`,
`backend/services/security.py` (trust and origin parts), `backend/routers/auth.py`,
`backend/routers/setup.py`, `entrypoint.sh`, `Dockerfile`, `docker-compose.yml`, `backend/config.py`,
uvicorn 0.54 `middleware/proxy_headers.py` and its CLI defaults, Starlette 1.10 `URL` and
`parse_host_header`. Skimmed: `backend/tests/test_security.py`, `backend/routers/logs.py` (WebSocket
wiring), the wizard auth payloads in `frontend/src/pages/setup/auth.jsx`. Skipped as other zones:
`check_outbound_url`, config masking, container guards, notifications.

Sweep owner opened every cited line. Lenses applied: exploitability, claim correctness, existing
mitigation, plus "what does the guard not cover" (F2, F4 against the M3 guard) and "is the pair
covered" (F5: HTTP scheme detection vs cookie flags). Probes run in pre-flight: the stack probes
for infrastructure, frontend and Python in `references/stack-probes.md`.

## Hand-off

Proposals, not changes:

- F7 first (High): unknown auth mode raises `ConfigError`. Ship `test_unknown_auth_mode_fails_closed`
  with the fix and remove its xfail marker.
- F1, F2, F4 together: they all concern who becomes a trusted proxy. One change: start uvicorn with
  `--no-proxy-headers`, save `trusted_proxies` only with the mode in one call, and never auto-trust a
  bridge gateway. Add a guard test asserting both the blocked paths and that enabling proxy mode
  through a proxy container still works.
- F3: one-line entrypoint change.
- F5: `Secure` on any `X-Forwarded-Proto: https`.
- F6: README wording; consider also the Settings placeholder (`frontend/src/components/auth-section.jsx`,
  out of zone, noted in the frontend report).
- Hardening for R1: set a Starlette lower bound with `parse_host_header` and use
  `request.scope["path"]` in the middleware. R10, R11, R12, R13, R14 as listed in the table.
- First run: propose a one-line pointer from `CONTRIBUTING.md` to `docs/audits/` so later runs find
  the registry.
