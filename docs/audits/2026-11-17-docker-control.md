# Verified security sweep: docker-control, 2026-11-17

## Context

Scope: `backend/services/docker.py`, `backend/services/registry.py`, `backend/routers/containers.py`,
`backend/routers/system.py`, `backend/routers/logs.py`.

Trigger: owner request for a full sweep after the 2026-11-16 audit fixes; the zone is fresh code
(container guard, self-update sidecar, registry token flow and the log WebSocket were rewritten on
`fix/audit-security-and-bugs`). First run of this zone. An authenticated user controlling Docker is
by design (`docs/audits/categories.md`); findings here are guards the code claims and outbound
requests the docs say are refused.

Commit: af8e46af79661e8669cd5d9547a584a51b2c943e

## Delegation

One read-only reviewer (`claude-kit:owasp-reviewer`, fresh context) with the shared brief (pre-read
of the rules, categories, the 2026-11-16 audit and the follow-up closures, test names) and zone
lenses: `_guard_critical` bypasses, sidecar command construction and env handling, rollback and
downgrade refusal, registry token realm and image references, log WebSocket auth and counters,
container label URLs, Docker URL injection, side effects on GET. It returned 2 findings, 10 refused
items and 6 hardening notes. Verification and reproduction by the sweep owner.

## Verification

| Finding | Zone | Verdict | Claimed | Verified | Reservations | Proof |
|---|---|---|---|---|---|---|
| F1 registry token realm fetched without the outbound guard | docker-control | OVER-RATED | Medium | Low | blind GET only: the response is read back only through a JSON `token` or `access_token` key; the actor already supplies an image the owner runs; Compose overwrites the label variant | `backend/tests/test_audit_sweep_2026_11_17.py::test_registry_realm_to_metadata_is_refused`, ran, fails as expected (request reached `169.254.169.254`); guard `test_registry_realm_public_guard`, ran, passes |
| F2 `_guard_critical` compares strings, not the resolved container | docker-control | VERIFIED REAL | Low | Low | the actor is the authenticated owner; the guard is a safety rail the README promises, not an authorization boundary | `test_guard_refuses_proxy_and_self_by_resolved_identity` (two cases), ran, fails as expected (200, not 409); guard `test_guard_allows_ordinary_container`, ran, passes |
| R1 path or argument injection through container names | docker-control | FALSE POSITIVE | - | - | lens: existing mitigation; `CONTAINER_NAME_RE` blocks `/ ? # %` and leading dots | `backend/routers/containers.py:24` |
| R2 shell injection in the self-update script | docker-control | FALSE POSITIVE | - | - | lens: existing mitigation; every argument goes through `_shell_quote`, env travels base64 in the sidecar environment | `backend/services/docker.py:945` |
| R3 sidecar image pinned by tag, not digest | docker-control | FALSE POSITIVE | - | - | lens: exploitability; gate not met, supply-chain hardening | `backend/services/docker.py:580` |
| R4 downgrade refusal ignores pre-release suffix | docker-control | FALSE POSITIVE | - | - | lens: exploitability; reaches only a pre-release of the same version, authenticated only | `backend/routers/system.py:506` |
| R5 log WebSocket auth or Origin missing | docker-control | FALSE POSITIVE | - | - | lens: claim correctness; same `host_allowed`, `origin_allowed`, `authenticate` as HTTP | `backend/routers/logs.py:78` |
| R6 log stream counter exceeds 50 under concurrent handshakes | docker-control | FALSE POSITIVE | - | - | lens: exploitability; authenticated only, generic exhaustion | `backend/routers/logs.py:87` |
| R7 container URL labels rendered unsanitised | docker-control | FALSE POSITIVE | - | - | lens: existing mitigation; `_safe_http_url` server side and `safeHref` client side | `backend/services/docker.py:213` |
| R8 Discord health webhook bypasses the guard via the proxy IP | docker-control | FALSE POSITIVE | - | - | lens: exploitability; only the authenticated admin sets it | `backend/routers/system.py:330` |
| R9 registry fetch has no total deadline or size cap | docker-control | FALSE POSITIVE | - | - | lens: exploitability; gate not met, a slow registry stalls the update check under its lock | `backend/services/docker.py:1298` |
| R10 `resolve_update_image` drops a `name:tag@digest` pin | docker-control | FALSE POSITIVE | - | - | lens: exploitability; correctness issue, no lower-trust principal | `backend/services/docker.py:611` |
| R11 sidecar mounts the in-container socket path as a host path | docker-control | FALSE POSITIVE | - | - | lens: exploitability; correctness on Podman or remapped sockets | `backend/services/docker.py:962` |
| R12 Plex thumb proxy echoes the upstream Content-Type | docker-control | FALSE POSITIVE | - | - | lens: existing mitigation; CSP `script-src 'self'` and `nosniff`; the upstream is the owner's Plex | `backend/routers/system.py:387` |

## Confirmed defects

### F1. Registry token realm fetched without the outbound guard (Low, claimed Medium)

- Location: `backend/services/docker.py:1298`
- Class: outbound requests (SSRF), CWE-918.
- Evidence chain:
  1. `_get_registry_token` checks only that the realm is http or https, then GETs it at
     `backend/services/docker.py:1298`; it runs whenever a manifest HEAD answers 401.
  2. The realm comes from the registry's `WWW-Authenticate` header; the registry host comes from the
     container image, and `_parse_container` prefers the `com.docker.compose.image` label
     (`backend/services/docker.py:273`), which an image can carry.
  3. `check_outbound_url` is called in `backend/routers/system.py:330`, `backend/services/config.py`
     and `backend/services/notifications.py`, never in the registry code, although the README says
     metadata, link-local and Docker API targets are refused.
- Scenario: the owner runs an image from a registry the attacker controls. Every update check
  (the Containers page polls it), the registry answers 401 with
  `realm="http://169.254.169.254/latest/meta-data/"` or the socket proxy's address, and Panelarr sends
  the GET from its own network position. If the response has a top-level `token` key, Panelarr
  forwards it as a bearer to the attacker's registry.
- Why Low: the request is blind unless the target answers JSON with a `token` key, the Docker API
  GETs it can reach are read-only, and the actor already has code running on the host through the
  image. The documented outbound control is still bypassed, so it stays a defect.
- Fix approach: `await check_outbound_url(realm)` before the GET, returning `""` when blocked, as
  `backend/routers/system.py:330` does; use `Config.Image` rather than the Compose label for registry
  lookups.
- Reproduction: `test_registry_realm_to_metadata_is_refused` (attack, fails: the mock transport
  records a request to `169.254.169.254`); `test_registry_realm_public_guard` (a public realm still
  returns its token, passes).

### F2. `_guard_critical` compares strings, not the resolved container (Low)

- Location: `backend/routers/containers.py:54`
- Class: container control (CWE-697, incorrect comparison).
- Evidence chain:
  1. `backend/routers/containers.py:54` compares the URL name with the hostname in
     `DOCKER_SOCKET`. In the documented socket-proxy setup (`DOCKER_SOCKET=tcp://dockerproxy:2375`,
     no `container_name`) the container is `<project>-dockerproxy-1`, so the comparison never
     matches.
  2. The resolved-identity check below it runs only when `HOSTNAME` is at least 12 characters and
     compares against Panelarr's own id; with `hostname: panelarr` it is skipped, and Docker
     resolves an id prefix in the URL to Panelarr itself.
  3. The README promises "Panelarr won't stop or recreate its own container or its Docker socket
     proxy"; the only test covers the literal name `panelarr`.
- Scenario: the owner clicks Stop on `stack-dockerproxy-1`. The proxy stops, every Docker call
  fails, including Start for the proxy, and recovery needs a shell on the host.
- Fix approach: resolve the target once (`get_container`, already called at
  `backend/routers/containers.py:62`) and refuse when its name is `panelarr`, its id is Panelarr's
  own, or the proxy host is one of its network aliases or names.
- Reproduction: `test_guard_refuses_proxy_and_self_by_resolved_identity`, two cases: the proxy by
  its Compose name and Panelarr by id prefix with `HOSTNAME=panelarr` (attack, both fail);
  `test_guard_allows_ordinary_container` (stopping `sonarr` still works, passes).

## Refused or unconfirmed candidates

- R1, container name injection: refused, lens existing mitigation (`backend/routers/containers.py:24`).
- R2, self-update shell injection: refused, lens existing mitigation (`backend/services/docker.py:945`).
- R3, sidecar tag pin: refused, lens exploitability, gate not met (`backend/services/docker.py:580`);
  proposed as hardening.
- R4, pre-release downgrade: refused, lens exploitability (`backend/routers/system.py:506`).
- R5, log WebSocket auth: refused, lens claim correctness (`backend/routers/logs.py:78`).
- R6, log stream counter race: refused, lens exploitability (`backend/routers/logs.py:87`).
- R7, label URLs: refused, lens existing mitigation (`backend/services/docker.py:213`).
- R8, Discord health webhook by IP: refused, lens exploitability (`backend/routers/system.py:330`).
- R9, no total deadline on registry calls: refused, lens exploitability, gate not met
  (`backend/services/docker.py:1298`); proposed as hardening.
- R10, digest pin dropped: refused, lens exploitability, correctness only
  (`backend/services/docker.py:611`); proposed as a bug fix.
- R11, sidecar socket path: refused, lens exploitability, correctness only
  (`backend/services/docker.py:962`).
- R12, Plex thumb Content-Type: refused, lens existing mitigation (`backend/routers/system.py:387`);
  proposed as hardening (allow only `image/*`).

## Coverage

Reviewer read fully: `backend/routers/containers.py`, `backend/routers/logs.py`,
`backend/routers/system.py`, `backend/services/docker.py`, `backend/services/registry.py`,
`backend/main.py`, `backend/services/security.py`, `docker-compose.yml`, `Dockerfile`, `entrypoint.sh`.
Skimmed: `authenticate`, the setup router's Docker calls, `backend/tests/test_security.py` and
`test_func_docker.py` names, `safeHref`, the container hooks in `frontend/src/hooks/use-api.js`.
Evaluated in Python: `resolve_update_image`, `_split_image_ref`, `_parse_container` label priority,
`_parse_www_authenticate`, httpx path normalisation of `..` in image names. Lenses: exploitability,
claim correctness, existing mitigation, "what does the guard not cover" (F2). Not verified here: the
sidecar and registry paths against a real Docker daemon (none available; unit-level mocks only).

## Hand-off

- F1: guard the realm with `check_outbound_url`, take the registry image from `Config.Image`, and
  reject image strings with `..`, `?` or `#` before building Docker or registry URLs. Ship
  `test_registry_realm_to_metadata_is_refused` with it.
- F2: resolve the target and compare identity (name, id, aliases). Ship both cases of
  `test_guard_refuses_proxy_and_self_by_resolved_identity`.
- R3: pin `SIDECAR_IMAGE` by digest and abort when its pull fails. R9: `asyncio.wait_for` around
  each registry check. R10: keep or refuse `name:tag@digest`. R12: allow only `image/*` from Plex.
