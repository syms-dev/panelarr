# Verified security sweep: config-secrets-outbound, 2026-11-17

## Context

Scope: `backend/services/config.py`, `backend/routers/config.py`, `backend/services/notifications.py`,
`backend/routers/notifications.py`, and in `backend/services/security.py` only `check_outbound_url`
and its helpers.

Trigger: owner request for a full sweep after the 2026-11-16 audit fixes (fail-closed config,
secret masking, the test-endpoint exfiltration fix M1, the resolving SSRF guard). Fresh code; first
run of this zone.

Commit: 488433a5e623382ee2d7e56d44256c20220cab17

## Delegation

One read-only reviewer (`claude-kit:owasp-reviewer`, fresh context) with the shared brief and zone
lenses: masking completeness, masked-value round trips and URL origin normalisation,
`PROTECTED_KEYS`, write atomicity and file modes, fail-closed edge cases, SSRF guard bypasses
(rebinding, redirects, IPv6 forms, numeric IPv4 forms), unguarded outbound call sites, SMTP, log
leakage. It returned 2 findings, 13 refused items and 13 hardening notes. Verification and
reproduction by the sweep owner.

## Verification

| Finding | Zone | Verdict | Claimed | Verified | Reservations | Proof |
|---|---|---|---|---|---|---|
| F1 unwritable config directory makes Panelarr ignore panelarr.json | config-secrets-outbound | VERIFIED REAL | Medium | Medium | needs `/config` unwritable at startup (disk full, read-only remount, wrong owner); in the official image saves then fail, so the actor gets the pre-setup endpoints, not credentials | `backend/tests/test_audit_sweep_2026_11_17.py::test_unwritable_config_dir_does_not_reopen_setup`, ran, fails as expected (403 `setup_required` instead of 401); guard `test_writable_config_dir_guard`, ran, passes |
| F2 unauthenticated 503 echoes pydantic input values | config-secrets-outbound | VERIFIED REAL | Low | Low | needs a hand-edited file of the wrong shape; the reviewer's example (`notifications` as a list) is normalised by the v1 migration, a `services` entry written as a list does echo | `test_config_invalid_response_does_not_echo_values`, ran, fails as expected (marker found in the response); guard `test_config_invalid_still_fails_closed_guard`, ran, passes |
| R1 `url_origin` parser differential sends a key elsewhere | config-secrets-outbound | FALSE POSITIVE | - | - | lens: claim correctness; 23 forms tried, every disagreement errs toward "different destination" | `backend/services/config.py:52` |
| R2 omitted or masked secret sent to a new URL by the test endpoint | config-secrets-outbound | FALSE POSITIVE | - | - | lens: claim correctness; closed by M1, blanked unless typed | `backend/services/config.py:484` |
| R3 switching a channel's type reuses its secret | config-secrets-outbound | FALSE POSITIVE | - | - | lens: claim correctness; `same_dest` requires the original type | `backend/services/config.py:241` |
| R4 `PROTECTED_KEYS` bypass by case or nesting | config-secrets-outbound | FALSE POSITIVE | - | - | lens: claim correctness; only three keys are merged | `backend/routers/config.py:47` |
| R5 STARTTLS downgrade | config-secrets-outbound | FALSE POSITIVE | - | - | lens: existing mitigation; `starttls` raises when unsupported, caught as a failure | `backend/services/notifications.py:131` |
| R6 email header injection | config-secrets-outbound | FALSE POSITIVE | - | - | lens: existing mitigation; `EmailMessage` refuses CR/LF, subject is constant | `backend/services/notifications.py:115` |
| R7 redirects followed to a blocked target | config-secrets-outbound | FALSE POSITIVE | - | - | lens: existing mitigation; httpx 0.28 does not follow by default, tests set it explicitly | `backend/services/config.py:616` |
| R8 numeric, mapped and NAT64 IPv4 forms bypass the guard | config-secrets-outbound | FALSE POSITIVE | - | - | lens: claim correctness; resolved by `getaddrinfo` and checked | `backend/services/security.py:231` |
| R9 config file mode or concurrent writers lose secrets | config-secrets-outbound | FALSE POSITIVE | - | - | lens: claim correctness; `mkstemp` 0600, chmod before replace, no await between load and save | `backend/services/config.py:371` |
| R10 DNS rebinding between check and request | config-secrets-outbound | FALSE POSITIVE | - | - | lens: exploitability; gate not met, only an authenticated user or the pre-setup wizard sets URLs | `backend/services/security.py:291` |
| R11 Docker endpoint check compares hostnames only | config-secrets-outbound | FALSE POSITIVE | - | - | lens: exploitability; gate not met, same principal as R10 | `backend/services/security.py:282` |
| R12 6to4, IPv4-compatible and other IPv6 metadata forms | config-secrets-outbound | FALSE POSITIVE | - | - | lens: exploitability; gate not met, same principal as R10 | `backend/services/security.py:230` |
| R13 SMTP guard checks port 80 and urlparse's host | config-secrets-outbound | FALSE POSITIVE | - | - | lens: exploitability; gate not met, same principal as R10 | `backend/services/notifications.py:226` |
| R14 email destination ignores `encryption`, masked password downgraded to plaintext AUTH | config-secrets-outbound | FALSE POSITIVE | - | - | lens: exploitability; gate not met, needs an authenticated user | `backend/services/config.py:36` |
| R15 `SENSITIVE_KEYS` unused; custom service names mask only `api_key` | config-secrets-outbound | FALSE POSITIVE | - | - | lens: exploitability; gate not met, registry services are complete, custom names are not created by the UI | `backend/services/config.py:22` |
| R16 80 characters of a blocked webhook URL logged | config-secrets-outbound | FALSE POSITIVE | - | - | lens: exploitability; only blocked (metadata, link-local) targets are logged | `backend/services/notifications.py:221` |
| R17 malformed `notifications` body gives a 500 | config-secrets-outbound | FALSE POSITIVE | - | - | lens: exploitability; authenticated, fails closed | `backend/routers/config.py:84` |

## Confirmed defects

### F1. An unwritable config directory makes Panelarr ignore panelarr.json and reopen the wizard (Medium)

- Location: `backend/services/config.py:95`
- Class: configuration integrity; fail-open on error (CWE-636).
- Evidence chain:
  1. `resolve_config_path` tries `[primary, fallback]` (`backend/services/config.py:95`) and moves
     to `~/.config/panelarr/panelarr.json` on any `OSError` from a write test, without checking
     whether the primary `panelarr.json` exists; the choice is cached for the process.
  2. `load_config` then finds no file at the fallback and returns defaults, so
     `is_auth_configured()` is false and `backend/main.py:145` lets `/api/setup/*` through
     unauthenticated.
  3. The fail-closed branch (`backend/services/config.py:313`) covers a file that exists and does
     not parse; an existing but unwritable file is never read.
- Scenario: the disk holding `/config` fills with downloads and the host reboots. Panelarr starts
  as a fresh install: any LAN client can call `/api/setup/discover` (container names, images,
  ports), `/api/setup/system-check` and `/api/setup/test-notification`; on installs where the home
  directory is writable (source installs, derived images) `POST /api/setup/auth` succeeds and the
  actor takes the instance. The state persists until a restart because the path is cached.
- Fix approach: never fall back once the primary `panelarr.json` exists or `CONFIG_PATH` is set;
  read it and fail saves, or raise `ConfigError` (503) as `backend/services/config.py:324` does.
- Reproduction: `test_unwritable_config_dir_does_not_reopen_setup` makes the config directory
  read-only and points the home directory into the test's temp folder (attack, fails: 403
  `setup_required`); `test_writable_config_dir_guard` (passes). The attack test skips when run as
  root, which ignores directory permissions.

### F2. The unauthenticated 503 `config_invalid` echoes parts of panelarr.json (Low)

- Location: `backend/services/config.py:313`
- Class: secrets in responses (CWE-209).
- Evidence chain:
  1. `backend/services/config.py:313` builds the error from `str(exc)`; for a pydantic
     `ValidationError` that text includes `input_value=` with the first and last characters of the
     offending value.
  2. `backend/main.py:158` returns it in the 503 body to any client, before authentication.
  3. Masking exists only in `get_masked_config` and `mask_channel`; nothing sanitises the error.
- Scenario: the owner hand-edits a service as a list (`"sonarr": ["http://sonarr:8989", "<key>"]`)
  and restarts; any unauthenticated client that requests `/api/containers` receives the tail of the
  key and the config path.
- Fix approach: build the message from `exc.errors(include_input=False)` (location and message
  only) for validation errors, in both the response and the log.
- Reproduction: `test_config_invalid_response_does_not_echo_values` (attack, fails: the key's
  marker is in the response); `test_config_invalid_still_fails_closed_guard` (still 503
  `config_invalid`, passes).

## Refused or unconfirmed candidates

- R1, URL origin differential: refused, lens claim correctness (`backend/services/config.py:52`).
- R2, test-endpoint secret reuse: closed earlier, by the follow-up review's M1 fix; re-checked
  (`backend/services/config.py:484`).
- R3, channel type switch: refused, lens claim correctness (`backend/services/config.py:241`).
- R4, `PROTECTED_KEYS`: refused, lens claim correctness (`backend/routers/config.py:47`).
- R5, STARTTLS downgrade: refused, lens existing mitigation (`backend/services/notifications.py:131`).
- R6, header injection: refused, lens existing mitigation (`backend/services/notifications.py:115`).
- R7, redirects: refused, lens existing mitigation (`backend/services/config.py:616`).
- R8, IPv4 and mapped forms: refused, lens claim correctness (`backend/services/security.py:231`).
- R9, file modes and writers: refused, lens claim correctness (`backend/services/config.py:371`).
- R10 to R14, SSRF guard gaps (rebinding, Docker endpoint by IP, IPv6 forms, SMTP port, email
  encryption field): refused, lens exploitability, gate not met: only an authenticated user, or
  anyone before setup, can set an outbound URL, and both already control Docker by design. Cited at
  `backend/services/security.py:291`, `backend/services/security.py:282`,
  `backend/services/security.py:230`, `backend/services/notifications.py:226`,
  `backend/services/config.py:36`; proposed as hardening because the README promises the refusal.
- R15, unused `SENSITIVE_KEYS`: refused, lens exploitability (`backend/services/config.py:22`).
- R16, blocked webhook prefix logged: refused, lens exploitability (`backend/services/notifications.py:221`).
- R17, malformed notifications body: refused, lens exploitability (`backend/routers/config.py:84`).

## Coverage

Reviewer read fully: `backend/services/config.py`, `backend/routers/config.py`,
`backend/services/notifications.py`, `backend/routers/notifications.py`, `backend/services/security.py`,
`backend/main.py`. Skimmed to trace calls: `backend/routers/setup.py`, `backend/services/auth_config.py`,
`backend/services/auth.py`, `backend/services/registry.py`, `backend/services/discover.py`,
`Dockerfile`, `entrypoint.sh`, `docker-compose.yml`, the channel fields in
`frontend/src/pages/settings.jsx`. Skipped as other zones: outbound calls in `backend/routers/system.py`,
`backend/services/arr.py`, `backend/services/media.py`, `backend/routers/media.py`,
`backend/services/docker.py` (the registry realm is docker-control F1). Lenses: exploitability,
claim correctness, existing mitigation, "what happens on the recovery path" (F1: restart after a
disk-full event). The sweep owner corrected F2's example: `notifications` as a list is normalised
by `_migrate_v1_to_v2` and does not trigger; a `services` entry of the wrong type does.

## Hand-off

- F1: fail closed when the primary config exists but its directory is unwritable. Ship
  `test_unwritable_config_dir_does_not_reopen_setup`.
- F2: strip input values from validation errors. Ship `test_config_invalid_response_does_not_echo_values`.
- R10 to R14: the README says outbound requests to metadata and the Docker API "are refused";
  either pin the vetted address in the transport, resolve the Docker endpoint and compare
  addresses, add the missing IPv6 forms and check SMTP host and port directly, or soften the README
  sentence to what the guard does.
- R15: use `SENSITIVE_KEYS` for unknown service names. R17: validate the notifications body with a
  Pydantic model as `ThresholdsUpdate` does.
