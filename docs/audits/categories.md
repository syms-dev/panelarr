# Categories the security sweep verifies

Categories, not patterns: a new pattern lands under an existing category without changing the list.
"Covered by" names the project's own control. "Mechanical" means a test in `backend/tests/` or
`frontend/` fails when the control regresses; "sentence" means it is only documented.

Baseline controls that are by design (a finding that restates one of these without a concrete
bypass is not a finding):

- Whoever is authenticated controls Docker and therefore the host (README "Security").
- Auth mode `none` means no authentication; it is the owner's choice (docs/configuration.md "none").
- Outbound requests to private and loopback addresses are allowed (homelab services and LAN webhooks
  live there); only metadata, link-local, unspecified, multicast and the Docker API are refused
  (docs/configuration.md "Outbound requests").
- The API key is accepted in every auth mode via `X-Api-Key` (documented, accepted risk L3 of the
  2026-11-16 review).

| Category | Covered by | Mechanical? |
|---|---|---|
| Authentication and sessions | `backend/services/auth.py` (`authenticate`, JWT HS256 with `jti`, persisted revocation, secret rotation on credential change), `SameSite=Strict` cookie | yes: `test_security.py` |
| Setup and bootstrap | `backend/main.py` setup gating, `backend/routers/setup.py`, `is_auth_configured` | yes: `test_security.py`, `test_auth_config.py` |
| Trusted proxies and client identity | `backend/services/security.py` (`is_trusted_proxy`, `client_ip`, `proxy_user`), default loopback only | yes: `test_security.py` |
| Cross-origin and DNS rebinding | `origin_allowed`, `host_allowed`, no CORS, WebSocket Origin check | yes: `test_security.py` |
| Configuration integrity | `load_config` fails closed (503), corrupt-file backup, `PROTECTED_KEYS` | yes: `test_security.py` |
| Secrets at rest and in responses | masking in `/api/config` and `mask_channel`, `_preserve_secrets`, `SecretReuseError` | yes: `test_security.py` |
| Outbound requests (SSRF) | `check_outbound_url` (resolve then check), `follow_redirects=False` on tests | partial: literal and resolved cases tested |
| Container control | `_guard_critical` (self and socket proxy), self-update sidecar pin, env-file, rollback, downgrade refusal | partial: unit tests with mocked Docker |
| Rate limiting | per-IP login limiter (IPv6 /64 buckets) on `client_ip` | yes |
| Input validation | Pydantic models (`ThresholdsUpdate`, setup payloads), path containment in `spa_fallback` | partial |
| Security headers | CSP with `frame-ancestors`, set in `backend/main.py` middleware | partial |
| Frontend trust | server enforces every gate; `safeHref` for container URL labels; `?next=` handling in `api.js` | partial: vitest |
| Calendar day | calendar range and air dates in local time | yes: `test_calendar.py`, vitest |
| Supply chain and deploy | pinned lockfiles, gitleaks and npm audit in CI, non-root container, `no-new-privileges` | partial |
| Spec drift | README "Security" and docs/configuration.md describe the controls above | sentence |
