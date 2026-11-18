# Verified security sweep: media-integrations, 2026-11-17

## Context

Scope: `backend/services/arr.py`, `backend/routers/arr.py`, `backend/routers/downloads.py`,
`backend/services/media.py`, `backend/routers/media.py`, `backend/services/discover.py`,
`backend/services/calendar.py`, `backend/routers/calendar.py`.

Trigger: owner request for a full sweep after the 2026-11-16 audit fixes (qBittorrent 5.x, the ICS
feed token, poster proxying, calendar dates). Fresh code; first run of this zone.

Commit: 2c08b9ca107c889e896874630396ea8bd91988cd

## Delegation

One read-only reviewer (`claude-kit:owasp-reviewer`, fresh context) with the shared brief and zone
lenses: ICS feed token scope, comparison, regeneration and leakage; ICS injection; poster and
thumbnail proxying (SSRF, path traversal, content type, cache growth); ids interpolated into
upstream URLs; upstream HTML returned as HTML; destructive actions on GET. It returned 1 finding,
14 refused items and 10 hardening notes. Verification and reproduction by the sweep owner, who also
checked every other `logger.*(…exc)` call in the backend for the same class (Sonarr, Radarr, Plex,
Jellyfin and Emby send their keys in headers; the notification senders never call
`raise_for_status`, so only transport errors without URLs are logged).

## Verification

| Finding | Zone | Verdict | Claimed | Verified | Reservations | Proof |
|---|---|---|---|---|---|---|
| F1 SABnzbd API key written to the log on a non-2xx answer | media-integrations | VERIFIED REAL | Low | Low | needs someone with log access but no Panelarr login (a log viewer or shipper) | `backend/tests/test_audit_sweep_2026_11_17.py::test_sab_stats_error_does_not_log_api_key`, ran, fails as expected (key in the captured WARNING); guard `test_sab_stats_success_guard`, ran, passes |
| R1 feed token unlocks other routes or methods | media-integrations | FALSE POSITIVE | - | - | lens: claim correctness; exact path and GET only | `backend/main.py:139` |
| R2 ICS property injection from titles | media-integrations | FALSE POSITIVE | - | - | lens: existing mitigation; CR removed, LF escaped | `backend/routers/calendar.py:85` |
| R3 SSRF through `/api/media/poster` with an absolute URL | media-integrations | FALSE POSITIVE | - | - | lens: existing mitigation; https only, five allowlisted CDN hosts, no host differential found | `backend/routers/media.py:278` |
| R4 path traversal through `/MediaCover/` | media-integrations | FALSE POSITIVE | - | - | lens: existing mitigation; prefix checked raw and decoded, no `..`, `\` or `://` | `backend/routers/media.py:234` |
| R5 poster cache filename traversal | media-integrations | FALSE POSITIVE | - | - | lens: claim correctness; md5 hex name | `backend/routers/media.py:286` |
| R6 stored XSS through an SVG poster | media-integrations | FALSE POSITIVE | - | - | lens: existing mitigation; CSP `script-src 'self'`, `nosniff`, allowlisted CDNs, cached hits served as JPEG | `backend/routers/media.py:306` |
| R7 ids injected into upstream paths | media-integrations | FALSE POSITIVE | - | - | lens: existing mitigation; ids typed `int`, qBit hashes regex-checked, sources allowlisted | `backend/routers/downloads.py:295` |
| R8 upstream record ids re-used in paths | media-integrations | FALSE POSITIVE | - | - | lens: exploitability; the request goes back to the same service with the same key | `backend/routers/downloads.py:197` |
| R9 destructive action on GET | media-integrations | FALSE POSITIVE | - | - | lens: claim correctness; every write is POST or DELETE behind the Origin check | `backend/main.py:129` |
| R10 discovery URL built from container data | media-integrations | FALSE POSITIVE | - | - | lens: exploitability; suggestion only, the user saves it | `backend/services/discover.py:152` |
| R11 upstream errors in the calendar JSON | media-integrations | FALSE POSITIVE | - | - | lens: claim correctness; URL only, keys travel in headers, authenticated route | `backend/services/calendar.py:256` |
| R12 control characters break the ICS feed | media-integrations | FALSE POSITIVE | - | - | lens: exploitability; gate not met, availability of the feed only | `backend/routers/calendar.py:85` |
| R13 unbounded window on the token-reachable feed | media-integrations | FALSE POSITIVE | - | - | lens: exploitability; gate not met, the token holder is the owner's calendar app | `backend/routers/calendar.py:184` |
| R14 poster size checked after the full read | media-integrations | FALSE POSITIVE | - | - | lens: exploitability; authenticated, allowlisted CDNs | `backend/routers/media.py:310` |

## Confirmed defects

### F1. SABnzbd API key written to the container log on a non-2xx answer (Low)

- Location: `backend/services/arr.py:242`
- Class: secrets in logs (CWE-532).
- Evidence chain:
  1. `get_sabnzbd_stats` sends the key as the `apikey` query parameter and calls
     `raise_for_status()`; httpx's `HTTPStatusError` text contains the full request URL.
  2. `backend/services/arr.py:242` logs that exception with `%s`. The project configures no log
     filter, so the WARNING reaches stderr and `docker logs`. The dashboard polls
     `GET /api/downloads/stats`, so every failed poll logs the key again.
  3. `_safe_error` (`backend/services/arr.py:37`, "never includes URLs or query params") is applied
     to the response, not the log line.
- Scenario: SAB's hostname whitelist does not include the name Panelarr uses, so SAB answers 403 on
  every poll. Anyone with read access to Panelarr's logs (a Dozzle or Portainer viewer, a Loki
  pipeline) but no Panelarr login reads the key and controls SABnzbd, including its usenet server
  credentials.
- Fix approach: log `_safe_error(exc)` instead of `exc`, as the next line already does for the
  response. The same pattern appears in the SAB connection test in `backend/services/config.py`
  (out of zone, see hand-off).
- Reproduction: `test_sab_stats_error_does_not_log_api_key` (attack, fails: the captured WARNING
  contains the key); `test_sab_stats_success_guard` (stats still come back, passes).

## Refused or unconfirmed candidates

- R1, feed token scope: refused, lens claim correctness (`backend/main.py:139`).
- R2, ICS injection: refused, lens existing mitigation (`backend/routers/calendar.py:85`).
- R3, poster SSRF: refused, lens existing mitigation (`backend/routers/media.py:278`).
- R4, MediaCover traversal: refused, lens existing mitigation (`backend/routers/media.py:234`).
- R5, cache filename: refused, lens claim correctness (`backend/routers/media.py:286`).
- R6, SVG poster: refused, lens existing mitigation (`backend/routers/media.py:306`); proposed as
  hardening (raster types only).
- R7, ids in upstream URLs: refused, lens existing mitigation (`backend/routers/downloads.py:295`).
- R8, upstream ids re-used: refused, lens exploitability (`backend/routers/downloads.py:197`);
  proposed as hardening (`int()` coercion).
- R9, GET side effects: refused, lens claim correctness (`backend/main.py:129`).
- R10, discovery URLs: refused, lens exploitability (`backend/services/discover.py:152`).
- R11, calendar errors: refused, lens claim correctness (`backend/services/calendar.py:256`).
- R12, ICS control characters: refused, lens exploitability (`backend/routers/calendar.py:85`).
- R13, feed window: refused, lens exploitability (`backend/routers/calendar.py:184`).
- R14, poster size: refused, lens exploitability (`backend/routers/media.py:310`).

## Coverage

Reviewer read fully: every file in scope, plus `backend/main.py`. Skimmed to trace calls: the
calendar-token endpoints in `backend/routers/auth.py`, `backend/services/auth_config.py`, the Plex
thumb proxy in `backend/routers/system.py`, `load_config` and `save_config`, `entrypoint.sh`,
`Dockerfile`, test names in `backend/tests/test_security.py`. Checks run by the reviewer: a
urlparse versus httpx host differential, httpx dot-segment normalisation, the `HTTPStatusError`
text, `_build_ics` output for CRLF and control characters. Lenses: exploitability, claim
correctness, existing mitigation, "is the pair covered" (response and log for the same error).

## Hand-off

- F1: log `_safe_error(exc)` at `backend/services/arr.py:242`, and apply the same to the SAB and
  Jellyfin connection tests in `backend/services/config.py` (out of zone: proposed for the next
  `config-secrets-outbound` run). Ship `test_sab_stats_error_does_not_log_api_key`.
- Hardening: R6 raster types only for posters and the Plex thumb; R8 `int()` on upstream ids;
  R12 strip control characters and fold ICS lines at 75 octets; R13 cap the feed window; R14
  stream posters with a byte limit; `Cache-Control: private` on authenticated image responses;
  `--no-access-log` or a query filter so the feed token stays out of the access log.
