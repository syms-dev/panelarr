# Verified security sweep: supply-chain-deploy, 2026-11-17

## Context

Scope: `Dockerfile`, `entrypoint.sh`, `docker-compose.yml`, `.dockerignore`, `.github/workflows/ci.yml`,
`.github/workflows/publish.yml`, `.github/workflows/release.yml`, `pyproject.toml`,
`frontend/package.json` and `frontend/package-lock.json`.

Trigger: owner request for a full sweep. First run of this zone. The uvicorn launch line in
`entrypoint.sh` was swept for authentication effects in the auth-sessions zone (F2, F3 there) and is
not re-reported here.

Commit: 2c08b9ca107c889e896874630396ea8bd91988cd

## Delegation

No reviewer: a small zone of configuration files, read by the sweep owner, as the skill allows for a
single small zone. The reading is therefore not independent of the verifier; the dependency audits
below are mechanical and independent of either.

## Verification

| Finding | Zone | Verdict | Claimed | Verified | Reservations | Proof |
|---|---|---|---|---|---|---|
| R1 known-vulnerable Python dependencies | supply-chain-deploy | FALSE POSITIVE | - | - | lens: claim correctness; `pip-audit -l` on the installed set: "No known vulnerabilities found" | `pyproject.toml:9` |
| R2 known-vulnerable npm dependencies | supply-chain-deploy | FALSE POSITIVE | - | - | lens: claim correctness; `npm audit` (all) and `--omit=dev`: "found 0 vulnerabilities" | `frontend/package.json:10` |
| R3 workflow script injection from event data | supply-chain-deploy | FALSE POSITIVE | - | - | lens: claim correctness; no `github.event.*` in `run:`; the release tag is pushed only by maintainers | `.github/workflows/release.yml:21` |
| R4 `pull_request_target` or secrets exposed to fork PRs | supply-chain-deploy | FALSE POSITIVE | - | - | lens: claim correctness; `pull_request` only, no workflow-level secrets | `.github/workflows/ci.yml:6` |
| R5 actions pinned by tag, not commit SHA | supply-chain-deploy | FALSE POSITIVE | - | - | lens: exploitability; gate not met, hardening against a compromised action | `.github/workflows/publish.yml:47` |
| R6 `ci.yml` has no `permissions:` block | supply-chain-deploy | FALSE POSITIVE | - | - | lens: exploitability; gate not met, default token scope depends on repository settings | `.github/workflows/ci.yml:13` |
| R7 no Python lockfile; image installs the newest versions in range | supply-chain-deploy | FALSE POSITIVE | - | - | lens: exploitability; gate not met, but it also lets an old Starlette in (auth-sessions R1) | `Dockerfile:19` |
| R8 base images not pinned by digest | supply-chain-deploy | FALSE POSITIVE | - | - | lens: exploitability; gate not met | `Dockerfile:1` |
| R9 compose without `read_only` | supply-chain-deploy | FALSE POSITIVE | - | - | lens: exploitability; gate not met, the process already controls Docker | `docker-compose.yml:13` |
| R10 entrypoint `chown -R` follows a planted symlink as root | supply-chain-deploy | FALSE POSITIVE | - | - | lens: claim correctness; GNU `chown -R` defaults to `-P` and does not traverse symlinks | `entrypoint.sh:20` |
| R11 secrets or local config copied into the image | supply-chain-deploy | FALSE POSITIVE | - | - | lens: existing mitigation; `.dockerignore` excludes `.env*` and `panelarr.json` | `.dockerignore:17` |

## Confirmed defects

None. Zero confirmed in this zone on 2026-11-17; the lenses applied are listed in Coverage so the
result is auditable.

## Refused or unconfirmed candidates

- R1, R2: refused, lens claim correctness; the audits ran clean (`pyproject.toml:9`, `frontend/package.json:10`).
- R3: refused, lens claim correctness (`.github/workflows/release.yml:21`).
- R4: refused, lens claim correctness (`.github/workflows/ci.yml:6`).
- R5: refused, lens exploitability, gate not met (`.github/workflows/publish.yml:47`); proposed as hardening.
- R6: refused, lens exploitability, gate not met (`.github/workflows/ci.yml:13`); proposed as hardening.
- R7: refused, lens exploitability, gate not met (`Dockerfile:19`); proposed as hardening.
- R8: refused, lens exploitability, gate not met (`Dockerfile:1`); proposed as hardening.
- R9: refused, lens exploitability, gate not met (`docker-compose.yml:13`).
- R10: refused, lens claim correctness (`entrypoint.sh:20`).
- R11: refused, lens existing mitigation (`.dockerignore:17`).

## Coverage

Read fully by the sweep owner: every file in scope. Commands run: `pip-audit -l` (pip-audit 2.10.1)
on the installed environment (fastapi 0.163.1, starlette 1.10.0, uvicorn 0.54.0, httpx 0.28.1,
PyJWT 2.15.1, bcrypt 4.3.0, pydantic 2.14.3); `npm audit` and `npm audit --omit=dev` in `frontend/`;
the infrastructure probes of `references/stack-probes.md` (unpinned actions, workflow-level secrets,
event interpolation, compose hardening). Not run here: gitleaks (CI only), a build of the image (no
Docker daemon on this machine).

## Hand-off

- R5: pin every action to a commit SHA (Dependabot can keep them current).
- R6: add `permissions: contents: read` at the top of `ci.yml`.
- R7: add a lockfile (`uv lock` or `pip-compile`) and install from it in the Dockerfile; at least set
  `starlette>=` to a version with `parse_host_header` (auth-sessions R1).
- R8: pin `node:22-slim` and `python:3.11-slim` by digest.
- R9: consider `read_only: true` with the existing `tmpfs: /tmp`, after checking that only `/config`
  is written.
