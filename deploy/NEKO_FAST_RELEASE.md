# NEKO Sub2API Fast Release

This runbook targets a production update in less than ten minutes after the
required Tailscale SSH additional check has completed. GitHub runner queueing,
human authentication time, merge conflicts, destructive migrations, identity
drift, and new production error categories are outside the fast-path SLO. Any
of those conditions stops the release and moves it to the investigation path.

## Why the previous release took so long

The source is the current Codex Session JSONL:

```text
/root/.codex/sessions/2026/09/07/rollout-2026-09-07T05-15-05-01a07893-2a35-7bd1-9ddd-8c8be5a8e8c4.jsonl
SHA-256 073ea0f76b673894755d274af29e748f867d253dc6ebc756c72e7914da40e1da
```

The release task issued 128 execution calls and 55 wait calls. Nine execution
calls failed before a corrected attempt. The main elapsed-time blocks were:

| Phase | Observed wall time | Cause |
| --- | ---: | --- |
| Repository discovery and merge | 15m 36s | Reconstructed paths and prior release facts manually |
| Local validation | 29m 41s | Repeated full suites, DNS retry, pnpm version retry |
| Candidate CI | 10m 19s | Unit (6m 32s) and integration (3m 38s) ran serially |
| Tag CI and image publication | 10m 44s | Repeated the same CI after candidate CI; image was ready in 4m 44s |
| Tailscale handling | 16m 53s active plus human wait | Several short-lived links were generated |
| Production backup | 8m 01s | DB credentials/tool versions were discovered during the release |
| Production deploy | 4m 21s | One local/remote Docker image-ID mismatch retry plus 60s stability |
| Postflight and incident diagnosis | 30m 31s | Generic log parsing found pre-existing schema drift and triggered forensics |

The irreducible operations were much shorter: the successful release workflow
took 4m 44s, a known-good backup path takes about one minute, and the successful
image transaction took about 75 seconds. Most elapsed time was duplicate work
or first-time discovery that now belongs in scripts and durable preflight.

## Fast-path prerequisites

Do these before starting the ten-minute clock:

1. Complete `tailscale ssh root@debian-s-2vcpu-4gb-120gb-intel-sfo2 true`.
   If Tailscale prints an additional-check URL, finish it and rerun the command
   once. Do not repeatedly generate new URLs.
2. Use a clean `neko/stable` worktree with the `origin` upstream and `neko` fork
   remotes configured.
3. Keep Go module/build caches and pnpm store warm. Pin pnpm to `9.15.9`.
4. Verify `gh auth status`, Docker, `jq`, and at least 1 GB free on both hosts.
5. Confirm the previous production release receipt and its rollback directory
   still exist.

## Ten-minute path

| Budget | Operation | Required evidence |
| --- | --- | --- |
| 0:00-1:30 | Run `deploy/neko-merge-upstream.sh vX.Y.Z` | Clean merge, additive-migration scan, codegen parity, all-package compile, focused NEKO tests, Compose checks |
| 1:30 | Create immutable `vX.Y.Z-neko.N`; push the candidate branch and tag together | Candidate branch and annotated tag resolve to the same SHA |
| 1:30-8:00 | Run candidate CI, security scan, and tag image build concurrently | All three successful on the same SHA; GHCR RepoDigest and OCI revision match |
| 1:30-3:00 | In parallel, freeze production preimage and create the PostgreSQL/config backup | Current service healthy/restart 0; hashes recorded; PG 18 archive list and full decode pass |
| 8:00-9:30 | Promote the exact SHA to `neko/stable`, then deploy the immutable RepoDigest | Only Sub2API recreated; automatic image rollback armed |
| 9:30-10:00 | Fixed postflight | Internal/public health 200, version/commit/digest exact, migrations present, config/env unchanged, restart 0, no panic/fatal/new error category |

The CI workflow splits unit and integration tests into separate jobs. From the
recorded run, that reduces the test critical path from about 10m 10s to about
6m 32s plus setup. CI and security workflows run on branch pushes only, so a
release tag no longer launches a duplicate full validation batch.

The tag can be published while candidate CI is running so the image build runs
in parallel. A failing gate consumes that immutable NEKO version; fix the
candidate and increment `neko.N`. Never move or overwrite a published tag.

## Required gates

Fast-path gates are intentionally small but meaningful:

- upstream tag and candidate commit identities are exact;
- no merge conflicts and no tracked worktree drift;
- no obvious destructive migration statement;
- generated Ent/Wire files match committed output;
- every Go package compiles;
- NEKO routing, priority, membership, concurrency, and failure metadata tests pass;
- deployment/Compose contract tests pass;
- the Apple Container lifecycle test runs in the macOS CI job; Linux fast gates
  syntax-check that macOS-specific script;
- full unit, integration, frontend, lint, and security jobs pass once in GitHub;
- the published image reports the expected version, commit, platform, and RepoDigest;
- production backup, automatic rollback, health, migration, and log-category checks pass.

## Exit to investigation

Stop the fast path without deploying when any of these occurs:

- Tailscale authentication is incomplete when the timed run starts;
- a real merge conflict appears;
- migration changes include data deletion, table/column deletion, truncation,
  or a column type rewrite;
- code generation changes files unexpectedly;
- any focused or GitHub gate fails;
- the expected image is not ready by minute eight;
- production preimage, image identity, configuration hash, or protected routing
  settings drift;
- postflight finds a panic, fatal event, restart, failed migration, or an error
  category absent from the established baseline.

Investigation time is reported separately. A release that exits the fast path
has not missed the SLO; it has correctly declined the routine-release route.

## Existing production transaction contract

Use the proven transaction implementation at:

```text
/root/neko/codex-transfer/artifacts/sub2api-release-v0182-20260825/sub2api_image_only_transaction.py
```

Resolve the candidate image ID on the production Docker daemon after pulling
the immutable RepoDigest. Do not reuse a local daemon image ID: the v0.2.1
Session proved that the two daemons report different IDs for the same verified
RepoDigest. Use PostgreSQL 18.4 to validate the custom-format backup; PostgreSQL
15 cannot parse archive format 1.16.

The current production baseline and release evidence are in
`/root/neko/codex-transfer/artifacts/sub2api-release-v021-20260907/`.
