#!/usr/bin/env bash
set -Eeuo pipefail

readonly default_budget_seconds=120

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf 'usage: %s PREVIOUS_UPSTREAM_TAG TARGET_UPSTREAM_TAG\n' "${0##*/}" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
readonly previous_tag=$1
readonly target_tag=$2
[[ $previous_tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage
[[ $target_tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || die 'not inside a Git repository'
cd "$repo_root"
[[ -z $(git status --porcelain) ]] || die 'working tree must be clean'
git rev-parse --verify "$previous_tag^{commit}" >/dev/null
git rev-parse --verify "$target_tag^{commit}" >/dev/null
git merge-base --is-ancestor "$target_tag^{commit}" HEAD || die "$target_tag is not merged into HEAD"

readonly started_at=$SECONDS
readonly budget_seconds=${NEKO_FAST_GATE_BUDGET_SECONDS:-$default_budget_seconds}
go_version=$(awk '$1 == "go" { print $2; exit }' backend/go.mod)
[[ $go_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'backend/go.mod has an unsupported Go version'
readonly go_image=${NEKO_GO_IMAGE:-golang:${go_version}-alpine}
readonly cache_root=${XDG_CACHE_HOME:-${HOME:?HOME is required}/.cache}
readonly go_path=${GOPATH:-${HOME:?HOME is required}/go}
readonly module_cache=${NEKO_GO_MOD_CACHE:-$go_path/pkg/mod}
readonly build_cache=${NEKO_GO_BUILD_CACHE:-$cache_root/go-build}
mkdir -p "$module_cache" "$build_cache"

run_go() {
  docker run --rm --init --network host \
    --volume "$repo_root:/src" \
    --volume "$module_cache:/go/pkg/mod" \
    --volume "$build_cache:/root/.cache/go-build" \
    --workdir /src/backend \
    "$go_image" \
    sh -c 'export PATH=/go/bin:/usr/local/go/bin:$PATH; exec "$@"' sh "$@"
}

printf 'fast_gate: previous=%s target=%s candidate=%s go=%s\n' \
  "$previous_tag" "$target_tag" "$(git rev-parse HEAD)" "$go_version"

# Fast path permits additive migrations. Data deletion and table/column type
# rewrites need the slower migration review before a release tag is created.
if git diff --unified=0 "$previous_tag..$target_tag" -- 'backend/migrations/*.sql' \
  | sed -n '/^+[^+]/p' \
  | sed '/^+[[:space:]]*--/d' \
  | grep -Eiq 'DROP[[:space:]]+(TABLE|COLUMN)|TRUNCATE([[:space:]]|$)|DELETE[[:space:]]+FROM|ALTER[[:space:]].*ALTER[[:space:]]+COLUMN.*TYPE'; then
  die 'potentially destructive upstream migration requires the slow path'
fi

# Preserve upstream instruction templates byte-for-byte; Markdown prompt text
# may carry trailing spaces intentionally. All executable/source files remain
# under the whitespace gate.
git diff --check -- . ':(exclude)backend/internal/pkg/openai/instructions_gpt6_astra.txt'
/bin/bash -n deploy/apple-container.sh
/bin/bash -n deploy/tests/apple-container-test.sh
/bin/bash -n deploy/neko-merge-upstream.sh
/bin/bash -n deploy/neko-fast-gate.sh
if [[ $(uname -s) == Darwin ]]; then
  /bin/bash deploy/tests/apple-container-test.sh
fi
/bin/sh deploy/tests/docker-compose-security-test.sh
/bin/sh deploy/tests/docker-compose-gateway-env-test.sh
/bin/sh deploy/tests/docker-runtime-resources-test.sh
/bin/sh deploy/test-caddyfile-cache.sh

run_go go generate ./ent
run_go go generate ./cmd/server
git diff --exit-code -- backend/ent backend/cmd/server/wire_gen.go

# Compile every default package, then run only the contracts maintained by the
# NEKO fork. The full unit/integration suites remain required in parallel CI.
run_go go test -run '^$' ./...
readonly focused='Routing|GroupAccountPriority|SchedulerMembership|ConcurrencyHandoff|FailureMetadata|AccountConcurrencyConfirmation|BindGroups|ModelNotAllowed|AllowlistedModel|Duplicate.*Model|CaseVariantModel|SessionUpdate'
run_go go test -count=1 ./cmd/server ./internal/handler ./internal/repository ./internal/service ./internal/server/routes -run "$focused"
run_go go test -count=1 -tags=unit ./internal/config ./internal/handler/admin ./internal/service -run "$focused"
run_go go test -count=1 -tags=integration ./internal/repository -run "$focused"

if ! git diff --quiet "$previous_tag..$target_tag" -- frontend/package.json frontend/pnpm-lock.yaml; then
  npx --yes pnpm@9.15.9 --dir frontend install --frozen-lockfile --lockfile-only
  git diff --exit-code -- frontend/pnpm-lock.yaml
fi

[[ -z $(git status --porcelain) ]] || die 'fast gate changed tracked files'
elapsed=$((SECONDS - started_at))
printf 'fast_gate: passed elapsed_seconds=%d budget_seconds=%d\n' "$elapsed" "$budget_seconds"
if (( elapsed > budget_seconds )); then
  die 'fast gate passed but exceeded its fast-path budget'
fi
