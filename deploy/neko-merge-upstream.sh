#!/usr/bin/env bash
set -euo pipefail

readonly upstream_url='https://github.com/Wei-Shaw/sub2api.git'
readonly stable_branch='neko/stable'
readonly generated_path='backend/cmd/server/wire_gen.go'

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

run_go() {
  local command=$1
  if command -v go >/dev/null 2>&1; then
    (cd backend && bash -lc "$command")
    return
  fi
  command -v docker >/dev/null 2>&1 || die 'Go or Docker is required'
  local go_version
  go_version=$(awk '$1 == "go" { print $2; exit }' backend/go.mod)
  docker run --rm \
    --network host \
    --volume "$repo_root:/src" \
    --workdir /src/backend \
    "golang:${go_version}-alpine" \
    sh -c 'export PATH=/go/bin:/usr/local/go/bin:$PATH; exec sh -c "$1"' sh "$command"
}

usage() {
  printf 'usage: %s vX.Y.Z\n' "${0##*/}" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
readonly upstream_tag=$1
[[ "$upstream_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || die 'not inside a Git repository'
cd "$repo_root"

[[ -z "$(git status --porcelain)" ]] || die 'working tree must be clean'
[[ "$(git branch --show-current)" == "$stable_branch" ]] || die "run from $stable_branch"

previous_upstream_tag=$(git tag --merged HEAD --list 'v[0-9]*' --sort=-v:refname \
  | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
  | head -n 1)
[[ -n "$previous_upstream_tag" ]] || die 'cannot identify the previous upstream release tag'

if git remote get-url upstream >/dev/null 2>&1; then
  [[ "$(git remote get-url upstream)" == "$upstream_url" ]] || die 'remote upstream points to an unexpected URL'
else
  git remote add upstream "$upstream_url"
fi

git fetch --no-tags upstream "refs/tags/$upstream_tag:refs/tags/$upstream_tag"
git rev-parse --verify "$upstream_tag^{commit}" >/dev/null

readonly upgrade_branch="upgrade/${upstream_tag#v}"
git show-ref --verify --quiet "refs/heads/$upgrade_branch" && die "branch $upgrade_branch already exists"
git switch -c "$upgrade_branch"

set +e
git merge --no-ff --no-edit "$upstream_tag"
merge_status=$?
set -e

if [[ $merge_status -ne 0 ]]; then
  mapfile -t conflicts < <(git diff --name-only --diff-filter=U)
  if [[ ${#conflicts[@]} -eq 1 && "${conflicts[0]}" == "$generated_path" ]]; then
    git checkout --theirs -- "$generated_path"
    git add "$generated_path"
  else
    printf 'real merge conflict; agent review required:\n' >&2
    printf '  %s\n' "${conflicts[@]}" >&2
    exit 20
  fi
fi

run_go 'go generate ./ent && go generate ./cmd/server'
git diff --check -- . ':(exclude)backend/internal/pkg/openai/instructions_gpt6_astra.txt'

if ! git diff --quiet; then
  git add backend/ent backend/cmd/server/wire_gen.go
  if git rev-parse -q --verify MERGE_HEAD >/dev/null; then
    git commit --no-edit
  else
    git commit -m "chore: regenerate code after merging $upstream_tag"
  fi
elif git rev-parse -q --verify MERGE_HEAD >/dev/null; then
  git commit --no-edit
fi

"$repo_root/deploy/neko-fast-gate.sh" "$previous_upstream_tag" "$upstream_tag"

git switch "$stable_branch"
git merge --ff-only "$upgrade_branch"

printf 'merged %s into %s\n' "$upstream_tag" "$stable_branch"
printf 'next: git push origin %s\n' "$stable_branch"
