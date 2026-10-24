#!/usr/bin/env bash
# Re-pins every third-party action in this repository to the commit SHA of a release tag.
#
#   scripts/pin-actions.sh            # pin each action to the newest vX.Y.Z tag
#   scripts/pin-actions.sh --check    # exit 1 if any `uses:` is not pinned to a 40-character SHA
#
# Each line becomes `uses: owner/repo@<sha> # vX.Y.Z`. Review the diff and the release notes of
# every bumped action before committing. The SLSA generator is intentionally left on its tag:
# its builder verifies its own ref and refuses to run from a SHA.
set -euo pipefail
cd "$(dirname "$0")/.."
files=()
while IFS= read -r line; do
  files+=("$line")
done < <(find .github/workflows action.yml examples -name '*.yml' -type f)

if [ "${1:-}" = "--check" ]; then
  # examples/ carry a <commit-sha> placeholder for consumers to fill in
  bad=$(grep -nE '^\s*-?\s*uses:\s*[^./][^@]+@' "${files[@]}" | grep -vE '@[0-9a-f]{40}( |$)' | grep -v 'slsa-framework/slsa-github-generator' | grep -v '@<commit-sha>' || true)
  if [ -n "$bad" ]; then echo "unpinned actions:"; echo "$bad"; exit 1; fi
  echo "all actions are pinned to commit SHAs"; exit 0
fi

latest() { # repo -> "tag sha" of the newest vX.Y.Z tag (annotated tags dereferenced)
  local refs tag sha
  refs=$(git ls-remote --tags "https://github.com/$1")
  tag=$(awk '{print $2}' <<<"$refs" | sed 's#refs/tags/##; s#\^{}##' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1)
  sha=$(grep -E "refs/tags/$tag\^\{\}$" <<<"$refs" | awk '{print $1}' || true)
  [ -n "$sha" ] || sha=$(grep -E "refs/tags/$tag$" <<<"$refs" | awk '{print $1}' || true)
  echo "$tag $sha"
}

repos=$(grep -hoE '^\s*-?\s*uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[^@ ]+)?@' "${files[@]}" | sed -E 's/^\s*-?\s*uses:\s*//; s/@$//' \
        | awk -F/ '{print $1"/"$2}' | sort -u | grep -v '^slsa-framework/slsa-github-generator$')
for repo in $repos; do
  read -r tag sha < <(latest "$repo")
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "skip $repo: no release tag found" >&2; continue; }
  echo "$repo -> $tag ($sha)"
  for f in "${files[@]}"; do
    sed -i -E "s#^(\s*-?\s*uses:\s*${repo//./\\.}(/[^@ ]+)?)@[^ ]+( \#.*)?\$#\1@$sha \# $tag#" "$f"
  done
done
echo "done — review with: git diff"
