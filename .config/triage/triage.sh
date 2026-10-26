#!/usr/bin/env bash
# Every issue is filed with a `kind:` and an `area:` label
# (gandr-lang/gandr#2538), run by `.github/workflows/triage.yml` on every
# opened, labelled or unlabelled issue, or by hand:
#
#   triage.sh <issue> [--dry-run]
#
# It reads the issue's labels as they stand now, not as the event carried
# them, so runs arriving out of order still settle on the last state;
# `triage.jq` decides whether `needs:triage` is added, removed or kept.
# `--dry-run` prints the decision without acting on it.
set -euo pipefail
issue=${1:?usage: triage.sh <issue> [--dry-run]}
dry=${2:-}
repo=${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}
here=$(dirname "${BASH_SOURCE[0]}")
label=needs:triage

read_labels=$(gh api "repos/$repo/issues/$issue" --jq 'if .pull_request then "pull request" else [.labels[].name] end')
if [[ "$read_labels" == "pull request" ]]; then
  echo "#$issue is a pull request; only issues are triaged"
  exit 0
fi
decision=$(jq -r -f "$here/triage.jq" <<< "$read_labels")
if [[ "$dry" != --dry-run ]]; then
  case "$decision" in
    add) gh issue edit "$issue" --repo "$repo" --add-label "$label" > /dev/null ;;
    remove) gh issue edit "$issue" --repo "$repo" --remove-label "$label" > /dev/null ;;
    keep) ;;
    *) echo "triage.jq gave no decision for #$issue" >&2; exit 1 ;;
  esac
fi
printf '#%s: %s %s\n' "$issue" "$decision" "$label"
