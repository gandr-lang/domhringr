#!/usr/bin/env bash
# The claim lifecycle (gandr-lang/gandr#1270), run by `.github/workflows/claims.yml`:
#
#   claims.sh merged [--dry-run]   after a merge; the body is $CLAIMS_MERGED_BODY
#   claims.sh sweep [--dry-run]    the scheduled sweep
#
# It reads the claimed open issues and the open pull requests through the API,
# lets `decide.jq` pick the claims that come off, removes the label from each
# and prints one line per removal; nothing is posted on an issue. `--dry-run`
# prints the removals without making them.
set -euo pipefail
mode=${1:?usage: claims.sh merged|sweep [--dry-run]}
dry=${2:-}
repo=${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}
here=$(dirname "${BASH_SOURCE[0]}")
label=status:claimed

case "$mode" in
  merged) merged=$(jq -n 'env.CLAIMS_MERGED_BODY // ""') ;;
  sweep) merged=null ;;
  *) echo "unknown mode: $mode" >&2; exit 2 ;;
esac

claimed=$(gh api --paginate "repos/$repo/issues?state=open&labels=$label&per_page=100" \
  --jq '[.[] | select(.pull_request == null) | {number, labels: [.labels[].name], updated_at}]' | jq -s 'add // []')
open_prs=$(gh api --paginate "repos/$repo/pulls?state=open&per_page=100" \
  --jq '[.[] | {number, body: (.body // ""), head: .head.ref}]' | jq -s 'add // []')

removals=$(jq -rn --argjson now "$(date +%s)" --argjson claimed "$claimed" --argjson open_prs "$open_prs" --argjson merged "$merged" \
  '{now: $now, claimed: $claimed, open_prs: $open_prs, merged_body: $merged}' | jq -r -f "$here/decide.jq")

count=0
while IFS=$'\t' read -r number reason; do
  [[ -n "$number" ]] || continue
  if [[ "$dry" != --dry-run ]]; then
    gh api -X DELETE "repos/$repo/issues/$number/labels/${label/:/%3A}" > /dev/null
  fi
  printf 'unclaimed #%s: %s\n' "$number" "$reason"
  count=$((count + 1))
done <<< "$removals"
printf '%s: %d of %d claims removed\n' "$mode" "$count" "$(jq length <<< "$claimed")"
