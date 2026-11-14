#!/usr/bin/env bash
# Refuses each line of the tree that holds the path of a home directory
# (gandr #7041). Such a path names an account of a host, and the tree is
# public. One `rg` reads every file that git does not ignore, with the
# patterns of `patterns`, one regular expression a line. A path under a name
# of `placeholders` stands, as a fixture of a rubric reads one. The
# cases of `cases.json` run first, through one `rg` of their lines: each
# holds a line and whether the check refuses it. The patterns file and the
# cases file hold such paths by design, so the read of the tree skips them.
#
# Usage: check.bash
# Exits 1 on a refusal or a failed case, and 2 when `rg` fails.
set -euo pipefail
here=$(cd "${BASH_SOURCE[0]%/*}" && pwd)
root=$(git -C "$here" rev-parse --show-toplevel)
patterns=$here/patterns
placeholders=$here/placeholders
cases=$here/cases.json

# The lines of `rg -o` output whose path no placeholder names. The name is
# the segment past the home directory: `/Users/<name>`, `/home/<name>` or
# `\Users\<name>`. A path under the root's home has no name. With
# `prefixed=1`, each line starts with `<file>:<line>:`, which the read of
# the name skips.
local_paths() {
  awk -v list="$placeholders" -v prefixed="${1:-0}" '
    BEGIN {
      while ((getline name < list) > 0) if (name != "" && name !~ /^#/) placeholder[name] = 1
    }
    NF == 0 { next }
    {
      text = $0
      if (prefixed && match(text, /:[0-9]+:/)) text = substr(text, RSTART + RLENGTH)
      name = ""
      if (match(text, /\/(Users|home)\/[^\/[:space:]"'\''`),>\]]+/)) {
        split(substr(text, RSTART, RLENGTH), part, "/")
        name = part[3]
      }
      else if (match(text, /\\Users\\[^\\[:space:]]+/)) {
        split(substr(text, RSTART, RLENGTH), part, "\\")
        name = part[3]
      }
      if (name == "" || !(name in placeholder)) print
    }'
}

# `rg` with the patterns. A match exits 0 and no match exits 1; an error of
# `rg` exits 2, which a caller passes on.
search() {
  local status=0
  rg --only-matching --file "$patterns" "$@" || status=$?
  (( status <= 1 )) || { echo "check:local-paths: rg failed with exit $status" >&2; return 2; }
}

# Case `k` is line `k` of the input of `rg`, and `rg` names standard input
# `<stdin>`, so its refused lines read as those of a file.
mapfile -d '' -t fields < <(jq -j '.[] | .name, "\u0000", .line, "\u0000", (.refused | tostring), "\u0000"' "$cases")
lines=()
for ((i = 1; i < ${#fields[@]}; i += 3)); do lines+=("${fields[i]}"); done
matches=$(printf '%s\n' "${lines[@]}" | search --with-filename --line-number -) || exit 2
refused=" $(local_paths 1 <<< "$matches" | awk -F: '{ print $2 }' | sort -un | tr '\n' ' ')"
failed=0
for ((k = 1; k <= ${#lines[@]}; k++)); do
  got=false
  if [[ $refused == *" $k "* ]]; then got=true; fi
  base=$(((k - 1) * 3))
  if [[ $got != "${fields[base + 2]}" ]]; then
    printf 'local paths case FAILED: %s\n  line: %s\n  refused: %s, recorded: %s\n' \
      "${fields[base]}" "${fields[base + 1]}" "$got" "${fields[base + 2]}" >&2
    failed=1
  fi
done
(( failed == 0 )) || exit 1

matches=$(cd "$root" && search --line-number --with-filename --hidden \
  --glob '!.git' --glob '!.config/local-paths/patterns' --glob '!.config/local-paths/cases.json' .) || exit 2
found=$(local_paths 1 <<< "$matches")
if [[ -n $found ]]; then
  printf '%s\n' "$found" >&2
  echo "local paths check FAILED: $(wc -l <<< "$found" | tr -d ' ') lines of the tree hold the path of a home directory; write a placeholder, a relative path or \`\$HOME\`" >&2
  exit 1
fi
echo "local paths check OK: ${#lines[@]} cases read as recorded; no line of the tree holds the path of a home directory"
