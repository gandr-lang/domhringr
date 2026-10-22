# The pull request a new one stacks on: the top of the server's open stacks.
#
# Input: the open pull requests, each
# `{number, head, base, created, landing, held}`. Arguments: `$own`, the branch
# being opened, left out of the reading; `$trunk`, the default branch. Output:
# `{number, head, depth, held}` for the open pull request no other open pull
# request targets, on the longest chain from the trunk, the newest on a tie;
# null when no other pull request is open. A landing pull request is never the
# top: the merge deletes its branch and closes, unmerged, whatever a link cannot
# carry, and a queued stack takes no link (gandr-lang/gandr#1455). `held` is the
# top's `landing` label: a `pr:land` is waiting to queue it, so `pr:open`
# refuses to stack on it (gandr-lang/gandr#1556).

[.[] | select(.head != $own)] as $open
| def depth($pr):
    [limit(64; $pr | recurse(. as $at | if $at.base == $trunk then empty else ([$open[] | select(.head == $at.base)] | first // empty) end))]
    | length;
  [$open[] | . as $pr | select((.landing | not) and all($open[]; .base != $pr.head)) | . + {depth: depth(.)}]
| (sort_by([.depth, .created]) | last) as $top
| if $top == null then null else $top | {number, head, depth, held: (.held // false)} end
