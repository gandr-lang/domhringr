# The open pull requests a landing would close: each based on the branch of a
# pull request that lands, and not landing itself. GitHub deletes a merged pull
# request's branch and closes every open pull request still based on it,
# unmerged, unless a linked stack carries it; retargeted to the trunk first,
# each survives the merge, and `pr:land` from its top rebases it. Two are left
# alone: one already landing merges with its stack, and the queue refuses an
# edit of its base (gandr-lang/gandr#1455); one linked into the stack of the
# pull request its base belongs to is carried through the merge by that stack,
# and GitHub refuses to change the base of a stack's member
# (gandr-lang/gandr#1520).
#
# Input: the open pull requests, each `{number, head, base, created, landing,
# stack}`, `stack` the number of the linked stack holding it or null.
# Arguments: `$landing`, the numbers of the pull requests the landing merges.
# Output: the pull requests to retarget, each `{number, base}`, by number.

. as $open
| [$open[] | select(.number | IN($landing[])) | {head, stack}] as $deleted
| [$open[]
    | select(.number | IN($landing[]) | not)
    | select(.landing | not)
    | . as $pr
    | select(any($deleted[]; .head == $pr.base))
    | select(any($deleted[]; .head == $pr.base and .stack != null and .stack == $pr.stack) | not)]
| sort_by(.number)
| map({number, base})
