# How `pr:land` lands a pull request, decided from its stack on the server,
# the only record (gandr-lang/gandr#1264).
#
# Input: an object with
#   server   the pull request's stack, bottom to top, each `{number, head}`
#            (`chain.jq`);
#   own      the checked-out branch;
#   queued   the numbers of the stack's pull requests already in the merge
#            queue;
#   carried  the numbers of the pull requests outside the stack, queued on
#            their own, whose branch the stack's top holds
#            (`carried_queued`); absent reads as none.
#
# Output: one tab-separated line:
#   single              land the one pull request;
#   wait<TAB>N          #N below, or carried, is queued on its own; land once
#                       it merges, when the stack is read again;
#   stack<TAB>N         restack and queue the stack whose top is #N;
#   refuse<TAB>MESSAGE  stop, naming why.
#
# A stack lands whole from its top, run from the top's checked-out branch. A
# stack that holds the commits of a
# pull request queued on its own, below it or retargeted off its branch
# (gandr-lang/gandr#1420), waits for that one to merge before it lands.

def chain: [.server[] | "#\(.number)"] | join(" ← ");
. as $in
| (($in.carried // []) + [$in.server[:-1][] | .number | select(. as $n | $in.queued | index($n))]) as $waiting
| if ($waiting | length) > 0 then
    "wait\t\($waiting | last)"
  elif ($in.server | length) <= 1 then
    "single"
  elif $in.own != $in.server[-1].head then
    "refuse\tthe checked-out branch is not the top of the server stack \($in | chain); land it with `pr:land` from #\($in.server[-1].number)'s branch"
  else
    "stack\t\($in.server[-1].number)"
  end
