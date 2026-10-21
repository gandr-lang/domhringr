# The claim lifecycle (gandr-lang/gandr#1270): which claimed open issues lose
# `status:claimed`, one `number<TAB>reason` line each.
#
# Input:
#   now           the reading's time, in seconds since the epoch
#   claimed       the open issues carrying the label:
#                 [{number, labels: [name], updated_at}]
#   open_prs      the open pull requests: [{number, body, head}]
#   merged_body   the body of the pull request that just merged, or null
#
# With a merged body, the claim comes off every `Advances #n` target it names:
# that slice is done, and a seat working the next one claims it again. Without
# one, the sweep: a `kind:tracking` or `kind:epic` issue is never claimed, and
# a claim untouched for 24 hours that no open pull request names (`Closes`,
# `Fixes`, `Resolves` or `Advances` in its body, or the number in its branch)
# has no seat on it.

def advances: [match("(?i)\\badvances\\s+#([0-9]+)\\b"; "g") | .captures[0].string | tonumber];
def names($n):
  (.body | test("(?i)\\b(close[sd]?|fix(e[sd])?|resolve[sd]?|advances)\\s+#\($n)\\b"))
  or (.head | test("(^|[^0-9])\($n)([^0-9]|$)"));
def silent($now): ($now - (.updated_at | fromdateiso8601)) >= 86400;

.now as $now
| .open_prs as $prs
| if .merged_body != null then
    (.merged_body | advances) as $targets
    | .claimed[] | select(.number as $n | $targets | index($n)) | "\(.number)\tadvanced"
  else
    .claimed[]
    | . as $issue
    | if (.labels | index("kind:tracking")) then "\(.number)\ttracking"
      elif (.labels | index("kind:epic")) then "\(.number)\tepic"
      elif silent($now) and ([$prs[] | names($issue.number)] | any | not) then "\(.number)\tsilent"
      else empty
      end
  end
