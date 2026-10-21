# The claim lifecycle (gandr-lang/gandr#1270): which claimed issues lose
# `status:claimed`, one `number<TAB>reason` line each.
#
# Input:
#   now           the reading's time, in seconds since the epoch
#   claimed       the issues carrying the label, open or closed:
#                 [{number, state, labels: [name], updated_at}]
#   open_prs      the open pull requests: [{number, body, head}]
#   merged_body   the body of the pull request that just merged, or null
#
# With a merged body, the claim comes off every issue the body advances
# (`Advances #n`: that slice is done, and a seat working the next one claims
# it again) or closes (`Closes`, `Fixes` or `Resolves #n`: GitHub closes the
# issue and leaves its labels). Without one, the sweep: a closed issue keeps
# no claim, a `kind:tracking` or `kind:epic` issue is never claimed, and a
# claim untouched for 24 hours that no open pull request names (one of those
# keywords in its body, or the number in its branch) has no seat on it.

def targets($keyword): [match("(?i)\\b\($keyword)\\s+#([0-9]+)\\b"; "g") | .captures[-1].string | tonumber];
def names($n):
  (.body | test("(?i)\\b(close[sd]?|fix(e[sd])?|resolve[sd]?|advances)\\s+#\($n)\\b"))
  or (.head | test("(^|[^0-9])\($n)([^0-9]|$)"));
def silent($now): ($now - (.updated_at | fromdateiso8601)) >= 86400;

.now as $now
| .open_prs as $prs
| if .merged_body != null then
    (.merged_body | targets("advances")) as $advanced
    | (.merged_body | targets("(close[sd]?|fix(e[sd])?|resolve[sd]?)")) as $closed
    | .claimed[]
    | .number as $n
    | if ($advanced | index($n)) then "\($n)\tadvanced"
      elif ($closed | index($n)) then "\($n)\tclosed"
      else empty
      end
  else
    .claimed[]
    | . as $issue
    | if .state == "closed" then "\(.number)\tclosed"
      elif (.labels | index("kind:tracking")) then "\(.number)\ttracking"
      elif (.labels | index("kind:epic")) then "\(.number)\tepic"
      elif silent($now) and ([$prs[] | names($issue.number)] | any | not) then "\(.number)\tsilent"
      else empty
      end
  end
