# The trunk's required contexts on a pull request's head, read before its stack
# queues (gandr-lang/gandr#1601). Only the required contexts are read, so a
# check the rules do not require, such as the mutants report, never holds the
# landing. A context is read at its newest run: a re-run attempt starts later
# than the run it replaces.
#
# Input: the head's status check rollup, each a `CheckRun` (`name`,
# `status`, `conclusion`, `startedAt`) or a `StatusContext` (`context`,
# `state`, `startedAt`).
# Arguments: `$required`, the trunk's required contexts.
# Output: `{failed, pending}`, the required contexts that concluded
# otherwise than success, skipped or neutral, and those not yet concluded or
# not yet reported, each in `$required`'s order. Both empty: the stack may
# queue.

def verdict:
  if .__typename == "StatusContext" then
    if .state == "SUCCESS" then "pass" elif IN(.state; "PENDING", "EXPECTED") then "pending" else "fail" end
  elif .status != "COMPLETED" then "pending"
  elif IN(.conclusion; "SUCCESS", "SKIPPED", "NEUTRAL") then "pass"
  else "fail"
  end;

. as $rollup
| [$required[] as $name
    | {name: $name,
       verdict: ([$rollup[] | select((.name // .context) == $name)] | sort_by(.startedAt // "")
         | if length == 0 then "pending" else last | verdict end)}]
| {failed: [.[] | select(.verdict == "fail") | .name], pending: [.[] | select(.verdict == "pending") | .name]}
