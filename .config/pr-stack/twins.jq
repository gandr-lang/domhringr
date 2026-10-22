# The runs to re-run on a pull request's head before its stack queues. A
# restack pushes a head and its base at once, so the head gets two runs of
# each workflow on one commit, and the workflow's concurrency cancels one of
# them; when the cancelled one is the newer, the status rollup reads it and
# the head reads as failed though its twin passes.
#
# Input: the runs on the head commit, each `{databaseId, workflowName,
# startedAt, conclusion}`, `startedAt` the latest attempt's start and
# `conclusion` empty while the run is in flight.
# Output: the ids, ascending, of each workflow's newest run when it was
# cancelled and no run of that workflow on the commit failed: a failure is
# the head's own, and re-running would only repeat it.

group_by(.workflowName)
| map(sort_by(.startedAt, .databaseId)
    | select(last.conclusion == "cancelled" and all(.[]; .conclusion != "failure" and .conclusion != "timed_out"))
    | last.databaseId)
| sort