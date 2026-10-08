# domhringr-peer

One record-plane peer over a state directory: commits to a sedimentree, reads its heads, and syncs it with another peer over iroh, through `domhringr-record-tree`.

```text
domhringr-peer --state <dir> id                                    # endpoint id, then peer id
domhringr-peer --state <dir> serve                                 # ids, `listening`, then `accepted <peer-id>` per peer
domhringr-peer --state <dir> commit <tree-id> <text>               # the new commit id
domhringr-peer --state <dir> heads <tree-id>                       # the heads, one sorted hex line each
domhringr-peer --state <dir> sync <endpoint-id> <peer-id> <tree-id>  # the heads after the sync
```

Ids are 64 hex digits. The state directory's keys and store are created on first use; the keys are never printed. A running command holds the store exclusively, so `commit`, `heads` and `sync` fail while `serve` runs on the same directory; `id` runs beside it.

The exit status is 0 on success, 1 when the command fails, and 2 for a command line that cannot be run.
