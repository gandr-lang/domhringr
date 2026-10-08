# domhringr-peer

One record-plane peer over a state directory: opens a sedimentree, grants write authority on it, writes notes to it, prints the view its commits fold to, reads its heads, and syncs it with another peer over iroh, through `domhringr-record-tree`.

```text
domhringr-peer --state <dir> id                                    # endpoint id, then peer id
domhringr-peer --state <dir> serve [--port <port>]                 # ids, `listening`, then per peer `accepted <peer-id>` and its path
domhringr-peer --state <dir> open <tree-id>                        # the Open's commit id
domhringr-peer --state <dir> grant <tree-id> <peer-id>             # the grant's commit id
domhringr-peer --state <dir> note <tree-id> <text>                 # the note's commit id
domhringr-peer --state <dir> view <tree-id>                        # the view, one line per fact
domhringr-peer --state <dir> heads <tree-id>                       # the heads, one sorted hex line each
domhringr-peer --state <dir> sync <endpoint-id> <peer-id> <tree-id>  # the heads after the sync, then its path
```

Ids are 64 hex digits. The state directory's keys and store are created on first use; the keys are never printed. A running command holds the store exclusively, so every command but `id` fails while `serve` runs on the same directory; `id` runs beside it.

`view` prints `owner <peer-id>`, then `member <peer-id>` for each peer granted write authority, `note <peer-id> <text>` for each admitted note in canonical order (a note's backslashes and control characters escaped), and `refused <commit-id> <reason>` for each commit the fold refuses: `wrong tree`, `undecodable`, `duplicate operation`, `no authority`, or `second open`.

`serve --port` binds iroh's UDP sockets, IPv4 and IPv6, at that port so a firewall rule can name it; without it the port is ephemeral. A path line reads `path <peer-id> direct <address>`, `path <peer-id> relay <url>`, or `path <peer-id> pending`: `serve` prints the path selected when it admits a peer, `sync` the one selected once its round ends, having given iroh up to five seconds to move a relayed connection to a direct path. iroh does not promise that move, even between two peers on one host, so a sync can end relayed.

The exit status is 0 on success, 1 when the command fails, and 2 for a command line that cannot be run.
