# domhringr-surface-peer

The `domhringr-peer` binary manages and synchronizes a record-plane peer over a state directory.

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Identifiers and state](#identifiers-and-state)
- [Output](#output)
- [Networking](#networking)
- [License](#license)

## Synopsis

**What.** `domhringr-surface-peer` provides the `domhringr-peer` command-line binary. It opens sedimentrees, delegates write authority, writes notes, reads views and heads, and synchronizes a tree with another peer.

**Why.** A peer needs a persistent identity and a command-line surface for operating its trees and inspecting their interpretation. Separate state directories let peers retain independent keys and stores while exchanging the same signed commits.

**How.** Commands use `domhringr-record-tree` for identity, storage, receipt construction, folding, and synchronization. `serve` accepts connections over iroh; `sync` dials one remote, exchanges one tree in a batch round, and disconnects.

## References

- `domhringr-record-tree`, [crate documentation](../record-tree/README.md): the persistent peer, receipt fold, and synchronization operation.
- `iroh`, [crate documentation](https://docs.rs/iroh): endpoint discovery and direct or relayed network paths.
- `lexopt`, [crate documentation](https://docs.rs/lexopt): command-line options and operands.

## Provided features

- Identity inspection and persistent state creation.
- `Open`, `Grant`, and `Note` receipt submission.
- Canonical views and sorted tree heads.
- Serving on an ephemeral or fixed UDP port.
- Single-tree synchronization and selected-path reporting.

## Expected features

- A writable state directory; commands using its store require exclusive access.
- A native target with an operating-system random source for identities and receipts.
- For synchronization, a serving remote and its endpoint id, peer id, and tree id.
- Network access for iroh discovery and transport; a fixed port must be available for binding.

## Examples

From the workspace root, build the binary and operate a tree in a fresh state directory:

```sh
mise exec -- cargo build -p domhringr-surface-peer
state=$(mktemp -d)
tree=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
target/debug/domhringr-peer --state "$state" id
target/debug/domhringr-peer --state "$state" open "$tree"
target/debug/domhringr-peer --state "$state" note "$tree" hello
target/debug/domhringr-peer --state "$state" view "$tree"
target/debug/domhringr-peer --state "$state" heads "$tree"
```

The example's `tree` value selects a sedimentree. The commands print endpoint, signing-peer, and commit ids in hex; their meanings are defined in [Identifiers and state](#identifiers-and-state).

With `domhringr-peer` on `PATH`, the complete invocation set is:

```text
domhringr-peer --state <dir> id                                    # endpoint id, then peer id
domhringr-peer --state <dir> serve [--port <port>]                 # ids, listening, accepted peers and paths
domhringr-peer --state <dir> open <tree-id>                        # the Open's commit id
domhringr-peer --state <dir> grant <tree-id> <peer-id>             # the grant's commit id
domhringr-peer --state <dir> note <tree-id> <text>                 # the note's commit id
domhringr-peer --state <dir> view <tree-id>                        # the view, one line per fact
domhringr-peer --state <dir> heads <tree-id>                       # the heads, one sorted hex line each
domhringr-peer --state <dir> sync <endpoint-id> <peer-id> <tree-id>  # the heads after sync, then its path
```

Run the crate's tests, including two-process synchronization:

```sh
mise exec -- cargo nextest run -p domhringr-surface-peer
```

## Identifiers and state

The command-line interface uses 64 hex digits for each id and prints ids in hex:

| Id | Meaning |
| -- | ------- |
| Tree id | Selects a sedimentree. |
| Commit id | BLAKE3 digest of the encoded receipt blob. |
| Endpoint id | Public key of the remote's iroh endpoint. |
| Peer id | Public key of the subduction signer that authenticates handshakes and signs commits. |

The state directory's two keys and store are created on first use. Secret keys are never printed. A running command holds the store exclusively, so every command but `id` fails while `serve` runs on the same directory; `id` runs beside it.

## Output

`view` prints `owner <peer-id>`, then `member <peer-id>` for each peer granted write authority, `note <peer-id> <text>` for each admitted note in canonical order, and `refused <commit-id> <reason>` for each refused commit. Notes escape backslashes and control characters. Refusal reasons are `wrong tree`, `undecodable`, `duplicate operation`, `no authority`, and `second open`.

`serve` prints its endpoint id, peer id, and `listening`, then `accepted <peer-id>` and the selected path for each admitted peer. `sync` prints sorted heads followed by its selected path.

The exit status is 0 on success, 1 when the command fails, and 2 for a command line that cannot be run. Diagnostics go to standard error.

## Networking

`serve --port` binds iroh's IPv4 and IPv6 UDP sockets at that port so a firewall rule can name it; without it the port is ephemeral. A path line reads `path <peer-id> direct <address>`, `path <peer-id> relay <url>`, or `path <peer-id> pending`.

`serve` reports the path selected when it admits a peer. `sync` reports the path once its round ends, giving iroh up to five seconds to move a relayed connection to a direct path. iroh does not promise that move, even between two peers on one host, so a sync can end relayed.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
