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

**What.** `domhringr-surface-peer` provides the `domhringr-peer` command-line binary. It opens sedimentrees, delegates write authority, writes notes, binds paths, claims DNS names for a tree, introduces other trees by label, resolves anchors by key, by DNS name, or by label, reads views and heads, and synchronizes a tree with another peer.

**Why.** A peer needs a persistent identity and a command-line surface for operating its trees and inspecting their interpretation. Separate state directories let peers retain independent keys and stores while exchanging the same signed commits.

**How.** Commands use `domhringr-record-tree` for identity, storage, receipt construction, folding, resolution, and synchronization. `whence` asks DNS for a DNS name's `_domhringr.<domain>` TXT records unless `--witness` names the candidate trees, and reads a label in the `--in` tree. `serve` accepts connections over iroh; `sync` dials one remote, by endpoint id or at a direct address, exchanges one tree in a batch round, and disconnects.

## References

- `domhringr-record-tree`, [crate documentation](../record-tree/README.md): the persistent peer, receipt fold, and synchronization operation.
- `iroh`, [crate documentation](https://docs.rs/iroh): endpoint discovery and direct or relayed network paths.
- `lexopt`, [crate documentation](https://docs.rs/lexopt): command-line options and operands.

## Provided features

- Identity inspection and persistent state creation.
- Tree opening under a freshly minted tree key, printing the tree's anchor.
- `Grant`, `Note`, `Bind`, `Claim`, and `Introduce` receipt submission.
- Anchor resolution in the key, DNS, and label forms, with DNS witnesses or witnesses supplied by hand; canonical views; and sorted tree heads.
- Serving on an ephemeral or fixed UDP port.
- Single-tree synchronization, optionally at the remote's direct address, and selected-path reporting.

## Expected features

- A writable state directory; commands using its store require exclusive access.
- A native target with an operating-system random source for identities and receipts.
- For synchronization, a serving remote and its endpoint id, peer id, and tree anchor; on one host or at first contact, its direct address.
- Network access for iroh discovery and transport; a fixed port must be available for binding.
- For a DNS-form anchor, DNS resolvers reaching the name's `_domhringr.<domain>` TXT records, unless `--witness` names its trees; and in the local store, the witnessed tree whose root claims the name.
- For a label-form anchor, the tree that introduced the label, named by `--in` and held in the local store.

## Examples

From the workspace root, build the binary and operate a tree in a fresh state directory:

```sh
mise exec -- cargo build -p domhringr-surface-peer
state=$(mktemp -d)
target/debug/domhringr-peer --state "$state" id
tree=$(target/debug/domhringr-peer --state "$state" open)
note=$(target/debug/domhringr-peer --state "$state" note "$tree" hello)
target/debug/domhringr-peer --state "$state" bind "${tree}greeting" commit "$note"
target/debug/domhringr-peer --state "$state" whence "${tree}greeting"
target/debug/domhringr-peer --state "$state" claim "$tree" example.test
id=${tree#domhringr://}; id=${id%/}
target/debug/domhringr-peer --state "$state" whence domhringr://example.test/greeting --witness "example.test=$id"
other=$(target/debug/domhringr-peer --state "$state" open)
target/debug/domhringr-peer --state "$state" introduce "$tree" other "$other"
target/debug/domhringr-peer --state "$state" whence domhringr://other/ --in "$tree"
target/debug/domhringr-peer --state "$state" view "$tree"
target/debug/domhringr-peer --state "$state" heads "$tree"
```

`open` prints the new tree's anchor, `domhringr://<tree-id>/`; appending a path to it names that path in the tree. The two `whence` lines after the claim resolve the same path by the DNS name the tree claimed, witnessed by hand, and the second tree by the label the first introduced it by. The commands print endpoint, signing-peer, and commit ids in hex; the forms are defined in [Identifiers and state](#identifiers-and-state).

With `domhringr-peer` on `PATH`, the complete invocation set is:

```text
domhringr-peer --state <dir> id                                    # endpoint id, then peer id
domhringr-peer --state <dir> serve [--port <port>]                 # ids, listening, accepted peers and paths
domhringr-peer --state <dir> open                                  # the new tree's anchor
domhringr-peer --state <dir> grant <tree> <peer-id>                # the grant's commit id
domhringr-peer --state <dir> note <tree> <text>                    # the note's commit id
domhringr-peer --state <dir> bind <anchor> commit <commit-id>      # the bind's commit id
domhringr-peer --state <dir> bind <anchor> tree <tree>             # the bind's commit id
domhringr-peer --state <dir> bind <anchor> endpoint <endpoint-id>  # the bind's commit id
domhringr-peer --state <dir> bind <anchor> datum <text>            # the bind's commit id
domhringr-peer --state <dir> claim <tree> <domain>                 # the claim's commit id
domhringr-peer --state <dir> introduce <tree> <label> <tree>       # the introduction's commit id
domhringr-peer --state <dir> whence <name> [--witness <domain>=<tree-id>]... [--in <tree>]  # what the name resolves to
domhringr-peer --state <dir> view <tree>                           # the view, one line per fact
domhringr-peer --state <dir> heads <tree>                          # the heads, one sorted hex line each
domhringr-peer --state <dir> sync <endpoint-id> <peer-id> <tree> [--at <ip:port>]  # the heads after sync, then its path
```

Run the crate's tests, including two-process synchronization:

```sh
mise exec -- cargo nextest run -p domhringr-surface-peer
```

## Identifiers and state

A tree is named by its anchor; every other id is 64 hex digits, and the binary prints each in the form it reads:

| Name | Form | Meaning |
| ---- | ---- | ------- |
| Tree | `domhringr://<tree-id>/` | Selects a sedimentree; the tree id is the tree key's verifying key in 52 z-base-32 characters. |
| Anchor | `domhringr://<tree-id>/<segment>/…/<segment>` | A path in a tree; each segment is non-empty and holds no `/`. |
| Name, key form | a tree or an anchor | What `whence` resolves, its tree named by key; a bare tree resolves as no bind binds it. |
| Name, DNS form | `domhringr://<domain>/…` | The tree a witness names for the DNS name and whose root claims it; the name holds a dot and is lowercase letters, digits, and hyphens. |
| Name, label form | `domhringr://<label>/…` | The tree introduced by the label in the `--in` tree; the label holds no dot and no `/` and is not spelled as a tree id. |
| Witness | `<domain>=<tree-id>` | A `--witness` value: a candidate tree for the DNS name, in place of its TXT records. Any `--witness` replaces DNS for the command. |
| Commit id | 64 hex digits | BLAKE3 digest of the encoded receipt blob. |
| Endpoint id | 64 hex digits | Public key of the remote's iroh endpoint. |
| Peer id | 64 hex digits | Public key of the subduction signer that authenticates handshakes and signs commits. |

Only `whence` reads the DNS and label forms; every other tree operand and the anchor to bind name the tree by key, and a DNS name or a label there is a usage error. The state directory's two keys and store are created on first use, and `open` keeps each tree's key beside them. Secret keys are never printed. A running command holds the store exclusively, so every command but `id` fails while `serve` runs on the same directory; `id` runs beside it.

## Output

`view` prints `owner <peer-id>`, then `member <peer-id>` for each peer granted write authority, `note <peer-id> <text>` for each admitted note in canonical order, `bind <path> <target>` for each bound path in path order, `claim <domain>` for each claimed DNS name in name order, `introduce <label> <tree>` for each introduced label in label order, and `refused <commit-id> <reason>` for each refused commit. A target reads `commit <commit-id>`, `tree <tree>`, `endpoint <endpoint-id>`, or `datum <text>`. Notes, paths, labels, and data escape backslashes and control characters; paths and labels escape spaces as `\u{20}` too. Refusal reasons are `wrong tree`, `undecodable`, `duplicate operation`, `no authority`, `not owner` (a claim by anyone but the owner), `second open`, and `bad proof`.

`open` prints the new tree's anchor. `whence` prints the target the anchor's path is bound to in the local view of the tree its name resolves to, as `view` writes it, or `unbound`; a bare DNS-form or label-form name prints `tree <tree>` for the tree it names. It reads the local store and syncs nothing, and asks DNS only for a DNS-form name with no `--witness`. A name that does not resolve fails the command with one of `unwitnessed <domain>` (the witness names no tree), `unclaimed <domain>` (no witnessed tree in the store claims it), `ambiguous <domain>` (more than one does), `unscoped <label>` (no `--in`), `unintroduced <label>` (the `--in` tree did not introduce it), `cannot read the witness of <domain>` (the DNS lookup failed), or `cannot fold the tree <tree-id>` (a tree the resolution reads is not in the store), each followed by its cause where it has one. `serve` prints its endpoint id, peer id, and `listening`, then `accepted <peer-id>` and the selected path for each admitted peer. `sync` prints sorted heads followed by its selected path.

The exit status is 0 on success, 1 when the command fails, and 2 for a command line that cannot be run. Diagnostics go to standard error.

## Networking

`serve --port` binds iroh's IPv4 and IPv6 UDP sockets at that port so a firewall rule can name it; without it the port is ephemeral. `sync --at <ip:port>` dials the remote at that address as well as through iroh's lookups, so a dial on one host or at first contact does not wait for the remote's address to be published. A path line reads `path <peer-id> direct <address>`, `path <peer-id> relay <url>`, or `path <peer-id> pending`.

`serve` reports the path selected when it admits a peer. `sync` reports the path once its round ends, giving iroh up to five seconds to move a relayed connection to a direct path. iroh does not promise that move, even between two peers on one host, so a sync can end relayed.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
